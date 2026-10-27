"""One bounded initial-RAM OWNER snapshot preparation, then clean recovery.

No C phase/remote lease, normal user session, hardware-watchdog ownership or
fallback writer exists here. A failed/unknown attempt is held for the inherited
reset and cannot replay. The loader must admit this entire bootset first.
"""
from pathlib import Path
import ctypes
import hashlib
import importlib.util
import os
import re
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

INSTALL = Path('/usr/lib/omarchy/shield/owner')
CONFIG = Path('/etc/shield-owner/preparation.json')
LAYER = Path('/etc/shield-owner/owner-layer.tar.gz')
SECOND = 1_000_000_000
sys.path.insert(0, str(INSTALL))
from owner_profile import require, exact
from owner_runtime import regular, decode
from owner_command_line import preparation as preparation_command_line, normal as normal_command_line
from owner_layer import canonical, marker, read_archive, validate_layer, Tree


def local_module(name, leaf):
  spec = importlib.util.spec_from_file_location(name, INSTALL / leaf)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


def default_subvolume(raw):
  if raw == b'ID 5 (FS_TREE)\n':
    return {'id': 5, 'top_level': None, 'path': None}
  match = re.fullmatch(rb'ID ([0-9]+) gen ([0-9]+) top level ([0-9]+) path ([^\n]+)\n', raw)
  require(match is not None, 'Unrecognized default-subvolume output')
  return {'id': int(match[1]), 'top_level': int(match[3]), 'path': match[4].decode('ascii')}


def validate_config(config, boot):
  exact(config, ['purpose', 'boot', 'layer', 'parent_default', 'parent_postimages', 'sources_sha256', 'boot_payloads'],
        'Preparation fields differ')
  require(config['purpose'] == 'omarchy-shield-owner-preparation', 'Explicit preparation purpose required')
  enrolled, context = boot.validate_boot(config['boot'])
  exact(config['layer'], ['bytes', 'sha256'], 'Exact layer identity required')
  require(type(config['layer']['bytes']) is int and 0 < config['layer']['bytes'] <= 8 * 1024**2
          and config['layer']['sha256'] == config['boot']['preparation']['layer_sha256'],
          'Preparation layer does not bind normal boot')
  sources = config['sources_sha256']
  require(type(sources) is dict and set(sources) == boot.BOOT_SOURCES | {'owner-prepare.py'}
          and {name: sources[name] for name in boot.BOOT_SOURCES} == context['sources_sha256']
          and type(sources['owner-prepare.py']) is str
          and re.fullmatch('[0-9a-f]{64}', sources['owner-prepare.py']), 'Preparation source closure differs')
  selected = config['parent_default']
  exact(selected, ['id', 'top_level', 'path'], 'Default selection fields differ')
  require(type(selected['id']) is int and 5 <= selected['id'] < 2**64, 'Invalid default selection')
  if selected['id'] == 5:
    require(selected['top_level'] is selected['path'] is None, 'Wrong FS_TREE selection')
  else:
    require(type(selected['top_level']) is int and 0 < selected['top_level'] < 2**64
            and type(selected['path']) is str and 0 < len(selected['path']) <= 512
            and selected['path'].isascii() and '\n' not in selected['path'] and '\0' not in selected['path'],
            'Invalid selected default metadata')
  images = config['parent_postimages']
  require(type(images) is dict and all(name in images and images[name] == item
          for name, item in config['boot']['root_postimages'].items()),
          'Parent must bind all selected normal startup postimages')
  require(set(images) == set(config['boot']['root_postimages']) | {'etc/passwd', 'etc/group', 'etc/shadow', 'etc/gshadow'},
          'Parent account/startup preimage set differs')
  for name, item in images.items():
    boot.relative(name)
    exact(item, ['bytes', 'sha256', 'mode'], 'Parent preimage fields differ')
    require(type(item['bytes']) is int and 0 < item['bytes'] <= 128 * 1024**2
            and type(item['mode']) is int and item['mode'] in [0o600, 0o640, 0o644, 0o755]
            and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']),
            'Parent preimage identity differs')
  artifacts = config['boot_payloads']
  expected = {'Image', 'probe.dtb', 'initramfs.cpio.gz', 'BOOTSET.json', 'boot.json', 'context.json', 'enrollment.json'}
  require(type(artifacts) is dict and set(artifacts) == expected, 'Exact persistent boot payload set required')
  for name, item in artifacts.items():
    exact(item, ['bytes', 'sha256'], 'Boot payload identity fields differ')
    require(type(item['bytes']) is int and 0 < item['bytes'] <= 128 * 1024**2
            and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']),
            'Invalid persistent boot payload identity')
  require(sum(item['bytes'] for item in artifacts.values()) <= 160 * 1024**2,
          'Persistent boot payload exceeds preparation budget')
  for name, value in [('boot.json', config['boot']), ('context.json', context), ('enrollment.json', enrolled)]:
    data = canonical(value)
    require(artifacts[name] == {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
            'Persistent boot configuration binding differs')
  return enrolled, context


class ChildClosureError(RuntimeError):
  pass


def command_allowed(argv):
  require(type(argv) is list and argv[:2] == ['/usr/bin/btrfs', 'subvolume'], 'Fixed Btrfs client required')
  if argv == ['/usr/bin/btrfs', 'subvolume', 'get-default', '/run/shield-usb']:
    return
  require(len(argv) == 5 and argv[2] == 'snapshot' and all(type(path) is str
    and re.fullmatch('/run/shield-usb/@shield-[0-9a-f]{32}(-(home|log))?', path)
    for path in argv[3:]), 'Only selected snapshot/default operations allowed')


def run(argv, deadline, check, clients):
  command_allowed(argv)
  check()
  remaining = (deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / SECOND
  require(remaining > 1 and argv[:2] == ['/usr/bin/btrfs', 'subvolume'], 'Invalid/budgetless owned Btrfs client')
  child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
  timed = False
  try:
    output, errors = child.communicate(timeout=min(10, remaining))
  except subprocess.TimeoutExpired:
    timed = True
    try:
      os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
      pass
    try:
      output, errors = child.communicate(timeout=3)
    except subprocess.TimeoutExpired as error:
      raise ChildClosureError('Owned Btrfs child closure unknown') from error
  try:
    os.killpg(child.pid, 0)
    gone = False
  except ProcessLookupError:
    gone = True
  clients.append({'actual_wait_exit': child.returncode, 'positive_wait': True,
                  'group_absent': gone, 'timed_out': timed})
  if timed or not gone:
    raise ChildClosureError('Owned Btrfs client timed out or group remains')
  require(child.returncode == 0 and len(output) <= 4096 and not errors, 'Owned Btrfs client failed')
  check()
  return output


def record(stage, digest):
  require(re.fullmatch('[A-Za-z0-9_-]{1,64}', stage) and (digest == 'unknown'
          or re.fullmatch('[0-9a-f]{64}', digest)), 'Invalid preparation observation')
  raw = ('<6>shield-owner-prepare stage=' + stage + ' config_sha256=' + digest + '\n').encode('ascii')
  fd = os.open('/dev/kmsg', os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    require(stat.S_ISCHR(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_rdev == os.makedev(1, 11), 'Wrong printk node')
    require(os.write(fd, raw) == len(raw), 'Preparation observation not retained')
  finally:
    os.close(fd)


def load(boot):
  boot.admit_initial_ram()
  raw = regular(CONFIG, 8 * 1024**2, 0o600)
  config = decode(raw)
  validate_config(config, boot)
  digest = hashlib.sha256(raw).hexdigest()
  tokens = Path('/proc/cmdline').read_text().split()
  require(tokens == preparation_command_line(raw).decode('ascii').split(),
          'Complete preparation command line differs')
  for prefix, value in [('shield.omarchy-owner-prepare=', 'shield.omarchy-owner-prepare=1'),
      ('shield.owner-preparation=', 'shield.owner-preparation=' + digest),
      ('modprobe.blacklist=', 'modprobe.blacklist=r8169')]:
    require([token for token in tokens if token.startswith(prefix)] == [value], 'Wrong preparation boot binding')
  require(not any(token.startswith(('shield.omarchy-owner=', 'shield.owner-boot=', 'systemd.unit='))
                  for token in tokens), 'Normal boot and preparation cannot share a purpose')
  for name, value in config['sources_sha256'].items():
    require(hashlib.sha256(regular(INSTALL / name, 1024**2, 0o644)).hexdigest() == value,
            'Preparation runtime source differs')
  item = config['layer']
  data = regular(LAYER, item['bytes'], 0o600)
  require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
          'Preparation layer bytes differ')
  layer, payloads = read_archive(data)
  normal = config['boot']
  validate_layer(layer, payloads, normal['enrollment'], normal['context'], normal['root_postimages'])
  for name, item in config['boot_payloads'].items():
    data = regular(CONFIG.parent / 'boot-payload' / name, item['bytes'], 0o600)
    require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
            'Initial RAM persistent boot payload differs')
  descriptor = decode(regular(CONFIG.parent / 'boot-payload/BOOTSET.json', 128 * 1024, 0o600))
  exact(descriptor, ['purpose', 'owner_id', 'filesystem', 'artifacts', 'command_line', 'kernel_config'],
        'Persistent boot descriptor fields differ')
  require(descriptor['purpose'] == 'omarchy-shield-owner-bootset'
          and descriptor['owner_id'] == normal['enrollment']['owner_id']
          and descriptor['filesystem'] == normal['enrollment']['filesystem']
          and descriptor['artifacts'] == {name: item for name, item in config['boot_payloads'].items() if name != 'BOOTSET.json'}
          and descriptor['command_line'] == normal_command_line(canonical(normal), canonical(normal['context'])).decode('ascii'),
          'Persistent boot descriptor binding differs')
  exact(descriptor['kernel_config'], ['bytes', 'sha256'], 'Selected kernel config identity differs')
  require(type(descriptor['kernel_config']['bytes']) is int and descriptor['kernel_config']['bytes'] > 0
          and type(descriptor['kernel_config']['sha256']) is str
          and re.fullmatch('[0-9a-f]{64}', descriptor['kernel_config']['sha256']), 'Invalid selected kernel config')
  return config, layer, payloads, digest


def control_directory(top, enrolled):
  parent = top / '.shield-owner'
  try:
    parent.mkdir(mode=0o700)
  except FileExistsError:
    pass
  info = parent.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == 0o700, 'Unowned OWNER control directory')
  path = parent / enrolled['owner_id']
  path.mkdir(mode=0o700)  # An existing attempt is never adopted/replayed.
  return path


def write_control(path, raw, check):
  check()
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  try:
    view = memoryview(raw)
    while view:
      check()
      amount = os.write(fd, view[:1024**2])
      require(amount > 0, 'Short preparation record write')
      view = view[amount:]
    check()
    os.fsync(fd)
  finally:
    os.close(fd)
  parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    os.fsync(parent)
  finally:
    os.close(parent)


def main():
  os.umask(0o077)
  require(os.getpid() == 1 and sys.argv[1:] == ['--run'], 'Initial preparation PID1 required')
  boot = local_module('owner_normal_boot', 'owner-init.py')
  config, layer, payloads, digest = load(boot)
  deadline = 120 * SECOND
  boot.budget(deadline)
  record('admitted', digest)
  from native_boot_context import USB_STORAGE
  from native_root_storage import USBRoot
  from native_mounts import MountDomain
  from qualification_recovery import filesystem_identity
  enrolled = config['boot']['enrollment']
  bundle = SimpleNamespace(epoch='early', phase='owner-prepare', profile=enrolled,
    configuration={'purpose': 'omarchy-shield-owner-preparation', 'usb_storage': USB_STORAGE})
  device = USBRoot(bundle, boot.wait_usb(bundle, deadline))
  domain = MountDomain(device)
  clients = []
  cooling = local_module('owner_prepare_cooling', 'owner-thermal.py')
  sensors = {}
  try:
    sensors = cooling.discover()
    boot.budget(deadline)
    cooling.write_fan(sensors['fan'], 'pwm1_enable', b'2\n')
    boot.budget(deadline)
    cooling.write_fan(sensors['fan'], 'pwm1', b'255\n')
    asserted = cooling.boot_ns()
    top = domain.readonly_top(deadline)
    def check():
      boot.budget(deadline)
      sample, begin, end = cooling.read_sample(sensors)
      cooling.health(sample, begin, end, asserted)
      domain.check()
      require(Path('/proc/self/task/1/children').read_text().strip() == '', 'Unreaped preparation child')
    old = layer['base_subvolumes']
    names = enrolled['filesystem']['subvolumes']
    for volume in ['root', 'home', 'log']:
      source = boot.safe_path(top, old[volume])
      info = source.lstat()
      require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_ino == 256,
              'Parent is not an owned Btrfs subvolume root')
      filesystem_identity(source, enrolled['filesystem']['uuid'])
      target = boot.safe_path(top, names[volume])
      require(not target.exists() and not target.is_symlink(), 'OWNER snapshot name already consumed')
    attempt = boot.safe_path(top, '.shield-owner/' + enrolled['owner_id'], missing_parents=True)
    require(not attempt.exists() and not attempt.is_symlink(), 'OWNER preparation attempt already consumed')
    for name, item in config['parent_postimages'].items():
      boot.observe_file(top / old['root'], name, item, deadline)
    before = default_subvolume(run(['/usr/bin/btrfs', 'subvolume', 'get-default', str(top)], deadline, check, clients))
    require(before == config['parent_default'], 'Default selection differs before preparation')
    domain.owner_preparation_rw(deadline)
    check()
    control = control_directory(top, enrolled)
    write_control(control / 'ATTEMPT.json', canonical({'purpose': 'omarchy-shield-owner-preparation',
      'config_sha256': digest, 'no_replay': True}), check)
    record('write_claimed', digest)
    for volume in ['root', 'home', 'log']:
      run(['/usr/bin/btrfs', 'subvolume', 'snapshot', str(top / old[volume]), str(top / names[volume])],
          deadline, check, clients)
      observed = (top / names[volume]).lstat()
      require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == observed.st_gid == 0
              and observed.st_ino == 256, 'Snapshot result not observed as a Btrfs subvolume')
      filesystem_identity(top / names[volume], enrolled['filesystem']['uuid'])
    roots = {name: top / names[name] for name in ['root', 'home', 'log']}
    tree = Tree(roots, check)
    try:
      tree.apply(layer, payloads)
    finally:
      tree.close()
    check()
    content = canonical(marker(enrolled, config['boot']['context'], config['layer']['sha256']))
    expected = config['boot']['preparation']
    require(len(content) == expected['bytes'] and hashlib.sha256(content).hexdigest() == expected['sha256'],
            'Preparation marker differs from normal boot')
    boot_files = control / 'boot'
    check()
    boot_files.mkdir(mode=0o700)
    for name, item in config['boot_payloads'].items():
      check()
      data = regular(CONFIG.parent / 'boot-payload' / name, item['bytes'], 0o600)
      require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
              'Persistent boot input changed')
      write_control(boot_files / name, data, check)
      actual = regular(boot_files / name, item['bytes'], 0o600)
      require(len(actual) == item['bytes'] and hashlib.sha256(actual).hexdigest() == item['sha256'],
              'Persistent boot payload readback differs')
    write_control(control / 'PREPARED.json', content, check)
    boot.root_admission(top, config['boot'], deadline)
    after = default_subvolume(run(['/usr/bin/btrfs', 'subvolume', 'get-default', str(top)], deadline, check, clients))
    require(after == before, 'Default selection changed')
    check()
    domain.release(deadline)
    require(not domain.mounted and not Path('/proc/self/task/1/children').read_text().strip()
            and len(clients) == 5 and all(item['positive_wait'] and item['group_absent']
             and item['actual_wait_exit'] == 0 and not item['timed_out'] for item in clients),
            'Preparation cleanup not proven')
    device.close()
    record('payload_verified_children_reaped_usb_unmounted_readonly', digest)
    # This is initial RAM with no normal user/system writers; ordinary reboot2
    # is permitted only after explicit mount/child release above.
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    result = library.syscall(ctypes.c_long(142), ctypes.c_ulong(0xfee1dead),
      ctypes.c_ulong(672274793), ctypes.c_ulong(0xa1b2c3d4), ctypes.c_char_p(b'recovery'))
    require(result == 0, 'Clean preparation recovery reboot refused')
    raise ValueError('Recovery reboot unexpectedly returned')
  finally:
    for fd in sensors.values():
      os.close(fd)
    device.close()


if __name__ == '__main__':
  try:
    main()
  except BaseException as error:
    if os.getpid() != 1:
      raise SystemExit(65)
    try:
      raw = regular(CONFIG, 8 * 1024**2, 0o600)
      digest = hashlib.sha256(raw).hexdigest()
      trace = error.__traceback__
      while trace is not None and trace.tb_next is not None:
        trace = trace.tb_next
      record('failed_' + type(error).__name__[:32] + '_' + str(trace.tb_lineno if trace else 0), digest)
    except BaseException:
      pass
    while True:
      time.sleep(1)
