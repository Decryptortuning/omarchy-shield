#!/usr/bin/env python3
"""Real full-system ARM VM collector; native hardware admission stays closed."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PREFIX = Path('/usr/lib/shield-systemd-vm')
NATIVE = Path('/usr/lib/omarchy/shield/qualification')
USER_UNIT = 'shield-systemd-vm-user.service'
NEGATIVE_UNIT = 'shield-systemd-vm-native-refusal.service'
SOCKET = Path('/run/user/1001/shield-systemd-vm.sock')
LIMIT = 32768
END = 0.0
LAST_COMMAND = {}


def require(ok, message):
  if not ok: raise ValueError(message)


def explicit_polkit_no(result):
  # Exact polkit127 C-locale output, including its escaped detail key.
  # Check the full command output before any bounded evidence truncation.
  return (type(result['returncode']) is int and result['returncode'] == 1
          and result['output'] == r'polkit\56result=no' + '\nNot authorized.\n')


def remaining(limit):
  left = END - time.monotonic()
  require(left > 0.25, 'VM probe deadline exhausted')
  return min(limit, left)


def command(argv, timeout=5):
  global LAST_COMMAND
  budget = remaining(timeout)
  LAST_COMMAND = {'argv': list(argv), 'state': 'starting'}
  process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT, start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
  try: output, _ = process.communicate(timeout=budget)
  except BaseException:
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    process.communicate(timeout=1)
    raise
  LAST_COMMAND = {'argv': list(argv), 'returncode': process.returncode,
    'output': output.decode('utf-8', errors='replace')[:2048], 'output_truncated': len(output) > 2048}
  require(len(output) <= LIMIT, 'Excessive VM command output')
  return {'returncode': process.returncode, 'output': output.decode('utf-8', errors='replace')}


def checked(argv, timeout=5):
  result = command(argv, timeout)
  require(result['returncode'] == 0, 'VM command refused: ' + Path(argv[0]).name)
  return result['output']


def properties(unit, names):
  argv = ['/usr/bin/systemctl', 'show', '--no-pager']
  if unit: argv.append(unit)
  argv += ['--property=' + name for name in names]
  text = checked(argv)
  values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
  require(set(values) == set(names), 'Missing actual systemd properties')
  return values


def wait_for(predicate, seconds):
  until = time.monotonic() + remaining(seconds)
  while time.monotonic() < until:
    value = predicate()
    if value: return value
    time.sleep(0.1)
  raise ValueError('Expected actual VM state did not arrive')


def process_start(pid):
  text = Path('/proc/' + str(pid) + '/stat').read_text()
  return int(text[text.rfind(')') + 2:].split()[19])


def actual_session(pid):
  lib = ctypes.CDLL('libsystemd.so.0')
  lib.sd_pid_get_session.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
  lib.sd_pid_get_session.restype = ctypes.c_int
  value = ctypes.c_void_p()
  require(lib.sd_pid_get_session(pid, ctypes.byref(value)) >= 0 and value.value,
          'Fixture PID is outside an actual PAM/logind session')
  try: session = ctypes.string_at(value).decode('ascii')
  finally:
    libc = ctypes.CDLL(None); libc.free.argtypes = [ctypes.c_void_p]; libc.free(value)
  require(re.fullmatch('[A-Za-z0-9_-]{1,64}', session), 'Unsafe actual session identity')
  return session


def boot_bytes(path, maximum=512):
  with path.open('rb') as stream: data = stream.read(maximum + 1)
  require(len(data) <= maximum, 'Oversized boot metadata: ' + path.name)
  return data


def boot_text(path, maximum=512):
  return boot_bytes(path, maximum).decode('ascii').strip()


def virtio_inventory(records):
  devices = sorted(Path('/sys/bus/virtio/devices').iterdir())
  require(len(devices) <= 8, 'Excessive virtual device inventory')
  for device in devices:
    record = {'name': device.name}
    records.append(record)
    require(re.fullmatch('virtio[0-9]+', device.name), 'Unexpected virtio device name')
    path = device.resolve(strict=True)
    record.update(path=str(path), parent=str(path.parent))
    require(path.is_relative_to(Path('/sys/devices')), 'Unexpected virtio sysfs location')
    for name in ['device', 'vendor', 'status', 'features']:
      record[name] = boot_text(path / name, 256)
    for name, link in [('driver', path / 'driver'), ('parent_driver', path.parent / 'driver')]:
      record[name] = str(link.resolve(strict=True)) if link.is_symlink() else None
    require(re.fullmatch('0x[0-9a-f]{4,8}', record['device'])
            and re.fullmatch('0x[0-9a-f]{4,8}', record['vendor'])
            and re.fullmatch('0x[0-9a-f]{8}', record['status'])
            and re.fullmatch('[01]{128}', record['features']), 'Unexpected virtio metadata dialect')
    # Selected virtio.c features_show prints bit zero first, for 128 bits.
    record['version_1_negotiated'] = record['features'][32] == '1'
    require(len(json.dumps(records)) <= 4096, 'Excessive virtio metadata')


def emulated_kms(evidence):
  evidence.update(passed=False, stage='virtio before module', virtio_before=[])
  virtio_inventory(evidence['virtio_before'])
  evidence['stage'] = 'module and udev'
  evidence['module_load'] = command(['/usr/bin/modprobe', 'virtio_gpu'], 10)
  if evidence['module_load']['returncode'] == 0:
    evidence['udev_settle'] = command(['/usr/bin/udevadm', 'settle', '--timeout=10'], 12)
  evidence.update(stage='virtio after module', virtio_after=[])
  virtio_inventory(evidence['virtio_after'])
  require(evidence['module_load']['returncode'] == 0, 'Emulated virtio KMS module did not load')
  require(evidence['udev_settle']['returncode'] == 0, 'Emulated KMS udev did not settle')
  evidence['stage'] = 'DRM card inventory'
  evidence['cards'] = cards = []
  paths = sorted(p for p in Path('/sys/class/drm').iterdir() if re.fullmatch('card[0-9]+', p.name))
  require(len(paths) <= 4, 'Excessive DRM card inventory')
  for path in paths:
    record = {'name': path.name}
    cards.append(record)
    transport = (path / 'device').resolve(strict=True)
    record.update(path=str(path.resolve(strict=True)), transport=str(transport))
    record['transport_driver'] = str((transport / 'driver').resolve(strict=True))
    record['dev'] = boot_text(path / 'dev', 32)
  # DRM is parented to the virtio transport; the GPU driver binds its child.
  evidence['stage'] = 'GPU and card correlation'
  gpus = [device for device in evidence['virtio_after'] if device['device'] == '0x0010']
  require(len(gpus) == 1, 'Expected one actual virtio GPU')
  gpu = gpus[0]
  require(gpu['driver'] == '/sys/bus/virtio/drivers/virtio_gpu'
          and gpu['parent_driver'] == '/sys/bus/platform/drivers/virtio-mmio'
          and Path(gpu['parent']).is_relative_to(Path('/sys/devices/platform'))
          and gpu['version_1_negotiated'] is True
          and int(gpu['status'], 16) & 0xcf == 0x0f, 'Virtio GPU is not healthy on modern MMIO')
  matches = [card for card in cards if card['transport'] == gpu['parent']
             and card['transport_driver'] == '/sys/bus/platform/drivers/virtio-mmio']
  require(len(matches) == 1, 'No actual DRM card linked to the bound virtio GPU')
  evidence.update(passed=True, stage='complete', version_1_negotiated=True,
                  gpu_transport_link_verified=True, renderer_qualified=False)


def emulated_nor(item, evidence, mounts):
  evidence.update(passed=False, stage='MTD identity')
  mtd = Path('/sys/class/mtd/mtd0').resolve(strict=True)
  evidence['mtd_path'] = str(mtd)
  evidence['mtd'] = {}
  for name in ['name', 'type', 'size', 'dev']:
    evidence['mtd'][name] = boot_text(mtd / name)
  evidence['mtd_class'] = sorted(p.name for p in Path('/sys/class/mtd').iterdir())
  evidence['of_node'] = str((mtd / 'of_node').resolve(strict=True))
  target = item.resolve(strict=True)
  evidence['holders'] = sorted(p.name for p in (target / 'holders').iterdir())
  require(item.name == 'mtdblock0' and target.parent == mtd
          and not (target / 'partition').exists()
          and boot_text(target / 'dev') == '31:0' and boot_text(target / 'size') == '262144'
          and not evidence['holders'], 'Unexpected NOR block identity')
  device = Path('/dev/mtdblock0').stat()
  require(stat.S_ISBLK(device.st_mode) and (os.major(device.st_rdev), os.minor(device.st_rdev)) == (31, 0),
          'Unexpected NOR device node')
  require(evidence['mtd'] == {'name': '0.flash', 'type': 'nor', 'size': '134217728', 'dev': '90:0'}
          and set(evidence['mtd_class']) in ({'mtd0'}, {'mtd0', 'mtd0ro'})
          and evidence['of_node'] == '/sys/firmware/devicetree/base/flash@0', 'Unexpected NOR master identity')
  flash = Path(evidence['of_node'])
  evidence['stage'] = 'NOR DT geometry'
  evidence['DT'] = {}
  for name in ['compatible', 'reg', 'bank-width']:
    evidence['DT'][name] = boot_bytes(flash / name, 64).hex()
  evidence['DT_status'] = boot_text(flash / 'status') if (flash / 'status').exists() else None
  evidence['DT_children'] = sorted(p.name for p in flash.iterdir() if p.is_dir())
  require(evidence['DT'] == {'compatible': b'cfi-flash\0'.hex(),
          'reg': struct.pack('>8I', 0, 0, 0, 0x4000000, 0, 0x4000000, 0, 0x4000000).hex(),
          'bank-width': struct.pack('>I', 4).hex()}
          and evidence['DT_status'] in (None, 'okay\x00') and not evidence['DT_children']
          and boot_bytes(Path('/proc/device-tree/#address-cells'), 4) == struct.pack('>I', 2)
          and boot_bytes(Path('/proc/device-tree/#size-cells'), 4) == struct.pack('>I', 2),
          'Unexpected NOR DT geometry')
  evidence['stage'] = 'NOR platform binding'
  platform = Path('/sys/bus/platform/devices/0.flash').resolve(strict=True)
  evidence['platform'] = {'path': str(platform)}
  for name in ['driver', 'subsystem', 'of_node']:
    evidence['platform'][name] = str((platform / name).resolve(strict=True))
  actual = evidence['platform']
  require(actual['driver'] == '/sys/bus/platform/drivers/physmap-flash'
          and actual['subsystem'] == '/sys/bus/platform'
          and actual['of_node'] == evidence['of_node'],
          'Unexpected NOR platform binding')
  require(not any(entry['dev'] == '31:0' for entry in mounts), 'NOR must remain unmounted')
  evidence.update(passed=True, stage='complete', mounted=False)


def boot_admission(identity, recovery, evidence):
  evidence.update(passed=False, stage='PID1 and board')
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0 and os.getppid() == 1,
          'VM collector must be a real root PID1 child')
  require(os.readlink('/proc/1/exe') == '/usr/lib/systemd/systemd'
          and os.uname().release == identity['kernel']['release'] and os.uname().machine == 'aarch64',
          'Selected ARM kernel and real systemd PID1 required')
  require(Path('/proc/device-tree/compatible').read_bytes() == b'linux,dummy-virt\0', 'Wrong QEMU virt board')
  tokens = Path('/proc/cmdline').read_text().split()
  require([x for x in tokens if x.startswith('shield.systemd-vm=')] == ['shield.systemd-vm=1'], 'Wrong unique VM marker')
  require(not any(x.startswith(('shield.first-ram-probe=', 'shield.guardian=',
          'tegra_smmu.reset_inherited=', 'tegra_smmu.quarantine_gpub_inherited=')) for x in tokens),
          'Native markers must never be spoofed on virt')
  evidence.update(PID1_systemd=True, kernel_release=os.uname().release, virt_DT=True, no_native_markers=True)
  evidence['stage'] = 'root device'
  mounts = recovery.mounts(Path('/proc/self/mountinfo').read_text())
  block = Path('/sys/class/block/vda').resolve(strict=True)
  evidence['vda_path'] = str(block)
  require(str(block).startswith('/sys/devices/') and '/virtio' in str(block), 'Root must use emulated virtio block')
  expected_device = tuple(map(int, (block / 'dev').read_text().strip().split(':')))
  device = Path('/dev/vda').stat()
  require(stat.S_ISBLK(device.st_mode) and (os.major(device.st_rdev), os.minor(device.st_rdev)) == expected_device,
          'Unexpected virtual root device')
  evidence['stage'] = 'block inventory'
  evidence['blocks'] = inventory = []
  items = sorted(Path('/sys/class/block').iterdir())
  evidence['block_count'] = len(items)
  require(len(items) <= 48, 'Excessive block inventory')
  # Complete the inventory before classifying any device; a failed predicate
  # must retain the actual unexpected device rather than an empty check.
  for item in items:
    record = {'name': item.name}
    inventory.append(record)
    target = item.resolve(strict=True)
    record.update(path=str(target), dev=boot_text(target / 'dev'), size=boot_text(target / 'size'),
                  partition=(target / 'partition').exists())
    require(len(json.dumps(inventory)) <= 8192, 'Excessive block metadata')
  for item in items:
    if item.name == 'vda': continue
    evidence['current_block'] = item.name
    target = item.resolve(strict=True)
    if item.name == 'mtdblock0':
      evidence['emulated_NOR'] = {}
      emulated_nor(item, evidence['emulated_NOR'], mounts)
      continue
    require(target.is_relative_to(Path('/sys/devices/virtual/block')) and
            re.fullmatch('(ram|zram|loop)[0-9]+', item.name), 'Unexpected exposed block hardware')
    if item.name.startswith('loop'):
      require((target / 'size').read_text().strip() == '0', 'Unexpected attached loop storage')
  require(evidence.get('emulated_NOR', {}).get('passed') is True, 'Expected emulated NOR was not identified')
  evidence['stage'] = 'Btrfs mounts'
  evidence['mounts'] = actual_mounts = []
  for path, purpose in [('/', 'root'), ('/home', 'home'), ('/var/log', 'log')]:
    values = [entry for entry in mounts if entry['path'] == path]
    actual_mounts.extend({**entry, 'options': sorted(entry['options']),
                          'super_options': sorted(entry['super_options'])} for entry in values)
    require(len(values) == 1 and values[0]['filesystem'] == 'btrfs'
            and values[0]['root'] == '/' + identity['filesystem']['subvolumes'][purpose]
            and Path(values[0]['source']).resolve(strict=True) == Path('/dev/vda')
            and 'nosuid' not in values[0]['options'] and 'rw' in values[0]['options']
            and {x for x in values[0]['super_options'] if x.startswith('compress')} == {'compress=zstd:1'},
            'VM candidate mount or live compression differs')
    recovery.filesystem_identity(path, identity['filesystem']['uuid'])
  require(all(Path(entry['source']).resolve(strict=True) == Path('/dev/vda')
              for entry in mounts if entry['filesystem'] == 'btrfs'), 'Additional Btrfs disk exposed')
  evidence.update(passed=True, stage='complete', whole_vda_only=True,
                  three_actual_Btrfs_subvolumes=True, mounts_allow_setuid=True,
                  runtime_compression='zstd:1', emulated_NOR_only=True)


def native_graph(result):
  result.update(passed=False, loaded={})
  for unit, kind, after, required in [
      ('shield-qualification-recovery.service', 'notify', {'local-fs.target', 'systemd-udev-trigger.service'}, {'local-fs.target'}),
      ('shield-guardian.service', 'notify', {'shield-qualification-recovery.service'}, {'shield-qualification-recovery.service'}),
      ('shield-qualification-desktop.service', 'idle', {'shield-guardian.service', 'systemd-logind.service'}, {'shield-guardian.service'})]:
    names = ['LoadState', 'Type', 'After', 'Requires', 'Restart', 'MainPID', 'ActiveState', 'ExecStart']
    if kind == 'notify': names += ['NotifyAccess', 'TimeoutStartUSec', 'TimeoutStopUSec', 'SendSIGKILL', 'KillMode',
                                   'DefaultDependencies', 'IgnoreOnIsolate', 'RefuseManualStop']
    else: names += ['BindsTo']
    values = properties(unit, names)
    result['loaded'][unit] = values
    require(values['LoadState'] == 'loaded' and values['Type'] == kind and values['Restart'] == 'no'
            and after.issubset(values['After'].split()) and required.issubset(values['Requires'].split()),
            'Production dependency graph differs')
    if kind == 'notify':
      require(values['NotifyAccess'] == 'main' and values['TimeoutStartUSec'] == values['TimeoutStopUSec'] == 'infinity'
              and values['SendSIGKILL'] == 'no' and values['KillMode'] == 'process'
              and values['DefaultDependencies'] == 'no' and values['IgnoreOnIsolate'] == 'yes'
              and values['RefuseManualStop'] == 'yes', 'Production guard lifetime differs')
    else:
      require('shield-guardian.service' in values['BindsTo'].split(), 'Desktop readiness dependency differs')
    expected_entry = str(NATIVE / ('qualification_recovery.py' if 'recovery' in unit else 'shield-guardian'))
    if kind == 'notify': require(expected_entry in values['ExecStart'], 'Loaded native entrypoint differs')
  checked(['/usr/bin/systemctl', '--no-block', 'start', 'shield-qualification.target'])
  def recovery_refused():
    value = properties('shield-qualification-recovery.service', ['ExecMainStatus', 'ActiveState', 'MainPID'])
    result['recovery_refusal'] = value
    return value if value['ExecMainStatus'] == '64' and value['MainPID'] == '0' else None
  wait_for(recovery_refused, 20)
  for unit in ['shield-guardian.service', 'shield-qualification-desktop.service']:
    v = properties(unit, ['ActiveState', 'MainPID'])
    result[unit + '_after_refusal'] = v
    require(v['ActiveState'] in {'inactive', 'failed'} and v['MainPID'] == '0', 'Native path acquired false readiness on virt')
  require(not Path('/run/shield-guardian/control.sock').exists()
          and not Path('/run/shield-recovery/request.sock').exists(), 'Unexpected native control/READY endpoint')
  checked(['/usr/bin/systemctl', 'start', NEGATIVE_UNIT])
  negative = properties(NEGATIVE_UNIT, ['ExecMainStatus', 'MainPID', 'Result'])
  result['separate_exact_guardian_refusal'] = negative
  require(negative['ExecMainStatus'] == '64' and negative['MainPID'] == '0' and negative['Result'] == 'success',
          'Exact enabled guardian did not reject virt')
  result.update(passed=True, native_READY=False, native_desktop_started=False)


def receive(channel):
  data, ancillary, flags, _ = channel.recvmsg(LIMIT, 0)
  require(data and not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'Invalid user probe packet')
  value = json.loads(data)
  require(type(value.get('version')) is int and value['version'] == 1, 'Wrong user probe dialect')
  return value


def send(channel, operation):
  data = json.dumps({'version': 1, 'operation': operation}, separators=(',', ':')).encode()
  require(channel.send(data) == len(data), 'User operation delivery failed')


def user_checks(actions, evidence):
  evidence['passed'] = False
  fixture = properties(USER_UNIT, ['Type', 'User', 'Group', 'PAMName', 'TTYPath',
    'NoNewPrivileges', 'RestrictSUIDSGID', 'ExecStart'])
  evidence['fixture_loaded'] = fixture
  require(fixture['Type'] == 'exec' and fixture['User'] == fixture['Group'] == 'shieldqual'
          and fixture['PAMName'] == 'login' and fixture['TTYPath'] == '/dev/tty1'
          and fixture['NoNewPrivileges'] == fixture['RestrictSUIDSGID'] == 'no'
          and '/usr/lib/shield-systemd-vm-user/user-probe.py' in fixture['ExecStart'],
          'Actual VM PAM fixture differs')
  checked(['/usr/bin/systemctl', '--no-block', 'start', USER_UNIT])
  def endpoint_ready():
    values = properties(USER_UNIT, ['MainPID', 'ActiveState', 'ExecMainStatus', 'Result'])
    evidence['fixture_state'] = values
    if values['ActiveState'] == 'failed': raise ValueError('User fixture failed before endpoint')
    return values if SOCKET.exists() and int(values['MainPID']) > 1 and values['ActiveState'] == 'active' else None
  unit = wait_for(endpoint_ready, 25)
  pid = int(unit['MainPID'])
  parent, endpoint = SOCKET.parent.lstat(), SOCKET.lstat()
  require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 1001 and stat.S_IMODE(parent.st_mode) == 0o700
          and stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == endpoint.st_gid == 1001
          and stat.S_IMODE(endpoint.st_mode) == 0o600, 'Untrusted user probe socket')
  with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC) as channel:
    channel.settimeout(remaining(10)); channel.connect(str(SOCKET))
    peer = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    evidence['observed_peer'] = list(peer)
    require(peer == (pid, 1001, 1001), 'User peer is not the actual fixture main process')
    hello = receive(channel)
    evidence['hello'] = hello
    require(set(hello) == {'version', 'kind', 'pid', 'starttime', 'uid', 'euid', 'gid', 'session', 'boot_id', 'tty'}
            and hello['kind'] == 'hello' and hello['pid'] == pid and hello['uid'] == hello['euid'] == hello['gid'] == 1001
            and hello['starttime'] == process_start(pid) and hello['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            and hello['tty'] == '/dev/tty1', 'User hello identity differs')
    session = actual_session(pid)
    require(session == hello['session'], 'Actual session/PID mapping differs')
    checked(['/usr/bin/loginctl', 'activate', session])
    names = ['Id', 'User', 'Active', 'Remote', 'Seat', 'Type', 'Class', 'State', 'Leader', 'VTNr']
    def active():
      text = checked(['/usr/bin/loginctl', 'show-session', session, *['--property=' + n for n in names]])
      value = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
      evidence['actual_session'] = value
      return value if value.get('Active') == 'yes' else None
    observed = wait_for(active, 10)
    require(set(observed) == set(names) and observed['Id'] == session and observed['User'] == '1001'
            and observed['Remote'] == 'no' and observed['Seat'] == 'seat0' and observed['Type'] == 'tty'
            and observed['Class'] == 'user' and observed['State'] == 'active' and observed['VTNr'] == '1'
            and Path('/sys/class/tty/tty0/active').read_text().strip() == 'tty1', 'Real active local seat/session not established')
    user_manager = properties('user@1001.service', ['ActiveState', 'MainPID'])
    evidence['real_user_manager'] = user_manager
    require(user_manager['ActiveState'] == 'active' and int(user_manager['MainPID']) > 1,
            'Real user manager is not running')
    # The installed defaults allow active local poweroff/reboot: denial must
    # not be a false pass obtained merely by testing an inactive process.
    catalog = ET.fromstring(Path('/usr/share/polkit-1/actions/org.freedesktop.login1.policy').read_bytes())
    defaults = {node.attrib['id']: node.findtext('defaults/allow_active') for node in catalog.findall('action')}
    require(all(defaults.get('org.freedesktop.login1.' + name) == 'yes' for name in ['power-off', 'reboot']),
            'No default-active authorization contrast was established')
    denied = []
    evidence['actual_policy_denials'] = denied
    for action in actions:
      require(process_start(pid) == hello['starttime'], 'Session subject died/reused')
      value = command(['/usr/bin/pkcheck', '--action-id', action, '--process',
                       str(pid) + ',' + str(hello['starttime']) + ',1001'], 3)
      proof = {'action': action, 'returncode': value['returncode'],
               'output': value['output'][:512], 'explicit_no': False}
      denied.append(proof)
      require(explicit_polkit_no(value), 'Explicit active-session policy NO not proven')
      proof['explicit_no'] = True
    send(channel, 'probe')
    channel.settimeout(remaining(45))
    result = receive(channel)
    evidence['user_probe'] = result
    require(result.get('kind') == 'probes' and result.get('passed') is True, 'Fixed user probes failed: ' + str(result.get('reason', 'unknown'))[:160])
    send(channel, 'finish')
    require(receive(channel) == {'version': 1, 'kind': 'bye'}, 'Missing user finish record')
  wait_for(lambda: (v if (v := properties(USER_UNIT, ['MainPID', 'ExecMainStatus']))['MainPID'] == '0' else None), 5)
  require(properties(USER_UNIT, ['ExecMainStatus'])['ExecMainStatus'] == '0', 'User fixture did not exit cleanly')
  evidence.update(passed=True, peer_starttime_verified=True, default_active_power_allowed=True)


def collect(result):
  sys.path.insert(0, str(PREFIX))
  from systemd_vm_profile import load_identity
  identity = load_identity()
  sys.path.insert(0, str(NATIVE))
  import guardian_binding as binding
  import qualification_recovery as recovery
  native_file = NATIVE / 'profile.json'
  require(hashlib.sha256(native_file.read_bytes()).hexdigest() == identity['native_profile_sha256'], 'Native profile changed')
  profile = binding.validate(json.loads(native_file.read_text()))
  payload = json.loads((PREFIX / 'payload-manifest.json').read_text())
  installation = json.loads((PREFIX / 'installation-receipt.json').read_text())
  require(identity['filesystem'] == {'uuid': profile['filesystem']['uuid'],
          'subvolumes': profile['filesystem']['subvolumes']}
          and payload['filesystem_uuid'] == identity['filesystem']['uuid']
          and payload['subvolumes'] == identity['filesystem']['subvolumes']
          and installation['profile_sha256'] == identity['native_profile_sha256']
          and installation['prepared_receipt_sha256'] == identity['prepared_receipt_sha256'],
          'VM/native/payload/installation custody differs')
  result['checks']['boot_mount_admission'] = {}
  boot_admission(identity, recovery, result['checks']['boot_mount_admission'])
  from usb_root_profile import verify_root
  verify_root(payload, Path('/'))
  result['checks']['actual_package_module_loader_payload'] = {'passed': True, 'verified_in_running_guest': True}
  kms = result['checks']['emulated_kms_seat_prerequisite'] = {'passed': False}
  emulated_kms(kms)
  recovery.artifacts(profile)
  recovery.startup_policy(profile)  # SOFTWARE validator only; never USB/native admission.
  result['checks']['installed_software_policy'] = {'passed': True, 'actual_manager_and_file_checks': True,
    'native_hardware_admission': False}
  result['checks']['manager'] = properties(None,
    ['RuntimeWatchdogUSec', 'RebootWatchdogUSec', 'KExecWatchdogUSec', 'CtrlAltDelBurstAction'])
  result['checks']['native_fail_closed'] = {}
  native_graph(result['checks']['native_fail_closed'])
  overlay = json.loads((NATIVE / 'overlay-manifest.json').read_text())
  policy = overlay['policy']['user_power_policy']
  actions = policy['denied_actions']
  require(policy['subject_user'] == 'shieldqual' and len(actions) == len(set(actions)) == 25
          and 'org.freedesktop.portable1.attach-images' in actions
          and all(isinstance(x, str) and re.fullmatch(r'org\.freedesktop\.(login1|systemd1|portable1)\.[a-z-]+', x) for x in actions),
          'Bound power action set differs')
  # Actual root policy queries complement the real unprivileged sudo execution.
  listing = checked(['/usr/bin/sudo', '-n', '-l', '-U', 'shieldqual'])
  lines = [line.strip() for line in listing.splitlines() if line.strip()]
  host = re.fullmatch(r'Matching Defaults entries for shieldqual on ([A-Za-z0-9_.-]+):', lines[0]) if lines else None
  require(len(lines) == 6 and host is not None
          and lines[1] == r'secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/bin, passwd_tries=10'
          and lines[2] == 'Runas and Command-specific defaults for shieldqual:'
          and lines[3] == 'Defaults!/usr/bin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"'
          and lines[4] == 'User shieldqual may run the following commands on ' + host[1] + ':'
          and lines[5] == '(ALL) !/usr/bin/asdcontrol', 'Unexpected sudo policy dialect/grant')
  denial = command(['/usr/bin/sudo', '-n', '-l', '-U', 'shieldqual', '--', '/usr/bin/true'])
  require(denial['returncode'] == 1 and denial['output'] == '', 'Root true policy query did not deny')
  result['checks']['root_sudo_policy'] = {'passed': True, 'negative_only': True, 'true_query_denied': True}
  result['checks']['session_setuid_power'] = {}
  user_checks(actions, result['checks']['session_setuid_power'])
  result['graphics'] = {'qualified': False, 'status': 'blocked',
    'reason': 'Actual virtual software UWSM/compositor/IPC rendering not demonstrated; current payload is Nouveau/Tegra'}
  result['passed'] = True


def main():
  global END
  END = time.monotonic() + 240
  result = {'format_version': 1, 'scope': 'owned full-system ARM VM', 'passed': False, 'checks': {},
    'native_guardian_admitted': False, 'Shield_native_qualified': False,
    'hardware_or_performance_qualified': False, 'graphics_qualified': False, 'boot_ready': False,
    'passed_scope': 'systemd/mount/native-refusal/active-PAM/userbus/setuid/power-policy only'}
  try:
    require(len(sys.argv) == 1, 'No VM collector arguments accepted')
    collect(result)
  except Exception as error:
    result['error'] = type(error).__name__; result['reason'] = str(error)[:240]
    result['failed_command'] = dict(LAST_COMMAND)
    try:
      journal = command(['/usr/bin/journalctl', '-b', '--no-pager', '-o', 'cat', '-n', '20',
        '-u', USER_UNIT, '-u', 'shield-qualification-recovery.service', '-u', NEGATIVE_UNIT,
        '-u', 'polkit.service'], 2)
      result['failure_journal'] = journal['output'][:3072]
    except (OSError, ValueError, subprocess.SubprocessError): pass
    try:
      kernel = command(['/usr/bin/journalctl', '-k', '-b', '--no-pager', '-o', 'cat', '-n', '24'], 2)
      result['failure_kernel_journal'] = kernel['output'][-2048:]
    except (OSError, ValueError, subprocess.SubprocessError): pass
    print('SHIELD_SYSTEMD_VM_DIAGNOSTIC ' + json.dumps(result.get('failed_command', {}),
          sort_keys=True, separators=(',', ':')), file=sys.stderr, flush=True)
  data = json.dumps(result, sort_keys=True, separators=(',', ':'))
  if len(data.encode()) > LIMIT:
    data = json.dumps({'format_version': 1, 'scope': 'owned full-system ARM VM', 'passed': False,
      'error': 'ResultTooLarge', 'native_guardian_admitted': False, 'boot_ready': False}, separators=(',', ':'))
    result['passed'] = False
  print('SHIELD_SYSTEMD_VM_RESULT ' + data, flush=True)
  return 0 if result['passed'] else 1


if __name__ == '__main__':
  raise SystemExit(main())
