"""Distinct OWNER initial-RAM PID1: local enrolled storage admission and normal systemd.

No qualification HMAC/clock/serial protocol or healthy desktop expiry is used.
The bootset constructor/loader must admit the initrd and its Python closure
before execution. These checks bind its actual early source and selected root.
This source alone is not an install, bootset or hardware qualification receipt.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import select
import socket
import stat
import sys
import time
from types import SimpleNamespace

INSTALL = Path('/usr/lib/omarchy/shield/owner')
CONFIG = Path('/etc/shield-owner/boot.json')
RUNTIME = Path('/run/shield-owner')
SECOND = 1_000_000_000
sys.path.insert(0, str(INSTALL))
from owner_profile import require, exact, validate, validate_context, render, MODULE
from owner_runtime import regular, decode, magic, sysfs
from owner_layer import validate_marker
from owner_command_line import admit_normal as admit_normal_command_line

# The transitive local import closure of the reused storage/mount primitives.
# Imports do not grant access to C protocols or call their main functions.
BOOT_SOURCES = frozenset(name + '.py' for name in [
  'owner-init', 'owner_profile', 'owner_runtime', 'owner_layer', 'owner_command_line', 'owner-network', 'owner-ready', 'owner-thermal',
  'native_root_storage', 'native_mounts', 'native_boot_context', 'qualification_recovery',
  'guardian_binding', 'guardian_client', 'native_control_protocol', 'native_cleanup_rpc',
  'native_serial_link', 'usb_root_profile'])
EMMC_BOOT_SOURCES = BOOT_SOURCES | {'native_emmc_storage.py', 'owner_internal_ack.py'}
CORE_FILES = frozenset(['usr/lib/systemd/systemd', 'usr/bin/python3.14', 'usr/bin/sshd',
                        'usr/bin/NetworkManager'])

DESKTOP_FILES = frozenset(['usr/share/omarchy/config/hypr/hyprland.lua',
  'usr/share/omarchy/default/hypr/autostart.lua'])


def canonical(value):
  return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def relative(name):
  require(type(name) is str and 0 < len(name) <= 512 and name.isascii()
          and all(part not in ('.', '..') and re.fullmatch('[A-Za-z0-9_@+.,:-]+', part)
                  for part in name.split('/')),
          'Unsafe OWNER root postimage path')
  return name


def validate_boot(config):
  exact(config, ['purpose', 'enrollment', 'context', 'root_postimages', 'preparation'], 'OWNER boot fields differ')
  require(config['purpose'] == 'omarchy-shield-owner', 'Explicit OWNER boot required')
  enrolled = validate(config['enrollment'])
  context = validate_context(config['context'], enrolled)
  require(context['enrollment_sha256'] == hashlib.sha256(canonical(enrolled)).hexdigest(),
          'Boot enrollment bytes differ')
  expected_sources = EMMC_BOOT_SOURCES if 'emmc' in enrolled['filesystem'] else BOOT_SOURCES
  require(set(context['sources_sha256']) == expected_sources, 'Initial RAM source closure differs')
  images = config['root_postimages']
  require(type(images) is dict and (CORE_FILES | DESKTOP_FILES) <= set(images) and len(images) <= 32768,
          'Selected base root postimages required')
  for name, item in images.items():
    relative(name)
    exact(item, ['bytes', 'sha256', 'mode'], 'Root postimage fields differ')
    require(type(item['bytes']) is int and 0 < item['bytes'] <= 128 * 1024**2
            and type(item['mode']) is int and item['mode'] in [0o600, 0o644, 0o755]
            and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']),
            'Root postimage identity differs')
  require(all(images[name]['mode'] == 0o755 for name in CORE_FILES),
          'Core system executables must retain execute permission')
  require(all(images[name]['mode'] == 0o644 for name in DESKTOP_FILES),
          'Matched desktop source permissions differ')
  validate_marker(config['preparation'], enrolled, context)
  return enrolled, context


def budget(deadline):
  require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) < deadline,
          'Local initial-RAM startup deadline expired')


def safe_path(root, name, missing_parents=False):
  path = root / relative(name)
  require(path.is_relative_to(root), 'OWNER postimage escaped')
  parents = [root]
  selected = root
  for part in path.relative_to(root).parts[:-1]:
    selected = selected / part
    parents.append(selected)
  for selected in parents:
    try:
      info = selected.lstat()
    except FileNotFoundError:
      require(missing_parents, 'OWNER postimage parent missing')
      break
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and not info.st_mode & 0o022, 'Unowned OWNER postimage parent')
  return path


def observe_file(root, name, item, deadline):
  budget(deadline)
  raw = regular(safe_path(root, name), item['bytes'], item['mode'])
  require(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'],
          'Selected root postimage differs')
  budget(deadline)


def root_admission(top, config, deadline):
  enrolled, context = config['enrollment'], config['context']
  item = config['preparation']
  observe_file(top, item['path'], {'bytes': item['bytes'], 'sha256': item['sha256'], 'mode': 0o600}, deadline)
  names = enrolled['filesystem']['subvolumes']
  root = safe_path(top, names['root'])
  home = safe_path(top, names['home'])
  require(root.is_dir() and not root.is_symlink() and home.is_dir() and not home.is_symlink(),
          'Selected OWNER subvolumes missing')
  for name, item in config['root_postimages'].items():
    observe_file(root, name, item, deadline)
  generated = render(enrolled)
  for name, item in generated['files'].items():
    if name.startswith('home/shieldqual/'):
      # User-owned contents are mutable after enrollment. This is not a home
      # content hash or writable-user-environment qualification.
      continue
    raw = regular(safe_path(root, name), len(item['data']), item['mode'])
    require(raw == item['data'], 'Enrolled OWNER system configuration differs')
  for name, item in generated['private_files'].items():
    observe_file(root, name, item, deadline)
  for name, target in generated['links'].items():
    path = safe_path(root, name)
    require(path.is_symlink() and os.readlink(path) == target, 'OWNER activation link differs')
  for name in generated['removals']:
    path = safe_path(root, name, missing_parents=True)
    require(not path.exists() and not path.is_symlink(), 'Qualification policy remains in OWNER root')
  for name, digest in context['sources_sha256'].items():
    raw = regular(safe_path(root, str(INSTALL.relative_to('/')) + '/' + name), 1024**2, 0o644)
    require(hashlib.sha256(raw).hexdigest() == digest, 'Installed OWNER source differs')
  network = enrolled['ethernet']
  for name, item in [(MODULE, network['module']), *network['firmware'].items()]:
    observe_file(root, name, item | {'mode': 0o644}, deadline)
  budget(deadline)


def admit_initial_ram():
  require(os.getpid() == 1 and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0
          and sys.argv[1:] == ['--run'], 'Initial RAM OWNER PID1 required')
  require(os.uname().machine == 'aarch64' and os.uname().release == '7.1.0-shield-bringup'
          and INSTALL.resolve(strict=True) == INSTALL, 'Matched OWNER initial RAM required')
  tree = Path('/sys/firmware/devicetree/base')
  require(sysfs(tree / 'compatible') == b'nvidia,p2894-0050-a04\0nvidia,darcy\0nvidia,tegra210\0'
          and sysfs(tree / 'model') == b'NVIDIA Shield TV (Darcy A04)\0'
          and sysfs(tree / 'pcie@1003000/status') == b'okay\0', 'Matched Darcy/PCIe device tree required')
  require(Path('/proc/self/task/1/children').read_text().strip() == '', 'Initial RAM has child processes')
  # /run must be separate RAM so switch_root can carry the local boot context.
  fd = os.open('/run', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    require(magic(fd) == 0x01021994, 'Initial RAM runtime filesystem differs')
  finally:
    os.close(fd)


def load():
  admit_initial_ram()
  raw = regular(CONFIG, 8 * 1024**2, 0o600)
  config = decode(raw)
  enrolled, context = validate_boot(config)
  context_raw = canonical(context)
  tokens = Path('/proc/cmdline').read_text().split()
  admit_normal_command_line(tokens, raw, context_raw, enrolled)
  for prefix, value in [('shield.omarchy-owner=', 'shield.omarchy-owner=1'),
      ('shield.owner-boot=', 'shield.owner-boot=' + hashlib.sha256(raw).hexdigest()),
      ('shield.owner-context=', 'shield.owner-context=' + hashlib.sha256(context_raw).hexdigest()),
      ('systemd.unit=', 'systemd.unit=graphical.target'),
      ('modprobe.blacklist=', 'modprobe.blacklist=r8169')]:
    require([token for token in tokens if token.startswith(prefix)] == [value],
            'OWNER initial RAM command line binding differs')
  for name, digest in context['sources_sha256'].items():
    require(hashlib.sha256(regular(INSTALL / name, 1024**2, 0o644)).hexdigest() == digest,
            'Initial RAM source closure differs')
  return config, context_raw


def wait_storage(bundle, deadline):
  if 'emmc' in bundle.profile['filesystem']:
    from native_emmc_storage import discover
  else:
    from native_root_storage import discover
  # Subscribe before the first snapshot to avoid missing a device-add race.
  events = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC
                         | socket.SOCK_NONBLOCK, 15)
  try:
    events.bind((os.getpid(), 1))
    while True:
      budget(deadline)
      observed = discover(bundle)
      if observed is not None:
        return observed
      remaining = (deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / SECOND
      require(remaining > 0, 'Storage discovery deadline expired')
      available, _, _ = select.select([events], [], [], remaining)
      require(available, 'Selected storage was not discovered before deadline')
      raw, _, flags, address = events.recvmsg(65536)
      require(not flags & socket.MSG_TRUNC and address[0] == 0 and raw,
              'Storage kernel event malformed or truncated')
  finally:
    events.close()


def wait_usb(bundle, deadline):
  require('usb' in bundle.profile['filesystem'], 'USB preparation requires USB enrollment')
  return wait_storage(bundle, deadline)


def close_initial_fds():
  require(Path('/proc/self/task/1/children').read_text().strip() == '',
          'Initial RAM child remained at handoff')
  descriptors = [int(path.name) for path in Path('/proc/self/fd').iterdir()]
  for fd in descriptors:
    if fd >= 3:
      try:
        os.close(fd)
      except OSError:
        # The scandir enumeration FD has already been closed.
        require(not Path('/proc/self/fd/' + str(fd)).exists(), 'Initial FD closure failed')


def main():
  os.umask(0o077)
  config, context_raw = load()
  deadline = 120 * SECOND  # Startup bound only; normal PID1 has no PC lease.
  budget(deadline)
  from native_mounts import MountDomain
  fs = config['enrollment']['filesystem']
  if 'emmc' in fs:
    from native_emmc_storage import EmmcRoot as Root
    storage = {'emmc_storage': fs['emmc']}
  else:
    from native_boot_context import USB_STORAGE
    from native_root_storage import USBRoot as Root
    storage = {'usb_storage': USB_STORAGE}
  bundle = SimpleNamespace(epoch='early', phase='owner', profile=config['enrollment'],
                           configuration=storage)
  device = Root(bundle, wait_storage(bundle, deadline))
  domain = MountDomain(device)
  try:
    top = domain.readonly_top(deadline)
    root_admission(top, config, deadline)
    root = domain.owner_candidate(deadline)
    domain.check()
    RUNTIME.mkdir(mode=0o700)  # Never adopt a prior context or attempt.
    with (RUNTIME / 'context.json').open('xb') as stream:
      stream.write(context_raw)
      stream.flush()
      os.fsync(stream.fileno())
    budget(deadline)
    domain.check()
    device.close()  # Success retains RW mounts; never call restrict_readonly.
    close_initial_fds()
    budget(deadline)
    os.execve('/usr/bin/switch_root', ['/usr/bin/switch_root', str(root), '/usr/lib/systemd/systemd'],
      {'PATH': '/usr/bin:/bin', 'HOME': '/', 'TERM': 'linux', 'LANG': 'C.UTF-8'})
  finally:
    device.close()


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    if os.getpid() != 1:
      raise SystemExit(65)
    # No shell, alternate root, retry, replay or hardware watchdog open here.
    # Retain failed RAM state for the existing inherited hardware reset path;
    # this is not a claim that reset or durable recovery has been qualified.
    while True:
      time.sleep(1)
