"""Owned recovery receiver for an admitted native systemd qualification.

This is not an installer or a general reboot endpoint. The guardian retains its
watchdog fd; this process never opens, feeds, closes or retimes that watchdog.
"""
import array
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, '/usr/lib/omarchy/shield/qualification')
from guardian_binding import INSTALL, PROFILE, load_runtime, owned_file
from guardian_client import GuardianClient, MAGIC, REQUEST, SECOND, STATUS, VERSION
from usb_root_profile import digest, require

DIRECTORY = Path('/run/shield-recovery')
ENDPOINT = DIRECTORY / 'request.sock'
RECOVER_FAULT, RECOVER_QUIESCE = 4, 5
# Exact selected Linux UAPI: struct btrfs_ioctl_fs_info_args is 1024 bytes.
BTRFS_IOC_FS_INFO = 0x8400941f
BLKROSET, BLKROGET = 0x125d, 0x125e
STOP_UNITS = ['shield-qualification-desktop.service', 'user@1001.service',
  'user-runtime-dir@1001.service', 'NetworkManager.service', 'bluetooth.service',
  'systemd-timesyncd.service', 'systemd-networkd.service', 'systemd-tmpfiles-clean.service']


def now():
  return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def private_directory(path):
  info = path.lstat()
  require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
          and info.st_uid == info.st_gid == 0, 'Untrusted recovery directory')


def record(phase, **fields):
  data = json.dumps({'phase': phase, 'boot_ready': False, **fields}, sort_keys=True).encode() + b'\n'
  temporary = DIRECTORY / 'state.tmp'
  fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(fd, 'wb') as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
  os.replace(temporary, DIRECTORY / 'state.json')


def unescape(value):
  return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)


def mounts(text):
  result = []
  for line in text.splitlines():
    before, after = line.split(' - ', 1)
    fields, fs = before.split(), after.split()
    require(len(fields) >= 6 and len(fs) == 3, 'Malformed kernel mount table')
    result.append({'id': int(fields[0]), 'parent': int(fields[1]), 'dev': fields[2],
      'root': unescape(fields[3]), 'path': unescape(fields[4]),
      'options': set(fields[5].split(',')), 'filesystem': fs[0],
      'source': unescape(fs[1]), 'super_options': set(fs[2].split(','))})
  return result


def table():
  return mounts(Path('/proc/self/mountinfo').read_text())


def filesystem_identity(path, expected):
  descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    data = bytearray(1024)
    fcntl.ioctl(descriptor, BTRFS_IOC_FS_INFO, data, True)
    require(struct.unpack_from('<Q', data, 8)[0] == 1
            and str(uuid.UUID(bytes=bytes(data[16:32]))) == expected, 'Unowned or multi-device Btrfs mount')
  finally:
    os.close(descriptor)


def block_device(source):
  path = Path(source).resolve(strict=True)
  require(path.is_relative_to(Path('/dev')), 'Unresolved block source')
  info = path.stat()
  require(stat.S_ISBLK(info.st_mode), 'Filesystem source is not a block device')
  return path, info.st_rdev


def usb_ancestry(rdev, expected):
  node = Path(f'/sys/dev/block/{os.major(rdev)}:{os.minor(rdev)}').resolve(strict=True)
  require(node.is_relative_to(Path('/sys/devices')), 'Block sysfs identity differs')
  for ancestor in [node, *node.parents]:
    vendor, product = ancestor / 'idVendor', ancestor / 'idProduct'
    if vendor.is_file() and product.is_file():
      if {'vendor': vendor.read_text().strip(), 'product': product.read_text().strip()} == expected:
        return node
  raise ValueError('Root block device is outside the admitted USB ancestry')


def owned_mounts(profile):
  expected = profile['filesystem']
  all_mounts = table()
  roots = [entry for entry in all_mounts if entry['path'] == '/']
  require(len(roots) == 1 and roots[0]['filesystem'] == 'btrfs'
          and roots[0]['root'] == '/' + expected['subvolumes']['root'], 'Qualification root mount differs')
  filesystem_identity('/', expected['uuid'])
  device, rdev = block_device(roots[0]['source'])
  usb_ancestry(rdev, expected['usb'])
  owned = []
  for entry in all_mounts:
    if entry['filesystem'] != 'btrfs':
      continue
    other, other_rdev = block_device(entry['source'])
    require(other_rdev == rdev, 'Unexpected additional Btrfs filesystem')
    filesystem_identity(entry['path'], expected['uuid'])
    owned.append(entry)
  require({'/', '/home', '/var/log'}.issubset({entry['path'] for entry in owned}), 'Required candidate mounts absent')
  for mountpoint, purpose in [('/home', 'home'), ('/var/log', 'log')]:
    entries = [entry for entry in owned if entry['path'] == mountpoint]
    require(len(entries) == 1 and entries[0]['root'] == '/' + expected['subvolumes'][purpose],
            'Candidate home/log mount differs')
  return device, rdev, owned


def artifacts(profile):
  data = json.loads(owned_file(INSTALL / 'artifacts.json', 0o600).read_text())
  require(data['format_version'] == 1 and data['candidate'] == profile['candidate']
          and data['profile_sha256'] == digest(owned_file(PROFILE, 0o600))
          and data['role'] == profile['role'] and data['compiled_enabled'] is True
          and data['source_inputs_sha256'] == profile['sources'], 'Artifact/profile identity differs')
  names = {'shield-guardian', 'shield-restart-recovery', 'guardian_client.py',
           'guardian_binding.py', 'qualification_recovery.py', 'usb_root_profile.py', 'overlay-manifest.json'}
  require(set(data['files']) == names, 'Incomplete runtime artifact closure')
  for name, identity in data['files'].items():
    mode = 0o700 if name.startswith('shield-') else (0o600 if name.endswith('.json') else 0o644)
    path = owned_file(INSTALL / name, mode)
    require(path.stat().st_size == identity['bytes'] and digest(path) == identity['sha256'], 'Runtime artifact differs')
    if name.endswith('.py'):
      require(identity['sha256'] == profile['sources']['tools/' + name], 'Installed Python source differs')
    if name == 'shield-restart-recovery':
      require(identity == profile['recovery_helper'], 'Recovery helper sidecar differs')
  return data


def startup_policy(profile):
  overlay = owned_file(INSTALL / 'overlay-manifest.json', 0o600)
  require(digest(overlay) == profile['overlay_sha256'], 'Startup policy binding differs')
  policy = json.loads(overlay.read_text())['policy']
  require(policy['payload_candidate_id'] == profile['filesystem']['candidate_id']
          and policy['guardian_required_before_desktop'] is True
          and policy['account']['uid'] == 1001 and policy['account']['administrative'] is False,
          'Startup ownership policy differs')
  masks = policy['masked_services']
  require({'power-profiles-daemon.service', 'udisks2.service', 'sleep.target',
           'sshd.service', 'sddm.service', 'getty@tty1.service'}.issubset(masks), 'Safety masks missing')
  for unit in masks:
    require(re.fullmatch('[A-Za-z0-9@_.-]+\\.(service|target)', unit)
            and unit not in {'shield-guardian.service', 'shield-qualification-recovery.service'}, 'Unsafe mask name')
    path = Path('/etc/systemd/system') / unit
    info = path.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0
            and os.readlink(path) == '/dev/null', 'Required service mask was not applied')
    result = subprocess.run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', unit],
      stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=2)
    require(result.returncode == 0 and result.stdout.strip() in {'inactive', 'failed'}, 'Masked unit remains active')
  result = subprocess.run(['/usr/bin/systemctl', 'show', '--property=RuntimeWatchdogUSec',
    '--property=RebootWatchdogUSec', '--property=KExecWatchdogUSec'],
    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=2)
  values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
  require(result.returncode == 0 and values == {'RuntimeWatchdogUSec': '0',
          'RebootWatchdogUSec': '0', 'KExecWatchdogUSec': '0'}, 'PID1 hardware watchdog ownership is not disabled')


def notify_ready():
  path = os.environ.get('NOTIFY_SOCKET', '')
  require(path and path[0] in ('/', '@'), 'Systemd readiness endpoint absent')
  endpoint = '\0' + path[1:] if path[0] == '@' else path
  with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as channel:
    channel.setblocking(False)
    message = b'READY=1\nSTATUS=bound qualification recovery receiver listening'
    require(channel.sendto(message, endpoint) == len(message), 'Recovery readiness delivery failed')


def command(arguments, deadline, limit=3):
  require(now() + SECOND < deadline, 'Cleanup deadline exhausted')
  timeout = min(limit, (deadline - now()) / SECOND - 0.5)
  with (DIRECTORY / 'command.log').open('wb') as log:
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=log,
      stderr=subprocess.STDOUT, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, start_new_session=True)
    try:
      status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
      os.killpg(process.pid, signal.SIGKILL)
      try:
        process.wait(timeout=0.5)
      except subprocess.TimeoutExpired:
        pass
      raise
  require(status == 0, 'Owned cleanup command failed')


def stop_writers(deadline):
  command(['/usr/bin/systemctl', '--no-block', 'stop', *STOP_UNITS], deadline)
  # This fixed slice contains the temporary user, never the guardian/recovery.
  def populated():
    return user_cgroup('cgroup.events').splitlines().count('populated 1') == 1

  until = min(deadline - 5 * SECOND, now() + 7 * SECOND)
  while populated() and now() < until:
    time.sleep(0.1)
  if populated():
    # Fixed owned cgroup only; no arbitrary PID/name/global kill.
    user_cgroup('cgroup.kill', write=True)
  for _attempt in range(20):
    if not populated():
      return
    require(now() < deadline - 3 * SECOND, 'User writers did not stop')
    time.sleep(0.1)
  raise ValueError('User cgroup remains populated')


def user_cgroup(name, write=False):
  """Access only the fixed root-owned cgroup2 slice through no-follow fds."""
  require((name, write) in {('cgroup.events', False), ('cgroup.kill', True)}, 'Wrong cgroup operation')
  matches = [entry for entry in table() if entry['path'] == '/sys/fs/cgroup']
  require(len(matches) == 1 and matches[0]['filesystem'] == 'cgroup2'
          and matches[0]['root'] == '/', 'Unified host cgroup mount required')
  descriptor = os.open('/sys/fs/cgroup', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    library = ctypes.CDLL(None, use_errno=True)
    library.fstatfs.argtypes, library.fstatfs.restype = [ctypes.c_int, ctypes.c_void_p], ctypes.c_int
    storage = (ctypes.c_long * 32)()
    require(library.fstatfs(descriptor, ctypes.byref(storage)) == 0 and storage[0] == 0x63677270,
            'Cgroup fd is outside cgroup2')
    for component in ['user.slice', 'user-1001.slice']:
      info = os.fstat(descriptor)
      require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'Unowned cgroup ancestor')
      try:
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor)
      except FileNotFoundError:
        return 'populated 0\n'  # Already removed by PID1; no effect to replay.
      os.close(descriptor)
      descriptor = child
    info = os.fstat(descriptor)
    require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'Unowned qualification slice')
    try:
      leaf = os.open(name, (os.O_WRONLY if write else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=descriptor)
    except FileNotFoundError:
      # A disappearing slice is harmless only when its events file is gone too.
      if not os.path.exists('/proc/self/fd/' + str(descriptor) + '/cgroup.events'):
        return 'populated 0\n'
      raise
    with os.fdopen(leaf, 'w' if write else 'r') as stream:
      info = os.fstat(stream.fileno())
      require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
              and not info.st_mode & 0o022, 'Unowned cgroup control file')
      if write:
        stream.write('1\n')
        return ''
      result = stream.read(4096)
      require(sum(line in ('populated 0', 'populated 1') for line in result.splitlines()) == 1,
              'Malformed cgroup state')
      return result
  finally:
    os.close(descriptor)


def sync_root():
  descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
  try:
    library = ctypes.CDLL(None, use_errno=True)
    library.syncfs.argtypes, library.syncfs.restype = [ctypes.c_int], ctypes.c_int
    require(library.syncfs(descriptor) == 0, 'Root syncfs failed')
  finally:
    os.close(descriptor)


def readonly(profile, deadline):
  device, rdev, entries = owned_mounts(profile)
  sync_root()  # May block in kernel I/O; separate guardian remains responsible.
  require(now() < deadline, 'syncfs exceeded cleanup budget')
  for path in ['/home', '/var/log']:
    command(['/usr/bin/umount', path], deadline)
  entries = [entry for entry in table() if entry['filesystem'] == 'btrfs']
  # Subvolumes can have distinct st_dev; use actual block SOURCE and FS_INFO.
  for entry in sorted(entries, key=lambda entry: len(entry['path']), reverse=True):
    _path, identity = block_device(entry['source'])
    require(identity == rdev, 'Filesystem source changed during cleanup')
    filesystem_identity(entry['path'], profile['filesystem']['uuid'])
    command(['/usr/bin/mount', '-o', 'remount,ro', entry['path']], deadline)
  remaining = [entry for entry in table() if entry['filesystem'] == 'btrfs']
  require(remaining and all('ro' in entry['options'] and 'ro' in entry['super_options']
          for entry in remaining), 'Writable Btrfs alias remains')
  # Block-level write protection supplements filesystem RO across namespaces.
  node = usb_ancestry(rdev, profile['filesystem']['usb'])
  require((node / 'partition').is_file(), 'Expected the prepared USB partition')
  parent = node.parent
  siblings = [entry for entry in parent.iterdir() if entry.is_dir() and (entry / 'partition').is_file()]
  require(siblings == [node], 'Unexpected additional USB partitions')
  nodes = [(device, rdev)]
  parent_major, parent_minor = map(int, (parent / 'dev').read_text().strip().split(':'))
  nodes.append((Path('/dev') / parent.name, os.makedev(parent_major, parent_minor)))
  for path, expected_device in nodes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
      info = os.fstat(descriptor)
      require(stat.S_ISBLK(info.st_mode) and info.st_rdev == expected_device, 'Block identity changed')
      one = array.array('i', [1])
      fcntl.ioctl(descriptor, BLKROSET, one, True)
      actual = array.array('i', [0])
      fcntl.ioctl(descriptor, BLKROGET, actual, True)
      require(actual[0] == 1, 'USB block device did not become read-only')
    finally:
      os.close(descriptor)
  require(now() < deadline, 'Cleanup completed outside budget')


def cleanup_deadline(profile, owner_pid, disconnected=False):
  deadline = min(now() + 45 * SECOND, profile['timing']['final_seconds'] * SECOND)
  client = GuardianClient(profile['candidate'], Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 2)
  try:
    status = client.request(STATUS)
    require(client.owner_pid == owner_pid, 'Cleanup guardian owner changed')
    current = now()
    require(0 < status['now_ns'] <= current and current - status['now_ns'] <= SECOND
            and 0 < status['cleanup_cutoff_ns'] <= 600 * SECOND,
            'Stale or unbounded cleanup status')
    deadline = min(deadline, status['cleanup_cutoff_ns'])
  except (OSError, ValueError):
    # A pre-open FAULT may be delivered immediately before the owner exits.
    # Confirm death before falling back, still before any cleanup effects.
    if not disconnected:
      try:
        descriptor = os.pidfd_open(owner_pid, 0)
      except ProcessLookupError:
        disconnected = True
      else:
        try:
          disconnected = bool(select.select([descriptor], [], [], 0)[0])
        finally:
          os.close(descriptor)
    # Only confirmed owner/channel loss permits the fixed final-cutoff fallback.
    # A delayed QUIESCE must never manufacture a fresh owner window.
    if not disconnected:
      raise
  finally:
    client.close()
  require(now() + SECOND < deadline, 'Existing cleanup budget exhausted')
  return deadline


def cleanup(profile, reason, owner_pid, disconnected=False):
  deadline = cleanup_deadline(profile, owner_pid, disconnected)
  record('cleanup-started', candidate=profile['candidate'], reason=reason,
         cleanup_deadline_ns=deadline, readonly_state_verified=False)
  stop_writers(deadline)
  readonly(profile, deadline)
  record('filesystem-readonly', candidate=profile['candidate'], reason=reason,
         readonly_state_verified=True, root_unmounted=False, hardware_powerloss_qualified=False)
  helper = INSTALL / 'shield-restart-recovery'
  require(digest(helper) == profile['recovery_helper']['sha256'], 'Recovery helper changed')
  require(now() + SECOND // 4 < deadline, 'No existing budget for recovery dispatch')
  timeout = min(2, (deadline - now()) / SECOND - 0.1)
  # A returned/refused restart never becomes a successful reboot receipt. No
  # global shutdown or unguarded reboot follows; the finite guardian persists.
  try:
    completed = subprocess.run([str(helper)], stdin=subprocess.DEVNULL,
      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    record('restart-returned', candidate=profile['candidate'], helper_exit=completed.returncode,
           readonly_state_verified=True, root_unmounted=False, reboot_observed=False)
  except subprocess.TimeoutExpired:
    record('restart-stalled', candidate=profile['candidate'], readonly_state_verified=True,
           root_unmounted=False, reboot_observed=False)


def main():
  profile = load_runtime()
  artifacts(profile)
  startup_policy(profile)
  owned_mounts(profile)  # No stopping/remounting before full native admission.
  private_directory(DIRECTORY)
  require(not ENDPOINT.exists() and not ENDPOINT.is_symlink(), 'Existing receiver never replaced')
  boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  require(str(uuid.UUID(boot)) == boot, 'Bad boot identity')
  with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC) as listener:
    listener.bind(str(ENDPOINT))
    os.chmod(ENDPOINT, 0o600)
    listener.listen(2)
    record('listening', candidate=profile['candidate'], readonly_state_verified=False)
    notify_ready()
    channel, _ = listener.accept()
    with channel:
      pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
      require(uid == gid == 0 and pid > 1, 'Untrusted recovery sender')
      require(Path('/proc/' + str(pid) + '/exe').resolve(strict=True) == INSTALL / 'shield-guardian',
              'Recovery sender is not the installed guardian')
      handled = False
      while True:
        data, ancillary, flags, _address = channel.recvmsg(REQUEST.size, 0)
        if not data:
          if not handled:
            handled = True
            try:
              cleanup(profile, {'event': 'guardian-disconnected'}, pid, disconnected=True)
            except BaseException as error:
              record('cleanup-failed', error=type(error).__name__, readonly_state_verified=False)
          while True:
            time.sleep(1)
        require(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                and len(data) == REQUEST.size, 'Invalid recovery packet')
        magic, version, operation, reason, candidate, instance = REQUEST.unpack(data)
        require(magic == MAGIC and version == VERSION and candidate == profile['candidate'].encode()
                and instance == boot.encode(), 'Recovery packet identity differs')
        require((operation == RECOVER_FAULT and 1 <= reason <= 9)
                or (operation == RECOVER_QUIESCE and reason == 0), 'Unknown recovery operation')
        if not handled:
          handled = True  # No cleanup replay after any uncertain result.
          try:
            cleanup(profile, {'operation': operation, 'fault': reason}, pid)
          except BaseException as error:
            record('cleanup-failed', error=type(error).__name__, readonly_state_verified=False)
        # No reply: the guardian treats unexpected incoming bytes as a fault.


if __name__ == '__main__':
  try:
    main()
  except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
    print('Qualification recovery refused: ' + type(error).__name__, file=sys.stderr)
    raise SystemExit(64)
