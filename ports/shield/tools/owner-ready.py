"""Finite local startup observation, independent of carrier, DHCP or this PC.

PID1 owns the hardware watchdog. This service never opens it and never claims
that initial ownership proves sustained feeding or a qualified reboot lifecycle.
The cooling daemon continues after this startup observer has exited.
"""
from pathlib import Path
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time

INSTALL = Path('/usr/lib/omarchy/shield/owner')
RUNTIME = Path('/run/shield-owner')
UNIT = 'shield-owner-ready.service'
SECOND = 1_000_000_000
sys.path.insert(0, str(INSTALL))
from owner_profile import require
from owner_runtime import admit, decode, regular, sysfs


def cooling(record, digest, now):
  require(type(record) is dict and record.get('context_sha256') == digest
          and record.get('state') == 'healthy', 'Cooling is not healthy in this boot')
  stamp = record.get('boottime_ns')
  require(type(stamp) is int and 0 < stamp <= now and now - stamp <= 3 * SECOND,
          'Cooling observation is stale')


def mounts(raw, enrolled):
  require(len(raw) <= 1024 * 1024, 'Mount inventory exceeds bound')
  lines = raw.splitlines()
  require(len(lines) <= 4096, 'Mount inventory exceeds bound')
  selected = {}
  for line in lines:
    left, right = line.split(' - ', 1)
    fields, filesystem = left.split(), right.split()
    if fields[4] in ('/', '/home', '/var/log'):
      require(fields[4] not in selected, 'Stacked OWNER mounts')
      selected[fields[4]] = (fields, filesystem)
  require(set(selected) == {'/', '/home', '/var/log'}, 'OWNER mounts missing')
  sources = set()
  for mount, purpose in [('/', 'root'), ('/home', 'home'), ('/var/log', 'log')]:
    fields, filesystem = selected[mount]
    options = set(fields[5].split(','))
    super_options = set(filesystem[2].split(','))
    expected = '/' + enrolled['filesystem']['subvolumes'][purpose]
    require(filesystem[0] == 'btrfs' and 'rw' in options and 'ro' not in options
            and 'rw' in super_options and 'ro' not in super_options
            and fields[3] == expected
            and 'subvol=' + expected in filesystem[2].split(','), 'Wrong OWNER mount')
    if mount == '/home':
      require({'nosuid', 'nodev'} <= options and 'noexec' not in options,
              'OWNER home mount policy differs')
    sources.add(filesystem[1])
  require(len(sources) == 1, 'OWNER mount backing sources differ')


class ObservationClosureError(RuntimeError):
  pass


def query(argv, deadline):
  require(time.monotonic() + 0.1 < deadline, 'Startup observation budget exhausted')
  child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, start_new_session=True,
    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
  timed = False
  try:
    output, errors = child.communicate(timeout=min(3, deadline - time.monotonic()))
  except subprocess.TimeoutExpired:
    timed = True
    try:
      os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
      pass
    # An unreaped client is fatal, never another observation attempt.
    try:
      child.communicate(timeout=2)
    except subprocess.TimeoutExpired as error:
      raise ObservationClosureError('Owned observation closure unknown') from error
  try:
    os.killpg(child.pid, 0)
    gone = False
  except ProcessLookupError:
    gone = True
  if not gone or timed:
    raise ObservationClosureError('Owned observation timed out or group remains')
  require(child.returncode == 0 and not errors and len(output) <= 16384,
          'Local service observation failed')
  result = {}
  for line in output.decode('ascii').splitlines():
    key, value = line.split('=', 1)
    require(key not in result, 'Duplicate service observation')
    result[key] = value
  return result


def service(name, deadline, user=False):
  argv = ['/usr/bin/systemctl', 'show', name, '--property=ActiveState,SubState,MainPID']
  if user:
    argv = ['/usr/bin/runuser', '-u', 'shieldqual', '--', '/usr/bin/env',
      'XDG_RUNTIME_DIR=/run/user/1001',
      'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus',
      '/usr/bin/systemctl', '--user', *argv[1:]]
  result = query(argv, deadline)
  require(set(result) == {'ActiveState', 'SubState', 'MainPID'}
          and result['ActiveState'] == 'active', 'Required local service is not active')
  require(re.fullmatch('[0-9]{1,10}', result['MainPID']), 'Malformed service PID')
  return int(result['MainPID']), result['SubState']


def watchdog(deadline):
  device = Path('/dev/watchdog0').stat()
  require(stat.S_ISCHR(device.st_mode), 'Watchdog device missing')
  root = Path('/sys/class/watchdog/watchdog0').resolve(strict=True)
  require(root.is_relative_to(Path('/sys/devices')),
          'Watchdog class path escaped')
  expected = ('%d:%d' % (os.major(device.st_rdev), os.minor(device.st_rdev))).encode('ascii')
  require(sysfs(root / 'dev').strip() == expected, 'Watchdog device identity differs')
  parent = (root / 'device').resolve(strict=True)
  require((parent / 'driver').resolve(strict=True) == Path('/sys/bus/platform/drivers/tegra-wdt')
          and (parent / 'of_node').resolve(strict=True)
              == Path('/sys/firmware/devicetree/base/timer@60005000'),
          'Wrong bound watchdog platform device')
  require(sysfs(parent / 'of_node' / 'compatible') == b'nvidia,tegra210-timer\0',
          'Wrong inherited watchdog provider')
  # CONFIG_WATCHDOG_SYSFS is disabled in the selected kernel. Do not require
  # its absent identity/timeout/state/nowayout attributes or reopen the device.
  # These are effective manager settings, not an observed hardware GETTIMEOUT.
  manager = query(['/usr/bin/systemctl', 'show',
    '--property=RuntimeWatchdogUSec,WatchdogDevice'], deadline)
  require(manager == {'RuntimeWatchdogUSec': '4min', 'WatchdogDevice': '/dev/watchdog0'},
          'PID1 watchdog policy differs')
  matches = 0
  entries = list(Path('/proc/1/fd').iterdir())
  require(len(entries) <= 4096, 'PID1 FD inventory exceeds bound')
  for entry in entries:
    try:
      info = entry.stat()
    except FileNotFoundError:
      continue
    if stat.S_ISCHR(info.st_mode) and info.st_rdev == device.st_rdev:
      matches += 1
  require(matches == 1, 'PID1 must hold exactly one inherited watchdog FD')


def ssh_listener(pid):
  require(pid > 1 and Path('/proc/' + str(pid) + '/exe').resolve(strict=True)
          == Path('/usr/bin/sshd'), 'Stock SSH server identity differs')
  sockets = set()
  entries = list(Path('/proc/' + str(pid) + '/fd').iterdir())
  require(len(entries) <= 4096, 'SSH FD inventory exceeds bound')
  for entry in entries:
    try:
      target = os.readlink(entry)
    except FileNotFoundError:
      continue
    match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
    if match:
      sockets.add(match[1])
  listeners = 0
  for name in ('tcp', 'tcp6'):
    text = Path('/proc/net/' + name).read_text()
    require(len(text) <= 1024 * 1024, 'Socket inventory exceeds bound')
    for line in text.splitlines()[1:]:
      fields = line.split()
      if fields[1].rsplit(':', 1)[1] == '0016' and fields[3] == '0A' and fields[9] in sockets:
        listeners += 1
  require(listeners > 0, 'SSH server has no port 22 listener')


def observe(admitted, deadline):
  cooling(decode(regular(RUNTIME / 'thermal-health.json', 16384, 0o600)),
          admitted.digest, time.clock_gettime_ns(time.CLOCK_BOOTTIME))
  network = decode(regular(RUNTIME / 'ethernet-ready.json', 16384, 0o600))
  require(network.get('owner_id') == admitted.enrollment['owner_id']
          and network.get('context_sha256') == admitted.digest
          and network.get('matched_driver_bound') is True, 'Ethernet admission incomplete')
  mounts(Path('/proc/self/mountinfo').read_text(), admitted.enrollment)
  watchdog(deadline)
  pid, state = service('sshd.service', deadline)
  require(state == 'running', 'SSH server is not running')
  ssh_listener(pid)
  pid, state = service('wayland-wm@hyprland.desktop.service', deadline, user=True)
  require(pid > 1 and state == 'running'
          and Path('/proc/' + str(pid)).stat().st_uid == 1001,
          'Owner compositor is not running as its user')
  # Recheck cooling after process observations, never publish a stale sample.
  cooling(decode(regular(RUNTIME / 'thermal-health.json', 16384, 0o600)),
          admitted.digest, time.clock_gettime_ns(time.CLOCK_BOOTTIME))


def main():
  os.umask(0o077)
  deadline = time.monotonic() + 60
  admitted = admit(UNIT)
  try:
    while True:
      try:
        observe(admitted, deadline)
        break
      except (FileNotFoundError, ValueError):
        require(time.monotonic() + 1 < deadline, 'Local OWNER startup deadline expired')
        time.sleep(1)
    value = {'purpose': 'omarchy-shield-owner', 'owner_id': admitted.enrollment['owner_id'],
      'context_sha256': admitted.digest, 'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME),
      'local_startup_ready': True, 'PID1_watchdog_fd_observed': True,
      'hardware_GETTIMEOUT_observed': False, 'sustained_watchdog_feeding_qualified': False, 'watchdog_lifecycle_qualified': False,
      'DHCP_address_observed': False, 'SSH_login_qualified': False}
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    fd = os.open('ready.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=admitted.runtime_fd)
    try:
      require(os.write(fd, raw) == len(raw), 'Short readiness record')
      os.fsync(fd)
    finally:
      os.close(fd)
    os.fsync(admitted.runtime_fd)
    if 'emmc' in admitted.enrollment['filesystem']:
      from owner_internal_ack import acknowledge_ready
      acknowledge_ready(admitted, value)
  finally:
    os.close(admitted.runtime_fd)


if __name__ == '__main__':
  try:
    main()
  except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ObservationClosureError):
    raise SystemExit(65)
