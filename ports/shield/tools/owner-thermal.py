"""OWNER cooling service. Polls sysfs; never owns hardware watchdog.
LM90 temperatures and fan PWM reads may be cached. Completed read cycles are
not independently timed hardware conversions or physical waveform proof.
"""
from pathlib import Path
import json
import os
import re
import socket
import stat
import struct
import sys
import time

INSTALL = Path('/usr/lib/omarchy/shield/owner')
RUNTIME = Path('/run/shield-owner')
DT = Path('/sys/firmware/devicetree/base')
UNIT = 'shield-owner-thermal.service'
SECOND = 1_000_000_000
SYSFS_MAGIC = 0x62656572
TMPFS_MAGIC = 0x01021994
sys.path.insert(0, str(INSTALL))
from owner_profile import require
from owner_runtime import magic, admit as admit_owner


def boot_ns():
  return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def admit():
  require(os.environ.get('WATCHDOG_USEC') == '12000000'
          and os.environ.get('WATCHDOG_PID', str(os.getpid())) == str(os.getpid()),
          'Expected systemd service watchdog required')
  admitted = admit_owner(UNIT)
  return admitted.runtime_fd, admitted.digest


def pinned(path):
  path = path.resolve(strict=True)
  require(path.is_relative_to(Path('/sys/devices')) or path.is_relative_to(DT), 'Sysfs path escaped')
  fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    st = os.fstat(fd)
    require(st.st_uid == st.st_gid == 0 and magic(fd) == SYSFS_MAGIC, 'Unowned sysfs directory')
  except BaseException:
    os.close(fd)
    raise
  return fd


def attribute(fd, name, limit=128):
  require(re.fullmatch('[A-Za-z0-9_,#.-]+', name), 'Attribute must be a direct child')
  child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
  try:
    st = os.fstat(child)
    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
            and magic(child) == SYSFS_MAGIC, 'Unowned sysfs attribute')
    raw = os.read(child, limit + 1)
    require(len(raw) <= limit, 'Sysfs observation exceeds bound')
    return raw
  finally:
    os.close(child)


def integer(raw):
  require(type(raw) is bytes and len(raw) <= 16 and re.fullmatch(rb'-?[0-9]+\n?', raw),
          'Malformed sensor number')
  value = int(raw)
  require(-(2**31) <= value < 2**31, 'Sensor number out of range')
  return value


def listing(base, prefix, label):
  rows = []
  with os.scandir(base) as entries:
    for count, entry in enumerate(entries, 1):
      require(count <= 512, 'Sensor inventory exceeds bound')
      if entry.name.startswith(prefix):
        path = Path(entry.path).resolve(strict=True)
        fd = pinned(path)
        try:
          rows.append({'path': path, 'name': attribute(fd, label)})
        finally:
          os.close(fd)
  return rows


def select(rows, name):
  require(type(rows) is list and len(rows) <= 512, 'Sensor inventory exceeds bound')
  matches = [row for row in rows if row['name'] == (name + '\n').encode('ascii')]
  require(len(matches) == 1, 'Unique required sensor not found')
  return matches[0]['path']


def binding(path, driver, of_path, compatible):
  require((path / 'driver').resolve(strict=True) == driver, 'Wrong sensor driver')
  require((path / 'of_node').resolve(strict=True) == DT / of_path, 'Wrong sensor OF node')
  fd = pinned(DT / of_path)
  try:
    require(attribute(fd, 'compatible') == compatible, 'Wrong sensor compatibility')
  finally:
    os.close(fd)


def topology():
  board = pinned(DT)
  try:
    require(attribute(board, 'compatible') == b'nvidia,p2894-0050-a04\0nvidia,darcy\0nvidia,tegra210\0'
            and attribute(board, 'model') == b'NVIDIA Shield TV (Darcy A04)\0', 'Wrong OWNER board')
  finally:
    os.close(board)
  provider = DT / 'thermal-sensor@700e2000'
  fd = pinned(provider)
  try:
    phandle = attribute(fd, 'phandle')
    require(len(phandle) == 4 and any(phandle), 'Missing SOCTHERM phandle')
    require(attribute(fd, 'compatible') == b'nvidia,tegra210-soctherm\0', 'Wrong SOCTHERM provider')
  finally:
    os.close(fd)
  driver = Path('/sys/bus/platform/drivers/tegra_soctherm')
  matches = []
  with os.scandir(driver) as entries:
    for count, entry in enumerate(entries, 1):
      require(count <= 128, 'Provider inventory exceeds bound')
      if entry.is_symlink():
        path = Path(entry.path).resolve(strict=True)
        if path.is_relative_to(Path('/sys/devices')) and (path / 'of_node').resolve(strict=True) == provider:
          matches.append(path)
  require(len(matches) == 1, 'Unique bound SOCTHERM required')
  binding(matches[0], driver, 'thermal-sensor@700e2000', b'nvidia,tegra210-soctherm\0')
  for name, channel in [('cpu-thermal', 0), ('gpu-thermal', 2)]:
    fd = pinned(DT / 'thermal-zones' / name)
    try:
      require(attribute(fd, 'thermal-sensors') == phandle + struct.pack('>I', channel),
              'Thermal zone provider/channel differs')
    finally:
      os.close(fd)
  fd = pinned(DT / 'pwm-fan')
  pfd = pinned(DT / 'pwm@7000a000')
  try:
    fanph = attribute(fd, 'phandle')
    require(len(fanph) == 4 and any(fanph), 'Missing fan phandle')
    require(attribute(fd, 'pwms') == attribute(pfd, 'phandle') + struct.pack('>3I', 3, 65536, 1)
            and attribute(fd, 'cooling-levels') == struct.pack('>4I', 0, 127, 191, 255),
            'Fan PWM topology differs')
  finally:
    os.close(fd)
    os.close(pfd)
  def walk_error(error):
    raise error
  count = 0
  for root, dirs, files in os.walk(DT / 'thermal-zones', followlinks=False, onerror=walk_error):
    require(len(Path(root).relative_to(DT).parts) <= 10, 'Thermal graph too deep')
    count += len(dirs) + len(files)
    require(count <= 2048, 'Thermal graph too large')
    require(not any((Path(root) / name).is_symlink() for name in dirs + files), 'Redirected thermal graph')
    if 'cooling-device' in files:
      fd = pinned(Path(root))
      try:
        raw = attribute(fd, 'cooling-device', 4096)
        require(raw and len(raw) % 4 == 0 and fanph not in [raw[i:i+4] for i in range(0, len(raw), 4)],
                'Competing fan cooling map')
      finally:
        os.close(fd)


def discover():
  topology()
  zones = listing('/sys/class/thermal', 'thermal_zone', 'type')
  hwmon = listing('/sys/class/hwmon', 'hwmon', 'name')
  paths = {'cpu': select(zones, 'cpu-thermal'), 'gpu': select(zones, 'gpu-thermal'),
           'tmp': select(hwmon, 'tmp451'), 'fan': select(hwmon, 'pwmfan')}
  binding((paths['tmp'] / 'device').resolve(strict=True), Path('/sys/bus/i2c/drivers/lm90'),
          'i2c@7000c000/temperature-sensor@4c', b'ti,tmp451\0')
  binding((paths['fan'] / 'device').resolve(strict=True), Path('/sys/bus/platform/drivers/pwm-fan'),
          'pwm-fan', b'pwm-fan\0')
  fds = {}
  try:
    for name, path in paths.items():
      fds[name] = pinned(path)
    return fds
  except BaseException:
    for fd in fds.values():
      os.close(fd)
    raise


def write_fan(fd, name, raw):
  require((name, raw) in [('pwm1_enable', b'2\n'), ('pwm1', b'255\n')], 'Unapproved fan write')
  child = os.open(name, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
  try:
    st = os.fstat(child)
    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
            and not st.st_mode & 0o022 and magic(child) == SYSFS_MAGIC, 'Unowned fan control')
    require(os.write(child, raw) == len(raw), 'Short fan write')
  finally:
    os.close(child)


def read_sample(fds):
  start = boot_ns()
  values = {name: integer(attribute(fds[device], attr)) for name, device, attr in [
    ('cpu', 'cpu', 'temp'), ('gpu', 'gpu', 'temp'), ('local', 'tmp', 'temp1_input'),
    ('remote', 'tmp', 'temp2_input'), ('remote_fault', 'tmp', 'temp2_fault'),
    ('pwm', 'fan', 'pwm1'), ('enable', 'fan', 'pwm1_enable'), ('rpm', 'fan', 'fan1_input'),
    ('tmp_update_interval_ms', 'tmp', 'update_interval')]}
  return values, start, boot_ns()


def health(values, start, end, asserted):
  require(all(type(v) is int for v in values.values()) and type(start) is int
          and type(end) is int and type(asserted) is int and 0 < asserted <= start <= end
          and end - start <= SECOND, 'Sensor cycle late or malformed')
  require(all(-40000 <= values[k] < 70000 for k in ['cpu', 'gpu', 'local', 'remote']),
          'Temperature exceeds conservative OWNER policy')
  require(values['remote_fault'] == 0 and values['pwm'] == 255 and values['enable'] == 2
          and 0 <= values['rpm'] <= 999999
          and 1 <= values['tmp_update_interval_ms'] <= 3000, 'Invalid cooling observation')
  if values['rpm'] == 0:
    require(end - asserted < 4 * SECOND, 'Fan tach did not establish or was lost')
    return 'warming'
  return 'healthy'


def cycle_delay(start, end, now):
  """Nominal 1s spacing from actual cycle start, without catch-up bursts.

  Scheduler/publication latency may consume that spacing. This does not relax
  the separate <=1s sensor-read bound or the <=3s completed-read freshness.
  The same guard is used immediately before health notifications.
  """
  require(all(type(v) is int for v in (start, end, now)) and 0 < start <= end <= now
          and end - start <= SECOND and now - end <= 3 * SECOND,
          'Late sensor read or stale cooling observation')
  return max(0, start + SECOND - now) / SECOND


def publish(fd, sequence, value, first=False):
  target = 'thermal-health.json'
  try:
    st = os.stat(target, dir_fd=fd, follow_symlinks=False)
  except FileNotFoundError:
    require(first, 'Health record disappeared')
  else:
    require(not first and stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1, 'Health record redirected')
  temporary = '.thermal-health-' + str(sequence)
  out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=fd)
  try:
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    require(os.write(out, raw) == len(raw), 'Short health record write')
    os.fsync(out)
  finally:
    os.close(out)
  os.rename(temporary, target, src_dir_fd=fd, dst_dir_fd=fd)
  os.fsync(fd)


def notify_socket():
  address = os.environ.get('NOTIFY_SOCKET', '')
  require(2 <= len(address) <= 107 and address[0] in '/@' and '\0' not in address,
          'systemd notify address required')
  if address[0] == '@':
    address = '\0' + address[1:]
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
  try:
    sock.connect(address)
  except BaseException:
    sock.close()
    raise
  return sock


def main():
  os.umask(0o077)
  runtime, digest = admit()
  fds = {}
  notifier = None
  try:
    notifier = notify_socket()
    fds = discover()
    claim = os.open('thermal-claimed.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=runtime)
    try:
      raw = b'{"purpose":"omarchy-shield-owner","no_replay":true}\n'
      require(os.write(claim, raw) == len(raw), 'Short thermal claim')
      os.fsync(claim)
    finally:
      os.close(claim)
    os.fsync(runtime)
    write_fan(fds['fan'], 'pwm1_enable', b'2\n')
    write_fan(fds['fan'], 'pwm1', b'255\n')
    asserted = boot_ns()
    ready = False
    sequence = 0
    previous = asserted
    while True:
      sequence += 1
      values, start, end = read_sample(fds)
      require(start >= previous and end - previous <= 3 * SECOND, 'Stale cooling cycle')
      state = health(values, start, end, asserted)
      require(not ready or state == 'healthy', 'Fan tach lost after readiness')
      publish(runtime, sequence, {'state': state, 'sequence': sequence,
        'boottime_ns': end, 'cycle_start_ns': start, 'context_sha256': digest,
        'values': values, 'independent_hardware_conversion_claimed': False}, first=sequence == 1)
      if state == 'healthy':
        cycle_delay(start, end, boot_ns())  # Refuse late/stale health before notifying.
        message = b'WATCHDOG=1\nSTATUS=OWNER cooling healthy'
        if not ready:
          message = b'READY=1\n' + message
        require(notifier.send(message) == len(message), 'Cooling notify failed')
        ready = True
      previous = end
      # A missed nominal wakeup is not itself a thermal fault. Every next
      # iteration establishes a new actual start; no historical tick catch-up.
      time.sleep(cycle_delay(start, end, boot_ns()))
  finally:
    for fd in fds.values():
      os.close(fd)
    if notifier is not None:
      notifier.close()
    os.close(runtime)


if __name__ == '__main__':
  try:
    main()
  except (OSError, ValueError, KeyError, TypeError):
    raise SystemExit(65)
