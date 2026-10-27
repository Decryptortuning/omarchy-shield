"""One local OWNER Ethernet admission; no DHCP wait, SSH authority or watchdog fd.

The service admits the actual onboard PCI function before manually loading the
matched driver. NetworkManager then owns addressing using the generated keyfile.
Every effect requires an enrolled OWNER boot; the C qualification is refused.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import signal
import stat
import struct
import subprocess
import sys
import time

INSTALL = Path('/usr/lib/omarchy/shield/owner')
RUNTIME = Path('/run/shield-owner')
SYSFS_MAGIC = 0x62656572
UNIT = 'shield-owner-ethernet.service'
sys.path.insert(0, str(INSTALL))
from owner_profile import MODULE, require
from owner_runtime import regular, sysfs, admit as admit_owner


def choose_endpoint(rows):
  """Pure selection. IDs are observed, not inferred from the Shield label."""
  require(type(rows) is list and len(rows) <= 256, 'PCI inventory bound')
  selected = [row for row in rows if row['vendor'] == '0x10ec'
              and row['device'] == '0x8168' and row['class'] == '0x020000']
  require(len(selected) == 1, 'Exactly one approved onboard Ethernet function required')
  result = selected[0]
  require(result['onboard_controller'] is True and result['driver'] is None,
          'Ethernet must be onboard and initially unbound')
  require(type(result['command']) is int and 0 <= result['command'] <= 65535
          and not result['command'] & 4, 'Unexpected pre-bind PCI bus mastering')
  return result


def inventory():
  entries = list(Path('/sys/bus/pci/devices').iterdir())
  require(len(entries) <= 256, 'PCI inventory exceeds bound')
  rows = []
  for entry in entries:
    path = entry.resolve(strict=True)
    require(path.is_relative_to(Path('/sys/devices')), 'PCI device escapes sysfs')
    fields = {name: sysfs(path / name).decode('ascii').strip()
              for name in ('vendor', 'device', 'class')}
    if fields['class'] != '0x020000':
      continue
    raw = sysfs(path / 'config', 64, prefix=True)
    require(len(raw) == 64 and fields['vendor'] == '0x%04x' % struct.unpack_from('<H', raw)[0]
            and fields['device'] == '0x%04x' % struct.unpack_from('<H', raw, 2)[0],
            'PCI identity/config readback differs')
    driver = path / 'driver'
    fields.update(path=str(path), command=struct.unpack_from('<H', raw, 4)[0],
      driver=driver.resolve(strict=True).name if driver.is_symlink() else None,
      onboard_controller=any(parent.name == '1003000.pcie' for parent in path.parents))
    rows.append(fields)
  return rows


def connection(interface):
  require(type(interface) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,15}', interface)
          and interface != 'lo', 'Invalid Ethernet interface name')
  return ('[connection]\nid=Omarchy Shield Ethernet\ntype=ethernet\ninterface-name=' + interface
    + '\nautoconnect=true\n\n[ethernet]\n\n[ipv4]\nmethod=auto\n'
      'dhcp-hostname=omarchy-shield\n\n[ipv6]\nmethod=auto\n').encode('ascii')


def admit():
  admitted = admit_owner(UNIT)
  try:
    tokens = Path('/proc/cmdline').read_text().split()
    require([x for x in tokens if x.startswith('modprobe.blacklist=')]
            == ['modprobe.blacklist=r8169'], 'Initial Ethernet autobind must be inhibited')
    expected = admitted.enrollment['ethernet']
    for name, item in [(MODULE, expected['module']), *expected['firmware'].items()]:
      data = regular(Path('/') / name, item['bytes'], 0o644)
      require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
              'Matched local Ethernet module/firmware differs')
    return admitted.enrollment, admitted.digest
  finally:
    os.close(admitted.runtime_fd)


def save(path, value):
  with path.open('x') as stream:
    json.dump(value, stream, sort_keys=True, separators=(',', ':'))
    stream.write('\n')
    stream.flush()
    os.fsync(stream.fileno())


def load_module(deadline):
  require(type(deadline) in (int, float) and time.monotonic() + 1 < deadline,
          'No existing budget for Ethernet module loading')
  cutoff = min(deadline, time.monotonic() + 12)
  require(time.monotonic() + 1 < cutoff, 'Ethernet module load budget exhausted')
  child = subprocess.Popen(['/usr/bin/insmod', '/' + MODULE], stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
  timed = False
  try:
    output, errors = child.communicate(timeout=max(0.01, cutoff - time.monotonic()))
  except subprocess.TimeoutExpired:
    timed = True
    try:
      os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
      pass
    try:
      output, errors = child.communicate(timeout=3)
    except subprocess.TimeoutExpired:
      save(RUNTIME / 'ethernet-module-client.json', {'positive_wait_observed': False,
        'timed_out': True, 'closure_unknown': True, 'no_replay': True})
      raise
  try:
    os.killpg(child.pid, 0)
    absent = False
  except ProcessLookupError:
    absent = True
  facts = {'actual_wait_exit': child.returncode, 'positive_wait_observed': True,
    'owned_group_absent': absent, 'timed_out': timed,
    'stdout_bytes': len(output), 'stderr_bytes': len(errors),
    'stderr_tail': errors[-4096:].decode('utf-8', errors='replace')}
  save(RUNTIME / 'ethernet-module-client.json', facts)
  require(not timed and child.returncode == 0 and absent and not output and not errors,
          'Owned Ethernet module loader did not complete cleanly')


def main():
  os.umask(0o077)
  deadline = time.monotonic() + 25
  enrollment, digest = admit()
  chosen = choose_endpoint(inventory())
  require(not Path('/sys/module/r8169').exists(), 'Existing NIC module is not adopted')
  require(time.monotonic() + 1 < deadline, 'Ethernet admission budget exhausted before claim')
  # Exclusive claim precedes the first driver effect. It is never replayed.
  save(RUNTIME / 'ethernet-claimed.json', {'purpose': 'omarchy-shield-owner',
    'owner_id': enrollment['owner_id'], 'no_replay': True})
  load_module(deadline)
  path = Path(chosen['path'])
  require((path / 'driver').resolve(strict=True).name == 'r8169', 'Matched driver did not bind')
  net = list((path / 'net').iterdir())
  require(len(net) == 1 and net[0].resolve(strict=True).is_relative_to(path),
          'Bound Ethernet netdev is ambiguous')
  raw = connection(net[0].name)
  require(time.monotonic() + 1 < deadline, 'No existing budget for DHCP profile write')
  directory = Path('/run/NetworkManager/system-connections')
  directory.mkdir(mode=0o700, parents=True, exist_ok=True)
  info = directory.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == 0o700 and directory.resolve(strict=True) == directory,
          'Unowned NetworkManager runtime profile directory')
  target = directory / 'omarchy-shield-wired.nmconnection'
  require(time.monotonic() + 1 < deadline, 'DHCP profile write budget exhausted')
  with target.open('xb') as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
  require(time.monotonic() < deadline, 'Ethernet admission exceeded its existing budget')
  save(RUNTIME / 'ethernet-ready.json', {'purpose': 'omarchy-shield-owner',
    'owner_id': enrollment['owner_id'], 'context_sha256': digest,
    'onboard_identity_admitted': True, 'prebind_busmaster_clear': True,
    'matched_local_module_and_firmware_verified': True, 'matched_driver_bound': True,
    'interface': net[0].name, 'NetworkManager_DHCP_profile_written': True,
    'DHCP_address_observed': False, 'SSH_login_qualified': False})


if __name__ == '__main__':
  try:
    main()
  except (OSError, ValueError, KeyError, subprocess.SubprocessError):
    # No fallback binding, alternate driver, retry, mount or reboot here.
    raise SystemExit(65)
