#!/usr/bin/env python3
"""Check repository-local inputs against the checksums used by builds."""
import hashlib
import json
from pathlib import Path
import re
import shlex


def main():
  port = Path(__file__).resolve().parent
  repository = port.parent.parent
  for lock_path in port.glob('kernel*.lock.json'):
    profile = json.loads(lock_path.read_text())
    lock = profile['kernel']
    entries = lock.get('patches', []) + lock.get('device_tree_overlays', []) + [profile['hardware_matrix']]
    for entry in entries:
      path = (repository / entry['path']).resolve()
      if not path.is_relative_to(repository) or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
        raise SystemExit(f"Kernel input checksum mismatch: {entry['path']}")
  recipe = (port / 'omarchy-shield/PKGBUILD').read_text()
  def array(name):
    match = re.search(r'^' + name + r'=\((.*?)\)', recipe, flags=re.M | re.S)
    if not match:
      raise SystemExit(f'Missing package input array: {name}')
    return shlex.split(match.group(1))
  sources, checksums = array('source'), array('sha256sums')
  if len(sources) != len(checksums):
    raise SystemExit('Package source/checksum counts differ')
  for name, expected in zip(sources, checksums):
    path = port / name if name in ('hardware.json', 'hardware-darcy.json', 'hardware-darcy-a08.json', 'collect-shield-linux.py') else port / 'omarchy-shield' / name
    if not path.resolve().is_relative_to(port) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
      raise SystemExit(f'Platform package checksum mismatch: {name}')
  harvest = json.loads((port / 'harvest/firmware.json').read_text())
  references = {entry['path']: entry for entry in harvest['artifacts']}
  for firmware_path in port.glob('firmware-darcy*.lock.json'):
    firmware = json.loads(firmware_path.read_text())
    if firmware['board_variant'] not in ('darcy-t210-a04', 'darcy-t210-a08') or firmware['installed_into_runtime'] is not False:
      raise SystemExit('Firmware lock must describe inactive Darcy revision inputs')
    board = 'a04' if firmware['board_variant'] == 'darcy-t210-a04' else 'a08'
    for entry in firmware['entries']:
      reference = references[entry['input_path']]
      if (entry['bytes'], entry['sha256']) != (reference['bytes'], reference['sha256']) or entry['activation_allowed'] is not False:
        raise SystemExit('Firmware staging differs from its harvested provenance')
      request = entry.get('runtime_request') or ''
      if 'p2894-0050-' in request and ('p2894-0050-' + board) not in request:
        raise SystemExit('Radio calibration request names a different Darcy revision')
  print('Kernel, package and inactive firmware inputs match their checksums and provenance.')


if __name__ == '__main__':
  main()
