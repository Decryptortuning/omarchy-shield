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
    path = port / name if name in ('hardware.json', 'hardware-darcy.json', 'collect-shield-linux.py') else port / 'omarchy-shield' / name
    if not path.resolve().is_relative_to(port) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
      raise SystemExit(f'Platform package checksum mismatch: {name}')
  print('Kernel overlays, patches and canonical platform-package inputs match their checksums.')


if __name__ == '__main__':
  main()
