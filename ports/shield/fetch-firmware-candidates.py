#!/usr/bin/env python3
"""Extract pinned, inactive NVIDIA firmware candidates without running BSP tools."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import struct
import tarfile
import urllib.request


def check_format(data, kind):
  if kind == 'xusb':
    if len(data) < 256 or struct.unpack_from('<I', data, 100)[0] != len(data) or data[104:112] != b'XUSBFW\0\0':
      raise ValueError('Invalid XUSB container header')
    return {'format': kind, 'version_id': hex(struct.unpack_from('<I', data, 72)[0]),
            'created_utc': datetime.datetime.fromtimestamp(struct.unpack_from('<I', data, 44)[0], datetime.timezone.utc).isoformat()}
  if kind == 'falcon':
    magic, version, size, os_offset, data_offset, data_size = struct.unpack_from('<6I', data)
    if magic not in (0x10de, 0x10fe) or version != 1 or size != len(data) or os_offset + 20 > size or data_offset + data_size > size:
      raise ValueError('Invalid Falcon v1 container')
    code, code_size, payload, payload_size, apps = struct.unpack_from('<5I', data, os_offset)
    if any(data_offset + offset + length > size for offset, length in ((code, code_size), (payload, payload_size))):
      raise ValueError('Falcon section exceeds its container')
    return {'format': kind, 'version': version, 'application_count': apps}
  if kind == 'hcd':
    offset, packets = 0, 0
    while offset < len(data):
      if offset + 3 > len(data):
        raise ValueError('Incomplete HCD command header')
      offset += 3 + data[offset + 2]
      packets += 1
      if offset > len(data):
        raise ValueError('Incomplete HCD command payload')
    return {'format': kind, 'command_packets': packets}
  return {}


def extract(tree, item, destination):
  member = tree.getmember(item['path'])
  if not member.isfile() or member.size != item['bytes']:
    raise ValueError('Unexpected archive entry')
  data = tree.extractfile(member).read()
  if hashlib.sha256(data).hexdigest() != item['sha256']:
    raise ValueError('Firmware input checksum mismatch')
  proof = check_format(data, item.get('format'))
  (destination / Path(item['path']).name).write_bytes(data)
  return {**item, 'container_check': proof, 'hardware_qualified': False}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--build-root', required=True, type=Path)
  root = parser.parse_args().build_root.resolve()
  lock = json.loads((Path(__file__).resolve().parent / 'firmware.lock.json').read_text())
  source = lock['source']
  archive = root / 'downloads' / source['filename']
  archive.parent.mkdir(parents=True, exist_ok=True)
  if not archive.exists():
    temporary = archive.with_suffix('.part')
    with urllib.request.urlopen(source['url'], timeout=45) as incoming, temporary.open('wb') as output:
      total = 0
      while block := incoming.read(1024 * 1024):
        total += len(block)
        if total > source['bytes']:
          raise ValueError('Download exceeds its pinned size')
        output.write(block)
    temporary.rename(archive)
  with archive.open('rb') as incoming:
    digest = hashlib.file_digest(incoming, 'sha256').hexdigest()
  if archive.stat().st_size != source['bytes'] or digest != source['sha256']:
    raise SystemExit('NVIDIA archive differs from its pinned input')
  destination = root / 'firmware-candidates/l4t-32.2.1'
  destination.mkdir(parents=True, exist_ok=True)
  with tarfile.open(archive, 'r:bz2') as tree:
    proof = [extract(tree, item, destination) for item in lock['outer_files']]
  with tarfile.open(destination / 'nvidia_drivers.tbz2', 'r:bz2') as tree:
    proof += [extract(tree, item, destination) for item in lock['inner_files']]
  report = {'source': source, 'files': proof, 'hardware_qualified': False, 'installed_into_runtime': False}
  (destination / 'firmware-candidate-report.json').write_text(json.dumps(report, indent=2) + '\n')
  print(json.dumps({'verified_files': len(proof), 'hardware_qualified': False, 'installed_into_runtime': False}, indent=2))


if __name__ == '__main__':
  main()
