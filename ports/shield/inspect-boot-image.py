#!/usr/bin/env python3
"""Inspect a saved Android boot image with pinned AOSP tools; never repack or flash."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def main():
  port = Path(__file__).resolve().parent
  lock = json.loads((port / 'boot-tools.lock.json').read_text())
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--tools', required=True, type=Path)
  parser.add_argument('--image', required=True, type=Path)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  tools, image = args.tools.resolve(strict=True), args.image.resolve(strict=True)
  if not image.is_file() or args.output.exists():
    raise SystemExit('Use a saved regular image file and a new output directory')
  output = args.output.resolve()
  output.mkdir(parents=True)
  with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as archive:
    subprocess.run(['git', '-c', f'safe.directory={tools}', '-C', str(tools), 'archive', lock['commit']], stdout=archive, check=True)
    archive.seek(0)
    with tarfile.open(fileobj=archive) as tree:
      tree.extractall(directory, filter='data')
    command = [sys.executable, str(Path(directory) / 'unpack_bootimg.py'),
               '--boot_img', str(image), '--out', str(output / 'payloads')]
    info = subprocess.run(command + ['--format', 'info'], capture_output=True, check=True)
    arguments = subprocess.run(command + ['--format', 'mkbootimg', '-0'], capture_output=True, check=True).stdout.split(b'\0')
    if arguments and arguments[-1] == b'':
      arguments.pop()
  (output / 'header.txt').write_bytes(info.stdout)
  with image.open('rb') as incoming:
    digest = hashlib.file_digest(incoming, 'sha256').hexdigest()
  report = {
    'source_filename': image.name, 'source_sha256': digest,
    'aosp_commit': lock['commit'],
    'header_arguments_as_data': [item.decode('utf-8') for item in arguments],
    'actual_shield_identity_confirmed': False,
    'device_tree_handoff_verified': False, 'flashable_candidate': False,
  }
  (output / 'inspection.json').write_text(json.dumps(report, indent=2) + '\n')
  print('Header and payloads extracted into a new directory; original image unchanged. No image was repacked or flashed.')


if __name__ == '__main__':
  main()
