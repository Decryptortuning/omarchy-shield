#!/usr/bin/env python3
"""Apply only checksum-pinned board overlays to a compiled evaluation DTB."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def digest(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
  project, lock_file, dtb = map(lambda value: Path(value).resolve(), sys.argv[1:])
  overlays = json.loads(lock_file.read_text())['kernel'].get('device_tree_overlays', [])
  if not overlays:
    return
  proof = {'base_dtb_sha256': digest(dtb), 'overlays': overlays}
  with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    current = dtb
    for index, overlay in enumerate(overlays):
      source = (project / overlay['path']).resolve()
      if not source.is_relative_to(project) or digest(source) != overlay['sha256']:
        raise SystemExit('Overlay is outside the project or differs from its checksum')
      compiled, result = temporary / f'{index}.dtbo', temporary / f'{index}.dtb'
      subprocess.run(['dtc', '-@', '-I', 'dts', '-O', 'dtb', '-o', str(compiled), str(source)], check=True)
      subprocess.run(['fdtoverlay', '-i', str(current), '-o', str(result), str(compiled)], check=True)
      current = result
    dtb.write_bytes(current.read_bytes())
  proof['result_dtb_sha256'] = digest(dtb)
  (dtb.parent / 'device-tree-overlays.json').write_text(json.dumps(proof, indent=2) + '\n')


if __name__ == '__main__':
  main()
