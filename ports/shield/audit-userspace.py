#!/usr/bin/env python3
"""Check installed CPU ELF payloads for accidental foreign-architecture builds.

This reads ELF headers only. It does not execute programs, prove CPU instruction
compatibility, inspect PE/.NET assemblies or qualify hardware acceleration.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import struct


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--rootfs', required=True, type=Path)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  root = args.rootfs.resolve(strict=True)
  if root == Path('/') or not (root / 'var/lib/shield-linux/sources.lock.json').is_file():
    raise SystemExit('Use the separately prepared ARM filesystem')
  counts, non_cpu, seen, foreign, unreadable = Counter(), Counter(), set(), [], []
  def read_error(error):
    unreadable.append(str(Path(error.filename).relative_to(root)))
  trees = (os.walk(root / name, followlinks=False, onerror=read_error)
           for name in ('usr', 'opt') if (root / name).is_dir())
  for directory, directories, files in (entry for tree in trees for entry in tree):
    relative = Path(directory).relative_to(root)
    if relative == Path('usr/lib'):
      directories[:] = [name for name in directories if name != 'firmware']
    for name in files:
      path = Path(directory) / name
      if path.is_symlink():
        continue
      try:
        metadata = path.stat()
        identity = metadata.st_dev, metadata.st_ino
        if identity in seen:
          continue
        seen.add(identity)
        with path.open('rb') as source:
          header = source.read(20)
      except (PermissionError, FileNotFoundError):
        unreadable.append(str(path.relative_to(root)))
        continue
      if len(header) != 20 or header[:4] != b'\x7fELF':
        continue
      if header[5] not in (1, 2):
        foreign.append({'path': str(path.relative_to(root)), 'error': 'invalid ELF byte order'})
        continue
      file_type, machine = struct.unpack(('<' if header[5] == 1 else '>') + 'HH', header[16:20])
      counts[str(machine)] += 1
      # Guile uses standalone-ABI EM_NONE ELF containers for its .go bytecode,
      # not CPU shared libraries (GNU Guile manual, Object File Format).
      if machine == 0 and header[7] == 255 and path.suffix == '.go':
        non_cpu['guile_bytecode'] += 1
        continue
      if machine == 247 and file_type == 1:
        non_cpu['bpf_objects'] += 1
        continue
      if file_type in (2, 3) and (machine != 183 or header[4] != 2):
        foreign.append({'path': str(path.relative_to(root)), 'elf_machine': machine, 'elf_type': file_type})
  report = {
    'target_elf_machine': 183, 'elf_files_by_machine': dict(counts),
    'non_cpu_elf_containers': dict(non_cpu),
    'scanned_trees': ['usr', 'opt'],
    'foreign_executable_or_shared_library': foreign,
    'unreadable_paths': unreadable,
    'all_cpu_elf_payloads_aarch64': not foreign and not unreadable,
    'excluded': ['device firmware', 'symlink duplicates', 'PE/.NET assemblies'],
    'scope': 'ELF machine headers only; CPU instructions, application behavior and physical hardware remain unqualified',
  }
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print(json.dumps({**report, 'foreign_executable_or_shared_library': foreign[:20]}, indent=2))
  raise SystemExit(bool(foreign or unreadable))


if __name__ == '__main__':
  main()
