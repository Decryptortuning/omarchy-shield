#!/usr/bin/env python3
"""Verify a source export against the pinned Git tree before compiling it."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('repository', type=Path)
  parser.add_argument('commit')
  parser.add_argument('archive', type=Path)
  parser.add_argument('output', type=Path)
  args = parser.parse_args()
  if args.output.exists():
    raise SystemExit(f'Refusing to overwrite an existing source directory: {args.output}')
  listing = subprocess.check_output(
    ['git', '-C', str(args.repository), 'ls-tree', '-rz', args.commit])
  expected = {}
  for record in listing.split(b'\0'):
    if not record:
      continue
    metadata, name = record.split(b'\t', 1)
    mode, kind, oid = metadata.decode().split()
    if kind != 'blob':
      raise SystemExit(f'Unsupported source entry: {name!r} ({kind})')
    expected[name.decode()] = (mode, oid)
  args.output.parent.mkdir(parents=True, exist_ok=True)
  temp = Path(tempfile.mkdtemp(prefix='kernel-verify.', dir=args.output.parent))
  try:
    original_links = {}
    def source_filter(member, destination):
      # The data filter safely normalizes redundant './' in symlink targets.
      # Preserve the original header spelling for Git blob verification.
      if member.issym():
        name = '/'.join(Path(member.name).parts[1:])
        original_links[name] = member.linkname
      return tarfile.data_filter(member, destination)
    with tarfile.open(args.archive) as archive:
      archive.extractall(temp, filter=source_filter)
    roots = list(temp.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
      raise SystemExit('Source export must have exactly one top-level directory')
    source = roots[0]
    actual = {str(p.relative_to(source)) for p in source.rglob('*')
         if p.is_file() or p.is_symlink()}
    if actual != set(expected):
      raise SystemExit(f'Export/tree paths differ: missing={sorted(set(expected)-actual)[:10]}, '
              f'extra={sorted(actual-set(expected))[:10]}')
    normalized_links = 0
    for name, (mode, oid) in expected.items():
      path = source / name
      if mode == '120000':
        if not path.is_symlink():
          raise SystemExit(f'Expected a symlink: {name}')
        original = original_links[name]
        if path.resolve() != (path.parent / original).resolve():
          raise SystemExit(f'Symlink target semantics changed: {name}')
        normalized_links += str(path.readlink()) != original
        data = original.encode()
        digest = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
      else:
        if path.is_symlink() or not path.is_file():
          raise SystemExit(f'Expected a regular file: {name}')
        size = path.stat().st_size
        value = hashlib.sha1(b'blob ' + str(size).encode() + b'\0')
        with path.open('rb') as file:
          for chunk in iter(lambda: file.read(1048576), b''):
            value.update(chunk)
        digest = value.hexdigest()
        if bool(path.stat().st_mode & 0o111) != (mode == '100755'):
          raise SystemExit(f'Executable mode mismatch: {name}')
      if digest != oid:
        raise SystemExit(f'Git blob mismatch: {name}')
    with args.archive.open('rb') as file:
      archive_sha = hashlib.file_digest(file, 'sha256').hexdigest()
    proof = {'commit': args.commit, 'verified_git_blobs': len(expected),
        'normalized_safe_symlinks': normalized_links,
        'source_archive_sha256': archive_sha}
    (source / '.shield-source-commit').write_text(args.commit + '\n')
    (source / '.shield-source-verification.json').write_text(json.dumps(proof, indent=2) + '\n')
    source.rename(args.output)
    print(json.dumps(proof, indent=2))
  finally:
    shutil.rmtree(temp)


if __name__ == '__main__':
  main()
