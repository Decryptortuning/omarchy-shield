#!/usr/bin/env python3
"""Apply the explicitly pinned project overlay to a verified kernel snapshot."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

project, lock_path, source = map(Path, sys.argv[1:])
lock = json.loads(lock_path.read_text())
patches = lock['kernel'].get('patches', [])
state_path = source / '.shield-applied-patches.json'
expected = {'base_commit': lock['kernel']['commit'], 'patches': patches}
previous = json.loads(state_path.read_text()) if state_path.exists() else None
def identity(state):
  return state['base_commit'], [item['sha256'] for item in state['patches']]


if previous is not None and identity(previous) != identity(expected):
  raise SystemExit('This source cache has a different patch set; use a fresh SHIELD_BUILD_ROOT')
for patch in patches:
  path = (project / patch['path']).resolve()
  if not path.is_relative_to(project.resolve()):
    raise SystemExit('Patch path must stay within the project')
  if hashlib.sha256(path.read_bytes()).hexdigest() != patch['sha256']:
    raise SystemExit(f'Patch checksum mismatch: {path}')
  if previous is None:
    subprocess.run(['git', 'apply', '--check', str(path)], cwd=source, check=True)
    subprocess.run(['git', 'apply', str(path)], cwd=source, check=True)
  else:
    subprocess.run(['git', 'apply', '--reverse', '--check', str(path)], cwd=source, check=True)
if patches:
  state_path.write_text(json.dumps(expected, indent=2) + '\n')
  print(f'Verified {len(patches)} pinned kernel patch(es)')
