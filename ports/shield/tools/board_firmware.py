"""Verify inactive per-board firmware staging and installed byte identity."""
import hashlib
import json
from pathlib import Path
import subprocess


def checked_path(root, relative):
  path = Path(relative)
  if path.is_absolute() or '..' in path.parts or not path.parts:
    raise ValueError('Firmware paths must be relative and contained')
  result = root / path
  if not result.resolve().is_relative_to(root.resolve()):
    raise ValueError('Firmware path escapes its root')
  return result


def verify_bytes(data, entry):
  if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
    raise ValueError(f"Firmware bytes differ from the lock: {entry['id']}")


def verify_stage(directory, lock_path, variant):
  directory, lock_path = Path(directory), Path(lock_path)
  raw = lock_path.read_bytes()
  lock = json.loads(raw)
  report = json.loads((directory / 'staging.json').read_text())
  if lock['board_variant'] != variant or report['board_variant'] != variant:
    raise ValueError('Firmware stage and kernel board variants disagree')
  if report['lock_sha256'] != hashlib.sha256(raw).hexdigest():
    raise ValueError('Firmware stage uses a different lock')
  if report['installed_into_runtime'] is not False or report['hardware_qualified'] is not False:
    raise ValueError('Inactive staging cannot establish activation or qualification')
  expected = {entry['id']: entry for entry in lock['entries']}
  if len(expected) != len(lock['entries']) or len(report['files']) != len(expected):
    raise ValueError('Duplicate or missing firmware records')
  seen = set()
  for entry in report['files']:
    if entry['id'] in seen or entry['id'] not in expected:
      raise ValueError('Duplicate or unexpected staged firmware')
    seen.add(entry['id'])
    locked = expected[entry['id']]
    if entry['path'] != 'inputs/' + locked['input_path']:
      raise ValueError('Unexpected staged firmware path')
    path = checked_path(directory, entry['path'])
    if not path.is_file() or path.is_symlink():
      raise ValueError('Staged payload must be a regular file')
    verify_bytes(path.read_bytes(), locked)
  return lock, report


def installed_identity(firmware_root, entry):
  """Read only exact request paths, accepting compressed package payloads."""
  request = entry.get('runtime_request')
  if not request or entry['usage'] != 'driver-candidate':
    return {'status': 'reference-only'}
  for suffix in ('', '.zst', '.xz'):
    path = checked_path(firmware_root, request + suffix)
    if not path.is_file():
      continue
    if suffix:
      executable = 'zstd' if suffix == '.zst' else 'xz'
      with subprocess.Popen([executable, '-dc', '--', str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL) as process:
        data = process.stdout.read(entry['bytes'] + 1)
        if len(data) > entry['bytes']:
          process.kill()
        result = process.wait()
      if result or len(data) > entry['bytes']:
        return {'status': 'different-or-invalid', 'path': request + suffix}
    else:
      with path.open('rb') as stream:
        data = stream.read(entry['bytes'] + 1)
    matches = len(data) == entry['bytes'] and hashlib.sha256(data).hexdigest() == entry['sha256']
    return {'status': 'byte-identical' if matches else 'different', 'path': request + suffix,
            'physical_qualified': False}
  return {'status': 'missing'}
