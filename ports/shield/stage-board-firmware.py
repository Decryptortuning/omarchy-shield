#!/usr/bin/env python3
"""Stage pinned board firmware into a new inactive directory; never install it."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import urllib.parse
import urllib.request
from tools.board_firmware import checked_path, verify_bytes


def stage(lock_path, input_root, output, download=False):
  raw = lock_path.read_bytes()
  lock = json.loads(raw)
  if lock['board_variant'] not in ('darcy-t210-a04', 'darcy-t210-a08') or lock['installed_into_runtime'] is not False:
    raise ValueError('This staging lock must describe inactive original-T210 Darcy inputs')
  output = output.resolve()
  if output.exists() or any(output.parts[i:i + 2] == ('lib', 'firmware') for i in range(len(output.parts) - 1)):
    raise ValueError('Use a new directory outside every runtime lib/firmware tree')
  entries = lock['entries']
  if len({e['id'] for e in entries}) != len(entries) or len({e['input_path'] for e in entries}) != len(entries):
    raise ValueError('Duplicate firmware inputs')
  for entry in entries:
    checked_path(input_root, entry['input_path'])
    if entry['activation_allowed'] is not False:
      raise ValueError('This tool only stages inactive inputs')
  output.parent.mkdir(parents=True, exist_ok=True)
  temporary = Path(tempfile.mkdtemp(prefix='.shield-firmware-', dir=output.parent))
  try:
    files = []
    for entry in entries:
      source = checked_path(input_root, entry['input_path'])
      if source.is_file() and not source.is_symlink():
        with source.open('rb') as stream:
          data = stream.read(entry['bytes'] + 1)
        method = 'verified-local-input'
      else:
        url = entry.get('download_url')
        parsed = urllib.parse.urlparse(url or '')
        if not download or parsed.scheme != 'https' or parsed.username or parsed.password:
          raise ValueError(f"Supply the pinned local input: {entry['id']}")
        with urllib.request.urlopen(url, timeout=45) as stream:
          if urllib.parse.urlparse(stream.url).scheme != 'https':
            raise ValueError('Firmware redirect left HTTPS')
          data = stream.read(entry['bytes'] + 1)
        method = 'verified-upstream-download'
      verify_bytes(data, entry)
      relative = 'inputs/' + entry['input_path']
      destination = checked_path(temporary, relative)
      destination.parent.mkdir(parents=True, exist_ok=True)
      destination.write_bytes(data)
      files.append({'id': entry['id'], 'path': relative, 'bytes': len(data),
                    'sha256': entry['sha256'], 'acquisition': method})
    report = {'board_variant': lock['board_variant'], 'lock_sha256': hashlib.sha256(raw).hexdigest(),
              'files': files, 'installed_into_runtime': False, 'hardware_qualified': False,
              'stock_payloads_redistributable': False, 'device_actions_performed': []}
    (temporary / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    shutil.copyfile(lock_path, temporary / 'firmware.lock.json')
    temporary.rename(output)
  except BaseException:
    shutil.rmtree(temporary)
    raise
  return report


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--input-root', required=True, type=Path, help='Previously acquired firmware harvest directory')
  parser.add_argument('--output', required=True, type=Path)
  parser.add_argument('--lock', type=Path, default=Path(__file__).resolve().parent / 'firmware-darcy.lock.json')
  parser.add_argument('--download-upstream', action='store_true', help='Fetch missing upstream files over HTTPS; stock OTA inputs must be local')
  args = parser.parse_args()
  try:
    report = stage(args.lock,
                   args.input_root.resolve(), args.output, args.download_upstream)
  except (ValueError, OSError) as error:
    raise SystemExit(str(error)) from error
  print(json.dumps({'files_verified': len(report['files']), 'installed_into_runtime': False,
                    'hardware_qualified': False}, indent=2))


if __name__ == '__main__':
  main()
