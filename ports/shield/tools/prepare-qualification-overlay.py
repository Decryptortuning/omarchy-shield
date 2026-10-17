#!/usr/bin/env python3
"""Render a new host qualification overlay; never apply it or select a boot."""
import argparse
import hashlib
import json
from pathlib import Path
from qualification_profile import GID, UID, render
from usb_root_profile import digest, require, safe_relative, verify_root


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--rootfs', type=Path, required=True)
  parser.add_argument('--payload-manifest', type=Path, required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  root = args.rootfs.resolve(strict=True)
  require(root != Path('/'), 'Use the matched ARM reference root')
  manifest = json.loads(args.payload_manifest.read_text())
  verify_root(manifest, root)
  profile = render(root, manifest)
  require(not args.output.exists() and not args.output.is_symlink(), 'Output must be new')
  args.output.mkdir(mode=0o700)
  files = {}
  for purpose in ['root', 'home']:
    for name, value in profile[purpose].items():
      safe_relative(name)
      path = args.output / purpose / name
      path.parent.mkdir(parents=True, exist_ok=True)
      with path.open('x') as stream:
        stream.write(value)
      path.chmod(0o644)
      files[purpose + '/' + name] = {'sha256': digest(path), 'mode': 0o644,
        'uid': UID if purpose == 'home' else 0, 'gid': GID if purpose == 'home' else 0}
  receipt = {'format_version': 1, 'policy': profile['policy'], 'files': files,
    'payload_manifest_sha256': digest(args.payload_manifest),
    'producer_sha256': digest(__file__),
    'renderer_sha256': digest(Path(__file__).with_name('qualification_profile.py')),
    'guardian_installed': False, 'account_created': False, 'theme_seeded': False,
    'root_modified': False, 'boot_ready': False}
  with (args.output / 'manifest.json').open('x') as output:
    output.write(json.dumps(receipt, indent=2) + '\n')
  print('Rendered source-bound qualification overlay only; no root or device changed.')


if __name__ == '__main__':
  main()
