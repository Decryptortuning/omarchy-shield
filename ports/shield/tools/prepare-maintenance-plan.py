#!/usr/bin/env python3
"""Pin the original root identity for a separately owned maintenance transaction."""
import argparse
import hashlib
import json
from pathlib import Path
from usb_candidate_transaction import validate_plan
from usb_root_profile import database_profile, digest, require
from maintenance_accounts import original_account_baseline


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--base-rootfs', required=True, type=Path)
  parser.add_argument('--payload-manifest', required=True, type=Path)
  parser.add_argument('--output', required=True, type=Path)
  parser.add_argument('--account-preimages-receipt', required=True, type=Path)
  parser.add_argument('--account-preimages-receipt-sha256', required=True)
  parser.add_argument('--base-image-sha256', required=True)
  args = parser.parse_args()
  root = args.base_rootfs.resolve(strict=True)
  require(root != Path('/') and (root / 'var/lib/shield-linux/sources.lock.json').is_file(), 'Use the pinned original USB reference')
  manifest = json.loads(args.payload_manifest.read_text())
  original, _contents = original_account_baseline(root, args.account_preimages_receipt.absolute(),
    args.account_preimages_receipt_sha256, args.base_image_sha256)
  accounts = original['account_preimages']
  critical = ['etc/fstab', 'etc/pacman.conf', 'usr/bin/pacman', 'usr/lib/libc.so.6',
              'usr/lib/omarchy/shield/kernel/Image', 'var/lib/shield-linux/package-build.json',
              'usr/bin/pacman-key', 'usr/bin/gpg', 'usr/bin/gpgconf',
              'usr/share/pacman/keyrings/archlinuxarm.gpg',
              'usr/share/pacman/keyrings/archlinuxarm-trusted',
              'usr/share/pacman/keyrings/archlinuxarm-revoked']
  critical += sorted(accounts)
  plan = {'format_version': 1, 'candidate_id': manifest['candidate_id'],
          'filesystem_uuid': manifest['filesystem_uuid'], 'original_subvolumes': {'root': '@', 'home': '@home', 'log': '@log'},
          'minimum_free_bytes': 3 * 1024**3, 'base_database': database_profile(root),
          'base_files': {name: digest(root / name) for name in critical},
          'payload_manifest_sha256': digest(args.payload_manifest),
          'base_image_sha256': args.base_image_sha256,
          'base_account_preimages': accounts,
          'original_image_account_receipt_sha256': args.account_preimages_receipt_sha256,
          'payload_canonical_sha256': hashlib.sha256(json.dumps(manifest, sort_keys=True,
             separators=(',', ':'), ensure_ascii=True).encode()).hexdigest(),
          'physical_write_released': False, 'boot_ready': False}
  validate_plan(plan, manifest)
  with args.output.open('x') as output:
    output.write(json.dumps(plan, indent=2) + '\n')
  print('Pinned original root plan only; no mount, update or boot selection.')


if __name__ == '__main__':
  main()
