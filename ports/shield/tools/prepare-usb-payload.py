#!/usr/bin/env python3
"""Prepare an exact maintenance payload on the host; never access the Shield."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import uuid
from package_set import PACKAGES, admitted_archives
from usb_root_profile import admit_payload, database_profile, digest, installed_versions, root_profile, transition_absences, validate_manifest


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--rootfs', required=True, type=Path)
  parser.add_argument('--audit', required=True, type=Path)
  parser.add_argument('--base-rootfs', required=True, type=Path, help='Pinned original USB reference, never the VM copy')
  parser.add_argument('--filesystem-uuid', required=True)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  root = args.rootfs.resolve(strict=True)
  if root == Path('/') or not (root / 'var/lib/shield-linux/package-build.json').is_file():
    raise SystemExit('Use the separately verified ARM build root')
  output = args.output.absolute()
  if output.exists() or not output.parent.is_dir():
    raise SystemExit('Use a new output directory with an existing parent')
  intent = json.loads((root / 'var/lib/shield-linux/package-artifacts-intent.json').read_text())
  archives = admitted_archives(root / 'build', root / 'var/lib/shield-linux/package-artifacts-intent.json')
  records = {}
  for (name, _), archive in zip(PACKAGES.items(), archives, strict=True):
    records[name] = {'filename': archive.name, 'version': intent['packages'][name]['version'],
                     'architecture': 'aarch64', 'bytes': archive.stat().st_size, 'sha256': digest(archive)}
  dtc = json.loads(args.audit.read_text())['resolved']['dtc']
  archive = root / 'var/cache/pacman/pkg' / dtc['filename'][0]
  if dtc['name'] != ['dtc'] or dtc['arch'] != ['aarch64'] or digest(archive) != dtc['sha256sum'][0]:
    raise SystemExit('DTC archive differs from pinned package audit')
  records['dtc'] = {'filename': archive.name, 'version': dtc['version'][0], 'architecture': 'aarch64',
                    'bytes': archive.stat().st_size, 'sha256': digest(archive)}
  archives.append(archive)
  signature = archive.with_name(archive.name + '.sig')
  records['dtc']['signature'] = {'filename': signature.name, 'bytes': signature.stat().st_size, 'sha256': digest(signature)}
  archives.append(signature)
  candidate = uuid.uuid4().hex
  subvolume = '@shield-' + candidate
  manifest = {'format_version': 1, 'candidate_id': candidate, 'filesystem_uuid': args.filesystem_uuid,
              'subvolumes': {'root': subvolume, 'home': subvolume + '-home', 'log': subvolume + '-log'},
              'packages': records, 'installed_packages': installed_versions(root),
              'database': database_profile(root), 'required_absent': transition_absences(args.base_rootfs, root),
              'root_files': root_profile(root, {n: p['version'] for n, p in records.items()}),
              'source': json.loads((root / 'var/lib/shield-linux/package-build.json').read_text()),
              'physical_USB_prepared': False, 'boot_ready': False,
              'scope': 'Exact offline package/root identity payload only. No mount, update, root selection or device action.'}
  validate_manifest(manifest)
  # Work remains in a private temporary directory until every copied archive is admitted.
  with tempfile.TemporaryDirectory(prefix='.shield-payload-', dir=output.parent) as temporary:
    staged = Path(temporary)
    payload = staged / 'packages'
    payload.mkdir()
    for archive in archives:
      shutil.copy2(archive, payload / archive.name)
    admit_payload(manifest, payload)
    (staged / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    staged.rename(output)
  print('Prepared exact six-component host payload; USB and boot remain unchanged.')


if __name__ == '__main__':
  main()
