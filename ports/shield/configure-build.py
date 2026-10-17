#!/usr/bin/env python3
"""Configure repositories and bootstrap inputs only inside a prepared ARM root."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def main():
  port = Path(__file__).resolve().parent
  lock = json.loads((port / 'userspace.lock.json').read_text())
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--rootfs', required=True, type=Path)
  parser.add_argument('--recipes', required=True, type=Path)
  parser.add_argument('--audit', required=True, type=Path)
  parser.add_argument('--metadata-dir', required=True, type=Path)
  args = parser.parse_args()
  rootfs, recipes = args.rootfs.resolve(strict=True), args.recipes.resolve(strict=True)
  if rootfs == Path('/') or not (rootfs / 'var/lib/shield-linux/sources.lock.json').is_file():
    raise SystemExit('Use a separately prepared ARM filesystem')
  audit = json.loads(args.audit.read_text())
  if not audit['all_package_names_available'] or audit['repositories'] != lock['repositories']:
    raise SystemExit('Resolve the complete package set against the current pinned metadata first')
  if audit.get('build_packages') != lock['build_packages'] or any(name not in audit['resolved'] for name in lock['build_packages']):
    raise SystemExit('Re-audit every locked build package before configuring the root filesystem')
  sync = rootfs / 'var/lib/pacman/sync'
  sync.mkdir(parents=True, exist_ok=True)
  for repository in lock['repositories']:
    database = args.metadata_dir / repository['file']
    if hashlib.sha256(database.read_bytes()).hexdigest() != repository['sha256']:
      raise SystemExit(f"Metadata differs from its lock: {repository['name']}")
    shutil.copy2(database, sync / f"{repository['name']}.db")
    (sync / f"{repository['name']}.db.sig").unlink(missing_ok=True)
  state = rootfs / 'var/lib/shield-linux'
  # Build these four locally; repository packages supply all their dependencies.
  built = {'omarchy', 'omarchy-settings', 'omarchy-shield', 'linux-shield'}
  names = sorted({'omarchy-keyring'} | {item['name'][0] for requested, item in audit['resolved'].items() if requested not in built})
  (state / 'repository-packages.txt').write_text('\n'.join(names) + '\n')
  shutil.copy2(port / 'bootstrap-packages.sh', state / 'bootstrap-packages.sh')
  templates = port.parent.parent / 'default/pacman/aarch64-shield'
  shutil.copy2(templates / 'pacman-edge.conf', rootfs / 'etc/pacman.conf')
  shutil.copy2(templates / 'mirrorlist-edge', rootfs / 'etc/pacman.d/mirrorlist')
  with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as archive:
    subprocess.run(['git', '-c', f'safe.directory={recipes}', '-C', str(recipes), 'archive',
                    lock['packaging']['commit'], 'pkgbuilds/omarchy-keyring'], stdout=archive, check=True)
    archive.seek(0)
    with tarfile.open(fileobj=archive) as tree:
      tree.extractall(temporary, filter='data')
    keyring = rootfs / 'usr/share/pacman/keyrings'
    keyring.mkdir(parents=True, exist_ok=True)
    for name in ('omarchy.gpg', 'omarchy-trusted', 'omarchy-revoked'):
      shutil.copy2(Path(temporary) / 'pkgbuilds/omarchy-keyring' / name, keyring / name)
  # Build-only network resolution. A deployable image still needs its own finalization.
  resolver = rootfs / 'etc/resolv.conf'
  if resolver.is_symlink():
    resolver.unlink()
  shutil.copyfile('/etc/resolv.conf', resolver)
  image = rootfs / 'var/lib/omarchy/image'
  image.mkdir(parents=True, mode=0o755, exist_ok=True)
  (image / 'target').write_text('format=1\nplatform=aarch64-shield\n')
  print('Prepared isolated ARM repository/bootstrap inputs; no host package configuration changed.')


if __name__ == '__main__':
  main()
