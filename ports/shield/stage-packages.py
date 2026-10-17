#!/usr/bin/env python3
"""Export an exact fork commit and paired recipes into a prepared ARM rootfs.

This only stages files. It never enters a chroot, installs on the host, or
executes upstream setup scripts. Python 3.12 or later is required.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from tools.kernel_profile import verify_kernel_intent


def git(repository, *arguments, **options):
  return subprocess.run(
    ['git', '-c', f'safe.directory={repository}', '-C', str(repository), *arguments],
    check=True, **options)


def export(repository, commit, destination, *paths):
  with tempfile.TemporaryFile() as archive:
    git(repository, 'archive', commit, *paths, stdout=archive)
    archive.seek(0)
    with tarfile.open(fileobj=archive) as tree:
      tree.extractall(destination, filter='data')


def main():
  port = Path(__file__).resolve().parent
  source = port.parent.parent
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--rootfs', required=True, type=Path)
  parser.add_argument('--recipes', required=True, type=Path)
  parser.add_argument('--kernel-dir', required=True, type=Path)
  parser.add_argument('--commit', default='HEAD', help='Exact fork commit to export; defaults to HEAD')
  args = parser.parse_args()
  rootfs = args.rootfs.resolve(strict=True)
  recipes = args.recipes.resolve(strict=True)
  kernel = args.kernel_dir.resolve(strict=True)
  if rootfs == Path('/') or not (rootfs / 'var/lib/shield-linux/sources.lock.json').is_file():
    raise SystemExit('Use a separately prepared Shield ARM build filesystem')
  commit = git(source, 'rev-parse', '--verify', f'{args.commit}^{{commit}}', capture_output=True, text=True).stdout.strip()
  lock = json.loads(git(source, 'show', f'{commit}:ports/shield/userspace.lock.json', capture_output=True, text=True).stdout)
  recipe_commit = lock['packaging']['commit']
  git(recipes, 'cat-file', '-e', f'{recipe_commit}^{{commit}}')
  subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=kernel, check=True)
  build = rootfs / 'build'
  if build.exists():
    raise SystemExit(f'Refusing to replace an existing build: {build}')
  with tempfile.TemporaryDirectory(prefix='shield-source-admission-') as directory:
    admitted = Path(directory) / 'omarchy-src'
    admitted.mkdir()
    export(source, commit, admitted)
    try:
      verify_kernel_intent(kernel, admitted)
    except (ValueError, OSError, KeyError) as error:
      raise SystemExit(str(error)) from error
    version = (admitted / 'version').read_text().strip()
    if not (admitted / 'install/omarchy-aarch64-shield.packages').is_file():
      raise SystemExit('The selected source commit does not contain the Shield platform')
    build.mkdir()
    exported = build / 'omarchy-src'
    shutil.copytree(admitted, exported)
  with tempfile.TemporaryDirectory() as temporary:
    staged = Path(temporary)
    export(recipes, recipe_commit, staged, 'pkgbuilds/omarchy', 'pkgbuilds/omarchy-settings')
    for package in ('omarchy', 'omarchy-settings'):
      destination = build / package
      shutil.copytree(staged / 'pkgbuilds' / package, destination)
      recipe = destination / 'PKGBUILD'
      replacements = {'pkgver': version, 'pkgrel': '99.7', '_commit': repr(commit), '_tag': "''"}
      lines = []
      for line in recipe.read_text().splitlines():
        key = line.split('=', 1)[0]
        lines.append(f'{key}={replacements[key]}' if key in replacements else line)
      recipe.write_text('\n'.join(lines) + '\n')
  shutil.copytree(exported / 'ports/shield/omarchy-shield', build / 'omarchy-shield')
  for asset in ('hardware.json', 'hardware-darcy.json', 'hardware-darcy-a08.json', 'collect-shield-linux.py'):
    shutil.copy2(exported / 'ports/shield' / asset, build / 'omarchy-shield' / asset)
  shutil.copytree(exported / 'ports/shield/linux-shield', build / 'linux-shield')
  shutil.copytree(kernel, build / 'kernel-inputs')
  for script, destination in (('build-packages.sh', 'build-target-packages.sh'),
                              ('install-packages.sh', 'install-target-packages.sh')):
    shutil.copy2(exported / 'ports/shield' / script, rootfs / 'var/lib/shield-linux' / destination)
  provenance = {
    'omarchy_commit': commit, 'packaging_commit': recipe_commit,
    'pkgver': version, 'pkgrel': '99.7', 'architecture': 'aarch64',
    'package_names': ['omarchy', 'omarchy-settings', 'omarchy-shield', 'linux-shield'],
    'kernel_source_commit': json.loads((kernel / 'sources.lock.json').read_text())['kernel']['commit'],
    'board_variant': json.loads((kernel / 'sources.lock.json').read_text())['board_variant'],
    'physical_shield_tested': False, 'flashable_image': False,
  }
  (rootfs / 'var/lib/shield-linux/package-build.json').write_text(json.dumps(provenance, indent=2) + '\n')
  print(json.dumps(provenance, indent=2))


if __name__ == '__main__':
  main()
