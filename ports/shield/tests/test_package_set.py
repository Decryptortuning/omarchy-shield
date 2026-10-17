"""Run the actual installer against archive metadata, with pacman effects fenced."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

PORT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('package_set', PORT / 'tools/package_set.py')
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class PackageSetTests(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory(prefix='shield-package-set-')
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.build = self.root / 'build'
    self.state = self.root / 'state'
    self.state.mkdir()
    (self.state / 'sources.lock.json').write_text('{}')
    for name, directory in PROFILE.PACKAGES.items():
      recipe = self.build / directory / 'PKGBUILD'
      recipe.parent.mkdir(parents=True)
      recipe.write_text(f"pkgname='{name}'\npkgver=4.0.4\npkgrel=99.7\narch=('aarch64')\n" +
                        ('epoch=1\n' if name == 'mesa' else ''))
    self.intent = PROFILE.package_intent(self.build)
    (self.state / 'package-artifacts-intent.json').write_text(json.dumps(self.intent))
    for name in PROFILE.PACKAGES:
      self.archive(name)
    helper = self.build / 'omarchy-src/ports/shield/tools/package_set.py'
    helper.parent.mkdir(parents=True)
    shutil.copy2(PORT / 'tools/package_set.py', helper)
    binaries = self.root / 'bin'
    binaries.mkdir()
    (binaries / 'python').symlink_to(sys.executable)
    for name, text in {'uname': '#!/bin/sh\necho aarch64\n',
                       'pacman': '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TRANSACTION_LOG"\n'}.items():
      path = binaries / name
      path.write_text(text)
      path.chmod(0o755)
    self.log = self.root / 'transaction.log'
    self.env = dict(os.environ, PATH=str(binaries) + ':' + os.environ['PATH'], TRANSACTION_LOG=str(self.log))

  def archive(self, name, version=None, arch='aarch64', recipe_sha=None):
    identity = self.intent['packages'][name]
    version = version or identity['version']
    info = f'pkgname = {name}\npkgver = {version}\narch = {arch}\n'
    build_info = (f'pkgname = {name}\npkgver = {version}\npkgarch = {arch}\n'
                  f"pkgbuild_sha256sum = {recipe_sha or identity['recipe_sha256']}\n")
    path = self.build / PROFILE.PACKAGES[name] / (name + '.pkg.tar.xz')
    with tarfile.open(path, 'w:xz') as archive:
      for member, content in [('.PKGINFO', info), ('.BUILDINFO', build_info)]:
        data = content.encode()
        entry = tarfile.TarInfo(member)
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
    return path

  def install(self):
    return subprocess.run(['bash', '-c', 'source "$1"; shield_install_packages "$2" "$3"',
                           'bash', str(PORT / 'install-packages.sh'), str(self.build), str(self.state)],
                          env=self.env, capture_output=True, text=True)

  def assert_refused_without_transaction(self, message):
    result = self.install()
    self.assertNotEqual(result.returncode, 0, result.stdout)
    self.assertIn(message, result.stderr)
    self.assertFalse(self.log.exists(), 'pacman was called before all archives were admitted')

  def test_matched_five_archives_enter_one_transaction(self):
    result = self.install()
    self.assertEqual(result.returncode, 0, result.stderr)
    calls = self.log.read_text().splitlines()
    transactions = [line for line in calls if line.startswith('-U ')]
    self.assertEqual(len(transactions), 1)
    self.assertEqual(transactions[0].count('.pkg.tar.xz'), 5)
    self.assertIn('SHIELD_OMARCHY_LOCAL_PACKAGES_INSTALLED', result.stdout)

  def test_same_name_old_mesa_refused(self):
    self.archive('mesa', version='1:26.2.4-1')
    self.assert_refused_without_transaction('mesa/pkgver')

  def test_old_runtime_pair_member_refused(self):
    self.archive('omarchy-settings', version='4.0.4-99.6')
    self.assert_refused_without_transaction('omarchy-settings/pkgver')

  def test_same_name_wrong_architecture_refused(self):
    self.archive('linux-shield', arch='x86_64')
    self.assert_refused_without_transaction('linux-shield/arch')

  def test_archive_from_other_recipe_refused(self):
    self.archive('omarchy-shield', recipe_sha='0' * 64)
    self.assert_refused_without_transaction('omarchy-shield/pkgbuild_sha256sum')

  def test_changed_staged_recipe_refused(self):
    with (self.build / 'mesa-shield/PKGBUILD').open('a') as target:
      target.write('# changed after intent\n')
    self.assert_refused_without_transaction('intent differs')

  def test_duplicate_archive_refused(self):
    (self.build / 'mesa-shield/extra.pkg.tar.xz').write_bytes(b'not a package')
    self.assert_refused_without_transaction('exactly one regular package archive: mesa')

  def test_missing_archive_refused(self):
    (self.build / 'omarchy/omarchy.pkg.tar.xz').unlink()
    self.assert_refused_without_transaction('exactly one regular package archive: omarchy')


if __name__ == '__main__':
  unittest.main()
