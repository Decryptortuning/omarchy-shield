"""Exercise maintenance admission without mounting or changing any device."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PORT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('usb_root_profile', PORT / 'tools/usb_root_profile.py')
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class UsbRootProfileTests(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory(prefix='shield-usb-profile-')
    self.addCleanup(temporary.cleanup)
    self.base = Path(temporary.name)
    self.root = self.base / 'root'
    self.payload = self.base / 'packages'
    self.payload.mkdir()
    versions = {name: '1.0-1' for name in PROFILE.COMPONENTS}
    for name in versions:
      directory = self.root / 'var/lib/pacman/local' / (name + '-1.0-1')
      directory.mkdir(parents=True)
      (directory / 'desc').write_text(f'%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n%ARCH%\naarch64\n\n%INSTALLDATE%\n1234\n')
      (directory / 'files').write_text(f'%FILES%\nusr/share/fixture/{name}\n')
      (directory / 'mtree').write_bytes(b'fixture mtree')
      path = self.root / 'usr/share/fixture' / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_text(name)
    module = self.root / 'usr/lib/modules/7.1.0-shield-bringup/example.ko'
    module.parent.mkdir(parents=True)
    module.write_bytes(b'fixture module')
    cache = self.root / 'etc/ld.so.cache'
    cache.parent.mkdir()
    cache.write_bytes(b'fixture loader cache')
    candidate = 'a' * 32
    self.manifest = {'format_version': 1, 'candidate_id': candidate,
      'filesystem_uuid': '12345678-1234-4234-8234-123456789abc',
      'subvolumes': {'root': '@shield-' + candidate, 'home': '@shield-' + candidate + '-home',
                     'log': '@shield-' + candidate + '-log'},
      'packages': {}, 'installed_packages': versions,
      'database': PROFILE.database_profile(self.root), 'required_absent': ['usr/share/fixture/obsolete-mesa.so'],
      'root_files': PROFILE.root_profile(self.root, versions)}
    for name in versions:
      path = self.payload / (name + '.pkg.tar.xz')
      with tarfile.open(path, 'w:xz') as archive:
        data = f'pkgname = {name}\npkgver = 1.0-1\narch = aarch64\n'.encode()
        entry = tarfile.TarInfo('.PKGINFO')
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
      self.manifest['packages'][name] = {'filename': path.name, 'version': '1.0-1',
        'architecture': 'aarch64', 'bytes': path.stat().st_size, 'sha256': PROFILE.digest(path)}
    signature = self.payload / 'dtc.pkg.tar.xz.sig'
    signature.write_bytes(b'fixture signature bytes; cryptographic verification belongs to pacman')
    self.manifest['packages']['dtc']['signature'] = {'filename': signature.name,
      'bytes': signature.stat().st_size, 'sha256': PROFILE.digest(signature)}

  def test_complete_archive_and_installed_root_admitted(self):
    self.assertTrue(PROFILE.admit_payload(self.manifest, self.payload, execute=PROFILE.host_metadata_execute))
    self.assertTrue(PROFILE.verify_root(self.manifest, self.root))

  def test_altered_archive_refused_before_any_installer(self):
    path = self.payload / 'mesa.pkg.tar.xz'
    path.write_bytes(path.read_bytes() + b'changed')
    with self.assertRaisesRegex(ValueError, 'Changed archive'):
      PROFILE.admit_payload(self.manifest, self.payload, execute=PROFILE.host_metadata_execute)

  def test_changed_signature_refused(self):
    (self.payload / 'dtc.pkg.tar.xz.sig').write_bytes(b'changed')
    with self.assertRaisesRegex(ValueError, 'Changed package signature'):
      PROFILE.admit_payload(self.manifest, self.payload, execute=PROFILE.host_metadata_execute)

  def test_signature_escape_refused_by_manifest_before_payload_access(self):
    self.manifest['packages']['dtc']['signature']['filename'] = '../outside.sig'
    with self.assertRaisesRegex(ValueError, 'Invalid package signature profile'):
      PROFILE.validate_manifest(self.manifest)

  def test_missing_dependency_signature_refused(self):
    del self.manifest['packages']['dtc']['signature']
    with self.assertRaisesRegex(ValueError, 'requires its detached signature'):
      PROFILE.validate_manifest(self.manifest)

  def test_unlisted_archive_refused(self):
    (self.payload / 'extra.pkg.tar.xz').write_bytes(b'extra')
    with self.assertRaisesRegex(ValueError, 'Extra or missing'):
      PROFILE.admit_payload(self.manifest, self.payload, execute=PROFILE.host_metadata_execute)

  def test_missing_dtc_dependency_refused(self):
    del self.manifest['packages']['dtc']
    with self.assertRaisesRegex(ValueError, 'Incomplete maintenance'):
      PROFILE.admit_payload(self.manifest, self.payload, execute=PROFILE.host_metadata_execute)

  def test_archive_symlink_refused(self):
    path = self.payload / 'mesa.pkg.tar.xz'
    target = self.base / 'outside'
    path.rename(target)
    path.symlink_to(target)
    with self.assertRaisesRegex(ValueError, 'regular file'):
      PROFILE.admit_payload(self.manifest, self.payload, execute=PROFILE.host_metadata_execute)

  def test_metadata_uses_only_the_explicit_command_owner(self):
    commands = []
    def execute(arguments):
      commands.append(arguments)
      with tarfile.open(arguments[2], 'r:xz') as archive:
        return archive.extractfile('.PKGINFO').read().decode('ascii')
    with patch.object(PROFILE.subprocess, 'run', side_effect=AssertionError('Hidden subprocess')):
      self.assertTrue(PROFILE.admit_payload(self.manifest, self.payload, execute=execute))
    self.assertEqual(len(commands), 6)
    self.assertTrue(all(command[:2] == ['/usr/bin/bsdtar', '-xOf']
                        and command[-1] == '.PKGINFO' for command in commands))

  def test_wrong_candidate_subvolume_refused(self):
    self.manifest['subvolumes']['home'] = '@home'
    with self.assertRaisesRegex(ValueError, 'subvolumes'):
      PROFILE.validate_manifest(self.manifest)

  def test_changed_module_loader_and_package_file_refused(self):
    for name in ['usr/lib/modules/7.1.0-shield-bringup/example.ko', 'etc/ld.so.cache', 'usr/share/fixture/mesa']:
      with self.subTest(name=name):
        path = self.root / name
        previous = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'root differs'):
          PROFILE.verify_root(self.manifest, self.root)
        path.write_bytes(previous)

  def test_changed_file_mode_refused(self):
    path = self.root / 'usr/share/fixture/mesa'
    # Always change the observed mode, including under a private umask077.
    path.chmod((path.stat().st_mode & 0o777) ^ 0o100)
    with self.assertRaisesRegex(ValueError, 'root differs'):
      PROFILE.verify_root(self.manifest, self.root)

  def test_parent_symlink_escape_refused(self):
    parent = self.root / 'usr/share/fixture'
    target = self.base / 'outside'
    parent.rename(target)
    parent.symlink_to(target)
    with self.assertRaisesRegex(ValueError, 'parent'):
      PROFILE.verify_root(self.manifest, self.root)

  def test_unsafe_manifest_path_refused(self):
    self.manifest['root_files']['../outside'] = next(iter(self.manifest['root_files'].values()))
    with self.assertRaisesRegex(ValueError, 'Unsafe relative path'):
      PROFILE.validate_manifest(self.manifest)

  def test_stale_installed_version_refused(self):
    path = self.root / 'var/lib/pacman/local/mesa-1.0-1/desc'
    path.write_text('%NAME%\nmesa\n\n%VERSION%\n0.9-1\n')
    with self.assertRaisesRegex(ValueError, 'Installed dependency/package set differs'):
      PROFILE.verify_root(self.manifest, self.root)

  def test_unexpected_dependency_database_record_refused(self):
    directory = self.root / 'var/lib/pacman/local/unexpected-1.0-1'
    directory.mkdir()
    (directory / 'desc').write_text('%NAME%\nunexpected\n\n%VERSION%\n1.0-1\n')
    with self.assertRaisesRegex(ValueError, 'Installed dependency/package set differs'):
      PROFILE.verify_root(self.manifest, self.root)

  def test_changed_architecture_dependencies_and_mtree_refused(self):
    directory = self.root / 'var/lib/pacman/local/mesa-1.0-1'
    path = directory / 'desc'
    original = path.read_text()
    for content in [original.replace('aarch64', 'x86_64'), original + '\n%DEPENDS%\nunexpected\n']:
      path.write_text(content)
      with self.assertRaises(ValueError):
        PROFILE.verify_root(self.manifest, self.root)
    path.write_text(original)
    (directory / 'mtree').unlink()
    with self.assertRaisesRegex(ValueError, 'Missing installed mtree'):
      PROFILE.verify_root(self.manifest, self.root)

  def test_installed_time_is_intentionally_variable(self):
    path = self.root / 'var/lib/pacman/local/mesa-1.0-1/desc'
    path.write_text(path.read_text().replace('1234', '5678'))
    self.assertTrue(PROFILE.verify_root(self.manifest, self.root))

  def test_obsolete_mesa_alias_refused(self):
    (self.root / 'usr/share/fixture/obsolete-mesa.so').symlink_to('mesa')
    with self.assertRaisesRegex(ValueError, 'Obsolete installed path remains'):
      PROFILE.verify_root(self.manifest, self.root)


if __name__ == '__main__':
  unittest.main()
