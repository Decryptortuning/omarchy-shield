"""Real Git export permissions are independent of private host umasks."""
import importlib.util
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
SPEC = importlib.util.spec_from_file_location('shield_package_stager', PORT / 'stage-packages.py')
STAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGER)


class SourceExportTests(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory(prefix='shield-source-export-')
    self.addCleanup(self.temp.cleanup)
    self.base = Path(self.temp.name)
    self.repo = self.base / 'repository'
    self.repo.mkdir()
    self.git('init', '--quiet', '--template=')
    nested = self.repo / 'themes/example/backgrounds'
    nested.mkdir(parents=True)
    (nested / 'public.txt').write_text('public source\n')
    (nested / 'public.txt').chmod(0o644)
    (nested / 'tool').write_text('#!/bin/bash\nexit 0\n')
    (nested / 'tool').chmod(0o755)
    (nested / 'tool-link').symlink_to('tool')
    self.commit()

  def git(self, *args):
    return subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=SHIELD test',
      '-c', 'user.email=shield-test@example.invalid', '-c', 'commit.gpgsign=false', *args],
      check=True, capture_output=True, text=True,
      env={**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'})

  def commit(self):
    self.git('add', '.')
    self.git('commit', '--quiet', '-m', 'Export fixture')
    self.commit_id = self.git('rev-parse', 'HEAD').stdout.strip()

  def test_public_directories_and_file_exec_bits_under_both_umasks(self):
    for mask in [0o077, 0o022]:
      with self.subTest(umask=oct(mask)):
        output = self.base / ('export-' + oct(mask))
        output.mkdir(mode=0o700)
        output.chmod(0o700)
        previous = os.umask(mask)
        try:
          STAGER.export(self.repo, self.commit_id, output)
        finally:
          os.umask(previous)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for relative in ['themes', 'themes/example', 'themes/example/backgrounds']:
          self.assertEqual(stat.S_IMODE((output / relative).stat().st_mode), 0o755)
        nested = output / 'themes/example/backgrounds'
        self.assertEqual(stat.S_IMODE((nested / 'public.txt').stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((nested / 'tool').stat().st_mode), 0o755)
        self.assertEqual((nested / 'public.txt').read_text(), 'public source\n')
        self.assertTrue((nested / 'tool-link').is_symlink())
        self.assertEqual(os.readlink(nested / 'tool-link'), 'tool')

  def test_outside_link_remains_refused_and_host_target_mode_unchanged(self):
    outside = self.base / 'outside'
    outside.mkdir(mode=0o700)
    outside.chmod(0o700)
    (self.repo / 'escape').symlink_to('../outside', target_is_directory=True)
    self.commit()
    output = self.base / 'rejected'
    output.mkdir(mode=0o700)
    with self.assertRaises(tarfile.FilterError):
      STAGER.export(self.repo, self.commit_id, output)
    self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)


class KernelModulePackageTests(unittest.TestCase):
  def test_module_package_permissions_are_public_without_changing_data_or_link_targets(self):
    # Exercise the actual package() boundary, not kernel compilation/admission.
    with tempfile.TemporaryDirectory(prefix='shield-module-package-') as temporary:
      base = Path(temporary)
      release = '7.1.0-shield-bringup'
      module_root = base / 'modules'
      module = module_root / 'lib/modules' / release / 'kernel/example.ko'
      module.parent.mkdir(parents=True)
      for directory in [module_root, *[p for p in module_root.rglob('*') if p.is_dir()]]:
        directory.chmod(0o700)
      module.write_bytes(b'fixture module bytes\n')
      module.chmod(0o600)
      metadata = module.parent.parent / 'modules.builtin'
      metadata.write_bytes(b'fixture module metadata\n')
      metadata.chmod(0o600)
      outside = base / 'outside'
      outside.mkdir(mode=0o700)
      outside.chmod(0o700)
      outside_file = outside / 'outside.ko'
      outside_file.write_bytes(b'outside fixture bytes\n')
      outside_file.chmod(0o600)
      (module.parent / 'outside-link').symlink_to(outside, target_is_directory=True)
      compiled = base / 'source/compiled'
      compiled.mkdir(parents=True)
      dtb = 'tegra210-p2894-0050-a04.dtb'
      (compiled / 'kernel-release.txt').write_text(release + '\n')
      (compiled / 'dtb-name.txt').write_text(dtb + '\n')
      for name in ['Image', 'Image.gz', 'kernel.config', 'config-fragments.json', dtb,
                   'hardware.json', 'sources.lock.json', 'compiler.txt', 'applied-patches.json',
                   'source-verification.json', 'device-tree-overlays.json']:
        (compiled / name).write_bytes(b'fixture kernel bundle\n')
      subprocess.run(['bsdtar', '--zstd', '-cf', str(compiled / 'kernel-modules.tar.zst'),
        '-C', str(module_root), 'lib/modules'], check=True, capture_output=True)
      package = base / 'package'
      package.mkdir(mode=0o700)
      subprocess.run(['bash', '-eu', '-c', 'source "$1"; srcdir=$2; pkgdir=$3; package',
        'bash', str(PORT / 'linux-shield/PKGBUILD'), str(compiled.parent), str(package)],
        check=True, capture_output=True, umask=0o077,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
      for directory in [p for p in (package / 'usr').rglob('*') if p.is_dir() and not p.is_symlink()]:
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
      installed = package / 'usr/lib/modules' / release / 'kernel/example.ko'
      self.assertEqual(installed.read_bytes(), module.read_bytes())
      self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)
      self.assertEqual(stat.S_IMODE(module.stat().st_mode), 0o600)
      installed_metadata = installed.parent.parent / 'modules.builtin'
      self.assertEqual(installed_metadata.read_bytes(), metadata.read_bytes())
      self.assertEqual(stat.S_IMODE(installed_metadata.stat().st_mode), 0o644)
      self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o600)
      self.assertEqual(stat.S_IMODE((installed.parent.parent / 'pkgbase').stat().st_mode), 0o644)
      self.assertTrue((installed.parent / 'outside-link').is_symlink())
      self.assertEqual(os.readlink(installed.parent / 'outside-link'), str(outside))
      self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)
      self.assertEqual(outside_file.read_bytes(), b'outside fixture bytes\n')
      self.assertEqual(stat.S_IMODE(outside_file.stat().st_mode), 0o600)


@unittest.skipUnless(os.geteuid() == 0, 'Disposable UID/GID migration fixtures require root')
class KernelModuleUpgradeTests(unittest.TestCase):
  def script(self, root):
    source = (PORT / 'linux-shield/linux-shield.install').read_text()
    fixed_path = '/usr/lib/modules/7.1.0-shield-bringup'
    self.assertEqual(source.count(fixed_path), 1)
    # Rebase only the fixed pathname in a test copy; production has no override.
    return source.replace(fixed_path, shlex.quote(str(root)))

  def run_script(self, root, entrypoint, success=True):
    result = subprocess.run(['bash', '-eu', '-c', self.script(root) + '\n' + entrypoint],
      capture_output=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    self.assertEqual(result.returncode == 0, success, result.stderr.decode(errors='replace'))

  def test_install_and_upgrade_repair_only_real_module_directories(self):
    for entrypoint in ['post_install', 'post_upgrade']:
      with self.subTest(entrypoint=entrypoint), tempfile.TemporaryDirectory(prefix='shield-module-owner-') as temporary:
        base = Path(temporary)
        root = base / 'modules'
        nested = root / 'kernel/drivers'
        nested.mkdir(parents=True)
        directories = [root, root / 'kernel', nested]
        for directory in directories:
          os.chown(directory, 1000, 1000)
          directory.chmod(0o700)
        module = nested / 'example.ko'
        module.write_bytes(b'unchanged module bytes\n')
        os.chown(module, 0, 0)
        module.chmod(0o644)
        outside = base / 'outside'
        outside.mkdir(mode=0o700)
        outside.chmod(0o700)
        os.chown(outside, 1000, 1000)
        link = root / 'outside-link'
        link.symlink_to(outside, target_is_directory=True)
        self.run_script(root, entrypoint)
        for directory in directories:
          info = directory.lstat()
          self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o755))
        self.assertEqual(module.read_bytes(), b'unchanged module bytes\n')
        info = module.lstat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o644))
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(outside))
        info = outside.lstat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (1000, 1000, 0o700))

  def test_symlink_module_root_is_refused_without_touching_target(self):
    with tempfile.TemporaryDirectory(prefix='shield-module-root-link-') as temporary:
      base = Path(temporary)
      outside = base / 'outside'
      outside.mkdir(mode=0o700)
      outside.chmod(0o700)
      os.chown(outside, 1000, 1000)
      root = base / 'modules'
      root.symlink_to(outside, target_is_directory=True)
      self.run_script(root, 'post_upgrade', success=False)
      info = outside.lstat()
      self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (1000, 1000, 0o700))

  def test_symlink_ancestor_is_refused_before_directory_owner_changes(self):
    with tempfile.TemporaryDirectory(prefix='shield-module-parent-link-') as temporary:
      base = Path(temporary)
      parent = base / 'real-parent'
      root = parent / 'modules'
      root.mkdir(parents=True)
      for directory in [parent, root]:
        directory.chmod(0o700)
        os.chown(directory, 1000, 1000)
      alias = base / 'alias'
      alias.symlink_to(parent, target_is_directory=True)
      self.run_script(alias / 'modules', 'post_upgrade', success=False)
      for directory in [parent, root]:
        info = directory.lstat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (1000, 1000, 0o700))
      self.assertTrue(alias.is_symlink())


if __name__ == '__main__': unittest.main()
