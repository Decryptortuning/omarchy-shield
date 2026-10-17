"""Real Git export permissions are independent of private host umasks."""
import importlib.util
import os
from pathlib import Path
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
  def test_module_package_directories_are_public_without_changing_files_or_links(self):
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
      module.chmod(0o644)
      outside = base / 'outside'
      outside.mkdir(mode=0o700)
      outside.chmod(0o700)
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
      self.assertTrue((installed.parent / 'outside-link').is_symlink())
      self.assertEqual(os.readlink(installed.parent / 'outside-link'), str(outside))
      self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)


if __name__ == '__main__': unittest.main()
