"""Current source intent must reject self-consistent stale kernel bundles."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock
import tempfile
import unittest

PORT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('kernel_profile', PORT / 'tools/kernel_profile.py')
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class KernelIntentTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix='shield-kernel-intent-')
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.source = self.root / 'source'
    self.bundle = self.root / 'bundle'
    self.bundle.mkdir()
    self.lock = json.loads((PORT / 'kernel.lock.json').read_text())
    fragments = ['ports/shield/config/bringup.fragment', self.lock['kernel']['config_fragment']]
    fragments += self.lock['kernel'].get('additional_config_fragments', [])
    paths = ['ports/shield/kernel.lock.json', *fragments, self.lock['hardware_matrix']['path']]
    paths += [x['path'] for x in self.lock['kernel']['patches']]
    paths += [x['path'] for x in self.lock['kernel']['device_tree_overlays']]
    for relative in paths:
      target = self.source / relative
      target.parent.mkdir(parents=True, exist_ok=True)
      shutil.copy2(PORT.parent.parent / relative, target)
    self.dump('sources.lock.json', self.lock)
    self.dump('applied-patches.json', {'base_commit': self.lock['kernel']['commit'],
                                     'patches': self.lock['kernel']['patches']})
    shutil.copy2(PORT.parent.parent / self.lock['hardware_matrix']['path'], self.bundle / 'hardware.json')
    dts = self.root / 'board.dts'
    dts.write_text('/dts-v1/; / { compatible = "nvidia,p2894-0050-a04", "nvidia,darcy", "nvidia,tegra210"; };\n')
    self.dtb = self.bundle / 'tegra210-p2894-0050-a04.dtb'
    subprocess.run(['dtc', '-I', 'dts', '-O', 'dtb', '-o', str(self.dtb), str(dts)],
                   capture_output=True, check=True)
    self.dump('device-tree-overlays.json', {'overlays': self.lock['kernel']['device_tree_overlays'],
                                           'result_dtb_sha256': self.sha(self.dtb)})
    (self.bundle / 'kernel.config').write_text('\n'.join([
      'CONFIG_ARM64=y', 'CONFIG_WATCHDOG=y', 'CONFIG_WATCHDOG_CORE=y', 'CONFIG_TEGRA_WATCHDOG=y',
      'CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y', 'CONFIG_WATCHDOG_OPEN_TIMEOUT=600']) + '\n')
    self.provenance = {'inputs': [{'path': p, 'sha256': self.sha(self.source / p)} for p in fragments],
                       'resolved_config_sha256': self.sha(self.bundle / 'kernel.config')}
    self.dump('config-fragments.json', self.provenance)

  @staticmethod
  def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

  def dump(self, name, value):
    (self.bundle / name).write_text(json.dumps(value) + '\n')

  def verify(self):
    return PROFILE.verify_kernel_intent(self.bundle, self.source)

  def test_current_intent_admitted(self):
    self.assertEqual(self.verify()[0], self.lock)

  def test_self_consistent_old_patch_bundle_refused(self):
    old = json.loads(json.dumps(self.lock))
    old['kernel']['patches'] = old['kernel']['patches'][:9]
    self.dump('sources.lock.json', old)
    self.dump('applied-patches.json', {'base_commit': old['kernel']['commit'], 'patches': old['kernel']['patches']})
    with self.assertRaisesRegex(ValueError, 'exported source commit intent'):
      self.verify()

  def test_wrong_patch_order_refused(self):
    self.dump('applied-patches.json', {'base_commit': self.lock['kernel']['commit'],
                                     'patches': list(reversed(self.lock['kernel']['patches']))})
    with self.assertRaisesRegex(ValueError, 'ordered patch set'):
      self.verify()

  def test_new_fragment_with_old_compilation_refused(self):
    fragment = self.source / self.lock['kernel']['config_fragment']
    fragment.write_text(fragment.read_text() + '\n# changed current intent\n')
    with self.assertRaisesRegex(ValueError, 'configuration provenance'):
      self.verify()

  def test_wrong_resolved_configuration_refused(self):
    config = self.bundle / 'kernel.config'
    config.write_text(config.read_text().replace('CONFIG_TEGRA_WATCHDOG=y', 'CONFIG_TEGRA_WATCHDOG=m'))
    self.provenance['resolved_config_sha256'] = self.sha(config)
    self.dump('config-fragments.json', self.provenance)
    with self.assertRaisesRegex(ValueError, 'built-in inherited watchdog'):
      self.verify()

  def test_mismatched_overlay_result_refused(self):
    self.dump('device-tree-overlays.json', {'overlays': self.lock['kernel']['device_tree_overlays'],
                                           'result_dtb_sha256': '0' * 64})
    with self.assertRaisesRegex(ValueError, 'resulting DTB'):
      self.verify()

  def test_mutated_exported_patch_refused(self):
    patch = self.source / self.lock['kernel']['patches'][-1]['path']
    patch.write_text(patch.read_text() + '\nchanged\n')
    with self.assertRaisesRegex(ValueError, 'Exported source input'):
      self.verify()

  def stale_checksummed_bundle(self):
    old = json.loads(json.dumps(self.lock))
    old['kernel']['patches'] = old['kernel']['patches'][:9]
    self.dump('sources.lock.json', old)
    self.dump('applied-patches.json', {'base_commit': old['kernel']['commit'], 'patches': old['kernel']['patches']})
    records = [self.sha(p) + '  ' + p.name for p in sorted(self.bundle.iterdir()) if p.is_file()]
    (self.bundle / 'SHA256SUMS').write_text('\n'.join(records) + '\n')

  def test_stager_rejects_stale_bundle_before_root_build_mutation(self):
    self.stale_checksummed_bundle()
    rootfs = self.root / 'rootfs'
    marker = rootfs / 'var/lib/shield-linux/sources.lock.json'
    marker.parent.mkdir(parents=True)
    marker.write_text('{}')
    recipes = self.root / 'recipes'
    recipes.mkdir()
    spec = importlib.util.spec_from_file_location('shield_stage_intent', PORT / 'stage-packages.py')
    stage = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, 'path', [str(PORT), *sys.path]):
      spec.loader.exec_module(stage)

    def git(repository, *arguments, **options):
      if arguments[0] == 'rev-parse':
        return SimpleNamespace(stdout='c' * 40 + '\n')
      if arguments[0] == 'show':
        return SimpleNamespace(stdout=json.dumps({'packaging': {'commit': 'a' * 40}}))
      return SimpleNamespace(stdout='')

    def export(repository, commit, destination, *paths):
      shutil.copytree(self.source, destination, dirs_exist_ok=True)

    args = ['stage-packages.py', '--rootfs', str(rootfs), '--recipes', str(recipes),
            '--kernel-dir', str(self.bundle), '--commit', 'c' * 40]
    with mock.patch.object(stage, 'git', git), mock.patch.object(stage, 'export', export), mock.patch.object(sys, 'argv', args):
      with self.assertRaisesRegex(SystemExit, 'exported source commit intent'):
        stage.main()
    self.assertFalse((rootfs / 'build').exists())

  def test_package_prepare_rejects_stale_bundle_before_copy(self):
    self.stale_checksummed_bundle()
    helper = self.source / 'ports/shield/tools/kernel_profile.py'
    helper.parent.mkdir(parents=True)
    shutil.copy2(PORT / 'tools/kernel_profile.py', helper)
    binaries = self.root / 'bin'
    binaries.mkdir()
    (binaries / 'python').symlink_to(sys.executable)
    import os
    env = dict(os.environ, OMARCHY_SRC=str(self.source), SHIELD_KERNEL_DIR=str(self.bundle),
               srcdir=str(self.root / 'package-source'), PATH=str(binaries) + ':' + os.environ['PATH'])
    result = subprocess.run(['bash', '-c', 'source "$1"; prepare', 'bash',
                             str(PORT / 'linux-shield/PKGBUILD')], env=env, capture_output=True, text=True)
    self.assertNotEqual(result.returncode, 0)
    self.assertIn('exported source commit intent', result.stderr)
    self.assertFalse((self.root / 'package-source/compiled').exists())

  def test_configure_refuses_stale_build_audit_before_root_mutation(self):
    rootfs = self.root / 'configure-root'
    marker = rootfs / 'var/lib/shield-linux/sources.lock.json'
    marker.parent.mkdir(parents=True)
    marker.write_text('{}')
    recipes = self.root / 'configure-recipes'
    recipes.mkdir()
    lock = json.loads((PORT / 'userspace.lock.json').read_text())
    audit = self.root / 'stale-audit.json'
    audit.write_text(json.dumps({'all_package_names_available': True,
                                 'repositories': lock['repositories'], 'resolved': {}}))
    spec = importlib.util.spec_from_file_location('shield_configure_intent', PORT / 'configure-build.py')
    configure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(configure)
    args = ['configure-build.py', '--rootfs', str(rootfs), '--recipes', str(recipes),
            '--audit', str(audit), '--metadata-dir', str(self.root / 'metadata')]
    with mock.patch.object(sys, 'argv', args):
      with self.assertRaisesRegex(SystemExit, 'Re-audit every locked build package'):
        configure.main()
    self.assertFalse((rootfs / 'var/lib/pacman/sync').exists())
    self.assertFalse((marker.parent / 'repository-packages.txt').exists())

  def test_missing_fragment_provenance_refused(self):
    (self.bundle / 'config-fragments.json').unlink()
    with self.assertRaises(FileNotFoundError):
      self.verify()


if __name__ == '__main__':
  unittest.main()
