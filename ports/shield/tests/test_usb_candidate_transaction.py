"""Transaction flow tests with real journals and a fenced command executor.

Root-only cases use an owned /run fixture, never a block device or mount.
Real Btrfs/ALPM and physical admission remain separate integration checks.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

PORT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PORT / 'tools'))
import usb_candidate_transaction as TRANSACTION
from usb_root_profile import database_profile, digest

SPEC = importlib.util.spec_from_file_location('usb_profile_fixture', PORT / 'tests/test_usb_root_profile.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class PlanFixture:
  def setUp(self):
    self.fixture = FIXTURE.UsbRootProfileTests()
    self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.manifest = self.fixture.manifest
    self.plan = {'format_version': 1, 'candidate_id': self.manifest['candidate_id'],
      'filesystem_uuid': self.manifest['filesystem_uuid'],
      'payload_canonical_sha256': hashlib.sha256(json.dumps(self.manifest, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest(),
      'original_subvolumes': {'root': '@', 'home': '@home', 'log': '@log'},
      'minimum_free_bytes': 3 * 1024**3, 'base_database': database_profile(self.fixture.root),
      'base_files': {'usr/share/fixture/mesa': digest(self.fixture.root / 'usr/share/fixture/mesa')}}

class PlanTests(PlanFixture, unittest.TestCase):
  def test_exact_plan_admitted(self):
    self.assertEqual(TRANSACTION.validate_plan(self.plan, self.manifest), self.plan)

  def test_changed_manifest_refused(self):
    self.manifest['root_files']['usr/share/fixture/mesa']['uid'] += 1
    with self.assertRaisesRegex(ValueError, 'manifest differs'):
      TRANSACTION.validate_plan(self.plan, self.manifest)

  def test_old_original_root_names_cannot_be_repurposed(self):
    self.plan['original_subvolumes']['home'] = '@other'
    with self.assertRaisesRegex(ValueError, 'Wrong original root set'):
      TRANSACTION.validate_plan(self.plan, self.manifest)

  def test_missing_capacity_reservation_refused(self):
    self.plan['minimum_free_bytes'] = 0
    with self.assertRaisesRegex(ValueError, 'capacity reservation'):
      TRANSACTION.validate_plan(self.plan, self.manifest)


@unittest.skipUnless(os.geteuid() == 0, 'Run the fenced journal/transaction flow cases as WSL root')
class RootTransactionTests(PlanFixture, unittest.TestCase):
  def setUp(self):
    super().setUp()
    temporary = tempfile.TemporaryDirectory(prefix='shield-transaction-test-', dir='/run')
    self.addCleanup(temporary.cleanup)
    self.run_root = Path(temporary.name)
    self.payload = self.run_root / 'packages'
    shutil.copytree(self.fixture.payload, self.payload)
    self.top = self.run_root / 'top'
    self.top.mkdir()
    shutil.copytree(self.fixture.root, self.top / '@')
    for relative in ['home', 'var/log', 'dev', 'proc', 'sys', 'run']:
      (self.top / '@' / relative).mkdir(parents=True, exist_ok=True)
    (self.top / '@home').mkdir()
    (self.top / '@log').mkdir()
    self.commands = []
    self.budgets = []
    self.fail = None
    capacity = mock.patch.object(TRANSACTION.os, 'statvfs', return_value=SimpleNamespace(
      f_bavail=4 * 1024**3 // 4096, f_frsize=4096))
    capacity.start()
    self.addCleanup(capacity.stop)

  def execute(self, command):
    self.commands.append(command)
    if self.fail and self.fail(command):
      raise subprocess.CalledProcessError(1, command)
    if command[:3] == ['btrfs', 'subvolume', 'get-default']:
      return 'ID 5 (FS_TREE)\n'
    if command[:3] == ['btrfs', 'subvolume', 'snapshot']:
      shutil.copytree(command[3], command[4])
    # mount, umount, ALPM and sync are fenced; no system command is executed.
    return ''

  def update(self):
    return TRANSACTION.update_candidate(self.plan, self.manifest, self.payload, self.top,
      guard_check=self.budgets.append, execute=self.execute)

  def state(self):
    return json.loads((self.top / '.shield-qualification' / self.manifest['candidate_id'] / 'state.json').read_text())

  def test_success_preserves_old_root_and_never_claims_boot_ready(self):
    result = self.update()
    self.assertEqual(result['state'], 'VERIFIED')
    self.assertFalse(result['boot_ready'])
    self.assertFalse(result['top_level_clean_unmount_verified'])
    self.assertEqual(self.state()['state'], 'VERIFIED')
    TRANSACTION.base_unchanged(self.top, self.plan)
    snapshots = [cmd for cmd in self.commands if cmd[:3] == ['btrfs', 'subvolume', 'snapshot']]
    self.assertEqual(len(snapshots), 3)
    self.assertEqual(len([cmd for cmd in self.commands if cmd[0] == 'umount']), 6)
    self.assertEqual(len([cmd for cmd in self.commands if '-U' in cmd]), 1)
    self.assertNotIn(['btrfs', 'subvolume', 'set-default'], [cmd[:3] for cmd in self.commands])

  def test_second_attempt_refused_without_replaying_effects(self):
    self.update()
    count = len(self.commands)
    with self.assertRaisesRegex(ValueError, 'no replay'):
      self.update()
    self.assertEqual(len(self.commands), count)

  def test_package_failure_keeps_incomplete_state_and_cleans_owned_bindings(self):
    self.fail = lambda command: '-U' in command
    with self.assertRaises(subprocess.CalledProcessError):
      self.update()
    self.assertEqual(self.state()['state'], 'INCOMPLETE')
    self.assertEqual(len([cmd for cmd in self.commands if cmd[0] == 'umount']), 6)
    TRANSACTION.base_unchanged(self.top, self.plan)

  def test_failed_nested_unmount_never_marks_verified(self):
    self.fail = lambda command: command[0] == 'umount'
    with self.assertRaisesRegex(ValueError, 'did not all unmount'):
      self.update()
    self.assertEqual(self.state()['state'], 'INCOMPLETE')
    self.assertEqual(self.state()['phase'], 'nested-unmount-failed')

  def test_failed_final_sync_restores_incomplete_interlock(self):
    syncs = []
    def fail(command):
      if command[:3] == ['btrfs', 'filesystem', 'sync']:
        syncs.append(command)
        return len(syncs) == 2
      return False
    self.fail = fail
    with self.assertRaises(subprocess.CalledProcessError):
      self.update()
    self.assertEqual(self.state()['state'], 'INCOMPLETE')
    self.assertEqual(self.state()['phase'], 'final-sync-failed')

  def test_bad_original_root_refused_before_durable_journal(self):
    (self.top / '@/usr/share/fixture/mesa').write_text('changed')
    with self.assertRaisesRegex(ValueError, 'bootstrap file changed'):
      self.update()
    self.assertFalse((self.top / '.shield-qualification').exists())
    self.assertEqual(self.commands, [])

  def test_insufficient_capacity_refused_before_durable_journal(self):
    with mock.patch.object(TRANSACTION.os, 'statvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)):
      with self.assertRaisesRegex(ValueError, 'free space'):
        self.update()
    self.assertFalse((self.top / '.shield-qualification').exists())
    self.assertEqual(self.commands, [])

  def test_mount_destination_rejects_symlink_parent(self):
    candidate = self.top / '@'
    shutil.rmtree(candidate / 'var')
    (candidate / 'var').symlink_to(self.top / '@log', target_is_directory=True)
    with self.assertRaisesRegex(ValueError, 'real directory'):
      TRANSACTION.mount_destination(candidate, 'var/log')

  def test_unowned_mount_destination_refused(self):
    with self.assertRaisesRegex(ValueError, 'Unowned mount'):
      TRANSACTION.mount_destination(self.top / '@', 'tmp')


if __name__ == '__main__':
  unittest.main()
