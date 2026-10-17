"""Exercise the actual VM-copy account and mount boundaries without privilege."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parent.parent / 'tools/qemu-guest-profile.sh'
ROOT = 'root:x:0:0:root:/root:/bin/bash\n'


class QemuGuestProfileTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix='shield-vm-profile-')
    self.addCleanup(self.temporary.cleanup)
    self.directory = Path(self.temporary.name)
    self.source = self.directory / 'source'
    self.guest = self.directory / 'guest'
    for path in [self.source, self.guest]:
      (path / 'etc').mkdir(parents=True)
      (path / 'etc/passwd').write_text(ROOT)
      (path / 'etc/fstab').write_text('UUID=physical-owner-root / btrfs rw,subvol=@ 0 0\n')
      (path / 'etc/crypttab').write_text('# no predefined mappings\n')
    self.bin = self.directory / 'bin'
    self.bin.mkdir()
    stub = self.bin / 'usermod'
    stub.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$VM_CALL_LOG"\n')
    stub.chmod(0o755)
    self.calls = self.directory / 'calls'
    self.environment = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'], VM_CALL_LOG=str(self.calls))

  def run_helper(self, command, *args):
    return subprocess.run(['bash', '-c', 'source "$1"; shift; "$@"', 'bash', str(HELPER), command, *map(str, args)],
                          env=self.environment, capture_output=True, text=True)

  def test_finalized_root_without_alarm_is_valid_and_only_root_locked(self):
    self.assertEqual(self.run_helper('shield_qemu_validate_source', self.source).returncode, 0)
    self.assertEqual(self.run_helper('shield_qemu_lock_accounts', self.guest).returncode, 0)
    self.assertEqual(self.calls.read_text().splitlines(), [f'--root {self.guest} --lock root'])

  def test_optional_dev_accounts_locked_when_present(self):
    with (self.guest / 'etc/passwd').open('a') as f:
      f.write('alarm:x:1000:1000::/home/alarm:/bin/bash\nportbuild:x:1001:1001::/home/portbuild:/bin/bash\n')
    self.assertEqual(self.run_helper('shield_qemu_lock_accounts', self.guest).returncode, 0)
    self.assertEqual(self.calls.read_text().splitlines(), [f'--root {self.guest} --lock {x}' for x in ['root', 'alarm', 'portbuild']])

  def test_missing_root_refused_before_usermod(self):
    (self.guest / 'etc/passwd').write_text('nobody:x:65534:65534::/:/usr/bin/nologin\n')
    self.assertNotEqual(self.run_helper('shield_qemu_lock_accounts', self.guest).returncode, 0)
    self.assertFalse(self.calls.exists())

  def test_preexisting_test_user_refused_before_usermod(self):
    with (self.guest / 'etc/passwd').open('a') as f:
      f.write('qemutest:x:1000:1000::/home/qemutest:/bin/bash\n')
    self.assertNotEqual(self.run_helper('shield_qemu_lock_accounts', self.guest).returncode, 0)
    self.assertFalse(self.calls.exists())

  def test_physical_crypto_mapping_refused(self):
    (self.source / 'etc/crypttab').write_text('physical UUID=owned-root none luks\n')
    self.assertNotEqual(self.run_helper('shield_qemu_validate_source', self.source).returncode, 0)

  def test_crypto_read_error_refused(self):
    stub = self.bin / 'grep'
    stub.write_text('#!/bin/bash\nexit 2\n')
    stub.chmod(0o755)
    result = self.run_helper('shield_qemu_validate_source', self.source)
    self.assertNotEqual(result.returncode, 0)
    self.assertIn('Cannot inspect VM source crypttab', result.stderr)

  def test_symlinked_crypto_configuration_refused(self):
    path = self.source / 'etc/crypttab'
    path.unlink()
    path.symlink_to(self.guest / 'etc/crypttab')
    self.assertNotEqual(self.run_helper('shield_qemu_validate_source', self.source).returncode, 0)

  def test_virtual_mount_profile_changes_guest_only(self):
    before = (self.source / 'etc/fstab').read_bytes()
    self.assertEqual(self.run_helper('shield_qemu_write_mounts', self.source, self.guest).returncode, 0)
    self.assertEqual((self.source / 'etc/fstab').read_bytes(), before)
    self.assertIn('/dev/vda / ext4 defaults 0 1', (self.guest / 'etc/fstab').read_text())
    self.assertNotIn('physical-owner-root', (self.guest / 'etc/fstab').read_text())

  def test_same_or_nested_target_refused_without_source_change(self):
    before = (self.source / 'etc/fstab').read_bytes()
    self.assertNotEqual(self.run_helper('shield_qemu_write_mounts', self.source, self.source).returncode, 0)
    nested = self.source / 'nested'
    nested.mkdir()
    self.assertNotEqual(self.run_helper('shield_qemu_write_mounts', self.source, nested).returncode, 0)
    self.assertEqual((self.source / 'etc/fstab').read_bytes(), before)


if __name__ == '__main__':
  unittest.main()
