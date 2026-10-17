"""Qualification admission refuses wrong artifacts before native effects."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools'))
from guardian_binding import BOARD, CONFIG_SHA256, DTB_SHA256, IMAGE_SHA256, SOURCE_NAMES, TIMING, USB, seal, validate
from qualification_recovery import mounts
from qualification_recovery import cleanup_deadline, SECOND


class GuardianBindingTests(unittest.TestCase):
  def body(self):
    candidate = '1' * 32
    root = '@shield-' + candidate
    return {'format_version': 1, 'role': 2, 'board': copy.deepcopy(BOARD),
      'kernel': {'release': '7.1.0-shield-bringup', 'image_sha256': IMAGE_SHA256,
                 'config_sha256': CONFIG_SHA256},
      'dtb': {'sha256': DTB_SHA256, 'bytes': 100},
      'filesystem': {'uuid': '11111111-1111-4111-8111-111111111111',
        'candidate_id': candidate, 'usb': copy.deepcopy(USB),
        'subvolumes': {'root': root, 'home': root + '-home', 'log': root + '-log'}},
      'overlay_sha256': '2' * 64, 'sources': {name: '3' * 64 for name in SOURCE_NAMES},
      'recovery_helper': {'sha256': '4' * 64, 'bytes': 1000},
      'account': {'name': 'shieldqual', 'uid': 1001, 'gid': 1001}, 'timing': copy.deepcopy(TIMING)}

  def test_mutation_after_sealing_is_rejected(self):
    profile = seal(self.body())
    profile['recovery_helper']['sha256'] = '5' * 64
    with self.assertRaisesRegex(ValueError, 'Binding digest differs'):
      validate(profile)

  def test_new_digest_cannot_admit_other_board_kernel_or_deadline(self):
    for field, key, value in [('board', 'model', 'Switch'), ('kernel', 'image_sha256', '5' * 64),
                              ('timing', 'final_seconds', 1200)]:
      with self.subTest(field=field):
        body = self.body(); body[field][key] = value
        with self.assertRaises(ValueError): seal(body)

  def test_alias_subvolumes_and_administrative_identity_are_rejected(self):
    for field, key, value in [('filesystem', 'subvolumes', {'root': '@', 'home': '@home', 'log': '@log'}),
                              ('account', 'uid', 0)]:
      with self.subTest(field=field):
        body = self.body(); body[field][key] = value
        with self.assertRaises(ValueError): seal(body)

  def test_role_is_bound_and_boolean_role_is_rejected(self):
    body = self.body(); systemd = seal(body)
    body['role'] = 1
    self.assertNotEqual(systemd['candidate'], seal(body)['candidate'])
    body['role'] = True
    with self.assertRaises(ValueError): seal(body)

  def test_source_path_escape_and_unknown_fields_are_rejected(self):
    body = self.body(); body['sources'] = {'../outside': '3' * 64}
    with self.assertRaises(ValueError): seal(body)
    body = self.body(); body['fallback_reboot'] = True
    with self.assertRaises(ValueError): seal(body)

  def test_kernel_mount_table_preserves_subvolumes_readonly_and_escapes(self):
    entries = mounts('42 1 0:28 /@shield-1 / rw,relatime shared:7 - btrfs /dev/sda1 rw,space_cache=v2\n'
                     '43 42 0:29 /@shield-1-home /home ro,relatime - btrfs /dev/disk/by-label/A\\040B ro,space_cache=v2\n')
    self.assertEqual(entries[0]['root'], '/@shield-1')
    self.assertEqual(entries[1]['source'], '/dev/disk/by-label/A B')
    self.assertIn('ro', entries[1]['options'])
    self.assertIn('ro', entries[1]['super_options'])
    with self.assertRaises(ValueError): mounts('not a kernel mount table')

  def test_delayed_cleanup_uses_existing_owner_deadline(self):
    owner = os.getpid()
    with patch('qualification_recovery.now', return_value=300 * SECOND), \
         patch('qualification_recovery.GuardianClient') as factory:
      client = factory.return_value; client.owner_pid = owner
      client.request.return_value = {'now_ns': 300 * SECOND, 'cleanup_cutoff_ns': 310 * SECOND}
      self.assertEqual(cleanup_deadline(seal(self.body()), owner), 310 * SECOND)
      client.request.return_value['cleanup_cutoff_ns'] = 299 * SECOND
      with self.assertRaisesRegex(ValueError, 'budget exhausted'):
        cleanup_deadline(seal(self.body()), owner)
      client.request.return_value['cleanup_cutoff_ns'] = 600 * SECOND
      client.owner_pid = 99
      with self.assertRaisesRegex(ValueError, 'owner changed'):
        cleanup_deadline(seal(self.body()), owner)

  def test_unavailable_owner_never_renews_quiesce_and_disconnect_is_finite(self):
    with patch('qualification_recovery.now', return_value=590 * SECOND), \
         patch('qualification_recovery.GuardianClient') as factory, \
         patch('qualification_recovery.os.pidfd_open', side_effect=PermissionError('not dead')):
      factory.return_value.request.side_effect = OSError('gone')
      with self.assertRaises(OSError): cleanup_deadline(seal(self.body()), 55)
      self.assertEqual(cleanup_deadline(seal(self.body()), 55, disconnected=True), 600 * SECOND)

  def test_preopen_fault_followed_by_confirmed_owner_death_has_one_budget(self):
    with patch('qualification_recovery.now', return_value=100 * SECOND), \
         patch('qualification_recovery.GuardianClient') as factory, \
         patch('qualification_recovery.os.pidfd_open', side_effect=ProcessLookupError('dead')):
      factory.return_value.request.side_effect = ConnectionRefusedError('owner exited')
      self.assertEqual(cleanup_deadline(seal(self.body()), 55), 145 * SECOND)


if __name__ == '__main__':
  unittest.main()
