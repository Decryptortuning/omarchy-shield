"""Unrun phase-B source fixtures; temporary directories only, no device/process IO.

The synthetic LayerContent fixtures model the already admitted reader boundary.
They do not claim to test archive admission, physical provenance or a mount lease.
Filesystem cases require root to exercise actual intended UID/GID metadata.
"""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_layer_reader import LayerContent, LayerPin, freeze
import native_layer_writer as writer
from maintenance_accounts import validate_accounts

CID = 'a' * 32
FSID = '11111111-2222-4333-8444-555555555555'


def accounts():
  # The signed original image has no build account. Keep an original service
  # identity so byte-preservation checks exercise more than the root row.
  before = {
    'etc/passwd': b'root:x:0:0:root:/root:/bin/bash\ndaemon:x:2:2:daemon:/:/usr/bin/nologin\n',
    'etc/group': b'root:x:0:\ndaemon:x:2:\nvideo:x:27:\nrender:x:44:\naudio:x:49:\ninput:x:52:\n',
    'etc/shadow': b'root:*:1:0:99999:7:::\ndaemon:!:1:0:99999:7:::\n',
    'etc/gshadow': b'root:!::\ndaemon:!::\nvideo:!::\nrender:!::\naudio:!::\ninput:!::\n'}
  after = {
    'etc/passwd': before['etc/passwd'] + b'shieldqual:x:1001:1001::/home/shieldqual:/bin/bash\n',
    'etc/group': b'root:x:0:\ndaemon:x:2:\nvideo:x:27:shieldqual\nrender:x:44:shieldqual\naudio:x:49:shieldqual\ninput:x:52:shieldqual\nshieldqual:x:1001:\n',
    'etc/shadow': b'root:!:2:0:99999:7:::\ndaemon:!:1:0:99999:7:::\nshieldqual:!:2:0:99999:7:::\n',
    'etc/gshadow': b'root:!::\ndaemon:!::\nvideo:!::shieldqual\nrender:!::shieldqual\naudio:!::shieldqual\ninput:!::shieldqual\nshieldqual:!::\n'}
  return before, after


class AccountSemanticsTests(unittest.TestCase):
  def test_exact_original_baseline_adds_only_qualification_identity(self):
    before, after = accounts()
    for raw in [*before.values(), *after.values()]: self.assertNotIn(b'portbuild:', raw)
    validate_accounts(before, after)

  def test_builder_leak_into_original_or_desired_is_rejected(self):
    rows = {'etc/passwd': b'portbuild:x:1000:1000::/home/portbuild:/usr/bin/nologin\n',
      'etc/group': b'portbuild:x:1000:\n', 'etc/shadow': b'portbuild:!:2:0:99999:7::1:\n',
      'etc/gshadow': b'portbuild:!::\n'}
    for leak_original in [False, True]:
      before, after = accounts()
      for name, row in rows.items():
        after[name] += row
        if leak_original: before[name] += row
      with self.subTest(leak_original=leak_original), self.assertRaisesRegex(ValueError, 'Build account'):
        validate_accounts(before, after)

  def test_new_or_deleted_account_in_any_database_is_rejected(self):
    extras = {'etc/passwd': b'extra:x:300:300::/:/usr/bin/nologin\n',
      'etc/group': b'extra:x:300:\n', 'etc/shadow': b'extra:!:1:0:99999:7:::\n',
      'etc/gshadow': b'extra:!::\n'}
    for name, extra in extras.items():
      for addition in [False, True]:
        before, after = accounts()
        if addition: after[name] += extra
        else: after[name] = b''.join(line for line in after[name].splitlines(keepends=True)
                                   if not line.startswith(b'daemon:'))
        with self.subTest(database=name, addition=addition), self.assertRaises(ValueError):
          validate_accounts(before, after)

  def test_every_original_passwd_field_is_preserved(self):
    for original in [b'root', b'daemon']:
      for field in range(1, 7):
        before, after = accounts()
        rows = [line.split(b':') for line in after['etc/passwd'].splitlines()]
        for row in rows:
          if row[0] == original: row[field] += b'9' if field in {2, 3} else b'-changed'
        after['etc/passwd'] = b''.join(b':'.join(row) + b'\n' for row in rows)
        with self.subTest(account=original, field=field), self.assertRaises(ValueError):
          validate_accounts(before, after)

  def test_original_shadow_except_root_lock_and_date_is_preserved(self):
    for original in [b'root', b'daemon']:
      for field in range(1, 9):
        if original == b'root' and field in {1, 2}: continue
        before, after = accounts()
        rows = [line.split(b':') for line in after['etc/shadow'].splitlines()]
        for row in rows:
          if row[0] == original: row[field] += b'9'
        after['etc/shadow'] = b''.join(b':'.join(row) + b'\n' for row in rows)
        with self.subTest(account=original, field=field), self.assertRaises(ValueError):
          validate_accounts(before, after)

  def test_original_group_identity_and_admin_fields_are_preserved(self):
    for database in ['etc/group', 'etc/gshadow']:
      for field in [1, 2]:
        before, after = accounts()
        rows = [line.split(b':') for line in after[database].splitlines()]
        for row in rows:
          if row[0] == b'video': row[field] += b'9'
        after[database] = b''.join(b':'.join(row) + b'\n' for row in rows)
        with self.subTest(database=database, field=field), self.assertRaises(ValueError):
          validate_accounts(before, after)

  def test_second_uid_zero_or_qualification_uid_is_rejected(self):
    for old, new in [(b'shieldqual:x:1001:', b'shieldqual:x:0:'),
                     (b'daemon:x:2:2:', b'daemon:x:1001:2:')]:
      before, after = accounts()
      after['etc/passwd'] = after['etc/passwd'].replace(old, new)
      with self.subTest(new=new), self.assertRaises(ValueError): validate_accounts(before, after)

  def test_unrelated_privileged_group_membership_is_rejected(self):
    for database, old, new in [('etc/group', b'root:x:0:', b'root:x:0:shieldqual'),
                               ('etc/gshadow', b'root:!::', b'root:!::shieldqual')]:
      before, after = accounts()
      after[database] = after[database].replace(old, new)
      with self.subTest(database=database), self.assertRaises(ValueError): validate_accounts(before, after)

  def test_unlocked_root_or_qualification_account_is_rejected(self):
    for account in [b'root', b'shieldqual']:
      before, after = accounts()
      after['etc/shadow'] = after['etc/shadow'].replace(account + b':!:', account + b'::')
      with self.subTest(account=account), self.assertRaises(ValueError): validate_accounts(before, after)

  def test_root_shadow_date_is_nonnegative_bounded_days(self):
    for date in [b'', b'-1', b'2147483648', b'not-a-day']:
      before, after = accounts()
      after['etc/shadow'] = after['etc/shadow'].replace(b'root:!:2:', b'root:!:' + date + b':')
      with self.subTest(date=date), self.assertRaises(ValueError): validate_accounts(before, after)


@unittest.skipUnless(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
                     'Actual intended ownership fixtures require root')
class LayerWriterFilesystemTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    base = Path(self.temporary.name)
    self.root, self.home, self.journal = [base / name for name in ['root', 'home', 'phase-B']]
    for path in [self.root, self.home]: path.mkdir(mode=0o755)
    self.journal.mkdir(mode=0o700)
    self.before, self.after = accounts()
    for name in ['etc', 'etc/systemd', 'etc/systemd/system', 'etc/polkit-1',
                 'etc/polkit-1/rules.d', 'usr', 'usr/share']:
      (self.root / name).mkdir(mode=0o755)
    rules = self.root / 'etc/polkit-1/rules.d'
    os.chown(rules, 0, 102); rules.chmod(0o750)
    for name, data in self.before.items():
      path = self.root / name
      path.write_bytes(data); path.chmod(0o600 if 'shadow' in name else 0o644)
    (self.root / 'etc/machine-id').write_bytes(b'old-id\n')
    (self.root / 'etc/machine-id').chmod(0o644)
    (self.home / 'preserved').mkdir(mode=0o700)
    (self.home / 'preserved/keep').write_bytes(b'preexisting-owner-data')
    self.fds = [os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                for path in [self.root, self.home, self.journal]]
    for fd in self.fds: self.addCleanup(os.close, fd)
    self.addCleanup(patch.stopall)
    patch.object(writer, 'JOURNAL_PARENT', str(self.journal)).start()
    self.entries = {}
    self.expected = {}
    for name in ['etc', 'etc/systemd', 'etc/systemd/system', 'etc/polkit-1',
                 'etc/polkit-1/rules.d', 'usr', 'usr/share', 'home']:
      self.entries[name] = {'identity': self.live(name), 'roles': ['ancestor']}
    self.desired_bytes = {**self.after, 'etc/machine-id': b'',
      'usr/share/example': b'pinned qualification data\n',
      'home/shieldqual/.config/example': b'qualification configuration\n'}
    for name in self.desired_bytes:
      self.entries[name] = {'identity': None, 'roles': ['account'] if name in self.before
        else ['machine-id'] if name == 'etc/machine-id'
        else ['home'] if name.startswith('home/') else ['overlay']}
    for name in ['home/shieldqual', 'home/shieldqual/.config']:
      self.entries[name] = {'identity': {'type': 'directory', 'mode': 0o755,
        'uid': 1001, 'gid': 1001, 'xattrs': {}}, 'roles': ['ancestor', 'home']}
    self.entries['etc/systemd/system/example.service'] = {'identity': {
      'type': 'symlink', 'mode': 0o777, 'uid': 0, 'gid': 0, 'xattrs': {},
      'target': '/dev/null'}, 'roles': ['mask']}
    self.expected = {name: self.live(name) for name in self.entries}
    self.rebind()

  def path(self, name):
    return self.home if name == 'home' else self.home / name[5:] if name.startswith('home/') else self.root / name

  def live(self, name):
    path = self.path(name)
    try: info = path.lstat()
    except FileNotFoundError: return None
    result = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
      'xattrs': {key: os.getxattr(path, key, follow_symlinks=False).hex()
        for key in sorted(os.listxattr(path, follow_symlinks=False))}}
    if stat.S_ISREG(info.st_mode):
      result.update(type='file', bytes=info.st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    elif stat.S_ISDIR(info.st_mode): result['type'] = 'directory'
    else: result.update(type='symlink', target=os.readlink(path))
    return result

  def rebind(self):
    ranges, chunks, offset = {}, [], 0
    for name, data in self.desired_bytes.items():
      digest = hashlib.sha256(data).hexdigest()
      owner = 1001 if name.startswith('home/') else 0
      self.entries[name]['identity'] = {'type': 'file', 'sha256': digest, 'bytes': len(data),
        'mode': 0o600 if 'shadow' in name else 0o644, 'uid': owner, 'gid': owner, 'xattrs': {}}
      if digest not in ranges:
        ranges[digest] = (offset, len(data)); chunks.append(data); offset += len(data)
    self.manifest = {'sources': {'tools/fixture.py': 'd' * 64},
      'profile_sha256': 'b' * 64, 'payload_manifest_sha256': 'c' * 64,
      'filesystem': {'candidate_id': CID, 'uuid': FSID, 'subvolumes': {
        'root': '@shield-' + CID, 'home': '@shield-' + CID + '-home', 'log': '@shield-' + CID + '-log'}},
      'entries': self.entries}
    self.layer_pin = LayerPin('e' * 64, 1, hashlib.sha256(writer.canonical(self.manifest)).hexdigest(),
      'b' * 64, 'c' * 64, (('tools/fixture.py', 'd' * 64),))
    self.content = LayerContent(freeze(self.manifest), freeze(ranges), b''.join(chunks))
    original = {name: {key: self.expected[name][key] for key in writer.FIVE} for name in self.before}
    self.profile = {'format_version': 1, 'purpose': writer.PURPOSE, 'candidate_id': CID,
      'filesystem_uuid': FSID, 'phase_a_plan_sha256': 'f' * 64, 'phase_a_receipt_sha256': '9' * 64,
      'original_accounts_sha256': hashlib.sha256(writer.canonical(original)).hexdigest(),
      'original_accounts': original, 'layer': {key: getattr(self.layer_pin, key) for key in
        ['archive_sha256', 'manifest_sha256', 'profile_sha256', 'payload_manifest_sha256']},
      'roots': {'root': self.live_root(self.root), 'home': self.live_root(self.home)},
      'entries': self.expected}
    self.repin_profile()

  def live_root(self, path):
    info = path.stat()
    return {'type': 'directory', 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid,
      'gid': info.st_gid, 'xattrs': {key: os.getxattr(path, key).hex() for key in os.listxattr(path)}}

  def repin_profile(self):
    self.raw = writer.canonical(self.profile)
    self.pin = writer.WriterPin(self.layer_pin, hashlib.sha256(self.raw).hexdigest(), len(self.raw),
      CID, FSID, 'f' * 64, '9' * 64, self.profile['original_accounts_sha256'])

  def run_writer(self, guard=lambda: None):
    return writer.materialize(self.content, self.pin, self.raw, *self.fds, guard_check=guard)

  def test_materializes_exact_files_accounts_masks_and_separate_home(self):
    result = self.run_writer()
    self.assertEqual(result['state'], 'LAYER_MATERIALIZED')
    for key in ['boot_ready', 'clean_usb_release', 'physical_powerloss_qualified']:
      self.assertIs(result[key], False)
    for name, row in self.entries.items(): self.assertEqual(self.live(name), row['identity'])
    self.assertEqual((self.home / 'preserved/keep').read_bytes(), b'preexisting-owner-data')
    self.assertFalse((self.root / 'home').exists())
    self.assertTrue((self.journal / CID / 'INCOMPLETE.json').is_file())
    self.assertTrue((self.journal / CID / 'MATERIALIZED.json').is_file())
    with self.assertRaises(TypeError): result['boot_ready'] = True

  def test_one_mismatched_preimage_prevents_every_destination_write(self):
    (self.root / 'usr/share/example').write_bytes(b'unknown existing data')
    with self.assertRaises(ValueError): self.run_writer()
    for name, data in self.before.items(): self.assertEqual(self.path(name).read_bytes(), data)
    self.assertFalse((self.journal / CID).exists())

  def test_all_desired_account_semantics_checked_before_any_write(self):
    self.desired_bytes['etc/passwd'] = self.after['etc/passwd'].replace(b'shieldqual:x:1001:', b'shieldqual:x:0:')
    self.rebind()
    with self.assertRaises(ValueError): self.run_writer()
    self.assertFalse((self.journal / CID).exists())
    for name, data in self.before.items(): self.assertEqual(self.path(name).read_bytes(), data)

  def test_polkit_ancestor_is_never_repaired(self):
    path = self.root / 'etc/polkit-1/rules.d'
    os.chown(path, 0, 0)
    with self.assertRaises(ValueError): self.run_writer()
    self.assertEqual(path.stat().st_gid, 0)
    self.assertFalse((self.journal / CID).exists())

  def test_missing_ancestor_only_preimage_cannot_authorize_creation(self):
    self.expected['usr'] = None
    self.repin_profile()
    with self.assertRaises(ValueError): self.run_writer()
    self.assertFalse((self.journal / CID).exists())

  def test_symlink_parent_cannot_escape_supplied_root(self):
    outside = self.root.parent / 'outside'; outside.mkdir()
    (outside / 'passwd').write_bytes(b'outside sentinel')
    (self.root / 'etc').rename(self.root / 'old-etc')
    (self.root / 'etc').symlink_to(outside)
    with self.assertRaises((ValueError, OSError)): self.run_writer()
    self.assertEqual((outside / 'passwd').read_bytes(), b'outside sentinel')

  def test_existing_phase_b_journal_cannot_be_replayed(self):
    (self.journal / CID).mkdir(mode=0o700)
    with self.assertRaises(FileExistsError): self.run_writer()
    for name, data in self.before.items(): self.assertEqual(self.path(name).read_bytes(), data)

  def test_partial_failure_keeps_incomplete_state_and_never_reports_success(self):
    original = writer.apply_one
    def failed(roots, name, wanted, expected):
      original(roots, name, wanted, expected)
      if name == 'etc/machine-id': raise OSError('synthetic interruption')
    with patch.object(writer, 'apply_one', side_effect=failed):
      with self.assertRaises(OSError): self.run_writer()
    self.assertTrue((self.journal / CID / 'INCOMPLETE.json').is_file())
    self.assertFalse((self.journal / CID / 'MATERIALIZED.json').exists())
    with self.assertRaises((ValueError, FileExistsError)): self.run_writer()

  def test_atomic_new_commit_never_overwrites_a_racing_destination(self):
    original = writer.noreplace
    def collide(parent, source, destination):
      if destination == 'example':
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
        try: os.write(fd, b'unexpected collision')
        finally: os.close(fd)
      original(parent, source, destination)
    with patch.object(writer, 'noreplace', side_effect=collide):
      with self.assertRaises(ValueError): self.run_writer()
    # The first example destination is usr/share/example (depth3).
    self.assertEqual((self.root / 'usr/share/example').read_bytes(), b'unexpected collision')
    self.assertFalse((self.journal / CID / 'MATERIALIZED.json').exists())

  def test_guard_refusal_does_not_start_an_attempt(self):
    def refused(): raise ValueError('synthetic exhausted reserve')
    with self.assertRaises(ValueError): self.run_writer(refused)
    self.assertFalse((self.journal / CID).exists())

  def test_wrong_external_profile_pin_cannot_be_adopted(self):
    self.pin = replace(self.pin, preimages_sha256='1' * 64)
    with self.assertRaises(ValueError): self.run_writer()
    self.assertFalse((self.journal / CID).exists())


if __name__ == '__main__':
  unittest.main()
