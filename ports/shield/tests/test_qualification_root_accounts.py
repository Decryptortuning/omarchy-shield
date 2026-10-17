"""Original-image account admission and new host-copy seeding; no device IO."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
from maintenance_accounts import original_account_baseline, original_baseline_from_record
SPEC = importlib.util.spec_from_file_location('qualification_account_preparer', TOOLS / 'prepare-qualification-root.py')
PREPARER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARER)


def account_bytes():
  return {'etc/passwd': b'root:x:0:0::/root:/bin/bash\ndaemon:x:2:2::/:/usr/bin/nologin\n',
    'etc/group': b'root:x:0:\ndaemon:x:2:\nvideo:x:10:\nrender:x:11:\naudio:x:12:\ninput:x:13:\n',
    'etc/shadow': b'root:*:1:0:99999:7:::\ndaemon:*:1:0:99999:7:::\n',
    'etc/gshadow': b'root:!::\ndaemon:!::\nvideo:!::\nrender:!::\naudio:!::\ninput:!::\n'}


def desired_bytes(before):
  after = dict(before)
  after['etc/passwd'] += b'shieldqual:x:1001:1001::/home/shieldqual:/bin/bash\n'
  after['etc/group'] = after['etc/group'].replace(b':10:\n', b':10:shieldqual\n').replace(
    b':11:\n', b':11:shieldqual\n').replace(b':12:\n', b':12:shieldqual\n').replace(
    b':13:\n', b':13:shieldqual\n') + b'shieldqual:x:1001:\n'
  after['etc/shadow'] = after['etc/shadow'].replace(b'root:*:1:', b'root:!:2:') + b'shieldqual:!:2:0:99999:7:::\n'
  after['etc/gshadow'] = after['etc/gshadow'].replace(b'video:!::\n', b'video:!::shieldqual\n').replace(
    b'render:!::\n', b'render:!::shieldqual\n').replace(b'audio:!::\n', b'audio:!::shieldqual\n').replace(
    b'input:!::\n', b'input:!::shieldqual\n') + b'shieldqual:!::\n'
  return after


@unittest.skipUnless(os.geteuid() == 0, 'Root-owned account metadata fixtures')
class OriginalAccountRootTests(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory(prefix='shield-original-accounts-')
    self.addCleanup(self.temp.cleanup)
    self.directory = Path(self.temp.name)
    self.source = self.directory / 'original'
    self.target = self.directory / 'copy'
    for root in [self.source, self.target]: (root / 'etc').mkdir(parents=True, mode=0o755)
    self.before = account_bytes()
    self.write(self.source, self.before)
    self.expected = {}
    for name, raw in self.before.items():
      info = (self.source / name).stat()
      self.expected[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
        'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}
    self.image_sha = 'd' * 64
    self.receipt = self.directory / 'original-evidence.json'
    self.evidence = {'format_version': 1, 'scope': 'Original immutable host image account evidence only',
      'image_unchanged': True, 'root_id': 256, 'image_sha256': self.image_sha,
      'actual_physical_USB_preimages_verified': False, 'physical_write_authority': False,
      'boot_ready': False, 'account_preimages': self.expected}
    self.pin_receipt()

  def write(self, root, contents):
    for name, raw in contents.items():
      path = root / name
      path.write_bytes(raw)
      path.chmod(0o600 if name.endswith(('shadow', 'gshadow')) else 0o644)

  def pin_receipt(self):
    self.receipt.write_text(json.dumps(self.evidence) + '\n')
    self.receipt.chmod(0o600)
    self.receipt_sha = hashlib.sha256(self.receipt.read_bytes()).hexdigest()

  def admit(self):
    return original_account_baseline(self.source, self.receipt, self.receipt_sha, self.image_sha)

  def test_original_bytes_and_provenance_roundtrip_without_reference_mutation(self):
    provenance, contents = self.admit()
    self.assertEqual(contents, self.before)
    self.assertEqual(original_baseline_from_record(provenance), self.before)
    self.assertEqual({name: (self.source / name).read_bytes() for name in self.before}, self.before)

  def test_new_copy_replaces_builder_tables_with_exact_original_bytes_and_modes(self):
    builder = {'etc/passwd': b'portbuild:x:1000:1000::/home/portbuild:/bin/bash\n',
      'etc/group': b'portbuild:x:1000:\n', 'etc/shadow': b'portbuild:!:2:0:99999:7:::\n',
      'etc/gshadow': b'portbuild:!::\n'}
    self.write(self.target, {name: raw + builder[name] for name, raw in self.before.items()})
    provenance, contents = self.admit()
    PREPARER.seed_original_accounts(self.target, provenance, contents)
    for name, raw in self.before.items():
      self.assertEqual((self.target / name).read_bytes(), raw)
      self.assertEqual(stat.S_IMODE((self.target / name).stat().st_mode), self.expected[name]['mode'])
    self.assertEqual({name: (self.source / name).read_bytes() for name in self.before}, self.before)

  def test_wrong_receipt_or_original_image_pin_is_refused(self):
    for receipt_sha, image_sha in [('0' * 64, self.image_sha), (self.receipt_sha, 'e' * 64)]:
      with self.subTest(receipt=receipt_sha), self.assertRaises(ValueError):
        original_account_baseline(self.source, self.receipt, receipt_sha, image_sha)

  def test_wrong_root_or_any_physical_authority_claim_is_refused(self):
    for key, value in [('root_id', True), ('root_id', 257), ('image_unchanged', False),
                       ('physical_write_authority', True), ('actual_physical_USB_preimages_verified', True)]:
      with self.subTest(key=key):
        original = self.evidence[key]; self.evidence[key] = value; self.pin_receipt()
        with self.assertRaises(ValueError): self.admit()
        self.evidence[key] = original
    self.pin_receipt()

  def test_moved_source_bytes_or_alias_cannot_supply_original_accounts(self):
    path = self.source / 'etc/passwd'
    path.write_bytes(self.before['etc/passwd'] + b'changed')
    with self.assertRaises(ValueError): self.admit()
    path.unlink(); path.symlink_to(self.source / 'etc/group')
    with self.assertRaises(ValueError): self.admit()

  def test_producer_uses_same_strict_runtime_account_delta_as_materializer(self):
    self.write(self.target, desired_bytes(self.before))
    proof = PREPARER.account_proof(self.target, self.before)
    self.assertTrue(proof['build_account_absent'])
    self.assertTrue(proof['runtime_account_baseline_admitted'])
    with (self.target / 'etc/passwd').open('ab') as stream:
      stream.write(b'portbuild:x:1000:1000::/home/portbuild:/bin/bash\n')
    with self.assertRaises(ValueError): PREPARER.account_proof(self.target, self.before)


if __name__ == '__main__': unittest.main()
