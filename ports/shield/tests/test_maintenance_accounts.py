"""Root-owned disposable file tests; never mount or access a block device."""
import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import maintenance_accounts as guest


@unittest.skipUnless(os.geteuid() == 0, 'Disposable root-owned account fixtures require root')
class AccountWitnessTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix='shield-account-witness-')
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    (self.root / 'etc').mkdir(mode=0o755)
    self.expected = {}
    for name in guest.ACCOUNT_NAMES:
      path = self.root / name
      content = ('fixture-' + path.name + '\n').encode()
      path.write_bytes(content)
      path.chmod(0o600)
      self.expected[name] = {'sha256': hashlib.sha256(content).hexdigest(),
        'bytes': len(content), 'mode': 0o600, 'uid': 0, 'gid': 0}

  def test_actual_readback_and_xattr_change_are_visible(self):
    before = guest.account_preimages(self.root, self.expected)
    path = self.root / 'etc/passwd'
    os.setxattr(path, 'user.shield-fixture', b'changed')
    after = guest.account_preimages(self.root, self.expected)
    self.assertNotEqual(before, after)
    self.assertEqual(after['etc/passwd']['xattrs']['user.shield-fixture'], b'changed'.hex())

  def test_missing_or_unbounded_preimage_fails(self):
    bad = copy.deepcopy(self.expected)
    del bad['etc/shadow']
    with self.assertRaises(ValueError): guest.account_preimages(self.root, bad)
    bad = copy.deepcopy(self.expected)
    bad['etc/shadow']['bytes'] = 2 * 1024**2
    with self.assertRaises(ValueError): guest.account_preimages(self.root, bad)

  def test_symlink_and_hardlink_rejected(self):
    path = self.root / 'etc/shadow'
    path.rename(self.root / 'saved')
    path.symlink_to('../saved')
    with self.assertRaises(ValueError): guest.account_preimages(self.root, self.expected)
    path.unlink()
    os.link(self.root / 'saved', path)
    with self.assertRaises(ValueError): guest.account_preimages(self.root, self.expected)

  def test_changed_bytes_or_metadata_rejected(self):
    path = self.root / 'etc/passwd'
    content = path.read_bytes()
    path.write_bytes(content.replace(b'fixture', b'changed'))
    with self.assertRaises(ValueError): guest.account_preimages(self.root, self.expected)
    path.write_bytes(content)
    path.chmod(0o644)
    with self.assertRaises(ValueError): guest.account_preimages(self.root, self.expected)

  def test_link_ancestor_rejected(self):
    (self.root / 'etc').rename(self.root / 'elsewhere')
    (self.root / 'etc').symlink_to('elsewhere')
    with self.assertRaises(ValueError): guest.account_preimages(self.root, self.expected)


if __name__ == '__main__':
  unittest.main()
