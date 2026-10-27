"""Durable startup record transaction tests, confined to temporary directories."""
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from owner_internal_ack import acknowledge, read_record, record, MAGIC


@unittest.skipUnless(os.geteuid() == 0, 'Record ownership requires root')
class InternalAck(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.path = Path(self.temp.name)
    self.path.chmod(0o700)
    self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
    self.generation = 'ab' * 32

  def tearDown(self):
    os.close(self.fd)
    self.temp.cleanup()

  def put(self, name, raw):
    target = self.path / name
    target.write_bytes(raw)
    target.chmod(0o600)

  def test_record_known_vector(self):
    raw = record(self.generation, 0x0102030405060708)
    self.assertEqual(len(raw), 48)
    self.assertEqual(raw, MAGIC + bytes.fromhex(self.generation) + bytes.fromhex('0807060504030201'))

  def test_matching_pending_ack_is_durable_and_not_replayed(self):
    raw = record(self.generation, 1)
    self.put('pending', raw)
    result = acknowledge(self.fd, self.generation, 1)
    self.assertTrue(result['durable_startup_ack_written'])
    self.assertFalse(result['runtime_expiry_created'])
    self.assertEqual(read_record(self.fd, 'healthy'), raw)
    self.assertEqual(read_record(self.fd, 'pending'), raw)
    with self.assertRaises(ValueError):
      acknowledge(self.fd, self.generation, 1)
    self.assertFalse((self.path / 'healthy.next').exists())

  def test_missing_or_wrong_pending_never_writes(self):
    for pending in [None, record('cd' * 32, 1), record(self.generation, 2)]:
      if pending is not None:
        self.put('pending', pending)
      with self.assertRaises(ValueError):
        acknowledge(self.fd, self.generation, 1)
      self.assertFalse((self.path / 'healthy').exists())
      self.assertFalse((self.path / 'healthy.next').exists())

  def test_prior_sequence_is_retained_across_generation_update(self):
    self.put('healthy', record('cd' * 32, 8))
    self.put('pending', record(self.generation, 9))
    acknowledge(self.fd, self.generation, 9)
    self.assertEqual(read_record(self.fd, 'healthy'), record(self.generation, 9))

  def test_nonmonotonic_or_interrupted_ack_refuses(self):
    self.put('healthy', record(self.generation, 4))
    self.put('pending', record(self.generation, 6))
    with self.assertRaises(ValueError):
      acknowledge(self.fd, self.generation, 6)
    self.assertEqual(read_record(self.fd, 'healthy'), record(self.generation, 4))
    self.put('pending', record(self.generation, 5))
    self.put('healthy.next', b'interrupted')
    with self.assertRaises(FileExistsError):
      acknowledge(self.fd, self.generation, 5)
    self.assertEqual(read_record(self.fd, 'healthy'), record(self.generation, 4))
    self.assertEqual((self.path / 'healthy.next').read_bytes(), b'interrupted')

  def test_malformed_record_and_symlink_refuse(self):
    for raw in [b'', record(self.generation, 1)[:-1], record(self.generation, 1) + b'x',
                b'BADMAGIC' + bytes.fromhex(self.generation) + struct.pack('<Q', 1),
                MAGIC + bytes.fromhex(self.generation) + bytes(8)]:
      self.put('pending', raw)
      with self.assertRaises(ValueError):
        read_record(self.fd, 'pending')
    (self.path / 'pending').unlink()
    (self.path / 'pending').symlink_to('/etc/passwd')
    with self.assertRaises(OSError):
      read_record(self.fd, 'pending')


if __name__ == '__main__':
  unittest.main()
