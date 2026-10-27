"""Pure producer/actual initial-RAM admission contracts; no device actions."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from owner_command_line import normal, internal_normal, admit_normal


class InternalCommandLine(unittest.TestCase):
  def setUp(self):
    self.boot = b'{"purpose":"boot"}\n'
    self.context = b'{"purpose":"context"}\n'
    self.generation = 'ab' * 32
    self.enrollment = {'filesystem': {'emmc': {}}, 'boot_store': {'generation_id': self.generation}}
    self.line = internal_normal(self.boot, self.context, self.generation, '0000000000000001').decode().split()

  def test_current_internal_attempt_and_maximum_sequence(self):
    for seq in ['0000000000000001', 'ffffffffffffffff']:
      line = internal_normal(self.boot, self.context, self.generation, seq).decode().split()
      admit_normal(line, self.boot, self.context, self.enrollment)
      self.assertEqual(line[:-2], normal(self.boot, self.context).decode().split())

  def test_generation_sequence_and_boot_bindings(self):
    for tokens, boot, context in [
        (self.line[:-1], self.boot, self.context),
        (self.line + [self.line[-1]], self.boot, self.context),
        (self.line[:-2] + self.line[-2:][::-1], self.boot, self.context),
        (self.line[:-2] + ['shield.owner-internal-generation=' + 'cd' * 32, self.line[-1]], self.boot, self.context),
        (self.line, self.boot + b' ', self.context),
        (self.line, self.boot, self.context + b' '),
        (self.line + ['init=/bin/sh'], self.boot, self.context)]:
      with self.subTest(tokens=tokens[-2:]), self.assertRaises(ValueError):
        admit_normal(tokens, boot, context, self.enrollment)

  def test_malformed_sequences_and_generations(self):
    for seq in ['0000000000000000', '1', 'FFFFFFFFFFFFFFFF', '-000000000000001', '10000000000000000', 1, True]:
      with self.subTest(sequence=seq), self.assertRaises(ValueError):
        internal_normal(self.boot, self.context, self.generation, seq)
    for generation in ['', 'AB' * 32, 'a' * 63, 1, True]:
      with self.subTest(generation=generation), self.assertRaises(ValueError):
        internal_normal(self.boot, self.context, generation, '0000000000000001')

  def test_usb_purpose_does_not_accept_internal_attempt(self):
    usb = {'filesystem': {'usb': {}}}
    admit_normal(normal(self.boot, self.context).decode().split(), self.boot, self.context, usb)
    with self.assertRaises(ValueError):
      admit_normal(self.line, self.boot, self.context, usb)


if __name__ == '__main__':
  unittest.main()
