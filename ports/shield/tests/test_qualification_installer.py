"""Enabled artifact admission inspects headers without executing a binary."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent.parent / 'tools'
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location('qualification_installer', TOOLS / 'install-qualification-artifacts.py')
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class QualificationInstallerTests(unittest.TestCase):
  def setUp(self):
    self.directory = tempfile.TemporaryDirectory()
    self.addCleanup(self.directory.cleanup)
    self.path = Path(self.directory.name) / 'artifact'
    self.elf = bytearray(64 + 56)
    self.elf[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', self.elf, 16, 2, 183, 1)
    struct.pack_into('<Q', self.elf, 32, 64)
    struct.pack_into('<HHH', self.elf, 52, 64, 56, 1)
    struct.pack_into('<I', self.elf, 64, 1)

  def inspect(self, data):
    self.path.write_bytes(data)
    INSTALLER.static_arm(self.path)

  def test_expected_static_arm_header_is_inspected_only(self):
    self.inspect(self.elf)

  def test_x86_64_editor_cache_or_other_architecture_cannot_be_installed(self):
    struct.pack_into('<H', self.elf, 18, 62)
    with self.assertRaises(ValueError): self.inspect(self.elf)

  def test_interpreter_or_dynamic_headers_are_rejected(self):
    for kind in [2, 3]:
      with self.subTest(kind=kind):
        data = self.elf + bytearray(56)
        struct.pack_into('<H', data, 56, 2)
        struct.pack_into('<I', data, 120, kind)
        with self.assertRaises(ValueError): self.inspect(data)

  def test_truncated_or_out_of_bounds_header_table_is_rejected(self):
    for data in [self.elf[:63], self.elf[:100], bytearray(self.elf)]:
      if len(data) == 120: struct.pack_into('<Q', data, 32, 4096)
      with self.subTest(length=len(data)), self.assertRaises(ValueError): self.inspect(data)

  def test_wrong_class_endian_version_or_header_stride_is_rejected(self):
    for offset, value in [(4, 1), (5, 2), (6, 0), (52, 63), (54, 55), (56, 0)]:
      data = bytearray(self.elf); data[offset] = value
      with self.subTest(offset=offset), self.assertRaises(ValueError): self.inspect(data)


if __name__ == '__main__':
  unittest.main()
