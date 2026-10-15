"""Test stock image cloning, archive bounds and original-T210 identity guards."""
import hashlib
from pathlib import Path
import stat
import struct
import subprocess
import sys
import unittest

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
from tools.stock_boot import aligned, read_newc, write_newc, stock_parts, replace_ramdisk


class StockFormatTests(unittest.TestCase):
  def image(self):
    header = bytearray(2048)
    header[:8] = b'ANDROID!'
    struct.pack_into('<10I', header, 8, 5, 0x00991680, 3, 0x01989680, 0, 0,
                     0x00989780, 2048, 1, 0xdeadbeef)
    header[64:68] = b'test'
    struct.pack_into('<I', header, 1644, 1648)
    return bytes(header) + b'\x1f\x8babc'.ljust(2048, b'\0') + b'old'.ljust(2048, b'\0')

  def test_stock_kernel_addresses_and_other_header_fields_are_preserved(self):
    original = self.image()
    ramdisk = b'new compressed ramdisk'
    image = replace_ramdisk(original, ramdisk)
    header, kernel, result = stock_parts(image)
    self.assertEqual(kernel, stock_parts(original)[1])
    self.assertEqual(result, ramdisk)
    self.assertEqual(len(image) % 2048, 0)
    allowed = set(range(16, 20)) | set(range(64, 1632))
    self.assertTrue(all(a == b for i, (a, b) in enumerate(zip(original[:2048], header)) if i not in allowed))
    self.assertIn(b'shield.stock-inventory=1', header[64:576])
    digest = hashlib.sha1(kernel + struct.pack('<I', len(kernel)) + ramdisk + struct.pack('<I', len(ramdisk)) + b'\0' * 8).digest()
    self.assertEqual(header[576:608], digest.ljust(32, b'\0'))

  def test_unmeasured_header_or_payload_bounds_are_rejected(self):
    for offset, value in ((40, 2), (36, 4096), (8, 99999999), (24, 1), (1632, 1)):
      image = bytearray(self.image())
      struct.pack_into('<I', image, offset, value)
      with self.subTest(offset=offset), self.assertRaises(ValueError):
        stock_parts(image)

  def test_newc_preserves_binary_symlink_directory_and_device(self):
    entries = {'bin': {'mode': stat.S_IFDIR | 0o755, 'data': b''},
               'bin/sh': {'mode': stat.S_IFLNK | 0o777, 'data': b'busybox'},
               'bin/busybox': {'mode': stat.S_IFREG | 0o755, 'data': b'\0\xffbinary'},
               'dev/console': {'mode': stat.S_IFCHR | 0o600, 'data': b'', 'rdevmajor': 5, 'rdevminor': 1}}
    decoded = read_newc(write_newc(entries))
    for name, entry in entries.items():
      for key, value in entry.items():self.assertEqual(decoded[name][key], value)

  def test_newc_truncation_and_escaping_paths_are_refused(self):
    with self.assertRaises(ValueError):
      write_newc({'../outside': {'mode': stat.S_IFREG, 'data': b'x'}})
    data = write_newc({'a': {'mode': stat.S_IFREG, 'data': b'x'}})
    for length in (4, 110, 113):
      with self.subTest(length=length), self.assertRaises(ValueError):read_newc(data[:length])

  def test_newc_duplicate_names_are_refused(self):
    data = write_newc({'a': {'mode': stat.S_IFREG, 'data': b'x'}})
    first_size = aligned(aligned(110 + 2) + 1)
    with self.assertRaisesRegex(ValueError, 'duplicate'):
      read_newc(data[:first_size] + data)


class StockIdentityTests(unittest.TestCase):
  def test_init_refuses_an_ordinary_host_process_before_any_mount(self):
    result = subprocess.run(['sh', str(PORT/'stock-bootstrap/init.sh')], capture_output=True, text=True)
    self.assertEqual(result.returncode, 1)
    self.assertIn('requires ramdisk PID 1', result.stderr)

  def test_original_darcy_only(self):
    cases = [(['nvidia,darcy','nvidia,foster-e','nvidia,tegra210'], '33', '1', True),
             (['nvidia,darcy','nvidia,tegra210','nvidia,tegra210b01'], '33', '2', False),
             (['nvidia,darcy','nvidia,tegra210','nvidia,tegra210b01'], '33', '1', False),
             (['nvidia,darcy','nvidia,tegra210'], '33', '', False),
             (['nvidia,p3450-0000','nvidia,tegra210'], '33', '1', False),
             (['nvidia,darcy','nvidia,tegra210','qcom,board'], '33', '1', False)]
    for tokens, chip, major, expected in cases:
      with self.subTest(tokens=tokens,major=major):
        result = subprocess.run(['sh','-c','. "$1"; stock_inventory_supported "$2" "$3" "$4"',
                                 'sh',str(PORT/'stock-bootstrap/identity.sh'),'\n'.join(tokens),chip,major],capture_output=True)
        self.assertEqual(result.returncode == 0, expected)


if __name__ == '__main__':
  unittest.main()
