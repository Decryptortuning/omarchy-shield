"""Exercise the Windows ADB text boundary before strict segment admission."""
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_phase_coordinator import Coordinator, legacy_shell_text
from native_legacy_memory import review_segments


class LegacyLoaderTransportTests(unittest.TestCase):
  def setUp(self):
    self.image = bytearray(4096)
    struct.pack_into('<QQ', self.image, 8, 0, 8192)
    self.image[56:60] = b'ARM\x64'
    self.image = bytes(self.image)
    self.report = 'kexec_load: entry = 0x80205000 flags = 0xb70000\nnr_segments = 4\n'
    for index, (size, address, extent) in enumerate([
        (4096, 0x80200000, 8192), (6000, 0x80202000, 8192),
        (1000, 0x80204000, 4096), (512, 0x80205000, 4096)]):
      for field, value in [('buf', 0x10000 + index * 0x10000),
                            ('bufsz', size), ('mem', address), ('memsz', extent)]:
        self.report += f'segment[{index}].{field} = 0x{value:x}\n'

  def through_shell(self, raw):
    owner = SimpleNamespace(adc=Mock(return_value=raw))
    text = Coordinator.shell(owner, 'cat /tmp/shield-native/loader.log', budget=1024**2)
    owner.adc.assert_called_once_with(['shell', 'cat /tmp/shield-native/loader.log'], budget=1024**2)
    return review_segments(text, 6000, self.image, reserved_ranges=[])

  def test_actual_shell_route_accepts_lf_and_crlf_equally(self):
    lf = self.through_shell(self.report.encode('ascii'))
    self.assertEqual(lf, self.through_shell(self.report.replace('\n', '\r\n').encode('ascii')))
    self.assertTrue(lf['placement_review_passed'])
    self.assertFalse(lf['device_execution_authorized_by_this_tool'])

  def test_bare_cr_and_non_ascii_are_rejected(self):
    for raw in [b'a\rb', b'a\r\r\nb', b'\xff']:
      with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeDecodeError)):
        legacy_shell_text(raw)

  def test_exec_out_remains_binary(self):
    raw = b'\x00\xff\r\n\r'
    owner = SimpleNamespace(deadline=2**63, expected_legacy_boot=None, serial='test')
    with patch('native_phase_coordinator.run_owned', return_value=(raw, b'')):
      self.assertIs(Coordinator.adc(owner, ['exec-out', 'cat', '/sys/firmware/fdt']), raw)

  def test_normalization_preserves_strict_loader_rejections(self):
    malformed = [
      self.report.replace('nr_segments = 4', 'nr_segments = 5'),
      self.report + 'segment[0].mem = 0x80200000\n',
      self.report.replace('flags = 0xb70000', 'flags = 0xb70001'),
      self.report.replace('segment[2].mem = 0x80204000', 'segment[2].mem = 0x80203000'),
      self.report.replace('segment[2].mem = 0x80204000', 'segment[2].mem = 0x92cc3000'),
    ]
    for text in malformed:
      with self.subTest(report=text), self.assertRaises(ValueError):
        self.through_shell(text.replace('\n', '\r\n').encode('ascii'))
    with self.assertRaises(ValueError):
      review_segments(legacy_shell_text(self.report.encode('ascii')), 6000, self.image,
                      reserved_ranges=[(0x80204000, 0x80205000)])


if __name__ == '__main__':
  unittest.main()
