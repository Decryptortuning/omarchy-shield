"""Exercise firmware corruption/containment and diagnostic format boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PORT))
from tools.board_firmware import verify_stage, installed_identity
from tools.fan_profile import inspect_fan_contract


def module(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


STAGER = module('board_stager', PORT / 'stage-board-firmware.py')
BOOT = module('diagnostic_boot', PORT / 'prepare-diagnostic-boot.py')


class FirmwareTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    self.inputs = self.root / 'harvest'
    self.inputs.mkdir()
    self.data = b'pinned-test-firmware'
    (self.inputs / 'radio.bin').write_bytes(self.data)
    self.entry = {'id': 'radio', 'input_path': 'radio.bin', 'bytes': len(self.data),
                  'sha256': hashlib.sha256(self.data).hexdigest(), 'activation_allowed': False,
                  'usage': 'driver-candidate', 'runtime_request': 'brcm/BCM4354.hcd'}
    self.lock = {'board_variant': 'darcy-t210-a04', 'installed_into_runtime': False, 'entries': [self.entry]}
    self.lock_path = self.root / 'lock.json'
    self.output = self.root / 'staged'
    self.save()

  def save(self):
    self.lock_path.write_text(json.dumps(self.lock))

  def stage(self):
    return STAGER.stage(self.lock_path, self.inputs, self.output)

  def test_staged_availability_is_not_installation(self):
    report = self.stage()
    self.assertFalse(report['installed_into_runtime'])
    self.assertFalse(report['hardware_qualified'])
    verify_stage(self.output, self.lock_path, 'darcy-t210-a04')
    self.assertEqual(installed_identity(self.inputs, self.entry)['status'], 'missing')

  def test_corrupt_input_never_publishes_a_partial_stage(self):
    (self.inputs / 'radio.bin').write_bytes(b'wrong')
    with self.assertRaisesRegex(ValueError, 'differ'):
      self.stage()
    self.assertFalse(self.output.exists())
    self.assertFalse(list(self.root.glob('.shield-firmware-*')))

  def test_tampered_staged_bytes_are_refused(self):
    self.stage()
    (self.output / 'inputs/radio.bin').write_bytes(b'changed')
    with self.assertRaisesRegex(ValueError, 'differ'):
      verify_stage(self.output, self.lock_path, 'darcy-t210-a04')

  def test_wrong_silicon_stage_is_refused(self):
    self.stage()
    with self.assertRaisesRegex(ValueError, 'variants disagree'):
      verify_stage(self.output, self.lock_path, 'mdarcy-t210b01')

  def test_input_path_escape_is_refused(self):
    self.entry['input_path'] = '../outside'
    self.save()
    with self.assertRaisesRegex(ValueError, 'contained'):
      self.stage()

  def test_runtime_search_directory_is_refused(self):
    self.output = self.root / 'rootfs/usr/lib/firmware/new-board'
    with self.assertRaisesRegex(ValueError, 'runtime'):
      self.stage()

  def test_local_only_missing_input_never_fetches_stock_ota(self):
    (self.inputs / 'radio.bin').unlink()
    with self.assertRaisesRegex(ValueError, 'pinned local input'):
      self.stage()

  def test_existing_destination_is_preserved(self):
    self.output.mkdir()
    marker = self.output / 'owner-file'
    marker.write_text('preserve')
    with self.assertRaisesRegex(ValueError, 'new directory'):
      self.stage()
    self.assertEqual(marker.read_text(), 'preserve')

  def test_exact_installed_identity_and_other_chip_rejection(self):
    firmware = self.root / 'runtime'
    (firmware / 'brcm').mkdir(parents=True)
    (firmware / 'brcm/BCM4356.hcd').write_bytes(self.data)
    self.assertEqual(installed_identity(firmware, self.entry)['status'], 'missing')
    (firmware / 'brcm/BCM4354.hcd').write_bytes(b'other')
    self.assertEqual(installed_identity(firmware, self.entry)['status'], 'different')
    (firmware / 'brcm/BCM4354.hcd').write_bytes(self.data)
    self.assertEqual(installed_identity(firmware, self.entry)['status'], 'byte-identical')

  def test_compressed_installed_firmware(self):
    firmware = self.root / 'runtime'
    (firmware / 'brcm').mkdir(parents=True)
    import lzma
    (firmware / 'brcm/BCM4354.hcd.xz').write_bytes(lzma.compress(self.data))
    self.assertEqual(installed_identity(firmware, self.entry)['status'], 'byte-identical')


class BootContractTests(unittest.TestCase):
  def test_stock_header_format_and_bounds(self):
    profile = {'android_header': {'page_bytes': 2048, 'version': 1}}
    data = bytearray(4096)
    data[:8] = b'ANDROID!'
    struct.pack_into('<I', data, 8, 32)
    struct.pack_into('<I', data, 36, 2048)
    struct.pack_into('<I', data, 40, 1)
    data[2048:2050] = b'\x1f\x8b'
    BOOT.inspect_stock(data, profile)
    for offset, value in ((36, 4096), (40, 0), (40, 2), (8, 8192)):
      wrong = data.copy()
      struct.pack_into('<I', wrong, offset, value)
      with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
        BOOT.inspect_stock(wrong, profile)
    with self.assertRaises(ValueError):
      BOOT.inspect_stock(data[:40], profile)

  def test_changing_pwm_cell_width_cannot_invert_gpu_regulator(self):
    for gpu_flags, expected in ((0, True), (1, False)):
      with self.subTest(gpu_flags=gpu_flags), tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / 'test.dts'
        source.write_text('/dts-v1/; / { pwm@7000a000 { phandle=<1>; #pwm-cells=<3>; }; '
                          'pwm-fan { pwms=<1 3 65536 1>; cooling-levels=<0 127 191 255>; }; '
                          'regulator-vdd-gpu { pwms=<1 1 8000 ' + str(gpu_flags) + '>; }; };')
        subprocess.run(['dtc', '-I', 'dts', '-O', 'dtb', '-o', str(root / 'test.dtb'), str(source)],
                       capture_output=True, check=True)
        self.assertEqual(inspect_fan_contract(root / 'test.dtb')['binding_contract_matches'], expected)


if __name__ == '__main__':
  unittest.main()
