"""Reject cross-generation board identities at the collection and USB boundaries."""
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

PORT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('shield_collector', PORT / 'collect-shield-linux.py')
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)
PROFILE_SPEC = importlib.util.spec_from_file_location('kernel_profile', PORT / 'tools/kernel_profile.py')
PROFILE = importlib.util.module_from_spec(PROFILE_SPEC)
PROFILE_SPEC.loader.exec_module(PROFILE)


class BoardIdentityTests(unittest.TestCase):
  def check_identity(self, tokens, expected):
    self.assertEqual(COLLECTOR.board_variant(tokens), expected)
    result = subprocess.run(['sh', '-c', '. "$1"; shield_usb_supported_board "$2"',
                 'sh', str(PORT / 'diagnostic/usb-gadget.sh'), '\n'.join(tokens)], capture_output=True)
    self.assertEqual(result.returncode == 0, expected is not None)

  def test_original_darcy(self):
    self.check_identity(['nvidia,p2894-0050-a08', 'nvidia,darcy', 'nvidia,tegra210'], 'darcy-t210')

  def test_mdarcy_b01(self):
    self.check_identity(['nvidia,p2894-2551-b00', 'nvidia,tegra210b01', 'nvidia,tegra210'], 'mdarcy-t210b01')

  def test_original_board_cannot_claim_b01(self):
    self.check_identity(['nvidia,p2894-0050-a08', 'nvidia,tegra210', 'nvidia,tegra210b01'], None)

  def test_b01_board_requires_b01(self):
    self.check_identity(['nvidia,p2894-2551-b00', 'nvidia,tegra210'], None)

  def test_two_board_revisions_conflict(self):
    self.check_identity(['nvidia,p2894-0050-a08', 'nvidia,p2894-2551-b00', 'nvidia,tegra210b01', 'nvidia,tegra210'], None)

  def test_generic_tegra_is_not_a_shield(self):
    self.check_identity(['nvidia,p3450-0000', 'nvidia,tegra210'], None)

  def test_incomplete_identity(self):
    self.check_identity(['nvidia,p2894-0050-a08'], None)

  def test_foreign_family_conflicts(self):
    self.check_identity(['nvidia,p2894-0050-a08', 'nvidia,tegra210', 'apple,t6021'], None)


class CompiledBundleTests(unittest.TestCase):
  def fixture(self, directory, variant, compatible):
    filename, _, _ = PROFILE.PROFILES[variant]
    source = directory / 'fixture.dts'
    source.write_text('/dts-v1/; / { compatible = ' + ', '.join(json.dumps(token) for token in compatible) + '; };\n')
    subprocess.run(['dtc', '-I', 'dts', '-O', 'dtb', '-o', str(directory / filename), str(source)], check=True, capture_output=True)
    matrix = b'{"subsystems": []}\n'
    (directory / 'hardware.json').write_bytes(matrix)
    lock = {'board_variant': variant, 'kernel': {'device_tree': 'nvidia/' + filename},
        'hardware_matrix': {'sha256': hashlib.sha256(matrix).hexdigest()}}
    (directory / 'sources.lock.json').write_text(json.dumps(lock))

  def test_each_real_compiled_identity_matches_its_lock(self):
    for variant, (_, board, soc) in PROFILE.PROFILES.items():
      with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        self.fixture(directory, variant, [board, soc])
        self.assertEqual(PROFILE.verify_kernel_profile(directory)[0]['board_variant'], variant)

  def test_renaming_b01_dtb_does_not_make_a_darcy_bundle(self):
    with tempfile.TemporaryDirectory() as temporary:
      directory = Path(temporary)
      self.fixture(directory, 'darcy-t210', ['nvidia,p2894-2551-b00', 'nvidia,tegra210b01'])
      with self.assertRaisesRegex(ValueError, 'compiled DTB'):
        PROFILE.verify_kernel_profile(directory)

  def test_a_matrix_from_another_bundle_is_refused(self):
    with tempfile.TemporaryDirectory() as temporary:
      directory = Path(temporary)
      self.fixture(directory, 'darcy-t210', ['nvidia,p2894-0050-a08', 'nvidia,tegra210'])
      (directory / 'hardware.json').write_text('{"wrong_board": true}\n')
      with self.assertRaisesRegex(ValueError, 'acceptance matrix'):
        PROFILE.verify_kernel_profile(directory)


if __name__ == '__main__':
  unittest.main()
