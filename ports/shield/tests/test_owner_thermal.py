"""Pure cooling-policy fixtures; no live sensors, notifications or fan writes.
"""
import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location('owner_thermal_target', TOOLS / 'owner-thermal.py')
thermal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(thermal)


class OwnerThermalPureTests(unittest.TestCase):
  def sample(self):
    return dict(cpu=40000, gpu=45000, local=35000, remote=43000,
                remote_fault=0, pwm=255, enable=2, rpm=2000, tmp_update_interval_ms=500)

  def check(self, values=None, at=6_000_000_000, duration=100_000_000):
    return thermal.health(self.sample() if values is None else values, at, at + duration, 1_000_000_000)

  def test_integer_strict_decimal(self):
    self.assertEqual(thermal.integer(b'-40000\n'), -40000)
    for raw in [b'', b' 1\n', b'1\n\n', b'1.0', b'+1', b'2147483648\n']:
      with self.assertRaises(ValueError): thermal.integer(raw)

  def test_unique_selection_ignores_indices(self):
    rows = [{'name': b'gpu-thermal\n', 'path': 'zone9'}, {'name': b'cpu-thermal\n', 'path': 'zone17'}]
    self.assertEqual(thermal.select(rows, 'cpu-thermal'), 'zone17')

  def test_missing_duplicate_and_inventory_bound_refused(self):
    row = {'name': b'cpu-thermal\n', 'path': 'zone1'}
    for rows in [[], [row, row], [row] * 513]:
      with self.assertRaises(ValueError): thermal.select(rows, 'cpu-thermal')

  def test_full_sample_healthy(self):
    self.assertEqual(self.check(), 'healthy')

  def test_gpu_temperature_is_required_and_capped(self):
    for value in [70000, -40001]:
      s = self.sample(); s['gpu'] = value
      with self.assertRaises(ValueError): self.check(s)
    s = self.sample(); del s['gpu']
    with self.assertRaises(KeyError): self.check(s)

  def test_other_temperature_caps(self):
    for name in ['cpu', 'local', 'remote']:
      s = self.sample(); s[name] = 70000
      with self.assertRaises(ValueError): self.check(s)

  def test_fault_pwm_enable_and_invalid_rpm(self):
    for name, value in [('remote_fault', 1), ('pwm', 254), ('enable', 1), ('rpm', -1), ('rpm', 1000000)]:
      s = self.sample(); s[name] = value
      with self.assertRaises(ValueError): self.check(s)

  def test_tach_grace_strictly_less_than_four_seconds(self):
    s = self.sample(); s['rpm'] = 0
    self.assertEqual(self.check(s, at=2_000_000_000), 'warming')
    with self.assertRaises(ValueError): self.check(s, at=5_000_000_000, duration=0)

  def test_late_and_reversed_cycles_refused(self):
    with self.assertRaises(ValueError): self.check(duration=1_000_000_001)
    with self.assertRaises(ValueError): self.check(duration=-1)

  def test_unbounded_cached_sensor_interval_refused(self):
    for value in [0, 3001]:
      s = self.sample(); s['tmp_update_interval_ms'] = value
      with self.assertRaises(ValueError): self.check(s)

  def test_boolean_values_not_sensor_integers(self):
    s = self.sample(); s['remote_fault'] = False
    with self.assertRaises(ValueError): self.check(s)

  def test_unapproved_write_refused_before_open(self):
    for name, raw in [('pwm1', b'0\n'), ('pwm1_enable', b'0\n'), ('anything', b'255\n')]:
      with self.assertRaises(ValueError): thermal.write_fan(-1, name, raw)

  def test_scheduler_lateness_preserves_sampling_and_freshness_bounds(self):
    start, end = 1_000_000_000, 1_100_000_000
    self.assertEqual(thermal.cycle_delay(start, end, 1_500_000_000), 0.5)
    self.assertEqual(thermal.cycle_delay(start, end, 2_200_000_000), 0)
    self.assertEqual(thermal.cycle_delay(start, end, 4_100_000_000), 0)
    for a, b, now in [(start, end, 4_100_000_001),
                      (start, start + 1_000_000_001, start + 1_000_000_001),
                      (start, end, end - 1)]:
      with self.assertRaises(ValueError): thermal.cycle_delay(a, b, now)
