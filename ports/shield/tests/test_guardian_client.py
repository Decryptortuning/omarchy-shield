"""Pure guardian protocol/admission rejection cases; no sockets or devices."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools'))
import guardian_client as G

CANDIDATE = 'a' * 64
BOOT = '11111111-1111-4111-8111-111111111111'


class GuardianClientTests(unittest.TestCase):
  def status(self):
    packet = G.RESPONSE.pack(G.MAGIC, G.VERSION, 248, 1, G.WORK, 0, 7, 0,
      CANDIDATE.encode(), BOOT.encode(), 0, 30*G.SECOND, 5*G.SECOND,
      30*G.SECOND, 30*G.SECOND, 540*G.SECOND, 600*G.SECOND, 1, 2,
      40000, 30000, 41000, 0, 255, 2, 5000, 0x8017, 0xc3938700, 1, 17, 0)
    return G.decode_packet(packet, CANDIDATE, BOOT, 1)

  def test_live_finite_work_reserve_is_comparison_only(self):
    status = self.status()
    self.assertIs(G.require_work_status(status, 120, 30*G.SECOND), status)
    self.assertEqual(status['work_cutoff_ns'], 540*G.SECOND)

  def test_boundary_reserve_may_not_reach_or_extend_cutoff(self):
    with self.assertRaisesRegex(ValueError, 'Insufficient finite'):
      G.require_work_status(self.status(), 510, 30*G.SECOND)

  def test_fault_quiescing_or_missing_descriptor_never_admits_work(self):
    for key, value in [('phase', G.FAULT_HOLD), ('phase', G.QUIESCING), ('fault', 1), ('flags', 6)]:
      status = self.status(); status[key] = value
      with self.assertRaisesRegex(ValueError, 'not admitted'):
        G.require_work_status(status, 1, 30*G.SECOND)

  def test_stale_future_sample_and_late_status_refused(self):
    for key, value in [('sample_ns', 26*G.SECOND), ('sample_ns', 31*G.SECOND), ('now_ns', 28*G.SECOND)]:
      status = self.status(); status[key] = value
      with self.assertRaises(ValueError):
        G.require_work_status(status, 1, 30*G.SECOND)

  def test_temperature_fault_fan_tach_or_timer_drift_refused(self):
    for key, value in [('cpu', 70000), ('remote_fault', 1), ('pwm', 191),
                       ('enable', 1), ('rpm', 0), ('cfg', 0), ('ptv', 0), ('sts', 0)]:
      status = self.status(); status[key] = value
      with self.assertRaises(ValueError):
        G.require_work_status(status, 1, 30*G.SECOND)

  def test_unqualified_timeouts_or_ownership_history_refused(self):
    for key, value in [('work_cutoff_ns', 600*G.SECOND), ('cleanup_cutoff_ns', 900*G.SECOND),
                       ('opened_ns', 120*G.SECOND), ('ping_count', 0), ('last_ping_ns', 0)]:
      status = self.status(); status[key] = value
      with self.assertRaises(ValueError):
        G.require_work_status(status, 1, 30*G.SECOND)
    status = self.status()
    status.update(now_ns=100*G.SECOND, sample_ns=100*G.SECOND, last_ping_ns=10*G.SECOND)
    with self.assertRaisesRegex(ValueError, 'ownership history'):
      G.require_work_status(status, 1, 100*G.SECOND)

  def test_wire_identity_reserved_fields_and_length_refused(self):
    status = self.status()
    values = [status[key] for key in ['magic','version','bytes','role','phase','fault','flags','request_result']]
    suffix = [CANDIDATE.encode(), BOOT.encode(), 0, 30*G.SECOND, 5*G.SECOND, 30*G.SECOND,
      30*G.SECOND, 540*G.SECOND, 600*G.SECOND, 1, 2, 40000, 30000, 41000, 0, 255, 2,
      5000, 0x8017, 0xc3938700, 1, 17, 0]
    packet = G.RESPONSE.pack(*values, *suffix)
    for bad in [packet[:-1], packet + b'x']:
      with self.assertRaises(ValueError):G.decode_packet(bad, CANDIDATE, BOOT, 1)
    for offset, value in [(0, 0), (4, 2), (12, 2), (24, 8), (132, 1), (244, 1)]:
      bad = bytearray(packet);struct.pack_into('<I', bad, offset, value)
      with self.assertRaises(ValueError):G.decode_packet(bad, CANDIDATE, BOOT, 1)
    with self.assertRaises(ValueError):G.decode_packet(packet, 'b'*64, BOOT, 1)
    with self.assertRaises(ValueError):G.decode_packet(packet, CANDIDATE, '22222222-2222-4222-8222-222222222222', 1)


if __name__ == '__main__':
  unittest.main()
