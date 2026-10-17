"""Host/native transcript fixtures. Source only until the combined208 gate.

Synthetic keys/UUIDs only. These tests use temporary private receipt files and
local pipes; they never open a serial device, invoke a process or dispatch work.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_control_protocol as protocol
import native_host_link as host_module

SECOND = host_module.SECOND
KEY = b'\x03' * 32
BOOT = '11111111-2222-4333-8444-555555555555'
OTHER_BOOT = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'


class Clock:
  def __init__(self): self.value = 100 * SECOND
  def __call__(self): return self.value


class NativeHostLinkTests(unittest.TestCase):
  def setUp(self):
    self.clock = Clock()
    self.temporary = tempfile.TemporaryDirectory()
    self.directory = Path(self.temporary.name)
    os.chmod(self.directory, 0o700)
    self.store = host_module.PrivateFrameStore(self.directory, purpose='root-cleanup')
    self.read_fd, self.write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    self.bridge = host_module.BridgeState()
    self.bridge.feed_stderr(b'SHIELD_NATIVE_BRIDGE_ARMED 42\n')
    self.bridge.feed_stderr(b'SHIELD_NATIVE_BRIDGE_CONNECTED\n')
    self.context = protocol.Context('a' * 64, 'systemd', 'b' * 64, 'd' * 64)
    self.host = self.make_host()
    self.native = protocol.Session(self.context, KEY, side='native', boot_id=BOOT)

  def tearDown(self):
    os.close(self.read_fd); os.close(self.write_fd)
    self.store.close()
    self.temporary.cleanup()

  def make_host(self, *, epoch='root', context=None, boot_id=BOOT, handoff_pin=None, maintenance_pin=None):
    challenges = iter(['e' * 64, 'c' * 64])
    context = context or self.context
    store = self.store if epoch == 'root' or context.phase == 'systemd' or maintenance_pin is not None else None
    return host_module.HostLink(context, KEY, self.bridge,
      self.clock.value + 100 * SECOND, epoch=epoch, store=store,
      boot_id=boot_id, handoff_pin=handoff_pin, maintenance_pin=maintenance_pin, clock=self.clock,
      challenge_source=lambda: next(challenges))

  def hint(self, host=None):
    host = host or self.host
    return b'SNCR1 ' + host.session.context.session_id.encode() + b'\n'

  def written(self):
    while self.host.wants_write: self.host.drive_write(self.write_fd)
    chunks = []
    while True:
      try: chunks.append(os.read(self.read_fd, 8192))
      except BlockingIOError: break
    return b''.join(chunks).splitlines(keepends=True)

  def ready(self):
    self.host.feed_device(self.hint())
    probe, = self.written()
    self.native.receive(probe)
    self.host.feed_device(self.native.send('HELLO', {
      'kernel_release': protocol.KERNEL_RELEASE, 'boottime_ns': SECOND,
      'probe_challenge': self.native.probe_challenge}))
    ack, ping = self.written()
    self.native.receive(ack)
    ping_record = self.native.receive(ping)
    self.host.feed_device(self.native.send('PONG', {
      'challenge': ping_record.payload['challenge'], 'boottime_ns': 2 * SECOND}))
    self.assertTrue(self.host.ready)
    self.host.take_events()

  def observation(self, *, reason=None):
    receipt = {'phase': 'filesystem-readonly', 'boot_ready': False,
      'candidate': self.context.candidate,
      'reason': {'operation': 5, 'fault': 0} if reason is None else reason,
      'cleanup_deadline_ns': 20 * SECOND, 'readonly_state_verified': True,
      'root_unmounted': False, 'hardware_powerloss_qualified': False}
    raw = (json.dumps(receipt, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')
    return {'kind': 'cleanup-readonly', 'candidate': self.context.candidate,
      'boot_id': BOOT, 'cleanup_deadline_ns': 20 * SECOND,
      'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'nonce': 'f' * 64,
      'readonly_state_verified': True, 'root_unmounted': False,
      'hardware_powerloss_qualified': False, 'receipt': receipt}

  def evidence(self, observation=None):
    return self.native.send('EVIDENCE', {'observations':
      self.observation() if observation is None else observation})

  def test_unsigned_hint_triggers_exactly_one_probe_without_adopting_boot(self):
    self.maintenance_phase(ready=False)
    host = self.host
    hint = self.hint(host)
    host.feed_device(hint[:15]); host.feed_device(hint[15:] + hint)
    self.assertEqual(host.session.sent_sequence, 1)
    self.assertIsNone(host.session.boot_id)
    self.assertFalse(host.ready)
    self.assertEqual(len(host.pending), 1)

  def test_device_forged_bridge_marker_cannot_become_local_metadata(self):
    with self.assertRaises(ValueError):
      self.host.feed_device(b'SHIELD_NATIVE_BRIDGE_STOPPED\n')
    self.assertFalse(self.bridge.stopped)
    self.assertTrue(self.host.failed)
    self.assertEqual(self.host.session.sent_sequence, 0)

  def test_metadata_is_bounded_and_eof_requires_terminal_marker(self):
    bridge = host_module.BridgeState()
    bridge.feed_stderr(b'SHIELD_NATIVE_BRIDGE_ARMED ')
    bridge.feed_stderr(b'42\nSHIELD_NATIVE_BRIDGE_STOPPED\n')
    bridge.eof()
    other = host_module.BridgeState()
    with self.assertRaises(ValueError): other.eof()
    self.assertTrue(other.failed)
    with self.assertRaises(ValueError): other.feed_stderr(b'SHIELD_NATIVE_BRIDGE_ARMED 1\n')

  def test_root_requires_prebound_boot_and_rejects_different_native_boot(self):
    with self.assertRaises(ValueError): self.make_host(boot_id=None)
    self.host.feed_device(self.hint())
    probe, = self.written()
    other = protocol.Session(self.context, KEY, side='native', boot_id=OTHER_BOOT)
    other.receive(probe)
    with self.assertRaises(ValueError):
      self.host.feed_device(other.send('HELLO', {
        'kernel_release': protocol.KERNEL_RELEASE, 'boottime_ns': SECOND,
        'probe_challenge': other.probe_challenge}))
    self.assertEqual(self.host.session.boot_id, BOOT)
    self.assertFalse(self.host.ready)

  def test_cleanup_retained_exactly_before_correlated_ping_then_confirmed(self):
    self.ready()
    frame = self.evidence()
    observed = []
    original = os.fsync
    def synced(fd):
      observed.append(self.host.session.sent_sequence)
      return original(fd)
    with patch.object(host_module.os, 'fsync', side_effect=synced):
      self.host.feed_device(frame)
    self.assertEqual(observed, [3, 3])  # ACK + initial PING, no cleanup PING yet.
    self.assertEqual((self.directory / 'cleanup.sncp1').read_bytes(), frame)
    self.assertEqual((self.directory / 'cleanup.sncp1').stat().st_mode & 0o777, 0o600)
    ping, = self.written()
    record = self.native.receive(ping)
    challenge = host_module.cleanup_challenge(frame)
    self.assertEqual(record.payload['challenge'], challenge)
    self.assertFalse(self.host.cleanup_confirmed)
    self.host.feed_device(self.native.send('PONG', {'challenge': challenge,
      'boottime_ns': 3 * SECOND}))
    self.assertTrue(self.host.cleanup_confirmed)
    kinds = [event.kind for event in self.host.take_events()]
    self.assertIn('cleanup-retained', kinds)
    self.assertIn('cleanup-confirmed', kinds)

  def test_retention_failure_cannot_queue_cleanup_ping_or_resume(self):
    self.ready()
    with patch.object(host_module.os, 'fsync', side_effect=OSError('synthetic')):
      with self.assertRaises(OSError): self.host.feed_device(self.evidence())
    self.assertEqual(self.host.session.sent_sequence, 3)
    self.assertTrue(self.host.failed)
    self.assertTrue(self.store.attempted)
    self.assertFalse(self.host.wants_write)
    with self.assertRaises(ValueError): self.host.tick()

  def test_wrong_receipt_digest_fails_before_retention(self):
    self.ready()
    observation = self.observation()
    observation['receipt_sha256'] = '0' * 64
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(observation))
    self.assertFalse(self.store.attempted)
    self.assertEqual(self.host.session.sent_sequence, 3)

  def test_bool_guardian_cause_rejected_even_with_matching_digest(self):
    self.ready()
    observation = self.observation(reason={'operation': 5, 'fault': False})
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(observation))
    self.assertFalse(self.store.attempted)

  def test_unknown_signed_observations_and_result_are_not_action_selectors(self):
    self.ready()
    with self.assertRaises(ValueError):
      self.host.feed_device(self.evidence({'kind': 'run', 'path': '/anything'}))
    self.assertFalse(self.store.attempted)
    self.assertEqual(self.host.session.sent_sequence, 3)

  def test_only_one_cleanup_receipt_per_session(self):
    self.ready()
    self.host.feed_device(self.evidence())
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence())
    self.assertTrue(self.host.failed)

  def test_outstanding_liveness_ping_is_completed_before_cleanup_ping(self):
    self.ready()
    self.host.ping('9' * 64)
    ping, = self.written()
    self.native.receive(ping)
    frame = self.evidence()
    self.host.feed_device(frame)
    self.assertEqual(self.host.session.sent_sequence, 4)
    self.assertFalse(self.host.wants_write)
    self.host.feed_device(self.native.send('PONG', {
      'challenge': '9' * 64, 'boottime_ns': 3 * SECOND}))
    self.assertEqual(self.host.session.sent_sequence, 5)
    cleanup_ping, = self.written()
    self.assertEqual(self.native.receive(cleanup_ping).payload['challenge'],
                     host_module.cleanup_challenge(frame))

  def test_prior_pong_age_does_not_impose_an_unmeasured_receipt_timestamp(self):
    self.ready()
    self.clock.value += 3 * SECOND
    self.host.feed_device(self.evidence())
    self.assertEqual(self.host.session.sent_sequence, 4)
    self.assertTrue(self.store.attempted)
    self.assertFalse(self.host.cleanup_confirmed)

  def test_known_short_write_continues_only_unsent_suffix(self):
    self.host.feed_device(self.hint())
    frame = self.host.pending[0][0]
    original = os.write
    def short(fd, data): return original(fd, data[:7])
    with patch.object(host_module.os, 'write', side_effect=short):
      while self.host.wants_write: self.host.drive_write(self.write_fd)
    self.assertEqual(os.read(self.read_fd, 8192), frame)
    self.assertEqual(self.host.session.sent_sequence, 1)

  def test_uncertain_write_and_replaced_pipe_discard_session(self):
    self.host.feed_device(self.hint())
    with patch.object(host_module.os, 'write', side_effect=OSError('synthetic')):
      with self.assertRaises(OSError): self.host.drive_write(self.write_fd)
    self.assertTrue(self.host.failed)
    self.assertEqual(self.host.session.sent_sequence, 1)
    with self.assertRaises(ValueError): self.host.drive_write(self.write_fd)

  def test_pipe_identity_cannot_change_mid_frame(self):
    self.host.feed_device(self.hint())
    original = os.write
    with patch.object(host_module.os, 'write', side_effect=lambda fd, data: original(fd, data[:7])):
      self.host.drive_write(self.write_fd)
    other_read, other_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    try:
      with self.assertRaises(ValueError): self.host.drive_write(other_write)
      self.assertTrue(self.host.failed)
    finally:
      os.close(other_read); os.close(other_write)

  def test_host_deadline_and_incomplete_line_deadline_are_absolute(self):
    self.host.feed_device(b'SNCR1 ')
    self.clock.value += 5 * SECOND
    with self.assertRaises(ValueError): self.host.tick()
    self.assertTrue(self.host.failed)

  def test_host_absolute_deadline_never_renews(self):
    self.ready()
    self.clock.value = self.host.deadline
    with self.assertRaises(ValueError): self.host.tick()
    self.assertTrue(self.host.failed)

  def test_native_timestamp_regression_is_not_readiness(self):
    self.ready()
    self.host.ping('9' * 64)
    ping, = self.written()
    self.native.receive(ping)
    with self.assertRaises(ValueError):
      self.host.feed_device(self.native.send('PONG', {
        'challenge': '9' * 64, 'boottime_ns': SECOND}))

  def test_root_target_deadline_is_strictly_less_than_600_seconds(self):
    self.host.feed_device(self.hint())
    probe, = self.written()
    self.native.receive(probe)
    with self.assertRaises(ValueError):
      self.host.feed_device(self.native.send('HELLO', {
        'kernel_release': protocol.KERNEL_RELEASE, 'boottime_ns': 600 * SECOND,
        'probe_challenge': self.native.probe_challenge}))
    self.assertFalse(self.host.ready)

  def test_zero_nonce_cannot_become_a_receipt(self):
    self.ready()
    observation = self.observation()
    observation['nonce'] = '0' * 64
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(observation))
    self.assertFalse(self.store.attempted)

  def test_cleanup_pong_at_native_cutoff_never_confirms(self):
    self.ready()
    self.host.feed_device(self.evidence())
    ping, = self.written()
    challenge = self.native.receive(ping).payload['challenge']
    with self.assertRaises(ValueError):
      self.host.feed_device(self.native.send('PONG', {
        'challenge': challenge, 'boottime_ns': 20 * SECOND}))
    self.assertFalse(self.host.cleanup_confirmed)

  def early_systemd(self):
    self.store.close()
    self.store = host_module.PrivateFrameStore(self.directory, purpose='systemd-handoff')
    self.handoff_pin = host_module.HandoffPin('8' * 64, 'b' * 32,
      '99999999-aaaa-4bbb-8ccc-dddddddddddd', '1' * 64, '2' * 64,
      '3' * 64, '4' * 64, (256, 5, '@'))
    self.host = self.make_host(epoch='early', boot_id=None, handoff_pin=self.handoff_pin)
    self.native = protocol.Session(self.context, KEY, side='native', boot_id=BOOT)
    self.ready()

  def handoff_observation(self):
    return {'kind': 'systemd-handoff', **self.handoff_pin.projection(),
      'ram_children_reaped': True, 'watchdog_opened': False,
      'source_root_verified': True, 'boottime_ns': 3 * SECOND}

  def handoff_ping(self):
    frame = self.evidence(self.handoff_observation())
    self.assertEqual(self.host.feed_device(frame), b'')
    ping, = self.written()
    challenge = self.native.receive(ping).payload['challenge']
    self.assertEqual(challenge, host_module.handoff_challenge(frame))
    return challenge

  def test_early_systemd_requires_independent_handoff_pin(self):
    with self.assertRaises(ValueError): self.make_host(epoch='early', boot_id=None)

  def test_handoff_wrong_root_session_is_rejected_before_retention(self):
    self.early_systemd()
    value = self.handoff_observation(); value['root_session_id'] = '7' * 64
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
    self.assertFalse(self.store.attempted)

  def test_handoff_wrong_filesystem_uuid_is_rejected_before_retention(self):
    self.early_systemd()
    value = self.handoff_observation(); value['filesystem_uuid'] = OTHER_BOOT
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
    self.assertFalse(self.store.attempted)

  def test_handoff_timestamp_regression_is_not_retained(self):
    self.early_systemd()
    value = self.handoff_observation(); value['boottime_ns'] = SECOND
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
    self.assertFalse(self.store.attempted)

  def test_handoff_claim_at_100_seconds_cannot_be_retained(self):
    self.early_systemd()
    value = self.handoff_observation(); value['boottime_ns'] = 100 * SECOND
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
    self.assertFalse(self.store.attempted)

  def test_handoff_pong_at_100_seconds_does_not_confirm(self):
    self.early_systemd()
    challenge = self.handoff_ping()
    with self.assertRaises(ValueError):
      self.host.feed_device(self.native.send('PONG', {
        'challenge': challenge, 'boottime_ns': 100 * SECOND}))
    self.assertFalse(self.host.handoff_confirmed)

  def test_handoff_retains_full_frame_before_ping_and_returns_all_future_bytes(self):
    self.early_systemd()
    frame = self.evidence(self.handoff_observation())
    sequence_at_sync = []
    original = os.fsync
    def synced(fd):
      sequence_at_sync.append(self.host.session.sent_sequence)
      return original(fd)
    with patch.object(host_module.os, 'fsync', side_effect=synced):
      self.host.feed_device(frame)
    self.assertEqual(sequence_at_sync, [3, 3])
    self.assertEqual((self.directory / 'handoff.sncp1').read_bytes(), frame)
    self.assertFalse((self.directory / 'cleanup.sncp1').exists())
    ping, = self.written()
    challenge = self.native.receive(ping).payload['challenge']
    future = b'SNCR1 ' + b'8' * 64 + b'\n' + b'SNCR1 partial-root-hint'
    final_pong = self.native.send('PONG', {'challenge': challenge, 'boottime_ns': 4 * SECOND})
    self.assertEqual(self.host.feed_device(final_pong + future), future)
    self.assertTrue(self.host.terminal)
    self.assertTrue(self.host.handoff_confirmed)
    self.assertEqual(self.host.framer.pending, b'')
    self.assertIn('handoff-confirmed', [event.kind for event in self.host.take_events()])
    self.assertEqual(self.host.session.boot_id, BOOT)
    self.assertFalse(self.host.wants_write)
    with self.assertRaises(ValueError): self.host.feed_device(self.hint())

  def test_partial_root_hint_tail_is_reassembled_only_by_new_pinned_session(self):
    self.early_systemd()
    challenge = self.handoff_ping()
    root_hint = b'SNCR1 ' + b'8' * 64 + b'\n'
    pong = self.native.send('PONG', {'challenge': challenge, 'boottime_ns': 4 * SECOND})
    # Include an already buffered partial early PONG before the gate arrives.
    self.assertEqual(self.host.feed_device(pong[:17]), b'')
    tail = self.host.feed_device(pong[17:] + root_hint[:19])
    self.assertEqual(tail, root_hint[:19])
    root_context = protocol.Context('8' * 64, 'systemd', self.context.candidate, self.context.config_sha256)
    root_store = host_module.PrivateFrameStore(self.directory, purpose='root-cleanup')
    self.addCleanup(root_store.close)
    root = host_module.HostLink(root_context, b'\x04' * 32, self.bridge,
      self.host.deadline, epoch='root', store=root_store, boot_id=self.host.session.boot_id,
      clock=self.clock, challenge_source=lambda: 'd' * 64)
    self.assertEqual(root.feed_device(tail), b'')
    self.assertEqual(root.session.sent_sequence, 0)
    root.feed_device(root_hint[19:])
    self.assertEqual(root.session.sent_sequence, 1)
    self.assertEqual(root.session.boot_id, BOOT)
    self.assertFalse(root.ready)  # A hint/confirmed preparation is not a root HELLO.

  def test_handoff_waits_for_preexisting_ping_without_extending_host_deadline(self):
    self.early_systemd()
    original_deadline = self.host.deadline
    self.host.ping('9' * 64)
    ping, = self.written(); self.native.receive(ping)
    frame = self.evidence(self.handoff_observation())
    self.host.feed_device(frame)
    self.assertFalse(self.host.wants_write)
    self.assertFalse(self.host.handoff_confirmed)
    self.host.feed_device(self.native.send('PONG', {'challenge': '9' * 64, 'boottime_ns': 4 * SECOND}))
    handoff_ping, = self.written()
    challenge = self.native.receive(handoff_ping).payload['challenge']
    self.assertEqual(challenge, host_module.handoff_challenge(frame))
    self.assertEqual(self.host.deadline, original_deadline)

  def test_handoff_flag_types_are_exact_and_pin_default_is_immutable(self):
    self.early_systemd()
    value = self.handoff_observation(); value['ram_children_reaped'] = 1
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
    self.assertFalse(self.store.attempted)
    self.assertIsInstance(self.handoff_pin.original_default, tuple)

  def test_handoff_retention_failure_never_queues_confirmation_ping(self):
    self.early_systemd()
    with patch.object(host_module.os, 'fsync', side_effect=OSError('synthetic retention failure')):
      with self.assertRaises(OSError):
        self.host.feed_device(self.evidence(self.handoff_observation()))
    self.assertEqual(self.host.session.sent_sequence, 3)
    self.assertFalse(self.host.handoff_confirmed)
    self.assertFalse(self.host.terminal)
    self.assertTrue(self.host.failed)

  def maintenance_phase(self, phase='packages', *, ready=True):
    self.store.close()
    self.store = host_module.PrivateFrameStore(self.directory, purpose='maintenance-release')
    self.context = protocol.Context('a' * 64, phase, 'b' * 64, 'd' * 64)
    self.maintenance_pin = host_module.FrozenMaintenancePin(phase, 'b' * 32,
      '99999999-aaaa-4bbb-8ccc-dddddddddddd', '1' * 64, '2' * 64, (256, 5, '@'))
    self.host = self.make_host(epoch='early', boot_id=None, maintenance_pin=self.maintenance_pin)
    self.native = protocol.Session(self.context, KEY, side='native', boot_id=BOOT)
    if ready: self.ready()

  def maintenance_observation(self, *, passed=True):
    return {'kind': 'maintenance-released', **self.maintenance_pin.projection(),
      'worker_result_sha256': '3' * 64 if passed else None,
      'journal_sha256': '4' * 64 if passed else None,
      'original_root_profile_preserved': True, 'phase_passed': passed, 'worker_started': passed,
      'worker_reaped': True, 'reaper_reaped': True, 'worker_leaf_empty': True,
      'filesystem_unmounted': True, 'partition_ro': True, 'disk_ro': True, 'internal_user_ro': True,
      'cleanup_deadline_ns': 20 * SECOND, 'boottime_ns': 3 * SECOND, 'nonce': '5' * 64,
      'boot_ready': False, 'physical_powerloss_qualified': False}

  def maintenance_ping(self, value=None):
    frame = self.evidence(self.maintenance_observation() if value is None else value)
    self.assertEqual(self.host.feed_device(frame), b'')
    ping, = self.written()
    challenge = self.native.receive(ping).payload['challenge']
    self.assertEqual(challenge, host_module.maintenance_challenge(frame))
    return challenge

  def test_maintenance_requires_independent_pin_and_exact_store_purpose(self):
    self.maintenance_phase(ready=False)
    with self.assertRaises(ValueError): self.make_host(epoch='early', boot_id=None)
    self.store.close()
    self.store = host_module.PrivateFrameStore(self.directory, purpose='root-cleanup')
    with self.assertRaises(ValueError):
      self.make_host(epoch='early', boot_id=None, maintenance_pin=self.maintenance_pin)
    with self.assertRaises(ValueError):
      host_module.FrozenMaintenancePin('packages', 'b' * 32, OTHER_BOOT, '1' * 64, '2' * 64, [256, 5, '@'])

  def test_maintenance_retains_exact_frame_fsyncs_before_correlated_ping(self):
    self.maintenance_phase()
    frame = self.evidence(self.maintenance_observation())
    sequence_at_sync = []
    original = os.fsync
    def synced(fd):
      sequence_at_sync.append(self.host.session.sent_sequence)
      return original(fd)
    with patch.object(host_module.os, 'fsync', side_effect=synced): self.host.feed_device(frame)
    self.assertEqual(sequence_at_sync, [3, 3])
    self.assertEqual((self.directory / 'maintenance.sncp1').read_bytes(), frame)
    self.assertEqual((self.directory / 'maintenance.sncp1').stat().st_mode & 0o777, 0o600)
    self.assertFalse((self.directory / 'cleanup.sncp1').exists())
    ping, = self.written()
    challenge = self.native.receive(ping).payload['challenge']
    self.assertEqual(challenge, hashlib.sha256(b'shield-native-maintenance/v1\0' + frame).hexdigest())
    self.host.feed_device(self.native.send('PONG', {'challenge': challenge, 'boottime_ns': 4 * SECOND}))
    self.assertTrue(self.host.maintenance_confirmed)
    self.assertTrue(self.host.terminal)
    self.assertIn('maintenance-confirmed', [event.kind for event in self.host.take_events()])
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(self.maintenance_observation()))

  def test_failed_layer_release_can_be_fenced_without_positive_phase_claim(self):
    self.maintenance_phase('layer')
    value = self.maintenance_observation(passed=False)
    challenge = self.maintenance_ping(value)
    self.host.feed_device(self.native.send('PONG', {'challenge': challenge, 'boottime_ns': 4 * SECOND}))
    self.assertTrue(self.host.maintenance_confirmed)
    observed = host_module.plain(self.host.maintenance_expected[2].payload['observations'])
    self.assertIs(observed['phase_passed'], False)
    self.assertIs(observed['worker_started'], False)
    self.assertIsNone(observed['worker_result_sha256'])
    self.assertIsNone(observed['journal_sha256'])
    self.assertNotIn('completion', [event.kind for event in self.host.take_events()])

  def test_maintenance_pin_mismatch_rejected_before_retention(self):
    for field, wrong in [('phase', 'layer'), ('candidate_id', 'c' * 32),
      ('filesystem_uuid', OTHER_BOOT), ('payload_manifest_sha256', '6' * 64), ('plan_sha256', '7' * 64),
      ('original_default', {'id': 257, 'top_level': 5, 'path': '@'})]:
      self.maintenance_phase()
      value = self.maintenance_observation(); value[field] = wrong
      with self.subTest(field=field), self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
      self.assertFalse(self.store.attempted)

  def test_maintenance_requires_all_actual_release_proofs_as_exact_booleans(self):
    for field in ['original_root_profile_preserved', 'worker_reaped', 'reaper_reaped',
      'worker_leaf_empty', 'filesystem_unmounted', 'partition_ro', 'disk_ro', 'internal_user_ro']:
      self.maintenance_phase()
      value = self.maintenance_observation(); value[field] = 1
      with self.subTest(field=field), self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
      self.assertFalse(self.store.attempted)

  def test_maintenance_pass_requires_started_worker_and_two_nonzero_digests(self):
    for field, wrong in [('worker_started', False), ('worker_result_sha256', None),
      ('journal_sha256', '0' * 64), ('phase_passed', 1), ('worker_result_sha256', 'bad')]:
      self.maintenance_phase()
      value = self.maintenance_observation(); value[field] = wrong
      with self.subTest(field=field), self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
      self.assertFalse(self.store.attempted)

  def test_maintenance_rejects_unknown_missing_fields_and_false_qualification_claims(self):
    for field, wrong in [('extra', True), ('boot_ready', True), ('physical_powerloss_qualified', True),
      ('nonce', '0' * 64), ('worker_started', 0)]:
      self.maintenance_phase()
      value = self.maintenance_observation(); value[field] = wrong
      with self.subTest(field=field), self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
      self.assertFalse(self.store.attempted)
    self.maintenance_phase()
    value = self.maintenance_observation(); del value['internal_user_ro']
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
    self.assertFalse(self.store.attempted)

  def test_maintenance_clock_regression_expiry_and_boolean_types_rejected(self):
    for field, wrong in [('boottime_ns', SECOND), ('boottime_ns', True),
      ('boottime_ns', 20 * SECOND), ('cleanup_deadline_ns', 601 * SECOND), ('cleanup_deadline_ns', True)]:
      self.maintenance_phase()
      value = self.maintenance_observation(); value[field] = wrong
      with self.subTest(field=field), self.assertRaises(ValueError): self.host.feed_device(self.evidence(value))
      self.assertFalse(self.store.attempted)

  def test_maintenance_waits_for_outstanding_ping_without_renewing_deadline(self):
    self.maintenance_phase()
    deadline = self.host.deadline
    self.host.ping('9' * 64)
    ping, = self.written(); self.native.receive(ping)
    frame = self.evidence(self.maintenance_observation())
    self.host.feed_device(frame)
    self.assertFalse(self.host.wants_write)
    self.host.feed_device(self.native.send('PONG', {'challenge': '9' * 64, 'boottime_ns': 4 * SECOND}))
    ping, = self.written()
    self.assertEqual(self.native.receive(ping).payload['challenge'], host_module.maintenance_challenge(frame))
    self.assertEqual(self.host.deadline, deadline)

  def test_maintenance_pong_at_deadline_never_confirms(self):
    self.maintenance_phase()
    challenge = self.maintenance_ping()
    with self.assertRaises(ValueError):
      self.host.feed_device(self.native.send('PONG', {'challenge': challenge, 'boottime_ns': 20 * SECOND}))
    self.assertFalse(self.host.maintenance_confirmed)

  def test_maintenance_retention_failure_never_queues_release_ping(self):
    self.maintenance_phase()
    with patch.object(host_module.os, 'fsync', side_effect=OSError('synthetic retention failure')):
      with self.assertRaises(OSError): self.host.feed_device(self.evidence(self.maintenance_observation()))
    self.assertEqual(self.host.session.sent_sequence, 3)
    self.assertTrue(self.host.failed)
    self.assertFalse(self.host.maintenance_confirmed)

  def test_maintenance_duplicate_release_is_absorbing(self):
    self.maintenance_phase()
    self.host.feed_device(self.evidence(self.maintenance_observation()))
    with self.assertRaises(ValueError): self.host.feed_device(self.evidence(self.maintenance_observation()))
    self.assertTrue(self.host.failed)

  def test_maintenance_final_pong_with_extra_bytes_cannot_confirm_or_transfer(self):
    self.maintenance_phase()
    challenge = self.maintenance_ping()
    pong = self.native.send('PONG', {'challenge': challenge, 'boottime_ns': 4 * SECOND})
    with self.assertRaises(ValueError): self.host.feed_device(pong + b'extra')
    self.assertFalse(self.host.maintenance_confirmed)
    self.assertTrue(self.host.failed)

  def test_maintenance_liveness_ping_refused_after_release_seen(self):
    self.maintenance_phase()
    self.host.feed_device(self.evidence(self.maintenance_observation()))
    with self.assertRaises(ValueError): self.host.ping('9' * 64)
    self.assertTrue(self.host.failed)

  def test_store_digest_is_unset_until_both_fsyncs_and_final_check(self):
    self.assertIsNone(self.store.retained_sha256)
    frame = b'exact retained wire bytes\n'
    checks, syncs = [], []
    original = os.fsync
    def synced(fd):
      self.assertIsNone(self.store.retained_sha256)
      syncs.append(fd)
      return original(fd)
    def checked():
      self.assertIsNone(self.store.retained_sha256)
      checks.append(len(syncs))
    with patch.object(host_module.os, 'fsync', side_effect=synced):
      self.store.retain(frame, checked)
    self.assertEqual(len(syncs), 2)
    self.assertEqual(checks[-1], 2)
    self.assertEqual(self.store.retained_sha256, hashlib.sha256(frame).hexdigest())

  def test_store_digest_stays_unset_after_file_or_directory_fsync_failure(self):
    original = os.fsync
    for fail_at in [1, 2]:
      with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as name:
        os.chmod(name, 0o700)
        store = host_module.PrivateFrameStore(Path(name), purpose='maintenance-release')
        syncs = []
        def synced(fd):
          syncs.append(fd)
          if len(syncs) == fail_at: raise OSError('synthetic retention failure')
          return original(fd)
        try:
          with patch.object(host_module.os, 'fsync', side_effect=synced):
            with self.assertRaises(OSError): store.retain(b'exact wire\n', lambda: None)
          self.assertIsNone(store.retained_sha256)
          self.assertTrue(store.attempted)
        finally: store.close()

  def test_store_digest_stays_unset_after_final_deadline_check_failure(self):
    original = os.fsync
    syncs = []
    def synced(fd):
      syncs.append(fd)
      return original(fd)
    def checked():
      if len(syncs) == 2: raise ValueError('original deadline elapsed')
    with patch.object(host_module.os, 'fsync', side_effect=synced):
      with self.assertRaises(ValueError): self.store.retain(b'exact wire\n', checked)
    self.assertIsNone(self.store.retained_sha256)
    self.assertTrue(self.store.attempted)

  def test_store_digest_stays_unset_after_incomplete_write(self):
    with patch.object(host_module.os, 'write', return_value=0):
      with self.assertRaises(ValueError): self.store.retain(b'exact wire\n', lambda: None)
    self.assertIsNone(self.store.retained_sha256)
    self.assertTrue(self.store.attempted)


if __name__ == '__main__':
  unittest.main()
