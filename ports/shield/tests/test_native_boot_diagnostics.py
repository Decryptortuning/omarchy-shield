"""Validate the diagnostic boundary without opening any kernel device."""
import ast
import builtins
from contextlib import ExitStack, contextmanager
import importlib.util
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def policy_profile():
  candidate = 'a' * 32
  root = '@shield-' + candidate
  return {'account': {'name': 'shieldqual', 'uid': 1001, 'gid': 1001},
    'filesystem': {'candidate_id': candidate,
      'subvolumes': {'root': root, 'home': root + '-home', 'log': root + '-log'}}}
sys.path.insert(0, str(TOOLS))

def module(name, leaf):
  spec = importlib.util.spec_from_file_location(name, TOOLS / leaf)
  target = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(target)
  return target

BOOT = module('diagnostic_boot_target', 'native-boot.py')
CAPSULE = module('diagnostic_capsule_target', 'prepare-native-capsule.py')
ROOT = module('diagnostic_root_target', 'native-root-control.py')


class SplashExitAdmissionTests(unittest.TestCase):
  def setUp(self):
    import native_unit_policy
    self.policy = native_unit_policy
    self.quit = dict(FragmentPath='/usr/lib/systemd/system/plymouth-quit.service',
      DropInPaths='', ActiveState='active', SubState='exited', Result='success', MainPID='0', ExecMainCode='1', ExecMainStatus='0')
    self.splash = dict(FragmentPath='/usr/lib/systemd/system/plymouth-start.service',
      DropInPaths='', ActiveState='active', SubState='exited', MainPID='0',
      ControlGroup='/system.slice/plymouth-start.service')

  def admit(self, quit=None, splash=None):
    with patch.object(self.policy, 'unit_properties', side_effect=[
      self.quit if quit is None else quit, self.splash if splash is None else splash]), \
      patch.object(self.policy, 'validate_splash_cgroup'), \
      patch.object(self.policy, 'owned_bytes', side_effect=lambda path, limit, mode: self.policy.SPLASH_UNIT_BYTES[path.name]):
      self.policy.validate_splash_exit()

  def test_finished_or_skipped_splash_is_admitted(self):
    self.admit()
    self.admit(splash=self.splash | dict(ActiveState='inactive', SubState='dead'))

  def test_oneshot_success_does_not_admit_a_running_daemon(self):
    with self.assertRaises(ValueError):
      self.admit(splash=self.splash | dict(MainPID='123', SubState='running'))

  def test_failed_incomplete_or_overridden_quit_is_refused(self):
    for delta in [dict(Result='exit-code'), dict(ExecMainCode='0'), dict(ExecMainStatus='1'),
      dict(ActiveState='activating'),
      dict(SubState='start'), dict(MainPID='123'), dict(FragmentPath='/etc/systemd/system/plymouth-quit.service'),
      dict(DropInPaths='/run/systemd/system/plymouth-quit.service.d/override.conf')]:
      with self.subTest(delta=delta), self.assertRaises(ValueError): self.admit(quit=self.quit | delta)

  def test_failed_or_overridden_splash_is_refused(self):
    for delta in [dict(ActiveState='failed', SubState='failed'),
      dict(FragmentPath='/etc/systemd/system/plymouth-start.service'), dict(DropInPaths='/private/override.conf'),
      dict(ControlGroup='/system.slice/other.service')]:
      with self.subTest(delta=delta), self.assertRaises(ValueError): self.admit(splash=self.splash | delta)

  def test_live_daemon_cgroup_refuses_even_with_zero_mainpid(self):
    for data in [b'123\n', b'0\n', b' ']:
      with self.subTest(data=data), patch.object(self.policy.os, 'open', return_value=71), \
        patch.object(self.policy.os, 'fstat', return_value=SimpleNamespace(
          st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)), \
        patch.object(self.policy.os, 'read', return_value=data), \
        patch.object(self.policy.os, 'close') as closed, self.assertRaises(ValueError):
        self.policy.validate_splash_cgroup()
      closed.assert_called_once_with(71)

  def test_absent_or_empty_owned_splash_cgroup_passes(self):
    with patch.object(self.policy.os, 'open', side_effect=FileNotFoundError):
      self.policy.validate_splash_cgroup()
    with patch.object(self.policy.os, 'open', return_value=71), \
      patch.object(self.policy.os, 'fstat', return_value=SimpleNamespace(
        st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)), \
      patch.object(self.policy.os, 'read', return_value=b'') as read, \
      patch.object(self.policy.os, 'close') as closed:
      self.policy.validate_splash_cgroup()
    read.assert_called_once_with(71, 4097)
    closed.assert_called_once_with(71)

  def test_changed_stock_unit_bytes_are_refused_before_daemon_admission(self):
    with patch.object(self.policy, 'owned_bytes', return_value=b'changed'), \
      patch.object(self.policy, 'unit_properties') as query, self.assertRaises(ValueError):
      self.policy.validate_splash_exit()
    query.assert_not_called()

  def test_property_query_rejects_duplicates_missing_fields_stderr_and_failure(self):
    for code, text, error in [(0, 'A=1\nA=2\n', ''), (0, 'A=1\n', ''),
      (0, 'A=1\nB=2\n', 'unexpected'), (1, 'A=1\nB=2\n', ''), (0, 'invalid\nB=2\n', '')]:
      with self.subTest(text=text, error=error), patch.object(self.policy.subprocess, 'run',
        return_value=SimpleNamespace(returncode=code, stdout=text, stderr=error)), self.assertRaises(ValueError):
        self.policy.unit_properties('plymouth-start.service', ('A', 'B'))


class NativeDiagnosticBoundaryTests(unittest.TestCase):
  def node(self, **changes):
    values = dict(st_mode=stat.S_IFCHR | 0o600, st_uid=0, st_gid=0,
                  st_rdev=os.makedev(1, 11))
    return SimpleNamespace(**(values | changes))

  def test_non_pid1_cannot_open_device(self):
    with patch.object(BOOT.os, 'getpid', return_value=1234), \
         patch.object(BOOT.os, 'open') as opened:
      BOOT.diagnostic('entry')
      opened.assert_not_called()

  def test_pid1_fixed_node_bounded_record_excludes_exception_text(self):
    with patch.object(BOOT.os, 'getpid', return_value=1), \
         patch.object(BOOT.os, 'open', return_value=83) as opened, \
         patch.object(BOOT.os, 'fstat', return_value=self.node()), \
         patch.object(BOOT.os, 'write', return_value=1) as written, \
         patch.object(BOOT.os, 'close') as closed, \
         patch.object(BOOT.time, 'clock_gettime_ns', return_value=123456):
      BOOT.diagnostic('gadget-bind', ValueError('PRIVATE_EXCEPTION_TEXT'))
      opened.assert_called_once_with('/dev/kmsg', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
      written.assert_called_once()
      fd, raw = written.call_args.args
      self.assertEqual(fd, 83)
      self.assertEqual(raw, b'<3>shield-native stage=gadget-bind boottime_ns=123456 error=ValueError\n')
      self.assertLessEqual(len(raw), 240)
      closed.assert_called_once_with(83)
      # A partial diagnostic write receives no retry or success authority.

  def traceback_error(self, frames):
    """Synthetic frame metadata exercises output bounds without private frames."""
    trace = None
    for filename, function, line in reversed(frames):
      code = SimpleNamespace(co_filename=filename, co_name=function)
      trace = SimpleNamespace(tb_frame=SimpleNamespace(f_code=code), tb_lineno=line, tb_next=trace)
    return SimpleNamespace(__traceback__=trace)

  def capture_diagnostic(self, error, write_error=None):
    with patch.object(BOOT.os, 'getpid', return_value=1), \
         patch.object(BOOT.os, 'open', return_value=83), \
         patch.object(BOOT.os, 'fstat', return_value=self.node()), \
         patch.object(BOOT.os, 'write', side_effect=write_error) as written, \
         patch.object(BOOT.os, 'close') as closed, \
         patch.object(BOOT.time, 'clock_gettime_ns', return_value=123456):
      self.assertIsNone(BOOT.diagnostic('admission-refused', error))
      closed.assert_called_once_with(83)
      return [call.args[1] for call in written.call_args_list]

  def test_faultsites_redact_paths_functions_exception_and_skipped_frames(self):
    error = self.traceback_error([
      ('/PRIVATE_PATH/native-boot.py', 'PRIVATE_FUNCTION', 700),
      ('/PRIVATE_PATH/secret.py', 'PRIVATE_FUNCTION', 999),
      ('/PRIVATE_PATH/native_boot_context.py', 'directory', 151),
      ('/PRIVATE_PATH/usb_root_profile.py', 'require', 44)])
    error.private = 'PRIVATE_EXCEPTION_TEXT'
    records = self.capture_diagnostic(error)
    self.assertEqual(len(records), 3)
    self.assertEqual(records[1], b'<3>shield-native-fault file=native-boot.py line=700 caller_file=none caller_line=0 depth=0\n')
    self.assertEqual(records[2], b'<3>shield-native-fault file=native_boot_context.py line=151 caller_file=native-boot.py caller_line=700 depth=2\n')
    self.assertNotIn(b'PRIVATE', b''.join(records))
    self.assertNotIn(b'require', b''.join(records))

  def test_faultsite_traversal_and_each_record_are_bounded(self):
    frames = [('/private/native_boot_context.py', 'directory', 151)] * 20
    records = self.capture_diagnostic(self.traceback_error(frames))
    self.assertEqual(len(records), 9)
    self.assertTrue(all(len(record) <= 240 for record in records))
    self.assertIn(b'depth=7', records[-1])
    self.assertNotIn(b'depth=8', b''.join(records))

  def test_faultsites_reject_unknown_files_and_invalid_lines(self):
    frames = [('private.py', 'anything', 10), ('native-boot.py', 'anything', 0),
      ('native-boot.py', 'anything', 100000), ('native-boot.py', 'anything', True),
      ('native-boot.py', 'anything', -1)]
    self.assertEqual(len(self.capture_diagnostic(self.traceback_error(frames))), 1)

  def test_stage_write_failure_is_contained_without_retry(self):
    error = self.traceback_error([('native_boot_context.py', 'directory', 151)])
    records = self.capture_diagnostic(error, BlockingIOError('PRIVATE'))
    self.assertEqual(len(records), 1)

  def test_faultsite_write_failure_stops_further_diagnostics_without_retry(self):
    error = self.traceback_error([('native_boot_context.py', 'directory', 151)] * 3)
    records = self.capture_diagnostic(error, [None, BlockingIOError('PRIVATE')])
    self.assertEqual(len(records), 2)
    self.assertIn(b'shield-native-fault', records[1])

  def test_low_level_public_faultsites_keep_private_paths_and_functions_redacted(self):
    names = ['native_gadget.py', 'native_serial_link.py', 'native_children.py',
      'native_root_storage.py', 'native_maintenance.py', 'native_mounts.py',
      'native_work_guard.py', 'native_layer_reader.py', 'native_layer_writer.py',
      'native_ram_recovery.py', 'native_cleanup_rpc.py', 'guardian_client.py']
    for name in names:
      with self.subTest(name=name):
        error = self.traceback_error([('/PRIVATE/' + name, 'PRIVATE_FUNCTION', 99999)])
        records = self.capture_diagnostic(error)
        self.assertEqual(len(records), 2)
        self.assertIn(('file=' + name + ' line=99999 ').encode(), records[1])
        self.assertLessEqual(len(records[1]), 240)
        self.assertNotIn(b'PRIVATE', b''.join(records))

  def test_unknown_frames_consume_the_same_eight_link_budget(self):
    frames = [('PRIVATE.py', 'PRIVATE_FUNCTION', 10)] * 8
    frames.append(('native_gadget.py', 'PRIVATE_FUNCTION', 99))
    self.assertEqual(len(self.capture_diagnostic(self.traceback_error(frames))), 1)

  def test_wrong_node_owner_type_permissions_or_device_cannot_receive_data(self):
    bad = [self.node(st_mode=stat.S_IFREG | 0o600), self.node(st_uid=1001),
           self.node(st_gid=1001), self.node(st_mode=stat.S_IFCHR | 0o622),
           self.node(st_rdev=os.makedev(1, 3))]
    for node in bad:
      with self.subTest(node=node), \
           patch.object(BOOT.os, 'getpid', return_value=1), \
           patch.object(BOOT.os, 'open', return_value=83), \
           patch.object(BOOT.os, 'fstat', return_value=node), \
           patch.object(BOOT.os, 'write') as written, \
           patch.object(BOOT.os, 'close') as closed:
        BOOT.diagnostic('entry')
        written.assert_not_called()
        closed.assert_called_once_with(83)

  def test_log_failure_and_malformed_stage_cannot_change_control_flow(self):
    with patch.object(BOOT.os, 'getpid', return_value=1), \
         patch.object(BOOT.os, 'open', side_effect=BlockingIOError) as opened:
      self.assertIsNone(BOOT.diagnostic('entry'))
      opened.assert_called_once()
    for stage in ['bad\nstage', 'bad stage', '\u00e9', '', 'x' * 65]:
      with self.subTest(stage=stage), \
           patch.object(BOOT.os, 'getpid', return_value=1), \
           patch.object(BOOT.os, 'open') as opened:
        BOOT.diagnostic(stage)
        opened.assert_not_called()

  def test_pre_owner_hold_survives_interruption_without_starting_an_owner(self):
    pid = os.fork()
    if pid == 0:
      def sleep(_seconds):
        # The first interruption must be contained; the second call exits only
        # this disposable child, proving the actual refusal hold continued.
        sleep.calls += 1
        if sleep.calls == 1: raise KeyboardInterrupt
        os._exit(73)
      sleep.calls = 0
      try:
        with patch.object(BOOT.os, 'getpid', return_value=1), \
             patch.object(BOOT, 'diagnostic'), \
             patch.object(BOOT.time, 'sleep', side_effect=sleep):
          BOOT.admission_hold('python-import-refused', ImportError('private'))
      finally: os._exit(74)
    status = None
    deadline = time.monotonic() + 3
    try:
      while time.monotonic() < deadline:
        returned, observed = os.waitpid(pid, os.WNOHANG)
        if returned == pid: status = observed; break
        time.sleep(0.01)
    finally:
      if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    self.assertIsNotNone(status, 'Refusal child did not positively finish')
    self.assertTrue(os.WIFEXITED(status))
    self.assertEqual(os.WEXITSTATUS(status), 73)

  def test_diagnostic_commandline_disables_compression_and_retains_watchdog_bounds(self):
    tokens = CAPSULE.command_line('packages', 'a' * 64, 'b' * 64).decode('ascii').split()
    self.assertEqual(tokens.count('pstore.compress=none'), 1)
    self.assertEqual(tokens.count('watchdog.open_timeout=240'), 1)
    self.assertEqual(tokens.count('watchdog.stop_on_reboot=0'), 1)
    self.assertIn('rdinit=/init', tokens)


class NativeInitialClockTests(unittest.TestCase):
  UTC_NS = 1_800_000_000_000_000_000
  SECOND = 1_000_000_000

  def setUp(self):
    self.s = BOOT.Supervisor.__new__(BOOT.Supervisor)
    self.s.bundle = SimpleNamespace(epoch='early')
    self.s.link = SimpleNamespace(ready=True)
    self.s.clock_sample = BOOT.Event('ready', utc_ns=self.UTC_NS,
      received_boottime_ns=10 * self.SECOND)
    self.s.clock_attempted = self.s.clock_ready = False
    self.s.check = Mock()
    self.deadline = 20 * self.SECOND
    self.enterContext(patch.object(BOOT.os, 'getpid', return_value=1))
    self.enterContext(patch.object(BOOT.os, 'geteuid', return_value=0))
    self.enterContext(patch.object(BOOT, 'now', return_value=11 * self.SECOND))
    self.setter = self.enterContext(patch.object(BOOT.time, 'clock_settime_ns'))
    self.realtime = self.enterContext(patch.object(BOOT.time, 'time_ns',
      return_value=self.UTC_NS + self.SECOND))

  def test_single_realtime_set_uses_boottime_elapsed_and_original_deadline(self):
    self.s.apply_clock(self.deadline)
    self.setter.assert_called_once_with(BOOT.time.CLOCK_REALTIME, self.UTC_NS + self.SECOND)
    self.assertTrue(self.s.clock_ready)
    self.assertTrue(self.s.clock_attempted)
    self.assertEqual([call.args for call in self.s.check.call_args_list],
      [(self.deadline,), (self.deadline,)])
    with self.assertRaises(ValueError): self.s.apply_clock(self.deadline)
    self.assertEqual(self.setter.call_count, 1)

  def test_uncertain_setter_failure_is_consumed_and_never_retried(self):
    self.setter.side_effect = OSError('synthetic clock refusal')
    with self.assertRaises(OSError): self.s.apply_clock(self.deadline)
    self.assertTrue(self.s.clock_attempted)
    self.assertFalse(self.s.clock_ready)
    with self.assertRaises(ValueError): self.s.apply_clock(self.deadline)
    self.assertEqual(self.setter.call_count, 1)

  def test_root_epoch_or_unfinished_pong_never_sets_any_clock(self):
    for epoch, ready in [('root', True), ('early', False)]:
      self.s.bundle.epoch = epoch; self.s.link.ready = ready
      with self.assertRaises(ValueError): self.s.apply_clock(self.deadline)
    self.setter.assert_not_called()

  def test_stale_future_or_invalid_samples_never_set_any_clock(self):
    for sample in [None, BOOT.Event('ready', utc_ns=True, received_boottime_ns=10*self.SECOND),
      BOOT.Event('ready', utc_ns=self.UTC_NS, received_boottime_ns=0),
      BOOT.Event('ready', utc_ns=self.UTC_NS, received_boottime_ns=12*self.SECOND)]:
      self.s.clock_sample = sample
      with self.assertRaises(ValueError): self.s.apply_clock(self.deadline)
    self.setter.assert_not_called()

  def test_bad_readback_never_releases_work(self):
    self.realtime.return_value = self.UTC_NS + 50*self.SECOND
    with self.assertRaises(ValueError): self.s.apply_clock(self.deadline)
    self.assertTrue(self.s.clock_attempted)
    self.assertFalse(self.s.clock_ready)
    self.setter.assert_called_once()

  def test_expired_original_deadline_after_setter_never_releases_work(self):
    with patch.object(BOOT, 'now', side_effect=[11*self.SECOND, self.deadline]):
      with self.assertRaises(ValueError):
        self.s.apply_clock(self.deadline)
    self.setter.assert_called_once_with(BOOT.time.CLOCK_REALTIME, self.UTC_NS+self.SECOND)
    self.assertTrue(self.s.clock_attempted)
    self.assertFalse(self.s.clock_ready)
    self.assertEqual([call.args for call in self.s.check.call_args_list], [(self.deadline,)])

  def test_real_handshake_pump_latches_sample_before_transport_sets_clock(self):
    from native_control_protocol import Context, Session
    from native_serial_link import NativeLink
    key = b'\x07' * 32
    context = Context('a'*64, 'packages', 'b'*64, 'c'*64)
    boot = '11111111-2222-4333-8444-555555555555'
    device, host = socket.socketpair()
    for endpoint in [device, host]:
      endpoint.setblocking(False)
      self.addCleanup(endpoint.close)
    self.s.bundle = SimpleNamespace(epoch='early', phase='packages',
      contexts={'early': context}, boot_id=boot, key=lambda epoch: key)
    self.s.events = BOOT.select.epoll()
    self.addCleanup(self.s.events.close)
    self.s.children = SimpleNamespace(wake_read=-99, reap=Mock())
    self.s.uevent = SimpleNamespace(fileno=lambda: -98)
    self.s.child_fds = {}
    self.s.control_events = []
    self.s.handoff_challenge = None
    self.s.clock_sample = None
    peer = Session(context, key, side='host')
    host.sendall(peer.send('PROBE', {'challenge': 'd'*64}))
    pending = bytearray()
    received_kinds = []
    deadlines = []
    def handshake(predicate, deadline):
      deadlines.append(deadline)
      for _step in range(32):
        self.s.pump(0)
        try: pending.extend(host.recv(8192))
        except BlockingIOError: pass
        while b'\n' in pending:
          end = pending.index(10)+1
          frame = bytes(pending[:end]); del pending[:end]
          if frame.startswith(b'SNCR1 '):
            self.assertEqual(frame, b'SNCR1 '+context.session_id.encode()+b'\n')
            continue
          record = peer.receive(frame)
          received_kinds.append(record.kind)
          if record.kind == 'HELLO':
            host.sendall(peer.send('ACK', {'hello_body_sha256': record.body_sha256})
              + peer.send('PING', {'challenge': 'e'*64, 'utc_ns': self.UTC_NS}))
        if predicate():
          self.assertIsNotNone(self.s.clock_sample)
          self.assertFalse(self.s.clock_ready)
          self.setter.assert_not_called()
          return
      self.fail('Actual socketpair handshake did not finish')
    self.s.wait = handshake
    def native_link(fd, ctx, secret, boot_id, deadline):
      return NativeLink(fd, ctx, secret, boot_id, deadline,
        clock=lambda: 10*self.SECOND)
    with patch.object(BOOT, 'diagnostic'), patch.object(BOOT, 'prepare'), \
         patch.object(BOOT, 'bind'), patch.object(BOOT, 'wait_configured'), \
         patch.object(BOOT, 'open_native_tty', return_value=device.fileno()), \
         patch.object(BOOT, 'NativeLink', side_effect=native_link):
      self.s.transport()
    self.assertEqual(received_kinds, ['HELLO', 'PONG'])
    self.assertEqual(deadlines, [21*self.SECOND])
    self.assertTrue(self.s.clock_ready)
    self.setter.assert_called_once_with(BOOT.time.CLOCK_REALTIME, self.UTC_NS+self.SECOND)
    sample = self.s.clock_sample
    self.assertEqual((sample.utc_ns, sample.received_boottime_ns),
      (self.UTC_NS, 10*self.SECOND))
    self.assertIs(self.s.take_control_events()[0], sample)
    self.assertIs(self.s.clock_sample, sample)

  def test_storage_cannot_start_before_clock_admission(self):
    with patch.object(BOOT, 'discover') as discover:
      with self.assertRaises(ValueError): self.s.storage()
      discover.assert_not_called()



class RootDiagnosticBoundaryTests(unittest.TestCase):
  def node(self, **changes):
    return SimpleNamespace(**(dict(st_mode=stat.S_IFCHR | 0o600, st_uid=0, st_gid=0,
      st_rdev=os.makedev(1, 11)) | changes))

  def capture(self, stage='root-effective-units', error=None, overrides=None,
              node=None, write_effect=None, close_effect=None, open_effect=None, argv=None, action=None):
    with ExitStack() as stack:
      identity = dict(getpid=77, getppid=1, getuid=0, geteuid=0, getgid=0, getegid=0,
        uname=SimpleNamespace(machine='aarch64', release='7.1.0-shield-bringup'))
      identity.update(overrides or {})
      for name, value in identity.items(): stack.enter_context(patch.object(ROOT.os, name, return_value=value))
      stack.enter_context(patch.object(ROOT.sys, 'argv', ['native-root-control.py', '--run'] if argv is None else argv))
      opened=stack.enter_context(patch.object(ROOT.os, 'open', return_value=83, side_effect=open_effect))
      stack.enter_context(patch.object(ROOT.os, 'fstat', return_value=node or self.node()))
      written=stack.enter_context(patch.object(ROOT.os, 'write', side_effect=write_effect, return_value=1))
      closed=stack.enter_context(patch.object(ROOT.os, 'close', side_effect=close_effect))
      stack.enter_context(patch.object(ROOT.time, 'clock_gettime_ns', return_value=123456))
      if action is None: self.assertIsNone(ROOT.diagnostic(stage, error))
      else: action()
      return opened, written, closed

  def test_only_exact_native_root_pid1_child_run_can_open_kmsg(self):
    cases=[dict(getpid=1), dict(getpid=0), dict(getppid=2), dict(getuid=1001),
      dict(geteuid=1001), dict(getgid=1001), dict(getegid=1001),
      dict(uname=SimpleNamespace(machine='x86_64', release='7.1.0-shield-bringup')),
      dict(uname=SimpleNamespace(machine='aarch64', release='4.9.141'))]
    for case in cases:
      with self.subTest(case=case):
        opened, written, closed=self.capture(overrides=case)
        opened.assert_not_called();written.assert_not_called();closed.assert_not_called()
    for argv in [['native-root-control.py'], ['native-root-control.py', '--run', 'extra']]:
      opened, written, closed=self.capture(argv=argv)
      opened.assert_not_called();written.assert_not_called()

  def test_exact_device_flags_partial_write_no_retry_and_private_text_excluded(self):
    opened, written, closed=self.capture(error=ValueError('PRIVATE_KEY_VALUE'))
    opened.assert_called_once_with('/dev/kmsg',os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC|os.O_NOFOLLOW)
    written.assert_called_once_with(83,b'<3>shield-root-control stage=root-effective-units boottime_ns=123456 error=ValueError\n')
    closed.assert_called_once_with(83)
    self.assertNotIn(b'PRIVATE',written.call_args.args[1])

  def test_non_device_wrong_owner_permissions_or_device_number_refused(self):
    for node in [self.node(st_mode=stat.S_IFREG|0o600), self.node(st_uid=1001),
      self.node(st_gid=1001),self.node(st_mode=stat.S_IFCHR|0o622),self.node(st_rdev=os.makedev(1,3))]:
      with self.subTest(node=node):
        opened, written, closed=self.capture(node=node)
        written.assert_not_called();closed.assert_called_once_with(83)

  def test_malformed_stage_or_log_failure_cannot_change_control_flow(self):
    for stage in ['', 'bad stage', 'bad\nstage', '\u00e9', 'x'*65, None]:
      opened, written, closed=self.capture(stage=stage)
      opened.assert_not_called();written.assert_not_called()
    opened, written, closed=self.capture(write_effect=BlockingIOError('PRIVATE'))
    written.assert_called_once();closed.assert_called_once_with(83)
    self.capture(close_effect=ValueError('PRIVATE'))
    opened,written,closed=self.capture(open_effect=PermissionError('PRIVATE'))
    opened.assert_called_once();written.assert_not_called();closed.assert_not_called()

  def test_tracebacks_whitelist_public_sites_and_limit_traversal_without_private_values(self):
    frames=[('/PRIVATE/native-root-control.py','PRIVATE_FUNCTION',51),
      ('/PRIVATE/native_unit_policy.py','PRIVATE_FUNCTION',77),
      ('/PRIVATE/usb_root_profile.py','require',19)]+[('/PRIVATE/secret.py','PRIVATE',9)]*5
    frames += [('/PRIVATE/native_boot_context.py','directory',159)]
    error=NativeDiagnosticBoundaryTests.traceback_error(self,frames)
    _,written,closed=self.capture(error=error)
    raw=b''.join(call.args[1] for call in written.call_args_list)
    self.assertIn(b'file=native-root-control.py line=51',raw)
    self.assertIn(b'file=native_unit_policy.py line=77',raw)
    self.assertNotIn(b'PRIVATE',raw);self.assertNotIn(b'require',raw)
    self.assertNotIn(b'file=native_boot_context.py',raw)
    self.assertTrue(all(len(call.args[1])<=240 for call in written.call_args_list))
    closed.assert_called_once_with(83)

  def test_target_import_failure_is_visible_and_original_exception_preserved(self):
    failure=ImportError('PRIVATE_KEY_VALUE')
    original=builtins.__import__
    def importing(name,*args,**kwargs):
      if name=='guardian_client': raise failure
      return original(name,*args,**kwargs)
    def action():
      with patch.object(builtins,'__import__',side_effect=importing):
        with self.assertRaises(ImportError) as observed:
          module('diagnostic_root_import_failure','native-root-control.py')
      self.assertIs(observed.exception,failure)
    _,written,_=self.capture(action=action)
    raw=b''.join(call.args[1] for call in written.call_args_list)
    self.assertIn(b'stage=root-imports',raw);self.assertIn(b'error=ImportError',raw)
    self.assertNotIn(b'PRIVATE',raw)

  def test_entrypoint_logs_without_masking_existing_exit_or_uncaught_failure(self):
    source=ast.parse((TOOLS/'native-root-control.py').read_text())
    entry=next(n for n in source.body if isinstance(n,ast.If) and isinstance(n.test,ast.Compare)
      and isinstance(n.test.left,ast.Name) and n.test.left.id=='__name__')
    code=compile(ast.Module(body=[entry],type_ignores=[]),'native-root-control.py','exec')
    failures=[ValueError('PRIVATE'),OSError('PRIVATE'),KeyError('PRIVATE'),
      subprocess.TimeoutExpired(['PRIVATE'],1),SystemExit(71),KeyboardInterrupt()]
    for failure in failures:
      diagnostic=Mock();scope=dict(ROOT.__dict__,__name__='__main__',
        main=Mock(side_effect=failure),diagnostic=diagnostic,DIAGNOSTIC_STAGE='root-effective-units')
      if isinstance(failure,(OSError,ValueError,KeyError)):
        with self.assertRaises(SystemExit) as observed:exec(code,scope)
        self.assertEqual(observed.exception.code,65)
      else:
        with self.assertRaises(type(failure)) as observed:exec(code,scope)
        self.assertIs(observed.exception,failure)
      diagnostic.assert_called_once_with('root-effective-units',failure)

  def test_systemd_log_controls_are_unique_phase_bound_and_watchdog_bounds_unchanged(self):
    logging={'ignore_loglevel','systemd.log_target=kmsg','systemd.log_level=info',
      'systemd.journald.forward_to_kmsg=1','systemd.journald.max_level_kmsg=info'}
    for phase in ['packages','layer','systemd']:
      tokens=CAPSULE.command_line(phase,'a'*64,'b'*64).decode('ascii').split()
      self.assertEqual(logging.intersection(tokens),logging if phase=='systemd' else set())
      self.assertTrue(all(tokens.count(token)==1 for token in logging.intersection(tokens)))
      self.assertEqual(tokens.count('systemd.unit=shield-qualification.target'),int(phase=='systemd'))
      self.assertEqual([token for token in tokens if token.startswith('ignore_loglevel')],
        ['ignore_loglevel'] if phase=='systemd' else [])
      for token in ['watchdog.open_timeout=240','watchdog.stop_on_reboot=0','pstore.compress=none']:
        self.assertEqual(tokens.count(token),1)



  def postimage_failure(self, failure=None):
    # Execute the real systemd verification path with only OS/device boundaries mocked.
    supervisor=BOOT.Supervisor.__new__(BOOT.Supervisor)
    supervisor.bundle=SimpleNamespace(input=Mock(return_value=(Path('/unused-layer'),None)),
      profile={'filesystem':{'subvolumes':{'root':'candidate-root','home':'candidate-home'}}})
    for name in ['helper','transport','storage','verify_payload','stage_policy','root_source_inventory','wait','check','guard_preopen']:
      setattr(supervisor,name,Mock())
    supervisor.mounts=SimpleNamespace(readonly_top=Mock(),candidate=Mock(),check=Mock())
    supervisor.children=SimpleNamespace(require_handoff=Mock())
    supervisor.link=SimpleNamespace(evidence=Mock())
    supervisor.events=SimpleNamespace(unregister=Mock())
    supervisor.device=SimpleNamespace(close=Mock());supervisor.tty=62
    default={'id':256,'top_level':5,'path':'original-root'}
    supervisor.original_default=Mock(return_value=default)
    maintenance={'original_subvolumes':{'root':'original-root'},'base_account_preimages':{},'candidate_id':'c'*64}
    plan=SimpleNamespace(writer=SimpleNamespace(layer=object()),original_default=default,
      maintenance_data=lambda:maintenance,manifest_data=lambda:{})
    journals=[b'original-A-journal',b'completed-B-journal']
    predecessors=[{'boot_id':str(i),'session_id':str(i),
      'journal_sha256':BOOT.hashlib.sha256(raw).hexdigest()} for i,raw in enumerate(journals)]
    content=SimpleNamespace(manifest={'entries':{'etc/a':{'identity':1},'etc/b':{'identity':2},'etc/c':{'identity':3},'etc/machine-id':{'identity':dict(BOOT.MACHINE_ID_BASELINE)}}})
    roots=SimpleNamespace(observe=Mock(side_effect=[1,99 if failure is None else failure,3]),close=Mock())
    with ExitStack() as stack:
      diagnostic=stack.enter_context(patch.object(BOOT,'diagnostic'))
      stack.enter_context(patch.object(BOOT,'predecessor',side_effect=predecessors))
      stack.enter_context(patch.object(BOOT,'read_layer',return_value=content))
      stack.enter_context(patch.object(BOOT,'base_unchanged'))
      stack.enter_context(patch.object(BOOT,'account_preimages'))
      stack.enter_context(patch.object(BOOT,'owned_bytes',side_effect=journals))
      factory=stack.enter_context(patch.object(BOOT,'Roots',return_value=roots))
      opened=stack.enter_context(patch.object(BOOT.os,'open',side_effect=[60,61]))
      closed=stack.enter_context(patch.object(BOOT.os,'close'))
      # If the verification barrier regresses, successors remain harmless and make the test fail.
      stack.enter_context(patch.object(BOOT.Path,'exists',return_value=False))
      stack.enter_context(patch.object(BOOT.Path,'is_symlink',return_value=False))
      stack.enter_context(patch.object(BOOT.signal,'set_wakeup_fd'))
      stack.enter_context(patch.object(BOOT,'close_from'))
      execute=stack.enter_context(patch.object(BOOT.os,'execve',side_effect=AssertionError('NO_TEST_EXEC')))
      with self.assertRaises(ValueError if failure is None else type(failure)) as observed:
        supervisor.systemd(plan)
      actual=observed.exception
      if failure is not None:self.assertIs(actual,failure)
      else:self.assertEqual(str(actual),'Full prepared layer postimage differs')
      self.assertEqual([call.args for call in roots.observe.call_args_list],[('etc/a',),('etc/b',)])
      self.assertIn(unittest.mock.call('layer-postimage-1',actual),diagnostic.call_args_list)
      roots.close.assert_called_once_with()
      self.assertEqual([call.args for call in closed.call_args_list],[(60,),(61,)])
      self.assertEqual(len(opened.call_args_list),2)
      for call in opened.call_args_list:
        self.assertEqual(call.args[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
      factory.assert_called_once_with(60,61,supervisor.guard_preopen)
      supervisor.mounts.candidate.assert_not_called();supervisor.stage_policy.assert_not_called()
      supervisor.link.evidence.assert_not_called();execute.assert_not_called()

  def test_real_systemd_postimage_mismatch_logs_stable_ordinal_and_blocks_handoff(self):
    self.postimage_failure()

  def test_real_systemd_postimage_io_failure_reraises_original_and_closes_descriptors(self):
    self.postimage_failure(OSError('PRIVATE_FILE_VALUE'))


@unittest.skipUnless(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
                     'Real owned-directory admission fixtures require root')
class NativeMachineIdLifecycleTests(unittest.TestCase):
  VALUE = b'0123456789abcdef0123456789abcdef\n'

  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.base = Path(self.temporary.name)
    self.root, self.home = self.base / 'candidate-root', self.base / 'candidate-home'
    self.root.mkdir(); self.home.mkdir(); (self.root / 'etc').mkdir()
    self.leaf = self.root / 'etc/machine-id'
    self.make(self.VALUE)
    descriptors = [os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                   for path in (self.root, self.home)]
    self.guard = Mock()
    try: self.roots = BOOT.Roots(*descriptors, self.guard)
    finally:
      for fd in descriptors: os.close(fd)

  def tearDown(self):
    self.roots.close()
    self.temporary.cleanup()

  def make(self, raw, mode=0o444):
    if self.leaf.is_dir() and not self.leaf.is_symlink(): self.leaf.rmdir()
    elif self.leaf.exists() or self.leaf.is_symlink(): self.leaf.unlink()
    self.leaf.write_bytes(raw); self.leaf.chmod(mode)

  @contextmanager
  def capture(self, *, open_hook=None, read_hook=None):
    real_open, real_read, real_parent = os.open, os.read, self.roots.parent
    facts = {'parents': [], 'files': [], 'reads': [], 'flags': []}
    def parent(name):
      fd, leaf = real_parent(name); facts['parents'].append(fd); return fd, leaf
    def opened(path, flags, *args, **kwargs):
      if path != 'machine-id': return real_open(path, flags, *args, **kwargs)
      facts['flags'].append(flags)
      fd = (real_open(path, flags, *args, **kwargs) if open_hook is None
            else open_hook(real_open, path, flags, args, kwargs))
      facts['files'].append(fd); return fd
    def read(fd, limit):
      facts['reads'].append((fd, limit))
      return real_read(fd, limit) if read_hook is None else read_hook(real_read, fd, limit)
    with patch.object(self.roots, 'parent', new=parent), \
         patch.object(BOOT.os, 'open', new=opened), patch.object(BOOT.os, 'read', new=read):
      yield facts

  def assert_closed(self, facts):
    for fd in set(facts['parents'] + facts['files']):
      with self.assertRaises(OSError): os.fstat(fd)

  def test_empty_and_canonical_initialized_single_read_owned_fds(self):
    for raw, state in [(b'', 'empty'), (self.VALUE, 'initialized'), (b'f' * 32 + b'\n', 'initialized')]:
      with self.subTest(state=state):
        self.make(raw)
        before = self.leaf.stat()
        with self.capture() as facts:
          self.assertEqual(BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE), state)
        after = self.leaf.stat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        self.assertEqual(tuple(getattr(before, key) for key in fields), tuple(getattr(after, key) for key in fields))
        self.assertEqual(self.leaf.read_bytes(), raw)
        self.assertEqual(facts['reads'], [(facts['files'][0], 34)])
        self.assertEqual(facts['flags'], [os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK])
        self.assert_closed(facts)
    self.assertGreaterEqual(self.guard.call_count, 9)

  def test_noncanonical_sizes_refused_before_leaf_open_or_read(self):
    for raw in [self.VALUE[:-1], b'uninitialized\n', b'X' * 34, b'X' * (1024 * 1024)]:
      with self.subTest(size=len(raw)):
        self.make(raw)
        with self.capture() as facts, self.assertRaises(ValueError):
          BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
        self.assertEqual(facts['files'], []); self.assertEqual(facts['reads'], [])
        self.assert_closed(facts)

  def test_noncanonical_33_byte_contents_refused_without_disclosing_value(self):
    values = [b'0' * 32 + b'\n', b'A' * 32 + b'\n', b'g' * 32 + b'\n',
              b'1' * 32 + b'\x00', b'1' * 31 + b'\n\n', b' ' + b'1' * 31 + b'\n',
              b'PRIVATE' + b'1' * 25 + b'\n']
    for raw in values:
      self.assertEqual(len(raw), 33); self.make(raw)
      with self.capture() as facts, self.assertRaises(ValueError) as error:
        BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
      self.assertEqual(str(error.exception), 'Machine ID persisted form differs')
      self.assertNotIn('PRIVATE', str(error.exception)); self.assert_closed(facts)

  def test_wrong_permissions_and_nonroot_ownership_refused_before_read(self):
    for uid, gid, mode in [(0, 0, 0o644), (0, 0, 0o400), (0, 0, 0o4444),
                           (1, 0, 0o444), (0, 1, 0o444)]:
      self.make(self.VALUE, mode); os.chown(self.leaf, uid, gid); self.leaf.chmod(mode)
      with self.capture() as facts, self.assertRaises(ValueError):
        BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
      self.assertEqual(facts['files'], []); self.assertEqual(facts['reads'], [])
      self.assert_closed(facts)

  def test_symlink_directory_and_fifo_refused_without_leaf_open(self):
    for kind in ('symlink', 'directory', 'fifo'):
      self.make(self.VALUE); self.leaf.unlink()
      if kind == 'symlink': self.leaf.symlink_to(self.base / 'not-followed')
      elif kind == 'directory': self.leaf.mkdir(mode=0o444)
      else: os.mkfifo(self.leaf, 0o444)
      with self.capture() as facts, self.assertRaises(ValueError):
        BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
      self.assertEqual(facts['files'], []); self.assertEqual(facts['reads'], [])
      self.assert_closed(facts)

  def test_shared_inode_refused_before_read(self):
    os.link(self.leaf, self.root / 'shared-id')
    with self.capture() as facts, self.assertRaises(ValueError):
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertEqual(facts['files'], []); self.assertEqual(facts['reads'], [])
    self.assert_closed(facts)

  def test_xattrs_refused_without_read_and_owned_fds_close(self):
    os.setxattr(self.leaf, 'user.fixture', b'PRIVATE_ATTRIBUTE')
    with self.capture() as facts, self.assertRaises(ValueError):
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertEqual(facts['reads'], []); self.assert_closed(facts)

  def test_fifo_substitution_is_nonblocking_and_refused_before_read(self):
    def substitute(real_open, path, flags, args, kwargs):
      self.assertTrue(flags & os.O_NONBLOCK)  # Fail before creating a blocking regression.
      self.leaf.unlink(); os.mkfifo(self.leaf, 0o444)
      return real_open(path, flags, *args, **kwargs)
    with self.capture(open_hook=substitute) as facts, self.assertRaises(ValueError):
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertEqual(len(facts['files']), 1); self.assertEqual(facts['reads'], [])
    self.assert_closed(facts)

  def test_postread_leaf_identity_swap_refused(self):
    def substitute(real_read, fd, limit):
      raw = real_read(fd, limit)
      self.leaf.rename(self.root / 'old-id')
      self.leaf.write_bytes(self.VALUE); self.leaf.chmod(0o444)
      return raw
    with self.capture(read_hook=substitute) as facts, self.assertRaises(ValueError):
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assert_closed(facts)

  def test_postread_content_mutation_refused(self):
    def mutate(real_read, fd, limit):
      raw = real_read(fd, limit)
      self.leaf.write_bytes(b'2' * 32 + b'\n'); self.leaf.chmod(0o444)
      return raw
    with self.capture(read_hook=mutate) as facts, self.assertRaises(ValueError):
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assert_closed(facts)

  def test_short_read_refused_without_retry(self):
    with self.capture(read_hook=lambda real_read, fd, limit: real_read(fd, 1)) as facts, \
         self.assertRaises(ValueError):
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertEqual(len(facts['reads']), 1); self.assert_closed(facts)

  def test_read_error_original_identity_and_fd_cleanup(self):
    failure = OSError('PRIVATE_IO_FAILURE')
    def failed(*args): raise failure
    with self.capture(read_hook=failed) as facts, self.assertRaises(OSError) as error:
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertIs(error.exception, failure); self.assert_closed(facts)

  def test_missing_file_and_xattr_error_close_fds_without_reads(self):
    self.leaf.unlink()
    with self.capture() as facts, self.assertRaises(FileNotFoundError):
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertEqual(facts['files'], []); self.assertEqual(facts['reads'], []); self.assert_closed(facts)
    self.make(self.VALUE)
    failure = OSError('PRIVATE_ATTRIBUTE_FAILURE')
    with self.capture() as facts, patch.object(BOOT.os, 'listxattr', side_effect=failure), \
         self.assertRaises(OSError) as error:
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertIs(error.exception, failure); self.assertEqual(facts['reads'], []); self.assert_closed(facts)

  def test_open_error_preserved_and_parent_closed(self):
    failure = PermissionError('PRIVATE_OPEN_FAILURE')
    def failed(*args): raise failure
    with self.capture(open_hook=failed) as facts, self.assertRaises(PermissionError) as error:
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertIs(error.exception, failure); self.assertEqual(facts['files'], [])
    self.assert_closed(facts)

  def test_guard_failure_preserved_and_all_owned_fds_closed(self):
    failure = ValueError('ORIGINAL_GUARD_REFUSAL')
    self.roots.guard = Mock(side_effect=[None, None, failure])
    with self.capture() as facts, self.assertRaises(ValueError) as error:
      BOOT.machine_id_state(self.roots, BOOT.MACHINE_ID_BASELINE)
    self.assertIs(error.exception, failure); self.assert_closed(facts)

  def test_nonempty_or_changed_prepared_baseline_never_opens_any_path(self):
    values = [dict(BOOT.MACHINE_ID_BASELINE, bytes=33), dict(BOOT.MACHINE_ID_BASELINE, mode=0o644),
              dict(BOOT.MACHINE_ID_BASELINE, bytes=False), dict(BOOT.MACHINE_ID_BASELINE, uid=True),
              dict(BOOT.MACHINE_ID_BASELINE, sha256='f' * 64), None]
    for expected in values:
      with patch.object(self.roots, 'parent') as parent, self.assertRaises(ValueError):
        BOOT.machine_id_state(self.roots, expected)
      parent.assert_not_called()

  def systemd_boundary(self, *, variant='passed', raw=None):
    self.make(self.VALUE if raw is None else raw)
    for leaf, mode in [('fstab', 0o644), ('group', 0o644), ('gshadow', 0o600), ('passwd', 0o644)]:
      path = self.root / 'etc' / leaf; path.write_bytes(b'fixture\n'); path.chmod(mode)
    names = ['etc', 'etc/fstab', 'etc/group', 'etc/gshadow', 'etc/machine-id', 'etc/passwd']
    entries = {name: {'identity': self.roots.observe(name)} for name in names}
    entries['etc/machine-id']['identity'] = dict(BOOT.MACHINE_ID_BASELINE)
    user_home = self.home / 'shieldqual'
    user_home.mkdir(exist_ok=True); user_home.chmod(0o700); os.chown(user_home, 1001, 1001)
    entries['home/shieldqual'] = {'identity': self.roots.observe('home/shieldqual')}
    if variant == 'later-mismatch': entries['etc/passwd']['identity']['sha256'] = 'f' * 64
    if variant == 'missing-entry': del entries['etc/machine-id']
    if variant == 'bad-machine-metadata': self.leaf.chmod(0o644)
    supervisor = BOOT.Supervisor.__new__(BOOT.Supervisor)
    supervisor.bundle = SimpleNamespace(phase='systemd', input=Mock(return_value=(Path('/unused-layer'), None)),
      profile={'filesystem': {'subvolumes': {'root': 'candidate-root', 'home': 'candidate-home'}}})
    for name in ['helper', 'transport', 'storage', 'verify_payload', 'stage_policy', 'root_source_inventory',
                 'wait', 'check', 'guard_preopen']:
      setattr(supervisor, name, Mock())
    supervisor.mounts = SimpleNamespace(readonly_top=Mock(), candidate=Mock(), check=Mock())
    supervisor.children = SimpleNamespace(require_handoff=Mock())
    supervisor.link = SimpleNamespace(evidence=Mock())
    default = {'id': 256, 'top_level': 5, 'path': 'original-root'}
    supervisor.original_default = Mock(side_effect=[default, dict(default, id=999)] if variant == 'default' else None,
      return_value=default)
    maintenance = {'original_subvolumes': {'root': 'original-root'}, 'base_account_preimages': {}, 'candidate_id': 'c' * 64}
    plan = SimpleNamespace(writer=SimpleNamespace(layer=object()), original_default=default,
      maintenance_data=lambda: maintenance, manifest_data=lambda: {})
    journals = [b'original-A-journal', b'completed-B-journal']
    predecessors = [{'boot_id': str(i), 'session_id': str(i),
      'journal_sha256': BOOT.hashlib.sha256(value).hexdigest()} for i, value in enumerate(journals)]
    if variant == 'journal': predecessors[1]['journal_sha256'] = 'f' * 64
    stop = RuntimeError('STOP_AFTER_ADMISSION_NO_TEST_MOUNT')
    supervisor.stage_policy.side_effect = stop
    if variant == 'payload': supervisor.verify_payload.side_effect = stop
    original_roots, original_open = BOOT.Roots, os.open
    actual_roots, directories = [], []
    def factory(*args):
      value = original_roots(*args); actual_roots.append(value); return value
    def opened(path, flags, *args, **kwargs):
      fd = original_open(path, flags, *args, **kwargs)
      if isinstance(path, Path) and path in (self.root, self.home): directories.append(fd)
      return fd
    with ExitStack() as stack:
      stack.enter_context(patch.object(BOOT, 'TOP', self.base))
      stack.enter_context(patch.object(BOOT, 'predecessor', side_effect=predecessors))
      stack.enter_context(patch.object(BOOT, 'read_layer', return_value=SimpleNamespace(manifest={'entries': entries})))
      stack.enter_context(patch.object(BOOT, 'base_unchanged'))
      stack.enter_context(patch.object(BOOT, 'account_preimages'))
      stack.enter_context(patch.object(BOOT, 'owned_bytes', side_effect=journals))
      stack.enter_context(patch.object(BOOT, 'Roots', new=factory))
      stack.enter_context(patch.object(BOOT.os, 'open', new=opened))
      diagnostic = stack.enter_context(patch.object(BOOT, 'diagnostic'))
      reader = stack.enter_context(patch.object(BOOT, 'machine_id_state', wraps=BOOT.machine_id_state))
      execute = stack.enter_context(patch.object(BOOT.os, 'execve', side_effect=AssertionError('NO_TEST_EXEC')))
      with self.assertRaises((ValueError, RuntimeError)) as error:
        supervisor.systemd(plan)
    for value in actual_roots: self.assertEqual(value.fds, {})
    for fd in directories:
      with self.assertRaises(OSError): os.fstat(fd)
    execute.assert_not_called(); supervisor.link.evidence.assert_not_called()
    return supervisor, error.exception, stop, diagnostic, reader, actual_roots

  def test_real_systemd_initialized_and_empty_cross_only_readonly_admission(self):
    for raw, state in [(self.VALUE, 'initialized'), (b'', 'empty')]:
      supervisor, error, stop, diagnostic, reader, roots = self.systemd_boundary(raw=raw)
      self.assertIs(error, stop); reader.assert_called_once(); self.assertEqual(len(roots), 1)
      supervisor.mounts.candidate.assert_called_once_with(95 * BOOT.SECOND)
      supervisor.stage_policy.assert_called_once_with()
      self.assertIn(unittest.mock.call('machine-id-' + state), diagnostic.call_args_list)
      self.assertNotIn(self.VALUE.decode().strip(), repr(diagnostic.call_args_list))

  def test_real_systemd_later_postimage_still_refuses_at_original_ordinal(self):
    supervisor, error, stop, diagnostic, reader, roots = self.systemd_boundary(variant='later-mismatch')
    self.assertEqual(str(error), 'Immutable prepared layer postimage differs'); reader.assert_called_once()
    self.assertIn(unittest.mock.call('layer-postimage-5', error), diagnostic.call_args_list)
    supervisor.mounts.candidate.assert_not_called(); supervisor.stage_policy.assert_not_called()

  def test_real_systemd_invalid_machine_metadata_refuses_before_handoff(self):
    supervisor, error, stop, diagnostic, reader, roots = self.systemd_boundary(variant='bad-machine-metadata')
    self.assertEqual(str(error), 'Machine ID node metadata differs'); reader.assert_called_once()
    self.assertIn(unittest.mock.call('layer-postimage-4', error), diagnostic.call_args_list)
    supervisor.mounts.candidate.assert_not_called(); supervisor.stage_policy.assert_not_called()

  def test_real_systemd_missing_machine_entry_never_weakens_layer_contract(self):
    supervisor, error, stop, diagnostic, reader, roots = self.systemd_boundary(variant='missing-entry')
    self.assertEqual(str(error), 'Prepared machine ID or user home entry missing'); reader.assert_not_called()
    supervisor.mounts.candidate.assert_not_called(); supervisor.stage_policy.assert_not_called()

  def test_real_systemd_default_still_checked_after_runtime_state_admission(self):
    supervisor, error, stop, diagnostic, reader, roots = self.systemd_boundary(variant='default')
    self.assertEqual(str(error), 'Default changed during read-only verification'); reader.assert_called_once()
    supervisor.mounts.candidate.assert_not_called(); supervisor.stage_policy.assert_not_called()

  def test_real_systemd_journals_and_payload_refuse_before_runtime_state_read(self):
    for variant in ('journal', 'payload'):
      supervisor, error, stop, diagnostic, reader, roots = self.systemd_boundary(variant=variant)
      if variant == 'journal': self.assertEqual(str(error), 'Physical phase journal differs')
      else: self.assertIs(error, stop)
      reader.assert_not_called(); self.assertEqual(roots, [])
      supervisor.mounts.candidate.assert_not_called(); supervisor.stage_policy.assert_not_called()



class NativeMutableHomeTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    base = Path(self.temporary.name)
    root, home = base / 'root', base / 'home'
    root.mkdir(); home.mkdir(); (root / 'etc').mkdir()
    (root / 'etc/machine-id').write_bytes(b'')
    (root / 'etc/machine-id').chmod(0o444)
    self.home = home / 'shieldqual'
    self.home.mkdir(mode=0o700); os.chown(self.home, 1001, 1001)
    self.guard = Mock()
    descriptors = [os.open(path, os.O_RDONLY | os.O_DIRECTORY) for path in (root, home)]
    try: self.roots = BOOT.Roots(*descriptors, self.guard)
    finally:
      for fd in descriptors: os.close(fd)
    self.addCleanup(self.roots.close)
    self.entries = {name: {'identity': self.roots.observe(name)}
      for name in ('etc/machine-id', 'home/shieldqual')}
    self.supervisor = BOOT.Supervisor.__new__(BOOT.Supervisor)
    self.supervisor.bundle = SimpleNamespace(phase='systemd')

  def verify(self):
    with patch.object(BOOT, 'diagnostic'):
      self.supervisor.verify_layer_postimages(SimpleNamespace(manifest={'entries': self.entries}), self.roots)

  def test_changed_preferences_and_unsafe_descendants_are_never_traversed(self):
    settings = self.home / 'settings.json'; settings.write_bytes(b'original')
    self.entries['home/shieldqual/settings.json'] = {'identity': self.roots.observe('home/shieldqual/settings.json')}
    settings.write_bytes(b'changed by desktop')
    (self.home / 'external').symlink_to('/etc/shadow')
    os.mkfifo(self.home / 'pipe')
    original = self.roots.parent
    def parent(name):
      self.assertNotEqual(name, 'home/shieldqual/settings.json')
      self.assertFalse(name.startswith('home/shieldqual/'))
      return original(name)
    with patch.object(self.roots, 'parent', side_effect=parent): self.verify()
    self.assertEqual(settings.read_bytes(), b'changed by desktop')
    self.assertTrue((self.home / 'external').is_symlink())
    self.assertGreaterEqual(self.guard.call_count, 2)

  def test_home_prefix_neighbor_remains_exact(self):
    neighbor = self.home.parent / 'shieldqual2'; neighbor.mkdir()
    item = neighbor / 'data'; item.write_bytes(b'original')
    # The existing fixed home namespace rejects this path before observation.
    with self.assertRaisesRegex(ValueError, 'Preexisting owner home is excluded'):
      self.roots.observe('home/shieldqual2/data')
    self.entries['home/shieldqual2/data'] = {'identity': {'type': 'file'}}
    item.write_bytes(b'changed')
    with self.assertRaisesRegex(ValueError, 'Preexisting owner home is excluded'): self.verify()

  def test_immutable_root_mutation_still_refuses(self):
    leaf = Path(os.readlink('/proc/self/fd/' + str(self.roots.fds['root']))) / 'etc/passwd'
    leaf.write_bytes(b'original')
    self.entries['etc/passwd'] = {'identity': self.roots.observe('etc/passwd')}
    leaf.write_bytes(b'changed')
    with self.assertRaisesRegex(ValueError, 'Immutable prepared'): self.verify()

  def test_world_writable_or_wrong_owner_home_refuses_without_repair(self):
    self.home.chmod(0o777)
    with self.assertRaisesRegex(ValueError, 'Unsafe runtime'): self.verify()
    self.assertEqual(stat.S_IMODE(self.home.stat().st_mode), 0o777)
    self.home.chmod(0o700); os.chown(self.home, 0, 0)
    with self.assertRaisesRegex(ValueError, 'Unsafe runtime'): self.verify()

  def test_top_symlink_refuses_and_preserves_target(self):
    saved = self.home.with_name('saved'); self.home.rename(saved)
    self.home.symlink_to(saved, target_is_directory=True)
    with self.assertRaises(OSError): self.verify()
    self.assertTrue(saved.is_dir()); self.assertTrue(self.home.is_symlink())

  def test_non_C_phase_never_reads_home(self):
    for phase in ('packages', 'layer'):
      self.supervisor.bundle.phase = phase
      with patch.object(self.roots, 'parent') as opened:
        with self.assertRaisesRegex(ValueError, 'systemd C only'): self.verify()
        opened.assert_not_called()


class NativeHomePolicyTests(unittest.TestCase):
  def setUp(self):
    self.policy = module('home_policy_target', 'native_unit_policy.py')

  def row(self, flags=b'rw,nosuid,nodev,relatime', filesystem=b'btrfs'):
    return b'42 1 8:1 /candidate-home /home ' + flags + b' - ' + filesystem + b' /dev/test rw,compress=zstd:1\n'

  def test_actual_mountinfo_home_requires_both_flags_and_execution(self):
    self.assertTrue(self.policy.validate_home_mount(self.row()))
    for raw in (b'', self.row(b'rw,nodev'), self.row(b'rw,nosuid'),
        self.row(b'rw,nosuid,nodev,noexec'), self.row(filesystem=b'ext4'),
        self.row() + self.row(), b'malformed\n', b'x' * (256 * 1024 + 1)):
      with self.subTest(raw=raw[:80]), self.assertRaises(ValueError): self.policy.validate_home_mount(raw)

  def test_home_dropin_binds_exact_profile_without_rewriting_fstab(self):
    profile = policy_profile()
    files = self.policy.files(profile)
    self.assertEqual(files['run/systemd/system/home.mount.d/10-user-data.conf'],
      ('[Mount]\nOptions=rw,noatime,nosuid,nodev,exec,compress=zstd:1,subvol=@shield-' + 'a'*32 + '-home\n').encode())
    self.assertNotIn('etc/fstab', files)
    for field in ('candidate', 'subvolume', 'account'):
      profile = policy_profile()
      if field == 'candidate': profile['filesystem']['candidate_id'] = 'a'*32 + '\n'
      if field == 'subvolume': profile['filesystem']['subvolumes']['home'] += ',suid'
      if field == 'account': profile['account']['uid'] = 0
      with self.subTest(field=field), self.assertRaises(ValueError): self.policy.files(profile)

  def test_actual_mount_syscall_keeps_home_executable_and_restricts_privilege(self):
    import native_mounts as mounts
    for path, expected in [(mounts.TOP, 6), (mounts.NEWROOT / 'home', 6),
                           (mounts.NEWROOT, 0), (mounts.NEWROOT / 'var/log', 0)]:
      domain = mounts.MountDomain.__new__(mounts.MountDomain)
      domain.failed = domain.release_attempted = False
      domain.mounted = {}; domain.attempts = set()
      domain.budget = Mock(); domain.check = Mock(); domain._validate = Mock()
      domain.device = SimpleNamespace(check=Mock(), partition=SimpleNamespace(name='fixture'))
      domain.library = SimpleNamespace(mount=Mock(return_value=0))
      row = {'path': str(path), 'filesystem': 'btrfs', 'root': '/candidate', 'id': 42}
      with patch.object(mounts, 'directory'), patch.object(mounts, 'table', return_value=[row]):
        domain._mount(path, 'candidate', False, 1)
      flags = domain.library.mount.call_args.args[3]
      self.assertEqual(flags & (mounts.MS_NOSUID | mounts.MS_NODEV | mounts.MS_NOEXEC), expected)
      self.assertTrue(flags & mounts.MS_RELATIME)


class StartupObserverPolicyTests(unittest.TestCase):
  """Exercise the generated parser without starting an observer or opening kmsg."""
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory(prefix='shield-startup-parser-')
    self.addCleanup(self.temporary.cleanup)
    self.policy = module('startup_policy_target', 'native_unit_policy.py')
    self.script = Path(self.temporary.name) / 'startup.sh'
    self.script.write_bytes(self.policy.files(policy_profile())[self.policy.STARTUP_SCRIPT])
    self.script.chmod(0o644)

  def run_bash(self, data='', *, execute=False, arguments=()):
    argv = ['/usr/bin/bash', '--noprofile', '--norc', '-p']
    if execute:
      argv += [str(self.script), *arguments]
    else:
      argv += ['-c', 'set -euo pipefail; source "$1"; startup_summarize', 'shield-startup-parser-test', str(self.script)]
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
      stderr=subprocess.PIPE, text=True, start_new_session=True,
      env={'PATH': '/usr/bin:/bin', 'HOME': '/', 'LC_ALL': 'C'})
    try:
      stdout, stderr = process.communicate(data, timeout=3)
    except BaseException:
      try: os.killpg(process.pid, signal.SIGKILL)
      except ProcessLookupError: pass
      process.communicate(timeout=3)
      raise
    with self.assertRaises(ProcessLookupError): os.killpg(process.pid, 0)
    self.assertLessEqual(len(stdout), 16 * 1024)
    self.assertEqual(stderr, '')
    return process.returncode, stdout

  def test_real_generated_parser_normalizes_pid_job_and_private_paths(self):
    code, output = self.run_bash('Id=shield-native-control.service\nLoadState=loaded\n'
      'ActiveState=activating\nSubState=start\nResult=success\nMainPID=123456\n'
      'Job=9876 /org/freedesktop/systemd1/job/9876\nExecMainCode=1\nExecMainStatus=65\n'
      'FragmentPath=/run/systemd/system/private-unique-path\n'
      'DropInPaths=/run/systemd/system/private-unique-dropin\n\n')
    self.assertEqual(code, 0)
    self.assertIn('unit=shield-native-control.service load=loaded active=activating sub=start', output)
    self.assertIn('job=pending pid=present exec-code=1 exec-status=65 fragment=ram dropins=other-present', output)
    for private in ['123456', '9876', 'private-unique-path', 'private-unique-dropin']:
      self.assertNotIn(private, output)

  def test_unknown_units_properties_and_non_enum_values_never_export(self):
    secret = 'PRIVATE_CONTEXT_0123456789abcdef0123456789abcdef'
    code, output = self.run_bash('Id=' + secret + '\nCookie=' + secret + '\n\n'
      'Id=local-fs.target\nLoadState=' + secret + '\nActiveState=' + secret + '\n'
      'SubState=' + secret + '\nResult=' + secret + '\nMainPID=' + secret + '\nJob=' + secret + '\n')
    self.assertEqual(code, 0)
    self.assertNotIn(secret, output)
    self.assertIn('probe=unknown-unit', output)
    self.assertIn('load=invalid active=invalid sub=invalid result=invalid job=invalid pid=invalid', output)

  def test_absent_pid_job_and_receiver_dropin_classification(self):
    fixed = '/run/systemd/system/shield-qualification-recovery.service.d/10-native-control.conf'
    cases = [(fixed, 'owned-receiver-present'), (fixed + '.backup', 'other-present'),
      ('/prefix' + fixed, 'other-present'), ('/run/systemd/system/*', 'other-present'),
      ('/other\t' + fixed + ' /tail', 'owned-receiver-present'),
      (' \t ', 'other-present'), ('', 'none')]
    for value, expected in cases:
      code, output = self.run_bash('Id=shield-qualification-recovery.service\nMainPID=0\nJob=0\n'
        'FragmentPath=/etc/systemd/system/shield-qualification-recovery.service\n'
        'DropInPaths=' + value + '\n')
      self.assertEqual(code, 0)
      self.assertIn('job=none pid=absent', output)
      self.assertIn('fragment=etc dropins=' + expected, output)

  def test_duplicate_fields_are_refused_without_their_contents(self):
    code, output = self.run_bash('Id=local-fs.target\nId=PRIVATE_REPLACEMENT\n')
    self.assertEqual(code, 2)
    self.assertEqual(output, 'probe=duplicate-field\n')

  def test_single_line_and_record_count_limits(self):
    code, output = self.run_bash('PRIVATE_OVERSIZE=' + 'Z' * 2048 + '\n')
    self.assertEqual(code, 2)
    self.assertEqual(output, 'probe=line-size-cap\n')
    code, output = self.run_bash('unrecognized=value\n' * 300)
    self.assertEqual(code, 2)
    self.assertEqual(output, 'probe=line-count-cap\n')

  def test_group_count_limit_and_empty_groups(self):
    code, output = self.run_bash('\n\n' + 'Id=local-fs.target\n\n' * 24)
    self.assertEqual(code, 2)
    self.assertEqual(output.count('unit=local-fs.target'), 20)
    self.assertTrue(output.endswith('probe=group-cap\n'))

  def test_no_argument_or_non_pid1_execution_refuses_without_output(self):
    for args in [(), ('45',), ('90',), ('unexpected',)]:
      code, output = self.run_bash(execute=True, arguments=args)
      self.assertEqual(code, 64)
      self.assertEqual(output, '')

  def test_observer_is_sealed_data_and_independent_of_boot_prerequisites(self):
    from native_boot_context import POLICY_PATHS, source_path
    files = self.policy.files(policy_profile())
    self.assertEqual(set(files), POLICY_PATHS)
    for name in files: self.assertEqual(str(source_path(name)), '/' + name)
    service = files['run/systemd/system/shield-native-startup@.service'].decode()
    self.assertIn('DefaultDependencies=no\n', service)
    self.assertIn('TimeoutStartSec=10s\nTimeoutStopSec=3s\nKillMode=control-group\n', service)
    self.assertIn('bash --noprofile --norc -p ', service)
    self.assertNotIn('After=local-fs.target', service)
    self.assertNotIn('Requires=', service)
    for phase in (45, 90):
      timer = files[f'run/systemd/system/shield-native-startup-{phase}.timer'].decode()
      self.assertIn('DefaultDependencies=no\n', timer)
      self.assertIn(f'OnBootSec={phase}s\nAccuracySec=1s\nRandomizedDelaySec=0\n', timer)
      self.assertIn('Conflicts=shutdown.target\nBefore=shutdown.target\n', timer)
      self.assertNotIn('OnUnitActiveSec=', timer)




@unittest.skipUnless(os.geteuid() == 0, 'Actual ownership/chroot regression requires root')
class NativePolicyParentPermissionsTests(unittest.TestCase):
  def fixture(self, refusal=None):
    # No mounts, devices or target commands: an isolated filesystem namespace
    # exercises the actual producer with initial PID1's restrictive umask.
    with tempfile.TemporaryDirectory(prefix='shield-policy-parents-') as temporary:
      root = Path(temporary)
      root.chmod(0o755)
      (root / 'run').mkdir(mode=0o755)
      (root / 'run').chmod(0o755)
      (root / 'run/shield-native').mkdir(mode=0o700)
      if refusal == 'mode':
        (root / 'run/systemd').mkdir(mode=0o700)
      elif refusal == 'symlink':
        (root / 'private').mkdir(mode=0o700)
        (root / 'run/systemd').symlink_to('/private')
      child = os.fork()
      if child == 0:
        try:
          os.chroot(root)
          os.chdir('/')
          os.umask(0o077)
          policy = BOOT.policy_files(policy_profile())
          supervisor = BOOT.Supervisor.__new__(BOOT.Supervisor)
          supervisor.bundle = SimpleNamespace(profile=policy_profile(), configuration={'sources': {'root': {
            name: {'bytes': len(raw), 'sha256': BOOT.hashlib.sha256(raw).hexdigest(),
                   'mode': 0o644} for name, raw in policy.items()}}})
          if refusal is not None:
            try: supervisor.stage_policy()
            except ValueError:
              protected = Path('/private' if refusal == 'symlink' else '/run/systemd')
              if stat.S_IMODE(protected.stat().st_mode) != 0o700: os._exit(75)
              os._exit(0)
            os._exit(76)
          supervisor.stage_policy()
          if any(stat.S_IMODE(Path(name).stat().st_mode) != 0o755
                 for name in BOOT.PUBLIC_POLICY_DIRECTORIES): os._exit(77)
          if stat.S_IMODE(Path('/run/shield-native').stat().st_mode) != 0o700: os._exit(78)
          if any((Path('/') / name).read_bytes() != raw
                 or stat.S_IMODE((Path('/') / name).stat().st_mode) != 0o644
                 for name, raw in policy.items()): os._exit(79)
          journal = Path('/run/systemd/journal')
          journal.mkdir(mode=0o755)
          journal.chmod(0o755)
          with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
            server.bind(str(journal / 'socket'))
            (journal / 'socket').chmod(0o666)
            server.settimeout(0.5)
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
              client.connect(str(journal / 'socket'))
              if client.send(b'policy-journal-access') != 21: os._exit(80)
            if server.recv(64) != b'policy-journal-access': os._exit(81)
          os._exit(0)
        except BaseException:
          os._exit(74)
      status = None
      deadline = time.monotonic() + 4
      try:
        while time.monotonic() < deadline:
          returned, observed = os.waitpid(child, os.WNOHANG)
          if returned == child:
            status = observed
            break
          time.sleep(0.01)
      finally:
        if status is None:
          os.kill(child, signal.SIGKILL)
          os.waitpid(child, 0)
      self.assertIsNotNone(status, 'Policy producer child did not finish')
      self.assertTrue(os.WIFEXITED(status))
      self.assertEqual(os.WEXITSTATUS(status), 0)

  def test_actual_policy_under_private_umask_allows_unprivileged_journal_access(self):
    self.fixture()

  def test_existing_nontraversable_public_parent_is_refused_without_repair(self):
    self.fixture('mode')

  def test_symlink_public_parent_is_refused_without_chmod_target(self):
    self.fixture('symlink')


class NativeCleanupObserverTests(unittest.TestCase):
  def setUp(self):
    import native_unit_policy
    self.policy = native_unit_policy
    self.observer = {'__name__': 'cleanup_observer_fixture'}
    exec(compile(self.policy.CLEANUP_HELPER, '<sealed-cleanup-observer>', 'exec'), self.observer)

  def test_whitelist_redacts_private_state_and_command_values(self):
    state = {'phase': 'cleanup-failed', 'error': 'ValueError',
      'readonly_state_verified': False, 'candidate': 'PRIVATE_CANDIDATE',
      'reason': {'PRIVATE_KEY': 'PRIVATE_SECRET'}}
    result = self.observer['summarize'](state,
      b'umount: /PRIVATE_PATH: target is busy PRIVATE_SERIAL')
    self.assertEqual(result, 'phase=cleanup-failed error=ValueError readonly=no command=busy')
    self.assertNotIn('PRIVATE', result)
    for state in ({'phase': ['PRIVATE'], 'error': {'PRIVATE': 1}},
                  {'phase': 'PRIVATE', 'error': 'PRIVATE'}, ['PRIVATE'], None):
      self.assertNotIn('PRIVATE', self.observer['summarize'](state, b'PRIVATE'))

  def test_command_error_categories_do_not_return_source_text(self):
    for raw, expected in ((b'', 'empty'), (b'NOT MOUNTED', 'not-mounted'),
        (b'Permission denied', 'permission'), (b'Operation not permitted', 'permission'),
        (b'Timed out', 'timeout'), (b'No such file', 'missing'),
        (b'Read-only file system', 'readonly'), (b'PRIVATE UNKNOWN', 'other')):
      with self.subTest(expected=expected):
        self.assertTrue(self.observer['summarize']({}, raw).endswith('command=' + expected))

  @unittest.skipUnless(os.geteuid() == 0, 'owned-file fixture requires root')
  def test_fixed_reader_caps_and_accepts_producer_modes_but_refuses_links_fifo_and_writes(self):
    with tempfile.TemporaryDirectory() as temporary:
      directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
      path = Path(temporary) / 'command.log'
      try:
        self.assertEqual(self.observer['read_file'](directory, 'command.log', 8), (b'', 'absent'))
        path.write_bytes(b'0123456789PRIVATE')
        path.chmod(0o600)
        self.assertEqual(self.observer['read_file'](directory, 'command.log', 8), (b'01234567', 'clipped'))
        # Actual receiver command() uses open('wb') under PID1's default 0022;
        # the separately verified private parent supplies traversal protection.
        path.chmod(0o644)
        self.assertEqual(self.observer['read_file'](directory, 'command.log', 8), (b'01234567', 'clipped'))
        for mode in (0o664, 0o666):
          path.chmod(mode)
          self.assertEqual(self.observer['read_file'](directory, 'command.log', 8), (b'', 'refused'))
        state = Path(temporary) / 'state.json'
        state.write_bytes(b'{}')
        state.chmod(0o644)
        self.assertEqual(self.observer['read_file'](directory, 'state.json', 8), (b'', 'refused'))
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertEqual(self.observer['read_file'](directory, 'command.log', 8), (b'', 'refused'))
        path.unlink()
        path.symlink_to('/dev/null')
        with self.assertRaises(OSError): self.observer['read_file'](directory, 'command.log', 8)
      finally:
        os.close(directory)

  def test_cleanup_observer_is_sealed_and_has_finite_independent_lifetime(self):
    from native_boot_context import POLICY_PATHS, CLEANUP_SCRIPT
    files = self.policy.files(policy_profile())
    self.assertEqual(set(files), POLICY_PATHS)
    self.assertEqual(files[CLEANUP_SCRIPT], self.policy.CLEANUP_HELPER.encode('ascii'))
    service = files['run/systemd/system/shield-native-cleanup-observer.service'].decode()
    self.assertIn('RuntimeMaxSec=25s\nTimeoutStopSec=2s\nKillMode=control-group\n', service)
    self.assertIn('Restart=no\n', service)
    self.assertNotIn('Requires=', service)
    self.assertNotIn('WatchdogSec=', service)
    timer = files['run/systemd/system/shield-native-cleanup-observer.timer'].decode()
    self.assertIn('OnBootSec=539s\n', timer)
    self.assertNotIn('OnUnitActiveSec=', timer)

  def test_non_pid1_child_cannot_open_devices_or_recovery_files(self):
    with patch.object(self.observer['os'], 'getuid', return_value=0), \
         patch.object(self.observer['os'], 'geteuid', return_value=0), \
         patch.object(self.observer['os'], 'getppid', return_value=123), \
         patch.object(self.observer['os'], 'open') as opened:
      self.assertEqual(self.observer['main'](), 64)
      opened.assert_not_called()


if __name__ == '__main__':
  unittest.main()
