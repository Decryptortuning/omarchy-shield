"""Source-only worker fixtures pending the combined native208 source gate.

Synthetic job data and mocked command IO only: no subprocess, device, mount,
package or watchdog operation. Fatal command failures model PID1 cancellation;
these fixtures do not prove actual descendant reaping or physical release.
"""
from contextlib import ExitStack
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import sys
import unittest
from unittest.mock import Mock, patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location('native_maintenance_worker', TOOLS / 'maintenance-worker.py')
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)
SECOND = worker.SECOND


def bundle(phase='packages'):
  return SimpleNamespace(epoch='early', phase=phase, boot_id='11111111-2222-4333-8444-555555555555',
    profile={'role': 1, 'candidate': 'a' * 64},
    contexts={'early': SimpleNamespace(config_sha256='b' * 64, session_id='c' * 64)})


def job(value):
  return {'format_version': 1, 'purpose': 'native maintenance worker', 'phase': value.phase,
    'guardian_pid': 20, 'reaper_pid': 21, 'worker_pid': 22, 'candidate': value.profile['candidate'],
    'boot_id': value.boot_id, 'configuration_sha256': 'b' * 64, 'session_id': 'c' * 64,
    'top_mount_id': 45}


class JobBindingTests(unittest.TestCase):
  def test_both_role1_phases_accept_exact_job(self):
    for phase in ['packages', 'layer']:
      value = bundle(phase)
      worker.validate_job(job(value), value, 22, 21)

  def test_role2_or_root_epoch_never_dispatches(self):
    for field, replacement in [('epoch', 'root'), ('phase', 'systemd')]:
      value = bundle(); setattr(value, field, replacement)
      with self.assertRaises(ValueError): worker.validate_job(job(value), value, 22, 21)
    value = bundle(); value.profile['role'] = 2
    with self.assertRaises(ValueError): worker.validate_job(job(value), value, 22, 21)

  def test_wrong_session_capsule_boot_candidate_and_actual_parent_rejected(self):
    value = bundle()
    for field in ['candidate', 'boot_id', 'configuration_sha256', 'session_id']:
      changed = job(value); changed[field] = 'd' * 64
      with self.subTest(field=field), self.assertRaises(ValueError):
        worker.validate_job(changed, value, 22, 21)
    with self.assertRaises(ValueError): worker.validate_job(job(value), value, 22, 30)
    with self.assertRaises(ValueError): worker.validate_job(job(value), value, 30, 21)

  def test_unknown_fields_boolean_pids_pid_alias_and_mount_rejected(self):
    value = bundle()
    for field, replacement in [('extra', True), ('format_version', True), ('guardian_pid', True),
      ('guardian_pid', 1), ('reaper_pid', 20), ('worker_pid', 20), ('top_mount_id', True), ('top_mount_id', 0)]:
      changed = job(value); changed[field] = replacement
      with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
        worker.validate_job(changed, value, 22, 21)


class MountIdentityTests(unittest.TestCase):
  def setUp(self):
    self.stack = ExitStack(); self.addCleanup(self.stack.close)
    self.value = bundle()
    self.value.profile['filesystem'] = {'usb': {'vendor': '0781', 'product': '5591'},
      'uuid': '11111111-2222-4333-8444-555555555555'}
    self.row = {'id': 45, 'filesystem': 'btrfs', 'root': '/', 'path': str(worker.TOP),
      'options': {'rw', 'nosuid', 'nodev'}, 'super_options': {'rw', 'compress=zstd:1'},
      'dev': '0:42', 'source': '/dev/sda1'}
    self.stack.enter_context(patch.object(worker, 'table', return_value=[self.row]))
    self.directory = self.stack.enter_context(patch.object(worker, 'directory'))
    self.stack.enter_context(patch.object(worker.os, 'stat', return_value=SimpleNamespace(st_dev=os.makedev(0, 42))))
    self.stack.enter_context(patch.object(worker.Path, 'lstat', return_value=SimpleNamespace(
      st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(8, 1))))
    self.usb = self.stack.enter_context(patch.object(worker, 'usb_ancestor', return_value=('usb', 'xusb')))
    self.identity = self.stack.enter_context(patch.object(worker, 'filesystem_identity'))
    # Model the resolved sysfs link into devices while preserving source dev_t.
    self.node = Path('/sys/devices/tegra-xusb/usb/block/sda/sda1')
    def resolve(path, **_kwargs):
      return self.node if path == Path('/sys/dev/block/8:1') else path
    self.stack.enter_context(patch.object(worker.Path, 'resolve', autospec=True, side_effect=resolve))
    def geometry(path):
      if path.name == 'partition': return worker.USB_STORAGE['partition_index']
      if path.name == 'start': return worker.USB_STORAGE['partition_start_bytes'] // 512
      return worker.USB_STORAGE['partition_bytes' if path.parent == self.node else 'disk_bytes'] // 512
    self.stack.enter_context(patch.object(worker, 'number', side_effect=geometry))

  def test_anonymous_btrfs_view_and_distinct_physical_source_are_valid(self):
    worker.top_identity(self.value, job(self.value))
    self.directory.assert_called_once_with(worker.TOP)
    self.usb.assert_called_once_with(self.node, self.value.profile['filesystem']['usb'])
    self.identity.assert_called_once_with(worker.TOP, self.value.profile['filesystem']['uuid'])

  def test_wrong_mounted_view_device_is_rejected_before_usb_admission(self):
    self.row['dev'] = '0:43'
    with self.assertRaises(ValueError): worker.top_identity(self.value, job(self.value))
    self.usb.assert_not_called(); self.identity.assert_not_called()


class CommandAuthorityTests(unittest.TestCase):
  def setUp(self):
    self.maintenance = {'original_subvolumes': {'root': '@', 'home': '@home', 'log': '@log'}}
    self.manifest = {'subvolumes': {'root': '@candidate', 'home': '@candidate-home', 'log': '@candidate-log'},
      'packages': {name: {'filename': name + '.pkg.tar.zst'} for name in ['a', 'b', 'c', 'd', 'e', 'f']}}

  def test_layer_has_only_default_read_and_sync(self):
    self.assertEqual(worker.command_set('layer', self.maintenance, self.manifest), frozenset({
      ('btrfs', 'subvolume', 'get-default', str(worker.TOP)), ('btrfs', 'filesystem', 'sync', str(worker.TOP))}))

  def test_six_fixed_absolute_metadata_reads_and_no_arbitrary_shell(self):
    allowed = worker.command_set('packages', self.maintenance, self.manifest)
    metadata = {command for command in allowed if command[0] == '/usr/bin/bsdtar'}
    self.assertEqual(metadata, {('/usr/bin/bsdtar', '-xOf', str(worker.PACKAGES / (name + '.pkg.tar.zst')),
      '.PKGINFO') for name in self.manifest['packages']})
    self.assertFalse(any(command[0] in {'sh', 'bash', 'python', 'sudo'} for command in allowed))
    self.assertNotIn(('umount', '-l', str(worker.TOP)), allowed)
    self.assertNotIn(('btrfs', 'subvolume', 'set-default', '256', str(worker.TOP)), allowed)

  def test_pacman_archives_keep_sealed_order_and_exact_flags(self):
    allowed = worker.command_set('packages', self.maintenance, self.manifest)
    commands = [command for command in allowed if '/usr/bin/pacman' in command and '-U' in command]
    self.assertEqual(len(commands), 1)
    self.assertEqual(commands[0][-6:], tuple(str(worker.PACKAGES / item['filename'])
      for item in self.manifest['packages'].values()))
    self.assertEqual(commands[0][-10:-6], ('-U', '--disable-sandbox', '--noconfirm', '--ask=4'))


class FatalCommand(BaseException): pass


class CommandLifecycleTests(unittest.TestCase):
  def setUp(self):
    self.stack = ExitStack(); self.addCleanup(self.stack.close)
    self.guard = Mock()
    self.arguments = ['btrfs', 'subvolume', 'get-default', str(worker.TOP)]
    self.runner = worker.Execute(frozenset({tuple(self.arguments)}), self.guard)
    self.stream = Mock(); self.stream.fileno.return_value = 71
    self.process = Mock(stdout=self.stream)
    self.process.poll.return_value = 0; self.process.wait.return_value = 0
    self.spawn = self.patch(worker.subprocess, 'Popen', return_value=self.process)
    self.clock = self.patch(worker, 'now', return_value=100 * SECOND)
    self.patch(worker.select, 'poll', return_value=Mock())
    self.patch(worker.time, 'sleep')
    self.patch(worker.os, 'open', return_value=70)
    self.patch(worker.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
      st_nlink=1, st_uid=0, st_gid=0))
    for name in ['ftruncate', 'set_blocking', 'close', 'fsync']: self.patch(worker.os, name)
    self.read = self.patch(worker.os, 'read', side_effect=[b'ID 5 (FS_TREE)\n', b''])
    self.write = self.patch(worker.os, 'write', side_effect=lambda _fd, raw: len(raw))
    self.exit = self.patch(worker.os, '_exit', side_effect=FatalCommand)

  def patch(self, target, name, *args, **kwargs):
    return self.stack.enter_context(patch.object(target, name, *args, **kwargs))

  def fatal(self):
    with self.assertRaises(FatalCommand): self.runner(self.arguments)
    self.exit.assert_called_once_with(75)
    self.assertTrue(self.runner.running)

  def test_success_requires_positive_wait_and_eof_fixed_environment(self):
    self.assertEqual(self.runner(self.arguments), 'ID 5 (FS_TREE)\n')
    self.process.wait.assert_called_once_with(timeout=0)
    self.assertFalse(self.runner.running)
    args, kwargs = self.spawn.call_args
    self.assertEqual(args[0], ['/usr/bin/btrfs', *self.arguments[1:]])
    self.assertEqual(kwargs['env'], worker.ENV)
    self.assertIs(kwargs['shell'], False)
    self.assertIs(kwargs['close_fds'], True)
    self.assertIs(kwargs['start_new_session'], True)
    self.assertEqual(kwargs['stdin'], worker.subprocess.DEVNULL)
    self.assertEqual(kwargs['stderr'], worker.subprocess.STDOUT)
    self.exit.assert_not_called()

  def test_short_known_log_writes_complete_before_return(self):
    self.write.side_effect = lambda _fd, raw: min(2, len(raw))
    self.runner(self.arguments)
    self.assertGreater(self.write.call_count, 1)
    self.process.wait.assert_called_once_with(timeout=0)

  def test_absolute_metadata_program_never_gets_double_prefix(self):
    self.arguments = ['/usr/bin/bsdtar', '-xOf', str(worker.PACKAGES / 'a.pkg.tar.zst'), '.PKGINFO']
    self.runner.allowed = frozenset({tuple(self.arguments)})
    self.runner(self.arguments)
    self.assertEqual(self.spawn.call_args.args[0], self.arguments)

  def test_prespawn_guard_refusal_propagates_without_spawn_or_exit(self):
    self.guard.side_effect = ValueError('no existing reserve')
    with self.assertRaises(ValueError): self.runner(self.arguments)
    self.spawn.assert_not_called(); self.exit.assert_not_called()

  def test_unowned_or_overlapping_command_never_spawns(self):
    with self.assertRaises(ValueError): self.runner(['sh', '-c', 'true'])
    self.runner.running = True
    with self.assertRaises(ValueError): self.runner(self.arguments)
    self.spawn.assert_not_called(); self.exit.assert_not_called()

  def test_nonzero_or_signaled_leader_is_immediate_fatal(self):
    self.process.poll.return_value = -9
    self.fatal()
    self.process.wait.assert_not_called()

  def test_postspawn_guard_failure_never_unwinds_into_core_cleanup(self):
    self.guard.side_effect = [None, ValueError('guardian lost')]
    self.fatal()
    self.process.wait.assert_not_called()

  def test_zero_leader_without_pipe_eof_expires_and_is_not_success(self):
    self.read.side_effect = BlockingIOError
    self.clock.side_effect = [100 * SECOND, 101 * SECOND, 101 * SECOND, 281 * SECOND]
    self.fatal()
    self.process.wait.assert_not_called()

  def test_eof_without_leader_waits_until_actual_positive_exit(self):
    self.read.side_effect = [b'']
    self.process.poll.side_effect = [None, 0]
    self.runner(self.arguments)
    self.assertEqual(self.process.poll.call_count, 2)
    self.process.wait.assert_called_once_with(timeout=0)

  def test_output_cap_is_fatal(self):
    self.patch(worker, 'MAX_OUTPUT', 3)
    self.read.side_effect = [b'four']
    self.fatal()
    self.process.wait.assert_not_called()

  def test_uncertain_log_write_is_fatal(self):
    self.write.side_effect = None; self.write.return_value = 0
    self.fatal()
    self.process.wait.assert_not_called()

  def test_clock_regression_is_fatal(self):
    self.clock.side_effect = [100 * SECOND, 99 * SECOND]
    self.fatal()

  def test_absolute_480_second_cutoff_prevents_spawn(self):
    self.clock.return_value = 480 * SECOND
    with self.assertRaises(ValueError): self.runner(self.arguments)
    self.spawn.assert_not_called(); self.exit.assert_not_called()

  def test_spawn_exception_is_conservative_fatal(self):
    self.spawn.side_effect = OSError('uncertain launch')
    self.fatal()

  def test_missing_positive_wait_is_fatal(self):
    self.process.wait.side_effect = worker.subprocess.TimeoutExpired('fixed', 0)
    self.fatal()

  def test_postwait_guard_loss_does_not_return_success(self):
    self.guard.side_effect = [None, None, ValueError('reserve lost')]
    self.fatal()
    self.process.wait.assert_called_once_with(timeout=0)


if __name__ == '__main__': unittest.main()
