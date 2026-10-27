"""Maintenance worker identity, ownership and fixed-command fixtures.

Job and command fixtures use mocked IO; a read-only host procfs fixture checks
owned FD mount IDs. No subprocess, device, mount, package or watchdog operation.
These fixtures do not prove physical Btrfs release or native package success.
"""
from contextlib import ExitStack
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import sys
import tempfile
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
    self.table = self.stack.enter_context(patch.object(worker, 'table', return_value=[self.row]))
    self.directory = self.stack.enter_context(patch.object(worker, 'directory'))
    self.mounted = SimpleNamespace(st_dev=os.makedev(0, 99), st_ino=256,
      st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
    self.path_stat = self.stack.enter_context(patch.object(worker.os, 'stat', return_value=self.mounted))
    self.stack.enter_context(patch.object(worker.os, 'fstat', return_value=self.mounted))
    self.opened = self.stack.enter_context(patch.object(worker.os, 'open', return_value=71))
    self.closed = self.stack.enter_context(patch.object(worker.os, 'close'))
    self.mount_id = self.stack.enter_context(patch.object(worker, 'fd_mount_id', return_value=45))
    self.stack.enter_context(patch.object(worker.Path, 'lstat', return_value=SimpleNamespace(
      st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(8, 1))))
    self.usb = self.stack.enter_context(patch.object(worker, 'usb_ancestor', return_value=('usb', 'xusb')))
    self.identity = self.stack.enter_context(patch.object(worker, 'filesystem_identity'))
    self.node = Path('/sys/devices/tegra-xusb/usb/block/sda/sda1')
    def resolve(path, **_kwargs):
      return self.node if path == Path('/sys/dev/block/8:1') else path
    self.stack.enter_context(patch.object(worker.Path, 'resolve', autospec=True, side_effect=resolve))
    def geometry(path):
      if path.name == 'partition': return worker.USB_STORAGE['partition_index']
      if path.name == 'start': return worker.USB_STORAGE['partition_start_bytes'] // 512
      return worker.USB_STORAGE['partition_bytes' if path.parent == self.node else 'disk_bytes'] // 512
    self.stack.enter_context(patch.object(worker, 'number', side_effect=geometry))

  def test_distinct_btrfs_root_stat_and_superblock_devices_accept_matching_owned_mount_id(self):
    worker.top_identity(self.value, job(self.value))
    self.assertNotEqual(self.row['dev'], f'{os.major(self.mounted.st_dev)}:{os.minor(self.mounted.st_dev)}')
    self.directory.assert_called_once_with(worker.TOP)
    self.opened.assert_called_once_with(worker.TOP, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    self.mount_id.assert_called_once_with(71)
    self.closed.assert_called_once_with(71)
    self.usb.assert_called_once_with(self.node, self.value.profile['filesystem']['usb'])
    self.identity.assert_called_once_with(worker.TOP, self.value.profile['filesystem']['uuid'])
    self.assertEqual(self.table.call_count, 2)

  def test_wrong_owned_fd_mount_id_rejected_before_usb_admission(self):
    self.mount_id.return_value = 46
    with self.assertRaises(ValueError): worker.top_identity(self.value, job(self.value))
    self.usb.assert_not_called(); self.identity.assert_not_called()
    self.closed.assert_called_once_with(71)

  def test_job_mount_id_mismatch_is_rejected_before_open(self):
    self.row['id'] = 46
    with self.assertRaises(ValueError): worker.top_identity(self.value, job(self.value))
    self.opened.assert_not_called(); self.usb.assert_not_called(); self.identity.assert_not_called()

  def test_replaced_path_inode_rejected_before_usb_admission(self):
    self.path_stat.return_value = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755,
      st_dev=self.mounted.st_dev, st_ino=self.mounted.st_ino + 1)
    with self.assertRaises(ValueError): worker.top_identity(self.value, job(self.value))
    self.usb.assert_not_called(); self.identity.assert_not_called(); self.closed.assert_called_once_with(71)

  def test_nondirectory_path_with_same_numeric_identity_is_rejected(self):
    self.path_stat.return_value = SimpleNamespace(st_mode=stat.S_IFLNK | 0o755,
      st_dev=self.mounted.st_dev, st_ino=self.mounted.st_ino)
    with self.assertRaises(ValueError): worker.top_identity(self.value, job(self.value))
    self.usb.assert_not_called(); self.identity.assert_not_called(); self.closed.assert_called_once_with(71)

  def test_same_inode_bind_replacement_with_changed_final_mount_id_is_rejected(self):
    changed = dict(self.row, id=46)
    self.table.side_effect = [[dict(self.row)], [changed]]
    with self.assertRaises(ValueError): worker.top_identity(self.value, job(self.value))
    self.identity.assert_called_once_with(worker.TOP, self.value.profile['filesystem']['uuid'])
    self.assertEqual(self.table.call_count, 2); self.closed.assert_called_once_with(71)

  def test_geometry_rejection_still_closes_held_mount_fd(self):
    with patch.object(worker, 'number', return_value=0), self.assertRaises(ValueError):
      worker.top_identity(self.value, job(self.value))
    self.identity.assert_not_called(); self.closed.assert_called_once_with(71)

  def test_filesystem_uuid_failure_remains_fatal_and_closes_held_fd(self):
    self.identity.side_effect = ValueError('Different filesystem UUID')
    with self.assertRaises(ValueError): worker.top_identity(self.value, job(self.value))
    self.closed.assert_called_once_with(71); self.assertEqual(self.table.call_count, 1)


class KernelFdMountIdentityTests(unittest.TestCase):
  def capture(self, raw, *, info=None, magic=0x9fa0):
    metadata = info or SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0)
    with patch.object(worker.os, 'open', return_value=72) as opened, \
         patch.object(worker.os, 'fstat', return_value=metadata), \
         patch.object(worker, 'filesystem_magic', return_value=magic), \
         patch.object(worker.os, 'read', return_value=raw) as read, \
         patch.object(worker.os, 'close') as closed:
      try: value = worker.fd_mount_id(71)
      except BaseException:
        self.assertLessEqual(read.call_count, 1); closed.assert_called_once_with(72)
        raise
      opened.assert_called_once_with('/proc/self/fdinfo/71', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
      read.assert_called_once_with(72, 4097); closed.assert_called_once_with(72)
      return value

  @unittest.skipUnless(os.geteuid() == 0, 'Actual root-owned procfs FD fixture requires root')
  def test_real_owned_directory_fd_uses_actual_kernel_mount_table_identifier(self):
    with tempfile.TemporaryDirectory(prefix='shield-owned-fd-') as directory:
      fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
      try:
        candidates = [row for row in worker.table() if Path(directory).is_relative_to(Path(row['path']))]
        row = max(candidates, key=lambda item: len(item['path']))
        self.assertEqual(worker.fd_mount_id(fd), row['id'])
      finally: os.close(fd)

  def test_exact_single_positive_canonical_id_including_maximum(self):
    for value in [1, 45, 0x7fffffff]:
      raw = b'pos:\t0\nflags:\t02300000\nmnt_id:\t' + str(value).encode('ascii') + b'\nino:\t256\n'
      self.assertEqual(self.capture(raw), value)

  def test_missing_duplicate_noncanonical_truncated_or_oversized_metadata_refused(self):
    cases = [b'', b'pos:\t0\n', b'mnt_id:\t45', b'mnt_id:\t0\n', b'mnt_id:\t-1\n',
      b'mnt_id:\t+45\n', b'mnt_id:\t045\n', b'mnt_id:\t2147483648\n', b'mnt_id:\t99999999999\n',
      b'mnt_id: 45\n', b'mnt_id:\t45 \n', b'mnt_id:\t45\r\n', b'mnt_id:\t45\0\n',
      b'mnt_id:\t45\nprivate:\xff\n', b'mnt_id:\t45\nmnt_id:\t45\n',
      b'mnt_id:\t45\n' + b'x' * 4096 + b'\n']
    for raw in cases:
      with self.subTest(raw=raw[:60]), self.assertRaises(ValueError): self.capture(raw)

  def test_kernel_metadata_must_be_procfs_regular_root_owned_and_nonwritable(self):
    for changes in [dict(st_mode=stat.S_IFDIR | 0o444), dict(st_uid=1), dict(st_gid=1),
                    dict(st_mode=stat.S_IFREG | 0o464), dict(st_mode=stat.S_IFREG | 0o446)]:
      info = dict(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0); info.update(changes)
      with self.assertRaises(ValueError): self.capture(b'mnt_id:\t45\n', info=SimpleNamespace(**info))
    with self.assertRaises(ValueError): self.capture(b'mnt_id:\t45\n', magic=0xef53)

  def test_invalid_descriptor_refused_before_metadata_open(self):
    for descriptor in [-1, True, None, '71', 0x80000000]:
      with patch.object(worker.os, 'open') as opened, self.assertRaises(ValueError):
        worker.fd_mount_id(descriptor)
      opened.assert_not_called()

  def test_metadata_read_failure_closes_without_retry(self):
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_gid=0)
    with patch.object(worker.os, 'open', return_value=72), patch.object(worker.os, 'fstat', return_value=info), \
         patch.object(worker, 'filesystem_magic', return_value=0x9fa0), \
         patch.object(worker.os, 'read', side_effect=OSError(5, 'read refused')) as read, \
         patch.object(worker.os, 'close') as closed, self.assertRaises(OSError):
      worker.fd_mount_id(71)
    read.assert_called_once_with(72, 4097); closed.assert_called_once_with(72)

  def test_metadata_open_error_does_not_close_an_unowned_descriptor(self):
    with patch.object(worker.os, 'open', side_effect=OSError(40, 'nofollow refused')), \
         patch.object(worker.os, 'close') as closed, self.assertRaises(OSError):
      worker.fd_mount_id(71)
    closed.assert_not_called()


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
