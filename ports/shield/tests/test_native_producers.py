"""Focused host fixtures; no device, VM, compiler or target execution."""
import ctypes
import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import sys
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))


def load(name):
  spec = importlib.util.spec_from_file_location(name.replace('-', '_'), TOOLS / (name + '.py'))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


bootstrap = load('prepare-native-bootstrap')
runtime = load('prepare-native-runtime')
preimages = load('prepare-native-preimages')
capsule = runtime.helpers()


class LegacyRecoveryMemoryTextTests(unittest.TestCase):
  def parse(self, text):
    from native_phase_coordinator import legacy_available_bytes
    return legacy_available_bytes(text)

  def test_actual_recovery_CRLF_and_kernel_LF_report_available_memory(self):
    for ending in ['\r\n', '\n']:
      text = ending.join(['MemTotal:       3145728 kB',
        'MemAvailable:    2735272 kB', 'Buffers:           4096 kB', ''])
      self.assertEqual(self.parse(text), 2735272 * 1024)

  def test_duplicate_missing_malformed_or_non_ascii_memory_is_refused(self):
    for text in ['', 'MemAvailable: -1 kB', 'MemAvailable: 1 MB',
                 'MemAvailable:\n123 kB', 'MemAvailable: 1 kB injected',
                 'MemAvailable: 1 kB\r\nMemAvailable: 2 kB\r\n',
                 'MemAvailable: 1 kB\nMemAvailable: malformed\n',
                 'MemAvailable:\u00a0123 kB', None]:
      with self.subTest(text=text), self.assertRaises(ValueError): self.parse(text)

  def test_zero_remains_zero_and_overflow_is_not_available_memory(self):
    self.assertEqual(self.parse('MemAvailable: 0 kB\r\n'), 0)
    with self.assertRaises(ValueError): self.parse('MemAvailable: 18446744073709551615 kB')


class LegacyStagingWriterTests(unittest.TestCase):
  def command(self, name, size, checksum="a" * 64):
    from native_phase_coordinator import legacy_stage_command
    return legacy_stage_command(name, size, checksum)

  def test_exact_count_reader_precedes_exclusive_closed_marker(self):
    command, marker, expected = self.command('kexec', 1520208)
    self.assertIn('umask 077; set -C; /system/bin/toybox head -c 1520208 > /tmp/shield-native/kexec', command)
    self.assertIn(' && test "$(/system/bin/toybox stat -c %s /tmp/shield-native/kexec)" = 1520208 && ', command)
    self.assertTrue(command.endswith(' > ' + marker))
    self.assertEqual(marker, '/tmp/shield-native/kexec.closed')
    self.assertEqual(expected, 'NATIVE_STAGE_CLOSED_V1 1520208 ' + 'a' * 64)
    self.assertNotIn('cat >', command)

  def test_writer_exits_and_closes_file_while_transport_stdin_stays_open(self):
    import native_phase_coordinator as coordinator
    data = bytes(range(256)) * 2
    with tempfile.TemporaryDirectory(prefix='shield-stage-') as directory, \
         patch.object(coordinator, 'RAM', directory):
      command, marker, expected = self.command('kexec', len(data), hashlib.sha256(data).hexdigest())
      command = command.replace('/system/bin/toybox head', '/usr/bin/head').replace(
        '/system/bin/toybox stat', '/usr/bin/stat').replace(
        '/system/bin/toybox sha256sum', '/usr/bin/sha256sum')
      process = subprocess.Popen(['/bin/sh', '-c', command], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      try:
        process.stdin.write(data); process.stdin.flush()
        self.assertEqual(process.wait(timeout=3), 0)
        self.assertFalse(process.stdin.closed)
        identity = (Path(directory) / 'kexec').stat()
        self.assertEqual(Path(marker).read_text(), expected + ' ' + str(identity.st_dev) + ' ' + str(identity.st_ino) + '\n')
        self.assertEqual((Path(directory) / 'kexec').read_bytes(), data)
        self.assertEqual(stat.S_IMODE((Path(directory) / 'kexec').stat().st_mode), 0o600)
      finally:
        process.stdin.close()
        if process.poll() is None: process.kill()
        process.wait(timeout=3)

  def test_short_transport_eof_never_creates_closed_completion_marker(self):
    import native_phase_coordinator as coordinator
    with tempfile.TemporaryDirectory(prefix='shield-stage-') as directory, \
         patch.object(coordinator, 'RAM', directory):
      command, marker, expected = self.command('kexec', 512)
      command = command.replace('/system/bin/toybox head', '/usr/bin/head').replace(
        '/system/bin/toybox stat', '/usr/bin/stat').replace(
        '/system/bin/toybox sha256sum', '/usr/bin/sha256sum')
      result = subprocess.run(['/bin/sh', '-c', command], input=b'short', timeout=3,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      self.assertNotEqual(result.returncode, 0)
      self.assertFalse(Path(marker).exists())
      self.assertEqual((Path(directory) / 'kexec').read_bytes(), b'short')

  def test_only_fixed_artifacts_and_bounded_integer_counts_are_allowed(self):
    for name in ['../kexec', 'kexec;reboot', '/tmp/kexec', 'Image.closed', '', None]:
      with self.subTest(name=name), self.assertRaises(ValueError): self.command(name, 1)
    for count in [0, -1, True, 1.0, '1', 384 * 1024**2 + 1]:
      with self.subTest(count=count), self.assertRaises(ValueError): self.command('Image', count)

  def test_binary_archive_length_is_a_count_not_shell_data(self):
    command, marker, expected = self.command('initramfs.cpio.gz', 246495584)
    self.assertIn('head -c 246495584 > /tmp/shield-native/initramfs.cpio.gz && ', command)
    self.assertEqual(marker, '/tmp/shield-native/initramfs.cpio.gz.closed')
    self.assertEqual(expected, 'NATIVE_STAGE_CLOSED_V1 246495584 ' + 'a' * 64)


class RetainedGeometryTests(unittest.TestCase):
  def profile(self):
    return {'controller': {'platform_node': '700b0600.mmc',
      'compatible': 'nvidia,tegra210-sdhci', 'card_type': 'MMC',
      'USER_parent_sectors': 30777344, 'USER_partition_count': 33,
      'boot_and_RPMB_open_forbidden': True}, 'partition_rows': [
        {'index': n, 'label': 'P' + str(n), 'blocks_1024': 2048,
         'start': None, 'sectors': None, 'start_pinned': False} for n in range(1, 34)]}

  def test_floored_proc_blocks_never_become_exact_sectors(self):
    header = bootstrap.mmc_header(self.profile(), 'a' * 64).decode()
    self.assertEqual(header.count('.sectors = UINT64_MAX'), 33)
    self.assertEqual(header.count('.start = UINT64_MAX'), 33)
    self.assertIn('#define SIR_PARTITIONS 33', header)
    self.assertIn('"' + 'a' * 64 + '"', header)

  def test_independently_pinned_odd_sector_count_is_preserved(self):
    value = self.profile()
    value['partition_rows'][0].update(start=100, start_pinned=True, sectors=4097)
    header = bootstrap.mmc_header(value, 'a' * 64).decode()
    self.assertIn('.start = UINT64_C(100), .sectors = UINT64_C(4097)', header)

  def test_duplicate_label_or_geometry_conflict_is_rejected(self):
    for change in [{'label': 'P2'}, {'start': 100}, {'sectors': 4098},
                   {'start': 30777343, 'start_pinned': True, 'sectors': 4096},
                   {'label': 'P1";bad'}]:
      with self.subTest(change=change):
        value = self.profile(); value['partition_rows'][0].update(change)
        with self.assertRaises(ValueError): bootstrap.mmc_header(value, 'a' * 64)


class RuntimeArchiveTests(unittest.TestCase):
  def archive(self, changes=None):
    items = {name: (stat.S_IFDIR | 0o755, b'') for name in
      ['usr', 'usr/lib', 'usr/lib/shield-maintenance']}
    items['lib'] = (stat.S_IFLNK | 0o777, b'usr/lib')
    for name in ['usb_root_profile.py', 'usb_candidate_transaction.py']:
      items['usr/lib/shield-maintenance/' + name] = (
        stat.S_IFREG | 0o644, (TOOLS / name).read_bytes())
    if changes: changes(items)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
      for name, (mode, raw) in items.items():
        entry = tarfile.TarInfo(name); entry.mode = stat.S_IMODE(mode)
        if stat.S_ISDIR(mode): entry.type = tarfile.DIRTYPE
        elif stat.S_ISLNK(mode):
          entry.type = tarfile.SYMTYPE; entry.linkname = raw.decode()
        else: entry.size = len(raw)
        archive.addfile(entry, io.BytesIO(raw) if entry.isfile() else None)
    receipt = {'paths': len(items), 'regular_bytes': sum(len(data)
      for mode, data in items.values() if stat.S_ISREG(mode))}
    return gzip.compress(stream.getvalue(), mtime=0), receipt

  def test_current_runtime_roundtrips_without_an_init(self):
    raw, receipt = self.archive()
    entries = runtime.base_entries(raw, receipt, capsule)
    result = capsule.component_entries(gzip.compress(runtime.write_newc(entries), mtime=0))
    self.assertEqual(result, entries)
    self.assertNotIn('init', result)

  def test_missing_real_parent_or_alias_escape_is_rejected(self):
    for change in [lambda items: items.pop('usr/lib'),
                   lambda items: items.update(lib=(stat.S_IFLNK | 0o777, b'../../outside')),
                   lambda items: items.update(init=(stat.S_IFREG | 0o700, b'not-an-init')),
                   lambda items: items.update({'usr/lib/bad': (stat.S_IFREG | 0o4755, b'x')})]:
      raw, receipt = self.archive(change)
      with self.assertRaises(ValueError): runtime.base_entries(raw, receipt, capsule)

  def test_sealed_stale_embedded_executor_api_is_not_silently_replaced(self):
    raw, receipt = self.archive(lambda items: items.update({
      'usr/lib/shield-maintenance/usb_root_profile.py': (stat.S_IFREG | 0o644, b'stale API')}))
    entries = runtime.base_entries(raw, receipt, capsule)
    with self.assertRaises(ValueError):
      capsule.component_entries(gzip.compress(runtime.write_newc(entries), mtime=0))


class ReadonlyWitnessDescriptorTests(unittest.TestCase):
  FSID = '11111111-2222-4333-8444-555555555555'

  def admit(self, *, readonly=True, parent=5, directory_id=900, name='@', tree=256,
            fsid=None, inode=256, fs_info_return=0, subvol_info_return=0):
    def ioctl(fd, command, buffer, mutate):
      if command == preimages.FS_INFO:
        buffer[16:32] = uuid.UUID(fsid or self.FSID).bytes
        return fs_info_return
      else:
        self.assertEqual(command, preimages.SUBVOL_INFO)
        struct.pack_into('<Q', buffer, 0, tree)
        buffer[8:8 + len(name)] = name.encode()
        struct.pack_into('<QQ', buffer, 264, parent, directory_id)
        return subvol_info_return

    def fstatfs(fd, buffer):
      ctypes.cast(buffer, ctypes.POINTER(ctypes.c_long))[0] = 0x9123683e
      return 0

    with patch.object(preimages.os, 'fstat', return_value=SimpleNamespace(st_ino=inode)), \
         patch.object(preimages.os, 'fstatvfs', return_value=SimpleNamespace(
           f_flag=preimages.os.ST_RDONLY if readonly else 0)), \
         patch.object(preimages.ctypes, 'CDLL', return_value=SimpleNamespace(fstatfs=fstatfs)), \
         patch.object(preimages.fcntl, 'ioctl', side_effect=ioctl):
      preimages.readonly_btrfs(123, self.FSID, '@', True)

  def test_uapi_parent_offset_uses_parent_id_and_not_directory_inode(self):
    self.admit(parent=5, directory_id=900)
    with self.assertRaises(ValueError): self.admit(parent=900, directory_id=5)

  def test_rw_mount_wrong_original_or_other_filesystem_is_rejected(self):
    for options in [{'readonly': False}, {'tree': 300}, {'name': '@wrong'}, {'inode': 900},
                    {'fsid': 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'}]:
      with self.subTest(options=options):
        with self.assertRaises(ValueError): self.admit(**options)

  def test_positive_ioctl_return_never_admits_an_even_plausible_output_buffer(self):
    for returns in [{'fs_info_return': 1}, {'subvol_info_return': 1}]:
      with self.subTest(returns=returns), self.assertRaisesRegex(ValueError, 'complete success'):
        self.admit(**returns)

  def test_receipt_path_cannot_replace_live_publication(self):
    with self.assertRaises(ValueError):
      preimages.finalize(b'{}', '0' * 64, None, None, Path('/tmp/receipt.json'),
                         'a' * 64, 'b' * 64)


if __name__ == '__main__': unittest.main()
