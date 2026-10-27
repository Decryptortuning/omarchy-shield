"""Focused host fixtures; no device, VM, compiler or target execution."""
import base64
import copy
import ctypes
import gzip
import hashlib
import importlib.util
import io
import json
import os
import select
from contextlib import contextmanager
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import sys
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
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
    self.assertIn('umask 077; set -C; /system/bin/toybox head -c 2026944 | /system/bin/toybox base64 -d > /tmp/shield-native/kexec', command)
    self.assertIn(' && test "$(/system/bin/toybox stat -c %s /tmp/shield-native/kexec)" = 1520208 && ', command)
    self.assertIn(' > ' + marker + '.pending && test ! -e ' + marker + ' && test ! -L ' + marker, command)
    self.assertIn('/system/bin/toybox ln ' + marker + '.pending ' + marker + ' && /system/bin/toybox printf', command)
    self.assertTrue(command.endswith("'SHIELD_STAGE_INPUT_CONFIRMED 1520208 " + 'a' * 64 + "'"))
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
        '/system/bin/toybox sha256sum', '/usr/bin/sha256sum').replace(
        '/system/bin/toybox ln', '/usr/bin/ln').replace(
        '/system/bin/toybox base64', '/usr/bin/base64').replace(
        '/system/bin/toybox printf', '/usr/bin/printf')
      process = subprocess.Popen(['/bin/sh', '-c', command], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      try:
        process.stdin.write(base64.b64encode(data)); process.stdin.flush()
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
        '/system/bin/toybox sha256sum', '/usr/bin/sha256sum').replace(
        '/system/bin/toybox ln', '/usr/bin/ln').replace(
        '/system/bin/toybox base64', '/usr/bin/base64').replace(
        '/system/bin/toybox printf', '/usr/bin/printf')
      result = subprocess.run(['/bin/sh', '-c', command], input=base64.b64encode(b'short'), timeout=3,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      self.assertNotEqual(result.returncode, 0)
      self.assertFalse(Path(marker).exists())
      self.assertEqual((Path(directory) / 'kexec').read_bytes(), b'short')


  def test_final_marker_is_absent_during_partial_write_and_complete_before_writer_exit(self):
    import native_phase_coordinator as coordinator
    data = bytes(range(256)) * 2
    with tempfile.TemporaryDirectory(prefix='shield-stage-') as directory, \
         patch.object(coordinator, 'RAM', directory):
      command, marker, expected = self.command('kexec', len(data), hashlib.sha256(data).hexdigest())
      command = command.replace('/system/bin/toybox ', '/usr/bin/')
      ready_read, ready_write = os.pipe()
      resume_read, resume_write = os.pipe()
      process = None
      script = f"""printf() {{
        command printf '%s' "$2"
        command printf P >&{ready_write}
        IFS= read -r resume <&{resume_read} || return 1
        command printf ' %s\\n' "$3"
      }}
      {command}
      status=$?
      command printf L >&{ready_write}
      IFS= read -r finish <&{resume_read}
      exit "$status"
      """
      def event():
        self.assertTrue(select.select([ready_read], [], [], 3)[0], 'Producer event timed out')
        return os.read(ready_read, 1)
      try:
        process = subprocess.Popen(['/bin/bash', '-c', script], stdin=subprocess.PIPE,
          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(ready_write, resume_read))
        os.close(ready_write); ready_write = None
        os.close(resume_read); resume_read = None
        process.stdin.write(base64.b64encode(data)); process.stdin.flush()
        self.assertEqual(event(), b'P')
        self.assertFalse(Path(marker).exists(), 'Final marker exposed before printf completed')
        self.assertTrue(Path(marker + '.pending').read_bytes())
        os.write(resume_write, b'continue\n')
        self.assertEqual(event(), b'L')
        self.assertIsNone(process.poll(), 'Read must precede remote producer exit')
        identity = (Path(directory) / 'kexec').stat()
        self.assertEqual(Path(marker).read_text(),
          expected + ' ' + str(identity.st_dev) + ' ' + str(identity.st_ino) + '\n')
        self.assertEqual(Path(marker).stat().st_ino, Path(marker + '.pending').stat().st_ino)
        self.assertEqual(Path(marker).stat().st_nlink, 2)
        self.assertEqual(identity.st_nlink, 1)
        os.write(resume_write, b'finish\n')
        self.assertEqual(process.wait(timeout=3), 0)
      finally:
        if process is not None:
          if process.poll() is None: process.kill()
          process.wait(timeout=3)
          process.stdin.close()
        for fd in [ready_read, ready_write, resume_read, resume_write]:
          if fd is not None: os.close(fd)

  def test_existing_marker_objects_and_pending_record_are_never_replaced(self):
    import native_phase_coordinator as coordinator
    data = bytes(range(256)) * 2
    for collision in ['final-file', 'final-directory', 'final-dangling-link', 'pending-file']:
      with self.subTest(collision=collision), tempfile.TemporaryDirectory(prefix='shield-stage-') as directory, \
           patch.object(coordinator, 'RAM', directory):
        command, marker, _expected = self.command('kexec', len(data), hashlib.sha256(data).hexdigest())
        final = Path(marker); pending = Path(marker + '.pending')
        sentinel = b'preserve-existing'
        if collision == 'final-file': final.write_bytes(sentinel)
        elif collision == 'final-directory': final.mkdir()
        elif collision == 'final-dangling-link': final.symlink_to('missing-target')
        else: pending.write_bytes(sentinel)
        result = subprocess.run(['/bin/sh', '-c', command.replace('/system/bin/toybox ', '/usr/bin/')],
          input=base64.b64encode(data), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        if collision == 'final-file': self.assertEqual(final.read_bytes(), sentinel)
        elif collision == 'final-directory': self.assertEqual(list(final.iterdir()), [])
        elif collision == 'final-dangling-link': self.assertEqual(os.readlink(final), 'missing-target')
        else:
          self.assertEqual(pending.read_bytes(), sentinel)
          self.assertFalse(final.exists())
        self.assertEqual((Path(directory) / 'kexec').read_bytes(), data)

  def test_complete_wrong_hash_never_publishes_pending_or_final_marker(self):
    import native_phase_coordinator as coordinator
    data = bytes(range(256)) * 2
    with tempfile.TemporaryDirectory(prefix='shield-stage-') as directory, \
         patch.object(coordinator, 'RAM', directory):
      command, marker, _expected = self.command('kexec', len(data))
      result = subprocess.run(['/bin/sh', '-c', command.replace('/system/bin/toybox ', '/usr/bin/')],
        input=base64.b64encode(data), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
      self.assertNotEqual(result.returncode, 0)
      self.assertFalse(Path(marker).exists())
      self.assertFalse(Path(marker + '.pending').exists())

  def test_only_fixed_artifacts_and_bounded_integer_counts_are_allowed(self):
    for name in ['../kexec', 'kexec;reboot', '/tmp/kexec', 'Image.closed', '', None]:
      with self.subTest(name=name), self.assertRaises(ValueError): self.command(name, 1)
    for count in [0, -1, True, 1.0, '1', 384 * 1024**2 + 1]:
      with self.subTest(count=count), self.assertRaises(ValueError): self.command('Image', count)

  def test_binary_archive_length_is_a_count_not_shell_data(self):
    command, marker, expected = self.command('initramfs.cpio.gz', 246495584)
    self.assertIn('head -c 328660780 | /system/bin/toybox base64 -d > /tmp/shield-native/initramfs.cpio.gz && ', command)
    self.assertIn('SHIELD_STAGE_INPUT_CONFIRMED 246495584 ', command)
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


# Cross-component inventory checks use an explicitly reviewed fixture manifest.
# Synthetic predecessor records below are disposable TEST DATA, never native evidence.
class RootRuntimeReceiverIntegrationTests(unittest.TestCase):
  BASE = Path('/home/jresp/build/omarchy-shield')
  FIXTURE_ENV = 'SHIELD_NATIVE_TEST_FIXTURE'
  FIXTURE_SHA_ENV = 'SHIELD_NATIVE_TEST_FIXTURE_SHA256'

  @staticmethod
  def sha(raw):
    return hashlib.sha256(raw).hexdigest()

  @classmethod
  def setUpClass(cls):
    if os.geteuid() != 0:
      raise unittest.SkipTest('Real immutable owned_file checks require the reviewed WSL root test job')
    fixture_path = os.environ.get(cls.FIXTURE_ENV)
    fixture_sha = os.environ.get(cls.FIXTURE_SHA_ENV)
    if fixture_path is None and fixture_sha is None:
      raise unittest.SkipTest('Reviewed native fixture manifest absent; inventory integration is UNQUALIFIED')
    if not fixture_path or not fixture_sha:
      raise ValueError('Incomplete native fixture manifest binding')
    path = Path(fixture_path)
    if (not path.is_absolute() or not path.is_relative_to(cls.BASE)
        or len(fixture_sha) != 64 or any(char not in '0123456789abcdef' for char in fixture_sha)):
      raise ValueError('Invalid native fixture manifest binding')
    pin = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': fixture_sha, 'mode': 0o600}
    fixture = json.loads(capsule.pinned(pin, 128 * 1024))
    fields = {'format_version', 'purpose', 'capsule_contract', 'guardian_artifacts',
      'guardian_profile', 'bootstrap_receipt', 'layer_archive', 'layer_pin'}
    if (set(fixture) != fields or type(fixture['format_version']) is not int
        or fixture['format_version'] != 1 or fixture['purpose'] != 'native systemd inventory test fixture'):
      raise ValueError('Wrong native fixture manifest purpose')
    raw = capsule.pinned(fixture['capsule_contract'], 128 * 1024)
    cls.workspace = tempfile.TemporaryDirectory(prefix='shield-receiver-fixture-', dir='/home/jresp/build')
    cls.addClassCleanup(cls.workspace.cleanup)
    cls.fixture_root = Path(cls.workspace.name)
    cls.counter = 0
    cls.contract = copy.deepcopy(json.loads(raw))
    if (cls.contract.get('phase') != 'packages' or cls.contract.get('format_version') != 1
        or cls.contract.get('purpose') != 'host-only native capsule inputs'
        or set(cls.contract.get('inputs', {})) != {'payload', 'plan'}):
      raise ValueError('Expected a fresh reviewed packages input contract')
    # The freshly built contract must already match this frozen source cohort.
    # Do not silently repin an older artifact's inputs to force compatibility.
    capsule.source_snapshot(cls.contract['source_sha256'])
    cls.contract['phase'] = 'systemd'
    cls.contract['packages'] = {}
    cls.prefix = 'usr/lib/omarchy/shield/qualification/'
    artifact_path = Path(fixture['guardian_artifacts']['path'])
    profile_path = Path(fixture['guardian_profile']['path'])
    if (artifact_path.name != 'artifacts.json' or profile_path.name != 'profile.json'
        or profile_path.parent != artifact_path.parent):
      raise ValueError('Systemd guardian fixture paths differ')
    cls.guardian = artifact_path.parent
    artifact = json.loads(capsule.pinned(fixture['guardian_artifacts'], 128 * 1024))
    cls.profile_raw = capsule.pinned(fixture['guardian_profile'], 128 * 1024)
    if artifact['profile_sha256'] != cls.sha(cls.profile_raw):
      raise ValueError('Guardian fixture profile binding differs')
    cls.profile = json.loads(cls.profile_raw)
    cls.receiver_path = cls.guardian / 'qualification_recovery.py'
    if cls.receiver_path.read_bytes() != (TOOLS / 'qualification_recovery.py').read_bytes():
      raise ValueError('Installed receiver is not byte-identical to the immutable source under review')
    cls.receiver_sha256 = cls.sha(cls.receiver_path.read_bytes())
    bootstrap_pin = fixture['bootstrap_receipt']
    helper_receipt = json.loads(capsule.pinned(bootstrap_pin, 128 * 1024))
    if helper_receipt['source_sha256'] != cls.contract['source_sha256']:
      raise ValueError('Bootstrap fixture source cohort differs')
    helper_directory = Path(bootstrap_pin['path']).parent / 'systemd'
    for name in list(cls.contract['files']):
      if name.startswith(cls.prefix):
        del cls.contract['files'][name]
    for name in capsule.ARTIFACT_NAMES | {'profile.json', 'artifacts.json'}:
      mode = 0o600 if name.endswith('.json') else 0o644 if name.endswith('.py') else 0o700
      cls.contract['files'][cls.prefix + name] = cls.file_pin(cls.guardian / name, mode)
    for name in capsule.COMMON_RUNTIME | {'native-root-control.py', 'native_cleanup_rpc.py'}:
      cls.contract['files'][capsule.RUNTIME_PREFIX + name] = cls.file_pin(TOOLS / name, 0o644)
    for leaf in ['shield-early-health', 'shield-internal-ro']:
      helper_pin = cls.file_pin(helper_directory / leaf, 0o700)
      expected = helper_receipt['files']['systemd/' + leaf]
      if {key: helper_pin[key] for key in ['bytes', 'sha256', 'mode']} != expected:
        raise ValueError('Systemd helper fixture differs from its build receipt')
      cls.contract['files'][capsule.RUNTIME_PREFIX + leaf] = helper_pin
    old_plan = json.loads(capsule.pinned(cls.contract['inputs']['plan'], 16 * 1024**2))
    payload_pin = cls.contract['inputs']['payload']
    # Only predecessor/schema fixture data is synthetic. Actual validators stay live.
    lp = copy.deepcopy(fixture['layer_pin'])
    if (type(lp['sources']) is not dict
        or lp['archive_sha256'] != fixture['layer_archive']['sha256']
        or lp['archive_bytes'] != fixture['layer_archive']['bytes']):
      raise ValueError('Fresh layer fixture binding differs')
    capsule.pinned(fixture['layer_archive'], 64 * 1024**2)
    original_accounts = cls.sha(capsule.canonical(old_plan['maintenance']['base_account_preimages']))
    phase_a_plan_sha = cls.contract['inputs']['plan']['sha256']
    a = cls.synthetic_completion('packages', old_plan, phase_a_plan_sha, 1)
    a_raw = capsule.canonical(a)
    writer = {'layer': lp, 'preimages_sha256': cls.sha(b'TEST ONLY expected-A profile'),
      'preimages_bytes': 1, 'candidate_id': old_plan['maintenance']['candidate_id'],
      'filesystem_uuid': old_plan['maintenance']['filesystem_uuid'],
      'phase_a_plan_sha256': phase_a_plan_sha, 'phase_a_receipt_sha256': cls.sha(a_raw),
      'original_accounts_sha256': original_accounts}
    plan = {'format_version': 1, 'purpose': 'native layer plan',
      'maintenance': old_plan['maintenance'], 'original_default': old_plan['original_default'],
      'writer_pin': writer}
    plan_raw = capsule.canonical(plan)
    b = cls.synthetic_completion('layer', plan, cls.sha(plan_raw), 2)
    cls.contract['inputs'] = {
      'payload': payload_pin, 'plan': cls.store_pin('TEST-ONLY-plan.json', plan_raw),
      'layer': fixture['layer_archive'],
      'predecessorA': cls.store_pin('TEST-ONLY-predecessor-A.json', a_raw),
      'predecessorB': cls.store_pin('TEST-ONLY-predecessor-B.json', capsule.canonical(b))}
    # Exactly one real assemble call for this class; no copied root-filter logic.
    cls.blobs, cls.receipt = capsule.assemble(cls.contract)
    cls.bundle = json.loads(cls.blobs['boot.json'])
    cls.entries = capsule.read_newc(gzip.decompress(cls.blobs['initramfs.cpio.gz']))
    saved_path = list(sys.path)
    try:
      spec = importlib.util.spec_from_file_location('immutable_fixture_receiver', cls.receiver_path)
      cls.receiver = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(cls.receiver)
    finally:
      sys.path[:] = saved_path
    # Only final client construction is stubbed; load(root), RPC and real C startup are outside this boundary test.
    cls.cleanup_module = importlib.import_module('native_cleanup_rpc')

  @classmethod
  def file_pin(cls, path, mode):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': cls.sha(data), 'mode': mode}

  @classmethod
  def store_pin(cls, name, data):
    path = cls.fixture_root / name
    with path.open('xb') as stream:
      stream.write(data)
    path.chmod(0o600)
    return cls.file_pin(path, 0o600)

  @classmethod
  def synthetic_completion(cls, phase, plan, plan_sha, number):
    maintenance = plan['maintenance']
    seed = ('TEST ONLY predecessor ' + phase).encode('ascii')
    digest = cls.sha(seed)
    return {'format_version': 1, 'purpose': 'native preparation completion',
      'state': 'RELEASED_AND_RECOVERED', 'phase': phase,
      'filesystem_uuid': maintenance['filesystem_uuid'], 'candidate_id': maintenance['candidate_id'],
      'payload_manifest_sha256': maintenance['payload_manifest_sha256'], 'plan_sha256': plan_sha,
      'guardian_candidate': cls.profile['candidate'],
      'boot_id': '00000000-0000-4000-8000-' + f'{number:012d}',
      'configuration_sha256': digest, 'session_id': cls.sha(seed + b' session'),
      'evidence_sha256': digest, 'journal_sha256': digest, 'worker_result_sha256': digest,
      'original_default': plan['original_default'], 'clean_usb_release': True,
      'authenticated_recovery_observed': True, 'recovery_observation_sha256': digest,
      'boot_ready': False, 'physical_powerloss_qualified': False}

  @contextmanager
  def receiver_fixture(self, bundle=None):
    type(self).counter += 1
    root = self.fixture_root / ('receiver-' + str(self.counter))
    private = root / 'run/shield-native'
    runtime_dir = private / 'runtime'
    runtime_dir.mkdir(parents=True, mode=0o700)
    private.chmod(0o700)
    runtime_dir.chmod(0o700)
    # Stage actual producer archive bytes, including unreferenced early ELF helpers.
    for name, entry in self.entries.items():
      prefix = capsule.SEED + 'runtime/'
      if name.startswith(prefix) and stat.S_ISREG(entry['mode']):
        path = runtime_dir / name[len(prefix):]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(entry['data'])
        path.chmod(stat.S_IMODE(entry['mode']))
    current = copy.deepcopy(self.bundle if bundle is None else bundle)
    boot_raw = capsule.canonical(current)
    boot_file = private / 'boot.json'
    boot_file.write_bytes(boot_raw)
    boot_file.chmod(0o600)
    cmdline = root / 'proc/cmdline'
    cmdline.parent.mkdir(parents=True)
    cmdline.write_text('shield.native-bundle=' + self.sha(boot_raw) + '\n')
    def mapped_path(value):
      path = Path(value)
      if path == Path('/'):
        return root
      if path == Path('/run/shield-native') or path.is_relative_to('/run/shield-native'):
        return root / str(path).lstrip('/')
      if path == Path('/proc/cmdline'):
        return cmdline
      raise AssertionError('Unexpected absolute receiver Path outside the fixed temporary adapter')
    sentinel = object()
    constructor = Mock(return_value=sentinel)
    saved_path = list(sys.path)
    try:
      with patch.object(self.receiver, 'Path', side_effect=mapped_path), \
           patch.object(self.cleanup_module, 'CleanupClient', constructor):
        yield SimpleNamespace(call=lambda: self.receiver.bind_native_control(self.profile),
          private=private, runtime=runtime_dir, constructor=constructor, sentinel=sentinel)
    finally:
      sys.path[:] = saved_path

  def test_real_producer_output_reaches_immutable_receiver_with_python_root_inventory(self):
    early = self.bundle['configuration']['sources']['early']
    root = self.bundle['configuration']['sources']['root']
    for leaf in ['shield-internal-ro', 'shield-early-health']:
      name = capsule.RUNTIME_PREFIX + leaf
      self.assertIn(name, early)
      self.assertNotIn(name, root)
      entry = self.entries[capsule.SEED + 'runtime/' + leaf]
      self.assertEqual(self.sha(entry['data']), early[name]['sha256'])
      self.assertEqual(stat.S_IMODE(entry['mode']), 0o700)
    for leaf in capsule.COMMON_RUNTIME | {'native-root-control.py', 'native_cleanup_rpc.py'}:
      self.assertIn(capsule.RUNTIME_PREFIX + leaf, root)
    for leaf in capsule.ARTIFACT_NAMES | {'profile.json', 'artifacts.json'}:
      self.assertIn(self.prefix + leaf, root)
    for name, raw in capsule.policy_files(self.profile).items():
      self.assertEqual(root[name], {'sha256': self.sha(raw), 'bytes': len(raw), 'mode': 0o644})
    with self.receiver_fixture() as fixture:
      self.assertIs(fixture.call(), fixture.sentinel)
      fixture.constructor.assert_called_once_with(self.profile)
    self.assertEqual(self.sha(self.receiver_path.read_bytes()), self.receiver_sha256)

  def test_injected_early_elf_reproduces_real_receiver_rejection_before_connection(self):
    for leaf in ['shield-internal-ro', 'shield-early-health']:
      with self.subTest(helper=leaf):
        bundle = copy.deepcopy(self.bundle)
        name = capsule.RUNTIME_PREFIX + leaf
        bundle['configuration']['sources']['root'][name] = bundle['configuration']['sources']['early'][name]
        with self.receiver_fixture(bundle) as fixture:
          with self.assertRaisesRegex(ValueError, 'Unsafe native bootstrap source'):
            fixture.call()
          fixture.constructor.assert_not_called()

  def test_root_python_byte_tamper_is_rejected_before_connection(self):
    with self.receiver_fixture() as fixture:
      target = fixture.runtime / 'native_cleanup_rpc.py'
      target.write_bytes(target.read_bytes() + b'\n# fixture tamper\n')
      with self.assertRaisesRegex(ValueError, 'Native bootstrap source differs'):
        fixture.call()
      fixture.constructor.assert_not_called()

  def test_root_python_mode_tamper_is_rejected_before_connection(self):
    with self.receiver_fixture() as fixture:
      (fixture.runtime / 'native_cleanup_rpc.py').chmod(0o600)
      with self.assertRaisesRegex(ValueError, 'Wrong private input mode'):
        fixture.call()
      fixture.constructor.assert_not_called()

  def test_missing_required_python_inventory_cannot_reach_connection(self):
    bundle = copy.deepcopy(self.bundle)
    del bundle['configuration']['sources']['root'][capsule.RUNTIME_PREFIX + 'native_cleanup_rpc.py']
    with self.receiver_fixture(bundle) as fixture:
      with self.assertRaisesRegex(ValueError, 'Native cleanup import closure absent'):
        fixture.call()
      fixture.constructor.assert_not_called()

  def test_missing_declared_python_file_is_rejected_before_connection(self):
    with self.receiver_fixture() as fixture:
      (fixture.runtime / 'native_cleanup_rpc.py').unlink()
      with self.assertRaises(FileNotFoundError):
        fixture.call()
      fixture.constructor.assert_not_called()


  def test_runtime_suffix_cannot_escape_or_nest_before_connection(self):
    identity = self.bundle['configuration']['sources']['root'][capsule.RUNTIME_PREFIX + 'native_cleanup_rpc.py']
    for suffix in ['', '../escape.py', '/absolute.py', 'nested/file.py', '..', '.', 'file.txt']:
      with self.subTest(suffix=suffix):
        bundle = copy.deepcopy(self.bundle)
        bundle['configuration']['sources']['root'][capsule.RUNTIME_PREFIX + suffix] = identity
        with self.receiver_fixture(bundle) as fixture:
          with self.assertRaises(ValueError):
            fixture.call()
          fixture.constructor.assert_not_called()

  def test_generic_payload_path_guard_still_rejects_runtime_paths(self):
    from usb_root_profile import safe_relative
    with self.assertRaisesRegex(ValueError, 'Virtual/build payload path'):
      safe_relative(capsule.RUNTIME_PREFIX + 'native_cleanup_rpc.py')



# Exercise the selected kernel's descriptor lifecycle with confined filesystem fixtures.
class GadgetDescriptorLifecycleTests(unittest.TestCase):
  from contextlib import contextmanager as _contextmanager

  @classmethod
  def setUpClass(cls):
    cls.G = load('native_gadget')
    if cls.G.os.getuid() != 0 or cls.G.os.geteuid() != 0:
      raise unittest.SkipTest('Actual root gadget ownership checks need the reviewed WSL-root host test job')

  @_contextmanager
  def fixture(self, *, bound=False):
    G = self.G
    with tempfile.TemporaryDirectory(prefix='gadget-lifecycle-') as name:
      temp = Path(name)
      config = temp / 'sys/kernel/config'
      base = config / 'usb_gadget'
      gadget = base / 'shield-native'
      for relative in ['strings/0x409', 'configs/c.1/strings/0x409', 'functions/acm.usb0']:
        (gadget / relative).mkdir(parents=True, mode=0o700, exist_ok=True)
      gadget.chmod(0o700)
      function = gadget / 'configs/c.1/acm.usb0'
      function.symlink_to(gadget / 'functions/acm.usb0')
      device = temp / 'sys/devices/platform/700d0000.usb'
      driver = temp / 'sys/bus/platform/drivers/tegra-xudc'
      driver.mkdir(parents=True)
      device.mkdir(parents=True)
      (device / 'driver').symlink_to(driver)
      udc_class = temp / 'sys/class/udc'
      udc = udc_class / '700d0000.usb'
      udc.mkdir(parents=True)
      (udc / 'device').symlink_to(device)
      bundle = SimpleNamespace(epoch='early', phase='packages',
        contexts={'early': SimpleNamespace(session_id='a' * 64)})
      def put(relative, value):
        if type(value) is int:
          value = str(value) if relative.endswith(('MaxPower', 'port_num')) else hex(value)
        (gadget / relative).write_text(value + '\n')
      for relative, value in G.NUMBERS.items():
        put(relative, value)
      for relative, value in G.strings(bundle).items():
        put(relative, value)
      put('functions/acm.usb0/port_num', 0)
      put('UDC', G.UDC if bound else '')
      real_listdir, real_open = G.os.listdir, G.os.open
      def mapped(value):
        value = Path(value)
        if str(value).startswith('/sys/'):
          return temp / str(value).lstrip('/')
        return value
      def listdir(value):
        path = mapped(value)
        if not path.is_relative_to(temp):
          raise AssertionError('Unexpected directory outside temporary gadget fixture')
        return real_listdir(path)
      def readonly_open(value, flags, *args, **kwargs):
        path = Path(value)
        forbidden = G.os.O_WRONLY | G.os.O_RDWR | G.os.O_CREAT | G.os.O_TRUNC | G.os.O_APPEND
        if args or kwargs or flags & forbidden or not path.is_relative_to(config):
          raise AssertionError('Unexpected operation outside read-only temporary configfs')
        return real_open(path, flags)
      def magic(value):
        path = Path(G.os.readlink('/proc/self/fd/' + str(value))) if type(value) is int else Path(value)
        if not path.is_relative_to(config):
          raise AssertionError('Filesystem type requested outside temporary configfs')
        return 0x62656570
      with patch.object(G, 'CONFIG', config), patch.object(G, 'BASE', base), \
           patch.object(G, 'GADGET', gadget), patch.object(G, 'Path', mapped), \
           patch.object(G.os, 'listdir', listdir), patch.object(G.os, 'open', readonly_open), \
           patch.object(G, 'filesystem_magic', magic):
        yield SimpleNamespace(validate=lambda: G.validate(bundle, bound=bound),
          put=put, gadget=gadget, config=config, base=base, temp=temp,
          function=function, device=device, driver=driver, udc_class=udc_class)

  def test_unbound_initial_0200_is_accepted(self):
    with self.fixture() as fixture:
      self.assertIsNone(fixture.validate())

  def test_bound_selected_kernel_lifecycle_transitions_are_accepted(self):
    with self.fixture(bound=True) as fixture:
      for value in [0x0200, 0x0320, 0x0210, 0x0320]:
        with self.subTest(bcdUSB=value):
          fixture.put('bcdUSB', value)
          self.assertIsNone(fixture.validate())

  def test_unbound_cannot_adopt_post_enumeration_versions(self):
    for value in [0x0210, 0x0320]:
      with self.subTest(bcdUSB=value), self.fixture() as fixture:
        fixture.put('bcdUSB', value)
        with self.assertRaisesRegex(ValueError, 'Gadget numeric descriptor differs'):
          fixture.validate()

  def test_bound_rejects_versions_outside_the_selected_driver_lifecycle(self):
    for value in [0x0201, 0x0300, 0x0310, 0x9999, 0, -1, 0xffff, 0x0110]:
      with self.subTest(bcdUSB=value), self.fixture(bound=True) as fixture:
        fixture.put('bcdUSB', value)
        with self.assertRaises(ValueError):
          fixture.validate()

  def test_every_other_numeric_identity_remains_exact_in_both_phases(self):
    for bound in [False, True]:
      for name, expected in self.G.NUMBERS.items():
        if name == 'bcdUSB':
          continue
        with self.subTest(bound=bound, field=name), self.fixture(bound=bound) as fixture:
          fixture.put(name, expected + 1)
          with self.assertRaisesRegex(ValueError, 'Gadget numeric descriptor differs'):
            fixture.validate()

  def test_every_string_remains_exact(self):
    bundle = SimpleNamespace(contexts={'early': SimpleNamespace(session_id='a' * 64)})
    for name in self.G.strings(bundle):
      with self.subTest(field=name), self.fixture(bound=True) as fixture:
        fixture.put(name, 'not-the-admitted-string')
        with self.assertRaisesRegex(ValueError, 'Gadget string descriptor differs'):
          fixture.validate()

  def test_function_target_and_extra_function_remain_refused(self):
    with self.fixture(bound=True) as fixture:
      alternate = fixture.gadget / 'unadmitted-function'
      alternate.mkdir()
      fixture.function.unlink()
      fixture.function.symlink_to(alternate)
      with self.assertRaisesRegex(ValueError, 'Wrong gadget function link'):
        fixture.validate()
    with self.fixture(bound=True) as fixture:
      (fixture.gadget / 'functions/acm.usb1').mkdir()
      with self.assertRaisesRegex(ValueError, 'Unexpected gadget function/configuration/string language'):
        fixture.validate()

  def test_port_and_binding_remain_exact(self):
    for field, value in [('functions/acm.usb0/port_num', 1), ('UDC', 'unadmitted-controller')]:
      with self.subTest(field=field), self.fixture(bound=True) as fixture:
        fixture.put(field, value)
        with self.assertRaisesRegex(ValueError, 'Gadget ACM port/binding differs'):
          fixture.validate()

  def test_private_gadget_mode_and_root_owner_remain_required(self):
    with self.fixture(bound=True) as fixture:
      fixture.gadget.chmod(0o755)
      with self.assertRaisesRegex(ValueError, 'Unsafe bundle directory'):
        fixture.validate()
    for uid, gid in [(1001, 0), (0, 1001)]:
      with self.subTest(uid=uid, gid=gid), self.fixture(bound=True) as fixture:
        self.G.os.chown(fixture.gadget, uid, gid)
        with self.assertRaisesRegex(ValueError, 'Unsafe bundle directory'):
          fixture.validate()

  def test_controller_driver_and_sole_UDC_remain_required(self):
    with self.fixture(bound=True) as fixture:
      wrong = fixture.driver.parent / 'unadmitted-driver'
      wrong.mkdir()
      (fixture.device / 'driver').unlink()
      (fixture.device / 'driver').symlink_to(wrong)
      with self.assertRaisesRegex(ValueError, 'Wrong A04 gadget controller'):
        fixture.validate()
    with self.fixture(bound=True) as fixture:
      (fixture.udc_class / 'extra-controller').mkdir()
      with self.assertRaisesRegex(ValueError, 'Wrong configfs or selected UDC'):
        fixture.validate()

  def test_malformed_numeric_observation_is_not_accepted_as_a_version(self):
    with self.fixture(bound=True) as fixture:
      fixture.put('bcdUSB', 'not-a-number')
      with self.assertRaises(ValueError):
        fixture.validate()


# Real socket receiver regressions. No PID1/guardian constructor or hardware.
class RealSocketReceiveFlagTests(unittest.TestCase):
  CANDIDATE = '1' * 64
  BOOT = '11111111-1111-4111-8111-111111111111'

  @classmethod
  def setUpClass(cls):
    import socket
    import native_ram_recovery
    import native_cleanup_rpc
    import native_boot_context
    import guardian_client
    cls.socket = socket
    cls.recovery_module = native_ram_recovery
    cls.cleanup_module = native_cleanup_rpc
    cls.context_module = native_boot_context
    cls.guardian_module = guardian_client
    if not hasattr(socket, 'MSG_CMSG_CLOEXEC'):
      raise AssertionError('This reviewed Linux regression requires MSG_CMSG_CLOEXEC')

  @contextmanager
  def pair(self):
    a, b = self.socket.socketpair(self.socket.AF_UNIX,
      self.socket.SOCK_SEQPACKET | self.socket.SOCK_CLOEXEC)
    a.settimeout(1)
    b.settimeout(1)
    try:
      yield a, b
    finally:
      a.close()
      b.close()

  def packet(self, *, magic=None, version=None, operation=6, fault=0,
             candidate=None, boot=None):
    g = self.guardian_module
    return g.REQUEST.pack(g.MAGIC if magic is None else magic,
      g.VERSION if version is None else version, operation, fault,
      (self.CANDIDATE if candidate is None else candidate).encode('ascii'),
      (self.BOOT if boot is None else boot).encode('ascii'))

  def owner(self, channel, clock_ns=5 * 1000000000):
    # Constructor's PID1, directory and device effects are deliberately excluded.
    # Only the clock observation boundary is synthetic; receive() is real.
    owner = self.recovery_module.Recovery.__new__(self.recovery_module.Recovery)
    owner.channel = channel
    owner.channel_eof = False
    owner.pending_owner_loss = False
    owner.bundle = SimpleNamespace(profile={'candidate': self.CANDIDATE}, boot_id=self.BOOT)
    owner.ready_received = False
    owner.reason = None
    owner.clock = lambda: clock_ns
    return owner

  def receive(self, kind, channel):
    if kind == 'READY':
      return self.owner(channel).receive()
    return self.cleanup_module.receive(channel)

  def payload(self, kind):
    return self.packet() if kind == 'READY' else self.context_module.canonical({'ok': True})

  def guard_message(self, kind):
    return ('Wrong guardian recovery packet' if kind == 'READY'
      else 'Truncated/ancillary/closed cleanup packet')

  def test_actual_ready_with_cloexec_echo_is_accepted(self):
    with self.pair() as (a, b):
      b.sendall(self.packet())
      owner = self.owner(a)
      self.assertEqual(owner.receive(), {'event': 'guardian-ready'})
      self.assertTrue(owner.ready_received)
      self.assertIsNone(owner.reason)

  def test_actual_cleanup_native_canonical_json_is_accepted(self):
    value = {'n': 7, 'ok': True}
    with self.pair() as (a, b):
      b.sendall(self.context_module.canonical(value))
      self.assertEqual(self.cleanup_module.receive(a), value)

  def test_actual_oversized_records_reject_truncation_for_both_receivers(self):
    for kind in ['READY', 'cleanup']:
      with self.subTest(receiver=kind), self.pair() as (a, b):
        data = self.packet() + b'x' if kind == 'READY' else b' ' * (self.cleanup_module.MAX_PACKET + 1)
        b.sendall(data)
        with self.assertRaisesRegex(ValueError, self.guard_message(kind)):
          self.receive(kind, a)

  def test_actual_rights_with_zero_control_buffer_reject_ctrunc_without_fd_leak(self):
    import array
    for kind in ['READY', 'cleanup']:
      with self.subTest(receiver=kind), self.pair() as (a, b):
        pipe_read, pipe_write = os.pipe()
        try:
          before = len(os.listdir('/proc/self/fd'))
          data = self.payload(kind)
          self.assertEqual(b.sendmsg([data], [(self.socket.SOL_SOCKET,
            self.socket.SCM_RIGHTS, array.array('i', [pipe_read]))]), len(data))
          with self.assertRaisesRegex(ValueError, self.guard_message(kind)):
            self.receive(kind, a)
          # Both real receive calls pass ancbufsize=0: no rights are imported.
          self.assertEqual(len(os.listdir('/proc/self/fd')), before)
        finally:
          os.close(pipe_read)
          os.close(pipe_write)

  def test_unknown_output_flags_still_reject_both_receivers(self):
    class ExtraOutputFlag:
      # Only an impossible output bit is injected; the data/actual recvmsg and
      # its CMSG_CLOEXEC flag still come from a real kernel socket.
      def __init__(self, channel):
        self.channel = channel
      def recvmsg(self, *args):
        data, ancillary, flags, address = self.channel.recvmsg(*args)
        return data, ancillary, flags | (1 << 28), address
    for kind in ['READY', 'cleanup']:
      with self.subTest(receiver=kind), self.pair() as (a, b):
        b.sendall(self.payload(kind))
        with self.assertRaisesRegex(ValueError, self.guard_message(kind)):
          self.receive(kind, ExtraOutputFlag(a))

  def test_ready_identity_version_and_cause_guards_remain_strict(self):
    cases = [dict(magic=0), dict(version=2), dict(candidate='2' * 64),
      dict(boot='22222222-2222-4222-8222-222222222222'),
      dict(operation=0), dict(operation=6, fault=1),
      dict(operation=4, fault=0), dict(operation=4, fault=10)]
    for case in cases:
      with self.subTest(fields=case), self.pair() as (a, b):
        b.sendall(self.packet(**case))
        owner = self.owner(a)
        with self.assertRaisesRegex(ValueError, 'Wrong guardian recovery identity/cause'):
          owner.receive()
        self.assertFalse(owner.ready_received)

  def test_ready_short_wire_record_rejects_before_identity_admission(self):
    with self.pair() as (a, b):
      b.sendall(self.packet()[:-1])
      with self.assertRaisesRegex(ValueError, 'Wrong guardian recovery packet'):
        self.owner(a).receive()

  def test_ready_duplicate_event_still_rejected(self):
    with self.pair() as (a, b):
      owner = self.owner(a)
      b.sendall(self.packet())
      self.assertEqual(owner.receive(), {'event': 'guardian-ready'})
      b.sendall(self.packet())
      with self.assertRaisesRegex(ValueError, 'Repeated, late or post-fault guardian readiness'):
        owner.receive()

  def test_ready_exact_deadline_remains_rejected(self):
    with self.pair() as (a, b):
      b.sendall(self.packet())
      owner = self.owner(a, clock_ns=120 * 1000000000)
      with self.assertRaisesRegex(ValueError, 'Repeated, late or post-fault guardian readiness'):
        owner.receive()
      self.assertFalse(owner.ready_received)

  def test_cleanup_noncanonical_or_duplicate_json_still_rejected(self):
    for data in [b'{}', b'{}\n\n', b'{"v":1.0}\n', b'{"v":1,"v":2}\n',
                 b'{"z":1,"a":2}\n', b'{}\ntrailing']:
      with self.subTest(data=data), self.pair() as (a, b):
        b.sendall(data)
        with self.assertRaises(ValueError):
          self.cleanup_module.receive(a)


@unittest.skipUnless(os.geteuid() == 0, 'real private failure records require root-owned temporary directories')
class HostWorkerFailureRecordTests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    import native_host_controller
    cls.controller = native_host_controller

  def error(self):
    try:
      exec(compile('raise ValueError("PRIVATE_KEY_MATERIAL")',
                   str(TOOLS / 'native_host_controller.py'), 'exec'), {})
    except ValueError as error:
      return error

  def test_actual_fork_failure_retains_private_record_and_original_exit75(self):
    import select
    import signal
    c = self.controller
    with tempfile.TemporaryDirectory() as tmp:
      directory = Path(tmp)
      directory.chmod(0o700)
      parent_peers = []
      handles = []
      for writing in [True, False, False]:
        read_fd, write_fd = os.pipe()
        owned, peer = (write_fd, read_fd) if writing else (read_fd, write_fd)
        handles.append(os.fdopen(owned, 'wb' if writing else 'rb', buffering=0))
        parent_peers.append(peer)
      process = SimpleNamespace(stdin=handles[0], stdout=handles[1], stderr=handles[2])
      attempt = c.Attempt.__new__(c.Attempt)
      attempt.started = True
      attempt.process = attempt.pid = attempt.pidfd = attempt.channel = None
      attempt.directory = directory
      attempt.deadline = c.now() + 60 * c.SECOND
      attempt.spec = SimpleNamespace(contexts={'early': SimpleNamespace(session_id='1' * 64)})
      waited = False
      def fail_worker(*unused):
        raise self.error()
      try:
        with patch.object(c.subprocess, 'Popen', return_value=process) as opened, \
             patch.object(c, 'session_worker', side_effect=fail_worker):
          attempt.launch()
        self.assertEqual(opened.call_count, 1)  # Stubbed pipe owner, no Windows process.
        self.assertTrue(select.select([attempt.pidfd], [], [], 3)[0])
        pid, status = os.waitpid(attempt.pid, 0)
        waited = True
        self.assertEqual(pid, attempt.pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 75)
        raw, ancillary, flags, _address = attempt.channel.recvmsg(8192)
        self.assertEqual((raw, ancillary, flags), (b'', [], 0))
        record = directory / 'worker-failure.json'
        payload = record.read_bytes()
        value = json.loads(payload)
        self.assertEqual(value['error_type'], 'ValueError')
        self.assertFalse(value['qualification'])
        self.assertFalse(value['boot_ready'])
        self.assertLessEqual(len(payload), 4096)
        self.assertLessEqual(len(value['public_frames']), 8)
        self.assertTrue(value['public_frames'])
        self.assertTrue(all(row['file'] == 'native_host_controller.py'
                            for row in value['public_frames']))
        self.assertNotIn(b'PRIVATE', payload)
        self.assertNotIn(str(TOOLS).encode(), payload)
        self.assertNotIn(b'fail_worker', payload)
        info = record.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                         (0, 0, 0o600, 1))
      finally:
        if attempt.pidfd is not None:
          if not waited:
            try: signal.pidfd_send_signal(attempt.pidfd, signal.SIGKILL)
            except ProcessLookupError: pass
            if select.select([attempt.pidfd], [], [], 3)[0]:
              os.waitpid(attempt.pid, 0)
          os.close(attempt.pidfd)
        if attempt.channel is not None: attempt.channel.close()
        for handle in handles: handle.close()
        for descriptor in parent_peers: os.close(descriptor)

  def test_existing_regular_or_symlink_record_is_never_replaced(self):
    c = self.controller
    for symbolic in [False, True]:
      with self.subTest(symlink=symbolic), tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        sentinel = directory / 'sentinel'
        sentinel.write_bytes(b'RETAINED_ORIGINAL')
        record = directory / 'worker-failure.json'
        if symbolic: record.symlink_to(sentinel)
        else: record.write_bytes(b'RETAINED_ORIGINAL')
        self.assertFalse(c.preserve_worker_failure(directory, self.error(), c.now() + c.SECOND))
        self.assertEqual(record.read_bytes(), b'RETAINED_ORIGINAL')
        self.assertEqual(sentinel.read_bytes(), b'RETAINED_ORIGINAL')
        self.assertEqual(record.is_symlink(), symbolic)

  def test_nonprivate_symlink_or_nondirectory_parent_is_refused(self):
    c = self.controller
    with tempfile.TemporaryDirectory() as tmp:
      root = Path(tmp)
      public = root / 'public'
      public.mkdir(mode=0o755)
      public.chmod(0o755)
      private = root / 'private'
      private.mkdir(mode=0o700)
      alias = root / 'alias'
      alias.symlink_to(private, target_is_directory=True)
      regular = root / 'regular'
      regular.write_bytes(b'unchanged')
      for path in [public, alias, regular]:
        with self.subTest(parent=path.name):
          self.assertFalse(c.preserve_worker_failure(path, self.error(), c.now() + c.SECOND))
      self.assertFalse((public / 'worker-failure.json').exists())
      self.assertFalse((private / 'worker-failure.json').exists())
      self.assertEqual(regular.read_bytes(), b'unchanged')

  def test_expired_cutoff_opens_nothing_and_partial_write_is_not_retried(self):
    c = self.controller
    with tempfile.TemporaryDirectory() as tmp:
      directory = Path(tmp)
      with patch.object(c.os, 'open') as opened:
        self.assertFalse(c.preserve_worker_failure(directory, self.error(), 0))
        opened.assert_not_called()
      before = len(os.listdir('/proc/self/fd'))
      with patch.object(c.os, 'write', return_value=1) as written:
        self.assertFalse(c.preserve_worker_failure(directory, self.error(), c.now() + c.SECOND))
        self.assertEqual(written.call_count, 1)
      self.assertEqual(len(os.listdir('/proc/self/fd')), before)
      self.assertEqual((directory / 'worker-failure.json').read_bytes(), b'')

  def test_unknown_frames_consume_eight_link_budget_without_private_metadata(self):
    c = self.controller
    trace = None
    frames = [(str(TOOLS / 'native_host_controller.py'), 50)]
    frames += [('/PRIVATE_PATH/PRIVATE_FRAME.py', 99)] * 8
    for filename, line in frames:
      trace = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(
        co_filename=filename, co_name='PRIVATE_FUNCTION')), tb_lineno=line, tb_next=trace)
    error = SimpleNamespace(__traceback__=trace)
    with tempfile.TemporaryDirectory() as tmp:
      directory = Path(tmp)
      self.assertTrue(c.preserve_worker_failure(directory, error, c.now() + c.SECOND))
      raw = (directory / 'worker-failure.json').read_bytes()
      value = json.loads(raw)
      self.assertEqual(value['public_frames'], [])
      self.assertTrue(value['trace_truncated'])
      self.assertEqual(value['error_type'], 'Other')
      self.assertNotIn(b'PRIVATE', raw)

  def test_errno_is_closed_bounded_numeric_data_without_exception_text(self):
    c = self.controller
    for number, expected in [(5, 5), (-1, 0), (4096, 0)]:
      with self.subTest(errno=number), tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        self.assertTrue(c.preserve_worker_failure(directory,
          OSError(number, 'PRIVATE_EXCEPTION_TEXT'), c.now() + c.SECOND))
        raw = (directory / 'worker-failure.json').read_bytes()
        self.assertEqual(json.loads(raw)['errno'], expected)
        self.assertNotIn(b'PRIVATE', raw)


@unittest.skipUnless(os.geteuid() == 0, 'Actual fixed-root worker ownership fixtures require root')
class NativeWorkerFailureDiagnosticsTests218(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.worker = load('maintenance-worker')
    cls.reaper = load('native_worker_reaper')

  def error(self):
    try:
      exec(compile("raise OSError(13, 'PRIVATE_MESSAGE_KEY_SESSION')", str(TOOLS / 'maintenance-worker.py'), 'exec'), {})
    except OSError as error:
      return error

  def device(self, **overrides):
    values = dict(st_mode=stat.S_IFCHR | 0o600, st_uid=0, st_gid=0, st_rdev=os.makedev(1, 11))
    values.update(overrides)
    return SimpleNamespace(**values)

  def capture(self, module, stage, error, device=None, written=None, **diagnostic):
    records = []
    def write(fd, raw):
      self.assertEqual(fd, 77)
      records.append(raw)
      return len(raw) if written is None else written
    with patch.object(module.os, 'open', return_value=77) as opened, \
         patch.object(module.os, 'fstat', return_value=device or self.device()), \
         patch.object(module.os, 'write', side_effect=write) as output, \
         patch.object(module.os, 'close') as closed:
      module.worker_diagnostic(stage, error, **diagnostic)
    return records, opened, output, closed

  def test_public_fault_sites_and_errno_without_private_exception_or_paths(self):
    for module in [self.worker, self.reaper]:
      rows, opened, output, closed = self.capture(module, 'worker-main', self.error())
      raw = b''.join(rows)
      self.assertIn(b'error=PermissionError errno=13', raw)
      self.assertIn(b'file=maintenance-worker.py line=1', raw)
      self.assertNotIn(b'PRIVATE', raw)
      self.assertNotIn(str(TOOLS).encode(), raw)
      self.assertTrue(all(0 < len(row) <= 240 for row in rows))
      opened.assert_called_once_with('/dev/kmsg', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
      closed.assert_called_once_with(77)

  def test_unknown_stage_has_no_open_or_output(self):
    for module in [self.worker, self.reaper]:
      rows, opened, output, closed = self.capture(module, 'PRIVATE_STAGE', self.error())
      self.assertEqual(rows, [])
      opened.assert_not_called(); output.assert_not_called(); closed.assert_not_called()

  def test_unknown_type_and_out_of_range_errno_never_copy_untrusted_values(self):
    private_type = type('PRIVATE_ERROR_NAME', (Exception,), {})
    for module in [self.worker, self.reaper]:
      for error, expected in [(private_type('PRIVATE_TEXT'), b'error=other errno=-1'),
                              (OSError(-1, 'PRIVATE_TEXT'), b'errno=-1'),
                              (OSError(4096, 'PRIVATE_TEXT'), b'errno=-1'),
                              (OSError(4095, 'PRIVATE_TEXT'), b'errno=4095')]:
        rows, *_ = self.capture(module, 'worker-command', error)
        self.assertIn(expected, b''.join(rows)); self.assertNotIn(b'PRIVATE', b''.join(rows))

  def test_unsafe_kmsg_object_is_never_written(self):
    changes = [dict(st_mode=stat.S_IFREG | 0o600), dict(st_mode=stat.S_IFLNK | 0o700),
               dict(st_uid=1), dict(st_gid=1), dict(st_rdev=os.makedev(1, 3)),
               dict(st_mode=stat.S_IFCHR | 0o620), dict(st_mode=stat.S_IFCHR | 0o602)]
    for module in [self.worker, self.reaper]:
      for change in changes:
        rows, opened, output, closed = self.capture(module, 'worker-main', self.error(), self.device(**change))
        self.assertEqual(rows, []); output.assert_not_called(); closed.assert_called_once_with(77)

  def test_partial_write_is_not_retried(self):
    for module in [self.worker, self.reaper]:
      rows, opened, output, closed = self.capture(module, 'worker-main', ValueError('PRIVATE_TEXT'), written=1)
      self.assertEqual(len(rows), 1); self.assertEqual(output.call_count, 1); closed.assert_called_once_with(77)

  def test_device_io_faults_cannot_escape_or_retry(self):
    for module in [self.worker, self.reaper]:
      for failing in ['open', 'fstat', 'write', 'close']:
        with patch.object(module.os, 'open', return_value=77) as opened, \
             patch.object(module.os, 'fstat', return_value=self.device()) as stated, \
             patch.object(module.os, 'write', return_value=1) as written, \
             patch.object(module.os, 'close') as closed:
          calls = dict(open=opened, fstat=stated, write=written, close=closed)
          calls[failing].side_effect = OSError(11, 'PRIVATE_IO_FAILURE')
          module.worker_diagnostic('worker-main', ValueError('PRIVATE_TEXT'))
          self.assertEqual(calls[failing].call_count, 1)
          self.assertLessEqual(written.call_count, 1)

  def test_unknown_frames_consume_the_eight_link_budget(self):
    public = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(
      co_filename=str(TOOLS / 'maintenance-worker.py'), co_name='PRIVATE_FUNCTION')),
      tb_lineno=123, tb_next=None)
    trace = public
    for unused in range(8):
      trace = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(
        co_filename='/PRIVATE_PATH/PRIVATE_FILE.py', co_name='PRIVATE_FUNCTION')),
        tb_lineno=42, tb_next=trace)
    for module in [self.worker, self.reaper]:
      rows, *_ = self.capture(module, 'worker-main', SimpleNamespace(__traceback__=trace))
      self.assertEqual(len(rows), 1)
      self.assertNotIn(b'fault', rows[0]); self.assertNotIn(b'PRIVATE', b''.join(rows))

  def test_line_bounds_and_require_frame_filter(self):
    trace = None
    for line, function in [(100000, 'PRIVATE_FN'), (99999, 'PRIVATE_FN'), (0, 'PRIVATE_FN'), (33, 'require')]:
      trace = SimpleNamespace(tb_frame=SimpleNamespace(f_code=SimpleNamespace(
        co_filename='/PRIVATE_PATH/guardian_client.py', co_name=function)), tb_lineno=line, tb_next=trace)
    for module in [self.worker, self.reaper]:
      rows, *_ = self.capture(module, 'worker-main', SimpleNamespace(__traceback__=trace))
      self.assertEqual(len(rows), 2)
      self.assertIn(b'file=guardian_client.py line=99999', rows[1])
      self.assertNotIn(b'PRIVATE', b''.join(rows))

  def actual_child(self, action, *, fail_write=False):
    import time
    with tempfile.TemporaryDirectory(prefix='shield-worker-diagnostic-') as tmp:
      root = Path(tmp); sink = root / 'kmsg'; sink.touch(mode=0o600)
      pid = os.fork()
      if pid == 0:
        real_open, real_stat, real_write = os.open, os.fstat, os.write
        kmsg_fds = set()
        def opened(path, flags, *args, **kwargs):
          if path == '/dev/kmsg':
            fd = real_open(sink, os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK | os.O_CLOEXEC)
            kmsg_fds.add(fd); return fd
          return real_open(path, flags, *args, **kwargs)
        def stated(fd): return self.device() if fd in kmsg_fds else real_stat(fd)
        def written(fd, raw):
          if fail_write and fd in kmsg_fds: raise BlockingIOError(11, 'PRIVATE_IO_FAILURE')
          return real_write(fd, raw)
        try:
          with patch.object(os, 'open', side_effect=opened), patch.object(os, 'fstat', side_effect=stated), \
               patch.object(os, 'write', side_effect=written):
            action(root)
        except SystemExit as error:
          os._exit(error.code if type(error.code) is int and 0 <= error.code <= 255 else 1)
        except BaseException:
          os._exit(1)
        os._exit(0)
      deadline = time.monotonic() + 5
      while True:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed:
          self.assertTrue(os.WIFEXITED(status))
          self.assertFalse((root / 'UNWOUND').exists())
          return os.WEXITSTATUS(status), sink.read_bytes()
        if time.monotonic() >= deadline:
          os.kill(pid, 9); os.waitpid(pid, 0)
          self.fail('Owned diagnostic fixture child did not exit within five seconds')
        time.sleep(0.01)

  def entrypoint(self, name, *, import_failure=False):
    def action(root):
      import builtins
      import runpy
      original = builtins.__import__
      denied = 'guardian_binding' if name == 'maintenance-worker' else 'native_boot_context'
      def imported(module, *args, **kwargs):
        if import_failure and module == denied: raise ModuleNotFoundError('PRIVATE_IMPORT_FAILURE')
        return original(module, *args, **kwargs)
      with patch.object(sys, 'argv', [str(TOOLS / (name + '.py')), '--invalid-fixture']), \
           patch.object(builtins, '__import__', side_effect=imported):
        runpy.run_path(str(TOOLS / (name + '.py')), run_name='__main__')
    return action

  def test_actual_worker_main_refusal_keeps_exit75_and_reports_site(self):
    status, raw = self.actual_child(self.entrypoint('maintenance-worker'))
    self.assertEqual(status, 75); self.assertIn(b'stage=worker-main', raw)
    self.assertIn(b'file=maintenance-worker.py', raw); self.assertNotIn(b'PRIVATE', raw)

  def test_actual_reaper_main_refusal_keeps_exit65_and_reports_site(self):
    status, raw = self.actual_child(self.entrypoint('native_worker_reaper'))
    self.assertEqual(status, 65); self.assertIn(b'stage=reaper-main', raw)
    self.assertIn(b'file=native_worker_reaper.py', raw)

  def test_actual_import_faults_retain_uncaught_exit1_and_report_stage(self):
    for name in ['maintenance-worker', 'native_worker_reaper']:
      status, raw = self.actual_child(self.entrypoint(name, import_failure=True))
      self.assertEqual(status, 1); self.assertIn(b'stage=worker-import', raw)
      self.assertNotIn(b'PRIVATE', raw)

  def test_actual_command_spawn_fault_exits75_without_unwinding(self):
    def action(root):
      with patch.object(self.worker, 'WORK', root), patch.object(self.worker, 'now', return_value=1_000_000_000), \
           patch.object(self.worker.subprocess, 'Popen', side_effect=PermissionError(13, 'PRIVATE_SPAWN_FAILURE')):
        run = self.worker.Execute(frozenset({('btrfs', 'filesystem', 'sync', '/FIXED')}), lambda: None)
        try: run(['btrfs', 'filesystem', 'sync', '/FIXED'])
        finally: (root / 'UNWOUND').touch()
    status, raw = self.actual_child(action)
    self.assertEqual(status, 75); self.assertIn(b'stage=worker-command', raw)
    self.assertIn(b'errno=13', raw); self.assertNotIn(b'PRIVATE', raw)

  def command_rows(self, metadata, **kwargs):
    rows, opened, output, closed = self.capture(self.worker, 'worker-command',
      ValueError('PRIVATE_EXCEPTION'), command=metadata, **kwargs)
    self.assertNotIn(b'PRIVATE', b''.join(rows))
    self.assertTrue(all(len(row) <= 240 for row in rows))
    return [row for row in rows if row.startswith(b'<3>shield-worker-command ')], opened, output, closed

  def test_exact_sorted_sealed_command_identity_without_argv_or_output(self):
    arguments = ['z-PRIVATE_COMMAND', '/PRIVATE_PATH']
    sealed = frozenset({tuple(arguments), ('a-PRIVATE_OTHER',)})
    rows, opened, output, closed = self.command_rows((sealed, arguments, 7, 23))
    self.assertEqual(rows, [b'<3>shield-worker-command index=2 count=2 ordinal=7 status=23\n'])
    opened.assert_called_once_with('/dev/kmsg', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    closed.assert_called_once_with(77)

  def test_unsealed_or_ambiguous_command_metadata_has_no_numeric_identity(self):
    args = ['PRIVATE_ARG']; valid = frozenset({tuple(args)})
    cases = [None, (), (valid,), [valid, args, 1, 1],
      (set(valid), args, 1, 1), (frozenset(), args, 1, 1),
      (frozenset({('OTHER',)}), args, 1, 1),
      (frozenset({('PRIVATE_ARG', 1)}), args, 1, 1),
      (frozenset({(str(i),) for i in range(129)}), ['1'], 1, 1)]
    for metadata in cases:
      rows, *_ = self.command_rows(metadata)
      if metadata is None:
        self.assertEqual(rows, [])
      else:
        self.assertEqual(len(rows), 1)
        self.assertIn(b'index=unknown count=unknown', rows[0])

  def test_child_status_reports_only_bounded_plain_actual_integers(self):
    for observed, expected in [(-64, '-64'), (-9, '-9'), (0, '0'), (255, '255'),
      (-65, 'unknown'), (256, 'unknown'), (True, 'unknown'), (None, 'unknown'), ('PRIVATE', 'unknown')]:
      rows, *_ = self.command_rows((frozenset({('fixed',)}), ['fixed'], 1, observed))
      self.assertIn(('status=' + expected + '\n').encode(), rows[0])

  def test_attempt_counter_limits_are_diagnostic_only(self):
    for ordinal, expected in [(1, '1'), (1024, '1024'), (0, 'unknown'), (1025, 'unknown'),
      (True, 'unknown'), ('PRIVATE', 'unknown')]:
      rows, *_ = self.command_rows((frozenset({('fixed',)}), ['fixed'], ordinal, 1))
      self.assertIn(('ordinal=' + expected + ' ').encode(), rows[0])

  def test_other_failure_stages_do_not_emit_command_identity(self):
    rows, *_ = self.capture(self.worker, 'worker-main', ValueError('PRIVATE'),
      command=(frozenset({('fixed',)}), ['fixed'], 1, 23))
    self.assertNotIn(b'shield-worker-command ', b''.join(rows))

  def test_command_record_partial_write_never_retries(self):
    rows, opened, output, closed = self.command_rows(
      (frozenset({('fixed',)}), ['fixed'], 1, -9), written=1)
    self.assertEqual(len(rows), 1)
    self.assertEqual(output.call_count, 2)  # Base failure and command identity, one attempt each.
    closed.assert_called_once_with(77)

  def test_command_record_cannot_bypass_device_ownership_or_io_failure(self):
    metadata = (frozenset({('fixed',)}), ['fixed'], 1, 23)
    rows, opened, output, closed = self.command_rows(metadata, device=self.device(st_uid=1))
    self.assertEqual(rows, []); output.assert_not_called(); closed.assert_called_once_with(77)
    with patch.object(self.worker.os, 'open', side_effect=BlockingIOError(11, 'PRIVATE')):
      self.worker.worker_diagnostic('worker-command', ValueError('PRIVATE'), command=metadata)

  def test_actual_nonzero_child_status_is_recorded_before_immediate_exit75(self):
    for initial_counter, expected_ordinal in [(0, b'1'), (1024, b'unknown')]:
      def action(root):
        import ctypes
        original = self.worker.subprocess.Popen
        arguments = ['btrfs', 'subvolume', 'get-default', '/FIXED']
        owner = os.getpid()
        libc = ctypes.CDLL(None, use_errno=True)
        def parent_owned():
          # The outer five-second fixture bound can kill this worker. Bind the
          # real command child to its lifetime before exec, including the race.
          if libc.prctl(1, 9, 0, 0, 0) != 0 or os.getppid() != owner:
            os._exit(2)
        def spawn(argv, **kwargs):
          self.assertEqual(argv, ['/usr/bin/btrfs', *arguments[1:]])
          return original([sys.executable, '-c', 'import sys; sys.exit(23)'],
            preexec_fn=parent_owned, **kwargs)
        with patch.object(self.worker, 'WORK', root), patch.object(self.worker, 'now', return_value=1_000_000_000), \
             patch.object(self.worker.subprocess, 'Popen', side_effect=spawn):
          run = self.worker.Execute(frozenset({tuple(arguments), ('btrfs', 'filesystem', 'sync', '/FIXED')}), lambda: None)
          run.attempted = initial_counter
          try: run(arguments)
          finally: (root / 'UNWOUND').touch()
      status, raw = self.actual_child(action)
      self.assertEqual(status, 75)
      self.assertIn(b'shield-worker-command index=2 count=2 ordinal=' + expected_ordinal + b' status=23\n', raw)
      self.assertNotIn(b'/FIXED', raw); self.assertNotIn(b'PRIVATE', raw)

  def test_actual_child_exec_fault_keeps_exit70_after_stopped_assignment(self):
    def action(root):
      import signal
      log = os.open(root / 'worker.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
      with patch.object(self.reaper.os, 'execve', side_effect=FileNotFoundError(2, 'PRIVATE_EXEC_FAILURE')):
        leader = self.reaper.stopped_worker(log)
        os.close(log)
        observed, status = os.waitpid(leader, os.WUNTRACED)
        if observed != leader or not os.WIFSTOPPED(status): os._exit(2)
        os.kill(leader, signal.SIGCONT)
        observed, status = os.waitpid(leader, 0)
        os._exit(os.WEXITSTATUS(status) if observed == leader and os.WIFEXITED(status) else 2)
    status, raw = self.actual_child(action)
    self.assertEqual(status, 70); self.assertIn(b'stage=worker-exec', raw)
    self.assertIn(b'errno=2', raw); self.assertNotIn(b'PRIVATE', raw)

  def test_actual_diagnostic_write_fault_cannot_replace_worker_exit75(self):
    status, raw = self.actual_child(self.entrypoint('maintenance-worker'), fail_write=True)
    self.assertEqual(status, 75); self.assertEqual(raw, b'')




@unittest.skipUnless(os.getuid() == os.geteuid() == 0, 'Intended root-owned claim fixture')
class AuditedCompletedPreparationTests(unittest.TestCase):
  """Synthetic closed proofs; bundle admission/physical observer/owned unit are mocked.

  MAC decoding, proof cross-links, private claim IO and continuation lifetime
  checks are real. No actual hardware, retained owner secrets or device calls.
  """
  def setUp(self):
    from contextlib import ExitStack
    import native_attempt_journal as journal
    import native_control_protocol as protocol
    from native_boot_context import freeze
    from native_host_controller import SOURCE_MINIMUM
    from native_host_link import MAINTENANCE_FIELDS
    from native_recovery_observer import Baseline, Observer
    self.J, self.P = journal, protocol
    self.stack = ExitStack(); self.addCleanup(self.stack.close)
    temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='closed-a-fixture-'))
    self.parent = Path(temporary); os.chmod(self.parent, 0o700)
    self.attempt = self.parent / 'old/capsule-A/native-attempt'
    self.data, self.artifacts = {}, {}
    self.special = {
      'predecessor': self.attempt / 'predecessor.json',
      'publication': self.attempt / 'publication.json',
      'recovery': self.attempt / 'recovery-observation.json',
      'frame': self.attempt / 'transport/early/maintenance.sncp1',
      'bundle': self.attempt.parent / 'boot.json', 'early_key': self.attempt.parent / 'early.key'}
    def pinned(raw, path):
      item = {'path': str(path), 'bytes': len(raw), 'sha256': self.sha(raw)}
      self.data[str(path)] = raw
      return item
    self.pinned = pinned
    def put(name, value, raw=False):
      body = value if raw else journal.canonical(value)
      item = pinned(body, self.special.get(name, self.parent / 'sealed' / (name + '.json')))
      self.artifacts[name] = item
      return item
    self.put = put
    self.cid = 'a' * 32; self.fsid = '11111111-2222-4333-8444-555555555555'
    self.serial = 'synthetic-shield'; self.key = b'k' * 32
    context = protocol.Context('1' * 64, 'packages', '2' * 64, '3' * 64)
    self.context = context
    baseline = {'utc': 'synthetic', 'board': 'darcy A04 original T210 A02',
      'historical_native80_and_older_controllers': [], 'current_context_result': 'fixture',
      'autonomous_modern_boot': False,
      'LNX': {'index': 18, 'bytes': 26738688, 'sha256': 'a' * 64, 'role': 'synthetic LNX'},
      'SOS': {'index': 16, 'bytes': 26738688, 'sha256': 'b' * 64, 'role': 'synthetic SOS'}}
    baseline_raw = journal.canonical(baseline)
    self.baseline = Baseline(baseline_raw, self.sha(baseline_raw))
    adb_sha = 'c' * 64
    critical = {name: {**{k: row[k] for k in ['index', 'bytes', 'sha256']},
      'block_identity': {'fixture': True}} for name, row in self.baseline.partitions.items()}
    self.scope = {'baseline_sha256': self.baseline.expected_sha256, 'adb_sha256': adb_sha,
      'USB': {'vid': '18D1', 'pid': 'D001', 'serial_sha256': self.sha(self.serial.encode('ascii'))}}
    self.put('execution_scope', self.scope)
    self.put('bundle', {'synthetic_boot_bundle': True, 'key_sha256': {'early': self.sha(self.key)}})
    self.put('early_key', self.key, raw=True)
    original = {}; default = {'id': 256, 'top_level': 5, 'path': '@'}
    payload = {'candidate_id': self.cid, 'filesystem_uuid': self.fsid}
    plan = {'maintenance': {**payload, 'base_account_preimages': original}, 'original_default': default}
    self.put('phase_a_payload', (json.dumps(payload, indent=2) + chr(10)).encode('ascii'), raw=True)
    self.put('phase_a_plan', plan)
    inputs = {name: {'sha256': self.artifacts[artifact]['sha256']} for name, artifact in
              [('plan', 'phase_a_plan'), ('payload', 'phase_a_payload')]}
    self.configuration = {'phase': 'packages', 'inputs': inputs}
    old_sources, snapshots = {}, {}
    for name in sorted(SOURCE_MINIMUM):
      raw = ('synthetic closed source ' + name).encode('ascii')
      item = pinned(raw, self.parent / 'old-source' / name)
      old_sources[name] = item['sha256']; snapshots[name] = item
    self.put('old_source_snapshot', {'old_source_sha256': old_sources, 'sources': snapshots})
    self.put('assembly_receipt', {'source_sha256': old_sources, 'files': {
      name: {'sha256': self.artifacts[artifact]['sha256'], 'bytes': self.artifacts[artifact]['bytes']}
      for name, artifact in [('boot.json', 'bundle'), ('early.key', 'early_key')]}})
    observations = {name: True for name in MAINTENANCE_FIELDS}
    observations.update(kind='maintenance-released', phase='packages', **payload,
      payload_manifest_sha256=inputs['payload']['sha256'], plan_sha256=inputs['plan']['sha256'],
      original_default=default, worker_result_sha256='d' * 64, journal_sha256='e' * 64,
      nonce='f' * 64, boottime_ns=1, cleanup_deadline_ns=10**9,
      boot_ready=False, physical_powerloss_qualified=False)
    self.observations = observations
    native_boot = '11111111-2222-4333-8444-555555555555'
    envelope = {'context': context.as_dict(), 'boot_id': native_boot, 'direction': 'native',
      'seq': 3, 'kind': 'EVIDENCE', 'payload': {'observations': observations}}
    self.envelope = envelope
    wire, _record = protocol._encode(self.key, envelope)
    self.put('frame', wire, raw=True)
    recovery = {'format_version': 1, 'purpose': 'secure SOS return observation',
      'route': 'recovery', 'secure_adb_root_observed': True,
      'baseline_sha256': self.baseline.expected_sha256, 'adb_sha256': adb_sha,
      'native_boot_id': native_boot, 'native_epoch': 'early', 'native_session_id': context.session_id,
      'native_configuration_sha256': context.config_sha256, 'evidence_sha256': self.sha(wire),
      'boot_id': '22222222-2222-4333-8444-555555555555',
      'initial_boot_id': '33333333-2222-4333-8444-555555555555',
      'critical_partitions': critical, 'device': 'darcy', 'kernel_release': '4.9.141-g9d1bd583388e',
      'boot_ready': False}
    self.put('recovery', recovery)
    predecessor = {'format_version': 1, 'purpose': 'native preparation completion',
      'state': 'RELEASED_AND_RECOVERED', 'phase': 'packages', **payload,
      'payload_manifest_sha256': inputs['payload']['sha256'], 'plan_sha256': inputs['plan']['sha256'],
      'guardian_candidate': context.candidate, 'boot_id': native_boot,
      'configuration_sha256': context.config_sha256, 'session_id': context.session_id,
      'evidence_sha256': self.sha(wire), 'journal_sha256': observations['journal_sha256'],
      'worker_result_sha256': observations['worker_result_sha256'], 'original_default': default,
      'clean_usb_release': True, 'authenticated_recovery_observed': True,
      'recovery_observation_sha256': self.artifacts['recovery']['sha256'],
      'boot_ready': False, 'physical_powerloss_qualified': False}
    self.put('predecessor', predecessor)
    publication = {'format_version': 1, 'purpose': 'durably published native preparation observations',
      'phase': 'packages', 'configuration_sha256': context.config_sha256, 'session_id': context.session_id,
      'predecessor_sha256': self.artifacts['predecessor']['sha256'],
      'recovery_observation_sha256': self.artifacts['recovery']['sha256'],
      'publication_observed_ns': 10, 'publication_deadline_ns': 20,
      'boot_ready': False, 'physical_powerloss_qualified': False}
    self.put('publication', publication)
    layer = {'archive_sha256': '5' * 64, 'archive_bytes': 1, 'manifest_sha256': '7' * 64,
      'profile_sha256': '8' * 64, 'payload_manifest_sha256': inputs['payload']['sha256'], 'sources': []}
    old_layer = {k: layer[k] for k in ['archive_sha256', 'manifest_sha256', 'profile_sha256', 'payload_manifest_sha256']}
    old_layer.update(archive_sha256='4' * 64, manifest_sha256='6' * 64)
    witness = {'format_version': 1, 'purpose': 'read-only VM expected-A content witness', **payload,
      'layer': old_layer, 'original_accounts': original,
      'original_accounts_sha256': self.sha(journal.canonical(original)),
      'roots': {}, 'entries': {'synthetic': None}, 'source_mounted_readonly': True,
      'physical_preimages_admitted': False, 'boot_ready': False}
    self.put('old_witness', witness)
    self.put('new_witness', {**witness, 'layer': {k: layer[k] for k in old_layer}})
    self.put('new_layer_pin', layer)
    self.put('execution_gate', {'state': 'REVIEWED', 'execution_release': True,
      'native_execution_released': True, 'physical_packages_only': True, 'boot_ready': False,
      'source_sha256': old_sources, 'execution_scope': self.artifacts['execution_scope'],
      'assembly_receipt_sha256': self.artifacts['assembly_receipt']['sha256'],
      'witness': self.artifacts['old_witness'], 'witness_layer_pin': old_layer})
    self.put('body_actual', {'actual_wait_exit': 1, 'positive_wait_observed': True,
      'owned_group_absent': True, 'unit_only_owner_remaining': True,
      'timed_out': False, 'interrupted': False, 'elapsed_seconds': 1})
    self.put('body_failure', {'actual_packages_publication_observed': True,
      'finalization_failed_after_valid_A_publication': True, 'replay_allowed': False, 'boot_ready': False,
      'error_type': 'ValueError', 'error': 'Ancestor-only destination requires exact existing identity'})
    self.put('body_publication', {'state': 'ACTUAL_PACKAGES_PREPARATION_PUBLISHED',
      'predecessor_sha256': self.artifacts['predecessor']['sha256'],
      'recovery_observation_sha256': self.artifacts['recovery']['sha256'],
      'publication_sha256': self.artifacts['publication']['sha256'],
      'directory': str(self.attempt), 'boot_ready': False})
    self.put('windows_owner', {'actualProcessHandleRetained': True,
      'positiveWslWaitObserved': True, 'wslActualExitCode': 1, 'ownerExitCode': 1, 'elapsedMs': 1})
    self.put('windows_launcher', {'actualOwnerHandleRetained': True,
      'positiveOwnerWaitObserved': True, 'actualOwnerExitCode': 1})
    closure = {'Windows_positive_handle_waits_and_actual_numeric_exits_verified': True,
      'Linux_positive_wait_PG_absence_sole_CG_verified': True, 'cgroup_absent': True,
      'packages_publication_observed_in_body': True, 'expected_preimages_and_WriterPin_absent': True,
      'no_physical_layer_written': True, 'B_C_or_permanent_boot_released': False, 'boot_ready': False}
    for name, artifact in [('gate', 'execution_gate'), ('predecessor', 'predecessor'), ('publication', 'publication'),
      ('recovery_observation', 'recovery'), ('body_actual', 'body_actual'), ('body_failure', 'body_failure'),
      ('Windows_owner_terminal', 'windows_owner'), ('Windows_launcher_terminal', 'windows_launcher')]:
      closure[name] = self.artifacts[artifact]
    self.put('root_closure', closure)
    self.put('actual_audit', {'closure': self.artifacts['root_closure'], 'outcome': {
      'actual_native_packages_phase_passed': True, 'clean_storage_release_and_new_secure_recovery_observed': True,
      'durable_A_publication_hash_chain_verified': True, 'overall_operator_exit': 1,
      'package_replay_allowed': False, 'same_live_HOST_finalization_succeeded': False,
      'WriterPin_or_expected_preimages_or_success_result_present': False}})
    migration = {'state': 'EXACT_OLD_TO_NEW_LAYER_CONTENT_ROLE_PROOF',
      'candidate_payload_filesystem_accounts_and_all_other_manifest_fields_equal': True,
      'old_witness_unchanged_and_not_retargeted': True, 'remaining_ancestor_only_mismatches': 0,
      'physical_preimages_admitted': False, 'writer_authority': False, 'native_release': False,
      'old_archive': {'path': 'old', 'sha256': old_layer['archive_sha256'], 'bytes': 1},
      'new_archive': {'path': 'new', 'sha256': layer['archive_sha256'], 'bytes': 1},
      'old_manifest_sha256': old_layer['manifest_sha256'], 'new_manifest_sha256': layer['manifest_sha256'],
      'entry_identities_equal': 1,
      'role_changes': ['etc/systemd/journald.conf.d', 'etc/systemd/system/user@1001.service.d'],
      'source_changes': ['tools/prepare-native-qualification-layer.py']}
    self.put('layer_migration_proof', migration)
    self.put('layer_migration_audit', {'compatibility_proof': self.artifacts['layer_migration_proof'],
      'old_archive_aggregate': migration['old_archive'], 'new_archive_aggregate': migration['new_archive']})
    self.put('new_witness_result', {'passed': True, 'qemu_exit': 0, 'console_EOF_observed': True,
      'both_backing_images_unchanged': True, 'guest_unmounted': True, 'media_writes': False,
      'transaction_replayed': False, 'physical_preimages_admitted': False, 'boot_ready': False,
      'witness_sha256': self.artifacts['new_witness']['sha256'],
      'witness_bytes': self.artifacts['new_witness']['bytes']})
    self.put('new_witness_audit', {'new_witness_aggregate': self.artifacts['new_witness'],
      'old_witness_aggregate': self.artifacts['old_witness'], 'host_result': self.artifacts['new_witness_result']})
    self.unit = 'shield-omarchy230-synthetic-tests.service'
    self.grant = {'format_version': 1,
      'purpose': 'resume audited completed packages after HOST finalization failure',
      'unit': self.unit, 'source_sha256': {'synthetic': '9' * 64}, 'artifacts': self.artifacts,
      'baseline_sha256': self.baseline.expected_sha256, 'adb_sha256': adb_sha,
      'target_serial_sha256': self.scope['USB']['serial_sha256'],
      'fresh_recovery_policy': 'same-target-baseline-any-recovery-boot',
      'claim_directory': str(self.parent / 'claim'),
      'native_execution_released': False, 'physical_preimages_admitted': False, 'boot_ready': False}
    self.cutoff = journal.now() + 60 * journal.SECOND
    self.observer = object.__new__(Observer)
    for name, value in {'baseline': self.baseline, 'serial': self.serial, 'adb_sha256': adb_sha,
      'deadline': self.cutoff, 'initial': None, 'returned': None,
      'initial_attempted': False, 'return_attempted': False}.items():setattr(self.observer, name, value)
    def inspect():
      self.observer.initial_attempted = True
      started = journal.now()
      value = {'format_version': 1, 'purpose': 'secure recovery identity observation', 'route': 'recovery',
        'secure_adb_root_observed': True, 'baseline_sha256': self.baseline.expected_sha256,
        'adb_sha256': adb_sha, 'boot_ready': False, 'critical_partitions': critical,
        'boot_id': '44444444-2222-4333-8444-555555555555', 'device': 'darcy',
        'kernel_release': '4.9.141-g9d1bd583388e',
        'started_monotonic_ns': started, 'observed_monotonic_ns': journal.now()}
      self.observer.initial = freeze(value)
      return self.observer.initial
    self.inspection = self.stack.enter_context(patch.object(Observer, 'inspect_initial', side_effect=inspect))
    self.stack.enter_context(patch.object(journal, 'ROOT', self.parent))
    self.stack.enter_context(patch.object(journal, 'source_check', side_effect=lambda pins: None))
    self.stack.enter_context(patch.dict(os.environ, {'INVOCATION_ID': 'a' * 32}))
    original_read = Path.read_text
    def read_text(path, *args, **kwargs):
      if path == Path('/proc/self/cgroup'):return '0::/system.slice/' + self.unit + '\n'
      return original_read(path, *args, **kwargs)
    self.stack.enter_context(patch.object(Path, 'read_text', read_text))
    import native_boot_context as boot
    import native_phase_coordinator as coordinator
    self.stack.enter_context(patch.object(boot, 'admit', return_value=(self.configuration, {'early': context})))
    def host_pin(item, maximum):
      raw = self.data[item['path']]
      if len(raw) != item['bytes'] or self.sha(raw) != item['sha256'] or not 0 < len(raw) <= maximum:
        raise ValueError('Synthetic private pin changed')
      return raw
    self.stack.enter_context(patch.object(coordinator, 'host_pin', side_effect=host_pin))

  @staticmethod
  def sha(raw):return hashlib.sha256(raw).hexdigest()

  def admit(self):
    raw = self.J.canonical(self.grant)
    return self.J.admit_audited_completed_preparation(raw, self.sha(raw), self.observer, self.cutoff)

  def mutate(self, name, **changes):
    value = json.loads(self.data[self.artifacts[name]['path']]);value.update(changes);self.put(name, value)

  def test_distinct_authority_uses_fresh_observer_without_constructing_Published(self):
    with patch.object(self.J, 'Published', side_effect=AssertionError('No Published reconstruction')):
      completed = self.admit()
    self.addCleanup(completed.close)
    self.assertIs(type(completed), self.J.AuditedCompletedPreparation)
    self.assertEqual(completed.predecessor_sha256, self.artifacts['predecessor']['sha256'])
    self.inspection.assert_called_once_with()
    self.assertEqual(completed.fresh_recovery_boot_relation, 'later-recovery-boot')
    self.assertTrue((self.parent / 'claim/FRESH_RECOVERY.json').is_file())
    self.assertNotIn('predecessor_raw', repr(completed))

  def test_formatted_payload_is_admitted_without_changing_its_original_hash(self):
    raw = self.data[self.artifacts['phase_a_payload']['path']]
    self.assertNotEqual(raw, self.J.canonical(json.loads(raw)))
    completed = self.admit();self.addCleanup(completed.close)
    self.assertEqual(json.loads(completed.predecessor_raw)['payload_manifest_sha256'], self.sha(raw))
    self.inspection.assert_called_once_with()

  def test_manual_authority_construction_is_refused(self):
    with self.assertRaises(TypeError):self.J.AuditedCompletedPreparation()

  def test_corrupted_MAC_stops_before_fresh_observation(self):
    raw = self.data[self.artifacts['frame']['path']]
    changed = raw[:-2] + (b'0' if raw[-2:-1] != b'0' else b'1') + raw[-1:]
    self.put('frame', changed, raw=True)
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()
    self.assertTrue((self.parent / 'claim/CLAIM.json').exists())

  def test_wrong_USB_target_fails_before_claim_or_observation(self):
    self.grant['target_serial_sha256'] = '0' * 64
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()
    self.assertFalse((self.parent / 'claim').exists())

  def test_expired_owner_cannot_be_admitted(self):
    self.cutoff = self.J.now() - 1; self.observer.deadline = self.cutoff
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()

  def test_incomplete_worker_fence_cannot_advance(self):
    self.mutate('body_actual', positive_wait_observed=False)
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()

  def test_changed_predicted_preimages_are_not_adopted(self):
    value = json.loads(self.data[self.artifacts['new_witness']['path']]);value['entries']['synthetic'] = {'changed': True}
    self.put('new_witness', value)
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()

  def test_other_HOST_failure_family_is_not_authorized_by_this_migration(self):
    self.mutate('body_failure', error_type='OSError', error='Synthetic other failure')
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()

  def test_unreviewed_fresh_recovery_policy_is_refused_before_claim(self):
    self.grant['fresh_recovery_policy'] = 'unreviewed'
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()
    self.assertFalse((self.parent / 'claim').exists())

  def test_foreign_migration_audit_binding_is_refused(self):
    self.mutate('layer_migration_audit', compatibility_proof={'path': 'foreign', 'bytes': 1, 'sha256': '0' * 64})
    with self.assertRaises(ValueError):self.admit()
    self.inspection.assert_not_called()

  def test_failed_fresh_recovery_consumes_claim_without_authority(self):
    self.inspection.side_effect = ValueError('Synthetic observer failure')
    with self.assertRaises(ValueError):self.admit()
    self.assertTrue((self.parent / 'claim/CLAIM.json').exists())
    with self.assertRaises(ValueError):self.admit()
    self.assertEqual(self.inspection.call_count, 1)

  def test_consumed_finalization_or_foreign_owner_cannot_be_reused(self):
    from native_layer_reader import LayerPin
    completed = self.admit();self.addCleanup(completed.close)
    value = json.loads(self.data[self.artifacts['new_layer_pin']['path']])
    value['sources'] = tuple(tuple(row) for row in value['sources'])
    layer = LayerPin(**value)
    completed.begin_finalization(self.artifacts['new_witness']['sha256'], layer)
    with self.assertRaises(ValueError):completed.begin_finalization(self.artifacts['new_witness']['sha256'], layer)
    with patch.object(os, 'getpid', return_value=os.getpid() + 1):
      with self.assertRaises(ValueError):completed.owner_check()



  def test_resume_finalizer_passes_real_writer_admission_and_stays_live_path_distinct(self):
    from dataclasses import asdict, replace
    import test_native_layer_writer as filesystem_fixtures
    from native_layer_reader import LayerContent, freeze
    import native_layer_writer as writer
    fs = filesystem_fixtures.LayerWriterFilesystemTests()
    fs.setUp(); self.addCleanup(fs.doCleanups)
    manifest = writer.plain(fs.content.manifest)
    manifest['payload_manifest_sha256'] = self.artifacts['phase_a_payload']['sha256']
    layer = replace(fs.layer_pin, payload_manifest_sha256=manifest['payload_manifest_sha256'],
      manifest_sha256=self.sha(writer.canonical(manifest)))
    content = LayerContent(freeze(manifest), fs.content.blob_ranges, fs.content.raw_tar)
    plan = json.loads(self.data[self.artifacts['phase_a_plan']['path']])
    plan['maintenance']['base_account_preimages'] = fs.profile['original_accounts']
    self.put('phase_a_plan', plan)
    self.configuration['inputs']['plan']['sha256'] = self.artifacts['phase_a_plan']['sha256']
    self.observations['plan_sha256'] = self.artifacts['phase_a_plan']['sha256']
    wire, _record = self.P._encode(self.key, self.envelope);self.put('frame', wire, raw=True)
    recovery = json.loads(self.data[self.artifacts['recovery']['path']])
    recovery['evidence_sha256'] = self.artifacts['frame']['sha256'];self.put('recovery', recovery)
    predecessor = json.loads(self.data[self.artifacts['predecessor']['path']])
    predecessor.update(plan_sha256=self.artifacts['phase_a_plan']['sha256'],
      evidence_sha256=self.artifacts['frame']['sha256'],
      recovery_observation_sha256=self.artifacts['recovery']['sha256'])
    self.put('predecessor', predecessor)
    publication = json.loads(self.data[self.artifacts['publication']['path']])
    publication.update(predecessor_sha256=self.artifacts['predecessor']['sha256'],
      recovery_observation_sha256=self.artifacts['recovery']['sha256']);self.put('publication', publication)
    old_projection = {k: getattr(layer, k) for k in ['archive_sha256', 'manifest_sha256',
      'profile_sha256', 'payload_manifest_sha256']}
    old_projection.update(archive_sha256='4' * 64, manifest_sha256='6' * 64)
    witness = {'format_version': 1, 'purpose': preimages.WITNESS_PURPOSE,
      'candidate_id': self.cid, 'filesystem_uuid': self.fsid, 'layer': old_projection,
      'original_accounts': fs.profile['original_accounts'],
      'original_accounts_sha256': fs.profile['original_accounts_sha256'],
      'roots': fs.profile['roots'], 'entries': fs.expected,
      'source_mounted_readonly': True, 'physical_preimages_admitted': False, 'boot_ready': False}
    self.put('old_witness', witness)
    self.put('new_witness', {**witness, 'layer': {k: getattr(layer, k) for k in old_projection}})
    self.put('new_layer_pin', asdict(layer))
    execution = json.loads(self.data[self.artifacts['execution_gate']['path']])
    execution.update(witness=self.artifacts['old_witness'], witness_layer_pin=old_projection)
    self.put('execution_gate', execution)
    body = json.loads(self.data[self.artifacts['body_publication']['path']])
    body.update(predecessor_sha256=self.artifacts['predecessor']['sha256'],
      recovery_observation_sha256=self.artifacts['recovery']['sha256'],
      publication_sha256=self.artifacts['publication']['sha256']);self.put('body_publication', body)
    closure = json.loads(self.data[self.artifacts['root_closure']['path']])
    for key, artifact in [('gate', 'execution_gate'), ('predecessor', 'predecessor'),
                         ('publication', 'publication'), ('recovery_observation', 'recovery')]:
      closure[key] = self.artifacts[artifact]
    self.put('root_closure', closure)
    audit = json.loads(self.data[self.artifacts['actual_audit']['path']])
    audit['closure'] = self.artifacts['root_closure'];self.put('actual_audit', audit)
    migration = json.loads(self.data[self.artifacts['layer_migration_proof']['path']])
    migration.update(new_archive={'path': 'new', 'sha256': layer.archive_sha256, 'bytes': layer.archive_bytes},
      new_manifest_sha256=layer.manifest_sha256, entry_identities_equal=len(fs.expected))
    self.put('layer_migration_proof', migration)
    self.put('layer_migration_audit', {'compatibility_proof': self.artifacts['layer_migration_proof'],
      'old_archive_aggregate': migration['old_archive'], 'new_archive_aggregate': migration['new_archive']})
    result = json.loads(self.data[self.artifacts['new_witness_result']['path']])
    result.update(witness_sha256=self.artifacts['new_witness']['sha256'],
      witness_bytes=self.artifacts['new_witness']['bytes']);self.put('new_witness_result', result)
    self.put('new_witness_audit', {'new_witness_aggregate': self.artifacts['new_witness'],
      'old_witness_aggregate': self.artifacts['old_witness'], 'host_result': self.artifacts['new_witness_result']})
    with patch.object(self.J, 'Published', side_effect=AssertionError('No Published reconstruction')):
      completed = self.admit();self.addCleanup(completed.close)
      raw_witness = self.data[self.artifacts['new_witness']['path']]
      with self.assertRaises(ValueError):
        preimages.finalize(raw_witness, self.sha(raw_witness), content, layer, completed,
          self.artifacts['phase_a_plan']['sha256'], witness['original_accounts_sha256'])
      raw, pin = preimages.finalize_audited_completed(raw_witness, self.sha(raw_witness), content,
        layer, completed, self.artifacts['phase_a_plan']['sha256'], witness['original_accounts_sha256'])
    admitted = writer.admit(content, pin, raw)
    self.assertEqual(json.loads(raw)['entries'], fs.expected)
    self.assertEqual(pin.phase_a_receipt_sha256, self.artifacts['predecessor']['sha256'])
    self.assertTrue((self.parent / 'claim/FINALIZATION_VALIDATED.json').is_file())
    with self.assertRaises(ValueError):completed.owner_check()
    self.assertFalse((fs.journal / filesystem_fixtures.CID).exists())


if __name__ == '__main__': unittest.main()


class OwnedStagingTransportTests(unittest.TestCase):
  # Real Linux child pipes exercise the ownership/EOF state machine. They are
  # not Windows/ADB/device qualification; that remains a separate probe.
  CHILD = r"""import base64,hashlib,os,select,sys,time
n=int(sys.argv[1]);ack=base64.b64decode(sys.argv[2]);mode=sys.argv[3]
if mode=='early':
 os.write(1,ack);time.sleep(30);sys.exit(0)
wire=bytearray()
while len(wire)<n:
 block=os.read(0,min(65536,n-len(wire)))
 if not block:sys.exit(71)
 wire.extend(block)
raw=base64.b64decode(wire,validate=True)
if hashlib.sha256(raw).hexdigest()!=sys.argv[4]:sys.exit(72)
if mode=='missing':sys.exit(0)
if mode=='wait':os.read(0,1);sys.exit(73)
# The sender must still hold stdin open after all wire bytes, before ACK.
if select.select([0],[],[],0)[0]:sys.exit(74)
if mode=='wrong':os.write(1,b'wrong acknowledgement\n');sys.exit(0)
if mode=='stderr':os.write(2,b'owned-test-stderr')
os.write(1,ack.replace(b'\n',b'\r\n') if mode=='crlf' else ack)
if mode=='duplicate':os.write(1,ack)
if os.read(0,1)!=b'':sys.exit(75)
sys.exit(23 if mode=='nonzero' else 0)
"""

  def fixture(self, mode='ok', size=2*1024**2+17):
    raw=(bytes(range(256))*((size+255)//256))[:size]
    wire=base64.b64encode(raw)
    checksum=hashlib.sha256(raw).hexdigest()
    ack=('SHIELD_STAGE_INPUT_CONFIRMED '+str(len(raw))+' '+checksum+'\n').encode('ascii')
    argv=['/usr/bin/python3','-I','-S','-B','-c',self.CHILD,str(len(wire)),
      base64.b64encode(ack).decode('ascii'),mode,checksum]
    return wire,ack,argv

  def run_input(self, mode, seconds=4, size=2*1024**2+17):
    import native_phase_coordinator as c
    wire,ack,argv=self.fixture(mode,size)
    return c.run_owned(argv,c.now()+int(seconds*c.SECOND),data=wire,input_ack=ack,budget=8192)

  def test_complete_decoded_all_byte_values_ACK_precedes_EOF_and_actual_zero(self):
    stdout,stderr=self.run_input('ok')
    self.assertEqual(stdout,self.fixture()[1]);self.assertEqual(stderr,b'')

  def test_external_CRLF_ACK_has_same_single_line_meaning(self):
    stdout,stderr=self.run_input('crlf')
    self.assertEqual(stdout,self.fixture()[1].replace(b'\n',b'\r\n'));self.assertEqual(stderr,b'')

  def test_local_zero_without_remote_ACK_is_reaped_and_refused(self):
    import native_phase_coordinator as c
    with self.assertRaises(c.OwnedClientError) as raised:self.run_input('missing')
    error=raised.exception
    self.assertEqual(error.actual_wait_exit,0);self.assertTrue(error.positive_wait_observed)
    self.assertFalse(error.input_ack_observed);self.assertEqual(error.stdout,b'')
    self.assertEqual(error.input_bytes_written,len(self.fixture('missing')[0]))

  def test_early_ACK_cannot_authorize_unsent_tail(self):
    import native_phase_coordinator as c
    with self.assertRaises(c.OwnedClientError) as raised:self.run_input('early')
    error=raised.exception
    self.assertTrue(error.positive_wait_observed);self.assertFalse(error.input_ack_observed)
    self.assertLess(error.input_bytes_written,len(self.fixture('early')[0]))

  def test_wrong_or_duplicate_ACK_is_never_a_success(self):
    import native_phase_coordinator as c
    for mode in ['wrong','duplicate']:
      with self.subTest(mode=mode),self.assertRaises(c.OwnedClientError) as raised:self.run_input(mode)
      self.assertTrue(raised.exception.positive_wait_observed)

  def test_nonzero_after_valid_ACK_preserves_actual_status_and_no_replay(self):
    import native_phase_coordinator as c
    with self.assertRaises(c.OwnedClientError) as raised:self.run_input('nonzero')
    error=raised.exception
    self.assertEqual(error.actual_wait_exit,23);self.assertTrue(error.positive_wait_observed)
    self.assertTrue(error.input_ack_observed);self.assertEqual(error.stdout,self.fixture('nonzero')[1])

  def test_stderr_after_valid_ACK_is_preserved_and_refused(self):
    import native_phase_coordinator as c
    with self.assertRaises(c.OwnedClientError) as raised:self.run_input('stderr')
    error=raised.exception
    self.assertEqual(error.actual_wait_exit,0);self.assertTrue(error.input_ack_observed)
    self.assertEqual(error.stderr,b'owned-test-stderr')

  def test_missing_ACK_deadline_closes_only_owned_child_without_input_retry(self):
    import native_phase_coordinator as c
    wire,ack,argv=self.fixture('wait',4096)
    original=subprocess.Popen
    with patch.object(c.subprocess,'Popen',wraps=original) as started:
      with self.assertRaises(c.OwnedClientError) as raised:
        c.run_owned(argv,c.now()+c.SECOND//2,data=wire,input_ack=ack,budget=8192)
    self.assertEqual(started.call_count,1)
    error=raised.exception
    self.assertTrue(error.positive_wait_observed);self.assertFalse(error.input_ack_observed)
    self.assertEqual(error.input_bytes_written,len(wire));self.assertIsNotNone(error.actual_wait_exit)

  def test_unacknowledged_or_mixed_input_mode_is_refused_before_process_start(self):
    import native_phase_coordinator as c
    with patch.object(c.subprocess,'Popen') as started:
      for values in [{'data':b'input'},{'input_ack':b'ack\n'},
        {'data':b'input','input_ack':b'ack\n','readonly_until':b'event'}]:
        with self.subTest(values=values),self.assertRaises(ValueError):
          c.run_owned(['/usr/bin/python3'],c.now()+c.SECOND,**values)
      started.assert_not_called()

  def test_noninput_binary_capture_and_readonly_event_tail_keep_their_scope(self):
    import native_phase_coordinator as c
    out,err=c.run_owned(['/usr/bin/python3','-I','-S','-B','-c',
      'import os;os.write(1,bytes(range(256)))'],c.now()+3*c.SECOND)
    self.assertEqual(out,bytes(range(256)));self.assertEqual(err,b'')
    out,err=c.run_owned(['/usr/bin/python3','-I','-S','-B','-c',
      "import os,time;os.write(1,b'RUNNER_READY\\n');time.sleep(30)"],
      c.now()+3*c.SECOND,readonly_until=b'RUNNER_READY\n')
    self.assertEqual(out,b'RUNNER_READY\n');self.assertEqual(err,b'')

  def test_upload_preserves_client_flags_boot_guard_encoded_wire_and_finite_deadline(self):
    import native_phase_coordinator as c
    fake=SimpleNamespace(expected_legacy_boot='11111111-2222-4333-8444-555555555555',
      serial='TEST_ONLY',deadline=c.now()+120*c.SECOND,record=Mock(),client_failure=Mock())
    fake.guarded_legacy_command=lambda value:c.Coordinator.guarded_legacy_command(fake,value)
    raw=bytes(range(256))*257
    with patch.object(c,'run_owned',return_value=(b'ack',b'')) as run:
      marker,expected=c.Coordinator.upload(fake,'Image',raw)
    argv,cutoff=run.call_args.args;options=run.call_args.kwargs
    self.assertEqual(argv[3:7],['shell','-T','-e','none'])
    self.assertIn(fake.expected_legacy_boot,argv[-1]);self.assertIn('timeout -k 1 55',argv[-1])
    self.assertIn('/system/bin/toybox base64 -d',argv[-1])
    self.assertEqual(options['data'],base64.b64encode(raw))
    self.assertNotIn(b'\r',options['data']);self.assertNotIn(b'\n',options['data']);self.assertTrue(options['data'].isascii())
    self.assertEqual(options['input_ack'],('SHIELD_STAGE_INPUT_CONFIRMED '+str(len(raw))+' '+hashlib.sha256(raw).hexdigest()+'\n').encode())
    self.assertLessEqual(cutoff,fake.deadline);self.assertEqual(marker,c.RAM+'/Image.closed')
    fake.record.assert_called_once();fake.client_failure.assert_not_called()

  def test_missing_shell_v2_refuses_before_memory_upload_or_RAM_directory_effects(self):
    import native_phase_coordinator as c
    fake=SimpleNamespace(stage_attempted=False,load_attempted=False,arm_attempted=False,
      shell=Mock(side_effect=lambda command,**kwargs:'0' if command=='cat /sys/kernel/kexec_loaded' else 'suspended'),
      adc=Mock(return_value=b'cmd\r\nstat_v2\r\n'),memory_guard=Mock(),check_ram_stage=Mock(),upload=Mock(),record=Mock())
    with self.assertRaisesRegex(ValueError,'requires shell_v2'):c.Coordinator.stage_load_arm(fake)
    fake.memory_guard.assert_not_called();fake.check_ram_stage.assert_not_called();fake.upload.assert_not_called()
    self.assertTrue(all('mkdir' not in call.args[0] for call in fake.shell.call_args_list))

  def test_private_failure_preview_is_bounded_and_keeps_actual_numeric_facts(self):
    import native_phase_coordinator as c
    error=c.OwnedClientError(ValueError('private'),23,True,b'x'*20000,b'y'*20000,123,False)
    fake=SimpleNamespace(journal=object(),deadline=c.now()+c.SECOND,record=Mock())
    c.Coordinator.client_failure(fake,'acknowledged-stage-Image',error)
    name,value=fake.record.call_args.args
    self.assertEqual(name,'owned-client-failure.json');self.assertEqual(value['actual_wait_exit'],23)
    self.assertEqual(value['stdout_bytes'],20000);self.assertEqual(value['stderr_bytes'],20000)
    self.assertEqual(len(value['stdout_preview_hex']),16384);self.assertEqual(len(value['stderr_preview_hex']),16384)
    self.assertLess(len(json.dumps(value).encode()),65536);self.assertFalse(value['replay_allowed'])


  def test_actual_ADB_feature_producer_is_one_name_per_LF_or_CRLF_line(self):
    from native_phase_coordinator import legacy_shell_features
    for ending in [b'\n',b'\r\n']:
      with self.subTest(ending=ending):
        raw=ending.join([b'cmd',b'shell_v2',b'stat_v2',b''])
        self.assertEqual(legacy_shell_features(raw),frozenset({'cmd','shell_v2','stat_v2'}))
    self.assertEqual(legacy_shell_features(b''),frozenset())

  def test_feature_parser_refuses_CSV_duplicate_blank_control_and_nonASCII_names(self):
    from native_phase_coordinator import legacy_shell_features
    for raw in [b'cmd,shell_v2\n',b'shell_v2\nshell_v2\n',b'shell_v2\n\n',
                b' shell_v2\n',b'shell_v2\r',b'\xff\n',None]:
      with self.subTest(raw=raw),self.assertRaises(ValueError):legacy_shell_features(raw)

  def test_multiline_shell_v2_admission_reaches_memory_guard_before_any_RAM_effect(self):
    import native_phase_coordinator as c
    fake=SimpleNamespace(stage_attempted=False,load_attempted=False,arm_attempted=False,
      shell=Mock(side_effect=lambda command,**kwargs:'0' if command=='cat /sys/kernel/kexec_loaded' else 'suspended'),
      adc=Mock(return_value=b'cmd\nshell_v2\nstat_v2\n'),record=Mock(),
      memory_guard=Mock(side_effect=ValueError('HOST_MEMORY_GUARD_STOP')),check_ram_stage=Mock(),upload=Mock())
    with self.assertRaisesRegex(ValueError,'HOST_MEMORY_GUARD_STOP'):c.Coordinator.stage_load_arm(fake)
    fake.memory_guard.assert_called_once();fake.check_ram_stage.assert_not_called();fake.upload.assert_not_called()
    self.assertTrue(all('mkdir' not in call.args[0] for call in fake.shell.call_args_list))
