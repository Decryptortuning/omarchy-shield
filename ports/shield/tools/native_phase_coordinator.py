"""Fixed outer owner of one qualified native preparation/systemd test boot.

No CLI or default release. A separately pinned current-cohort qualification
gate must be admitted before execute(). Unknown effects consume the boot-set
claim. No phase replay, flash, fastboot fallback or legacy-owner signal exists.
This source remains unqualified; settle/review the whole cohort before import.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import struct
import subprocess
import time

from native_attempt_journal import Journal, private_file, write_once
from native_boot_context import canonical, json_bytes, plain, sha
from native_host_controller import Attempt, Spec, source_check
from native_legacy_memory import review_segments
from native_recovery_observer import ADB, Baseline, Observer
from usb_root_profile import require

PORT = Path(__file__).resolve().parent.parent
PS = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
FDTGET = '/usr/bin/fdtget'
RAM = '/tmp/shield-native'
SECOND = 1_000_000_000
CLIENTS = ['54100000.tsecb', '54340000.vic', '54480000.nvdec', '544c0000.nvenc',
           '54500000.tsec', '54600000.isp', '54680000.isp']
FDT_PROPERTIES = [('/', 'compatible', 's'), ('/', 'nvidia,dtsfilename', 's'),
  ('/memory@80000000', 'reg', 'x'), ('/reserved-memory/iram-carveout', 'reg', 'x'),
  ('/reserved-memory/ramoops_carveout', 'reg', 'x'), ('/reserved-memory/fb0_carveout', 'reg', 'x'),
  ('/reserved-memory/vpr-carveout', 'size', 'x')]


def now(): return time.monotonic_ns()


def legacy_shell_text(raw):
  """Canonicalize only the external ADB shell text boundary, never binary I/O."""
  require(type(raw) is bytes, 'Legacy shell output must be bytes')
  text = raw.decode('ascii').replace('\r\n', '\n')
  require('\r' not in text, 'Bare carriage return in legacy shell text')
  return text.strip()


def legacy_shell_features(raw):
  """Current `adb features` CLI emits one opaque feature name per line."""
  require(type(raw) is bytes and len(raw) <= 8192, 'Invalid ADB feature output budget/type')
  text = raw.decode('ascii').replace('\r\n', '\n')
  require('\r' not in text, 'Bare carriage return in ADB features')
  rows = text.split('\n')
  if rows[-1] == '': rows.pop()
  require(len(rows) <= 256 and len(rows) == len(set(rows))
          and all(re.fullmatch('[A-Za-z0-9_.-]{1,128}', row) for row in rows),
          'Malformed one-feature-per-line ADB output')
  return frozenset(rows)


def legacy_available_bytes(text):
  # adb shell on the verified Windows/recovery route emits CRLF. Parse text
  # lines here; never normalize the binary exec-out byte streams.
  require(type(text) is str and text.isascii(), 'Invalid legacy memory text')
  lines = [line for line in text.splitlines() if line.startswith('MemAvailable:')]
  require(len(lines) == 1, 'Missing or duplicate legacy MemAvailable')
  match = re.fullmatch(r'MemAvailable:[ \t]+([0-9]+) kB', lines[0])
  require(match is not None and len(match[1]) <= 20, 'Malformed legacy MemAvailable')
  value = int(match[1]) * 1024
  require(value < 2**64, 'Legacy MemAvailable overflow')
  return value


def legacy_stage_command(name, size, expected_sha256):
  # A local pipe completion is not remote delivery. The sole staging wire
  # is base64 ASCII; decode to the original binary, verify and seal the
  # closed file, then emit the ACK before the host may close stdin.
  # A bounded reader exits after these exact immutable bytes. The shell waits
  # for that child and its redirected output to close before creating the
  # complete pending record before publishing its final name with a no-replace
  # hard link. Existence of the final marker must imply complete bytes, even
  # while the uploader's remote shell is still exiting. Keep the pending link as
  # evidence; only the marker has two links, never the staged artifact.
  # The private 0700 staging directory has one writer; explicit absence checks
  # reject preexisting directories/symlinks before ordinary ln can follow them.
  # Never wait for transport EOF to finish cat.
  require(type(name) is str and name in {'Image', 'initramfs.cpio.gz', 'board.dtb',
    'cmdline.txt', 'kexec', 'legacy-watchdog-exec', 'legacy-handoff.sh', 'legacy-boot-id'},
    'Unknown fixed staging artifact')
  require(type(size) is int and 0 < size <= 384 * 1024**2, 'Invalid staged byte count')
  sha(expected_sha256)
  encoded_size = 4 * ((size + 2) // 3)
  target = RAM + '/' + name
  marker = target + '.closed'
  pending = marker + '.pending'
  expected = 'NATIVE_STAGE_CLOSED_V1 ' + str(size) + ' ' + expected_sha256
  command = ('umask 077; set -C; /system/bin/toybox head -c ' + str(encoded_size) +
    ' | /system/bin/toybox base64 -d > ' + target +
    ' && test "$(/system/bin/toybox stat -c %s ' + target + ')" = ' + str(size) +
    ' && test "$(/system/bin/toybox sha256sum ' + target + ')" = ' +
    shlex.quote(expected_sha256 + '  ' + target) +
    " && printf '%s %s\\n' " + shlex.quote(expected) +
    ' "$(/system/bin/toybox stat -c \'%d %i\' ' + target + ')" > ' + pending +
    ' && test ! -e ' + marker + ' && test ! -L ' + marker +
    ' && /system/bin/toybox ln ' + pending + ' ' + marker +
    " && /system/bin/toybox printf '%s\\n' " + shlex.quote('SHIELD_STAGE_INPUT_CONFIRMED ' + str(size) + ' ' + expected_sha256))
  return command, marker, expected


def check(deadline):
  require(type(deadline) is int and 0 < now() < deadline, 'Outer phase deadline exhausted')


class OwnedClientError(ValueError):
  """Actual local client failure facts; never a remote completion or retry grant."""
  def __init__(self, cause, status, waited, stdout, stderr, written, acknowledged):
    super().__init__('Owned client failed; no effect replay')
    self.cause_type = type(cause).__name__
    self.actual_wait_exit, self.positive_wait_observed = status, waited
    self.stdout, self.stderr = stdout, stderr
    self.input_bytes_written, self.input_ack_observed = written, acknowledged


def run_owned(argv, cutoff, *, data=None, budget=1024**2, readonly_until=None, input_ack=None):
  """Own one bounded client. Binary input requires an explicit remote ACK.

  Keep stdin OPEN after the final local write until the complete remote ACK.
  A local pipe write/exit cannot establish remote delivery. Shell-v2 provides
  the ACK and remote exit on a separate output path; no exec-in fallback.
  """
  check(cutoff)
  require((data is None and input_ack is None) or
          (type(data) is bytes and len(data) > 0 and type(input_ack) is bytes
           and 0 < len(input_ack) <= 4096 and input_ack.isascii()
           and input_ack.endswith(b'\n') and input_ack.count(b'\n') == 1
           and b'\r' not in input_ack and readonly_until is None),
          'Binary input requires one exact remote acknowledgement')
  require(len(os.listdir('/proc/self/task')) == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
          'Owned client requires a single waitable process owner')
  process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
  outputs = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
  pending = set(outputs)
  input_fd = process.stdin.fileno() if data is not None else None
  cursor, acknowledged, waited, status = 0, False, False, None
  event_seen = False
  try:
    for fd in pending | ({input_fd} if input_fd is not None else set()): os.set_blocking(fd, False)
    while pending or input_fd is not None:
      check(cutoff)
      # Once all bytes are accepted locally, retain the descriptor but stop
      # selecting it for writes. EOF is released only after the remote ACK.
      writes = [input_fd] if input_fd is not None and cursor < len(data) else []
      reads, ready_writes, _ = select.select(list(pending), writes, [],
                                      min(0.25, max(0, (cutoff - now()) / SECOND)))
      check(cutoff)
      if input_fd is not None and input_fd in ready_writes:
        try: count = os.write(input_fd, data[cursor:cursor + 65536])
        except BlockingIOError: count = 0
        require(0 <= count <= min(65536, len(data) - cursor), 'Unknown staging write count')
        cursor += count
      for fd in reads:
        try: chunk = os.read(fd, min(65536, budget + 1 - len(outputs[fd])))
        except BlockingIOError: continue
        if not chunk: pending.remove(fd); continue
        outputs[fd].extend(chunk)
        require(len(outputs[fd]) <= budget, 'Owned client output budget')
      if input_ack is not None:
        observed = bytes(outputs[process.stdout.fileno()])
        # These are the same external LF/CRLF text boundary, not protocol versions.
        forms = (input_ack, input_ack.replace(b'\n', b'\r\n'))
        require(any(form.startswith(observed) for form in forms), 'Unexpected staging acknowledgement')
        if observed in forms:
          require(cursor == len(data), 'Acknowledgement preceded complete local input')
          acknowledged = True
          if input_fd is not None: process.stdin.close(); input_fd = None
        if not pending and not acknowledged and input_fd is not None:
          # Terminal output EOF without ACK is already a failed transfer.
          # Close input only for failure cleanup, then observe the natural
          # exit before classifying it. Do not race a zero exit with kill().
          process.stdin.close(); input_fd = None
      if readonly_until is not None and readonly_until in outputs[process.stdout.fileno()]:
        require(data is None, 'No early stop of an effectful input transfer')
        event_seen = True
        process.terminate()
        break
    check(cutoff)
    status = process.wait(timeout=min(2, max(0, (cutoff - now()) / SECOND)))
    waited = True
    check(cutoff)
    require(event_seen or status == 0, 'Owned client failed; no effect replay')
    require(data is None or (cursor == len(data) and acknowledged
            and not outputs[process.stderr.fileno()]), 'Unconfirmed staging input or stderr')
    return bytes(outputs[process.stdout.fileno()]), bytes(outputs[process.stderr.fileno()])
  except BaseException as cause:
    if process.poll() is None: process.kill()
    try: status = process.wait(timeout=1); waited = True
    except subprocess.TimeoutExpired: pass
    raise OwnedClientError(cause, status, waited, bytes(outputs[process.stdout.fileno()]),
      bytes(outputs[process.stderr.fileno()]), cursor, acknowledged) from cause
  finally:
    for stream in [process.stdin, process.stdout, process.stderr]:
      if stream is not None: stream.close()


def host_pin(item, maximum):
  require(type(item) is dict and set(item) == {'path', 'sha256', 'bytes'}
          and type(item['bytes']) is int and 0 < item['bytes'] <= maximum, 'Wrong fixed host input pin')
  sha(item['sha256'])
  path = Path(item['path'])
  require(path.is_absolute() and path.is_relative_to(Path('/home/jresp/build/omarchy-shield'))
          and path.parent.resolve(strict=True) == path.parent, 'Host input outside private build namespace')
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 0
            and not before.st_mode & 0o022 and before.st_size == item['bytes'], 'Unsafe pinned host input')
    with os.fdopen(os.dup(fd), 'rb') as stream: raw = stream.read(item['bytes'] + 1)
    after = os.fstat(fd)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'],
            'Pinned host input changed')
    return raw
  finally: os.close(fd)


def admit_release(raw, expected_sha256, spec, assembly_sha256, execution_scope):
  """Host qualification records, not a claim of native parity or measured boot."""
  require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == sha(expected_sha256), 'Release review pin differs')
  value = json_bytes(raw)
  require({'tools/native_phase_coordinator.py', 'tools/native_attempt_journal.py',
    'tools/native_recovery_observer.py', 'tools/native_legacy_memory.py',
    'qualification/legacy-handoff.inc', 'qualification/legacy-watchdog-exec.c'} <= set(spec.source_pins),
    'Outer producer/consumer source pins absent')
  require(set(value) == {'format_version', 'purpose', 'assembly_receipt_sha256', 'bundle_sha256',
    'source_sha256', 'qualification', 'execution_inputs_sha256', 'native_execution_released', 'boot_ready'}
    and type(value['format_version']) is int and value['format_version'] == 1
    and value['purpose'] == 'source-reviewed one native phase execution'
    and value['assembly_receipt_sha256'] == assembly_sha256
    and value['bundle_sha256'] == hashlib.sha256(spec.bundle_raw).hexdigest()
    and value['source_sha256'] == dict(spec.source_pins)
    and value['execution_inputs_sha256'] == hashlib.sha256(canonical(execution_scope)).hexdigest()
    and value['native_execution_released'] is True and value['boot_ready'] is False,
    'Release is not for this exact current host candidate')
  required = {'software': {'focused_regressions', 'source_inputs_unchanged'},
    'arm_runtime': {'runtime_imports', 'link_closure', 'fixed_entrypoint_refusal'},
    'systemd_vm': {'real_systemd_pid1', 'package_layer_match', 'cleanup_and_original_default'}}
  require(type(value['qualification']) is dict and set(value['qualification']) == set(required),
          'Current host qualification closure absent')
  for name, checks in required.items():
    receipt = json_bytes(host_pin(value['qualification'][name], 1024**2))
    require(set(receipt) == {'format_version', 'purpose', 'state', 'source_sha256', 'checks'}
            and type(receipt['format_version']) is int and receipt['format_version'] == 1
            and receipt['purpose'] == 'current native cohort ' + name
            and receipt['state'] == 'PASS' and receipt['source_sha256'] == dict(spec.source_pins)
            and type(receipt['checks']) is dict and set(receipt['checks']) == checks
            and all(item is True for item in receipt['checks'].values()),
            'Qualification record is stale, incomplete or out of scope')
  source_check(dict(spec.source_pins))


def reservations(raw):
  require(type(raw) is bytes and 40 <= len(raw) <= 4 * 1024**2 and raw[:4] == b'\xd0\x0d\xfe\xed',
          'Expected complete bounded live FDT')
  total, offset = struct.unpack_from('>I', raw, 4)[0], struct.unpack_from('>I', raw, 16)[0]
  require(total == len(raw) and 40 <= offset < total and offset % 8 == 0, 'FDT header bounds differ')
  rows = []
  for _index in range(64):
    require(offset + 16 <= len(raw), 'Truncated FDT reservations')
    row = struct.unpack_from('>QQ', raw, offset); offset += 16
    rows.append(row)
    if row == (0, 0): return rows
  raise ValueError('FDT reservation budget')


class Coordinator:
  def __init__(self, spec, bootset, assembly_sha256, baseline, serial, adb_sha256,
               release_raw, release_sha256, tools, reference_fdt, fdtget_sha256, tool_qualification):
    require(type(spec) is Spec and type(baseline) is Baseline, 'Content-admitted phase and baseline required')
    require(type(serial) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}', serial), 'Fixed USB serial required')
    scope = {'tools': tools, 'tool_qualification': tool_qualification, 'reference_fdt': reference_fdt,
      'fdtget_sha256': sha(fdtget_sha256), 'adb_sha256': sha(adb_sha256),
      'baseline_sha256': baseline.expected_sha256,
      'USB': {'vid': '18D1', 'pid': 'D001', 'serial_sha256': hashlib.sha256(serial.encode('ascii')).hexdigest()}}
    admit_release(release_raw, release_sha256, spec, sha(assembly_sha256), scope)
    require(type(tools) is dict and set(tools) == {'kexec', 'legacy-watchdog-exec'}, 'Exact legacy helper set required')
    self.tools = {name: host_pin(item, 16 * 1024**2) for name, item in tools.items()}
    qualified = json_bytes(host_pin(tool_qualification, 1024**2))
    require(set(qualified) == {'format_version', 'purpose', 'state', 'source_sha256', 'tools', 'checks'}
            and type(qualified['format_version']) is int and qualified['format_version'] == 1
            and qualified['purpose'] == 'current legacy tool artifact qualification' and qualified['state'] == 'PASS'
            and qualified['source_sha256'] == dict(spec.source_pins)
            and qualified['tools'] == {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
                                      for name, raw in self.tools.items()}
            and qualified['checks'] == {'static_arm_linkage': True, 'fixed_argv': True, 'kexec_source_identity': True}
            and all(type(item) is bool for item in qualified['checks'].values()),
            'Legacy actual artifacts/build qualification differ from the release review')
    for raw in self.tools.values():
      require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
              and struct.unpack_from('<HHI', raw, 16) == (2, 183, 1), 'Legacy tool is not static AArch64 ELF')
      offset = struct.unpack_from('<Q', raw, 32)[0]
      header, step, count = struct.unpack_from('<HHH', raw, 52)
      require(header == 64 and step == 56 and 0 < count <= 128
              and 64 <= offset <= len(raw) - count * step, 'Legacy ELF headers differ')
      kinds = [struct.unpack_from('<I', raw, offset + index * step)[0] for index in range(count)]
      require(1 in kinds and 2 not in kinds and 3 not in kinds, 'Legacy tool has an unadmitted dynamic loader')
    self.reference = host_pin(reference_fdt, 4 * 1024**2)
    require(hashlib.sha256(Path(FDTGET).read_bytes()).hexdigest() == sha(fdtget_sha256), 'Host FDT reader differs')
    require(reservations(self.reference) == [(0x80000000, 0x20000), (0, 0)], 'Reference FDT reservations differ')
    self.spec, self.bootset, self.assembly_sha = spec, Path(bootset), assembly_sha256
    self.baseline, self.serial, self.adb_sha = baseline, serial, adb_sha256
    self.started = self.cancelled = self.release_attempted = self.arm_attempted = False
    self.sos_reboot_attempted = self.stage_attempted = self.load_attempted = False
    self.journal = self.observer = self.transport = None
    self.files = {}
    self.expected_legacy_boot = None
    self.tmp_identity = None
    self.owner_pid = os.getpid()

  def owner_check(self):
    require(os.getpid() == self.owner_pid and len(os.listdir('/proc/self/task')) == 1
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            'Only the original single-threaded outer owner may commit or cancel')

  def guarded_legacy_command(self, command):
    if self.expected_legacy_boot is not None:
      return ('test "$(cat /proc/sys/kernel/random/boot_id)" = ' +
        shlex.quote(self.expected_legacy_boot) + ' && ( ' + command + ' )')
    return command

  def client_failure(self, operation, failure):
    if self.journal is None or now() >= self.deadline: return
    value = {'operation': operation, 'cause_type': failure.cause_type,
      'actual_wait_exit': failure.actual_wait_exit,
      'positive_wait_observed': failure.positive_wait_observed,
      'input_bytes_written': failure.input_bytes_written,
      'input_ack_observed': failure.input_ack_observed, 'replay_allowed': False}
    for name, raw in [('stdout', failure.stdout), ('stderr', failure.stderr)]:
      value[name + '_bytes'] = len(raw)
      value[name + '_sha256'] = hashlib.sha256(raw).hexdigest()
      value[name + '_preview_hex'] = raw[:8192].hex()
    try: self.record('owned-client-failure.json', value)
    except BaseException: pass  # Do not replace the actual failure or extend its deadline.

  def adc(self, arguments, *, seconds=20, budget=1024**2, readonly_until=None):
    check(self.deadline)
    if arguments[0] in {'shell', 'exec-out'}:
      command = arguments[1] if len(arguments) == 2 else ' '.join(shlex.quote(item) for item in arguments[1:])
      arguments = [arguments[0], self.guarded_legacy_command(command)]
    try:
      return run_owned([str(ADB), '-s', self.serial, *arguments], min(now() + seconds * SECOND, self.deadline),
                       budget=budget, readonly_until=readonly_until)[0]
    except OwnedClientError as failure:
      self.client_failure(arguments[0], failure)
      raise

  def upload(self, name, raw):
    require(self.expected_legacy_boot is not None and type(raw) is bytes, 'Fixed recovery boot and immutable bytes required before upload')
    command, marker, expected = legacy_stage_command(name, len(raw), hashlib.sha256(raw).hexdigest())
    acknowledgement = ('SHIELD_STAGE_INPUT_CONFIRMED ' + str(len(raw)) + ' ' +
                       hashlib.sha256(raw).hexdigest() + '\n').encode('ascii')
    # Client flags stay client-side. adc() deliberately only wraps command-only
    # shell callers; passing -T through it would put options inside the command.
    bounded = '/system/bin/toybox timeout -k 1 55 /system/bin/sh -c ' + shlex.quote(command)
    argv = [str(ADB), '-s', self.serial, 'shell', '-T', '-e', 'none',
            self.guarded_legacy_command(bounded)]
    # Windows shell stdin CRT mode is not assumed binary. This one current
    # wire representation contains no control bytes or line endings. The
    # device must decode, verify the original binary and ACK before EOF.
    wire = base64.b64encode(raw)
    try:
      run_owned(argv, min(now() + 60 * SECOND, self.deadline), data=wire,
                budget=8192, input_ack=acknowledgement)
    except OwnedClientError as failure:
      self.client_failure('acknowledged-stage-' + name, failure)
      raise
    self.record('stage-' + name + '-input-confirmed.json', {'input_bytes': len(raw),
      'input_sha256': hashlib.sha256(raw).hexdigest(), 'wire_encoding': 'base64-ascii',
      'wire_input_bytes': len(wire), 'remote_timeout_seconds': 55, 'remote_ack_observed': True,
      'actual_local_wait_exit': 0, 'remote_shell_v2_exit': 0, 'stdin_EOF_after_ACK': True})
    return marker, expected

  def shell(self, command, **options): return legacy_shell_text(self.adc(['shell', command], **options))

  def record(self, name, value):
    write_once(self.journal.fd, name, canonical(value), self.deadline)

  def usb_identity(self):
    # Exact present USB instance, not an IP/serial-regex inference. This is the
    # actual qualified recovery descriptor, distinct from native ACM 0525:a4a7.
    identity = 'USB\\VID_18D1&PID_D001\\' + self.serial
    script = ("$ErrorActionPreference='Stop'; $d=@(Get-PnpDevice -PresentOnly -InstanceId '" + identity +
      "'); if($d.Count -ne 1){throw 'Target count'}; $d | Select-Object Status,Class,InstanceId | ConvertTo-Json -Compress")
    raw, _stderr = run_owned([PS, '-NoProfile', '-NonInteractive', '-EncodedCommand',
      base64.b64encode(script.encode('utf-16le')).decode('ascii')],
      min(now() + 15 * SECOND, self.deadline), budget=8192)
    value = json.loads(raw.decode('utf-8-sig'))
    require(type(value) is dict and set(value) == {'Status', 'Class', 'InstanceId'}
            and value['Status'] == 'OK' and value['Class'] == 'USBDevice'
            and value['InstanceId'].casefold() == identity.casefold(), 'Selected physical USB instance differs')

  def ensure_sos(self):
    self.usb_identity()
    observed = self.observer.snapshot(min(now() + 60 * SECOND, self.deadline), require_sos=False)
    if observed['route'] != 'recovery':
      require(not self.sos_reboot_attempted, 'SOS transition cannot replay')
      self.sos_reboot_attempted = True
      self.adc(['reboot', 'recovery'], seconds=12, budget=8192)
      self.adc(['wait-for-disconnect'], seconds=25, budget=8192)
      self.adc(['wait-for-recovery'], seconds=100, budget=8192)
      self.usb_identity()
    actual = self.observer.inspect_initial()
    require(not self.sos_reboot_attempted or actual['boot_id'] != observed['boot_id'], 'SOS transition returned old boot')
    self.expected_legacy_boot = actual['boot_id']
    self.record('initial-recovery.json', plain(actual))

  def artifacts(self):
    root = os.open(self.bootset, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
      receipt = json_bytes(private_file(root, 'receipt.json', 512 * 1024))
      require(hashlib.sha256(canonical(receipt)).hexdigest() == self.assembly_sha, 'Assembly receipt changed')
      for name in ['Image', 'initramfs.cpio.gz', 'board.dtb', 'cmdline.txt']:
        item = receipt['files'][name]
        raw = private_file(root, name, 384 * 1024**2)
        require(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'],
                'Actual handoff artifact differs from admitted assembly')
        self.files[name] = raw
    finally: os.close(root)
    require(hashlib.sha256(self.files['Image']).hexdigest() == self.spec.configuration['kernel']['image_sha256']
            and hashlib.sha256(self.files['board.dtb']).hexdigest() == self.spec.configuration['dtb_sha256'],
            'Handoff kernel/DT differs')
    self.files.update(self.tools)
    self.files['legacy-handoff.sh'] = (PORT / 'qualification/legacy-handoff.inc').read_bytes()
    self.files['legacy-boot-id'] = (self.expected_legacy_boot + '\n').encode('ascii')
    source_check(dict(self.spec.source_pins))

  def memory_guard(self):
    live = self.adc(['exec-out', 'cat', '/sys/firmware/fdt'], seconds=15, budget=4 * 1024**2)
    require(reservations(live) == reservations(self.reference), 'Actual live FDT reservations differ')
    for name, data in [('live.dtb', live), ('reference.dtb', self.reference)]:
      fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                   0o600, dir_fd=self.journal.fd)
      try:
        os.fchmod(fd, 0o600)
        cursor = 0
        while cursor < len(data):
          check(self.deadline)
          count = os.write(fd, data[cursor:])
          require(0 < count <= len(data) - cursor, 'Uncertain private FDT write')
          cursor += count
        os.fsync(fd)
      finally: os.close(fd)
    for node, prop, kind in FDT_PROPERTIES:
      values = []
      for name in ['live.dtb', 'reference.dtb']:
        value, _stderr = run_owned([FDTGET, '-t', kind, str(self.journal.path / name), node, prop],
          min(now() + 3 * SECOND, self.deadline), budget=8192)
        values.append(value)
      require(values[0] == values[1], 'Live board/RAM/carveout property differs')
    graph = []
    for name in ['live.dtb', 'reference.dtb']:
      nodes = {}
      def get(node, option, prop=None):
        args = [FDTGET, *option, str(self.journal.path / name), node]
        if prop is not None: args.append(prop)
        return run_owned(args, min(now() + 3 * SECOND, self.deadline), budget=65536)[0]
      def walk(node, depth):
        require(depth <= 8 and len(nodes) < 128, 'Reserved-memory graph budget')
        props = get(node, ['-p']).decode('ascii').split()
        children = get(node, ['-l']).decode('ascii').split()
        require(len(props) <= 64 and len(props) == len(set(props))
                and len(children) == len(set(children))
                and all(re.fullmatch('[A-Za-z0-9_,@.+#-]+', value) for value in props + children),
                'Malformed reserved-memory graph names')
        nodes[node] = {}
        for prop in props:
          values = get(node, ['-t', 'bx'], prop).split()
          require(len(values) <= 4096 and all(re.fullmatch(b'[0-9a-fA-F]{1,2}', value) for value in values),
                  'Reserved-memory property byte budget/type')
          nodes[node][prop] = bytes(int(value, 16) for value in values)
        for child in children: walk(node + '/' + child, depth + 1)
      walk('/reserved-memory', 0)
      graph.append(nodes)
    require(graph[0] == graph[1], 'Full actual reserved-memory graph differs from the admitted reference')
    root = graph[0]['/reserved-memory']
    require(root.get('#address-cells') == root.get('#size-cells') == b'\0\0\0\2'
            and root.get('ranges') == b'', 'Unreviewed reserved-memory cell/range mapping')
    reserved = [(start, start + size) for start, size in reservations(live) if size]
    for node, props in graph[0].items():
      if node == '/reserved-memory' or props.get('status') == b'disabled\0': continue
      if 'reg' in props:
        require(len(props['reg']) % 16 == 0, 'Reserved-memory reg geometry differs')
        for offset in range(0, len(props['reg']), 16):
          start, size = struct.unpack_from('>QQ', props['reg'], offset)
          if size: reserved.append((start, start + size))
      elif props.get('size', b'\0' * 8) != b'\0' * 8:
        require(node == '/reserved-memory/vpr-carveout', 'Unmodeled dynamic persistent reservation')
    dmesg = self.shell('dmesg', budget=4 * 1024**2)
    iomem = self.shell('cat /proc/iomem', budget=64 * 1024)
    framebuffer_tokens = [value for value in self.shell('cat /proc/cmdline').split() if 'fbmem' in value]
    framebuffer_lines = [line for line in dmesg.splitlines() if re.search(r'\bFound\s+\S*fbmem', line)]
    require(framebuffer_tokens == ['tegra_fbmem=0x800000@0x92cc3000']
            and len(framebuffer_lines) == 1
            and re.search(r'Found tegra_fbmem\s*:\s*00800000@92cc3000\s*$', framebuffer_lines[0]),
            'Unexpected or ambiguous runtime framebuffer reservation')
    require(re.search(r'Found tegra_fbmem\s*:\s*00800000@92cc3000', dmesg)
            and re.search(r'resizable heap=vpr, base=0x0*d7000000, size=0x19000000', dmesg),
            'Actual framebuffer/VPR carveouts differ')
    reserved.extend([(0x92cc3000, 0x934c3000), (0xd7000000, 0xf0000000)])
    ram = []
    for line in iomem.splitlines():
      match = re.fullmatch(r'\s*([0-9a-fA-F]+)-([0-9a-fA-F]+) : (.+)', line)
      require(match is not None, 'Malformed actual iomem resource')
      start, end = int(match[1], 16), int(match[2], 16) + 1
      require(start < end, 'Empty actual iomem resource')
      if match[3] == 'System RAM': ram.append((start, end))
      elif match[3] not in {'Kernel code', 'Kernel data', 'Kernel bss'}:
        # Ordinary old-kernel image allocations are replaceable. Other named
        # resources are conservatively excluded from loaded segment extents.
        if start < 0x92cc3000 and end > 0x80020000: reserved.append((start, end))
    require(sorted(ram) == [(0x80000000, 0x9f000000), (0xa0000000, 0xb0000000),
      (0xb0200000, 0xfec00000), (0x100000000, 0x140000000)], 'Actual complete System RAM map differs')
    self.reserved_ranges = reserved
    self.record('memory-admission.json', {'actual_reference_properties_match': True,
      'framebuffer_VPR_and_RAM_match': True, 'live_fdt_sha256': hashlib.sha256(live).hexdigest(),
      'device_execution_authorized_by_this_record': False})

  def stage_load_arm(self):
    require(not self.stage_attempted and not self.load_attempted and not self.arm_attempted, 'Legacy effects cannot replay')
    self.stage_attempted = True
    require(self.shell('cat /sys/kernel/kexec_loaded') == '0', 'Another kernel is already loaded')
    for engine in CLIENTS:
      require(self.shell('/system/bin/toybox timeout -k 1 4 cat /sys/bus/platform/devices/' + engine +
        '/power/runtime_status') == 'suspended', 'Qualified legacy client is not suspended')
    raw_features = self.adc(['features'], seconds=10, budget=8192)
    self.record('stage-shell-capability-source.json', {'stdout_bytes': len(raw_features),
      'stdout_sha256': hashlib.sha256(raw_features).hexdigest(), 'stdout_hex': raw_features.hex()})
    features = legacy_shell_features(raw_features)
    require('shell_v2' in features, 'Acknowledged raw staging requires shell_v2')
    self.record('stage-shell-capability.json', {'shell_v2_observed': True, 'raw_shell_client_flags': ['-T', '-e', 'none']})
    self.memory_guard()
    self.check_ram_stage(before=True)
    self.shell('test ! -e ' + RAM + ' && test ! -L ' + RAM + ' && mkdir -m 700 ' + RAM)
    for name, raw in self.files.items():
      # One acknowledged raw-shell upload; immutable bytes never use Windows
      # file paths, and a local pipe/exit cannot substitute for remote delivery.
      marker, expected = self.upload(name, raw)
      closed = self.shell('/system/bin/toybox timeout -k 1 5 cat ' + marker,
        seconds=8, budget=8192)
      identity = self.shell("/system/bin/toybox stat -c '%f %u %g %d %i %h %s' " + RAM + '/' + name).split()
      require(len(identity) == 7 and identity[:3] == ['8180', '0', '0']
        and all(item.isdecimal() for item in identity[1:]) and identity[5:] == ['1', str(len(raw))],
        'Closed staged file identity differs')
      self.record('stage-' + name + '-completion.json', {'observed_marker': closed,
        'expected_marker': expected + ' ' + identity[3] + ' ' + identity[4], 'target_identity': identity})
      require(closed == expected + ' ' + identity[3] + ' ' + identity[4],
        'Remote staging writer completion or inode differs')
      require(self.shell('sha256sum ' + RAM + '/' + name).split() ==
        [hashlib.sha256(raw).hexdigest(), RAM + '/' + name], 'Actual staged artifact readback differs')
    self.check_ram_stage(before=False)
    self.shell('chmod 700 ' + RAM + '/kexec ' + RAM + '/legacy-watchdog-exec ' + RAM + '/legacy-handoff.sh')
    command = (RAM + '/kexec -d -c -l ' + RAM + '/Image --dtb=' + RAM + '/board.dtb --initrd=' +
      RAM + '/initramfs.cpio.gz --command-line=' + shlex.quote(self.files['cmdline.txt'].decode('ascii').strip()) +
      ' --mem-min=0x80020000 --mem-max=0x92cc2fff')
    self.load_attempted = True
    self.shell('( ' + command + ' > ' + RAM + '/loader.log 2>&1; s=$?; printf "%s\\n" "$s" > ' +
               RAM + '/loader.status; exit "$s" )', seconds=60)
    require(self.shell('cat ' + RAM + '/loader.status') == '0'
            and self.shell('cat /sys/kernel/kexec_loaded') == '1', 'Actual loader completion/state missing')
    report = review_segments(self.shell('cat ' + RAM + '/loader.log'), len(self.files['initramfs.cpio.gz']),
                             self.files['Image'], reserved_ranges=self.reserved_ranges)
    self.record('loaded-segments.json', report)
    self.shell("set -C; printf '%s\\n' NATIVE_SEGMENTS_REVIEWED_V1 > " + RAM + '/loaded-segments-reviewed')
    require(self.deadline - now() >= 780 * SECOND, 'Insufficient unchanged outer budget before legacy watchdog arm')
    self.arm_attempted = True
    self.shell('/system/bin/sh ' + RAM + '/legacy-handoff.sh --arm')
    self.adc(['shell', 'tail -c +1 -f ' + RAM + '/runner.log'], seconds=20, budget=65536,
             readonly_until=b'READY independent session/cgroup; loaded RAM image not executed')
    ready = self.shell('cat ' + RAM + '/READY; cat ' + RAM + '/runner.log; cat ' + RAM + '/child-cgroup', budget=65536)
    require('INDEPENDENT_RUNNER_READY_V1' in ready and '0::/shield-native' in ready and 'ABORT' not in ready,
            'Owned independent legacy runner not ready')
    self.record('legacy-ready.json', {'independent_runner_observed': True, 'loaded_kernel_not_executed': True})

  def check_ram_stage(self, *, before):
    require(self.shell('/system/bin/toybox readlink -f /tmp') == '/tmp', 'Staging parent is not the real /tmp')
    values = self.shell("/system/bin/toybox stat -c '%f %u %g %d %i' /tmp").split()
    require(len(values) == 5 and int(values[0], 16) == 0x41fd and values[1:3] == ['0', '2000']
            and all(value.isdecimal() for value in values[1:]), 'Legacy RAM parent metadata differs')
    fs = self.shell("/system/bin/toybox stat -f -c '%t %a %S' /tmp").split()
    require(len(fs) == 3 and int(fs[0], 16) == 0x01021994
            and all(value.isdecimal() for value in fs[1:]), 'Staging parent is not the selected RAM filesystem')
    mountinfo = self.shell('cat /proc/self/mountinfo', budget=128 * 1024)
    rows = []
    for line in mountinfo.splitlines():
      head, tail = line.split(' - ', 1); fields, superblock = head.split(), tail.split()
      if fields[4] == '/tmp': rows.append((fields, superblock))
    require(len(rows) == 1 and rows[0][1][0] == 'tmpfs' and rows[0][0][3] == '/'
            and rows[0][0][2] == str(os.major(int(values[3]))) + ':' + str(os.minor(int(values[3])))
            and 'rw' in rows[0][0][5].split(','), 'Actual RAM mount identity differs')
    identity = (tuple(values), rows[0][0][0], rows[0][0][2], rows[0][0][3])
    if before:
      require(self.tmp_identity is None, 'RAM admission cannot be renewed')
      total = sum(len(raw) for raw in self.files.values())
      available = legacy_available_bytes(self.shell('cat /proc/meminfo'))
      require(available >= 2 * total + 256 * 1024**2
              and int(fs[1]) * int(fs[2]) >= total + 64 * 1024**2,
              'Insufficient actual RAM/space for staging and the loaded copies')
      self.tmp_identity = identity
    else:
      require(identity == self.tmp_identity, 'RAM staging mount changed')
      require(self.shell('/system/bin/toybox readlink -f ' + RAM) == RAM
              and self.shell("/system/bin/toybox stat -c '%f %u %g %d' " + RAM).split()
                == ['41c0', '0', '0', values[3]], 'Owned staging leaf identity differs')

  def release(self):
    self.owner_check()
    require(not self.cancelled and not self.release_attempted and self.arm_attempted
            and self.transport.armed, 'Legacy release outside the single armed phase')
    self.usb_identity()
    ready = self.shell('test ! -e ' + RAM + '/ABORT && test ! -e ' + RAM + '/CANCEL && cat ' + RAM +
      '/READY && cat ' + RAM + '/child-cgroup', budget=8192)
    require(ready.splitlines() == ['INDEPENDENT_RUNNER_READY_V1', '0::/shield-native'],
            'Legacy readiness changed before the one release')
    check(self.deadline)
    require(not self.cancelled and not self.release_attempted and self.arm_attempted and self.transport.armed,
            'Legacy phase was cancelled/consumed during blocking admission')
    self.release_attempted = True  # Even an uncertain send consumes the commit.
    self.shell('test ! -e ' + RAM + '/ABORT && test ! -e ' + RAM + '/CANCEL && test ! -e ' + RAM + '/RELEASE && '
      "(set -C; printf '%s\\n' EXECUTE_NATIVE_QUALIFICATION_V1 > " + RAM + '/RELEASE)', seconds=8)

  def cancel_before_release(self):
    self.owner_check()
    if self.release_attempted or self.cancelled: return
    self.cancelled = True
    if self.arm_attempted:
      # Never signal/kill the legacy watchdog owner, and never issue RELEASE
      # after this one cancellation attempt, including an uncertain transfer.
      self.shell('test ! -e ' + RAM + '/RELEASE && '
        "(set -C; printf '%s\\n' CANCELLED > " + RAM + '/CANCEL)', seconds=5)

  def execute(self):
    self.owner_check()
    require(not self.started and not self.cancelled, 'Outer phase cancelled/already consumed')
    self.started = True
    self.deadline = now() + 900 * SECOND
    self.journal = Journal(self.spec, self.bootset, self.assembly_sha, self.deadline)
    try:
      self.observer = Observer(self.baseline, self.serial, self.adb_sha, self.deadline)
      self.ensure_sos()
      self.artifacts()
      self.stage_load_arm()
      self.transport = Attempt(self.spec, self.journal.transport_directory, outer_deadline_ns=self.deadline)
      self.transport.arm()
      self.release()
      completion = self.transport.finish()
      returned = self.observer.observe_return(self.transport)
      self.usb_identity()
      if self.spec.configuration['phase'] in {'packages', 'layer'}:
        published = self.journal.publish_preparation(self.observer, self.transport)
        self.journal.close()
        check(self.deadline)
        return published
      result = {'state': 'SYSTEMD_CONTROL_CLEANUP_AND_RECOVERY_OBSERVED',
        'terminal_evidence_sha256': completion['evidence_sha256'], 'recovery': plain(returned),
        'desktop_qualified': False, 'hardware_parity_qualified': False, 'boot_ready': False}
      self.record('systemd-return.json', result)
      self.journal.close()
      check(self.deadline)
      return result
    except BaseException:
      try: self.cancel_before_release()
      except (OSError, ValueError, subprocess.SubprocessError): pass
      if self.transport is not None: self.transport.cancel()
      if self.journal is not None and (self.journal.pid is None or self.journal.wait_status is not None):
        self.journal.close()
      # No retry, fallback reboot/flash, invented recovery observation or
      # adoption of a partial publication follows an unknown phase outcome.
      raise
