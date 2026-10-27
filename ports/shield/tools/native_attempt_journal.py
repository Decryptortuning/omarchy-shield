"""One private boot-set claim and supervised durable preparation publisher.

This module neither loads nor releases native code. The outer coordinator must
admit qualification, USB identity, memory placement and legacy handoff itself.
Existing claims/partial publications are preserved and cannot be adopted.
Files alone are not a publisher return: only a timely actual worker wait and
its private result create Published. Do not import before the source gate.
"""
import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import select
import signal
import socket
import stat

from native_boot_context import canonical, close_from, json_bytes, plain, sha
from native_host_controller import Attempt, Spec, notify, source_check
from native_recovery_observer import Observer
from usb_root_profile import require

SECOND = 1_000_000_000
ROOT = Path('/home/jresp/build/omarchy-shield')


def now():
  import time
  return time.monotonic_ns()


def check(cutoff):
  require(type(cutoff) is int and 0 < now() < cutoff, 'Existing journal deadline exhausted')


def private_file(directory_fd, name, maximum):
  require('/' not in name and name not in {'', '.', '..'}, 'Unknown journal leaf')
  fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
  try:
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
            and 0 < before.st_size <= maximum, 'Unsafe private artifact object')
    value = bytearray()
    while len(value) <= before.st_size:
      chunk = os.read(fd, min(65536, before.st_size + 1 - len(value)))
      if not chunk: break
      value.extend(chunk)
    after = os.fstat(fd)
    require(len(value) == before.st_size and (before.st_dev, before.st_ino, before.st_size,
      before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
      after.st_mtime_ns, after.st_ctime_ns), 'Private artifact changed while reading')
    return bytes(value)
  finally: os.close(fd)


def write_once(directory_fd, name, raw, cutoff):
  check(cutoff)
  require('/' not in name and name not in {'', '.', '..'} and type(raw) is bytes
          and 0 < len(raw) <= 65536, 'Wrong fixed journal record')
  fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
               0o600, dir_fd=directory_fd)
  try:
    os.fchmod(fd, 0o600)
    cursor = 0
    while cursor < len(raw):
      check(cutoff)
      count = os.write(fd, raw[cursor:])
      require(0 < count <= len(raw) - cursor, 'Uncertain private record write; never replay')
      cursor += count
    os.fsync(fd)
  finally: os.close(fd)
  os.fsync(directory_fd)
  check(cutoff)
  require(private_file(directory_fd, name, 65536) == raw, 'Durable record readback differs')
  check(cutoff)


@dataclass(frozen=True)
class Published:
  """Actual parent-observed publication; never constructed from file existence."""
  predecessor_raw: bytes
  predecessor_sha256: str
  recovery_observation_sha256: str
  publication_sha256: str
  directory: Path


def publisher(channel, directory_fd, content, observation, binding, cutoff):
  write_once(directory_fd, 'PUBLICATION_ATTEMPTED', b'ONE_PREPARATION_PUBLICATION\n', cutoff)
  write_once(directory_fd, 'recovery-observation.json', observation, cutoff)
  write_once(directory_fd, 'predecessor.json', content, cutoff)
  final = {'format_version': 1, 'purpose': 'durably published native preparation observations',
    **binding, 'predecessor_sha256': hashlib.sha256(content).hexdigest(),
    'recovery_observation_sha256': hashlib.sha256(observation).hexdigest(),
    'publication_observed_ns': now(), 'publication_deadline_ns': cutoff,
    'boot_ready': False, 'physical_powerloss_qualified': False}
  raw = canonical(final)
  write_once(directory_fd, 'publication.json', raw, cutoff)
  notify(channel, {'event': 'published', 'content': json_bytes(content),
    'predecessor_sha256': final['predecessor_sha256'],
    'recovery_observation_sha256': final['recovery_observation_sha256'],
    'publication_sha256': hashlib.sha256(raw).hexdigest()}, cutoff)


class Journal:
  def __init__(self, spec, bootset, receipt_sha256, overall_deadline_ns):
    require(type(spec) is Spec and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
            'Content-admitted spec and WSL root journal required')
    check(overall_deadline_ns)
    require(overall_deadline_ns <= now() + 900 * SECOND, 'Unbounded outer attempt journal')
    source_check(dict(spec.source_pins))
    self.spec, self.bootset = spec, Path(bootset)
    self.deadline = overall_deadline_ns
    self.fd = self.pid = self.pidfd = self.channel = None
    self.child_endpoint = None
    self.wait_status = None
    self.publish_attempted = self.kill_attempted = False
    self.published = None
    require(self.bootset.is_absolute() and self.bootset.is_relative_to(ROOT)
            and self.bootset.parent.resolve(strict=True) == self.bootset.parent, 'Unsafe boot-set namespace')
    base = os.open(self.bootset, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
      info = os.fstat(base)
      require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
              'Boot-set directory must be private and root-owned')
      raw = private_file(base, 'receipt.json', 512 * 1024)
      require(hashlib.sha256(raw).hexdigest() == sha(receipt_sha256), 'Independent assembly receipt differs')
      receipt = json_bytes(raw)
      require(receipt['purpose'] == 'host-only assembled native boot set'
              and receipt['phase'] == spec.configuration['phase'] and receipt['roundtrip_verified'] is True
              and receipt['configuration_sha256'] == spec.contexts['early'].config_sha256
              and receipt['bundle_sha256'] == hashlib.sha256(spec.bundle_raw).hexdigest()
              and receipt['source_sha256'] == dict(spec.source_pins)
              and receipt['native_execution_released'] is False and receipt['boot_ready'] is False,
              'Assembly receipt does not bind this host attempt')
      require(private_file(base, 'boot.json', 128 * 1024) == spec.bundle_raw, 'Boot bundle file differs')
      # This claim is tied to the boot-set directory, not a freely chosen
      # evidence path. Failure consumes it even before any device effect.
      os.mkdir('native-attempt', 0o700, dir_fd=base)
      os.fsync(base)
      self.path = self.bootset / 'native-attempt'
      self.fd = os.open('native-attempt', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=base)
      os.fchmod(self.fd, 0o700)
      self.identity = os.fstat(self.fd)
      write_once(self.fd, 'CLAIM.json', canonical({'format_version': 1,
        'purpose': 'one native boot-set execution claim', 'phase': spec.configuration['phase'],
        'assembly_receipt_sha256': receipt_sha256, 'bundle_sha256': receipt['bundle_sha256'],
        'configuration_sha256': spec.contexts['early'].config_sha256,
        'session_id': spec.contexts['early'].session_id, 'boot_ready': False}), self.deadline)
    except BaseException:
      if self.fd is not None: os.close(self.fd); self.fd = None
      raise
    finally: os.close(base)

  @property
  def transport_directory(self): return self.path / 'transport'

  def identity_check(self):
    check(self.deadline)
    require(self.fd is not None, 'Journal descriptor relinquished')
    actual, path = os.fstat(self.fd), self.path.lstat()
    require(stat.S_ISDIR(path.st_mode) and path.st_uid == path.st_gid == 0
            and stat.S_IMODE(path.st_mode) == 0o700
            and (actual.st_dev, actual.st_ino) == (path.st_dev, path.st_ino)
              == (self.identity.st_dev, self.identity.st_ino), 'Journal directory was replaced')
    check(self.deadline)

  def publish_preparation(self, observer, attempt):
    self.identity_check()
    require(not self.publish_attempted and type(observer) is Observer and type(attempt) is Attempt
            and attempt.spec is self.spec and attempt.directory == self.transport_directory
            and observer.deadline == self.deadline, 'Publisher ownership/attempt differs')
    self.publish_attempted = True
    content = observer.preparation_content(attempt)
    observation = canonical(plain(observer.returned))
    require(json_bytes(content)['recovery_observation_sha256'] == hashlib.sha256(observation).hexdigest(),
            'Preparation content and actual return observation differ')
    # Confirm the retained exact frame remains present. This is the already
    # authenticated worker's wire hash, not a new ad-hoc protocol decoder.
    transport = os.open('transport', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=self.fd)
    try:
      directory = os.open('early', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=transport)
      try: frame = private_file(directory, 'maintenance.sncp1', 65536)
      finally: os.close(directory)
    finally: os.close(transport)
    require(hashlib.sha256(frame).hexdigest() == attempt.completion['evidence_sha256'],
            'Retained preparation evidence differs')
    binding = {'phase': self.spec.configuration['phase'],
      'configuration_sha256': self.spec.contexts['early'].config_sha256,
      'session_id': self.spec.contexts['early'].session_id}
    parent, child = socket.socketpair(socket.AF_UNIX,
      socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
    self.channel, self.child_endpoint = parent, child
    owner = os.getpid()
    try:
      require(len(os.listdir('/proc/self/task')) == 1
              and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'Single waitable publisher owner required')
      self.pid = os.fork()
      if self.pid == 0:
        try:
          library = ctypes.CDLL(None, use_errno=True)
          require(library.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == owner,
                  'Publisher parent-death admission failed')
          for number in [signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGPIPE]:
            signal.signal(number, signal.SIG_DFL)
          signal.pthread_sigmask(signal.SIG_SETMASK, set())
          import fcntl
          descriptors = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10) for fd in [child.fileno(), self.fd]]
          os.dup2(descriptors[0], 3); os.dup2(descriptors[1], 4)
          close_from(5)
          channel = socket.socket(fileno=3)
          publisher(channel, 4, content, observation, binding, self.deadline)
          os._exit(0)
        except BaseException: os._exit(75)
      child.close(); self.child_endpoint = None
      self.pidfd = os.pidfd_open(self.pid, 0)
      value = None
      while value is None:
        check(self.deadline)
        ready, _, _ = select.select([self.channel, self.pidfd], [], [],
                                    min(0.5, max(0, (self.deadline - now()) / SECOND)))
        check(self.deadline)
        if self.channel in ready:
          raw, ancillary, flags, _address = self.channel.recvmsg(8192, 0)
          require(raw and not ancillary and not flags, 'Publisher result truncated/lost')
          value = json_bytes(raw)
        elif self.pidfd in ready: raise ValueError('Publisher exited before its result')
      require(set(value) == {'event', 'content', 'predecessor_sha256', 'recovery_observation_sha256',
        'publication_sha256'} and value['event'] == 'published'
        and canonical(value['content']) == content
        and value['predecessor_sha256'] == hashlib.sha256(content).hexdigest()
        and value['recovery_observation_sha256'] == hashlib.sha256(observation).hexdigest(),
        'Publisher result scope differs')
      sha(value['publication_sha256'])
      ready, _, _ = select.select([self.pidfd], [], [], min(2, max(0, (self.deadline - now()) / SECOND)))
      require(ready, 'Publisher completion without actual exit')
      pid, self.wait_status = os.waitpid(self.pid, 0)
      require(pid == self.pid and os.WIFEXITED(self.wait_status) and os.WEXITSTATUS(self.wait_status) == 0,
              'Publisher did not exit successfully')
      self.release_worker_handles()
      self.identity_check()
      self.published = Published(content, value['predecessor_sha256'], value['recovery_observation_sha256'],
                                 value['publication_sha256'], self.path)
      return self.published
    except BaseException:
      self.cancel_publisher()
      raise

  def release_worker_handles(self):
    if self.wait_status is None: return
    if self.channel is not None: self.channel.close(); self.channel = None
    if self.pidfd is not None: os.close(self.pidfd); self.pidfd = None

  def cancel_publisher(self):
    if self.wait_status is None and self.pid is not None and not self.kill_attempted:
      self.kill_attempted = True
      if self.pidfd is not None:
        try: signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
        except ProcessLookupError: pass
        if select.select([self.pidfd], [], [], 1)[0]:
          _pid, self.wait_status = os.waitpid(self.pid, 0)
      elif self.pid > 1:
        # Failed pidfd_open: only our waitable, never-reaped child PID.
        try: os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        if pid == self.pid: self.wait_status = status
    if self.child_endpoint is not None: self.child_endpoint.close(); self.child_endpoint = None
    if self.pid is None and self.channel is not None:
      self.channel.close(); self.channel = None
    self.release_worker_handles()
    # No Published value is returned for a blocked/unreaped writer. Its files
    # and the boot-set claim stay intact; no replacement worker or replay.

  def close(self):
    require(self.pid is None or self.wait_status is not None, 'Publisher owner still unresolved')
    self.release_worker_handles()
    if self.fd is not None: os.close(self.fd); self.fd = None


@dataclass(frozen=True, init=False, repr=False)
class AuditedCompletedPreparation:
  """Distinct closed-A continuation; never a replacement live Published value."""
  predecessor_raw: bytes
  predecessor_sha256: str
  recovery_observation_sha256: str
  original_publication_sha256: str
  fresh_recovery_sha256: str
  fresh_recovery_boot_relation: str
  grant_sha256: str
  witness_sha256: str
  layer_pin_sha256: str
  _owner: int
  _cutoff: int
  _group: str
  _fd: int
  _identity: tuple
  _claim_raw: bytes
  _consumed: bool

  def __new__(cls, *args, **kwargs):
    raise TypeError('Use the independently granted closed preparation admission factory')

  def owner_check(self):
    check(self._cutoff)
    require(os.getpid() == self._owner and len(os.listdir('/proc/self/task')) == 1
            and Path('/proc/self/cgroup').read_text().strip() == self._group,
            'Closed preparation belongs to its original single-threaded owner/unit')
    require(self._fd >= 0, 'Closed continuation handle is no longer live')
    info = os.fstat(self._fd)
    require((info.st_dev, info.st_ino) == self._identity
            and private_file(self._fd, 'CLAIM.json', 65536) == self._claim_raw,
            'Closed continuation claim identity changed')

  def begin_finalization(self, witness_sha256, layer_pin):
    from dataclasses import asdict
    self.owner_check()
    require(not self._consumed and witness_sha256 == self.witness_sha256
            and hashlib.sha256(canonical(asdict(layer_pin))).hexdigest() == self.layer_pin_sha256,
            'Consumed continuation or wrong authorized witness/layer')
    object.__setattr__(self, '_consumed', True)
    write_once(self._fd, 'FINALIZATION_ATTEMPTED.json', canonical({
      'purpose': 'one audited completed-A predicted preimage finalization',
      'grant_sha256': self.grant_sha256, 'original_predecessor_sha256': self.predecessor_sha256,
      'physical_write_authority': False}), self._cutoff)

  def note_finalized(self, raw):
    self.owner_check()
    require(self._consumed and type(raw) is bytes, 'Finalization was not attempted')
    write_once(self._fd, 'FINALIZATION_VALIDATED.json', canonical({
      'profile_sha256': hashlib.sha256(raw).hexdigest(), 'profile_bytes': len(raw),
      'original_predecessor_sha256': self.predecessor_sha256,
      'fresh_recovery_sha256': self.fresh_recovery_sha256,
      'fresh_recovery_boot_relation': self.fresh_recovery_boot_relation,
      'physical_preimages_admitted': False, 'physical_write_authority': False}), self._cutoff)

  def close(self):
    require(os.getpid() == self._owner, 'Foreign continuation owner cannot close this handle')
    if self._fd >= 0:
      os.close(self._fd)
      object.__setattr__(self, '_fd', -1)


def admit_audited_completed_preparation(grant_raw, expected_sha256, observer, cutoff):
  """One explicit root grant, sealed completed-A proofs and a NEW read-only SOS observation.

  Uses the protocol's existing MAC-before-JSON decoder for archival evidence;
  this does not recreate a Session, sequence history, live publisher or lease.
  Native phase B must independently check every actual physical preimage.
  """
  import json
  import math
  import re
  from native_boot_context import admit as admit_bundle, unique
  from native_control_protocol import _decode
  from native_host_link import MAINTENANCE_FIELDS
  from native_phase_coordinator import host_pin
  from native_phase_plan import RECEIPT_FIELDS, decode as decode_phase_input
  from native_recovery_observer import Baseline, boot_uuid

  require(type(grant_raw) is bytes and hashlib.sha256(grant_raw).hexdigest() == sha(expected_sha256),
          'Closed continuation grant changed')
  g = json_bytes(grant_raw)
  require(set(g) == {'format_version', 'purpose', 'unit', 'source_sha256', 'artifacts',
    'baseline_sha256', 'adb_sha256', 'target_serial_sha256', 'claim_directory', 'fresh_recovery_policy',
    'native_execution_released', 'physical_preimages_admitted', 'boot_ready'}
    and type(g['format_version']) is int and g['format_version'] == 1
    and g['purpose'] == 'resume audited completed packages after HOST finalization failure'
    and g['fresh_recovery_policy'] == 'same-target-baseline-any-recovery-boot'
    and all(g[k] is False for k in ['native_execution_released', 'physical_preimages_admitted', 'boot_ready']),
    'Wrong distinct closed preparation continuation purpose')
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0
          and len(os.listdir('/proc/self/task')) == 1
          and type(cutoff) is int and now() < cutoff <= now() + 120 * SECOND,
          'Finite single root continuation owner required')
  require(type(g['unit']) is str and re.fullmatch(r'shield-omarchy[0-9a-z-]+[.]service', g['unit'])
          and re.fullmatch('[0-9a-f]{32}', os.environ.get('INVOCATION_ID', '')),
          'Closed continuation requires its explicitly owned service')
  group = '0::/system.slice/' + g['unit']
  require(Path('/proc/self/cgroup').read_text().strip() == group, 'Wrong continuation unit')
  source_check(g['source_sha256'])
  require(type(observer) is Observer and type(observer.baseline) is Baseline and observer.deadline == cutoff
          and observer.baseline.expected_sha256 == g['baseline_sha256']
          and observer.adb_sha256 == g['adb_sha256']
          and hashlib.sha256(observer.serial.encode('ascii')).hexdigest() == g['target_serial_sha256']
          and observer.initial is observer.returned is None
          and not observer.initial_attempted and not observer.return_attempted,
          'A fresh fixed-target secure recovery observer is required')
  names = {'execution_gate', 'execution_scope', 'assembly_receipt', 'bundle', 'early_key', 'phase_a_plan',
    'phase_a_payload', 'frame', 'predecessor', 'publication', 'recovery', 'body_actual',
    'body_failure', 'body_publication', 'windows_owner', 'windows_launcher', 'root_closure',
    'actual_audit', 'old_source_snapshot', 'old_witness', 'new_witness', 'new_layer_pin',
    'layer_migration_proof', 'layer_migration_audit', 'new_witness_result', 'new_witness_audit'}
  require(type(g['artifacts']) is dict and set(g['artifacts']) == names, 'Incomplete closed continuation proof set')
  claim = Path(g['claim_directory'])
  require(claim.is_absolute() and claim.is_relative_to(ROOT)
          and claim.parent.resolve(strict=True) == claim.parent,
          'Continuation claim must be in its private build namespace')
  info = claim.parent.stat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and not info.st_mode & 0o077 and not claim.exists() and not claim.is_symlink(),
          'Unsafe or consumed continuation claim parent')
  claim.mkdir(mode=0o700)
  fd = os.open(claim, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  owner = os.getpid()
  claim_raw = canonical({'purpose': g['purpose'], 'grant_sha256': expected_sha256,
    'owner_pid': owner, 'original_packages_replayed': False, 'physical_write_authority': False})
  try:
    write_once(fd, 'CLAIM.json', claim_raw, cutoff)
    blobs = {name: host_pin(item, 16 * 1024**2) for name, item in g['artifacts'].items()}
    check(cutoff)
    def forbidden(_value): raise ValueError('Nonfinite closed report number')
    def report(name):
      return json.loads(blobs[name].decode('ascii'), object_pairs_hook=unique, parse_constant=forbidden)
    def fields(value, expected, message):
      require(type(value) is dict and all(k in value and type(value[k]) is type(v) and value[k] == v
              for k, v in expected.items()), message)
    execution, assembly = report('execution_gate'), json_bytes(blobs['assembly_receipt'])
    fields(execution, {'state': 'REVIEWED', 'execution_release': True, 'native_execution_released': True,
      'physical_packages_only': True, 'boot_ready': False}, 'Original packages execution was not admitted')
    from native_host_controller import SOURCE_MINIMUM
    scope = json_bytes(blobs['execution_scope'])
    require(execution['execution_scope'] == g['artifacts']['execution_scope']
            and execution['assembly_receipt_sha256'] == hashlib.sha256(blobs['assembly_receipt']).hexdigest(),
            'Original execution scope/assembly differs')
    fields(scope, {'baseline_sha256': g['baseline_sha256'], 'adb_sha256': g['adb_sha256']},
           'Original physical target scope differs')
    require(scope['USB'] == {'vid': '18D1', 'pid': 'D001', 'serial_sha256': g['target_serial_sha256']},
            'Continuation is not for the original physical USB target')
    attempt_path = Path(g['artifacts']['predecessor']['path']).parent
    require(Path(g['artifacts']['publication']['path']).parent == attempt_path
            and Path(g['artifacts']['recovery']['path']).parent == attempt_path
            and Path(g['artifacts']['frame']['path']) == attempt_path / 'transport/early/maintenance.sncp1'
            and Path(g['artifacts']['bundle']['path']).parent == attempt_path.parent
            and Path(g['artifacts']['early_key']['path']).parent == attempt_path.parent,
            'Original retained artifact namespace differs')
    snapshot = report('old_source_snapshot')
    require(type(execution['source_sha256']) is dict
            and SOURCE_MINIMUM <= set(execution['source_sha256'])
            and len(execution['source_sha256']) <= 160,
            'Original source producer/consumer closure is incomplete')
    require(snapshot['old_source_sha256'] == execution['source_sha256'] == assembly['source_sha256']
            and set(snapshot['sources']) == set(execution['source_sha256']), 'Closed source cohort differs')
    for name, item in snapshot['sources'].items():
      require(hashlib.sha256(host_pin(item, 1024**2)).hexdigest() == execution['source_sha256'][name],
              'Closed source snapshot changed')
    bundle = json_bytes(blobs['bundle'])
    configuration, contexts = admit_bundle(bundle)
    require(configuration['phase'] == 'packages' and set(contexts) == {'early'}, 'Only a completed packages phase may resume')
    for name, artifact in [('boot.json', 'bundle'), ('early.key', 'early_key')]:
      require(assembly['files'][name]['sha256'] == hashlib.sha256(blobs[artifact]).hexdigest()
              and assembly['files'][name]['bytes'] == len(blobs[artifact]), 'Original assembly binding differs')
    key = blobs['early_key']
    require(len(key) == 32 and any(key) and bundle['key_sha256'] == {'early': hashlib.sha256(key).hexdigest()},
            'Original private evidence key differs')
    record = _decode(key, blobs['frame'])
    require(record.context == contexts['early'] and record.direction == 'native' and record.kind == 'EVIDENCE',
            'Archived authenticated evidence belongs to another context')
    observations = plain(record.payload['observations'])
    require(set(observations) == MAINTENANCE_FIELDS and observations['kind'] == 'maintenance-released'
            and observations['phase'] == 'packages'
            and all(observations[k] is True for k in ['phase_passed', 'worker_started', 'worker_reaped',
              'reaper_reaped', 'worker_leaf_empty', 'filesystem_unmounted', 'partition_ro', 'disk_ro',
              'internal_user_ro', 'original_root_profile_preserved'])
            and observations['boot_ready'] is observations['physical_powerloss_qualified'] is False,
            'Completed package evidence is incomplete')
    require(sha(observations['nonce']) != '0' * 64
            and type(observations['boottime_ns']) is type(observations['cleanup_deadline_ns']) is int
            and 0 <= observations['boottime_ns'] < observations['cleanup_deadline_ns'] <= 600 * SECOND,
            'Archived maintenance challenge/time bounds differ')
    plan = json_bytes(blobs['phase_a_plan'])
    # Payload manifests retain their original exporter formatting and byte hash.
    payload = decode_phase_input(blobs['phase_a_payload'])
    for name, artifact in [('plan', 'phase_a_plan'), ('payload', 'phase_a_payload')]:
      require(configuration['inputs'][name]['sha256'] == hashlib.sha256(blobs[artifact]).hexdigest(),
              'Original package input differs')
    fields(observations, {'payload_manifest_sha256': hashlib.sha256(blobs['phase_a_payload']).hexdigest(),
      'plan_sha256': hashlib.sha256(blobs['phase_a_plan']).hexdigest()},
      'Archived maintenance work plan differs')
    predecessor, publication, recovery = [json_bytes(blobs[n]) for n in ['predecessor', 'publication', 'recovery']]
    require(set(publication) == {'format_version', 'purpose', 'phase', 'configuration_sha256', 'session_id',
      'predecessor_sha256', 'recovery_observation_sha256', 'publication_observed_ns', 'publication_deadline_ns',
      'boot_ready', 'physical_powerloss_qualified'}, 'Original publication schema differs')
    require(set(predecessor) == RECEIPT_FIELDS, 'Wrong original predecessor schema')
    binding = {'format_version': 1, 'purpose': 'native preparation completion', 'state': 'RELEASED_AND_RECOVERED',
      'phase': 'packages', 'clean_usb_release': True, 'authenticated_recovery_observed': True,
      'boot_ready': False, 'physical_powerloss_qualified': False, 'boot_id': record.boot_id,
      'configuration_sha256': contexts['early'].config_sha256, 'session_id': contexts['early'].session_id,
      'guardian_candidate': contexts['early'].candidate, 'evidence_sha256': hashlib.sha256(blobs['frame']).hexdigest(),
      'plan_sha256': hashlib.sha256(blobs['phase_a_plan']).hexdigest(),
      'payload_manifest_sha256': hashlib.sha256(blobs['phase_a_payload']).hexdigest(),
      'recovery_observation_sha256': hashlib.sha256(blobs['recovery']).hexdigest()}
    binding.update({k: observations[k] for k in ['candidate_id', 'filesystem_uuid', 'original_default',
                                              'worker_result_sha256', 'journal_sha256']})
    fields(predecessor, binding, 'Original authenticated predecessor binding differs')
    require(predecessor['candidate_id'] == payload['candidate_id'] == plan['maintenance']['candidate_id']
            and predecessor['filesystem_uuid'] == payload['filesystem_uuid'] == plan['maintenance']['filesystem_uuid']
            and predecessor['original_default'] == plan['original_default'], 'Original package identity differs')
    for name in ['worker_result_sha256', 'journal_sha256']:
      require(sha(predecessor[name]) != '0' * 64, 'Completed phase lacks actual worker/journal digests')
    fields(publication, {'format_version': 1, 'purpose': 'durably published native preparation observations',
      'phase': 'packages', 'configuration_sha256': contexts['early'].config_sha256,
      'session_id': contexts['early'].session_id, 'predecessor_sha256': hashlib.sha256(blobs['predecessor']).hexdigest(),
      'recovery_observation_sha256': hashlib.sha256(blobs['recovery']).hexdigest(),
      'boot_ready': False, 'physical_powerloss_qualified': False}, 'Original durable publication differs')
    require(type(publication['publication_observed_ns']) is type(publication['publication_deadline_ns']) is int
            and 0 < publication['publication_observed_ns'] < publication['publication_deadline_ns'],
            'Original publication was not within its own deadline')
    fields(recovery, {'purpose': 'secure SOS return observation', 'route': 'recovery',
      'secure_adb_root_observed': True, 'baseline_sha256': g['baseline_sha256'], 'adb_sha256': g['adb_sha256'],
      'native_boot_id': record.boot_id, 'native_epoch': 'early',
      'native_session_id': contexts['early'].session_id,
      'native_configuration_sha256': contexts['early'].config_sha256,
      'evidence_sha256': hashlib.sha256(blobs['frame']).hexdigest(), 'boot_ready': False},
      'Original secure recovery observation differs')
    require(recovery['boot_id'] not in {record.boot_id, recovery['initial_boot_id']}, 'Original secure recovery was not a new boot')
    fields(report('body_actual'), {'actual_wait_exit': 1, 'positive_wait_observed': True,
      'owned_group_absent': True, 'unit_only_owner_remaining': True, 'timed_out': False, 'interrupted': False},
      'Original closed HOST owner proof differs')
    elapsed = report('body_actual')['elapsed_seconds']
    require(type(elapsed) in {int, float} and math.isfinite(elapsed) and 0 < elapsed < 1100,
            'Original HOST owner exceeded its own lifetime')
    fields(report('body_failure'), {'actual_packages_publication_observed': True,
      'finalization_failed_after_valid_A_publication': True, 'replay_allowed': False, 'boot_ready': False,
      'error_type': 'ValueError', 'error': 'Ancestor-only destination requires exact existing identity'},
      'Failure did not follow an actual successful package publication')
    fields(report('body_publication'), {'state': 'ACTUAL_PACKAGES_PREPARATION_PUBLISHED',
      'predecessor_sha256': hashlib.sha256(blobs['predecessor']).hexdigest(),
      'recovery_observation_sha256': hashlib.sha256(blobs['recovery']).hexdigest(),
      'publication_sha256': hashlib.sha256(blobs['publication']).hexdigest(),
      'directory': str(attempt_path), 'boot_ready': False},
      'Original live publisher return was not recorded')
    fields(report('windows_owner'), {'actualProcessHandleRetained': True, 'positiveWslWaitObserved': True,
      'wslActualExitCode': 1, 'ownerExitCode': 1}, 'Original Windows WSL wait proof differs')
    windows_elapsed = report('windows_owner')['elapsedMs']
    require(type(windows_elapsed) is int and 0 < windows_elapsed < 1500000,
            'Original Windows owner exceeded its separate clock-domain lifetime')
    fields(report('windows_launcher'), {'actualOwnerHandleRetained': True, 'positiveOwnerWaitObserved': True,
      'actualOwnerExitCode': 1}, 'Original Windows owner wait proof differs')
    closure = report('root_closure')
    fields(closure, {'Windows_positive_handle_waits_and_actual_numeric_exits_verified': True,
      'Linux_positive_wait_PG_absence_sole_CG_verified': True, 'cgroup_absent': True,
      'packages_publication_observed_in_body': True, 'expected_preimages_and_WriterPin_absent': True,
      'no_physical_layer_written': True, 'B_C_or_permanent_boot_released': False, 'boot_ready': False},
      'Closed root observation differs')
    for k, artifact in [('gate', 'execution_gate'), ('predecessor', 'predecessor'), ('publication', 'publication'),
                        ('recovery_observation', 'recovery'), ('body_actual', 'body_actual'), ('body_failure', 'body_failure')]:
      require(closure[k] == g['artifacts'][artifact], 'Closed artifact ancestry differs')
    for k, artifact in [('Windows_owner_terminal', 'windows_owner'), ('Windows_launcher_terminal', 'windows_launcher')]:
      require(closure[k]['sha256'] == g['artifacts'][artifact]['sha256']
              and closure[k]['bytes'] == g['artifacts'][artifact]['bytes'], 'Retained Windows terminal copy differs')
    audit = report('actual_audit')
    require(audit['closure'] == g['artifacts']['root_closure'], 'Independent closed audit binding differs')
    fields(audit['outcome'], {'actual_native_packages_phase_passed': True,
      'clean_storage_release_and_new_secure_recovery_observed': True,
      'durable_A_publication_hash_chain_verified': True, 'overall_operator_exit': 1,
      'package_replay_allowed': False, 'same_live_HOST_finalization_succeeded': False,
      'WriterPin_or_expected_preimages_or_success_result_present': False}, 'Independent completed-A outcome differs')
    old_witness, witness, layer = [json_bytes(blobs[n]) for n in ['old_witness', 'new_witness', 'new_layer_pin']]
    require(execution['witness'] == g['artifacts']['old_witness']
            and old_witness['layer'] == {k: execution['witness_layer_pin'][k] for k in
              ['archive_sha256', 'manifest_sha256', 'profile_sha256', 'payload_manifest_sha256']},
            'Original witness was not the one admitted before package execution')
    require(set(old_witness) == set(witness) and all(old_witness[k] == witness[k] for k in witness if k != 'layer')
            and witness['physical_preimages_admitted'] is witness['boot_ready'] is False,
            'New witness changed predicted preimages or authority')
    require(witness['layer'] == {k: layer[k] for k in ['archive_sha256', 'manifest_sha256', 'profile_sha256', 'payload_manifest_sha256']}
            and witness['candidate_id'] == predecessor['candidate_id']
            and witness['filesystem_uuid'] == predecessor['filesystem_uuid']
            and witness['original_accounts'] == plan['maintenance']['base_account_preimages']
            and layer['payload_manifest_sha256'] == predecessor['payload_manifest_sha256'],
            'Current witness/layer is not for the original completed preparation')
    migration = report('layer_migration_proof')
    fields(migration, {'state': 'EXACT_OLD_TO_NEW_LAYER_CONTENT_ROLE_PROOF',
      'candidate_payload_filesystem_accounts_and_all_other_manifest_fields_equal': True,
      'old_witness_unchanged_and_not_retargeted': True, 'remaining_ancestor_only_mismatches': 0,
      'physical_preimages_admitted': False, 'writer_authority': False, 'native_release': False},
      'Layer migration proof is incomplete')
    require(migration['old_archive']['sha256'] == old_witness['layer']['archive_sha256']
            and migration['new_archive']['sha256'] == layer['archive_sha256']
            and migration['old_manifest_sha256'] == old_witness['layer']['manifest_sha256']
            and migration['new_manifest_sha256'] == layer['manifest_sha256']
            and migration['entry_identities_equal'] == len(witness['entries'])
            and migration['role_changes'] == ['etc/systemd/journald.conf.d', 'etc/systemd/system/user@1001.service.d']
            and migration['source_changes'] == ['tools/prepare-native-qualification-layer.py'],
            'Unreviewed layer migration')
    witness_result = report('new_witness_result')
    fields(witness_result, {'passed': True, 'qemu_exit': 0, 'console_EOF_observed': True,
      'both_backing_images_unchanged': True, 'guest_unmounted': True, 'media_writes': False,
      'transaction_replayed': False, 'physical_preimages_admitted': False, 'boot_ready': False,
      'witness_sha256': hashlib.sha256(blobs['new_witness']).hexdigest(),
      'witness_bytes': len(blobs['new_witness'])}, 'Fresh read-only witness completion differs')
    migration_audit, witness_audit = report('layer_migration_audit'), report('new_witness_audit')
    require(migration_audit['compatibility_proof'] == g['artifacts']['layer_migration_proof']
            and migration_audit['old_archive_aggregate'] == migration['old_archive']
            and migration_audit['new_archive_aggregate'] == migration['new_archive'],
            'Independent migration audit bindings differ')
    require(witness_audit['new_witness_aggregate'] == g['artifacts']['new_witness']
            and witness_audit['old_witness_aggregate'] == g['artifacts']['old_witness']
            and witness_audit['host_result'] == g['artifacts']['new_witness_result'],
            'Independent fresh witness audit bindings differ')
    began = now()
    fresh = plain(observer.inspect_initial())
    check(cutoff)
    fields(fresh, {'purpose': 'secure recovery identity observation', 'route': 'recovery',
      'secure_adb_root_observed': True, 'baseline_sha256': g['baseline_sha256'],
      'adb_sha256': g['adb_sha256'], 'boot_ready': False}, 'Fresh secure SOS observation failed')
    require(observer.initial_attempted and observer.initial is not None
            and plain(observer.initial) == fresh and observer.returned is None and not observer.return_attempted,
            'Fresh observation was not retained by its original observer')
    require(set(fresh['critical_partitions']) == {'LNX', 'SOS'}, 'Fresh critical partition closure differs')
    for name, expected in observer.baseline.partitions.items():
      fields(fresh['critical_partitions'][name], {k: expected[k] for k in ['index', 'bytes', 'sha256']},
             'Fresh critical partition differs from the independent baseline')
    # A later SOS boot is allowed only by this explicit root policy. It is not
    # evidence that USB content stayed unchanged; native B still checks all preimages.
    fresh_boot = boot_uuid(fresh['boot_id'])
    require(fresh['device'] == recovery['device'] and fresh['kernel_release'] == recovery['kernel_release'],
            'Fresh secure recovery device/kernel differs')
    require(fresh['critical_partitions'] == recovery['critical_partitions']
            and began <= fresh['started_monotonic_ns'] <= fresh['observed_monotonic_ns'] < cutoff,
            'Fresh secure recovery baseline or observation lifetime differs')
    write_once(fd, 'FRESH_RECOVERY.json', canonical(fresh), cutoff)
    source_check(g['source_sha256'])
    info = os.fstat(fd)
    values = {'predecessor_raw': blobs['predecessor'], 'predecessor_sha256': hashlib.sha256(blobs['predecessor']).hexdigest(),
      'recovery_observation_sha256': hashlib.sha256(blobs['recovery']).hexdigest(),
      'original_publication_sha256': hashlib.sha256(blobs['publication']).hexdigest(),
      'fresh_recovery_sha256': hashlib.sha256(canonical(fresh)).hexdigest(),
      'fresh_recovery_boot_relation': 'same-return-boot' if fresh_boot == recovery['boot_id'] else 'later-recovery-boot',
      'grant_sha256': expected_sha256,
      'witness_sha256': hashlib.sha256(blobs['new_witness']).hexdigest(),
      'layer_pin_sha256': hashlib.sha256(blobs['new_layer_pin']).hexdigest(),
      '_owner': owner, '_cutoff': cutoff, '_group': group, '_fd': fd,
      '_identity': (info.st_dev, info.st_ino), '_claim_raw': claim_raw, '_consumed': False}
    admitted = object.__new__(AuditedCompletedPreparation)
    for name, value in values.items(): object.__setattr__(admitted, name, value)
    admitted.owner_check()
    return admitted
  except BaseException:
    os.close(fd)
    raise
