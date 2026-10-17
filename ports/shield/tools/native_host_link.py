"""One presealed host SNCP1 consumer; no boot, workload or reboot dispatch.

The controller passes USB stdout only to feed_device(), and independently feeds
the owned PowerShell process's stderr to BridgeState.feed_stderr(). Device
bytes never become local lifecycle metadata. Both systemd epochs share that
BridgeState; the root session requires the early session's verified boot UUID.
The caller owns process supervision and an absolute host monotonic deadline.

Only fixed maintenance-release, systemd handoff and root cleanup EVIDENCE
schemas are accepted; observations never select work or authorize another phase.
PrivateFrameStore fsyncs the exact verified frame and its directory before the
receipt-correlated PING is queued. This retains a source-bound RO claim, not
independent media attestation, successful reboot or permission to write.
handoff-confirmed means retained prepared-handoff evidence and its round trip;
it does not establish switch_root execution, systemd or desktop startup.
maintenance-confirmed means retained release evidence and its round trip;
secure recovery and any positive predecessor receipt require separate proof.

Unqualified draft: do not import or run tests before the combined source gate.
"""
from collections import deque
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
import uuid

from native_control_protocol import MAX_LINE_BYTES, Session
from native_serial_link import (BYTE_BUDGET, Framer, cleanup_challenge, handoff_challenge,
                                maintenance_challenge)
from usb_root_profile import require

SECOND = 1_000_000_000
HEX = re.compile(r'[0-9a-f]{64}\Z')
HINT = re.compile(rb'SNCR1 ([0-9a-f]{64})\n\Z')
OBSERVATION_FIELDS = frozenset({'kind', 'candidate', 'boot_id',
  'cleanup_deadline_ns', 'receipt_sha256', 'nonce', 'readonly_state_verified',
  'root_unmounted', 'hardware_powerloss_qualified', 'receipt'})
RECEIPT_FIELDS = frozenset({'phase', 'boot_ready', 'candidate', 'reason',
  'cleanup_deadline_ns', 'readonly_state_verified', 'root_unmounted',
  'hardware_powerloss_qualified'})
HANDOFF_FIELDS = frozenset({'kind', 'root_session_id', 'candidate_id', 'filesystem_uuid',
  'payload_manifest_sha256', 'layer_manifest_sha256', 'phase_a_receipt_sha256',
  'phase_b_receipt_sha256', 'original_default', 'ram_children_reaped',
  'watchdog_opened', 'source_root_verified', 'boottime_ns'})

MAINTENANCE_FIELDS = frozenset({'kind', 'phase', 'candidate_id', 'filesystem_uuid',
  'payload_manifest_sha256', 'plan_sha256', 'worker_result_sha256', 'journal_sha256',
  'original_default', 'original_root_profile_preserved', 'phase_passed', 'worker_started',
  'worker_reaped', 'reaper_reaped', 'worker_leaf_empty', 'filesystem_unmounted',
  'partition_ro', 'disk_ro', 'internal_user_ro', 'cleanup_deadline_ns', 'boottime_ns',
  'nonce', 'boot_ready', 'physical_powerloss_qualified'})


@dataclass(frozen=True)
class FrozenMaintenancePin:
  phase: str
  candidate_id: str
  filesystem_uuid: str
  payload_manifest_sha256: str
  plan_sha256: str
  original_default: tuple

  def __post_init__(self):
    require(self.phase in {'packages', 'layer'}, 'Wrong independently sealed maintenance phase')
    for value in [self.payload_manifest_sha256, self.plan_sha256]:
      require(type(value) is str and HEX.fullmatch(value) and value != '0' * 64,
              'Wrong independent maintenance digest')
    require(type(self.candidate_id) is str and re.fullmatch('[0-9a-f]{32}', self.candidate_id)
            and type(self.filesystem_uuid) is str
            and str(uuid.UUID(self.filesystem_uuid)) == self.filesystem_uuid
            and type(self.original_default) is tuple and len(self.original_default) == 3
            and type(self.original_default[0]) is int and self.original_default[0] >= 256
            and type(self.original_default[1]) is int and self.original_default[1] == 5
            and self.original_default[2] == '@', 'Wrong independent maintenance identity/default')

  def projection(self):
    return {key: getattr(self, key) for key in ['phase', 'candidate_id', 'filesystem_uuid',
      'payload_manifest_sha256', 'plan_sha256']} | {'original_default': {
        'id': self.original_default[0], 'top_level': self.original_default[1],
        'path': self.original_default[2]}}


@dataclass(frozen=True)
class HandoffPin:
  root_session_id: str
  candidate_id: str
  filesystem_uuid: str
  payload_manifest_sha256: str
  layer_manifest_sha256: str
  phase_a_receipt_sha256: str
  phase_b_receipt_sha256: str
  original_default: tuple

  def __post_init__(self):
    for value in [self.root_session_id, self.payload_manifest_sha256,
                  self.layer_manifest_sha256, self.phase_a_receipt_sha256,
                  self.phase_b_receipt_sha256]:
      require(type(value) is str and HEX.fullmatch(value) and value != '0' * 64,
              'Wrong independent handoff digest/session')
    require(type(self.candidate_id) is str and re.fullmatch('[0-9a-f]{32}', self.candidate_id)
            and type(self.filesystem_uuid) is str
            and str(uuid.UUID(self.filesystem_uuid)) == self.filesystem_uuid
            and type(self.original_default) is tuple and len(self.original_default) == 3
            and type(self.original_default[0]) is int and self.original_default[0] >= 256
            and type(self.original_default[1]) is int and self.original_default[1] == 5
            and self.original_default[2] == '@', 'Wrong independent handoff identity/default')

  def projection(self):
    return {key: getattr(self, key) for key in ['root_session_id', 'candidate_id',
      'filesystem_uuid', 'payload_manifest_sha256', 'layer_manifest_sha256',
      'phase_a_receipt_sha256', 'phase_b_receipt_sha256']} | {'original_default': {
        'id': self.original_default[0], 'top_level': self.original_default[1],
        'path': self.original_default[2]}}


def now(): return time.monotonic_ns()


def plain(value):
  # Protocol records contain immutable mappings/tuples. Project explicitly.
  if hasattr(value, 'items'): return {key: plain(item) for key, item in value.items()}
  if type(value) is tuple: return [plain(item) for item in value]
  return value


class BridgeState:
  """Lifecycle observations from the separately owned stderr pipe only."""

  def __init__(self):
    self.pending = bytearray()
    self.pid = None
    self.connected = self.stopped = self.failed = False
    self.total = 0

  def feed_stderr(self, data):
    try:
      require(not self.failed and type(data) is bytes and 0 < len(data) <= 8192,
              'Invalid bridge metadata chunk')
      self.total += len(data)
      require(self.total <= 4096, 'Bridge metadata budget')
      for byte in data:
        require(byte == 10 or 32 <= byte <= 126, 'Invalid bridge metadata byte')
        self.pending.append(byte)
        require(len(self.pending) <= 128, 'Bridge metadata line budget')
        if byte != 10: continue
        line = bytes(self.pending); self.pending.clear()
        armed = re.fullmatch(rb'SHIELD_NATIVE_BRIDGE_ARMED ([1-9][0-9]{0,9})\n', line)
        if armed:
          require(self.pid is None and not self.connected and not self.stopped,
                  'Duplicate bridge arming')
          self.pid = int(armed[1])
        elif line == b'SHIELD_NATIVE_BRIDGE_CONNECTED\n':
          require(self.pid is not None and not self.connected and not self.stopped,
                  'Unexpected bridge connection')
          self.connected = True
        elif line == b'SHIELD_NATIVE_BRIDGE_STOPPED\n':
          require(self.pid is not None and not self.stopped, 'Unexpected bridge stop')
          self.stopped = True
        else:
          raise ValueError('Bridge failed or unrecognized metadata')
    except BaseException:
      self.failed = True
      raise

  def eof(self):
    if self.failed or self.pending or not self.stopped:
      self.failed = True
      raise ValueError('Incomplete or unexpected bridge metadata EOF')
    # Successful process exit is a separate controller-owned requirement.


class PrivateFrameStore:
  """One root/user-private local receipt file, never replaced or replayed.

  Caller chooses an already owned private evidence directory and supervises
  filesystem stalls under its outer deadline. An interrupted write/fsync leaves
  the attempted file intact and never authorizes a correlated PING.
  """

  def __init__(self, directory, *, purpose):
    require(purpose in {'root-cleanup', 'systemd-handoff', 'maintenance-release'}, 'Explicit fixed receipt purpose required')
    self.purpose = purpose
    self.filename = {'root-cleanup': 'cleanup.sncp1', 'systemd-handoff': 'handoff.sncp1',
                     'maintenance-release': 'maintenance.sncp1'}[purpose]
    path = Path(directory)
    require(path.is_absolute(), 'Absolute private receipt directory required')
    self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
      info = os.fstat(self.fd)
      require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
              and info.st_uid == os.geteuid() and info.st_gid == os.getegid(),
              'Unowned private receipt directory')
    except BaseException:
      os.close(self.fd)
      raise
    self.attempted = False
    self.retained_sha256 = None

  def close(self):
    if self.fd is not None:
      descriptor, self.fd = self.fd, None
      os.close(descriptor)

  def retain(self, frame, check):
    require(not self.attempted and self.fd is not None and type(frame) is bytes
            and 0 < len(frame) <= MAX_LINE_BYTES, 'Receipt retention cannot replay')
    self.attempted = True
    check()
    descriptor = os.open(self.filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
    try:
      info = os.fstat(descriptor)
      require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
              and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
              and info.st_nlink == 1, 'Wrong private receipt file')
      cursor = 0
      while cursor < len(frame):
        check()
        count = os.write(descriptor, frame[cursor:])
        require(type(count) is int and 0 < count <= len(frame) - cursor,
                'Uncertain receipt write')
        cursor += count
      os.fsync(descriptor)
    finally:
      os.close(descriptor)
    os.fsync(self.fd)
    check()
    self.retained_sha256 = hashlib.sha256(frame).hexdigest()


@dataclass(frozen=True)
class Event:
  kind: str
  record: object = None
  challenge: str | None = None


class HostLink:
  """One live session; discard after any exception, never resume/reconnect.

  Call tick(), feed_device(), drive_write(), take_events() from one owner.
  The host controller must service both bridge pipes and enforce its process
  deadline even when local storage or Windows pipe operations block. ping()
  supplies optional liveness probes; neither probes nor frames renew deadlines.
  A new root consumer uses the same bridge, the verified early boot UUID and
  the controller's unchanged absolute deadline, after the explicit handoff gate.
  """

  def __init__(self, context, key, bridge, deadline_ns, *, epoch, store=None,
               boot_id=None, handoff_pin=None, maintenance_pin=None, clock=now,
               challenge_source=lambda: secrets.token_hex(32)):
    require(type(bridge) is BridgeState and epoch in {'early', 'root'}
            and (epoch != 'root' or context.phase == 'systemd' and boot_id is not None)
            and type(deadline_ns) is int, 'Wrong host epoch/context/deadline')
    self.session = Session(context, key, side='host', boot_id=boot_id)
    self.bridge, self.epoch, self.store = bridge, epoch, store
    require(store is None or type(store) is PrivateFrameStore, 'Wrong private frame store')
    self.handoff_pin, self.maintenance_pin = handoff_pin, maintenance_pin
    if epoch == 'early' and context.phase == 'systemd':
      require(maintenance_pin is None and type(handoff_pin) is HandoffPin and handoff_pin.root_session_id != context.session_id
              and (store is None or store.purpose == 'systemd-handoff'),
              'Independent early-systemd handoff pin/store required')
    elif epoch == 'early' and context.phase in {'packages', 'layer'}:
      require(handoff_pin is None and type(maintenance_pin) is FrozenMaintenancePin
              and maintenance_pin.phase == context.phase and store is not None
              and store.purpose == 'maintenance-release', 'Independent maintenance pin/store required')
    else:
      require(handoff_pin is None and maintenance_pin is None and (store is None or epoch == 'root'
              and store.purpose == 'root-cleanup'), 'Wrong epoch receipt purpose')
    self.clock, self.challenge_source = clock, challenge_source
    self.previous = clock()
    require(0 < self.previous < deadline_ns, 'Expired host deadline')
    self.deadline = deadline_ns
    self.framer = Framer()
    self.pending = deque()
    self.sent_bytes = 0
    self.failed = self.ready = self.probed = False
    self.terminal = False
    self.ping_challenge = None
    self.cleanup_expected = None
    self.cleanup_seen = self.cleanup_confirmed = False
    self.handoff_seen = self.handoff_confirmed = False
    self.handoff_expected = None
    self.maintenance_seen = self.maintenance_confirmed = False
    self.maintenance_expected = None
    self.target_ns = self.target_seen_ns = None
    self.events = []
    self.write_identity = None

  def _time(self):
    require(not self.failed and not self.terminal and not self.bridge.failed and not self.bridge.stopped,
            'Discarded host transport')
    timestamp = self.clock()
    require(self.previous <= timestamp < self.deadline, 'Host clock/deadline')
    self.previous = timestamp
    self.framer.check(timestamp)
    return timestamp

  def _guard(self, operation):
    try: return operation()
    except BaseException:
      self.failed = True
      raise

  def _queue(self, frame):
    require(len(self.pending) < 8, 'Host transmit queue budget')
    self.sent_bytes += len(frame)
    require(self.sent_bytes <= BYTE_BUDGET, 'Host transmit byte budget')
    self.pending.append([frame, 0])

  def _event(self, event):
    require(len(self.events) < 64, 'Undrained host event budget')
    self.events.append(event)

  def _ping(self, challenge):
    require(self.ping_challenge is None, 'Outstanding host PING')
    self._queue(self.session.send('PING', {'challenge': challenge}))
    self.ping_challenge = challenge

  def _target(self, timestamp):
    limit = 120 * SECOND if self.epoch == 'early' and not self.ready else 600 * SECOND
    require(type(timestamp) is int and 0 < timestamp < limit
            and (self.target_ns is None or timestamp >= self.target_ns),
            'Native timestamp outside epoch or regressed')
    self.target_ns, self.target_seen_ns = timestamp, self._time()

  @property
  def wants_write(self): return bool(self.pending) and not self.failed and not self.terminal

  def tick(self): return self._guard(self._time)

  def ping(self, challenge):
    def operation():
      self._time()
      require(self.ready and not self.cleanup_seen and not self.handoff_seen and not self.maintenance_seen,
              'Liveness PING outside active phase')
      self._ping(challenge)
    return self._guard(operation)

  def _cleanup(self, record, frame):
    require(self.epoch == 'root' and self.session.context.phase == 'systemd'
            and self.ready and not self.cleanup_seen and self.store is not None,
            'Cleanup evidence outside owned root phase')
    value = plain(record.payload['observations'])
    require(type(value) is dict and set(value) == OBSERVATION_FIELDS
            and value['kind'] == 'cleanup-readonly'
            and value['candidate'] == self.session.context.candidate
            and value['boot_id'] == self.session.boot_id
            and value['readonly_state_verified'] is True
            and value['root_unmounted'] is False
            and value['hardware_powerloss_qualified'] is False,
            'Wrong cleanup observation fields or identity')
    receipt, deadline = value['receipt'], value['cleanup_deadline_ns']
    require(type(deadline) is int and self.target_ns < deadline <= 600 * SECOND
            and type(value['nonce']) is str and HEX.fullmatch(value['nonce'])
            and value['nonce'] != '0' * 64
            and type(value['receipt_sha256']) is str and HEX.fullmatch(value['receipt_sha256'])
            and type(receipt) is dict and set(receipt) == RECEIPT_FIELDS,
            'Wrong cleanup receipt types or deadline')
    require(receipt['phase'] == 'filesystem-readonly' and receipt['boot_ready'] is False
            and receipt['candidate'] == value['candidate']
            and type(receipt['cleanup_deadline_ns']) is int
            and receipt['cleanup_deadline_ns'] == deadline
            and receipt['readonly_state_verified'] is True
            and receipt['root_unmounted'] is False
            and receipt['hardware_powerloss_qualified'] is False, 'Wrong cleanup receipt claims')
    reason = receipt['reason']
    require(type(reason) is dict, 'Wrong cleanup cause')
    if set(reason) == {'event'}:
      require(reason['event'] == 'guardian-disconnected', 'Wrong disconnection cause')
    else:
      require(set(reason) == {'operation', 'fault'} and type(reason['operation']) is int
              and type(reason['fault']) is int
              and (reason['operation'] == 4 and 1 <= reason['fault'] <= 9
                   or reason['operation'] == 5 and reason['fault'] == 0), 'Wrong guardian cause')
    raw = (json.dumps(receipt, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')
    require(hashlib.sha256(raw).hexdigest() == value['receipt_sha256'], 'Cleanup receipt digest mismatch')
    self.cleanup_seen = True
    self.cleanup_expected = (cleanup_challenge(frame), deadline, record)
    self.store.retain(frame, self._time)
    self._event(Event('cleanup-retained', record, self.cleanup_expected[0]))
    if self.ping_challenge is None: self._cleanup_ping()

  def _cleanup_ping(self):
    challenge, deadline, _record = self.cleanup_expected
    # Do not invent a measured timestamp for the receipt or synchronize clocks.
    # The native RPC server independently owns its existing hard 2s cutoff.
    self._time()
    require(self.target_ns < deadline, 'Expired cleanup evidence')
    self._ping(challenge)

  def _handoff(self, record, frame):
    require(self.epoch == 'early' and self.session.context.phase == 'systemd'
            and self.ready and not self.handoff_seen and self.store is not None
            and self.store.purpose == 'systemd-handoff', 'Handoff outside owned early systemd phase')
    value = plain(record.payload['observations'])
    require(type(value) is dict and set(value) == HANDOFF_FIELDS
            and value['kind'] == 'systemd-handoff'
            and value['ram_children_reaped'] is True and value['watchdog_opened'] is False
            and value['source_root_verified'] is True
            and type(value['boottime_ns']) is int
            and self.target_ns <= value['boottime_ns'] < 100 * SECOND,
            'Wrong handoff fields, claims or native timestamp')
    default = value['original_default']
    require(type(default) is dict and set(default) == {'id', 'top_level', 'path'}
            and type(default['id']) is int and type(default['top_level']) is int,
            'Wrong handoff default types')
    for key, expected in self.handoff_pin.projection().items():
      require(value[key] == expected, 'Handoff differs from independently sealed identity')
    self._target(value['boottime_ns'])
    self.handoff_seen = True
    self.handoff_expected = (handoff_challenge(frame), record)
    self.store.retain(frame, self._time)
    self._event(Event('handoff-retained', record, self.handoff_expected[0]))
    if self.ping_challenge is None: self._handoff_ping()

  def _handoff_ping(self):
    self._time()
    require(self.target_ns < 100 * SECOND, 'Handoff confirmation cutoff exhausted')
    self._ping(self.handoff_expected[0])

  def _maintenance(self, record, frame):
    require(self.epoch == 'early' and self.session.context.phase in {'packages', 'layer'}
            and self.ready and not self.maintenance_seen and self.store is not None
            and self.store.purpose == 'maintenance-release', 'Release outside owned maintenance phase')
    value = plain(record.payload['observations'])
    require(type(value) is dict and set(value) == MAINTENANCE_FIELDS
            and value['kind'] == 'maintenance-released'
            and type(value['phase_passed']) is bool and type(value['worker_started']) is bool
            and value['boot_ready'] is False and value['physical_powerloss_qualified'] is False,
            'Wrong maintenance fields or result types')
    for field in ['original_root_profile_preserved', 'worker_reaped', 'reaper_reaped',
                  'worker_leaf_empty', 'filesystem_unmounted', 'partition_ro', 'disk_ro', 'internal_user_ro']:
      require(value[field] is True, 'Maintenance release proof incomplete')
    default = value['original_default']
    require(type(default) is dict and set(default) == {'id', 'top_level', 'path'}
            and type(default['id']) is int and type(default['top_level']) is int,
            'Wrong maintenance default types')
    for key, expected in self.maintenance_pin.projection().items():
      require(value[key] == expected, 'Maintenance differs from independently sealed identity')
    for field in ['worker_result_sha256', 'journal_sha256']:
      digest = value[field]
      require(digest is None or type(digest) is str and HEX.fullmatch(digest),
              'Wrong maintenance journal/result digest')
      if value['phase_passed']:
        require(value['worker_started'] is True and digest is not None and digest != '0' * 64,
                'Passed phase lacks actual worker/result/journal')
    deadline, timestamp = value['cleanup_deadline_ns'], value['boottime_ns']
    require(type(deadline) is int and type(timestamp) is int
            and self.target_ns <= timestamp < deadline <= 600 * SECOND
            and type(value['nonce']) is str and HEX.fullmatch(value['nonce']) and value['nonce'] != '0' * 64,
            'Wrong maintenance clock/deadline/nonce')
    self._target(timestamp)
    self.maintenance_seen = True
    self.maintenance_expected = (maintenance_challenge(frame), deadline, record)
    self.store.retain(frame, self._time)
    self._event(Event('maintenance-retained', record, self.maintenance_expected[0]))
    if self.ping_challenge is None: self._maintenance_ping()

  def _maintenance_ping(self):
    self._time()
    require(self.target_ns < self.maintenance_expected[1], 'Expired maintenance release')
    self._ping(self.maintenance_expected[0])

  def feed_device(self, data):
    """Consume this epoch only; return exact unconsumed bytes at explicit handoff.

    Normal calls and terminal maintenance confirmation return b''. Only
    handoff-confirmed transfers epochs: complete future frames and
    any partial tail are returned untouched, the old framer is cleared, and this
    session is terminal. Only the controller creates the sealed root session.
    """
    def operation():
      timestamp = self._time()
      require(self.bridge.connected and type(data) is bytes and 0 < len(data) <= 8192,
              'Wrong raw USB chunk or bridge state')
      cursor = 0
      while cursor < len(data):
        newline = data.find(b'\n', cursor)
        end = len(data) if newline < 0 else newline + 1
        frames = self.framer.feed(data[cursor:end], timestamp)
        cursor = end
        if not frames: continue
        frame, = frames
        hint = HINT.fullmatch(frame)
        if hint:
          require(hint[1].decode('ascii') == self.session.context.session_id,
                  'Unexpected unsigned session hint')
          if not self.probed:
            self.probed = True
            self._queue(self.session.send('PROBE', {'challenge': self.challenge_source()}))
          continue
        require(self.probed, 'Authenticated data before single PROBE')
        record = self.session.receive(frame)
        if record.kind == 'HELLO':
          self._target(record.payload['boottime_ns'])
          self._queue(self.session.send('ACK', {'hello_body_sha256': record.body_sha256}))
          self._ping(self.challenge_source())
        elif record.kind == 'PONG':
          self._target(record.payload['boottime_ns'])
          challenge = self.ping_challenge
          require(challenge is not None and record.payload['challenge'] == challenge,
                  'Unexpected host PONG')
          self.ping_challenge = None
          if not self.ready:
            self.ready = True
            self._event(Event('ready', record, challenge))
          if self.cleanup_expected is not None:
            if challenge == self.cleanup_expected[0]:
              require(self.target_ns < self.cleanup_expected[1], 'Cleanup confirmation too late')
              self.cleanup_confirmed = True
              self._event(Event('cleanup-confirmed', record, challenge))
            else:
              self._cleanup_ping()
          self._event(Event('pong', record, challenge))
          if self.maintenance_expected is not None:
            if challenge == self.maintenance_expected[0]:
              require(self.target_ns < self.maintenance_expected[1] and not self.pending
                      and cursor == len(data) and not self.framer.pending,
                      'Late maintenance confirmation or extra terminal bytes')
              self._time()
              self.maintenance_confirmed = True
              self._event(Event('maintenance-confirmed', record, challenge))
              self.terminal = True
              return b''
            self._maintenance_ping()
          if self.handoff_expected is not None:
            if challenge == self.handoff_expected[0]:
              require(self.target_ns < 100 * SECOND and not self.pending,
                      'Late handoff or host bytes not relinquished')
              self._time()
              self.handoff_confirmed = True
              self._event(Event('handoff-confirmed', record, challenge))
              tail = bytes(self.framer.pending) + data[cursor:]
              self.framer.pending.clear(); self.framer.started_ns = None
              self.terminal = True
              return tail
            self._handoff_ping()
        elif record.kind == 'EVIDENCE':
          if self.epoch == 'early' and self.session.context.phase in {'packages', 'layer'}:
            self._maintenance(record, frame)
          elif self.epoch == 'early': self._handoff(record, frame)
          else: self._cleanup(record, frame)
        else:
          raise ValueError('Unreviewed native observation kind')
      self._time()
      return b''
    return self._guard(operation)

  def drive_write(self, fd):
    def operation():
      self._time()
      require(type(fd) is int and fd >= 0 and self.bridge.connected
              and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK,
              'Owned nonblocking bridge stdin required')
      info = os.fstat(fd)
      require(stat.S_ISFIFO(info.st_mode)
              and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY,
              'Bridge stdin must be an owned pipe writer')
      identity = (fd, info.st_dev, info.st_ino)
      if self.write_identity is None: self.write_identity = identity
      require(identity == self.write_identity, 'Bridge stdin cannot be replaced')
      if not self.pending: return
      frame, cursor = self.pending[0]
      try: count = os.write(fd, frame[cursor:])
      except BlockingIOError: return  # Known EAGAIN transferred zero bytes.
      require(type(count) is int and 0 < count <= len(frame) - cursor, 'Uncertain host write')
      self.pending[0][1] += count
      self._time()
      if self.pending[0][1] == len(frame): self.pending.popleft()
    return self._guard(operation)

  def take_events(self):
    result, self.events = tuple(self.events), []
    return result
