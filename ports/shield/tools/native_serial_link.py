"""Bounded SNCP1 native endpoint, with no workload or reboot dispatch.

The caller owns the admitted tty, process lifetime and absolute BOOTTIME limit.
Transport progress does not extend that limit. A readiness hint is unsigned and
stateless: the host may use it only to initiate its ONE presealed PROBE. All
authority still requires context admission and the authenticated round trip.

This is draft source. Both actual callers, capsule producer and tests must be
settled and reviewed together before qualification or native use.
"""
from collections import deque
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import termios
import time

from native_control_protocol import MAX_LINE_BYTES, Session
from usb_root_profile import require

SECOND = 1_000_000_000
BYTE_BUDGET = 32 * 1024**2
CLEANUP_DOMAIN = b'shield-native-cleanup/v1\0'
HANDOFF_DOMAIN = b'shield-native-handoff/v1\0'
MAINTENANCE_DOMAIN = b'shield-native-maintenance/v1\0'


def now(): return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _receipt_challenge(domain, frame):
  require(type(frame) is bytes and frame.startswith(b'SNCP1 ')
          and frame.endswith(b'\n') and len(frame) <= MAX_LINE_BYTES,
          'Expected complete encoded evidence')
  return hashlib.sha256(domain + frame).hexdigest()


def cleanup_challenge(frame):
  """Host first verifies AND durably retains this exact EVIDENCE frame.

  A PING with this challenge, followed by its completely transferred PONG,
  fences that receipt and nonce only. It does not prove a restart occurred.
  """
  return _receipt_challenge(CLEANUP_DOMAIN, frame)


def handoff_challenge(frame):
  """Exact prepared-handoff frame; never a proof that PID1 exec succeeded."""
  return _receipt_challenge(HANDOFF_DOMAIN, frame)


def maintenance_challenge(frame):
  """Exact USB-release claim; observed secure recovery is still separate."""
  return _receipt_challenge(MAINTENANCE_DOMAIN, frame)


class Framer:
  """One bounded line accumulator; never treats arbitrary tty output as logs."""

  def __init__(self):
    self.pending = bytearray()
    self.bytes = 0
    self.started_ns = None

  def feed(self, data, timestamp):
    require(type(data) is bytes and 0 < len(data) <= 8192
            and type(timestamp) is int and timestamp > 0, 'Wrong receive chunk')
    self.bytes += len(data)
    require(self.bytes <= BYTE_BUDGET, 'Receive byte budget')
    result = []
    for byte in data:
      require(byte == 10 or 32 <= byte <= 126, 'Non-ASCII native frame')
      if not self.pending: self.started_ns = timestamp
      self.pending.append(byte)
      require(len(self.pending) <= MAX_LINE_BYTES, 'Native line budget')
      if byte == 10:
        result.append(bytes(self.pending))
        self.pending.clear()
        self.started_ns = None
    return result

  def check(self, timestamp):
    require(self.started_ns is None or timestamp - self.started_ns < 5 * SECOND,
            'Incomplete native frame deadline')


@dataclass(frozen=True)
class Event:
  kind: str
  challenge: str | None = None
  reason: str | None = None


class NativeLink:
  """One native session; positive short writes advance only this frame's suffix.

  drive_read()/drive_write()/tick() are called by one event-loop owner. Never
  reconnect, replace the fd or revive this object after any exception. Returned
  events are observations; the caller applies its own work/cleanup predicates.
  """

  def __init__(self, fd, context, key, boot_id, deadline_ns, *, clock=now):
    require(type(fd) is int and fd >= 3 and type(deadline_ns) is int,
            'Wrong endpoint descriptor/deadline')
    require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK,
            'Nonblocking endpoint required')
    self.fd = fd
    self.clock = clock
    self.previous = clock()
    require(0 < self.previous < deadline_ns <= 600 * SECOND,
            'Endpoint outside finite boot window')
    self.deadline = deadline_ns
    self.session = Session(context, key, side='native', boot_id=boot_id)
    self.framer = Framer()
    self.pending = deque()
    self.sent_bytes = 0
    self.state = 'probe'
    self.ready = False
    self.failed = False
    self.next_hint = self.previous
    self.events = []
    self.pong_pending = False
    self.last_host_ns = None

  def _time(self):
    require(not self.failed, 'Discarded endpoint')
    timestamp = self.clock()
    if not self.previous <= timestamp < self.deadline:
      self.failed = True
      raise ValueError('Endpoint clock/deadline')
    self.previous = timestamp
    self.framer.check(timestamp)
    return timestamp

  def _append(self, frame, completion=None):
    require(len(self.pending) < 8, 'Transmit queue budget')
    self.sent_bytes += len(frame)
    require(self.sent_bytes <= BYTE_BUDGET, 'Transmit byte budget')
    self.pending.append([frame, 0, completion])

  def _event(self, event):
    require(len(self.events) < 32, 'Unconsumed endpoint event budget')
    self.events.append(event)

  def _guard(self, operation):
    try:
      require(not self.failed, 'Discarded endpoint')
      return operation()
    except BaseException:
      self.failed = True
      raise

  @property
  def wants_write(self): return bool(self.pending) and not self.failed

  def tick(self):
    def operation():
      timestamp = self._time()
      if self.state == 'probe' and timestamp >= self.next_hint and not self.pending:
        self._append(b'SNCR1 ' + self.session.context.session_id.encode('ascii') + b'\n')
        self.next_hint = timestamp + SECOND
    return self._guard(operation)

  def drive_read(self):
    def operation():
      timestamp = self._time()
      try: data = os.read(self.fd, 8192)
      except BlockingIOError: return
      require(data, 'Native endpoint disconnected')
      for frame in self.framer.feed(data, timestamp):
        record = self.session.receive(frame)
        self.last_host_ns = self._time()
        if record.kind == 'PROBE':
          require(self.state == 'probe', 'Unexpected PROBE state')
          # A possibly partially transmitted unsigned hint must finish. Never
          # discard/restart a prefix; the HELLO simply follows that same line.
          self.state = 'hello'
          self._append(self.session.send('HELLO', {
            'kernel_release': '7.1.0-shield-bringup', 'boottime_ns': self._time(),
            'probe_challenge': record.payload['challenge']}), ('hello', None))
        elif record.kind == 'ACK':
          require(self.state == 'ack', 'ACK before complete HELLO transfer')
          self.state = 'ping'
        elif record.kind == 'PING':
          require(self.state in {'ping', 'active'} and not self.pong_pending,
                  'PING before HELLO/ACK or prior PONG transfer')
          challenge = record.payload['challenge']
          self.pong_pending = True
          self._append(self.session.send('PONG', {'challenge': challenge,
            'boottime_ns': self._time()}), ('pong', challenge))
        elif record.kind == 'ABORT':
          self._event(Event('abort', reason=record.payload['reason']))
        else:
          raise ValueError('Unexpected host message')
      self._time()
    return self._guard(operation)

  def drive_write(self):
    def operation():
      self._time()
      if not self.pending: return
      frame, cursor, completion = self.pending[0]
      try: count = os.write(self.fd, frame[cursor:])
      except BlockingIOError: return  # Known syscall EAGAIN means zero bytes.
      require(type(count) is int and 0 < count <= len(frame) - cursor,
              'Uncertain native write')
      self.pending[0][1] += count
      self._time()
      if self.pending[0][1] != len(frame): return
      self.pending.popleft()
      if completion is None: return
      kind, challenge = completion
      if kind == 'hello': self.state = 'ack'
      if kind == 'pong':
        self.pong_pending = False
        if not self.ready:
          self.ready = True
          self.state = 'active'
          self._event(Event('ready', challenge=challenge))
        self._event(Event('pong-transferred', challenge=challenge))
      elif kind == 'evidence':
        self._event(Event('evidence-transferred', challenge=challenge))
    return self._guard(operation)

  def evidence(self, observations, *, purpose, final=False):
    def operation():
      self._time()
      require(self.ready, 'Evidence before authenticated round trip')
      require(purpose in {'cleanup', 'handoff', 'maintenance'}, 'Wrong fixed evidence purpose')
      frame = self.session.send('RESULT' if final else 'EVIDENCE',
                                {'observations': observations})
      challenge = {'cleanup': cleanup_challenge, 'handoff': handoff_challenge,
                   'maintenance': maintenance_challenge}[purpose](frame)
      self._append(frame, ('evidence', challenge))
      return challenge
    return self._guard(operation)

  def take_events(self):
    events, self.events = tuple(self.events), []
    return events


def open_native_tty():
  """Exact configfs-created ACM0 character node, never a console/getty shell.

  The PID1 gadget producer must create the acm.usb0 function, verify port_num=0,
  chmod this devtmpfs node 0600, bind the UDC after all descriptor checks and
  observe configured before opening. A later real-root service opens the same
  node after the early owner is reaped. Neither epoch reopens after fd hangup.
  The caller separately validates gadget descriptors, function links and UDC.
  """
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
          'Root native tty owner required')
  from native_boot_context import filesystem_magic
  path = Path('/dev/ttyGS0')
  info = path.lstat()
  require(stat.S_ISCHR(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == 0o600, 'Unowned native tty node')
  dev = (Path('/sys/class/tty/ttyGS0/dev')).read_text().strip().split(':')
  require(len(dev) == 2 and all(part.isdigit() for part in dev)
          and info.st_rdev == os.makedev(*map(int, dev)), 'Native tty sysfs identity differs')
  descriptor = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK
                       | os.O_CLOEXEC | os.O_NOFOLLOW)
  try:
    actual = os.fstat(descriptor)
    require((actual.st_dev, actual.st_ino, actual.st_rdev) ==
            (info.st_dev, info.st_ino, info.st_rdev)
            and filesystem_magic(descriptor) == 0x01021994, 'Native tty changed')
    fcntl.ioctl(descriptor, termios.TIOCEXCL)
    attributes = termios.tcgetattr(descriptor)
    attributes[0] = attributes[1] = attributes[3] = 0
    attributes[2] = termios.CLOCAL | termios.CREAD | termios.CS8
    attributes[4] = attributes[5] = termios.B115200
    attributes[6][termios.VMIN] = 1
    attributes[6][termios.VTIME] = 0
    termios.tcsetattr(descriptor, termios.TCSANOW, attributes)
    return descriptor
  except BaseException:
    os.close(descriptor)
    raise
