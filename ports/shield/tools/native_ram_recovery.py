"""Role1 guardian's private recovery receiver, served by the RAM PID1 itself.

Receives only the fixed guardian ABI and preserves its existing cleanup cutoff.
It does not stop workers, mount/sync storage, open/feed a watchdog or restart.
Those ordered effects belong to the actual PID1 supervisor and its release and
authenticated host-evidence consumers, not a packet's mere arrival.
"""
import os
from pathlib import Path
import select
import socket
import stat
import struct

from guardian_binding import INSTALL
from guardian_client import GuardianClient, MAGIC, REQUEST, SECOND, STATUS, VERSION
from native_boot_context import directory
from native_serial_link import now
from usb_root_profile import require

DIRECTORY = Path('/run/shield-recovery')
ENDPOINT = DIRECTORY / 'request.sock'


class Recovery:
  def __init__(self, bundle):
    require(os.getpid() == 1 and bundle.epoch == 'early'
            and bundle.phase in {'packages', 'layer'} and bundle.profile['role'] == 1,
            'Only maintenance RAM PID1 serves role1 recovery')
    self.bundle = bundle
    DIRECTORY.mkdir(mode=0o700)  # Never adopt a prior receiver attempt.
    directory(DIRECTORY, private=True)
    require(not ENDPOINT.exists() and not ENDPOINT.is_symlink(), 'Existing recovery endpoint')
    self.listener = socket.socket(socket.AF_UNIX,
      socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
    self.listener.bind(str(ENDPOINT))
    os.chmod(ENDPOINT, 0o600)
    self.listener.listen(1)
    self.channel = self.guard = None
    self.accept_attempted = False
    self.ready_received = False
    self.deadline = self.reason = None
    self.pending_owner_loss = False
    self.channel_eof = False
    self.previous = now()
    self.client = GuardianClient(bundle.profile['candidate'], bundle.boot_id, 1)

  def accept(self, guard):
    require(not self.accept_attempted and guard.name == 'guardian' and not guard.reaped,
            'Recovery owner cannot be replaced')
    try: channel, _address = self.listener.accept()
    except BlockingIOError: return False
    self.accept_attempted = True
    try:
      pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
      require(pid == guard.pid and uid == gid == 0
              and not select.select([guard.pidfd], [], [], 0)[0]
              and os.readlink('/proc/' + str(pid) + '/exe') == str(INSTALL / 'shield-guardian'),
              'Recovery sender is not the owned guardian child')
      expected = [str(INSTALL / 'shield-guardian'), '--run']
      require(Path('/proc/' + str(pid) + '/cmdline').read_bytes()
              == b'\0'.join(os.fsencode(item) for item in expected) + b'\0',
              'Owned guardian argv differs')
      channel.setblocking(False)
      self.channel, self.guard = channel, guard
      return True
    except BaseException:
      channel.close()
      raise

  def clock(self):
    timestamp = now()
    require(0 < self.previous <= timestamp <= 600 * SECOND, 'Recovery clock/final budget')
    self.previous = timestamp
    return timestamp

  def status(self):
    require(self.guard is not None and not self.guard.reaped
            and not select.select([self.guard.pidfd], [], [], 0)[0], 'Owned guardian lost')
    value = self.client.request(STATUS)
    timestamp = self.clock()
    require(self.client.owner_pid == self.guard.pid
            and 0 < value['now_ns'] <= timestamp and timestamp - value['now_ns'] <= SECOND
            and 0 < value['cleanup_cutoff_ns'] <= 600 * SECOND,
            'Guardian status/cleanup window differs')
    observed = value['cleanup_cutoff_ns']
    self.deadline = observed if self.deadline is None else min(self.deadline, observed)
    require(timestamp < self.deadline, 'Observed guardian cleanup deadline already expired')
    return value

  def _cutoff(self, reason, disconnected=False):
    timestamp = self.clock()
    cutoff = min(timestamp + 45 * SECOND, 600 * SECOND)
    if disconnected:
      require(self.guard is not None and select.select([self.guard.pidfd], [], [], 0)[0],
              'A missing packet does not prove guardian death')
    else:
      cutoff = min(cutoff, self.status()['cleanup_cutoff_ns'])
    self.deadline = cutoff if self.deadline is None else min(self.deadline, cutoff)
    require(timestamp < self.deadline, 'No remaining owned cleanup allowance')
    if self.reason is None: self.reason = reason
    return {'reason': self.reason, 'cleanup_deadline_ns': self.deadline,
            'owner_confirmed': True}

  def _pending_loss(self, reason):
    # exit_files closes sockets BEFORE exit_notify makes pidfds readable. Stop
    # work immediately on the lost channel, but do not turn that ordering gap
    # into a proof of death, fresh cleanup window or restart permission.
    timestamp = self.clock()
    cutoff = min(timestamp + 45 * SECOND, 600 * SECOND)
    self.deadline = cutoff if self.deadline is None else min(self.deadline, cutoff)
    if self.reason is None: self.reason = reason
    self.pending_owner_loss = True
    return self.poll_owner_loss()

  def poll_owner_loss(self):
    require(self.pending_owner_loss and self.guard is not None, 'No pending owner loss')
    require(self.clock() < self.deadline, 'Owner-loss observation budget exhausted')
    if select.select([self.guard.pidfd], [], [], 0)[0]:
      self.pending_owner_loss = False
      return self._cutoff(self.reason, disconnected=True)
    return {'reason': self.reason, 'cleanup_deadline_ns': self.deadline,
            'owner_confirmed': False}

  def observe_dead_owner(self):
    require(self.guard is not None and select.select([self.guard.pidfd], [], [], 0)[0],
            'Pinned guardian death has not been observed')
    return self._cutoff(self.reason or {'event': 'guardian-disconnected'}, disconnected=True)

  def receive(self):
    require(self.channel is not None and not self.channel_eof and not self.pending_owner_loss,
            'Recovery guard not attached or loss pending')
    try: data, ancillary, flags, _address = self.channel.recvmsg(REQUEST.size, 0, socket.MSG_CMSG_CLOEXEC)
    except BlockingIOError: return None
    if not data:
      self.channel_eof = True
      # PID1 unregisters this still-owned fd and observes the pinned pidfd/wait
      # without polling the EOF stream. close() ultimately relinquishes it.
      return self._pending_loss({'event': 'guardian-disconnected'})
    # Linux echoes the requested CLOEXEC input flag; every other output flag is invalid.
    require(not ancillary and not (flags & ~socket.MSG_CMSG_CLOEXEC) and len(data) == REQUEST.size,
            'Wrong guardian recovery packet')
    magic, version, operation, fault, candidate, boot = REQUEST.unpack(data)
    require(magic == MAGIC and version == VERSION
            and candidate == self.bundle.profile['candidate'].encode('ascii')
            and boot == self.bundle.boot_id.encode('ascii')
            and ((operation == 4 and 1 <= fault <= 9) or (operation in {5, 6} and fault == 0)),
            'Wrong guardian recovery identity/cause')
    if operation == 6:
      require(not self.ready_received and self.reason is None and self.clock() < 120 * SECOND,
              'Repeated, late or post-fault guardian readiness')
      self.ready_received = True
      # An event wakes the supervisor. Only actual pinned work STATUS/health
      # and reserve admission may start its worker; this boolean cannot.
      return {'event': 'guardian-ready'}
    reason = {'operation': operation, 'fault': fault}
    if self.reason is None: self.reason = reason
    if select.select([self.guard.pidfd], [], [], 0)[0]:
      return self.observe_dead_owner()
    try: return self._cutoff(reason)
    except OSError:
      # A valid queued FAULT can precede pre-open owner exit. Preserve that
      # exact cause while awaiting actual death. Protocol, clock, identity and
      # observed-expired-cutoff errors are absorbing; they never become a fresh
      # pending-loss allowance.
      return self._pending_loss(reason)

  def close(self):
    self.client.close()
    if self.channel is not None: self.channel.close()
    self.listener.close()
