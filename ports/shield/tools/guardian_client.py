"""Root-only consumer of the finite guardian protocol; no watchdog descriptor.

STATUS compares a phase's required reserve with existing absolute deadlines.
No packet can choose a timeout, fan value, MMIO address or extend a deadline.
"""
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
import uuid
from usb_root_profile import require

MAGIC = 0x53474731
VERSION = 1
STATUS, ABORT, QUIESCE = 1, 2, 3
CLIENT_ABORT = 9
WORK, QUIESCING, FAULT_HOLD = 2, 3, 4
SECOND = 1_000_000_000
REQUEST = struct.Struct('<4I64s36s')
RESPONSE = struct.Struct('<8I64s36sI8Q7i5I')
SOCKET_PATH = Path('/run/shield-guardian/control.sock')


def identities(candidate, boot_id):
  require(isinstance(candidate, str) and re.fullmatch('[0-9a-f]{64}', candidate)
          and candidate != '0' * 64, 'Invalid guardian candidate')
  require(isinstance(boot_id, str) and str(uuid.UUID(boot_id)) == boot_id, 'Invalid boot identity')


def decode_packet(data, candidate, boot_id, role):
  identities(candidate, boot_id)
  require(role in (1, 2) and len(data) == RESPONSE.size, 'Wrong guardian response size/role')
  values = RESPONSE.unpack(data)
  fields = ['magic', 'version', 'bytes', 'role', 'phase', 'fault', 'flags', 'request_result',
    'candidate', 'boot_id', 'reserved', 'now_ns', 'opened_ns', 'sample_ns', 'last_ping_ns',
    'work_cutoff_ns', 'cleanup_cutoff_ns', 'ping_count', 'sample_sequence',
    'cpu', 'local', 'remote', 'remote_fault', 'pwm', 'enable', 'rpm', 'cfg', 'ptv', 'sts', 'pcr', 'reserved2']
  result = dict(zip(fields, values, strict=True))
  require(result['magic'] == MAGIC and result['version'] == VERSION and result['bytes'] == RESPONSE.size,
          'Wrong guardian protocol')
  require(result['candidate'] == candidate.encode() and result['boot_id'] == boot_id.encode()
          and result['role'] == role, 'Guardian identity differs')
  require(result['reserved'] == result['reserved2'] == 0 and not result['flags'] & ~7,
          'Unknown guardian response fields')
  require(result['phase'] in range(5) and result['fault'] in range(10)
          and result['request_result'] in (0, 1), 'Unknown guardian state')
  result['candidate'], result['boot_id'] = candidate, boot_id
  return result


def require_work_status(status, seconds, now_ns):
  require(isinstance(seconds, int) and not isinstance(seconds, bool) and seconds >= 0,
          'Reserve must be a nonnegative integer')
  require(status['phase'] == WORK and status['fault'] == 0 and status['flags'] == 7
          and status['request_result'] == 0, 'Guardian has not admitted work')
  require(0 < status['opened_ns'] < 120 * SECOND and status['ping_count'] > 0
          and status['opened_ns'] <= status['last_ping_ns'] <= status['now_ns']
          and now_ns - status['last_ping_ns'] <= 60 * SECOND, 'Guardian ownership history invalid')
  require(0 < status['sample_ns'] <= status['now_ns'] <= now_ns
          and now_ns - status['now_ns'] <= SECOND
          and now_ns - status['sample_ns'] <= 3 * SECOND and status['sample_sequence'] > 0,
          'Guardian status/sample is stale')
  require(status['work_cutoff_ns'] == 540 * SECOND and status['cleanup_cutoff_ns'] == 600 * SECOND,
          'Guardian compiled deadlines differ')
  require(all(-40000 <= status[name] < 70000 for name in ['cpu', 'local', 'remote'])
          and status['remote_fault'] == 0 and status['pwm'] == 255 and status['enable'] == 2
          and 0 < status['rpm'] <= 999999, 'Guardian cooling state invalid')
  require(status['cfg'] == 0x8017 and status['ptv'] == 0xc3938700 and status['sts'] & 1,
          'Inherited timer signature differs')
  require(now_ns + seconds * SECOND < status['work_cutoff_ns'], 'Insufficient finite work allowance')
  return status


class GuardianClient:
  def __init__(self, candidate, boot_id, role):
    identities(candidate, boot_id)
    require(role in (1, 2), 'Unknown guardian role')
    self.candidate, self.boot_id, self.role = candidate, boot_id, role
    self.owner_pid = self.owner_pidfd = None

  def close(self):
    if self.owner_pidfd is not None:
      os.close(self.owner_pidfd)
      self.owner_pidfd = None

  def request(self, operation, reason=0):
    require(os.geteuid() == 0, 'Guardian control requires root')
    require((operation, reason) in {(STATUS, 0), (ABORT, CLIENT_ABORT), (QUIESCE, 0)}, 'Unowned operation')
    parent, endpoint = SOCKET_PATH.parent.lstat(), SOCKET_PATH.lstat()
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700
            and parent.st_uid == parent.st_gid == 0, 'Untrusted guardian directory')
    require(stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o600
            and endpoint.st_uid == endpoint.st_gid == 0, 'Untrusted guardian endpoint')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC) as channel:
      channel.settimeout(1)
      channel.connect(str(SOCKET_PATH))
      pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
      require(pid > 1 and uid == gid == 0, 'Untrusted guardian peer')
      if self.owner_pid is None:
        self.owner_pid = pid
        self.owner_pidfd = os.pidfd_open(pid, 0)
      require(pid == self.owner_pid, 'Guardian owner changed; never adopt a restarted owner')
      import select
      require(not select.select([self.owner_pidfd], [], [], 0)[0], 'Guardian owner died')
      packet = REQUEST.pack(MAGIC, VERSION, operation, reason, self.candidate.encode(), self.boot_id.encode())
      require(channel.send(packet) == REQUEST.size, 'Incomplete guardian request')
      data, ancillary, flags, _address = channel.recvmsg(RESPONSE.size, 0)
      require(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'Truncated/ancillary guardian response')
    result = decode_packet(data, self.candidate, self.boot_id, self.role)
    require(result['request_result'] == 0, 'Guardian refused operation')
    return result

  def require_work(self, seconds):
    return require_work_status(self.request(STATUS), seconds, time.clock_gettime_ns(time.CLOCK_BOOTTIME))

  def abort(self):
    result = self.request(ABORT, CLIENT_ABORT)
    require(result['phase'] == FAULT_HOLD, 'Guardian did not latch abort')
    return result

  def quiesce(self):
    result = self.request(QUIESCE)
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    require(result['phase'] == QUIESCING and result['fault'] == 0 and result['flags'] & 1
            and now < result['cleanup_cutoff_ns'] <= 600 * SECOND
            and result['cleanup_cutoff_ns'] <= result['now_ns'] + 60 * SECOND,
            'Guardian did not admit bounded quiesce')
    return result
