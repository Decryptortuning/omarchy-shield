"""One held private cleanup-control connection; no watchdog or restart effects.

The receiver's observed RO receipt is exported over the authenticated native
link. Only retention of that exact receipt by the host, followed by a correlated
PING/PONG, permits the local RPC acknowledgement. This software fence does not
prove media durability, physical power loss or successful recovery reboot.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct

from native_boot_context import (DIRECTORY, RUNTIME, canonical, directory, json_bytes,
  load, owned_bytes, plain, sha)
from native_serial_link import SECOND, now
from usb_root_profile import require

ENDPOINT = DIRECTORY / 'root-control.sock'
RECEIPT = Path('/run/shield-recovery/state.json')
RECEIVER = Path('/usr/lib/omarchy/shield/qualification/qualification_recovery.py')
CONTROL = RUNTIME / 'native-root-control.py'
MAX_PACKET = 4096


def receipt_bytes(value):
  return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def validate_receipt(value, candidate, deadline):
  require(type(value) is dict and set(value) == {'phase', 'boot_ready', 'candidate',
    'reason', 'cleanup_deadline_ns', 'readonly_state_verified', 'root_unmounted',
    'hardware_powerloss_qualified'}, 'Wrong RO receipt fields')
  require(value['phase'] == 'filesystem-readonly' and value['candidate'] == candidate
          and value['boot_ready'] is False and value['readonly_state_verified'] is True
          and value['root_unmounted'] is False and value['hardware_powerloss_qualified'] is False
          and type(value['cleanup_deadline_ns']) is int
          and value['cleanup_deadline_ns'] == deadline, 'Wrong RO receipt binding/flags')
  reason = value['reason']
  require(type(reason) is dict, 'Wrong cleanup cause')
  if set(reason) == {'event'}:
    require(reason['event'] == 'guardian-disconnected', 'Wrong disconnected cause')
  else:
    require(set(reason) == {'operation', 'fault'} and type(reason['operation']) is int
            and type(reason['fault']) is int
            and ((reason['operation'] == 4 and 1 <= reason['fault'] <= 9)
                 or (reason['operation'] == 5 and reason['fault'] == 0)), 'Wrong guardian cause')


def evidence(value, bundle, timestamp):
  require(type(value) is dict and set(value) == {'kind', 'candidate', 'boot_id',
    'cleanup_deadline_ns', 'receipt_sha256', 'nonce', 'readonly_state_verified',
    'root_unmounted', 'hardware_powerloss_qualified', 'receipt'}, 'Wrong cleanup evidence fields')
  require(value['kind'] == 'cleanup-readonly' and value['candidate'] == bundle.profile['candidate']
          and value['boot_id'] == bundle.boot_id and value['readonly_state_verified'] is True
          and value['root_unmounted'] is False and value['hardware_powerloss_qualified'] is False,
          'Wrong cleanup evidence identity/flags')
  deadline = value['cleanup_deadline_ns']
  require(type(deadline) is int and 0 < timestamp < deadline <= 600 * SECOND,
          'Stale cleanup evidence deadline')
  sha(value['receipt_sha256']); sha(value['nonce'])
  validate_receipt(value['receipt'], bundle.profile['candidate'], deadline)
  require(hashlib.sha256(receipt_bytes(value['receipt'])).hexdigest() == value['receipt_sha256'],
          'Cleanup receipt digest differs')
  return min(timestamp + 2 * SECOND, deadline - 3 * SECOND)


def binding(bundle, kind):
  return {'kind': kind, 'candidate': bundle.profile['candidate'], 'boot_id': bundle.boot_id,
          'configuration_sha256': bundle.contexts['root'].config_sha256,
          'session_id': bundle.contexts['root'].session_id}


def response(bundle, request):
  return {**binding(bundle, 'cleanup-accepted'), 'receipt_sha256': request['receipt_sha256'],
          'nonce': request['nonce']}


class Peer:
  """Pin a live root PID1 child on this connection; never reconnect/adopt."""

  def __init__(self, channel, expected_argv):
    require(channel.family == socket.AF_UNIX
            and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET,
            'Wrong cleanup RPC transport')
    pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(pid > 1 and uid == gid == 0 and pid != os.getpid(), 'Wrong cleanup RPC peer')
    self.pid = pid
    self.fd = os.pidfd_open(pid, 0)
    self.argv = expected_argv
    try: self.check()
    except BaseException:
      self.close()
      raise

  def check(self):
    require(not select.select([self.fd], [], [], 0)[0], 'Cleanup RPC peer exited')
    process = Path('/proc') / str(self.pid)
    require(os.readlink(process / 'exe') == '/usr/bin/python3.14'
            and (process / 'cmdline').read_bytes() == b'\0'.join(os.fsencode(x) for x in self.argv) + b'\0',
            'Cleanup peer program differs')
    rows = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines())
    require(rows['PPid'].strip() == '1'
            and rows['Uid'].split() == rows['Gid'].split() == ['0'] * 4
            and os.readlink(process / 'ns/mnt') == os.readlink('/proc/1/ns/mnt'),
            'Cleanup peer ownership/namespace differs')
    require(not select.select([self.fd], [], [], 0)[0], 'Cleanup RPC peer changed')

  def close(self):
    if self.fd is not None: os.close(self.fd); self.fd = None


def send(channel, value):
  raw = canonical(value)
  require(len(raw) <= MAX_PACKET and channel.send(raw) == len(raw),
          'Uncertain cleanup packet; never replay')


def receive(channel):
  packet, ancillary, flags, _address = channel.recvmsg(MAX_PACKET, 0, socket.MSG_CMSG_CLOEXEC)
  require(packet and not ancillary and not flags, 'Truncated/ancillary/closed cleanup packet')
  return json_bytes(packet)


def wait_packet(channel, peer, deadline):
  peer.check()
  remaining = deadline - now()
  require(remaining > 0, 'Cleanup RPC budget exhausted')
  readable, _write, _error = select.select([channel, peer.fd], [], [], remaining / SECOND)
  require(channel in readable and peer.fd not in readable and now() < deadline,
          'Cleanup RPC peer/deadline lost')
  value = receive(channel)
  peer.check()
  require(now() < deadline, 'Cleanup RPC response late')
  return value


class CleanupClient:
  """Construct ONCE before recovery READY, then fence ONCE after actual RO."""

  def __init__(self, profile):
    self.bundle = load(epoch='root')
    require(self.bundle.phase == 'systemd' and self.bundle.guardian_profile() == profile,
            'Cleanup capsule/profile mismatch')
    directory(DIRECTORY, private=True)
    info = ENDPOINT.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600, 'Unowned cleanup endpoint')
    self.channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    self.channel.setblocking(False)
    self.peer = None
    self.attempted = False
    try:
      cutoff = min(now() + 2 * SECOND, 118 * SECOND)
      require(now() < cutoff, 'Late recovery receiver binding')
      self.channel.connect(str(ENDPOINT))
      self.peer = Peer(self.channel, ['/usr/bin/python3.14', '-I', '-S', '-B', str(CONTROL), '--run'])
      send(self.channel, binding(self.bundle, 'bind'))
      require(wait_packet(self.channel, self.peer, cutoff) == binding(self.bundle, 'bound'),
              'Cleanup RPC binding differs')
    except BaseException:
      self.close()
      raise

  def close(self):
    self.channel.close()
    if self.peer is not None: self.peer.close()

  def __enter__(self): return self

  def __exit__(self, _type, _value, _traceback): self.close()

  def fence(self, receipt, deadline):
    require(not self.attempted, 'Cleanup fence already attempted')
    self.attempted = True
    self.peer.check()
    raw = owned_bytes(RECEIPT, MAX_PACKET, 0o600)
    require(raw == receipt_bytes(receipt), 'Local completed RO receipt changed')
    request = {'kind': 'cleanup-readonly', 'candidate': self.bundle.profile['candidate'],
      'boot_id': self.bundle.boot_id, 'cleanup_deadline_ns': deadline,
      'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'nonce': os.urandom(32).hex(),
      'readonly_state_verified': True, 'root_unmounted': False,
      'hardware_powerloss_qualified': False, 'receipt': receipt}
    cutoff = evidence(request, self.bundle, now())
    require(now() < cutoff, 'No existing cleanup budget for host fence')
    send(self.channel, request)
    require(wait_packet(self.channel, self.peer, cutoff) == response(self.bundle, request),
            'Cleanup evidence acknowledgement differs')
    self.peer.check()
    require(now() < cutoff, 'Cleanup fence late')
    return request['receipt_sha256']


class RootFence:
  """Event-loop-owned server; never invokes the recovery helper itself."""

  def __init__(self, bundle, link):
    self.bundle, self.link = bundle, link
    self.channel = self.peer = None
    self.bound = self.attempted = self.transferred = self.accepted = False
    self.request = self.cutoff = self.challenge = None

  def accept(self, listener):
    require(self.channel is None, 'Recovery connection never replaced')
    self.channel, _address = listener.accept()
    self.channel.setblocking(False)
    self.peer = Peer(self.channel, ['/usr/bin/python3', '-I', '-B', str(RECEIVER)])

  def readable(self):
    self.peer.check()
    value = receive(self.channel)
    if not self.bound:
      require(value == binding(self.bundle, 'bind') and self.link.ready and now() < 118 * SECOND,
              'Wrong or late receiver binding')
      self.bound = True
      send(self.channel, binding(self.bundle, 'bound'))
      return
    require(not self.attempted and self.link.ready, 'Cleanup RPC already attempted/not authenticated')
    self.attempted = True
    self.cutoff = evidence(value, self.bundle, now())
    require(now() < self.cutoff, 'No existing RPC budget')
    raw = owned_bytes(RECEIPT, MAX_PACKET, 0o600)
    require(raw == receipt_bytes(value['receipt'])
            and hashlib.sha256(raw).hexdigest() == value['receipt_sha256'], 'Receiver RO state changed')
    self.request = value
    self.challenge = self.link.evidence(value, purpose='cleanup')

  def event(self, event):
    if self.request is None or event.challenge != self.challenge: return
    require(now() < self.cutoff, 'Host cleanup evidence fence late')
    self.peer.check()
    if event.kind == 'evidence-transferred': self.transferred = True
    elif event.kind == 'pong-transferred':
      require(self.transferred and not self.accepted, 'Cleanup PONG before evidence/replayed')
      self.accepted = True  # Mark before the one potentially uncertain send.
      send(self.channel, response(self.bundle, self.request))
      require(now() < self.cutoff, 'Cleanup local acknowledgement late')

  def tick(self):
    if self.peer is not None: self.peer.check()
    if self.request is not None and not self.accepted:
      require(now() < self.cutoff, 'Host did not retain completed RO receipt in time')
