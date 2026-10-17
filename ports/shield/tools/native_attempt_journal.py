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
