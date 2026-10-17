"""Native RAM PID1's fixed children, positive waits and private result pipes.

No child command, output path, timeout or signal target comes from the host.
This is not a general process runner. Kernel I/O can remain uninterruptible;
expiry consumes an attempt and prevents handoff, never fabricates a reap.
"""
from collections import deque
from dataclasses import dataclass, field
import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import stat

from native_boot_context import RUNTIME, close_from, filesystem_magic
from usb_root_profile import require

INSTALL = Path('/usr/lib/omarchy/shield/qualification')
ARGV = {
  'health': [str(RUNTIME / 'shield-early-health'), '--run'],
  'internal-ro': [str(RUNTIME / 'shield-internal-ro'), '--run'],
  'guardian': [str(INSTALL / 'shield-guardian'), '--run'],
  'restart-recovery': [str(INSTALL / 'shield-restart-recovery')],
  'reaper': ['/usr/bin/python3.14', '-I', '-S', '-B',
             str(RUNTIME / 'native_worker_reaper.py'), '--run'],
}
WALL = 0x40000000


def private_record(raw):
  def pairs(rows):
    result = {}
    for key, value in rows:
      require(key not in result, 'Duplicate private child record key')
      result[key] = value
    return result
  def forbidden(_text): raise ValueError('Noninteger private child record')
  require(0 < len(raw) <= 4096 and raw.endswith(b'\n'), 'Incomplete private child record')
  value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                     parse_float=forbidden, parse_constant=forbidden)
  require(type(value) is dict, 'Private child record must be an object')
  return value


@dataclass
class Child:
  name: str
  pid: int
  pidfd: int
  result_fd: int
  control: object = None
  pending: bytearray = field(default_factory=bytearray)
  records: deque = field(default_factory=deque)
  received_bytes: int = 0
  eof: bool = False
  wait_status: int | None = None
  kill_attempted: bool = False
  commands_attempted: set = field(default_factory=set)

  def read(self):
    require(not self.eof, 'Closed child result stream')
    try: data = os.read(self.result_fd, 4096)
    except BlockingIOError: return
    if not data:
      self.eof = True
      require(not self.pending, 'Partial child record at EOF')
      return
    self.received_bytes += len(data)
    require(self.received_bytes <= 8192, 'Child output lifetime budget')
    for byte in data:
      require(byte == 10 or 32 <= byte <= 126, 'Non-ASCII private child output')
      self.pending.append(byte)
      require(len(self.pending) <= 4096, 'Private child line budget')
      if byte == 10:
        require(len(self.records) < 8, 'Undrained private child record budget')
        self.records.append(private_record(bytes(self.pending)))
        self.pending.clear()

  def take_records(self):
    result = tuple(self.records)
    self.records.clear()
    return result

  @property
  def reaped(self): return self.wait_status is not None

  @property
  def success(self):
    return self.reaped and self.eof and os.WIFEXITED(self.wait_status) and os.WEXITSTATUS(self.wait_status) == 0


class Children:
  """One single-threaded PID1 owner; children are never replaced/restarted."""

  def __init__(self):
    require(os.getpid() == 1 and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0
            and len(os.listdir('/proc/self/task')) == 1, 'Single-threaded native root PID1 required')
    self.children = {}
    self.by_pid = {}
    self.attempted = set()
    self.unexpected_statuses = []
    self.interrupted = False
    self.wake_read, self.wake_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    signal.set_wakeup_fd(self.wake_write, warn_on_full_buffer=False)
    def changed(number, _frame):
      if number != signal.SIGCHLD: self.interrupted = True
    for number in [signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
      signal.signal(number, changed)
    signal.pthread_sigmask(signal.SIG_UNBLOCK,
      {signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP})

  def spawn(self, name):
    require(name in ARGV and name not in self.attempted and not self.interrupted,
            'Unknown/repeated native child attempt')
    self.attempted.add(name)  # An allocation/fork/exec uncertainty cannot replay.
    result_read, result_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    null = os.open('/dev/null', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    pair = None
    child_pid = None
    try:
      os.fchmod(result_write, 0o600)
      info = os.fstat(null)
      require(stat.S_ISCHR(info.st_mode) and info.st_uid == info.st_gid == 0
              and info.st_rdev == os.makedev(1, 3) and filesystem_magic(null) == 0x01021994,
              'Native child null endpoint differs')
      if name == 'reaper':
        pair = socket.socketpair(socket.AF_UNIX,
          socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
      child_pid = os.fork()  # Waitable SIGCHLD child, never CLONE_AUTOREAP.
      if child_pid == 0:
        try:
          signal.set_wakeup_fd(-1)
          for number in [signal.SIGCHLD, signal.SIGTERM, signal.SIGINT,
                         signal.SIGHUP, signal.SIGALRM, signal.SIGPIPE]:
            signal.signal(number, signal.SIG_DFL)
          signal.pthread_sigmask(signal.SIG_SETMASK, set())
          os.dup2(null, 0); os.dup2(result_write, 1); os.dup2(null, 2)
          if pair is not None:
            os.dup2(pair[1].fileno(), 3, inheritable=True)
            close_from(4)
          else:
            close_from(3)
          if name == 'guardian':
            # Match the role2 unit's sole-owner OOM protection. Its sampler
            # inherits this setting at the guardian's final pre-open fork.
            fd = os.open('/proc/self/oom_score_adj', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try: require(os.write(fd, b'-1000\n') == 6, 'Guardian OOM protection refused')
            finally: os.close(fd)
            require(Path('/proc/self/oom_score_adj').read_text() == '-1000\n',
                    'Guardian OOM protection readback differs')
          # No watchdog right exists in PID1 to inherit. Never give the guardian
          # an automatic parent-death signal which could close its sole fd.
          if name != 'guardian':
            library = ctypes.CDLL(None, use_errno=True)
            function = library.prctl
            function.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                                 ctypes.c_ulong, ctypes.c_ulong]
            function.restype = ctypes.c_int
            require(function(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == 1,
                    'Native child parent-death admission failed')
          os.execve(ARGV[name][0], ARGV[name],
                    {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'})
        except BaseException:
          os._exit(70)
      pidfd = os.pidfd_open(child_pid, 0)
      if pair is not None: pair[1].close()
      child = Child(name, child_pid, pidfd, result_read, pair[0] if pair else None)
      self.children[name] = child
      self.by_pid[child_pid] = child
      result_read = None
      pair = None
      return child
    except BaseException:
      # The child has not been reaped and cannot have reused its owned PID.
      # This exceptional pre-registration path must not silently leave a writer
      # or manufacture a completion. A guardian is NEVER killed here.
      if child_pid is not None and child_pid > 0 and name != 'guardian':
        try: os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError: pass
      raise
    finally:
      os.close(null); os.close(result_write)
      if result_read is not None: os.close(result_read)
      if pair is not None:
        for endpoint in pair: endpoint.close()

  def reap(self):
    """Drain real wait statuses; return true ONLY for actual ECHILD.

    With a live guardian this cannot prove global no-children. Phase C never
    launches the RAM guardian and requires ECHILD again immediately before
    PID1's standard switch_root exec.
    """
    while True:
      try: pid, status = os.waitpid(-1, os.WNOHANG | WALL)
      except ChildProcessError: return True
      if pid == 0: return False
      child = self.by_pid.get(pid)
      if child is None:
        require(len(self.unexpected_statuses) < 64, 'Unexpected native child budget')
        self.unexpected_statuses.append((pid, status))
      else:
        require(not child.reaped, 'Native child status was consumed twice')
        child.wait_status = status

  def kill_helper_once(self, name):
    require(name in {'health', 'internal-ro'}, 'Only one-shot helpers may be killed')
    child = self.children[name]
    if child.reaped or child.kill_attempted: return
    child.kill_attempted = True
    try: signal.pidfd_send_signal(child.pidfd, signal.SIGKILL)
    except ProcessLookupError: pass

  def reaper_command(self, command):
    require(command in {b'S', b'T'}, 'Wrong native worker control')
    child = self.children['reaper']
    require(not child.reaped and child.control is not None and command not in child.commands_attempted,
            'Stopped worker control owner lost')
    child.commands_attempted.add(command)
    require(child.control.send(command) == len(command), 'Uncertain worker control; never replay')

  def drain_wake(self):
    try: os.read(self.wake_read, 4096)
    except BlockingIOError: pass

  def close_reaped(self, name):
    child = self.children[name]
    require(child.reaped and child.eof and not child.pending and not child.records,
            'Cannot relinquish a live/uncollected native child')
    os.close(child.result_fd); os.close(child.pidfd)
    if child.control is not None: child.control.close()
    del self.by_pid[child.pid]; del self.children[name]

  def require_handoff(self):
    no_children = self.reap()
    require(not self.interrupted and not self.children and not self.unexpected_statuses
            and no_children, 'RAM children/statuses not fully relinquished')
    require(len(os.listdir('/proc/self/task')) == 1, 'PID1 gained another thread')
