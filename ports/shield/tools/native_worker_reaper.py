"""Dedicated RAM-maintenance subreaper; never a systemd PID1 replacement.

Only the one stopped worker is initially forked. All surviving descendants
remain in its owned cgroup and are adopted here when their parents exit. A real
ECHILD, an actual master reap and an empty subtree are distinct requirements.
PID1 must also reap THIS process successfully before it accepts the result.
No process-list heuristic, empty tick or fixed grace proves completion.

This is unqualified source preparation. Its PID1 producer, worker, profile and
cleanup consumers must be reviewed together before tests/build/native release.
"""
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import sys
import time

def worker_diagnostic(stage, error):
  fd = None
  try:
    stages = ('worker-import', 'worker-main', 'worker-command', 'worker-exec', 'reaper-main')
    if type(stage) is not str or stage not in stages:
      return
    public_stage = stages[stages.index(stage)]
    names = ('ValueError', 'RuntimeError', 'OSError', 'PermissionError',
        'FileNotFoundError', 'ProcessLookupError', 'TimeoutError',
        'ChildProcessError', 'ImportError', 'ModuleNotFoundError',
        'AttributeError', 'TypeError', 'KeyError', 'AssertionError',
        'SystemExit', 'KeyboardInterrupt', 'MemoryError')
    name = type(error).__name__
    public_type = names[names.index(name)] if name in names else 'other'
    number = error.errno if isinstance(error, OSError) else None
    number = number if type(number) is int and 0 <= number <= 4095 else -1
    fd = os.open('/dev/kmsg', os.O_WRONLY | os.O_NONBLOCK |
          os.O_CLOEXEC | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if (not stat.S_ISCHR(info.st_mode) or info.st_uid or info.st_gid or
        info.st_rdev != os.makedev(1, 11) or info.st_mode & 0o022):
      return
    record = (f'<3>shield-worker stage={public_stage} error={public_type} '
         f'errno={number}\n').encode('ascii')
    if len(record) <= 240:
      os.write(fd, record)  # One attempt, no retry/fsync.
    allowed = ('maintenance-worker.py', 'native_worker_reaper.py',
         'native_boot_context.py', 'native_phase_plan.py',
         'native_work_guard.py', 'native_mounts.py',
         'native_root_storage.py', 'usb_candidate_transaction.py',
         'usb_root_profile.py', 'maintenance_accounts.py',
         'guardian_binding.py', 'qualification_recovery.py',
         'native_layer_reader.py', 'native_layer_writer.py',
             'guardian_client.py', 'native_serial_link.py', 'native_control_protocol.py')
    trace = error.__traceback__
    for depth in range(8):  # Inspected links, including unlisted frames.
      if trace is None:
        break
      code = trace.tb_frame.f_code
      base = code.co_filename.rsplit('/', 1)[-1]
      line = trace.tb_lineno
      if (base in allowed and code.co_name != 'require' and
          type(line) is int and 0 < line <= 99999):
        public_file = allowed[allowed.index(base)]
        record = (f'<3>shield-worker-fault stage={public_stage} '
             f'file={public_file} line={line} depth={depth}\n').encode('ascii')
        if len(record) <= 240:
          os.write(fd, record)
      trace = trace.tb_next
  except BaseException:
    pass  # Evidence failure must not replace immediate owner exit.
  finally:
    if fd is not None:
      try:
        os.close(fd)
      except BaseException:
        pass


sys.path.insert(0, '/run/shield-native/runtime')

try:
  from native_boot_context import (DIRECTORY, RUNTIME, close_from, directory,
    filesystem_magic, load, standard_fds)
  from usb_root_profile import require
except BaseException as error:
  worker_diagnostic('worker-import', error)
  raise  # Preserve the original uncaught import failure and exit status.


LEAF = Path('/sys/fs/cgroup/shield-native-worker')
WORK = Path('/run/shield-worker')
WORKER = RUNTIME / 'maintenance-worker.py'
WALL = 0x40000000  # Selected Linux UAPI __WALL, including non-SIGCHLD clone children.
SECOND = 1_000_000_000
WORK_CUTOFF = 540 * SECOND
FINAL_CUTOFF = 600 * SECOND
CGROUP2_MAGIC = 0x63677270


def now(): return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def prctl(option, argument):
  library = ctypes.CDLL(None, use_errno=True)
  function = library.prctl
  function.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
  function.restype = ctypes.c_int
  require(function(option, argument, 0, 0, 0) == 0, 'Reaper prctl refused')


def subreaper():
  prctl(36, 1)  # PR_SET_CHILD_SUBREAPER
  state = ctypes.c_int(0)
  prctl(37, ctypes.addressof(state))  # PR_GET_CHILD_SUBREAPER
  require(state.value == 1, 'Subreaper state not established')


def emit(value):
  raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
  require(len(raw) <= 4096 and os.write(1, raw) == len(raw), 'Incomplete private reaper record')


class WorkerLeaf:
  """Already-created exclusive leaf; never mkdir, select or destroy a cgroup."""

  def __init__(self):
    directory(LEAF, private=True)
    self.fd = os.open(LEAF, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    self.identity = os.fstat(self.fd)
    require(filesystem_magic(self.fd) == CGROUP2_MAGIC, 'Actual cgroup2 leaf required')
    self.kill_attempted = False
    require(self.read('cgroup.type') == b'domain\n' and not self.procs(), 'Worker leaf is not empty')
    require(Path('/proc/self/cgroup').read_text() == '0::/\n', 'Reaper must stay outside worker leaf')

  def check(self):
    current = LEAF.lstat()
    require(stat.S_ISDIR(current.st_mode) and current.st_uid == current.st_gid == 0
            and stat.S_IMODE(current.st_mode) == 0o700
            and (current.st_dev, current.st_ino) == (self.identity.st_dev, self.identity.st_ino),
            'Worker leaf identity changed')

  def read(self, name):
    require(name in {'cgroup.events', 'cgroup.procs', 'cgroup.type'}, 'Unknown cgroup observation')
    self.check()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
    try:
      require(filesystem_magic(fd) == CGROUP2_MAGIC, 'Wrong cgroup observation filesystem')
      raw = os.read(fd, 4097)
      require(len(raw) <= 4096 and b'\0' not in raw, 'Oversized cgroup observation')
      return raw
    finally: os.close(fd)

  def procs(self):
    raw = self.read('cgroup.procs')
    rows = raw.splitlines()
    require(len(rows) <= 256 and all(row.isdigit() and int(row) > 1 for row in rows),
            'Wrong worker membership')
    values = [int(row) for row in rows]
    require(len(values) == len(set(values)), 'Duplicate worker membership')
    return set(values)

  def empty(self):
    rows = self.read('cgroup.events').splitlines()
    matches = [row for row in rows if row.startswith(b'populated ')]
    require(len(matches) == 1 and matches[0] in {b'populated 0', b'populated 1'},
            'Wrong worker population state')
    return matches[0] == b'populated 0'

  def write(self, name, data):
    require(name in {'cgroup.procs', 'cgroup.kill'}, 'Unknown worker operation')
    self.check()
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
    try:
      info = os.fstat(fd)
      require(filesystem_magic(fd) == CGROUP2_MAGIC and info.st_uid == info.st_gid == 0
              and not info.st_mode & 0o022, 'Unsafe worker operation file')
      require(os.write(fd, data) == len(data), 'Uncertain worker operation; never replay')
    finally: os.close(fd)

  def assign_stopped(self, pid):
    require(type(pid) is int and pid > 1 and pid != os.getpid() and not self.procs(),
            'Unexpected worker assignment')
    self.write('cgroup.procs', (str(pid) + '\n').encode('ascii'))
    require(self.procs() == {pid}
            and Path('/proc/' + str(pid) + '/cgroup').read_text() == '0::/shield-native-worker\n',
            'Stopped worker was not assigned exclusively')

  def kill_once(self):
    if self.kill_attempted: return
    self.kill_attempted = True  # A failed/partial operation is never retried.
    self.write('cgroup.kill', b'1\n')


def control_channel():
  channel = socket.socket(fileno=3)
  require(channel.family == socket.AF_UNIX
          and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
          and channel.getsockname() in {'', b''} and channel.getpeername() in {'', b''},
          'Private PID1 socketpair required')
  pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
  require(pid == 1 and uid == gid == 0 and os.getppid() == 1, 'Control peer is not native PID1')
  channel.setblocking(False)
  os.set_inheritable(3, False)
  return channel


def stopped_worker(log_fd):
  pid = os.fork()  # Waitable SIGCHLD child; never CLONE_AUTOREAP/posix_spawn.
  if pid:
    return pid
  try:
    parent = os.getppid()
    signal.set_wakeup_fd(-1)
    for item in [signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP,
                 signal.SIGALRM, signal.SIGPIPE]: signal.signal(item, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, set())
    prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG, with parent-race recheck.
    require(parent > 1 and os.getppid() == parent, 'Worker parent changed')
    os.dup2(log_fd, 1); os.dup2(log_fd, 2)
    close_from(3)
    os.kill(os.getpid(), signal.SIGSTOP)
    # Only the reaper's post-assignment START path sends the owned SIGCONT.
    os.execve('/usr/bin/python3.14', ['/usr/bin/python3.14', '-I', '-S', '-B',
              str(WORKER), '--run'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'})
  except BaseException as error:
    worker_diagnostic('worker-exec', error)
    os._exit(70)


def main():
  require(sys.argv[1:] == ['--run'] and os.getpid() != 1 and os.getppid() == 1,
          'Reaper is a fixed native PID1 child')
  bundle = load(epoch='early')
  require(bundle.phase in {'packages', 'layer'} and bundle.profile['role'] == 1,
          'RAM maintenance role required')
  standard_fds()
  channel = control_channel()
  close_from(4)
  require(len(os.listdir('/proc/self/task')) == 1, 'Single-threaded reaper required')
  directory(WORK, private=True)
  attempt = os.open(WORK / 'ATTEMPTED', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  os.close(attempt)
  leaf = WorkerLeaf()
  subreaper()
  previous = now()
  require(0 < previous < 120 * SECOND, 'Late reaper startup')
  wake_read, wake_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
  signal.set_wakeup_fd(wake_write, warn_on_full_buffer=False)
  signals = {signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
  interrupted = False
  def changed(number, _frame):
    nonlocal interrupted
    if number != signal.SIGCHLD: interrupted = True
  for item in signals: signal.signal(item, changed)
  signal.pthread_sigmask(signal.SIG_UNBLOCK, signals)
  log_fd = os.open(WORK / 'worker.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  leader = stopped_worker(log_fd)
  os.close(log_fd)
  started = stopped = leader_reaped = no_children = False
  leader_status = None
  reaped = 0
  stopping = failed = False
  stop_deadline = None
  clock_bad = False
  arm_deadline = min(previous + 10 * SECOND, 120 * SECOND)
  events = select.epoll()
  events.register(channel.fileno(), select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
  events.register(wake_read, select.EPOLLIN)
  group_event = os.open('cgroup.events', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=leaf.fd)
  require(filesystem_magic(group_event) == CGROUP2_MAGIC, 'Wrong cgroup event source')
  os.read(group_event, 4097)
  events.register(group_event, select.EPOLLPRI | select.EPOLLERR)

  def stop(fault=False, parent_stop=False):
    nonlocal stopping, failed, stop_deadline
    failed |= fault
    if not stopping:
      stopping = True
      stop_deadline = min(now() + 40 * SECOND, FINAL_CUTOFF)
      if stopped:
        # PID1 owns the one leaf-kill operation and its attempt state. This
        # remains true if this reaper unexpectedly dies. A request is not an
        # acknowledgement that anybody has terminated; wait/ECHILD/empty still
        # have to be observed here and this process reaped by PID1.
        if not parent_stop:
          emit({'kind': 'reaper-stop-requested', 'leader_pid': leader})
      elif not leader_reaped:
        # Before assignment/START, the still-owned master has never executed
        # or forked. Killing an empty leaf would miss this stopped child.
        try: os.kill(leader, signal.SIGKILL)
        except ProcessLookupError: pass

  while True:
    clock = now()
    if not clock or clock < previous:
      clock_bad = True
      stop(True)
    else:
      previous = clock
    if interrupted or clock >= WORK_CUTOFF or (not stopped and clock >= arm_deadline):
      stop(True)
    if not stopped and not leader_reaped:
      pid, status = os.waitpid(leader, os.WNOHANG | os.WUNTRACED | WALL)
      if pid:
        if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP and not stopping:
          leaf.assign_stopped(leader)
          stopped = True
          emit({'kind': 'reaper-ready', 'leader_pid': leader, 'worker_stopped_in_leaf': True})
        elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
          leader_reaped = True; leader_status = os.waitstatus_to_exitcode(status); reaped += 1
          stop(True)
        else:
          stop(True)
    while True:
      try:
        pid, status = os.waitpid(-1, os.WNOHANG | WALL)
      except ChildProcessError:
        no_children = True
        break
      if not pid:
        no_children = False
        break
      reaped += 1
      if pid == leader:
        leader_reaped = True; leader_status = os.waitstatus_to_exitcode(status)
        # Resource teardown is also required after a successful worker exit.
        stop(leader_status != 0)
    if stopping and leader_reaped and no_children and leaf.empty():
      finished = now()
      timely = not clock_bad and finished >= previous and finished < stop_deadline
      emit({'kind': 'reaper-complete', 'leader_pid': leader, 'leader_exit': leader_status,
            'started': started, 'reaped_statuses': reaped, 'no_remaining_children': True,
            'leaf_empty': True, 'phase_failed': failed or not timely,
            'finished_ns': finished})
      # exit0 proves timely resource release, never success of the package job.
      # PID1 separately requires leader_exit0/started and all phase postconditions.
      return 0 if timely else 65
    if stopping and clock >= stop_deadline:
      # An absorbing failure. Still reap genuinely completed children, never
      # issue another kill or pretend a D-state task has terminated.
      failed = True
    timeout = 1.0
    if stop_deadline is not None and clock < stop_deadline:
      timeout = min(timeout, (stop_deadline - clock) / SECOND)
    for descriptor, flags in events.poll(timeout):
      if descriptor == wake_read:
        try: os.read(wake_read, 4096)
        except BlockingIOError: pass
      elif descriptor == group_event:
        os.lseek(group_event, 0, os.SEEK_SET)
        require(len(os.read(group_event, 4097)) <= 4096, 'Oversized worker event')
      else:
        if flags & (select.EPOLLHUP | select.EPOLLERR):
          stop(True)
          events.unregister(channel.fileno())
          channel.close()
          continue
        try: packet, ancillary, message_flags, _address = channel.recvmsg(1, 0)
        except BlockingIOError: continue
        if not packet:
          stop(True)
          events.unregister(channel.fileno())
          channel.close()
          continue
        if ancillary or message_flags or packet not in {b'S', b'T'}:
          stop(True)
        elif packet == b'T':
          # The only sender is the owned PID1 socketpair. Its producer must
          # issue/record its one cgroup.kill before this notification.
          stop(parent_stop=True)
        elif started or stopping or not stopped or now() >= WORK_CUTOFF - 180 * SECOND:
          stop(True)
        else:
          require(leaf.procs() == {leader}, 'Stopped worker membership changed')
          started = True
          os.kill(leader, signal.SIGCONT)


if __name__ == '__main__':
  try:
    raise SystemExit(main())
  except (OSError, ValueError) as error:
    worker_diagnostic('reaper-main', error)
    # Early/unexpected reaper death is not a cleanup receipt. PID1 marks the
    # attempt ineligible; no replacement reaper, replay or fallback reboot.
    raise SystemExit(65)
