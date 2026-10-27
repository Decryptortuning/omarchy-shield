"""Own one Windows bridge and one finite, supervised SNCP1 worker.

The parent never performs receipt fsync or a Windows pipe write. Its independent
deadline remains live if the session worker stalls there. The Windows bridge
also owns a process-local hard deadline covering blocked serial close.

This is the real transport controller, not a loader or recovery observer. The
fixed outer handoff coordinator must arm it BEFORE its one legacy release and
must independently observe secure SOS before creating a positive predecessor.
No CLI, native release, device command or automatic retry is provided here.
Unqualified source: settle the whole producer/consumer cohort before import.
"""
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import secrets
import signal
import socket
import stat
import subprocess
import time
from types import MappingProxyType, SimpleNamespace

from guardian_binding import validate as validate_profile
from native_boot_context import (admit, canonical, close_from, freeze, json_bytes, plain)
from native_host_link import (BridgeState, FrozenMaintenancePin, HandoffPin, HostLink,
                              PrivateFrameStore)
from native_phase_plan import admit_plan, admit_predecessor, decode
from usb_root_profile import require

PORT = Path(__file__).resolve().parent.parent
PS = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
BRIDGE = PORT / 'qualification/native-serial-transport.ps1'
SECOND = 1_000_000_000
SOURCE_MINIMUM = {'tools/native_host_controller.py', 'tools/native_host_link.py',
  'tools/native_control_protocol.py', 'tools/native_serial_link.py', 'tools/native_boot_context.py',
  'tools/native_phase_plan.py', 'qualification/native-serial-transport.ps1'}


def now(): return time.monotonic_ns()


def source_check(pins):
  require(type(pins) is dict and SOURCE_MINIMUM <= set(pins) and len(pins) <= 160,
          'Host controller source closure absent')
  for name, expected in pins.items():
    require(type(name) is str and not name.startswith('/')
            and all(part not in {'', '.', '..'} for part in name.split('/')), 'Unsafe host source pin')
    path = PORT / name
    require(path.parent.resolve(strict=True).is_relative_to(PORT)
            and not path.is_symlink() and path.is_file()
            and hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'Host source changed')


@dataclass(frozen=True)
class Spec:
  """Content-admitted inputs; not physical release or recovery authority."""
  bundle_raw: bytes
  profile_raw: bytes
  inputs: object
  keys: object
  source_pins: object

  def __post_init__(self):
    bundle = json_bytes(self.bundle_raw)
    configuration, contexts = admit(bundle)
    profile = validate_profile(decode(self.profile_raw))
    require(hashlib.sha256(self.profile_raw).hexdigest() == configuration['guardian_profile_sha256']
            and all(context.candidate == profile['candidate'] and context.role == profile['role']
                    for context in contexts.values()), 'Host profile/session differs')
    require(type(self.inputs) is dict and set(self.inputs) == set(configuration['inputs'])
            and type(self.keys) is dict and set(self.keys) == set(contexts), 'Host input/key closure differs')
    for name, pin in configuration['inputs'].items():
      raw = self.inputs[name]
      require(type(raw) is bytes and len(raw) == pin['bytes']
              and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'Host phase input differs')
    for name, raw in self.keys.items():
      require(type(raw) is bytes and len(raw) == 32 and any(raw)
              and hashlib.sha256(raw).hexdigest() == bundle['key_sha256'][name], 'Host key differs')
    reference = SimpleNamespace(phase=configuration['phase'], profile=profile, configuration=configuration)
    plan = admit_plan(reference, decode(self.inputs['payload']), decode(self.inputs['plan']))
    if reference.phase == 'layer':
      admit_predecessor(reference, plan, 'predecessor', 'packages', decode(self.inputs['predecessor']))
    if reference.phase == 'systemd':
      a = admit_predecessor(reference, plan, 'predecessorA', 'packages', decode(self.inputs['predecessorA']))
      b = admit_predecessor(reference, plan, 'predecessorB', 'layer', decode(self.inputs['predecessorB']))
      require(a['boot_id'] != b['boot_id'] and a['session_id'] != b['session_id'],
              'Host predecessors are not distinct')
    source_check(self.source_pins)
    object.__setattr__(self, 'configuration', freeze(configuration))
    object.__setattr__(self, 'contexts', MappingProxyType(contexts))
    object.__setattr__(self, 'profile', freeze(profile))
    object.__setattr__(self, 'plan', plan)
    object.__setattr__(self, 'inputs', MappingProxyType(dict(self.inputs)))
    object.__setattr__(self, 'keys', MappingProxyType(dict(self.keys)))
    object.__setattr__(self, 'source_pins', MappingProxyType(dict(self.source_pins)))


def preserve_worker_failure(directory, error, deadline):
  """Best-effort bounded private diagnostic; never a success/authority record."""
  directory_fd = output_fd = None
  try:
    if now() >= deadline:
      return False
    admitted = frozenset({
      'native_host_controller.py', 'native_host_link.py',
      'native_control_protocol.py', 'native_serial_link.py',
      'native_phase_plan.py', 'native_boot_context.py',
      'usb_root_profile.py', 'guardian_binding.py'})
    frames = []
    node = error.__traceback__
    visited = 0
    while node is not None and visited < 8:
      visited += 1
      path = Path(node.tb_frame.f_code.co_filename)
      if path.parent == Path(__file__).parent and path.name in admitted:
        line = node.tb_lineno
        if type(line) is int and 0 < line <= 100000:
          frames.append({'file': path.name, 'line': line})
      node = node.tb_next
    kinds = {ValueError: 'ValueError', OSError: 'OSError',
             TimeoutError: 'TimeoutError', BlockingIOError: 'BlockingIOError'}
    number = getattr(error, 'errno', None) if isinstance(error, OSError) else None
    number = number if type(number) is int and 0 <= number <= 4095 else 0
    value = {'format_version': 1, 'purpose': 'failed host worker diagnostic only',
             'error_type': kinds.get(type(error), 'Other'), 'errno': number,
             'public_frames': frames, 'trace_truncated': node is not None,
             'qualification': False, 'boot_ready': False}
    raw = canonical(value)
    if len(raw) > 4096 or now() >= deadline:
      return False
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC)
    owner = os.fstat(directory_fd)
    if not (stat.S_ISDIR(owner.st_mode) and stat.S_IMODE(owner.st_mode) == 0o700
            and owner.st_uid == owner.st_gid == 0):
      return False
    output_fd = os.open('worker-failure.json', os.O_WRONLY | os.O_CREAT |
                        os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600, dir_fd=directory_fd)
    item = os.fstat(output_fd)
    if not (stat.S_ISREG(item.st_mode) and item.st_uid == item.st_gid == 0
            and item.st_nlink == 1 and stat.S_IMODE(item.st_mode) == 0o600):
      return False
    if now() >= deadline:
      return False
    # One write only. No fsync/durability claim, retry, extra deadline or authority.
    return os.write(output_fd, raw) == len(raw)
  except BaseException:
    return False
  finally:
    for descriptor in [output_fd, directory_fd]:
      if descriptor is not None:
        try:
          os.close(descriptor)
        except OSError:
          pass


def notify(channel, value, cutoff):
  raw = canonical(value)
  require(len(raw) <= 8192, 'Private controller result budget')
  while now() < cutoff:
    try: count = channel.send(raw)
    except BlockingIOError:
      select.select([], [channel], [], min(0.1, max(0, (cutoff - now()) / SECOND)))
      continue
    require(count == len(raw), 'Uncertain controller result; never replay')
    return
  raise ValueError('Private controller notification deadline')


def default_tuple(spec):
  value = spec.plan.original_default
  return tuple(value[name] for name in ['id', 'top_level', 'path'])


def link_for(spec, bridge, directory, deadline, epoch, boot_id=None):
  phase = spec.configuration['phase']
  purpose = 'root-cleanup' if epoch == 'root' else (
    'systemd-handoff' if phase == 'systemd' else 'maintenance-release')
  store = PrivateFrameStore(directory / epoch, purpose=purpose)
  filesystem, inputs = spec.profile['filesystem'], spec.configuration['inputs']
  args = {}
  if epoch == 'early' and phase == 'systemd':
    args['handoff_pin'] = HandoffPin(spec.contexts['root'].session_id, filesystem['candidate_id'],
      filesystem['uuid'], inputs['payload']['sha256'], spec.plan.writer.layer.manifest_sha256,
      inputs['predecessorA']['sha256'], inputs['predecessorB']['sha256'], default_tuple(spec))
  elif epoch == 'early':
    args['maintenance_pin'] = FrozenMaintenancePin(phase, filesystem['candidate_id'], filesystem['uuid'],
      inputs['payload']['sha256'], inputs['plan']['sha256'], default_tuple(spec))
  return HostLink(spec.contexts[epoch], spec.keys[epoch], bridge, deadline, epoch=epoch,
                  store=store, boot_id=boot_id, **args), store


def session_worker(spec, directory, channel, deadline):
  """Only child process owns frame writes/retention; no subprocess or device exec."""
  bridge = BridgeState()
  link, store = link_for(spec, bridge, directory, deadline, 'early')
  stores = [store]
  events = select.epoll()
  events.register(5, select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
  events.register(6, select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
  events.register(4, select.EPOLLHUP | select.EPOLLERR)
  armed = False
  epoch = 'early'
  eof = set()
  retained = None
  terminal = False
  stop_cursor = 0
  stopping_until = None
  ping_due = now() + 5 * SECOND
  challenge = challenge_started = None
  previous = now()
  before_connected = bytearray()
  try:
    while True:
      timestamp = now()
      require(0 < previous <= timestamp < deadline, 'Absolute host worker deadline/clock')
      previous = timestamp
      if stopping_until is not None: require(timestamp < stopping_until, 'Bridge stop deadline')
      if not terminal:
        link.tick()
        if link.ready and link.ping_challenge is None and not any(
            [link.cleanup_seen, link.handoff_seen, link.maintenance_seen]) and timestamp >= ping_due:
          link.ping(secrets.token_hex(32)); ping_due = timestamp + 5 * SECOND
        if link.ping_challenge != challenge:
          challenge, challenge_started = link.ping_challenge, timestamp
        if challenge is not None:
          require(timestamp - challenge_started < 10 * SECOND, 'Host PONG liveness deadline')
      wants = stop_cursor < 5 if terminal else link.wants_write
      if stop_cursor < 5:
        events.modify(4, select.EPOLLHUP | select.EPOLLERR | (select.EPOLLOUT if wants else 0))
      for fd, flags in events.poll(min(0.25, (deadline - timestamp) / SECOND)):
        if fd == 4:
          require(not flags & (select.EPOLLHUP | select.EPOLLERR), 'Owned bridge stdin lost')
          if terminal:
            try: count = os.write(4, b'STOP\n'[stop_cursor:])
            except BlockingIOError: continue
            require(type(count) is int and 0 < count <= 5 - stop_cursor, 'Unknown STOP write')
            stop_cursor += count
            if stop_cursor == 5:
              events.unregister(4); os.close(4)
          else: link.drive_write(4)
          continue
        try: data = os.read(fd, 8192)
        except BlockingIOError: continue
        if not data:
          require(terminal, 'Unexpected bridge pipe EOF')
          if fd == 6: bridge.eof()
          eof.add(fd); events.unregister(fd)
          continue
        if fd == 6:
          bridge.feed_stderr(data)
          if bridge.pid is not None and not armed:
            notify(channel, {'event': 'armed', 'windows_pid': bridge.pid}, min(now() + SECOND, deadline))
            armed = True
          # Separate Windows stdout/stderr forwarding may deliver raw USB
          # before its earlier CONNECTED marker. Never parse those bytes as
          # local metadata or reject a valid arrival solely for pipe ordering.
          if not bridge.connected or not before_connected: continue
          data = bytes(before_connected); before_connected.clear()
        else:
          if not bridge.connected:
            before_connected.extend(data)
            require(len(before_connected) <= 8192, 'Pre-connected USB buffer budget')
            continue
        require(not terminal, 'Extra native bytes after terminal fence')
        tail = link.feed_device(data)
        observed = link.take_events()
        for event in observed:
          if event.kind.endswith('-retained'): retained = event.record
        handoff = any(event.kind == 'handoff-confirmed' for event in observed)
        done = any(event.kind in {'maintenance-confirmed', 'cleanup-confirmed'} for event in observed)
        if handoff:
          require(epoch == 'early' and spec.configuration['phase'] == 'systemd', 'Unexpected epoch handoff')
          prior_boot = link.session.boot_id
          link, store = link_for(spec, bridge, directory, deadline, 'root', prior_boot)
          stores.append(store); epoch = 'root'; retained = None
          challenge = challenge_started = None
          ping_due = now() + 5 * SECOND
          if tail:
            require(link.feed_device(tail) == b'', 'Nested epoch handoff tail')
            for event in link.take_events():
              require(event.kind not in {'cleanup-confirmed', 'maintenance-confirmed', 'handoff-confirmed'},
                      'Terminal result before root round trip')
        else: require(not tail, 'Unowned epoch tail')
        if done:
          require(retained is not None and store.retained_sha256 is not None
                  and not link.pending, 'Terminal fence without retained evidence/outbound closure')
          terminal = True
          stopping_until = min(now() + 3 * SECOND, deadline)
      if terminal and eof == {5, 6}:
        require(stop_cursor == 5 and bridge.stopped and not bridge.failed, 'Bridge teardown not observed')
        notify(channel, {'event': 'complete', 'phase': spec.configuration['phase'], 'epoch': epoch,
          'boot_id': link.session.boot_id, 'evidence_sha256': store.retained_sha256,
          'observations': plain(retained.payload['observations']),
          'retained_fence': True, 'authenticated_recovery_observed': False,
          'boot_ready': False}, min(now() + SECOND, deadline))
        return
  finally:
    for item in stores: item.close()
    events.close()


class Attempt:
  """One owner: arm -> fixed outer legacy release -> finish; never replay."""
  def __init__(self, spec, directory, *, outer_deadline_ns):
    require(type(spec) is Spec and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
            'Admitted spec and native WSL root controller required')
    self.spec, self.directory = spec, Path(directory)
    self.process = self.channel = self.pidfd = self.pid = None
    self.child_endpoint = None
    self.started = self.armed = self.finished = self.kill_attempted = False
    self.wait_status = None
    self.completion = None
    self.deadline = None
    require(type(outer_deadline_ns) is int and now() < outer_deadline_ns <= now() + 900 * SECOND,
            'An existing bounded outer deadline is required')
    self.outer_deadline = outer_deadline_ns

  def arm(self):
    require(not self.started and len(os.listdir('/proc/self/task')) == 1
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'One single-threaded attempt required')
    self.started = True
    source_check(dict(self.spec.source_pins))
    require(self.directory.is_absolute() and self.directory.is_relative_to(Path('/home/jresp/build/omarchy-shield'))
            and self.directory.parent.resolve(strict=True) == self.directory.parent, 'Unsafe private attempt location')
    self.directory.mkdir(mode=0o700)
    for epoch in self.spec.contexts: (self.directory / epoch).mkdir(mode=0o700)
    with (self.directory / 'ATTEMPTED').open('xb') as stream:
      os.fchmod(stream.fileno(), 0o600); stream.write(b'ONE_OWNED_NATIVE_BRIDGE_ATTEMPT\n')
      stream.flush(); os.fsync(stream.fileno())
    descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    self.deadline = min(now() + 660 * SECOND, self.outer_deadline)
    require(self.deadline - now() >= 45 * SECOND, 'Insufficient existing bridge startup allowance')
    try:
      self.launch()
      value = self.receive(min(now() + 15 * SECOND, self.deadline))
      require(set(value) == {'event', 'windows_pid'} and value['event'] == 'armed'
              and type(value['windows_pid']) is int and value['windows_pid'] > 0, 'Host bridge did not arm')
      self.armed = True
    except BaseException:
      self.cancel()
      raise

  def launch(self):
    require(self.started and self.process is None and self.pid is None, 'Bridge launch cannot replay')
    script = '\\\\wsl.localhost\\Ubuntu-24.04' + str(BRIDGE).replace('/', '\\')
    seconds = min(660, (self.deadline - now()) // SECOND)
    require(seconds >= 45, 'Insufficient existing Windows bridge allowance')
    self.process = subprocess.Popen([PS, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', script, '-SerialToken', self.spec.contexts['early'].session_id[:32], '-DurationSeconds', str(seconds)],
      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    pipes = [self.process.stdin.fileno(), self.process.stdout.fileno(), self.process.stderr.fileno()]
    for fd in pipes: os.set_blocking(fd, False)
    parent, child = socket.socketpair(socket.AF_UNIX,
      socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
    self.channel, self.child_endpoint = parent, child
    owner = os.getpid()
    self.pid = os.fork()
    if self.pid == 0:
      try:
        library = ctypes.CDLL(None, use_errno=True)
        require(library.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == owner,
                'Host worker parent-death admission failed')
        for number in [signal.SIGCHLD, signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGPIPE]:
          signal.signal(number, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        copies = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10) for fd in [child.fileno(), *pipes]]
        for target, fd in enumerate(copies, 3): os.dup2(fd, target)
        close_from(7)
        channel = socket.socket(fileno=3)
        session_worker(self.spec, self.directory, channel, self.deadline)
        os._exit(0)
      except BaseException as error:
        preserve_worker_failure(self.directory, error, self.deadline)
        os._exit(75)
    child.close()
    self.child_endpoint = None
    self.pidfd = os.pidfd_open(self.pid, 0)
    # Only the actual session worker retains the pipe handles. Its death makes
    # input EOF visible to the bridge, independent of this parent's state.
    for pipe in [self.process.stdin, self.process.stdout, self.process.stderr]: pipe.close()

  def receive(self, cutoff):
    while now() < cutoff:
      readable, _, _ = select.select([self.channel, self.pidfd], [], [],
                                    min(0.5, max(0, (cutoff - now()) / SECOND)))
      require(now() < cutoff, 'Late host result wakeup')
      if self.channel in readable:
        raw, ancillary, flags, _address = self.channel.recvmsg(8192, 0)
        require(raw and not ancillary and not flags, 'Controller result truncated/lost')
        value = json_bytes(raw)
        require(now() < cutoff, 'Late host result admission')
        return value
      if self.pidfd in readable: raise ValueError('Owned host worker exited before its result')
    raise ValueError('Independent host controller deadline')

  def finish(self):
    require(self.armed and not self.finished, 'Host attempt not armed/already consumed')
    self.finished = True
    try:
      value = self.receive(self.deadline)
      require(set(value) == {'event', 'phase', 'epoch', 'boot_id', 'evidence_sha256', 'observations',
        'retained_fence', 'authenticated_recovery_observed', 'boot_ready'}
        and value['event'] == 'complete' and value['phase'] == self.spec.configuration['phase']
        and value['retained_fence'] is True and value['authenticated_recovery_observed'] is False
        and value['boot_ready'] is False, 'Unexpected host completion scope')
      readable, _, _ = select.select([self.pidfd], [], [], min(2, max(0, (self.deadline - now()) / SECOND)))
      require(readable, 'Host worker result without actual exit')
      pid, self.wait_status = os.waitpid(self.pid, 0)
      require(pid == self.pid and os.WIFEXITED(self.wait_status) and os.WEXITSTATUS(self.wait_status) == 0,
              'Host worker did not exit successfully')
      remaining = self.deadline - now()
      require(remaining > 0, 'No existing bridge exit allowance')
      require(self.process.wait(timeout=min(2, remaining / SECOND)) == 0,
              'Owned Windows bridge did not exit successfully')
      require(now() < self.deadline, 'Actual process completion after absolute host deadline')
      self.relinquish_reaped()
      require(now() < self.deadline, 'Late controller resource relinquishment')
      self.completion = freeze(value)
      return self.completion
    except BaseException:
      self.cancel()
      raise

  def cancel(self):
    # Never signal a looked-up Windows PID. Its fixed bridge owns its own
    # current-process deadline; unknown Windows shutdown remains unproven.
    if self.pidfd is not None and self.wait_status is None and not self.kill_attempted:
      self.kill_attempted = True
      try: signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
      except ProcessLookupError: pass
      if select.select([self.pidfd], [], [], 1)[0]:
        _pid, self.wait_status = os.waitpid(self.pid, 0)
    elif self.pidfd is None and type(self.pid) is int and self.pid > 1 and self.wait_status is None:
      # pidfd_open itself can fail after fork. SIGCHLD was admitted waitable
      # and no other reaper/thread exists, so this still-unreaped child PID
      # cannot have been reused. This is not a process lookup or name kill.
      if not self.kill_attempted:
        self.kill_attempted = True
        try: os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError: pass
      pid, status = os.waitpid(self.pid, os.WNOHANG)
      if pid == self.pid: self.wait_status = status
    if self.child_endpoint is not None:
      self.child_endpoint.close(); self.child_endpoint = None
    if self.process is not None:
      for pipe in [self.process.stdin, self.process.stdout, self.process.stderr]:
        if pipe is not None: pipe.close()
    if self.process is not None and self.process.poll() is None:
      self.process.terminate()  # Only the still-owned, unreaped WSL child.
      try: self.process.wait(timeout=1)
      except subprocess.TimeoutExpired: pass
    self.relinquish_reaped()
    # A D-state worker or Windows close may remain unknown. Do not fabricate
    # resource closure, reconnect, retry or a positive preparation completion.

  def relinquish_reaped(self):
    if self.wait_status is None: return
    if self.channel is not None:
      self.channel.close(); self.channel = None
    if self.pidfd is not None:
      os.close(self.pidfd); self.pidfd = None
