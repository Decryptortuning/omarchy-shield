#!/usr/bin/python3.14
"""Fixed native systemd USB control service; never owns the watchdog fd."""
import os
from pathlib import Path
import select
import socket
import stat
import sys
import time

sys.path.insert(0, '/run/shield-native/runtime')
sys.path.insert(1, '/usr/lib/omarchy/shield/qualification')

def diagnostic(stage, error=None):
  """Best-effort native PID1-child evidence; never a control or recovery grant."""
  fd = None
  try:
    if (sys.argv[1:] != ['--run'] or os.getpid() <= 1 or os.getppid() != 1
        or os.getuid() != 0 or os.geteuid() != 0 or os.getgid() != 0 or os.getegid() != 0
        or os.uname().machine != 'aarch64' or os.uname().release != '7.1.0-shield-bringup'):
      return
    name = 'none' if error is None else type(error).__name__
    if (type(stage) is not str or not 0 < len(stage) <= 64
        or not all(char.isascii() and (char.isalnum() or char in '-_') for char in stage)
        or not 0 < len(name) <= 64
        or not all(char.isascii() and (char.isalnum() or char == '_') for char in name)):
      return
    fd = os.open('/dev/kmsg', os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if (not stat.S_ISCHR(info.st_mode) or info.st_uid or info.st_gid
        or info.st_rdev != os.makedev(1, 11) or info.st_mode & 0o022):
      return
    elapsed = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    message = f'<3>shield-root-control stage={stage} boottime_ns={elapsed} error={name}\n'.encode('ascii')
    if len(message) <= 240:
      os.write(fd, message)  # One write only; no retry or output-derived authority.
    # At most eight traceback links; public allowlisted source sites only.
    # Never format an exception, locals, a full path, or arbitrary function name.
    allowed = ('native-root-control.py', 'native_unit_policy.py', 'native-boot.py', 'native_boot_context.py', 'guardian_binding.py',
               'native_control_protocol.py', 'usb_root_profile.py', 'native_gadget.py',
               'native_serial_link.py', 'native_children.py', 'native_root_storage.py',
               'native_maintenance.py', 'native_mounts.py', 'native_work_guard.py',
               'native_layer_reader.py', 'native_layer_writer.py', 'native_ram_recovery.py',
               'native_cleanup_rpc.py', 'guardian_client.py')
    trace = None if error is None else error.__traceback__
    caller_file, caller_line = 'none', 0
    for depth in range(8):
      if trace is None:
        break
      code = trace.tb_frame.f_code
      filename = code.co_filename
      line = trace.tb_lineno
      basename = filename.rsplit('/', 1)[-1] if type(filename) is str else ''
      if (basename in allowed and code.co_name != 'require'
          and type(line) is int and 0 < line <= 99999):
        # Select the literal whitelist member, never emit the original path.
        public_file = allowed[allowed.index(basename)]
        site = (f'<3>shield-root-fault file={public_file} line={line} '
                f'caller_file={caller_file} caller_line={caller_line} depth={depth}\n').encode('ascii')
        if len(site) <= 240:
          os.write(fd, site)  # One attempt per admitted site; no retry.
        caller_file, caller_line = public_file, line
      trace = trace.tb_next
  except BaseException:
    pass  # Logging cannot replace the owner, advance a phase or extend its time.
  finally:
    if fd is not None:
      try: os.close(fd)
      except BaseException: pass

DIAGNOSTIC_STAGE = 'root-imports'

def mark(stage):
  global DIAGNOSTIC_STAGE
  DIAGNOSTIC_STAGE = stage
  diagnostic(stage)


mark('root-imports')
try:
  from guardian_client import GuardianClient
  from native_boot_context import DIRECTORY, close_from, directory, load
  from native_cleanup_rpc import ENDPOINT, RootFence
  from native_gadget import validate as validate_gadget, wait_configured
  from native_serial_link import NativeLink, SECOND, now, open_native_tty
  from native_unit_policy import validate as validate_units
  from usb_root_profile import require
except BaseException as error:
  diagnostic(DIAGNOSTIC_STAGE, error)
  raise


def notify_ready():
  path = os.environ.get('NOTIFY_SOCKET', '')
  require(path and path[0] in {'/', '@'}, 'Native control readiness endpoint absent')
  endpoint = '\0' + path[1:] if path[0] == '@' else path
  with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as channel:
    channel.setblocking(False)
    raw = b'READY=1\nSTATUS=admitted USB control authenticated; cleanup RPC listening'
    require(channel.sendto(raw, endpoint) == len(raw), 'Native control readiness failed')


def main():
  require(sys.argv[1:] == ['--run'] and os.getpid() != 1 and os.getppid() == 1,
          'Native control is a fixed systemd PID1 child')
  mark('root-close-fds')
  close_from(3)  # No inherited watchdog, block device, mount or transport rights.
  mark('root-load-bundle')
  bundle = load(epoch='root')
  require(bundle.phase == 'systemd' and 0 < now() < 105 * SECOND,
          'Wrong or late full-systemd control startup')
  mark('root-effective-units')
  validate_units(bundle.profile)
  mark('root-gadget')
  validate_gadget(bundle, bound=True)
  mark('root-wait-configured')
  wait_configured(bundle, min(now() + 2 * SECOND, 107 * SECOND))
  mark('root-runtime-directory')
  directory(DIRECTORY, private=True)
  require(not ENDPOINT.exists() and not ENDPOINT.is_symlink(), 'Existing control endpoint never replaced')
  mark('root-open-tty')
  descriptor = open_native_tty()
  mark('root-guardian-client')
  guardian = GuardianClient(bundle.profile['candidate'], bundle.boot_id, 2)
  abort_attempted = False
  def abort_once():
    nonlocal abort_attempted
    if abort_attempted: return
    abort_attempted = True  # No retry after a possibly accepted request.
    guardian.abort()
  mark('root-listener')
  listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
  try:
    listener.setblocking(False)
    listener.bind(str(ENDPOINT))
    os.chmod(ENDPOINT, 0o600)
    listener.listen(1)
    mark('root-serial-session')
    link = NativeLink(descriptor, bundle.contexts['root'], bundle.key('root'),
                      bundle.boot_id, 600 * SECOND)
    fence = RootFence(bundle, link)
    mark('root-handshake')
    handshake_cutoff = min(now() + 10 * SECOND, 110 * SECOND)
    ready = False
    poll = select.epoll()
    poll.register(descriptor, select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
    poll.register(listener.fileno(), select.EPOLLIN)
    while now() < 600 * SECOND:
      timestamp = now()
      require(ready or timestamp < handshake_cutoff, 'Root authenticated handshake deadline')
      require(not ready or link.last_host_ns is not None
              and timestamp - link.last_host_ns < 15 * SECOND,
              'Authenticated host control became stale')
      link.tick()
      poll.modify(descriptor, select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR
                  | (select.EPOLLOUT if link.wants_write else 0))
      cutoff = min(timestamp + SECOND, 600 * SECOND)
      if not ready:
        cutoff = min(cutoff, handshake_cutoff)
        if link.state == 'probe' and not link.wants_write:
          cutoff = min(cutoff, link.next_hint)
      if fence.request is not None and not fence.accepted: cutoff = min(cutoff, fence.cutoff)
      for fd, flags in poll.poll(max(0, (cutoff - now()) / SECOND)):
        if fd == descriptor:
          require(not flags & (select.EPOLLHUP | select.EPOLLERR), 'Native USB control lost')
          if flags & select.EPOLLIN: link.drive_read()
          if flags & select.EPOLLOUT: link.drive_write()
        elif fd == listener.fileno():
          mark('root-receiver-bind')
          fence.accept(listener)
          mark('root-receiver-accepted')
          poll.unregister(listener.fileno())  # One held receiver connection only.
          poll.register(fence.channel.fileno(), select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
          poll.register(fence.peer.fd, select.EPOLLIN)
        elif fence.peer is not None and fd == fence.peer.fd:
          raise ValueError('Bound recovery receiver exited')
        elif fence.channel is not None and fd == fence.channel.fileno():
          require(not flags & (select.EPOLLHUP | select.EPOLLERR), 'Held cleanup connection lost')
          mark('root-rpc-read')
          fence.readable()
      for event in link.take_events():
        if event.kind == 'ready':
          require(not ready and now() < handshake_cutoff, 'Unexpected or late root readiness')
          # No guardian health dependency here: receiver needs this readiness,
          # and guardian starts only after the receiver's separate readiness.
          mark('root-notify-ready')
          notify_ready()
          ready = True
          mark('root-ready')
        elif event.kind == 'abort':
          require(ready, 'Abort before root readiness')
          abort_once()
        fence.event(event)
      fence.tick()
    raise ValueError('Finite native control deadline')
  except BaseException:
    # A failed transport never authorizes a plain reboot. The existing sole
    # guardian may latch abort and drive filesystem cleanup; its finite feeding
    # window persists even if this process cannot request or observe that path.
    try: abort_once()
    except (OSError, ValueError): pass
    raise
  finally:
    guardian.close()
    listener.close()
    os.close(descriptor)


if __name__ == '__main__':
  try:
    main()
  except BaseException as error:
    diagnostic(DIAGNOSTIC_STAGE, error)
    if isinstance(error, (OSError, ValueError, KeyError)):
      raise SystemExit(65)
    raise
