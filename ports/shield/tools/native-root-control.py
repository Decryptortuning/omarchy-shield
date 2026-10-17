#!/usr/bin/python3.14
"""Fixed native systemd USB control service; never owns the watchdog fd."""
import os
from pathlib import Path
import select
import socket
import sys

sys.path.insert(0, '/run/shield-native/runtime')
sys.path.insert(1, '/usr/lib/omarchy/shield/qualification')

from guardian_client import GuardianClient
from native_boot_context import DIRECTORY, close_from, directory, load
from native_cleanup_rpc import ENDPOINT, RootFence
from native_gadget import validate as validate_gadget, wait_configured
from native_serial_link import NativeLink, SECOND, now, open_native_tty
from native_unit_policy import validate as validate_units
from usb_root_profile import require


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
  close_from(3)  # No inherited watchdog, block device, mount or transport rights.
  bundle = load(epoch='root')
  require(bundle.phase == 'systemd' and 0 < now() < 105 * SECOND,
          'Wrong or late full-systemd control startup')
  validate_units()
  validate_gadget(bundle, bound=True)
  wait_configured(bundle, min(now() + 2 * SECOND, 107 * SECOND))
  directory(DIRECTORY, private=True)
  require(not ENDPOINT.exists() and not ENDPOINT.is_symlink(), 'Existing control endpoint never replaced')
  descriptor = open_native_tty()
  guardian = GuardianClient(bundle.profile['candidate'], bundle.boot_id, 2)
  abort_attempted = False
  def abort_once():
    nonlocal abort_attempted
    if abort_attempted: return
    abort_attempted = True  # No retry after a possibly accepted request.
    guardian.abort()
  listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
  try:
    listener.setblocking(False)
    listener.bind(str(ENDPOINT))
    os.chmod(ENDPOINT, 0o600)
    listener.listen(1)
    link = NativeLink(descriptor, bundle.contexts['root'], bundle.key('root'),
                      bundle.boot_id, 600 * SECOND)
    fence = RootFence(bundle, link)
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
          fence.accept(listener)
          poll.unregister(listener.fileno())  # One held receiver connection only.
          poll.register(fence.channel.fileno(), select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
          poll.register(fence.peer.fd, select.EPOLLIN)
        elif fence.peer is not None and fd == fence.peer.fd:
          raise ValueError('Bound recovery receiver exited')
        elif fence.channel is not None and fd == fence.channel.fileno():
          require(not flags & (select.EPOLLHUP | select.EPOLLERR), 'Held cleanup connection lost')
          fence.readable()
      for event in link.take_events():
        if event.kind == 'ready':
          require(not ready and now() < handshake_cutoff, 'Unexpected or late root readiness')
          # No guardian health dependency here: receiver needs this readiness,
          # and guardian starts only after the receiver's separate readiness.
          notify_ready()
          ready = True
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
  except (OSError, ValueError, KeyError):
    raise SystemExit(65)
