#!/usr/bin/python3.14
"""Fixed initial-RAM PID1 for the source-pinned native preparation cohort.

No host packet supplies a command, mount source, role, duration or boot path.
This source remains unqualified until its capsule/host/worker producers and
consumers settle together. It is never an Android recovery init replacement.
"""
import os
import stat
import sys
import time


def diagnostic(stage, error=None):
  """Best-effort fixed stage evidence only; never a control or recovery grant."""
  if os.getpid() != 1:
    return
  fd = None
  try:
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
    message = f'<3>shield-native stage={stage} boottime_ns={elapsed} error={name}\n'.encode('ascii')
    if len(message) <= 240:
      os.write(fd, message)  # One write only; no retry or output-derived authority.
    # At most eight traceback links; public allowlisted source sites only.
    # Never format an exception, locals, a full path, or arbitrary function name.
    allowed = ('native-boot.py', 'native_boot_context.py', 'guardian_binding.py',
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
        site = (f'<3>shield-native-fault file={public_file} line={line} '
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
      except OSError: pass


def admission_hold(stage, error):
  """PID1 refusal before an owner exists; retain the existing finite policy."""
  if os.getpid() != 1:
    raise RuntimeError('Admission hold requires PID1')
  diagnostic(stage, error)
  while True:
    try: time.sleep(0.25)
    except BaseException: pass


diagnostic('python-imports')
try:
  import hashlib
  from types import MappingProxyType
  from pathlib import Path
  import select
  import signal
  import socket
  import subprocess

  sys.path.insert(0, '/run/shield-native/runtime')
  sys.path.insert(1, '/usr/lib/omarchy/shield/qualification')

  from native_boot_context import (DIRECTORY, INPUTS, POLICY_PATHS, RUNTIME, close_from,
    directory, load, owned_bytes, plain, source_path)
  from native_children import Children
  from native_gadget import bind, prepare, wait_configured
  from native_layer_reader import read_layer
  from native_layer_writer import Roots
  from native_mounts import MountDomain, NEWROOT, TOP
  from native_phase_plan import load_plan, predecessor
  from native_root_storage import USBRoot, discover
  from native_control_protocol import valid_utc_ns
  from native_serial_link import Event, NativeLink, SECOND, now, open_native_tty
  from native_unit_policy import files as policy_files
  from usb_candidate_transaction import base_unchanged, default_subvolume
  from maintenance_accounts import account_preimages
  from usb_root_profile import (database_profile, file_identity, installed_packages,
    installed_versions, path_absent, require, sections)
except BaseException as error:
  if os.getpid() == 1:
    admission_hold('python-import-refused', error)
  raise

diagnostic('python-imports-ready')


# These RAM policy parents are shared system interfaces, unlike the private
# /run/shield-native tree. Initial PID1 deliberately inherits umask 0077.
PUBLIC_POLICY_DIRECTORIES = frozenset({
  '/run', '/run/systemd', '/run/systemd/system',
  '/run/systemd/system/shield-qualification-recovery.service.d',
  '/run/systemd/system/shield-qualification.target.d',
  '/run/systemd/system/home.mount.d',
  '/run/udev', '/run/udev/rules.d',
})


def policy_directory(path):
  """Create public RAM parents explicitly; never repair an existing object."""
  if str(path) not in PUBLIC_POLICY_DIRECTORIES:
    directory(path)  # Existing private parents retain their exact permissions.
    return
  try:
    path.mkdir(mode=0o755)
  except FileExistsError:
    pass
  else:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
      before = os.fstat(descriptor)
      require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
              and not before.st_mode & 0o022, 'Unowned new RAM policy parent')
      os.fchmod(descriptor, 0o755)  # mkdir's mode was filtered by inherited 0077.
      after = os.fstat(descriptor)
      require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
              and stat.S_IMODE(after.st_mode) == 0o755, 'RAM policy parent mode differs')
    finally:
      os.close(descriptor)
  directory(path)
  require(stat.S_IMODE(path.lstat().st_mode) == 0o755,
          'Existing public RAM policy parent must be traversable')


MACHINE_ID_BASELINE = MappingProxyType({'type': 'file', 'mode': 0o444,
  'uid': 0, 'gid': 0, 'bytes': 0,
  'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'xattrs': MappingProxyType({})})


def machine_id_state(roots, expected):
  """C-only systemd state admission under the already-held read-only USB lease.

  B still materializes and verifies its exact empty-file postimage. After PID1
  initializes the ID, C admits only the canonical systemd 262 persisted form.
  Never return/log its value or digest, normalize a file, or change B's witness.
  Other installed files retain byte-exact postimage verification.
  """
  require(type(expected) in (dict, MappingProxyType) and expected == MACHINE_ID_BASELINE
          and all(type(expected[key]) is int for key in ('mode', 'uid', 'gid', 'bytes'))
          and type(expected['type']) is str and type(expected['sha256']) is str
          and type(expected['xattrs']) in (dict, MappingProxyType),
          'Prepared machine ID baseline differs')
  def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
  def metadata(info):
    return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o444
            and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
            and info.st_size in (0, 33))
  roots.guard()
  parent, leaf = roots.parent('etc/machine-id')
  try:
    require(leaf == 'machine-id', 'Fixed machine ID leaf required')
    first = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    require(metadata(first), 'Machine ID node metadata differs')
    # NONBLOCK prevents a substituted FIFO from blocking before fstat rejects it.
    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 dir_fd=parent)
    try:
      opened = os.fstat(fd)
      require(metadata(opened) and identity(opened) == identity(first),
              'Machine ID node changed before read')
      require(not os.listxattr(fd), 'Machine ID has unexpected attributes')
      roots.guard()
      raw = os.read(fd, 34)  # Exactly one bounded read; includes one overflow byte.
      roots.guard()
      last = os.fstat(fd)
      current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
      require(identity(first) == identity(last) == identity(current)
              and not os.listxattr(fd) and len(raw) == first.st_size,
              'Machine ID changed during read')
      if raw == b'':
        return 'empty'
      require(len(raw) == 33 and raw[-1:] == b'\n'
              and all(value in b'0123456789abcdef' for value in raw[:32])
              and raw[:32] != b'0' * 32, 'Machine ID persisted form differs')
      return 'initialized'
    finally:
      os.close(fd)
  finally:
    os.close(parent)


QUALIFICATION_USER_HOME = 'home/shieldqual'


def user_home_boundary(roots, expected):
  """C admits the nonadmin user's directory, never its mutable descendants.

  The immutable layer still binds the account, privileged services and initial
  installation. Runtime preferences and user programs are lower-trust data.
  Their execution gets a separate nosuid,nodev home mount before PID1 starts.
  """
  require(expected['type'] == 'directory' and expected['uid'] == expected['gid'] == 1001,
          'Sealed qualification home ownership differs')
  roots.guard()
  parent, leaf = roots.parent(QUALIFICATION_USER_HOME)
  descriptor = None
  try:
    require(leaf == 'shieldqual', 'Fixed qualification user home required')
    before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    descriptor = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
    opened = os.fstat(descriptor)
    mode = stat.S_IMODE(opened.st_mode)
    require(stat.S_ISDIR(opened.st_mode) and opened.st_uid == opened.st_gid == 1001
            and mode <= 0o777 and not mode & 0o022 and mode & 0o500 == 0o500,
            'Unsafe runtime user home boundary')
    def identity(info):
      return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
              info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
    roots.guard()
    require(identity(before) == identity(opened) == identity(os.fstat(descriptor))
            == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)),
            'Runtime user home changed during admission')
  finally:
    if descriptor is not None: os.close(descriptor)
    os.close(parent)


class Supervisor:
  def __init__(self, bundle):
    self.bundle = bundle
    self.children = Children()
    self.events = select.epoll()
    self.events.register(self.children.wake_read, select.EPOLLIN)
    self.child_fds = {}
    self.tty = self.link = self.device = self.mounts = None
    self.aborted = False
    self.clock_sample = None
    self.clock_attempted = self.clock_ready = False
    self.stage = 'admission'
    diagnostic(self.stage)
    self.handoff_challenge = None
    self.handoff_transferred = self.handoff_confirmed = False
    self.control_events = []
    # Subscribe BEFORE the first storage scan. Events are wakeups only; their
    # strings never select a device or grant write authority. Kernel PID0 is
    # required and every wake is followed by actual source-pinned sysfs checks.
    self.uevent = socket.socket(socket.AF_NETLINK,
      socket.SOCK_DGRAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC, 15)
    self.uevent.bind((1, 1))
    self.events.register(self.uevent.fileno(), select.EPOLLIN | select.EPOLLERR)
    self.previous = now()

  def check(self, deadline):
    timestamp = now()
    require(type(deadline) is int and 0 < self.previous <= timestamp < deadline <= 600 * SECOND,
            'Native stage clock/deadline')
    self.previous = timestamp
    require(not self.aborted and not self.children.interrupted, 'Native work interrupted')
    require(not self.children.unexpected_statuses, 'Unexpected RAM descendant status')

  def spawn(self, name):
    child = self.children.spawn(name)
    for fd, kind in [(child.result_fd, 'result'), (child.pidfd, 'pid')]:
      self.child_fds[fd] = (child, kind)
      self.events.register(fd, select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
    return child

  def retire(self, name):
    child = self.children.children[name]
    for fd in [child.result_fd, child.pidfd]:
      if fd in self.child_fds:
        self.events.unregister(fd)
        del self.child_fds[fd]
    self.children.close_reaped(name)

  def pump(self, timeout=0):
    require(0 <= timeout <= 1, 'Bounded native event-loop wait required')
    if self.link is not None:
      self.link.tick()
      self.events.modify(self.tty, select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR
                         | (select.EPOLLOUT if self.link.wants_write else 0))
    for fd, flags in self.events.poll(timeout):
      if fd == self.children.wake_read:
        self.children.drain_wake()
        self.children.reap()
      elif fd == self.uevent.fileno():
        require(not flags & select.EPOLLERR, 'Kernel discovery event stream lost')
        for _event in range(32):
          try: raw, _ancillary, message_flags, sender = self.uevent.recvmsg(8192, 0)
          except BlockingIOError: break
          require(raw and not message_flags and sender[0] == 0, 'Invalid/truncated kernel discovery event')
      elif fd == self.tty:
        require(not flags & (select.EPOLLHUP | select.EPOLLERR), 'Native control tty lost')
        if flags & select.EPOLLIN: self.link.drive_read()
        if flags & select.EPOLLOUT: self.link.drive_write()
      elif fd in self.child_fds:
        child, kind = self.child_fds[fd]
        if kind == 'result':
          child.read()
          if child.eof:
            self.events.unregister(fd)
            del self.child_fds[fd]
        else:
          self.children.reap()
          if child.reaped:
            self.events.unregister(fd)
            del self.child_fds[fd]
      else:
        # The fixed maintenance producer registers its recovery/cgroup events
        # through an explicit subclass; no caller-selected plugin dispatch.
        raise ValueError('Unknown native event owner')
    self.children.reap()
    if self.link is not None:
      for event in self.link.take_events():
        if event.kind == 'ready':
          require(self.clock_sample is None and not self.clock_attempted,
                  'Repeated initial clock admission')
          self.clock_sample = event
        if self.bundle.phase in {'packages', 'layer'}:
          require(len(self.control_events) < 32, 'Unconsumed maintenance control event budget')
          self.control_events.append(event)
        if event.kind == 'abort': self.aborted = True
        if event.challenge == self.handoff_challenge and self.handoff_challenge is not None:
          if event.kind == 'evidence-transferred': self.handoff_transferred = True
          if event.kind == 'pong-transferred':
            require(self.handoff_transferred and now() < 100 * SECOND, 'Late/untransferred handoff fence')
            self.handoff_confirmed = True

  def take_control_events(self):
    result, self.control_events = tuple(self.control_events), []
    return result

  def wait(self, predicate, deadline):
    while not predicate():
      self.check(deadline)
      self.pump(min(0.5, max(0, (deadline - now()) / SECOND)))
    self.check(deadline)

  def helper(self, name):
    self.stage = name
    diagnostic(self.stage)
    started = now()
    if name == 'health':
      require(started < 60 * SECOND, 'Late early health start')
      deadline = min(started + 30 * SECOND, 60 * SECOND)
    else:
      require(name == 'internal-ro' and started < 70 * SECOND, 'Late internal restriction start')
      deadline = min(started + 20 * SECOND, 90 * SECOND)
    child = self.spawn(name)
    try:
      self.wait(lambda: child.reaped and child.eof, deadline)
      records = child.take_records()
      require(child.success and len(records) == 1, 'Helper exit/EOF/result disagrees')
      result = records[0]
      if name == 'health':
        require(set(result) == {'kind', 'healthy', 'worker_reaped', 'watchdog_opened',
          'sample_ns', 'finished_ns', 'rpm'} and result['kind'] == 'early-health'
          and result['healthy'] is True and result['worker_reaped'] is True
          and result['watchdog_opened'] is False
          and type(result['sample_ns']) is type(result['finished_ns']) is type(result['rpm']) is int
          and 0 < result['sample_ns'] <= result['finished_ns'] <= now()
          and now() - result['sample_ns'] <= 3 * SECOND and 0 < result['rpm'] <= 999999,
          'Early health record is not fresh and healthy')
      else:
        require(set(result) == {'kind', 'parent_ro', 'partitions_ro', 'media_reads',
          'media_writes', 'boot_RPMB_opened', 'layout_qualified'}
          and result['kind'] == 'internal-user-ro' and result['parent_ro'] is True
          and type(result['partitions_ro']) is int and result['partitions_ro'] == 33
          and all(result[key] is False for key in ['media_reads', 'media_writes',
                                                  'boot_RPMB_opened', 'layout_qualified']),
          'Internal restriction result differs')
      self.check(deadline)
      self.retire(name)
      return result
    except BaseException:
      self.children.kill_helper_once(name)
      raise

  def apply_clock(self, deadline):
    """One boot-bound HOST sample; never RTC or BOOTTIME writes.

    USB handshake latency is bounded, not measured NTP precision. The HOST
    realtime is trusted policy input; authentication cannot prove its accuracy.
    A failed/uncertain clock syscall consumes this attempt and prevents work.
    """
    self.check(deadline)
    sample = self.clock_sample
    require(os.getpid() == 1 and os.geteuid() == 0 and self.bundle.epoch == 'early'
            and self.link is not None and self.link.ready
            and not self.clock_attempted and not self.clock_ready
            and type(sample) is Event and sample.kind == 'ready'
            and valid_utc_ns(sample.utc_ns)
            and type(sample.received_boottime_ns) is int,
            'No initial boot-bound clock admission')
    before = now()
    elapsed = before - sample.received_boottime_ns
    require(0 <= elapsed <= 10 * SECOND, 'Initial UTC sample too old or future')
    target = sample.utc_ns + elapsed
    require(valid_utc_ns(target), 'Adjusted UTC outside supported calendar')
    self.clock_attempted = True
    time.clock_settime_ns(time.CLOCK_REALTIME, target)
    observed = time.time_ns()
    after = now()
    require(before <= after < deadline
            and target - 1_000_000 <= observed <= target + (after - before) + 1_000_000,
            'Initial wall clock readback differs')
    self.check(deadline)
    self.clock_ready = True

  def transport(self):
    self.stage = 'control'
    diagnostic(self.stage)
    diagnostic('gadget-prepare')
    prepare(self.bundle)
    diagnostic('gadget-bind')
    bind(self.bundle)
    diagnostic('gadget-bound')
    configured_cutoff = (35 if self.bundle.phase == 'systemd' else 90) * SECOND
    handshake_cutoff = (40 if self.bundle.phase == 'systemd' else 100) * SECOND
    diagnostic('gadget-wait-configured')
    wait_configured(self.bundle, min(now() + 10 * SECOND, configured_cutoff))
    diagnostic('gadget-configured')
    diagnostic('gadget-open-tty')
    self.tty = open_native_tty()
    self.link = NativeLink(self.tty, self.bundle.contexts['early'], self.bundle.key('early'),
                           self.bundle.boot_id, 600 * SECOND)
    self.events.register(self.tty, select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
    diagnostic('gadget-auth-handshake')
    deadline = min(now() + 10 * SECOND, handshake_cutoff)
    self.wait(lambda: self.link.ready, deadline)
    self.apply_clock(deadline)
    require(self.clock_ready, 'Wall clock required before USB work')
    diagnostic('gadget-auth-ready')

  def storage(self):
    require(self.clock_ready, 'Storage before initial clock admission')
    self.stage = 'usb'
    diagnostic(self.stage)
    observed = None
    def found():
      nonlocal observed
      observed = discover(self.bundle)
      return observed is not None
    cutoff = min(now() + 15 * SECOND, (50 if self.bundle.phase == 'systemd' else 105) * SECOND)
    self.wait(found, cutoff)
    self.device = USBRoot(self.bundle, observed)
    self.check(cutoff)
    self.mounts = MountDomain(self.device)

  def guard_preopen(self):
    self.check(95 * SECOND)
    self.pump(0)
    self.check(95 * SECOND)
    require(self.link.last_host_ns is not None and now() - self.link.last_host_ns < 15 * SECOND,
            'Authenticated pre-open host control became stale')

  def original_default(self):
    self.guard_preopen()
    process = subprocess.Popen(['/usr/bin/btrfs', 'subvolume', 'get-default', str(TOP)],
      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
      env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'})
    try:
      raw, _unused = process.communicate(timeout=min(3, (95 * SECOND - now()) / SECOND))
    except subprocess.TimeoutExpired:
      process.kill()  # Still-owned, unreaped child; no PID/name/global kill.
      try: process.wait(timeout=0.5)
      except subprocess.TimeoutExpired: pass
      raise
    self.guard_preopen()
    require(process.returncode == 0 and len(raw) <= 4096, 'Default-root inspection failed')
    return default_subvolume(raw.decode('ascii'))

  def verify_payload(self, manifest, root):
    """Same exact profile as verify_root, with control service between files."""
    self.guard_preopen()
    require(installed_versions(root) == manifest['installed_packages']
            and database_profile(root) == manifest['database'], 'Installed package/database closure differs')
    for name in manifest['required_absent']:
      self.guard_preopen()
      require(path_absent(root, name), 'Obsolete package path remains')
    packages = installed_packages(root)
    names = set()
    for name, item in manifest['packages'].items():
      package, metadata = packages[name]
      require(metadata['VERSION'] == [item['version']], 'Installed package version differs')
      names.update(value.rstrip('/') for value in sections(package / 'files')['FILES'])
    module_root = root / 'usr/lib/modules/7.1.0-shield-bringup'
    require(module_root.is_dir() and not module_root.is_symlink(), 'Matching module tree absent')
    names.update(str(path.relative_to(root)) for path in module_root.rglob('*'))
    names.add('etc/ld.so.cache')
    require(names == set(manifest['root_files']), 'Extra or missing package/module paths')
    for name in sorted(names):
      self.guard_preopen()
      require(file_identity(root, name) == manifest['root_files'][name], 'Matched root file differs')
    self.guard_preopen()

  def verify_layer_postimages(self, content, observed):
    require(self.bundle.phase == 'systemd', 'Runtime home admission is systemd C only')
    entries = content.manifest['entries']
    require('etc/machine-id' in entries and QUALIFICATION_USER_HOME in entries,
            'Prepared machine ID or user home entry missing')
    user_home_boundary(observed, entries[QUALIFICATION_USER_HOME]['identity'])
    diagnostic('user-home-boundary')
    for ordinal, (name, item) in enumerate(entries.items()):
      # These paths were fully verified by B when installed. C must not read
      # user-controlled contents as privileged inputs or freeze preferences.
      if name == QUALIFICATION_USER_HOME or name.startswith(QUALIFICATION_USER_HOME + '/'):
        continue
      try:
        if name == 'etc/machine-id':
          state = machine_id_state(observed, item['identity'])
          diagnostic('machine-id-' + state)
        else:
          require(observed.observe(name) == item['identity'], 'Immutable prepared layer postimage differs')
      except (OSError, ValueError) as error:
        diagnostic('layer-postimage-' + str(ordinal), error)
        raise

  def stage_policy(self):
    for name, data in policy_files(self.bundle.profile).items():
      require(name in POLICY_PATHS, 'Unknown RAM startup policy')
      expected = self.bundle.configuration['sources']['root'][name]
      require(plain(expected) == {'sha256': hashlib.sha256(data).hexdigest(),
                                 'bytes': len(data), 'mode': 0o644}, 'Policy producer/capsule mismatch')
      path = Path('/') / name
      current = Path('/')
      for part in path.parts[1:-1]:
        current /= part
        policy_directory(current)
      fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
      try:
        os.fchmod(fd, 0o644)
        require(os.write(fd, data) == len(data), 'Uncertain RAM policy write')
      finally: os.close(fd)

  def root_source_inventory(self):
    for name, item in self.bundle.configuration['sources']['root'].items():
      self.guard_preopen()
      path = source_path(name) if name.startswith('run/') else NEWROOT / name
      data = owned_bytes(path, item['bytes'], item['mode'])
      require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
              'Actual selected systemd source differs')
    for name, expected in [('profile.json', self.bundle.configuration['guardian_profile_sha256']),
                           ('artifacts.json', self.bundle.configuration['guardian_artifacts_sha256'])]:
      path = NEWROOT / 'usr/lib/omarchy/shield/qualification' / name
      require(hashlib.sha256(owned_bytes(path, 64 * 1024, 0o600)).hexdigest() == expected,
              'Selected root guardian/profile sidecar differs')

  def systemd(self, plan):
    self.stage = 'predecessors'
    diagnostic(self.stage)
    a = predecessor(self.bundle, plan, 'predecessorA', 'packages')
    b = predecessor(self.bundle, plan, 'predecessorB', 'layer')
    require(a['boot_id'] != b['boot_id'] and a['session_id'] != b['session_id'],
            'Preparation phases must be distinct owned boots')
    content = read_layer(self.bundle.input('layer')[0], plan.writer.layer)
    self.helper('health')
    self.helper('internal-ro')
    self.transport()
    self.storage()
    self.mounts.readonly_top(95 * SECOND)
    self.stage = 'verification'
    diagnostic(self.stage)
    maintenance = plan.maintenance_data()
    base_unchanged(TOP, maintenance)
    account_preimages(TOP / maintenance['original_subvolumes']['root'], maintenance['base_account_preimages'])
    require(self.original_default() == plan.original_default, 'Original default selection differs')
    for relative, receipt in [('.shield-qualification/' + maintenance['candidate_id'] + '/state.json', a),
      ('.shield-phase-B/' + maintenance['candidate_id'] + '/MATERIALIZED.json', b)]:
      raw = owned_bytes(TOP / relative, 64 * 1024, 0o600)
      require(hashlib.sha256(raw).hexdigest() == receipt['journal_sha256'], 'Physical phase journal differs')
    names = self.bundle.profile['filesystem']['subvolumes']
    root, home = TOP / names['root'], TOP / names['home']
    self.verify_payload(plan.manifest_data(), root)
    descriptors = [os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                   for path in [root, home]]
    try:
      observed = Roots(*descriptors, self.guard_preopen)
      try:
        self.verify_layer_postimages(content, observed)
      finally: observed.close()
    finally:
      for fd in descriptors: os.close(fd)
    require(self.original_default() == plan.original_default, 'Default changed during read-only verification')
    self.mounts.check()
    self.mounts.candidate(95 * SECOND)
    self.stage_policy()
    shadow = NEWROOT / 'etc/udev/rules.d/99-omarchy-shield-native-control.rules'
    require(not shadow.exists() and not shadow.is_symlink(), 'Candidate overrides owned RAM udev rule')
    self.root_source_inventory()
    self.children.require_handoff()
    self.stage = 'handoff'
    diagnostic(self.stage)
    observation = {'kind': 'systemd-handoff',
      'root_session_id': self.bundle.contexts['root'].session_id,
      'candidate_id': self.bundle.profile['filesystem']['candidate_id'],
      'filesystem_uuid': self.bundle.profile['filesystem']['uuid'],
      'payload_manifest_sha256': self.bundle.configuration['inputs']['payload']['sha256'],
      'layer_manifest_sha256': plan.writer.layer.manifest_sha256,
      'phase_a_receipt_sha256': self.bundle.configuration['inputs']['predecessorA']['sha256'],
      'phase_b_receipt_sha256': self.bundle.configuration['inputs']['predecessorB']['sha256'],
      'original_default': plain(plan.original_default), 'ram_children_reaped': True,
      'watchdog_opened': False, 'source_root_verified': True,
      'immutable_layer_postimages_verified': True, 'user_home_boundary_verified': True,
      'user_home_contents_verified': False, 'boottime_ns': now()}
    self.handoff_challenge = self.link.evidence(observation, purpose='handoff')
    self.wait(lambda: self.handoff_confirmed, 100 * SECOND)
    self.mounts.check()
    self.children.require_handoff()
    self.check(100 * SECOND)
    require('guardian' not in self.children.attempted, 'RAM guardian must never precede systemd handoff')
    self.events.unregister(self.tty)
    os.close(self.tty); self.tty = None
    self.device.close()
    # u_serial gs_close may block for its 15-second FIFO-close timeout even
    # with O_NONBLOCK. A clock check before close cannot authorize a late exec.
    self.children.require_handoff()
    self.check(100 * SECOND)
    signal.set_wakeup_fd(-1)
    close_from(3)
    self.children.require_handoff()
    self.check(100 * SECOND)
    os.execve('/usr/bin/switch_root', ['/usr/bin/switch_root', str(NEWROOT), '/usr/lib/systemd/systemd'],
              {'PATH': '/usr/bin:/bin', 'HOME': '/', 'TERM': 'linux', 'LANG': 'C.UTF-8'})

  def failed_hold(self, error):
    # A failed/unknown attempt never becomes boot-ready or a retry. Do not
    # kill/close a guardian. Reap real children while its existing finite
    # hardware policy (or the kernel's finite pre-open policy) remains owner.
    # No clean-release, authenticated-recovery or pstore-durability claim here.
    diagnostic(self.stage, error)
    if self.tty is not None:
      try: self.events.unregister(self.tty)
      except OSError: pass
      os.close(self.tty); self.tty = None; self.link = None
    while True:
      try:
        self.children.reap()
        for child in list(self.children.children.values()):
          if not child.eof: child.read()
        self.children.drain_wake()
      except (OSError, ValueError): pass
      time.sleep(0.25)


def main():
  require(sys.argv[1:] == ['--run'] and os.getpid() == 1, 'Only fixed native RAM PID1 may run')
  close_from(3)
  diagnostic('load-bundle')
  bundle = load(epoch='early')
  diagnostic('bundle-ready')
  diagnostic('supervisor-create')
  supervisor = Supervisor(bundle)
  diagnostic('supervisor-ready')
  try:
    diagnostic('load-plan')
    plan = load_plan(bundle)
    diagnostic('plan-ready')
    if bundle.phase == 'systemd':
      supervisor.systemd(plan)
    else:
      from native_maintenance import run
      run(supervisor, plan)
    raise ValueError('Native PID1 phase unexpectedly returned')
  except BaseException as error:
    supervisor.failed_hold(error)


if __name__ == '__main__':
  try:
    main()
  except BaseException as error:
    if os.getpid() != 1:
      raise SystemExit(64)
    # Admission failed before a supervisor existed. Do not exit PID1, start a
    # writer/guardian, or invent a release/restart receipt for that failure.
    admission_hold('admission-refused', error)
