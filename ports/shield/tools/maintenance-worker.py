#!/usr/bin/python3.14
"""Fixed role1 worker; PID1 owns cancellation, mounts and physical release.

Only the stopped-worker job produced by the owned PID1 is accepted. Commands
come from the reviewed package core, not messages or job selectors. An uncertain
post-fork command exits immediately so Python cleanup cannot unmount beneath a
still-writing descendant. PID1 alone kills the owned cgroup and proves reaping.
This is unqualified source; no tests/imports/build/native release is implied.
"""
import hashlib
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import time

def worker_diagnostic(stage, error, *, command=None):
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
    if public_stage == 'worker-command' and command is not None:
      # Public numeric identity only; never copy argv, output or exception text.
      # This cannot select a command or change the original failure policy.
      index = count = ordinal = child_status = 'unknown'
      if type(command) is tuple and len(command) == 4:
        sealed, arguments, attempted, observed = command
        if (type(sealed) is frozenset and 0 < len(sealed) <= 128
            and all(type(row) is tuple and row
                    and all(type(value) is str for value in row) for row in sealed)
            and type(arguments) is list and all(type(value) is str for value in arguments)
            and tuple(arguments) in sealed):
          count = len(sealed)
          index = sorted(sealed).index(tuple(arguments)) + 1
        if type(attempted) is int and 1 <= attempted <= 1024:
          ordinal = attempted
        if type(observed) is int and -64 <= observed <= 255:
          child_status = observed
      record = (f'<3>shield-worker-command index={index} count={count} '
           f'ordinal={ordinal} status={child_status}\n').encode('ascii')
      if len(record) <= 240:
        os.write(fd, record)  # One bounded attempt; never retry or export raw logs.
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
sys.path.insert(1, '/usr/lib/omarchy/shield/qualification')

try:
  from guardian_binding import INSTALL
  from maintenance_accounts import account_preimages
  from native_boot_context import (RUNTIME, USB_STORAGE, directory, filesystem_magic,
    json_bytes, load, owned_bytes, plain)
  from native_layer_reader import read_layer
  from native_layer_writer import materialize
  from native_mounts import TOP, table
  from native_phase_plan import canonical, decode, load_plan, predecessor, read_raw_input
  from native_root_storage import number, usb_ancestor
  from native_work_guard import WorkGuard
  from qualification_recovery import filesystem_identity
  from usb_candidate_transaction import base_unchanged, default_subvolume, update_candidate
  from usb_root_profile import admit_payload, require, verify_root
except BaseException as error:
  worker_diagnostic('worker-import', error)
  raise  # Preserve the original uncaught import failure and exit status.


WORK = Path('/run/shield-worker')
PACKAGES = Path('/run/shield-native/packages')
SECOND = 1_000_000_000
COMMAND_CUTOFF = 480 * SECOND  # Existing work540 minus sixty-second reserve.
MAX_OUTPUT = 1024**2
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'HOME': '/root', 'TERM': 'dumb'}
JOB_FIELDS = frozenset({'format_version', 'purpose', 'phase', 'guardian_pid', 'reaper_pid',
  'worker_pid', 'candidate', 'boot_id', 'configuration_sha256', 'session_id', 'top_mount_id'})
FD_PROBE = 'IFS= read -r value < <(/usr/bin/printf "%s\\n" shield-fd-ready) && [[ $value == shield-fd-ready ]]'


def now(): return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def validate_job(value, bundle, worker_pid, parent_pid):
  require(type(value) is dict and set(value) == JOB_FIELDS
          and type(value['format_version']) is int and value['format_version'] == 1
          and value['purpose'] == 'native maintenance worker'
          and bundle.epoch == 'early' and bundle.phase in {'packages', 'layer'}
          and bundle.profile['role'] == 1 and value['phase'] == bundle.phase,
          'Wrong fixed maintenance job')
  for key in ['guardian_pid', 'reaper_pid', 'worker_pid']:
    require(type(value[key]) is int and 1 < value[key] <= 0x7fffffff, 'Wrong owned job PID')
  require(len({value[key] for key in ['guardian_pid', 'reaper_pid', 'worker_pid']}) == 3
          and value['worker_pid'] == worker_pid and value['reaper_pid'] == parent_pid
          and type(value['top_mount_id']) is int and value['top_mount_id'] > 0,
          'Job actor/mount identity differs')
  context = bundle.contexts['early']
  require(value['candidate'] == bundle.profile['candidate'] and value['boot_id'] == bundle.boot_id
          and value['configuration_sha256'] == context.config_sha256
          and value['session_id'] == context.session_id, 'Job capsule/session binding differs')


def peer(pid, argv):
  descriptor = os.pidfd_open(pid, 0)
  try:
    path = Path('/proc') / str(pid)
    require(not select.select([descriptor], [], [], 0)[0]
            and os.readlink(path / 'exe') == argv[0]
            and (path / 'cmdline').read_bytes() == b'\0'.join(os.fsencode(x) for x in argv) + b'\0',
            'Owned maintenance peer changed')
    rows = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines())
    require(rows['PPid'].strip() == '1' and rows['Uid'].split() == rows['Gid'].split() == ['0'] * 4
            and os.readlink(path / 'ns/mnt') == os.readlink('/proc/1/ns/mnt')
            and not select.select([descriptor], [], [], 0)[0], 'Peer ownership/lifetime differs')
    return descriptor
  except BaseException:
    os.close(descriptor); raise



def fd_mount_id(descriptor):
  """Bind an owned open directory to the mountinfo/job mount-ID domain.

  Btrfs getattr reports a per-root anonymous device, while mountinfo reports
  the superblock device. Neither value is the physical USB device identity.
  The kernel exposes the matching mount identifier through this owned FD.
  """
  require(type(descriptor) is int and 0 <= descriptor <= 0x7fffffff,
          'Invalid owned mount descriptor')
  info_fd = os.open('/proc/self/fdinfo/' + str(descriptor),
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    info = os.fstat(info_fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and not info.st_mode & 0o022 and filesystem_magic(info_fd) == 0x9fa0,
            'Owned kernel FD metadata required')
    raw = os.read(info_fd, 4097)
    require(0 < len(raw) <= 4096 and raw.endswith(b'\n') and raw.isascii()
            and b'\0' not in raw and b'\r' not in raw, 'Incomplete kernel FD metadata')
    rows = [line for line in raw.split(b'\n') if line.startswith(b'mnt_id:')]
    prefix = b'mnt_id:\t'
    require(len(rows) == 1 and rows[0].startswith(prefix), 'Ambiguous kernel mount identifier')
    value = rows[0][len(prefix):]
    require(0 < len(value) <= 10 and value.isdigit()
            and str(int(value)).encode('ascii') == value
            and 0 < int(value) <= 0x7fffffff, 'Invalid kernel mount identifier')
    return int(value)
  finally:
    os.close(info_fd)


def top_identity(bundle, job):
  entries = [row for row in table() if row['path'] == str(TOP)]
  require(len(entries) == 1, 'Owned top mount is ambiguous')
  row = entries[0]
  require(row['id'] == job['top_mount_id'] and row['filesystem'] == 'btrfs' and row['root'] == '/'
          and 'rw' in row['options'] and 'rw' in row['super_options']
          and row['options'] & {'nosuid', 'nodev', 'noexec'} == {'nosuid', 'nodev'}
          and not any(x.startswith('rescue=') for x in row['super_options'])
          and 'compress=zstd:1' in row['super_options'], 'Wrong maintenance top posture')
  directory(TOP)
  descriptor = os.open(TOP, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    mounted = os.fstat(descriptor)
    require(stat.S_ISDIR(mounted.st_mode) and mounted.st_uid == mounted.st_gid == 0
            and not mounted.st_mode & 0o022 and fd_mount_id(descriptor) == row['id'],
            'Owned top FD mount identifier differs')
    current = os.stat(TOP, follow_symlinks=False)
    require(stat.S_ISDIR(current.st_mode)
            and (mounted.st_dev, mounted.st_ino) == (current.st_dev, current.st_ino),
            'Owned top path changed after opening')
    source = Path(row['source']).resolve(strict=True)
    info = source.lstat()
    require(source.is_relative_to(Path('/dev')) and stat.S_ISBLK(info.st_mode), 'Wrong USB source node')
    node = (Path('/sys/dev/block') / f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}').resolve(strict=True)
    require(node.is_relative_to(Path('/sys/devices'))
            and usb_ancestor(node, bundle.profile['filesystem']['usb']) is not None
            and number(node / 'partition') == USB_STORAGE['partition_index']
            and number(node / 'start') * 512 == USB_STORAGE['partition_start_bytes']
            and number(node / 'size') * 512 == USB_STORAGE['partition_bytes']
            and number(node.parent / 'size') * 512 == USB_STORAGE['disk_bytes'], 'Wrong selected USB geometry/host')
    filesystem_identity(TOP, bundle.profile['filesystem']['uuid'])
    # The held FD and the path can name the same Btrfs inode through different
    # bind mounts. Recheck the mount identifier and posture after source/UUID
    # admission; inode equality alone does not bind that final mount view.
    final = [entry for entry in table() if entry['path'] == str(TOP)]
    require(len(final) == 1 and final[0] == row,
            'Owned top mount changed during identity admission')
  finally:
    os.close(descriptor)


def command_set(phase, maintenance, manifest):
  """Exact argv emitted by the reviewed core, with paths only from sealed data."""
  allowed = {('btrfs', 'subvolume', 'get-default', str(TOP)),
             ('btrfs', 'filesystem', 'sync', str(TOP))}
  if phase == 'layer': return frozenset(allowed)
  require(phase == 'packages', 'Unknown fixed worker phase')
  candidate = TOP / manifest['subvolumes']['root']
  for purpose, source in maintenance['original_subvolumes'].items():
    allowed.add(('btrfs', 'subvolume', 'show', str(TOP / source)))
    allowed.add(('btrfs', 'subvolume', 'snapshot', str(TOP / source),
                 str(TOP / manifest['subvolumes'][purpose])))
  allowed.add(('mount', '--bind', str(candidate), str(candidate)))
  mounts = [(TOP / manifest['subvolumes']['home'], 'home'),
            (TOP / manifest['subvolumes']['log'], 'var/log'),
            (Path('/dev'), 'dev'), (Path('/proc'), 'proc'),
            (Path('/sys'), 'sys'), (Path('/run'), 'run')]
  for source, relative in mounts:
    allowed.add(('mount', '--bind', str(source), str(candidate / relative)))
    allowed.add(('umount', str(candidate / relative)))
  allowed.add(('umount', str(candidate)))
  prefix = ('chroot', str(candidate), '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
            'HOME=/root', 'USER=root', 'LC_ALL=C')
  allowed.add(prefix + ('/bin/bash', '-c', FD_PROBE))
  for option in [('--init',), ('--populate', 'archlinuxarm')]:
    allowed.add(prefix + ('/usr/bin/pacman-key', '--gpgdir', '/etc/pacman.d/gnupg') + option)
  archives = tuple(str(PACKAGES / item['filename']) for item in manifest['packages'].values())
  allowed.add(('chroot', str(candidate), '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
    'HOME=/root', 'USER=root', 'LC_ALL=C', 'OMARCHY_ALLOW_DIRECT_PACMAN=1', '/usr/bin/pacman',
    '-U', '--disable-sandbox', '--noconfirm', '--ask=4') + archives)
  allowed.add(('chroot', str(candidate), '/usr/bin/pacman', '-Dk'))
  allowed.add(('chroot', str(candidate), '/usr/bin/gpgconf', '--homedir', '/etc/pacman.d/gnupg', '--kill', 'all'))
  for archive in archives: allowed.add(('/usr/bin/bsdtar', '-xOf', archive, '.PKGINFO'))
  return frozenset(allowed)


class Execute:
  """One fixed command at a time; uncertain outcomes bypass all Python finally."""

  def __init__(self, allowed, guard):
    self.allowed, self.guard = allowed, guard
    self.running = False
    self.attempted = 0

  def __call__(self, arguments):
    require(type(arguments) is list and all(type(x) is str for x in arguments)
            and tuple(arguments) in self.allowed and not self.running, 'Unowned/repeated overlapping command')
    self.guard()  # Only pre-spawn guard/admission refusal propagates normally.
    started = now()
    cutoff = min(started + 180 * SECOND, COMMAND_CUTOFF)
    require(0 < started < cutoff, 'No existing command allowance')
    program = arguments[0] if arguments[0] == '/usr/bin/bsdtar' else '/usr/bin/' + arguments[0]
    self.running = True
    self.attempted += 1
    status = None  # Only the original poll below can establish a child status.
    try:
      log = os.open(WORK / 'worker-command.log', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
      info = os.fstat(log)
      require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
              and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
              'Unowned private command log')
      os.ftruncate(log, 0)  # Prior command must already have positively reaped/EOF.
      process = subprocess.Popen([program, *arguments[1:]], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, start_new_session=True,
        close_fds=True, shell=False)
      os.set_blocking(process.stdout.fileno(), False)
      events = select.poll()
      events.register(process.stdout.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
      raw, eof, previous = bytearray(), False, started
      while True:
        timestamp = now()
        require(previous <= timestamp < cutoff, 'Command clock/deadline uncertain')
        previous = timestamp
        self.guard()
        if not eof:
          for _chunk in range(32):
            try: chunk = os.read(process.stdout.fileno(), 8192)
            except BlockingIOError: break
            if not chunk:
              eof = True; break
            require(len(raw) + len(chunk) <= MAX_OUTPUT, 'Command output exceeded private budget')
            raw.extend(chunk)
            cursor = 0
            while cursor < len(chunk):
              require(now() < cutoff, 'Command log deadline exceeded')
              count = os.write(log, chunk[cursor:])
              require(0 < count <= len(chunk) - cursor, 'Uncertain command log write')
              cursor += count
        status = process.poll()  # Sole Popen waiter; SIGCHLD disposition is default.
        require(status is None or status == 0, 'Command failed/signaled; descendants may still write')
        if status is not None and eof:
          require(process.wait(timeout=0) == 0, 'Command positive wait did not agree')
          break
        if eof: time.sleep(min(0.1, max(0, (cutoff - now()) / SECOND)))
        else: events.poll(min(100, max(0, (cutoff - now()) // 1_000_000)))
      process.stdout.close()
      os.fsync(log); os.close(log)
      require(now() < cutoff, 'Command finished outside original allowance')
      self.guard()
      result = bytes(raw).decode('ascii') if arguments[:3] == ['btrfs', 'subvolume', 'get-default'] else bytes(raw).decode('utf-8', errors='replace')
    except BaseException as error:
      worker_diagnostic('worker-command', error,
        command=(self.allowed, arguments, self.attempted, status))
      # No killpg, retries, or unwinding into the core's mount cleanup. PID1
      # observes master failure, kills its cgroup ONCE, and reaps descendants.
      os._exit(75)
    self.running = False
    return result


def result_file(value):
  raw = canonical(value)
  require(len(raw) <= 64 * 1024, 'Worker result exceeds private record budget')
  fd = os.open(WORK / 'RESULT.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  try:
    cursor = 0
    while cursor < len(raw):
      count = os.write(fd, raw[cursor:]); require(count > 0, 'Uncertain worker result write'); cursor += count
    os.fsync(fd)
  finally: os.close(fd)
  descriptor = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try: os.fsync(descriptor)
  finally: os.close(descriptor)


def run(bundle, job, guard, execute, plan):
  maintenance, manifest = plan.maintenance_data(), plan.manifest_data()
  guard(); top_identity(bundle, job)
  base_unchanged(TOP, maintenance)
  original = account_preimages(TOP / maintenance['original_subvolumes']['root'], maintenance['base_account_preimages'])
  require(default_subvolume(execute(['btrfs', 'subvolume', 'get-default', str(TOP)])) == plan.original_default,
          'Original default differs before work')
  candidate = TOP / manifest['subvolumes']['root']
  if bundle.phase == 'packages':
    directory(PACKAGES, private=True)
    require(filesystem_magic(PACKAGES) == 0x01021994, 'Package staging must remain private RAM')
    admit_payload(manifest, PACKAGES, execute=execute)
    core = update_candidate(maintenance, manifest, PACKAGES, TOP, guard_check=guard, execute=execute)
    require(core['state'] == 'VERIFIED' and core['boot_ready'] is False, 'Package core incomplete')
    require(account_preimages(candidate, maintenance['base_account_preimages']) == original,
            'Package candidate accounts changed')
    journal = TOP / '.shield-qualification' / manifest['candidate_id'] / 'state.json'
  else:
    receipt = predecessor(bundle, plan, 'predecessor', 'packages')
    a_journal = TOP / '.shield-qualification' / manifest['candidate_id'] / 'state.json'
    require(hashlib.sha256(owned_bytes(a_journal, 64 * 1024, 0o600)).hexdigest() == receipt['journal_sha256'],
            'Physical phase-A journal differs')
    guard()
    content = read_layer(bundle.input('layer')[0], plan.writer.layer)
    preimages = read_raw_input(bundle, 'preimages')
    paths = [candidate, TOP / manifest['subvolumes']['home'], TOP / '.shield-phase-B']
    descriptors = []
    try:
      for path in paths:
        descriptors.append(os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
      core = materialize(content, plan.writer, preimages, *descriptors, guard_check=guard)
    finally:
      for fd in descriptors: os.close(fd)
    require(core['state'] == 'LAYER_MATERIALIZED', 'Layer writer incomplete')
    journal = TOP / '.shield-phase-B' / manifest['candidate_id'] / 'MATERIALIZED.json'
  guard(); verify_root(manifest, candidate)
  base_unchanged(TOP, maintenance)
  require(account_preimages(TOP / maintenance['original_subvolumes']['root'], maintenance['base_account_preimages']) == original,
          'Original accounts changed during work')
  require(default_subvolume(execute(['btrfs', 'subvolume', 'get-default', str(TOP)])) == plan.original_default,
          'Original default changed during work')
  execute(['btrfs', 'filesystem', 'sync', str(TOP)])
  guard(); top_identity(bundle, job)
  raw = owned_bytes(journal, 64 * 1024, 0o600)
  observed = decode(raw)
  if bundle.phase == 'packages':
    require(observed == {'candidate_id': manifest['candidate_id'], 'state': 'VERIFIED',
      'phase': 'nested-mounts-relinquished', 'boot_ready': False}, 'Actual phase-A journal differs')
  else:
    require(observed == plain(core), 'Actual phase-B journal differs')
  value = {'format_version': 1, 'purpose': 'native maintenance worker result', 'phase': bundle.phase,
    'candidate_id': manifest['candidate_id'], 'filesystem_uuid': manifest['filesystem_uuid'],
    'payload_manifest_sha256': bundle.configuration['inputs']['payload']['sha256'],
    'plan_sha256': bundle.configuration['inputs']['plan']['sha256'], 'core_state': core['state'],
    'original_root_profile_preserved': True, 'original_default': plain(plan.original_default),
    'journal_sha256': hashlib.sha256(raw).hexdigest(), 'core': plain(core),
    'boot_ready': False, 'clean_usb_release': False, 'physical_powerloss_qualified': False}
  guard(); result_file(value); guard()
  return value


def main():
  require(sys.argv[1:] == ['--run'] and os.getpid() != 1
          and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
          'Fixed root maintenance worker required')
  bundle = load(epoch='early')
  directory(WORK, private=True)
  require(filesystem_magic(WORK) == 0x01021994, 'Private worker state must remain RAM')
  job = json_bytes(owned_bytes(WORK / 'job.json', 4096, 0o600))
  validate_job(job, bundle, os.getpid(), os.getppid())
  require(Path('/proc/self/cgroup').read_text() == '0::/shield-native-worker\n'
          and os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'), 'Worker ownership domain differs')
  reaper = peer(job['reaper_pid'], ['/usr/bin/python3.14', '-I', '-S', '-B',
    str(RUNTIME / 'native_worker_reaper.py'), '--run'])
  guardian = peer(job['guardian_pid'], [str(INSTALL / 'shield-guardian'), '--run'])
  work = WorkGuard(bundle, job['guardian_pid'], minimum_seconds=60)
  def guard(seconds=None):
    require(os.getppid() == job['reaper_pid'] and not select.select([reaper, guardian], [], [], 0)[0],
            'Maintenance parent/guardian lifetime lost')
    return work(seconds)
  try:
    guard(); plan = load_plan(bundle)
    execute = Execute(command_set(bundle.phase, plan.maintenance_data(), plan.manifest_data()), guard)
    run(bundle, job, guard, execute, plan)
  finally:
    work.close(); os.close(reaper); os.close(guardian)


if __name__ == '__main__':
  try: main()
  except BaseException as error:
    worker_diagnostic('worker-main', error)
    os._exit(75)
