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

sys.path.insert(0, '/run/shield-native/runtime')
sys.path.insert(1, '/usr/lib/omarchy/shield/qualification')

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
  mounted = os.stat(TOP)
  require(row['dev'] == f'{os.major(mounted.st_dev)}:{os.minor(mounted.st_dev)}',
          'Mount table differs from actual Btrfs view')
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

  def __call__(self, arguments):
    require(type(arguments) is list and all(type(x) is str for x in arguments)
            and tuple(arguments) in self.allowed and not self.running, 'Unowned/repeated overlapping command')
    self.guard()  # Only pre-spawn guard/admission refusal propagates normally.
    started = now()
    cutoff = min(started + 180 * SECOND, COMMAND_CUTOFF)
    require(0 < started < cutoff, 'No existing command allowance')
    program = arguments[0] if arguments[0] == '/usr/bin/bsdtar' else '/usr/bin/' + arguments[0]
    self.running = True
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
    except BaseException:
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
  except BaseException: os._exit(75)
