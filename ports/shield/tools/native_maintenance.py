"""Actual RAM PID1 orchestration for the two finite USB preparation boots.

Only the stopped, assigned worker may run the package/layer transaction. Its
result is accepted after its subreaper's positive wait, EOF, ECHILD report and
actual empty leaf. A retained release fence is still not proof of recovery.
This source cohort is unqualified until its real capsule and host controller
have been reviewed and tested with all of these consumers.
"""
import hashlib
import os
from pathlib import Path
import select
import subprocess

from guardian_binding import INSTALL
from maintenance_accounts import ACCOUNT_NAMES, account_preimages
from native_boot_context import directory, owned_bytes, plain
from native_layer_reader import read_layer
from native_layer_writer import Roots, admit, observe, validate_accounts
from native_mounts import TOP
from native_phase_plan import canonical, decode, predecessor, read_raw_input
from native_ram_recovery import Recovery
from native_serial_link import SECOND, now
from native_work_guard import WorkGuard
from native_worker_reaper import LEAF, WORK, WorkerLeaf
from usb_candidate_transaction import base_unchanged, default_subvolume
from usb_root_profile import require


def exclusive(path, raw):
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  try:
    os.fchmod(fd, 0o600)
    require(os.write(fd, raw) == len(raw), 'Incomplete RAM job write; never replay')
    os.fsync(fd)
  finally: os.close(fd)
  parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try: os.fsync(parent)
  finally: os.close(parent)


class Maintenance:
  def __init__(self, supervisor, plan):
    self.s, self.plan, self.bundle = supervisor, plan, supervisor.bundle
    require(os.getpid() == 1 and self.bundle.phase in {'packages', 'layer'}
            and self.bundle.profile['role'] == 1, 'Only maintenance RAM PID1')
    self.recovery = Recovery(self.bundle)  # Listener exists before guardian.
    self.events = select.epoll()
    self.events.register(self.s.events.fileno(), select.EPOLLIN)
    self.events.register(self.recovery.listener.fileno(), select.EPOLLIN)
    self.guardian = self.reaper = self.leaf = self.work_guard = None
    self.group_event = None
    self.failed = self.stop_attempted = self.abort_attempted = False
    self.quiesce_attempted = False
    self.dispatch_attempted = self.event_fault = False
    self.detached_tty = None
    self.ready_record = self.complete = None
    self.release_challenge = None
    self.release_transferred = self.release_confirmed = False
    self.previous = now()
    self.result_sha = self.journal_sha = None
    self.original_preserved = False

  def budget(self, cutoff):
    timestamp = now()
    require(0 < self.previous <= timestamp < cutoff <= 600 * SECOND,
            'Maintenance existing deadline exhausted/regressed')
    self.previous = timestamp
    return timestamp

  def live(self):
    self.budget(540 * SECOND)
    require(not self.failed and not self.s.aborted and not self.s.children.interrupted
            and not self.s.children.unexpected_statuses and self.recovery.reason is None,
            'Maintenance work interrupted')
    require(self.s.link is not None and self.s.link.ready
            and self.s.link.last_host_ns is not None
            and now() - self.s.link.last_host_ns < 15 * SECOND,
            'Authenticated maintenance host became stale')
    if self.work_guard is not None: self.work_guard()

  def guard(self):
    self.pump(0)
    self.live()

  def base_events(self):
    try: self.s.pump(0)
    except (OSError, ValueError):
      # A transport failure cannot prevent the independent cleanup path.
      # Keep the existing deadline, poison work and never reopen the tty.
      self.failed = True
      self.event_fault = True
      if self.s.tty is not None:
        try: self.s.events.unregister(self.s.tty)
        except OSError: pass
        # gs_close can block for 15s. Do not delay writer cancellation by
        # closing this failed control endpoint. Retain the owned fd until the
        # existing finite recovery policy ends this failed boot; never reopen.
        self.detached_tty = self.s.tty
        self.s.tty = self.s.link = None

  def pump(self, timeout):
    self.budget(600 * SECOND)
    # Also arms EPOLLOUT for newly queued evidence and services link timers.
    # Waiting solely on nested epoll readiness would strand a new TX queue.
    self.base_events()
    for fd, flags in self.events.poll(timeout):
      if fd == self.s.events.fileno(): self.base_events()
      elif fd == self.recovery.listener.fileno():
        require(self.guardian is not None, 'Unexpected pre-owner recovery connection')
        if self.recovery.accept(self.guardian):
          self.events.unregister(fd)
          self.events.register(self.recovery.channel.fileno(),
                               select.EPOLLIN | select.EPOLLHUP | select.EPOLLERR)
      elif self.group_event is not None and fd == self.group_event:
        os.lseek(fd, 0, os.SEEK_SET)
        require(len(os.read(fd, 4097)) <= 4096, 'Oversized worker population event')
      else:
        require(self.recovery.channel is not None and fd == self.recovery.channel.fileno(),
                'Unknown maintenance event owner')
        self.recovery.receive()
        if self.recovery.channel_eof: self.events.unregister(fd)
    if self.recovery.pending_owner_loss: self.recovery.poll_owner_loss()
    if self.reaper is not None:
      for record in self.reaper.take_records(): self.worker_record(record)
    for event in self.s.take_control_events():
      if event.kind == 'abort': self.failed = True
      if self.release_challenge is not None and event.challenge == self.release_challenge:
        if event.kind == 'evidence-transferred': self.release_transferred = True
        if event.kind == 'pong-transferred':
          require(self.release_transferred and now() < self.recovery.deadline,
                  'Late/untransferred maintenance retention fence')
          self.release_confirmed = True

  def worker_record(self, value):
    require(type(value) is dict, 'Wrong private reaper record')
    kind = value.get('kind')
    if kind == 'reaper-ready':
      require(self.ready_record is None and self.complete is None and set(value) == {
        'kind', 'leader_pid', 'worker_stopped_in_leaf'}
        and type(value['leader_pid']) is int and value['leader_pid'] > 1
        and value['worker_stopped_in_leaf'] is True, 'Wrong/repeated reaper readiness')
      self.ready_record = value
    elif kind == 'reaper-stop-requested':
      require(set(value) == {'kind', 'leader_pid'} and self.ready_record is not None
              and value['leader_pid'] == self.ready_record['leader_pid'], 'Wrong reaper stop request')
      self.stop_worker()
    else:
      require(kind == 'reaper-complete' and self.complete is None and set(value) == {
        'kind', 'leader_pid', 'leader_exit', 'started', 'reaped_statuses',
        'no_remaining_children', 'leaf_empty', 'phase_failed', 'finished_ns'}
        and self.ready_record is not None and value['leader_pid'] == self.ready_record['leader_pid']
        and type(value['leader_exit']) is int and type(value['reaped_statuses']) is int
        and value['reaped_statuses'] >= 1
        and all(type(value[key]) is bool for key in ['started', 'phase_failed'])
        and value['no_remaining_children'] is True and value['leaf_empty'] is True
        and type(value['finished_ns']) is int and 0 < value['finished_ns'] <= now() < 600 * SECOND,
        'Wrong or unowned reaper completion')
      self.complete = value

  def stop_worker(self):
    if self.stop_attempted: return
    self.stop_attempted = True
    require(self.leaf is not None and self.reaper is not None, 'No owned worker to stop')
    self.leaf.kill_once()
    # The reaper can prove ECHILD/empty and exit between its stop request and
    # this notification. Never replay T; its delivery is not the resource proof.
    try: self.s.children.reaper_command(b'T')
    except (OSError, ValueError): pass

  def abort(self):
    self.failed = True
    try:
      if self.reaper is not None: self.stop_worker()
    finally:
      # A failed one-attempt leaf kill must not suppress the independent
      # guardian abort. Neither operation retries or proves resource closure.
      if not self.abort_attempted:
        self.abort_attempted = True
        require(self.recovery.client.owner_pid == self.guardian.pid, 'Abort owner not admitted')
        self.recovery.client.abort()  # Owned guardian validates all identities.

  def original_default(self, check):
    check()
    process = subprocess.Popen(['/usr/bin/btrfs', 'subvolume', 'get-default', str(TOP)],
      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
      env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'})
    try: raw, _unused = process.communicate(timeout=3)
    except subprocess.TimeoutExpired:
      process.kill()
      try: process.wait(timeout=0.5)
      except subprocess.TimeoutExpired: pass
      raise
    check()
    require(process.returncode == 0 and len(raw) <= 4096, 'Original default query failed')
    return default_subvolume(raw.decode('ascii'))

  def original(self, check):
    check()
    maintenance = self.plan.maintenance_data()
    base_unchanged(TOP, maintenance)
    account_preimages(TOP / maintenance['original_subvolumes']['root'], maintenance['base_account_preimages'])
    require(self.original_default(check) == self.plan.original_default, 'Original default changed')
    check()

  def preflight(self):
    self.original(self.guard)
    manifest = self.plan.manifest_data()
    if self.bundle.phase == 'packages':
      for relative in list(manifest['subvolumes'].values()) + [
          '.shield-qualification/' + manifest['candidate_id'], '.shield-phase-B/' + manifest['candidate_id']]:
        path = TOP / relative
        require(not path.exists() and not path.is_symlink(), 'Existing native attempt cannot replay')
      space = os.statvfs(TOP)
      require(space.f_bavail * space.f_frsize >= self.plan.maintenance['minimum_free_bytes'],
              'Insufficient physical candidate capacity')
      return
    previous = predecessor(self.bundle, self.plan, 'predecessor', 'packages')
    journal = TOP / '.shield-qualification' / manifest['candidate_id'] / 'state.json'
    require(hashlib.sha256(owned_bytes(journal, 64 * 1024, 0o600)).hexdigest() == previous['journal_sha256'],
            'Physical package journal differs from recovered predecessor')
    target = TOP / '.shield-phase-B' / manifest['candidate_id']
    require(not target.exists() and not target.is_symlink(), 'Existing layer attempt cannot replay')
    content = read_layer(self.bundle.input('layer')[0], self.plan.writer.layer)
    expected, entries = admit(content, self.plan.writer, read_raw_input(self.bundle, 'preimages'))
    descriptors = []
    try:
      for scope in ['root', 'home']:
        descriptors.append(os.open(TOP / manifest['subvolumes'][scope],
          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
      roots = Roots(*descriptors, self.guard)
      try:
        for scope in ['root', 'home']:
          require(observe(roots.fds[scope], None, self.guard) == expected['roots'][scope],
                  'Expected-A root metadata differs before RW')
        before, after = {}, {}
        for name in sorted(entries):
          if name in ACCOUNT_NAMES:
            actual, before[name] = roots.observe(name, data=True)
            after[name] = bytes(content.blob(entries[name]['identity']['sha256']))
          else: actual = roots.observe(name)
          require(actual == expected['entries'][name], 'Expected-A physical preimage differs before RW')
        validate_accounts(before, after)
      finally: roots.close()
    finally:
      for fd in descriptors: os.close(fd)

  def start_worker(self):
    self.guard()
    require(now() < 110 * SECOND, 'No existing reaper startup allowance')
    self.work_guard(180)
    self.s.mounts.maintenance_rw(115 * SECOND)
    if self.bundle.phase == 'packages': self.s.mounts.declare_worker_bindings(self.plan.manifest_data())
    else:
      parent = TOP / '.shield-phase-B'
      if not parent.exists() and not parent.is_symlink(): parent.mkdir(mode=0o700)
      directory(parent, private=True)
    WORK.mkdir(mode=0o700); directory(WORK, private=True)
    LEAF.mkdir(mode=0o700); os.chmod(LEAF, 0o700)
    self.leaf = WorkerLeaf()
    self.group_event = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=self.leaf.fd)
    os.read(self.group_event, 4097)
    self.events.register(self.group_event, select.EPOLLPRI | select.EPOLLERR)
    self.reaper = self.s.spawn('reaper')
    while self.ready_record is None:
      self.guard(); self.budget(120 * SECOND)
      require(not self.reaper.reaped, 'Reaper exited before owned assignment')
      self.pump(0.1)
    leader = self.ready_record['leader_pid']
    require(self.leaf.procs() == {leader}
            and Path('/proc/' + str(leader) + '/cgroup').read_text() == '0::/shield-native-worker\n',
            'Stopped worker not exclusively assigned')
    status = dict(row.split(':', 1) for row in Path('/proc/' + str(leader) + '/status').read_text().splitlines())
    require(status['PPid'].strip() == str(self.reaper.pid) and status['State'].strip().startswith('T'),
            'Worker is not the owned stopped reaper child')
    context = self.bundle.contexts['early']
    job = {'format_version': 1, 'purpose': 'native maintenance worker', 'phase': self.bundle.phase,
      'guardian_pid': self.guardian.pid, 'reaper_pid': self.reaper.pid, 'worker_pid': leader,
      'candidate': self.bundle.profile['candidate'], 'boot_id': self.bundle.boot_id,
      'configuration_sha256': context.config_sha256, 'session_id': context.session_id,
      'top_mount_id': self.s.mounts.mounted[TOP][0]}
    exclusive(WORK / 'job.json', canonical(job))
    self.guard(); self.work_guard(180)
    self.s.children.reaper_command(b'S')

  def collect(self):
    while not (self.reaper.reaped and self.reaper.eof):
      try: self.live()
      except (OSError, ValueError):
        try: self.abort()
        except (OSError, ValueError): self.failed = True
      cutoff = self.recovery.deadline or 600 * SECOND
      self.budget(cutoff)
      self.pump(0.2)
    require(self.reaper.success and self.complete is not None and self.leaf.empty()
            and not self.leaf.procs() and not self.s.children.unexpected_statuses and not self.event_fault,
            'Actual worker/reaper resource closure not established')
    self.s.retire('reaper')
    passed = not self.failed and self.complete['started'] and self.complete['leader_exit'] == 0 \
             and not self.complete['phase_failed']
    if passed:
      raw = owned_bytes(WORK / 'RESULT.json', 64 * 1024, 0o600)
      result = decode(raw)
      require(set(result) == {'format_version', 'purpose', 'phase', 'candidate_id', 'filesystem_uuid',
        'payload_manifest_sha256', 'plan_sha256', 'core_state', 'original_root_profile_preserved',
        'original_default', 'journal_sha256', 'core', 'boot_ready', 'clean_usb_release',
        'physical_powerloss_qualified'} and type(result['format_version']) is int
        and result['format_version'] == 1 and result['purpose'] == 'native maintenance worker result'
        and result['phase'] == self.bundle.phase
        and result['candidate_id'] == self.plan.manifest['candidate_id']
        and result['filesystem_uuid'] == self.plan.manifest['filesystem_uuid']
        and result['original_default'] == self.plan.original_default
        and result['original_root_profile_preserved'] is True
        and all(result[key] is False for key in ['boot_ready', 'clean_usb_release', 'physical_powerloss_qualified'])
        and result['core_state'] == ('VERIFIED' if self.bundle.phase == 'packages' else 'LAYER_MATERIALIZED')
        and result['plan_sha256'] == self.bundle.configuration['inputs']['plan']['sha256'],
        'Worker result scope differs')
      require(result['payload_manifest_sha256'] == self.bundle.configuration['inputs']['payload']['sha256'],
              'Worker payload result differs')
      relative = ('.shield-qualification/' if self.bundle.phase == 'packages' else '.shield-phase-B/')
      relative += result['candidate_id'] + ('/state.json' if self.bundle.phase == 'packages' else '/MATERIALIZED.json')
      journal = owned_bytes(TOP / relative, 64 * 1024, 0o600)
      require(hashlib.sha256(journal).hexdigest() == result['journal_sha256'], 'Actual completed journal differs')
      self.result_sha, self.journal_sha = hashlib.sha256(raw).hexdigest(), result['journal_sha256']
    return passed

  def cleanup_guard(self):
    self.pump(0)
    require(self.recovery.deadline is not None and self.recovery.reason is not None
            and not self.recovery.pending_owner_loss, 'Owned cleanup cutoff/cause not established')
    self.budget(self.recovery.deadline)

  def release(self, passed):
    if self.recovery.reason is None:
      self.quiesce_attempted = True
      status = self.recovery.client.quiesce()
      require(self.recovery.client.owner_pid == self.guardian.pid, 'Quiesce owner changed')
      self.recovery.deadline = min(self.recovery.deadline or 600 * SECOND, status['cleanup_cutoff_ns'])
    while self.recovery.reason is None or self.recovery.pending_owner_loss:
      self.budget(self.recovery.deadline or 600 * SECOND)
      self.pump(0.1)
    self.original(self.cleanup_guard)
    self.original_preserved = True
    self.cleanup_guard()
    self.s.mounts.release(self.recovery.deadline)
    self.cleanup_guard()
    require(self.leaf.empty() and not self.leaf.procs() and not self.s.children.unexpected_statuses,
            'Worker aliases reappeared after USB release')
    require(self.s.link is not None and self.s.link.ready, 'No authenticated release consumer')
    observation = {'kind': 'maintenance-released', 'phase': self.bundle.phase,
      'candidate_id': self.plan.manifest['candidate_id'], 'filesystem_uuid': self.plan.manifest['filesystem_uuid'],
      'payload_manifest_sha256': self.bundle.configuration['inputs']['payload']['sha256'],
      'plan_sha256': self.bundle.configuration['inputs']['plan']['sha256'],
      'worker_result_sha256': self.result_sha, 'journal_sha256': self.journal_sha,
      'original_default': plain(self.plan.original_default), 'original_root_profile_preserved': True,
      'phase_passed': passed, 'worker_started': self.complete['started'], 'worker_reaped': True,
      'reaper_reaped': True, 'worker_leaf_empty': True, 'filesystem_unmounted': True,
      'partition_ro': True, 'disk_ro': True, 'internal_user_ro': True,
      'cleanup_deadline_ns': self.recovery.deadline, 'boottime_ns': now(),
      'nonce': os.urandom(32).hex(), 'boot_ready': False, 'physical_powerloss_qualified': False}
    self.release_challenge = self.s.link.evidence(observation, purpose='maintenance')
    while not self.release_confirmed:
      self.cleanup_guard()
      self.pump(0.1)
    self.cleanup_guard()
    require(not self.event_fault and not self.s.children.unexpected_statuses
            and self.s.link is not None and self.release_confirmed,
            'Release control/source fault after retention; recovery dispatch forbidden')
    require(now() + SECOND < self.recovery.deadline, 'No existing recovery dispatch reserve')
    helper = INSTALL / 'shield-restart-recovery'
    require(hashlib.sha256(owned_bytes(helper, self.bundle.profile['recovery_helper']['bytes'], 0o700)).hexdigest()
            == self.bundle.profile['recovery_helper']['sha256'], 'Recovery helper changed')
    self.dispatch_attempted = True
    self.s.spawn('restart-recovery')
    # A return is never called recovery. Only the host may observe secure SOS.
    raise ValueError('Recovery dispatch returned to native PID1')

  def run(self):
    self.s.stage = 'maintenance-internal-ro'
    self.s.helper('internal-ro')
    self.s.transport()
    self.guardian = self.s.spawn('guardian')
    while not self.recovery.ready_received:
      self.budget(110 * SECOND)
      require(not self.guardian.reaped and self.recovery.reason is None, 'Guardian failed before work')
      self.pump(0.1)
    self.recovery.status()  # Bind the separate cleanup client before any effect.
    self.work_guard = WorkGuard(self.bundle, self.guardian.pid, minimum_seconds=60)
    self.guard(); self.work_guard(180)
    self.s.storage()
    self.s.mounts.readonly_top(110 * SECOND)
    self.s.stage = 'maintenance-preflight'
    self.preflight()
    self.s.stage = 'maintenance-worker'
    self.start_worker()
    passed = self.collect()
    self.s.stage = 'maintenance-release'
    self.release(passed)


def run(supervisor, plan):
  owner = Maintenance(supervisor, plan)
  try: owner.run()
  except BaseException:
    # Stop an actual assigned tree even if post-fork parent admission failed.
    # Missing positive resource proof still forbids release/helper/replay.
    if owner.guardian is not None and not owner.dispatch_attempted:
      try:
        if owner.recovery.guard is not None and owner.recovery.client.owner_pid is None:
          owner.recovery.status()
        owner.abort()
      except (OSError, ValueError): pass
    raise
