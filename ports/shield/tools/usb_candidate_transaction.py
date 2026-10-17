"""Candidate-only transaction inside an already admitted Btrfs mount.

There is deliberately no device/mount CLI. The maintenance broker must own the
device, mount lease, finite hardware guard and host attempt journal first.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from usb_root_profile import (admit_payload, database_profile, digest, require,
                              rooted, validate_manifest, verify_root)


def run(command):
  return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def directory(path, mode=None):
  info = Path(path).lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0,
          'Expected root-owned real directory: ' + str(path))
  if mode is not None:
    require(stat.S_IMODE(info.st_mode) == mode, 'Wrong owned directory mode')


def mount_destination(candidate, relative):
  # Package paths forbid virtual trees. These six mountpoints have a separate,
  # fixed authority; check every component without following symlink parents.
  require(relative in {'home', 'var/log', 'dev', 'proc', 'sys', 'run'}, 'Unowned mount destination')
  destination = Path(candidate)
  directory(destination)
  for part in relative.split('/'):
    destination /= part
    directory(destination)
  return destination


class Journal:
  def __init__(self, top, candidate):
    top = Path(top)
    directory(top)
    parent = top / '.shield-qualification'
    if not parent.exists() and not parent.is_symlink():
      parent.mkdir(mode=0o700)
      self.sync_directory(top)
    directory(parent, 0o700)
    self.path = parent / candidate
    # Existing state is an uncertain/previous attempt, never an automatic retry.
    self.path.mkdir(mode=0o700)
    self.sync_directory(parent)
    self.candidate = candidate
    self.record('INCOMPLETE', phase='admitted')

  @staticmethod
  def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
      os.fsync(fd)
    finally:
      os.close(fd)

  def record(self, state, **details):
    data = json.dumps({'candidate_id': self.candidate, 'state': state, **details}, sort_keys=True).encode() + b'\n'
    temporary = self.path / 'state.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
      with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
      os.replace(temporary, self.path / 'state.json')
      self.sync_directory(self.path)
    except BaseException:
      # Preserve any partial temporary data and the prior durable state.
      raise


def validate_plan(plan, manifest):
  validate_manifest(manifest)
  require(plan['format_version'] == 1 and plan['candidate_id'] == manifest['candidate_id'], 'Wrong execution plan')
  require(plan['filesystem_uuid'] == manifest['filesystem_uuid'], 'Plan/filesystem identity differs')
  canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
  require(hashlib.sha256(canonical).hexdigest() == plan['payload_canonical_sha256'], 'Plan/payload manifest differs')
  require(set(plan['original_subvolumes']) == {'root', 'home', 'log'}, 'Incomplete original root set')
  require(plan['original_subvolumes'] == {'root': '@', 'home': '@home', 'log': '@log'}, 'Wrong original root set')
  require(isinstance(plan['minimum_free_bytes'], int) and plan['minimum_free_bytes'] >= 3 * 1024**3,
          'Insufficient candidate capacity reservation')
  require(bool(plan['base_database']) and bool(plan['base_files']), 'Missing pinned original root profile')
  return plan


def base_unchanged(top, plan):
  root = rooted(top, plan['original_subvolumes']['root'])
  require(database_profile(root) == plan['base_database'], 'Original USB package database changed')
  for name, expected in plan['base_files'].items():
    path = rooted(root, name)
    require(path.is_file() and not path.is_symlink() and digest(path) == expected, 'Original bootstrap file changed: ' + name)


def default_subvolume(output):
  # Btrfs snapshots can advance the source root's generation without changing
  # the default selection. Bind the selection identity, not that transaction ID.
  if output == 'ID 5 (FS_TREE)\n':
    return {'id': 5, 'top_level': None, 'path': None}
  match = re.fullmatch(r'ID ([0-9]+) gen ([0-9]+) top level ([0-9]+) path ([^\n]+)\n', output)
  require(match is not None, 'Unrecognized Btrfs default-subvolume output')
  return {'id': int(match[1]), 'top_level': int(match[3]), 'path': match[4]}


def update_candidate(plan, manifest, payload, top, *, guard_check, execute=run):
  """Update fresh snapshots; return only after verified nested mount cleanup.

  The caller retains the top-level mount lease. A VERIFIED transaction is not a
  clean-unmount or boot-admission receipt. The broker must subsequently sync,
  unmount the filesystem and independently verify relinquishment.
  """
  require(os.geteuid() == 0, 'Candidate transaction requires root')
  validate_plan(plan, manifest)
  admit_payload(manifest, payload)
  top, payload = Path(top).resolve(strict=True), Path(payload).resolve(strict=True)
  directory(top)
  # This must fail before any durable journal/snapshot effect.
  require(payload.is_relative_to(Path('/run')), 'Live payload must reside under the broker RAM /run')
  guard_check(180)
  for value in manifest['subvolumes'].values():
    require(not (top / value).exists() and not (top / value).is_symlink(), 'Candidate already exists; no replay')
  base_unchanged(top, plan)
  space = os.statvfs(top)
  require(space.f_bavail * space.f_frsize >= plan['minimum_free_bytes'], 'Insufficient filesystem free space')
  default = default_subvolume(execute(['btrfs', 'subvolume', 'get-default', str(top)]))
  for value in plan['original_subvolumes'].values():
    directory(rooted(top, value))
    execute(['btrfs', 'subvolume', 'show', str(top / value)])
  journal = Journal(top, manifest['candidate_id'])
  mounted = []
  candidate = top / manifest['subvolumes']['root']
  success = False
  cleanup_errors = []
  keyring_started = False
  try:
    for purpose, source in plan['original_subvolumes'].items():
      guard_check(150)
      execute(['btrfs', 'subvolume', 'snapshot', str(top / source), str(top / manifest['subvolumes'][purpose])])
      journal.record('INCOMPLETE', phase='snapshot-' + purpose)
    # Give chroot's mount-table view an actual root mount. Without this bind,
    # ALPM cannot identify '/' for its normal disk-space checks.
    directory(candidate)
    execute(['mount', '--bind', str(candidate), str(candidate)])
    mounted.append(candidate)
    for source, relative in [(top / manifest['subvolumes']['home'], 'home'),
                             (top / manifest['subvolumes']['log'], 'var/log'),
                             (Path('/dev'), 'dev'), (Path('/proc'), 'proc'),
                             (Path('/sys'), 'sys'), (Path('/run'), 'run')]:
      destination = mount_destination(candidate, relative)
      # Nonrecursive bindings deliberately omit the top-level mount under /run.
      execute(['mount', '--bind', str(source), str(destination)])
      mounted.append(destination)
    guard_check(120)
    execute(['chroot', str(candidate), '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
             'HOME=/root', 'USER=root', 'LC_ALL=C', '/bin/bash', '-c',
             'IFS= read -r value < <(/usr/bin/printf "%s\\n" shield-fd-ready) && [[ $value == shield-fd-ready ]]'])
    # The original image deliberately carries no initialized private keyring.
    # Bootstrap only this fresh snapshot from its admitted distribution keys;
    # never copy a host secret key or weaken signed dependency validation.
    journal.record('INCOMPLETE', phase='candidate-keyring-bootstrap')
    keyring_started = True
    for arguments in [['--init'], ['--populate', 'archlinuxarm']]:
      execute(['chroot', str(candidate), '/usr/bin/env', '-i',
               'PATH=/usr/bin:/bin', 'HOME=/root', 'USER=root', 'LC_ALL=C',
               '/usr/bin/pacman-key', '--gpgdir', '/etc/pacman.d/gnupg', *arguments])
    guard_check(120)
    # The payload must be staged in RAM /run by the broker, visible in the bind.
    archives = [str(payload / item['filename']) for item in manifest['packages'].values()]
    journal.record('INCOMPLETE', phase='package-transaction')
    execute(['chroot', str(candidate), '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
             'HOME=/root', 'USER=root', 'LC_ALL=C', 'OMARCHY_ALLOW_DIRECT_PACMAN=1',
             '/usr/bin/pacman', '-U', '--disable-sandbox', '--noconfirm', '--ask=4', *archives])
    guard_check(90)
    execute(['chroot', str(candidate), '/usr/bin/pacman', '-Dk'])
    verify_root(manifest, candidate)
    # Bootstrap and the original root must remain unchanged through scriptlets.
    base_unchanged(top, plan)
    require(default_subvolume(execute(['btrfs', 'subvolume', 'get-default', str(top)])) == default,
            'Default subvolume changed')
    journal.record('INCOMPLETE', phase='installed-payload-verified')
    execute(['btrfs', 'filesystem', 'sync', str(top)])
    success = True
  finally:
    if keyring_started:
      try:
        execute(['chroot', str(candidate), '/usr/bin/gpgconf',
                 '--homedir', '/etc/pacman.d/gnupg', '--kill', 'all'])
      except BaseException as error:
        cleanup_errors.append(type(error).__name__ + ':candidate-keyring-agents')
    for destination in reversed(mounted):
      try:
        execute(['umount', str(destination)])
      except BaseException as error:
        cleanup_errors.append(type(error).__name__ + ':' + str(destination))
    if cleanup_errors:
      journal.record('INCOMPLETE', phase='owned-cleanup-failed', errors=cleanup_errors)
    elif success:
      guard_check(45)
      journal.record('VERIFIED', phase='nested-mounts-relinquished', boot_ready=False)
      try:
        execute(['btrfs', 'filesystem', 'sync', str(top)])
      except BaseException:
        journal.record('INCOMPLETE', phase='final-sync-failed')
        raise
  require(not cleanup_errors, 'Owned keyring or mount cleanup failed')
  require(success, 'Candidate transaction incomplete')
  return {'candidate_id': manifest['candidate_id'], 'state': 'VERIFIED',
          'top_level_clean_unmount_verified': False, 'boot_ready': False,
          'original_default_unchanged': True}
