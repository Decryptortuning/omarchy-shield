"""Fixed initial-RAM USB mount domain; never selects a default boot root.

PID1 owns the initial namespace and every actor which can create a child mount.
The maintenance worker may create its reviewed nested mounts ONLY inside TOP.
Before cleanup the supervisor must positively reap that worker tree. Blocking
mount/sync/unmount I/O is not cancellable by these software deadline checks.
"""
import ctypes
import os
from pathlib import Path
import stat
import time

from native_boot_context import directory, filesystem_magic
from qualification_recovery import filesystem_identity, mounts as parse_mounts
from usb_root_profile import require

TOP = Path('/run/shield-usb')
# switch_root moves /run into the new root. Putting NEWROOT under /run would
# attempt to move a parent mount into its own descendant. Keep it on rootfs.
NEWROOT = Path('/newroot')
SECOND = 1_000_000_000
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_RELATIME = 1, 2, 4, 8, 1 << 21


def now(): return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def table(): return parse_mounts(Path('/proc/self/mountinfo').read_text())


class MountDomain:
  def __init__(self, device):
    require(os.getpid() == 1 and device.bundle.epoch == 'early'
            and os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'),
            'Mount domain requires initial RAM PID1')
    device.require_unmounted()
    self.device = device
    self.bundle = device.bundle
    self.targets = {}
    self.mounted = {}
    self.attempts = set()
    self.failed = False
    self.release_attempted = False
    self.worker_bindings = None
    self.library = ctypes.CDLL(None, use_errno=True)
    self.library.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_ulong, ctypes.c_void_p]
    self.library.mount.restype = ctypes.c_int
    self.library.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    self.library.umount2.restype = ctypes.c_int
    self.library.syncfs.argtypes = [ctypes.c_int]
    self.library.syncfs.restype = ctypes.c_int

  def budget(self, deadline):
    require(type(deadline) is int and 0 < now() < deadline <= 600 * SECOND,
            'Mount operation outside existing deadline')

  def new_target(self, path):
    require(path in {TOP, NEWROOT} and path not in self.targets, 'Unknown/repeated RAM mount target')
    directory(path.parent)
    path.mkdir(mode=0o700)  # Existing targets are never adopted/replaced.
    directory(path, private=True)
    require(filesystem_magic(path) in {0x01021994, 0x858458f6}, 'Mount target must be RAM rootfs/tmpfs')
    info = path.lstat()
    self.targets[path] = (info.st_dev, info.st_ino)

  def _mount(self, path, subvolume, readonly, deadline):
    require(not self.failed and not self.release_attempted and path not in self.mounted,
            'Mount domain unavailable')
    attempt = (path, readonly)
    require(attempt not in self.attempts, 'Mount attempt cannot replay')
    self.attempts.add(attempt)
    try:
      self.budget(deadline)
      self.device.check()
      directory(path)
      flags = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC if readonly else MS_RELATIME
      if path in {TOP, NEWROOT / 'home'} and not readonly: flags |= MS_NOSUID | MS_NODEV
      options = 'subvolid=5' if subvolume is None else 'subvol=' + subvolume
      options += ',rescue=nologreplay' if readonly else ',compress=zstd:1'
      source = '/dev/' + self.device.partition.name
      data = ctypes.create_string_buffer(options.encode('ascii'))
      require(self.library.mount(os.fsencode(source), os.fsencode(path), b'btrfs',
                                  flags, ctypes.cast(data, ctypes.c_void_p)) == 0,
              'Owned Btrfs mount refused; no replay')
      self.budget(deadline)
      matches = [entry for entry in table() if entry['path'] == str(path)]
      require(len(matches) == 1, 'Owned mount identity is ambiguous')
      entry = matches[0]
      require(entry['filesystem'] == 'btrfs'
              and entry['root'] == ('/' if subvolume is None else '/' + subvolume),
              'Mounted Btrfs root differs')
      self._validate(entry, readonly)
      self.mounted[path] = (entry['id'], readonly)
      self.check()
    except BaseException:
      self.failed = True
      raise

  def _validate(self, entry, readonly):
    access = 'ro' if readonly else 'rw'
    require(access in entry['options'] and access in entry['super_options'], 'Btrfs access differs')
    if entry['path'] == str(TOP):
      expected = {'nosuid', 'nodev'} | ({'noexec'} if readonly else set())
      actual = entry['options'] & {'nosuid', 'nodev', 'noexec'}
      require(actual == expected, 'Owned top mount execution/device flags differ')
    elif entry['path'] == str(NEWROOT / 'home'):
      expected = {'nosuid', 'nodev'} | ({'noexec'} if readonly else set())
      require(entry['options'] & {'nosuid', 'nodev', 'noexec'} == expected,
              'Runtime home must retain nosuid,nodev and execution')
    elif entry['path'] in {str(NEWROOT), str(NEWROOT / 'var/log')}:
      require(not entry['options'] & {'nosuid', 'nodev', 'noexec'},
              'Normal candidate mount execution/device flags differ')
    rescue = {option for option in entry['super_options'] if option.startswith('rescue=')}
    require(rescue == ({'rescue=nologreplay'} if readonly else set()), 'Btrfs replay posture differs')
    if not readonly:
      require('compress=zstd:1' in entry['super_options'], 'Matched Btrfs compression differs')
    source = Path(entry['source']).resolve(strict=True)
    info = source.lstat()
    require(source.is_relative_to(Path('/dev')) and stat.S_ISBLK(info.st_mode)
            and info.st_rdev == self.device.identities[1][2], 'Mounted Btrfs source differs')
    filesystem_identity(entry['path'], self.bundle.profile['filesystem']['uuid'])

  def check(self):
    self.device.check()
    entries = [entry for entry in table() if entry['filesystem'] == 'btrfs']
    for path, (identity, readonly) in self.mounted.items():
      matches = [entry for entry in entries if entry['path'] == str(path)]
      require(len(matches) == 1 and matches[0]['id'] == identity, 'Owned mount was replaced')
      self._validate(matches[0], readonly)
    for entry in entries:
      if Path(entry['path']) not in self.mounted:
        self._worker_binding(entry)

  def declare_worker_bindings(self, manifest):
    """Exact seven nonrecursive bindings emitted by the fixed package core."""
    require(self.bundle.phase == 'packages' and self.worker_bindings is None
            and self.mounted.get(TOP, (None, None))[1] is False,
            'Worker mount graph can be declared once in package maintenance')
    names = self.bundle.profile['filesystem']['subvolumes']
    require(manifest['subvolumes'] == dict(names), 'Worker graph candidate differs')
    candidate = TOP / names['root']
    graph = {}
    for target, volume in [(candidate, names['root']), (candidate / 'home', names['home']),
                           (candidate / 'var/log', names['log'])]:
      graph[str(target)] = {'filesystem': 'btrfs', 'root': '/' + volume}
    for source, relative, kind in [('/dev', 'dev', 'devtmpfs'), ('/proc', 'proc', 'proc'),
                                   ('/sys', 'sys', 'sysfs'), ('/run', 'run', 'tmpfs')]:
      rows = [entry for entry in table() if entry['path'] == source]
      require(len(rows) == 1 and rows[0]['filesystem'] == kind, 'Worker bind source differs')
      graph[str(candidate / relative)] = {key: rows[0][key] for key in
        ['filesystem', 'root', 'dev', 'source', 'options', 'super_options']}
    self.worker_bindings = graph

  def _worker_binding(self, entry):
    require(self.worker_bindings is not None and entry['path'] in self.worker_bindings,
            'Mount outside the declared worker graph')
    expected = self.worker_bindings[entry['path']]
    require(all(entry[key] == value for key, value in expected.items()),
            'Worker mount source/root/type/flags differ')
    if expected['filesystem'] == 'btrfs':
      self._validate(entry, False)
      # Nonrecursive bind inherits its RW top's nodev/nosuid execution posture.
      require(entry['options'] & {'nosuid', 'nodev', 'noexec'} == {'nosuid', 'nodev'},
              'Worker Btrfs bind flags differ')

  def readonly_top(self, deadline):
    self.new_target(TOP)
    self._mount(TOP, None, True, deadline)
    return TOP

  def maintenance_rw(self, deadline):
    """Caller must finish its exact phase preimage/guard checks before this.

    This is an internal PID1 operation, not an independently granted writer
    lease. A host message cannot supply a mount path, flag or approval boolean.
    """
    require(self.bundle.phase in {'packages', 'layer'} and self.mounted.get(TOP, (None, None))[1] is True,
            'Maintenance must begin with its admitted read-only top')
    self._unmount(TOP, deadline)
    self.device.verify_superblock()
    self._mount(TOP, None, False, deadline)

  def owner_preparation_rw(self, deadline):
    require(self.bundle.phase == 'owner-prepare'
            and self.bundle.configuration.get('purpose') == 'omarchy-shield-owner-preparation'
            and self.bundle.profile.get('purpose') == 'omarchy-shield-owner'
            and self.mounted.get(TOP, (None, None))[1] is True,
            'OWNER preparation requires explicit purpose and read-only admission')
    self._unmount(TOP, deadline)
    self.device.verify_superblock()
    self._mount(TOP, None, False, deadline)

  def candidate(self, deadline):
    require(self.bundle.phase == 'systemd' and self.mounted.get(TOP, (None, None))[1] is True,
            'Systemd candidate requires completed read-only admission')
    return self._candidate_mounts(deadline)

  def owner_candidate(self, deadline):
    require(self.bundle.phase == 'owner' and self.bundle.profile.get('purpose') == 'omarchy-shield-owner',
            'OWNER candidate requires explicit OWNER enrollment')
    return self._candidate_mounts(deadline)

  def _candidate_mounts(self, deadline):
    require(self.mounted.get(TOP, (None, None))[1] is True,
            'Candidate requires completed read-only admission')
    self._unmount(TOP, deadline)
    self.device.verify_superblock()
    self.new_target(NEWROOT)
    names = self.bundle.profile['filesystem']['subvolumes']
    self._mount(NEWROOT, names['root'], False, deadline)
    for path, purpose in [(NEWROOT / 'home', 'home'), (NEWROOT / 'var/log', 'log')]:
      directory(path)
      self._mount(path, names[purpose], False, deadline)
    return NEWROOT

  def _unmount(self, path, deadline):
    self.budget(deadline)
    require(path in self.mounted, 'Unmount target is not owned')
    self.check()
    require(self.library.umount2(os.fsencode(path), 0) == 0, 'Owned unmount refused')
    self.budget(deadline)
    require(not any(entry['path'] == str(path) for entry in table()), 'Owned mount remains')
    del self.mounted[path]
    if path in self.targets:
      info = path.lstat()
      require((info.st_dev, info.st_ino) == self.targets[path], 'RAM mount target changed')

  def release(self, deadline):
    """Only after positive worker/helper tree relinquishment; no lazy unmount.

    Even a failed earlier mount attempt is not retried. Missing/foreign mount
    identity, busy aliases or blocked I/O prevent a clean release receipt.
    """
    require(not self.release_attempted, 'Mount release attempt cannot replay')
    self.release_attempted = True
    self.budget(deadline)
    entries = table()
    owned = [entry for entry in entries if any(entry['path'] == str(base)
             or entry['path'].startswith(str(base) + '/') for base in self.targets)]
    require(all(entry['filesystem'] != 'btrfs' or entry in owned for entry in entries),
            'Unowned Btrfs alias prevents release')
    for entry in owned:
      if Path(entry['path']) not in self.mounted: self._worker_binding(entry)
    filesystems = [entry for entry in owned if entry['filesystem'] == 'btrfs']
    if filesystems:
      for entry in filesystems:
        self._validate(entry, 'ro' in entry['options'])
    if any('rw' in entry['options'] for entry in filesystems):
      descriptor = os.open(filesystems[0]['path'], os.O_RDONLY | os.O_DIRECTORY
                            | os.O_CLOEXEC | os.O_NOFOLLOW)
      try:
        self.budget(deadline)
        require(self.library.syncfs(descriptor) == 0, 'Owned filesystem sync failed')
        self.budget(deadline)
      finally:
        os.close(descriptor)
    for entry in sorted(owned, key=lambda row: (len(Path(row['path']).parts), row['id']), reverse=True):
      self.budget(deadline)
      current = [row for row in table() if row['path'] == entry['path']]
      require(current and max(row['id'] for row in current) == entry['id'],
              'Mount stack changed during release')
      require(self.library.umount2(os.fsencode(entry['path']), 0) == 0, 'Owned release unmount refused')
      self.budget(deadline)
    require(not any(entry['path'] == str(base) or entry['path'].startswith(str(base) + '/')
                    for entry in table() for base in self.targets), 'Owned child mounts remain')
    self.mounted.clear()
    for path, identity in self.targets.items():
      info = path.lstat()
      require((info.st_dev, info.st_ino) == identity, 'Released RAM target identity changed')
    self.device.require_unmounted()
    self.device.restrict_readonly()
    self.budget(deadline)
