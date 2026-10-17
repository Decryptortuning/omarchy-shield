"""Fixed phase-B materializer for an independently pinned expected-A profile.

No archive parsing, mounting, chroot, root selection or process execution.
Caller supplies already admitted candidate root/home directory fds, an owned
phase-B journal parent, the exclusive actor/mount lease and a guard callback.
Held fds do not establish that lease. A successful result does not prove clean
USB release, hardware durability, physical postimage authority or boot readiness.
Any failed/partial attempt is retained; no rollback, repair or retry is offered.
Journal/result records require the supervisor's actual successful worker reap
and independent postconditions; a marker alone is never a completion receipt.
"""
from dataclasses import dataclass
import ctypes
import hashlib
import json
import os
import re
import stat
from types import MappingProxyType
import uuid

from maintenance_accounts import ACCOUNT_NAMES, validate_accounts
from native_layer_reader import LayerContent, LayerPin, MAX_BLOB_BYTES, MAX_TAR_BYTES
from usb_root_profile import require, safe_relative

PURPOSE = 'native phase-B expected-A preimages'
MAX_PROFILE = 16 * 1024**2
FIVE = frozenset({'sha256', 'bytes', 'mode', 'uid', 'gid'})
HEX = re.compile(r'[0-9a-f]{64}\Z')
JOURNAL_PARENT = '/run/shield-usb/.shield-phase-B'


def canonical(value):
  return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False) + '\n').encode('ascii')


def plain(value):
  if isinstance(value, MappingProxyType): return {key: plain(item) for key, item in value.items()}
  if type(value) is tuple: return [plain(item) for item in value]
  return value


def frozen(value):
  if type(value) is dict: return MappingProxyType({key: frozen(item) for key, item in value.items()})
  if type(value) is list: return tuple(frozen(item) for item in value)
  return value


def sha(value):
  require(type(value) is str and HEX.fullmatch(value) and value != '0' * 64, 'Wrong sealed digest')


@dataclass(frozen=True)
class WriterPin:
  layer: LayerPin
  preimages_sha256: str
  preimages_bytes: int
  candidate_id: str
  filesystem_uuid: str
  phase_a_plan_sha256: str
  phase_a_receipt_sha256: str
  original_accounts_sha256: str

  def validate(self):
    require(type(self.layer) is LayerPin, 'Independent LayerPin required')
    self.layer.validate()
    for value in [self.preimages_sha256, self.phase_a_plan_sha256,
                  self.phase_a_receipt_sha256, self.original_accounts_sha256]: sha(value)
    require(type(self.preimages_bytes) is int and 0 < self.preimages_bytes <= MAX_PROFILE
            and type(self.candidate_id) is str
            and re.fullmatch('[0-9a-f]{32}', self.candidate_id)
            and type(self.filesystem_uuid) is str
            and str(uuid.UUID(self.filesystem_uuid)) == self.filesystem_uuid,
            'Wrong sealed phase-B identity/size')


def identity_schema(item):
  require(type(item) is dict and item.get('type') in {'file', 'directory', 'symlink'},
          'Wrong object identity')
  extra = {'file': {'sha256', 'bytes'}, 'directory': set(), 'symlink': {'target'}}[item['type']]
  require(set(item) == {'type', 'mode', 'uid', 'gid', 'xattrs'} | extra
          and all(type(item[k]) is int for k in ['mode', 'uid', 'gid'])
          and 0 <= item['mode'] <= 0o777 and 0 <= item['uid'] <= 65535
          and 0 <= item['gid'] <= 65535, 'Wrong object metadata or privileged mode')
  attrs = item['xattrs']
  require(type(attrs) is dict and len(attrs) <= 16, 'Wrong xattr inventory')
  total = 0
  for key, value in attrs.items():
    require(type(key) is str and 0 < len(key) <= 255 and '\0' not in key
            and type(value) is str and len(value) <= 131072
            and re.fullmatch('(?:[0-9a-f]{2})*', value), 'Wrong xattr encoding')
    total += len(value)
  require(total <= 131072, 'Excessive xattrs')
  if item['type'] == 'file':
    sha(item['sha256'])
    require(type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_BLOB_BYTES, 'Excessive file')
  if item['type'] == 'symlink':
    require(type(item['target']) is str and 0 < len(item['target']) <= 4096
            and '\0' not in item['target'] and item['mode'] == 0o777, 'Wrong symlink')


def split_name(name):
  safe_relative(name)
  require(len(name) <= 4096, 'Excessive layer path')
  parts = name.split('/')
  require(parts[0] not in {'build', 'root', 'dev', 'proc', 'sys', 'run', 'tmp',
                          'mnt', 'media', 'boot'}
          and not parts[0].startswith('.shield-') and '.ssh' not in parts
          and '.gnupg' not in parts and not name.startswith('etc/pacman.d/gnupg')
          and not name.startswith('etc/ssh/ssh_host_'), 'Excluded private/runtime destination')
  if parts[0] == 'home':
    require(len(parts) == 1 or parts[1] == 'shieldqual', 'Preexisting owner home is excluded')
    return 'home', parts[1:]
  return 'root', parts


def _pairs(pairs):
  value = {}
  for key, item in pairs:
    require(key not in value, 'Duplicate expected-A field')
    value[key] = item
  return value


def admit(content, pin, raw):
  """Hash first, then exact schemas. No physical postimages are adopted."""
  require(type(pin) is WriterPin, 'WriterPin required'); pin.validate()
  require(type(content) is LayerContent and type(content.raw_tar) is bytes
          and len(content.raw_tar) <= MAX_TAR_BYTES
          and type(content.manifest) is MappingProxyType
          and type(content.blob_ranges) is MappingProxyType
          and content.physical_preimages_admitted is False
          and content.physical_write_authority is False, 'Admitted immutable LayerContent required')
  manifest = plain(content.manifest)
  require(hashlib.sha256(canonical(manifest)).hexdigest() == pin.layer.manifest_sha256
          and manifest['sources'] == dict(pin.layer.sources)
          and manifest['profile_sha256'] == pin.layer.profile_sha256
          and manifest['payload_manifest_sha256'] == pin.layer.payload_manifest_sha256,
          'Layer/content pin mismatch')
  filesystem = manifest['filesystem']
  require(filesystem['candidate_id'] == pin.candidate_id and filesystem['uuid'] == pin.filesystem_uuid
          and filesystem['subvolumes'] == {key: '@shield-' + pin.candidate_id + suffix
            for key, suffix in [('root', ''), ('home', '-home'), ('log', '-log')]},
          'Layer/candidate/filesystem mismatch')
  require(type(raw) is bytes and len(raw) == pin.preimages_bytes
          and hashlib.sha256(raw).hexdigest() == pin.preimages_sha256, 'Expected-A profile pin mismatch')
  def forbidden(_value): raise ValueError('Noninteger profile number')
  profile = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
                       parse_float=forbidden, parse_constant=forbidden)
  require(canonical(profile) == raw and type(profile) is dict and set(profile) == {
    'format_version', 'purpose', 'candidate_id', 'filesystem_uuid', 'phase_a_plan_sha256',
    'phase_a_receipt_sha256', 'original_accounts_sha256', 'original_accounts', 'layer', 'roots', 'entries'},
    'Wrong canonical expected-A profile')
  require(type(profile['format_version']) is int and profile['format_version'] == 1
          and profile['purpose'] == PURPOSE, 'Wrong expected-A profile purpose')
  for key in ['candidate_id', 'filesystem_uuid', 'phase_a_plan_sha256',
              'phase_a_receipt_sha256', 'original_accounts_sha256']:
    require(profile[key] == getattr(pin, key), 'Expected-A provenance differs')
  require(profile['layer'] == {key: getattr(pin.layer, key) for key in
    ['archive_sha256', 'manifest_sha256', 'profile_sha256', 'payload_manifest_sha256']}, 'Wrong layer provenance')
  original = profile['original_accounts']
  require(type(original) is dict and set(original) == ACCOUNT_NAMES
          and hashlib.sha256(canonical(original)).hexdigest() == pin.original_accounts_sha256,
          'Original account plan pin differs')
  for value in original.values():
    require(type(value) is dict and set(value) == FIVE, 'Wrong original account fields')
    identity_schema({'type': 'file', 'xattrs': {}, **value})
    require(value['uid'] == 0 and 0 < value['bytes'] <= 1024**2
            and not value['mode'] & 0o022, 'Unsafe original account identity')
  roots, expected, entries = profile['roots'], profile['entries'], manifest['entries']
  require(type(roots) is dict and set(roots) == {'root', 'home'}
          and type(expected) is dict and type(entries) is dict
          and set(expected) == set(entries) and 0 < len(entries) <= 12000
          and ACCOUNT_NAMES.issubset(entries), 'Incomplete exact destination/preimage inventory')
  for value in roots.values():
    identity_schema(value)
    require(value['type'] == 'directory' and value['uid'] == value['gid'] == 0
            and not value['mode'] & 0o022, 'Unsafe supplied root identity')
  for name, row in entries.items():
    split_name(name)
    require(type(row) is dict and set(row) == {'identity', 'roles'}
            and type(row['roles']) is list and row['roles']
            and row['roles'] == sorted(set(row['roles']))
            and set(row['roles']) <= {'account', 'overlay', 'mask', 'runtime', 'home',
                                      'machine-id', 'dbus-identity', 'ancestor'}, 'Wrong destination roles')
    item = row['identity']; identity_schema(item)
    if expected[name] is not None: identity_schema(expected[name])
    if row['roles'] == ['ancestor']:
      require(item['type'] == 'directory' and expected[name] == item,
              'Ancestor-only destination requires exact existing identity')
    if name == 'etc/polkit-1/rules.d':
      require(row['roles'] == ['ancestor'] and item['type'] == 'directory'
              and (item['uid'], item['gid'], item['mode']) == (0, 102, 0o750),
              'Polkit ancestor cannot be reassigned or repaired')
    owner = 1001 if name == 'home/shieldqual' or name.startswith('home/shieldqual/') else 0
    require(item['uid'] == owner and (item['gid'] == owner or
      name == 'etc/polkit-1/rules.d' and row['roles'] == ['ancestor']
      and item['gid'] == 102 and item['mode'] == 0o750), 'Unexpected layer ownership')
    require(all(key.startswith('user.') or key in {'system.posix_acl_access',
      'system.posix_acl_default'} for key in item['xattrs']), 'Privileged or unsupported destination xattr')
    parents = name.split('/')[:-1]
    for end in range(1, len(parents) + 1):
      parent = '/'.join(parents[:end])
      require(parent in entries and entries[parent]['identity']['type'] == 'directory',
              'Missing declared directory ancestor')
    if item['type'] == 'file':
      data = content.blob(item['sha256'])
      require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
              'Admitted immutable blob differs')
  require(entries['etc/machine-id']['identity']['type'] == 'file'
          and bytes(content.blob(entries['etc/machine-id']['identity']['sha256'])) == b'',
          'Host machine identity cannot be copied')
  for name in ACCOUNT_NAMES:
    require(entries[name]['identity']['type'] == 'file' and entries[name]['roles'] == ['account']
            and expected[name] is not None and expected[name]['type'] == 'file'
            and {key: expected[name][key] for key in FIVE} == original[name],
            'Expected-A accounts differ from original plan')
  return profile, entries


class Roots:
  def __init__(self, root_fd, home_fd, guard):
    require(callable(guard), 'Actual guardian/reserve callback required')
    self.guard = guard
    self.fds = {}
    self.identities = {}
    try:
      for key, fd in [('root', root_fd), ('home', home_fd)]: self.fds[key] = os.dup(fd)
      for key, fd in self.fds.items():
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0,
                'Owned candidate directory descriptors required')
        self.identities[key] = (info.st_dev, info.st_ino)
      require(self.identities['root'] != self.identities['home'], 'Distinct candidate root/home required')
    except BaseException:
      self.close(); raise

  def close(self):
    for fd in self.fds.values(): os.close(fd)
    self.fds.clear()

  def parent(self, name):
    scope, parts = split_name(name)
    fd = os.dup(self.fds[scope])
    try:
      require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == self.identities[scope], 'Supplied root changed')
      for part in parts[:-1]:
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        os.close(fd); fd = child
      return fd, parts[-1] if parts else None
    except BaseException:
      os.close(fd); raise

  def observe(self, name, *, data=False):
    self.guard()
    try: parent, leaf = self.parent(name)
    except FileNotFoundError: return (None, None) if data else None
    try:
      return observe(parent, leaf, self.guard, data=data)
    finally: os.close(parent)


def read_xattrs(target, *, symlink=False):
  options = {'follow_symlinks': False} if symlink else {}
  names = os.listxattr(target, **options)
  require(len(names) <= 16, 'Excessive live xattr inventory')
  result, total = {}, 0
  for key in sorted(names):
    require(0 < len(key) <= 255 and '\0' not in key, 'Wrong live xattr name')
    value = os.getxattr(target, key, **options)
    total += len(value)
    require(total <= 65536, 'Excessive live xattr values')
    result[key] = value.hex()
  return result


def observe(parent, leaf, guard, *, data=False):
  try: info = os.fstat(parent) if leaf is None else os.stat(leaf, dir_fd=parent, follow_symlinks=False)
  except FileNotFoundError: return (None, None) if data else None
  require(not info.st_mode & 0o7000, 'Privileged preimage mode')
  result = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
  if stat.S_ISLNK(info.st_mode):
    require(info.st_nlink == 1 and not data, 'Shared or unexpected account symlink')
    path = f'/proc/self/fd/{parent}/{leaf}'
    result.update(type='symlink', target=os.readlink(leaf, dir_fd=parent),
                  xattrs=read_xattrs(path, symlink=True))
    return result
  require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'Special preimage object')
  fd = os.dup(parent) if leaf is None else os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
  try:
    first = os.fstat(fd)
    require((first.st_dev, first.st_ino) == (info.st_dev, info.st_ino), 'Preimage moved')
    result['xattrs'] = read_xattrs(fd)
    raw = None
    if stat.S_ISREG(first.st_mode):
      require(first.st_nlink == 1 and first.st_size <= MAX_BLOB_BYTES, 'Shared or oversized preimage')
      digest = hashlib.sha256(); parts = [] if data else None; size = 0
      while True:
        guard(); chunk = os.read(fd, 1024**2)
        if not chunk: break
        size += len(chunk); require(size <= MAX_BLOB_BYTES, 'Growing preimage')
        digest.update(chunk)
        if data: parts.append(chunk)
      result.update(type='file', sha256=digest.hexdigest(), bytes=size)
      if data: raw = b''.join(parts)
    else:
      require(not data, 'Account preimage is not a file'); result['type'] = 'directory'
    last = os.fstat(fd)
    require((first.st_dev, first.st_ino, first.st_mode, first.st_uid, first.st_gid,
      first.st_size, first.st_mtime_ns, first.st_ctime_ns) == (last.st_dev, last.st_ino,
      last.st_mode, last.st_uid, last.st_gid, last.st_size, last.st_mtime_ns, last.st_ctime_ns),
      'Preimage changed while reading')
    return (result, raw) if data else result
  finally: os.close(fd)


def metadata(fd, item):
  os.fchown(fd, item['uid'], item['gid'])
  for key in os.listxattr(fd): os.removexattr(fd, key)
  for key, value in item['xattrs'].items(): os.setxattr(fd, key, bytes.fromhex(value))
  os.fchmod(fd, item['mode'])


def write_all(fd, raw, guard):
  cursor = 0
  while cursor < len(raw):
    guard(); count = os.write(fd, raw[cursor:cursor + 1024**2])
    require(0 < count <= min(1024**2, len(raw) - cursor), 'Uncertain layer write')
    cursor += count


def noreplace(parent, source, destination):
  # Selected Linux/libc renameat2, no fallback which might overwrite a new leaf.
  function = ctypes.CDLL(None, use_errno=True).renameat2
  function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
  function.restype = ctypes.c_int
  require(function(parent, os.fsencode(source), parent, os.fsencode(destination), 1) == 0,
          'New destination collision; preserve staging and fail')


def apply_one(roots, name, wanted, expected):
  require(roots.observe(name) == expected, 'Destination changed since full preflight')
  if wanted == expected: return
  parent, leaf = roots.parent(name)
  try:
    require(leaf is not None, 'Supplied home root metadata cannot be changed')
    roots.guard()
    if wanted['type'] == 'directory':
      require(expected is None or expected['type'] == 'directory', 'No directory type repair')
      if expected is None: os.mkdir(leaf, 0o700, dir_fd=parent)
      fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
      try: metadata(fd, wanted); roots.guard(); os.fsync(fd)
      finally: os.close(fd)
    else:
      require(expected is None or expected['type'] != 'directory', 'Cannot replace an existing directory')
      temporary = '.shield-layer-' + hashlib.sha256(name.encode()).hexdigest()[:32]
      if wanted['type'] == 'file':
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
          write_all(fd, roots.content.blob(wanted['sha256']), roots.guard)
          metadata(fd, wanted); roots.guard(); os.fsync(fd)
        finally: os.close(fd)
      else:
        os.symlink(wanted['target'], temporary, dir_fd=parent)
        os.chown(temporary, wanted['uid'], wanted['gid'], dir_fd=parent, follow_symlinks=False)
        path = f'/proc/self/fd/{parent}/{temporary}'
        for key in os.listxattr(path, follow_symlinks=False): os.removexattr(path, key, follow_symlinks=False)
        for key, value in wanted['xattrs'].items():
          os.setxattr(path, key, bytes.fromhex(value), follow_symlinks=False)
      require(observe(parent, temporary, roots.guard) == wanted, 'Staged postimage differs')
      roots.guard()
      require(roots.observe(name) == expected, 'Destination changed before atomic commit')
      if expected is None: noreplace(parent, temporary, leaf)
      else: os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
    roots.guard(); os.fsync(parent)
  finally: os.close(parent)
  require(roots.observe(name) == wanted, 'Destination postimage differs')


def materialize(content, pin, preimages_raw, root_fd, home_fd, journal_parent_fd, *, guard_check):
  """One actual owned phase-B attempt. Failure retains journal/staging changes."""
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'Root writer required')
  require(callable(guard_check), 'Actual guardian/reserve callback required')
  guard_check()
  profile, entries = admit(content, pin, preimages_raw)
  roots = Roots(root_fd, home_fd, guard_check); roots.content = content
  journal = None
  try:
    for scope in ['root', 'home']:
      require(observe(roots.fds[scope], None, guard_check) == profile['roots'][scope],
              'Supplied root metadata differs')
    before, after = {}, {}
    for name in sorted(entries):
      if name in ACCOUNT_NAMES:
        actual, before[name] = roots.observe(name, data=True)
        after[name] = bytes(content.blob(entries[name]['identity']['sha256']))
      else: actual = roots.observe(name)
      require(actual == profile['entries'][name], 'Actual expected-A preimage differs')
    validate_accounts(before, after)  # All four databases before any destination write.
    parent = os.fstat(journal_parent_fd)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0
            and stat.S_IMODE(parent.st_mode) == 0o700
            and os.readlink(f'/proc/self/fd/{journal_parent_fd}') == JOURNAL_PARENT
            and (parent.st_dev, parent.st_ino) not in roots.identities.values(), 'Owned distinct phase-B journal parent required')
    guard_check(); os.mkdir(pin.candidate_id, 0o700, dir_fd=journal_parent_fd)
    journal = os.open(pin.candidate_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=journal_parent_fd)
    os.fchmod(journal, 0o700); os.fsync(journal_parent_fd)
    def record(name, value):
      fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                   0o600, dir_fd=journal)
      try:
        os.fchmod(fd, 0o600)
        write_all(fd, canonical(value), guard_check); guard_check(); os.fsync(fd)
      finally: os.close(fd)
      os.fsync(journal)
    record('INCOMPLETE.json', {'candidate_id': pin.candidate_id,
                             'preimages_sha256': pin.preimages_sha256, 'state': 'INCOMPLETE'})
    for name in sorted(entries, key=lambda value: (len(value.split('/')), value)):
      row = entries[name]
      if row['roles'] == ['ancestor']:
        require(roots.observe(name) == row['identity'], 'Ancestor changed'); continue
      apply_one(roots, name, row['identity'], profile['entries'][name])
    for name, row in entries.items():
      require(roots.observe(name) == row['identity'], 'Final exact layer postimage differs')
    for scope in ['root', 'home']:
      guard_check(); os.fsync(roots.fds[scope])
      require(observe(roots.fds[scope], None, guard_check) == profile['roots'][scope], 'Supplied root metadata changed')
    result = {'format_version': 1, 'state': 'LAYER_MATERIALIZED', 'candidate_id': pin.candidate_id,
      'filesystem_uuid': pin.filesystem_uuid, 'preimages_sha256': pin.preimages_sha256,
      'layer_manifest_sha256': pin.layer.manifest_sha256, 'entries_verified': len(entries),
      'account_postimages': {name: entries[name]['identity'] for name in sorted(ACCOUNT_NAMES)},
      'boot_ready': False, 'clean_usb_release': False, 'physical_powerloss_qualified': False}
    guard_check(); record('MATERIALIZED.json', result); guard_check()
    return frozen(result)
  finally:
    if journal is not None: os.close(journal)
    roots.close()
