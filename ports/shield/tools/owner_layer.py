"""Current OWNER layer validation and bounded file application to new snapshots.

This is a library, not a writer grant. The preparation PID1 owns source/root
admission, sole actors, mount ownership, startup budget and every child. Callers
must close the Tree before syncing/unmounting. No tar extraction API is used.
"""
from pathlib import Path
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile

from owner_profile import INSTALL, MODULE, require, exact, validate, validate_context, render
from owner_runtime import decode

MAX_LAYER = 8 * 1024**2


def canonical(value):
  return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False) + '\n').encode('ascii')


def relative(name):
  require(type(name) is str and 0 < len(name) <= 512 and name.isascii()
          and all(part not in ('.', '..') and re.fullmatch('[A-Za-z0-9_@+.,:-]+', part)
                  for part in name.split('/')), 'Unsafe OWNER path')
  return name


def marker_path(enrolled):
  validate(enrolled)
  return '.shield-owner/' + enrolled['owner_id'] + '/PREPARED.json'


def marker(enrolled, context, layer_sha256):
  validate_context(context, enrolled)
  require(context['enrollment_sha256'] == hashlib.sha256(canonical(enrolled)).hexdigest(),
          'Marker enrollment bytes differ')
  require(type(layer_sha256) is str and re.fullmatch('[0-9a-f]{64}', layer_sha256),
          'Layer identity required')
  return {'purpose': 'omarchy-shield-owner-prepared', 'owner_id': enrolled['owner_id'],
    'filesystem': enrolled['filesystem'], 'context_sha256': hashlib.sha256(canonical(context)).hexdigest(),
    'layer_sha256': layer_sha256, 'payload_readback_complete': True,
    'cleanup_qualified': False, 'durable_failure_recovery_qualified': False}


def preparation(enrolled, context, layer_sha256):
  raw = canonical(marker(enrolled, context, layer_sha256))
  return {'path': marker_path(enrolled), 'bytes': len(raw),
          'sha256': hashlib.sha256(raw).hexdigest(), 'layer_sha256': layer_sha256}


def validate_marker(item, enrolled, context):
  exact(item, ['path', 'bytes', 'sha256', 'layer_sha256'], 'Preparation binding fields differ')
  require(type(item['bytes']) is int and 0 < item['bytes'] <= 4096
          and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256'])
          and item == preparation(enrolled, context, item['layer_sha256']),
          'Preparation binding does not match this OWNER system')


def read_archive(raw):
  require(type(raw) is bytes and 0 < len(raw) <= MAX_LAYER, 'Compressed layer exceeds bound')
  with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
    expanded = compressed.read(MAX_LAYER + 1)
  require(len(expanded) <= MAX_LAYER, 'Expanded layer exceeds bound')
  contents = {}
  with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
    for number, member in enumerate(archive, 1):
      require(number <= 1024 and member.isfile() and member.name not in contents
              and member.uid == member.gid == 0 and member.mode == 0o600
              and not member.pax_headers and 0 <= member.size <= MAX_LAYER,
              'Unexpected or duplicate layer member')
      relative(member.name)
      require(member.name == 'manifest.json' or member.name.startswith('files/'),
              'Unknown layer member')
      contents[member.name] = archive.extractfile(member).read(MAX_LAYER + 1)
      require(len(contents[member.name]) == member.size, 'Truncated layer member')
  require('manifest.json' in contents, 'Layer manifest missing')
  manifest = decode(contents.pop('manifest.json'))
  return manifest, {name[6:]: value for name, value in contents.items()}


def validate_layer(layer, payloads, enrolled, context, root_postimages):
  validate_context(context, enrolled)
  require(context['enrollment_sha256'] == hashlib.sha256(canonical(enrolled)).hexdigest(),
          'Layer enrollment bytes differ')
  exact(layer, ['purpose', 'owner_id', 'filesystem', 'base_subvolumes', 'files', 'directories',
    'links', 'removals', 'home_removals', 'normal_home_seed_in_layer', 'normal_first_run_complete',
    'base_full_filesystem_reverified', 'physical_root_prepared', 'boot_ready'], 'Layer fields differ')
  require(layer['purpose'] == 'omarchy-shield-owner' and layer['owner_id'] == enrolled['owner_id']
          and layer['filesystem'] == enrolled['filesystem'], 'Layer enrollment differs')
  require(layer['normal_home_seed_in_layer'] is True and all(layer[name] is False for name in
    ['normal_first_run_complete', 'base_full_filesystem_reverified', 'physical_root_prepared', 'boot_ready']),
    'Layer overclaims preparation or qualification')
  base = layer['base_subvolumes']
  exact(base, ['root', 'home', 'log'], 'Exact snapshot parents required')
  require(type(base['root']) is str and re.fullmatch('@shield-[0-9a-f]{32}', base['root'])
          and base == {'root': base['root'], 'home': base['root'] + '-home', 'log': base['root'] + '-log'}
          and not set(base.values()) & set(enrolled['filesystem']['subvolumes'].values()),
          'Snapshot parents or new names differ')
  return _validate_payloads(layer, payloads, enrolled, context, root_postimages)


def validate_image_layer(layer, payloads, enrolled, context, root_postimages):
  """Internal filesystem-image payload, without USB snapshot-parent authority."""
  validate_context(context, enrolled)
  require('emmc' in enrolled['filesystem']
          and context['enrollment_sha256'] == hashlib.sha256(canonical(enrolled)).hexdigest(),
          'Internal image layer enrollment differs')
  exact(layer, ['purpose', 'owner_id', 'filesystem', 'files', 'directories', 'links',
    'removals', 'home_removals', 'normal_home_seed_in_layer', 'boot_ready'],
    'Internal image layer fields differ')
  require(layer['purpose'] == 'omarchy-shield-owner-image-layer'
          and layer['owner_id'] == enrolled['owner_id']
          and layer['filesystem'] == enrolled['filesystem']
          and layer['normal_home_seed_in_layer'] is True and layer['boot_ready'] is False,
          'Internal image layer purpose or claims differ')
  return _validate_payloads(layer, payloads, enrolled, context, root_postimages)


def _validate_payloads(layer, payloads, enrolled, context, root_postimages):
  policy = render(enrolled)
  for name in ['directories', 'links', 'removals', 'home_removals']:
    require(layer[name] == policy[name], 'Layer policy descriptor differs')
  require(all(type(item[key]) is int for item in layer['directories'].values()
              for key in ['mode', 'uid', 'gid']), 'Directory metadata types differ')
  expected = dict(policy['files'])
  for name, digest in context['sources_sha256'].items():
    expected[INSTALL.lstrip('/') + '/' + name] = dict(mode=0o644, uid=0, gid=0, sha256=digest)
  expected.update(policy['private_files'])
  for name, item in [(MODULE, enrolled['ethernet']['module']), *enrolled['ethernet']['firmware'].items()]:
    expected[name] = dict(item, mode=0o644, uid=0, gid=0)
  seed = policy['home_seed']
  require(seed['source'] in root_postimages, 'Matched default home source not pinned')
  expected[seed['target']] = dict(root_postimages[seed['source']], mode=seed['mode'], uid=seed['uid'], gid=seed['gid'])
  require(type(layer['files']) is dict and type(payloads) is dict
          and set(layer['files']) == set(payloads) == set(expected), 'Layer payload set differs')
  for name, want in expected.items():
    relative(name)
    actual, data = layer['files'][name], payloads[name]
    exact(actual, ['bytes', 'sha256', 'mode', 'uid', 'gid', 'volume'], 'Payload metadata differs')
    require(type(data) is bytes and type(actual['bytes']) is int and actual['bytes'] == len(data)
            and len(data) <= MAX_LAYER and actual['sha256'] == hashlib.sha256(data).hexdigest()
            and all(type(actual[k]) is int and actual[k] == want[k] for k in ['mode', 'uid', 'gid'])
            and actual['volume'] == ('home' if name.startswith('home/') else 'root'),
            'Payload bytes, permissions or routing differ')
    if 'data' in want:
      require(data == want['data'], 'Rendered system payload differs')
    if 'sha256' in want:
      require(actual['sha256'] == want['sha256'], 'Pinned payload identity differs')
    if 'bytes' in want:
      require(actual['bytes'] == want['bytes'], 'Pinned payload size differs')
  seed_data = payloads[seed['target']]
  require(seed_data.count(b'require("default.hypr.omarchy")') == 1
          and b'package.loaded["default.hypr.autostart"] = true' not in seed_data,
          'Normal home startup was replaced by bounded qualification')
  return layer


class Tree:
  """Nofollow directory fds, fixed roots and no implicit default guard."""
  def __init__(self, roots, guard):
    require(set(roots) == {'root', 'home', 'log'} and callable(guard), 'Explicit snapshot roots/guard required')
    self.guard, self.roots, self.fds, self.counter = guard, roots, {}, 0
    try:
      for name, path in roots.items():
        guard()
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.fds[name] = fd
        info = os.fstat(fd)
        require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
                'Unowned snapshot root')
    except BaseException:
      self.close()
      raise

  def close(self):
    for fd in self.fds.values():
      os.close(fd)
    self.fds.clear()

  def route(self, name):
    relative(name)
    if name.startswith('home/'):
      return 'home', name[5:]
    require(name != 'var/log' and not name.startswith('var/log/'), 'Log contents are not system-layer write paths')
    return 'root', name

  def parent(self, name, create=False):
    volume, relative_name = self.route(name)
    self.guard()
    current = os.dup(self.fds[volume])
    try:
      parts = relative_name.split('/')
      for part in parts[:-1]:
        try:
          child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
        except FileNotFoundError:
          if not create:
            raise
          self.guard()
          os.mkdir(part, 0o700, dir_fd=current)
          child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
          try:
            self.guard()
            os.fchown(child, 1001 if volume == 'home' else 0, 1001 if volume == 'home' else 0)
            os.fchmod(child, 0o755)
            os.fsync(child)
            os.fsync(current)
          except BaseException:
            os.close(child)
            raise
        try:
          info = os.fstat(child)
          # Stock directories such as root:polkitd rules.d allow group reads.
          # A non-writing group does not grant authority to mutate this parent.
          owned = info.st_uid == 0 or (volume == 'home' and
                  (info.st_uid, info.st_gid) == (1001, 1001))
          require(stat.S_ISDIR(info.st_mode) and owned
                  and not info.st_mode & 0o022, 'Unowned snapshot parent')
        except BaseException:
          os.close(child)
          raise
        os.close(current)
        current = child
      return current, parts[-1]
    except BaseException:
      os.close(current)
      raise

  def existing(self, fd, leaf, volume):
    try:
      info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
      return None
    require((info.st_uid, info.st_gid) in ([(0, 0), (1001, 1001)] if volume == 'home' else [(0, 0)])
            and info.st_nlink == 1 and (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)),
            'Unexpected snapshot preimage')
    return info

  def temporary(self):
    self.counter += 1
    return '.shield-owner-write-' + str(self.counter)

  def write(self, name, item, data):
    fd, leaf = self.parent(name, create=True)
    try:
      self.guard()
      self.existing(fd, leaf, self.route(name)[0])
      temporary = self.temporary()
      out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
      try:
        view = memoryview(data)
        while view:
          self.guard()
          amount = os.write(out, view)
          require(amount > 0, 'Short snapshot payload write')
          view = view[amount:]
        self.guard()
        os.fchown(out, item['uid'], item['gid'])
        os.fchmod(out, item['mode'])
        os.fsync(out)
      finally:
        os.close(out)
      self.guard()
      os.rename(temporary, leaf, src_dir_fd=fd, dst_dir_fd=fd)
      os.fsync(fd)
    finally:
      os.close(fd)

  def remove(self, name):
    try:
      fd, leaf = self.parent(name)
    except FileNotFoundError:
      return
    try:
      self.guard()
      if self.existing(fd, leaf, self.route(name)[0]) is not None:
        os.unlink(leaf, dir_fd=fd)
        os.fsync(fd)
    finally:
      os.close(fd)

  def link(self, name, target):
    require(self.route(name)[0] == 'root', 'Only system activation links allowed')
    fd, leaf = self.parent(name, create=True)
    try:
      self.guard()
      self.existing(fd, leaf, 'root')
      temporary = self.temporary()
      os.symlink(target, temporary, dir_fd=fd)
      self.guard()
      os.rename(temporary, leaf, src_dir_fd=fd, dst_dir_fd=fd)
      os.fsync(fd)
    finally:
      os.close(fd)

  def verify_file(self, name, item):
    fd, leaf = self.parent(name)
    try:
      self.guard()
      actual = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
      try:
        info = os.fstat(actual)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_size)
                  == (item['uid'], item['gid'], item['mode'], item['bytes']), 'Snapshot file metadata differs')
        value = hashlib.sha256()
        total = 0
        while total <= item['bytes']:
          self.guard()
          data = os.read(actual, min(65536, item['bytes'] + 1 - total))
          if not data: break
          value.update(data)
          total += len(data)
        require(total == item['bytes'] and value.hexdigest() == item['sha256'], 'Snapshot file readback differs')
      finally:
        os.close(actual)
    finally:
      os.close(fd)

  def directory(self, name, item):
    fd, leaf = self.parent(name, create=True)
    child = None
    try:
      self.guard()
      try:
        child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
      except FileNotFoundError:
        os.mkdir(leaf, 0o700, dir_fd=fd)
        child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
      info = os.fstat(child)
      require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
              'Unowned explicit system directory')
      self.guard()
      os.fchown(child, item['uid'], item['gid'])
      os.fchmod(child, item['mode'])
      os.fsync(child)
      os.fsync(fd)
      observed = os.fstat(child)
      require((observed.st_uid, observed.st_gid, stat.S_IMODE(observed.st_mode))
              == (item['uid'], item['gid'], item['mode']), 'Directory metadata differs')
    finally:
      if child is not None:
        os.close(child)
      os.close(fd)

  def apply(self, layer, payloads):
    # validate_layer must have completed against the boot config before entry.
    for name, item in layer['directories'].items():
      self.directory(name, item)
    for name in layer['removals'] + layer['home_removals']:
      self.remove(name)
    for name, item in layer['files'].items():
      self.write(name, item, payloads[name])
    for name, target in layer['links'].items():
      self.link(name, target)
    for name, item in layer['files'].items():
      self.verify_file(name, item)
    for name, target in layer['links'].items():
      fd, leaf = self.parent(name)
      try:
        self.guard()
        info = self.existing(fd, leaf, 'root')
        require(info is not None and stat.S_ISLNK(info.st_mode)
                and os.readlink(leaf, dir_fd=fd) == target, 'Snapshot link readback differs')
      finally:
        os.close(fd)
    for name in layer['removals'] + layer['home_removals']:
      try:
        fd, leaf = self.parent(name)
      except FileNotFoundError:
        continue
      try:
        self.guard()
        require(self.existing(fd, leaf, self.route(name)[0]) is None, 'Retired snapshot policy remains')
      finally:
        os.close(fd)
