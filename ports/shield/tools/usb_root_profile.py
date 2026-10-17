"""Exact payload admission and installed-root verification for USB maintenance.

This module never mounts storage, installs packages, or selects a boot root.
The maintenance owner must establish device identity and exclusive ownership.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

COMPONENTS = {'mesa', 'linux-shield', 'omarchy', 'omarchy-settings', 'omarchy-shield', 'dtc'}


def require(condition, message):
  if not condition:
    raise ValueError(message)


def digest(path):
  value = hashlib.sha256()
  with Path(path).open('rb') as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
      value.update(chunk)
  return value.hexdigest()


def safe_relative(value):
  require(isinstance(value, str) and value != '', 'Missing relative path')
  path = PurePosixPath(value)
  require(not path.is_absolute() and all(part not in ('', '.', '..') for part in value.split('/')),
          'Unsafe relative path: ' + value)
  require(path.parts[0] not in {'dev', 'proc', 'sys', 'run', 'tmp', 'build'}, 'Virtual/build payload path')
  return path


def rooted(root, relative):
  relative = safe_relative(relative)
  root = Path(root).resolve(strict=True)
  parent = root
  for part in relative.parts[:-1]:
    parent /= part
    require(not parent.is_symlink() and parent.is_dir(), 'Symlink/missing payload parent: ' + str(relative))
  return root / relative


def file_identity(root, relative):
  path = rooted(root, relative)
  info = path.lstat()
  result = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
  if stat.S_ISREG(info.st_mode):
    result.update(type='file', bytes=info.st_size, sha256=digest(path))
  elif stat.S_ISLNK(info.st_mode):
    result.update(type='symlink', target=os.readlink(path))
  elif stat.S_ISDIR(info.st_mode):
    result.update(type='directory')
  else:
    raise ValueError('Special file in installed package payload: ' + relative)
  # Timestamp-only differences are deliberately outside runtime identity.
  result['xattrs'] = {name: os.getxattr(path, name, follow_symlinks=False).hex()
                     for name in sorted(os.listxattr(path, follow_symlinks=False))}
  return result


def sections(path):
  result = {}
  current = None
  for line in Path(path).read_text().splitlines():
    if line.startswith('%') and line.endswith('%'):
      current = line[1:-1]
      require(current not in result, 'Duplicate ALPM section')
      result[current] = []
    elif line:
      require(current is not None, 'ALPM value outside section')
      result[current].append(line)
  return result


def installed_packages(root):
  packages = {}
  for directory in sorted((Path(root) / 'var/lib/pacman/local').iterdir()):
    if not directory.is_dir():
      continue
    metadata = sections(directory / 'desc')
    name, = metadata['NAME']
    require(name not in packages, 'Duplicate installed package: ' + name)
    packages[name] = (directory, metadata)
  return packages


def installed_versions(root):
  result = {}
  for name, (_, metadata) in installed_packages(root).items():
    version, = metadata['VERSION']
    result[name] = version
  return result


def database_profile(root):
  result = {}
  for name, (directory, metadata) in installed_packages(root).items():
    if name in COMPONENTS:
      require(metadata.get('ARCH') == ['aarch64'], 'Wrong installed architecture: ' + name)
      require((directory / 'mtree').is_file(), 'Missing installed mtree: ' + name)
    # Installation time changes when applying these archives to the USB snapshot.
    # All dependency, architecture, reason, validation and other fields stay bound.
    semantic = {key: value for key, value in metadata.items() if key != 'INSTALLDATE'}
    result[name] = {'desc': semantic, 'files': digest(directory / 'files'),
                    'mtree': digest(directory / 'mtree') if (directory / 'mtree').is_file() else None,
                    'install': digest(directory / 'install') if (directory / 'install').is_file() else None}
  return result


def transition_absences(base_root, new_root):
  old = installed_packages(base_root)
  new = installed_packages(new_root)
  require((COMPONENTS - {'dtc'}).issubset(old), 'Missing original local package records')
  old_paths = set()
  new_paths = set()
  for name in COMPONENTS & old.keys():
    old_paths.update(value.rstrip('/') for value in sections(old[name][0] / 'files')['FILES'])
  # Shared paths still owned by another package must never become removal requirements.
  for directory, _ in new.values():
    new_paths.update(value.rstrip('/') for value in sections(directory / 'files').get('FILES', []))
  return sorted(old_paths - new_paths)


def path_absent(root, relative):
  parts = safe_relative(relative).parts
  path = Path(root).resolve(strict=True)
  for index, part in enumerate(parts):
    path /= part
    try:
      info = path.lstat()
    except FileNotFoundError:
      return True
    if index == len(parts) - 1:
      return False
    require(not stat.S_ISLNK(info.st_mode), 'Symlink in required-absence parent')
    if not stat.S_ISDIR(info.st_mode):
      return True
  return False


def root_profile(root, versions):
  require(set(versions) == COMPONENTS, 'Expected the complete six-component maintenance closure')
  root = Path(root).resolve(strict=True)
  packages = installed_packages(root)
  names = set()
  for name, version in versions.items():
    require(name in packages and packages[name][1]['VERSION'] == [version], 'Wrong installed version: ' + name)
    directory = packages[name][0]
    names.update(value.rstrip('/') for value in sections(directory / 'files')['FILES'])
  # depmod and the dynamic loader generate runtime state outside some file lists.
  modules = root / 'usr/lib/modules/7.1.0-shield-bringup'
  require(modules.is_dir() and not modules.is_symlink(), 'Missing matching module tree')
  names.update(str(path.relative_to(root)) for path in modules.rglob('*'))
  names.add('etc/ld.so.cache')
  return {name: file_identity(root, name) for name in sorted(names)}


def validate_manifest(manifest):
  require(manifest['format_version'] == 1, 'Unknown USB maintenance manifest')
  require(re.fullmatch(r'[0-9a-f]{32}', manifest['candidate_id']) is not None, 'Invalid candidate identity')
  require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', manifest['filesystem_uuid']) is not None,
          'Invalid filesystem UUID')
  expected = '@shield-' + manifest['candidate_id']
  require(manifest['subvolumes'] == {'root': expected, 'home': expected + '-home', 'log': expected + '-log'},
          'Candidate subvolumes do not match its identity')
  require(set(manifest['packages']) == COMPONENTS, 'Incomplete maintenance package set')
  require(isinstance(manifest['installed_packages'], dict) and
          COMPONENTS.issubset(manifest['installed_packages']), 'Incomplete installed package database profile')
  require(set(manifest['database']) == set(manifest['installed_packages']), 'Incomplete ALPM semantic profile')
  require(isinstance(manifest['required_absent'], list) and
          len(manifest['required_absent']) == len(set(manifest['required_absent'])), 'Invalid transition absence list')
  for name in manifest['required_absent']:
    safe_relative(name)
    require(name not in manifest['root_files'], 'Transition path both present and absent')
  filenames = set()
  for name, item in manifest['packages'].items():
    filename = item['filename']
    require(isinstance(filename, str) and re.fullmatch(r'[A-Za-z0-9_.+:-]+\.pkg\.tar\.(?:xz|zst)', filename) is not None,
            'Unsafe package filename')
    require(filename not in filenames, 'Duplicate package archive')
    filenames.add(filename)
    require(item['architecture'] == 'aarch64' and item['bytes'] > 0 and
            re.fullmatch(r'[0-9a-f]{64}', item['sha256']) is not None, 'Invalid archive identity: ' + name)
    require(isinstance(item['version'], str) and bool(item['version']), 'Missing package version')
    require(manifest['installed_packages'][name] == item['version'], 'Package/database version disagreement')
    if name == 'dtc':
      require('signature' in item, 'The audited dependency requires its detached signature')
    if 'signature' in item:
      signature = item['signature']
      require(isinstance(signature, dict) and signature.get('filename') == filename + '.sig' and
              isinstance(signature.get('bytes'), int) and signature['bytes'] > 0 and
              isinstance(signature.get('sha256'), str) and
              re.fullmatch(r'[0-9a-f]{64}', signature['sha256']) is not None, 'Invalid package signature profile')
  require(bool(manifest['root_files']), 'Empty installed-root profile')
  for name, item in manifest['root_files'].items():
    safe_relative(name)
    require(item['type'] in {'file', 'symlink', 'directory'}, 'Unknown root entry type')
    require(0 <= item['mode'] <= 0o7777 and item['uid'] >= 0 and item['gid'] >= 0, 'Invalid root metadata')
    if item['type'] == 'file':
      require(item['bytes'] >= 0 and re.fullmatch(r'[0-9a-f]{64}', item['sha256']) is not None, 'Invalid root file hash')
  return manifest


def host_metadata_execute(arguments):
  """Explicit trusted host metadata boundary, never the native worker runner."""
  require(len(arguments) == 4 and arguments[:2] == ['/usr/bin/bsdtar', '-xOf']
          and arguments[-1] == '.PKGINFO', 'Only package metadata extraction is owned here')
  require(not Path('/proc/device-tree/chosen/shield,first-ram-probe').exists(),
          'Native metadata extraction requires its owned command executor')
  return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def admit_payload(manifest, payload, *, execute):
  require(callable(execute), 'Explicit metadata command owner required')
  validate_manifest(manifest)
  payload = Path(payload).resolve(strict=True)
  files = {path.name for path in payload.iterdir()}
  expected_files = {item['filename'] for item in manifest['packages'].values()}
  expected_files.update(item['signature']['filename'] for item in manifest['packages'].values() if 'signature' in item)
  require(files == expected_files, 'Extra or missing package payload')
  for name, item in manifest['packages'].items():
    path = payload / item['filename']
    require(not path.is_symlink() and path.is_file(), 'Package must be a regular file')
    require(path.stat().st_size == item['bytes'] and digest(path) == item['sha256'], 'Changed archive: ' + name)
    if 'signature' in item:
      signature = item['signature']
      require(signature['filename'] == item['filename'] + '.sig', 'Wrong package signature filename')
      sig = payload / signature['filename']
      require(not sig.is_symlink() and sig.is_file() and sig.stat().st_size == signature['bytes'] and
              digest(sig) == signature['sha256'], 'Changed package signature: ' + name)
    metadata = execute(['/usr/bin/bsdtar', '-xOf', str(path), '.PKGINFO'])
    require(type(metadata) is str and len(metadata) <= 1024**2, 'Package metadata output differs')
    for key, expected in [('pkgname', name), ('pkgver', item['version']), ('arch', 'aarch64')]:
      values = [line.split(' = ', 1)[1] for line in metadata.splitlines() if line.startswith(key + ' = ')]
      require(values == [expected], 'Package metadata differs: ' + name + '/' + key)
  return True


def verify_root(manifest, root):
  validate_manifest(manifest)
  require(installed_versions(root) == manifest['installed_packages'], 'Installed dependency/package set differs')
  require(database_profile(root) == manifest['database'], 'Installed ALPM semantic/mtree/install state differs')
  for name in manifest['required_absent']:
    require(path_absent(root, name), 'Obsolete installed path remains: ' + name)
  versions = {name: item['version'] for name, item in manifest['packages'].items()}
  actual = root_profile(root, versions)
  require(actual == manifest['root_files'], 'Installed root differs from matched package/module/loader profile')
  return True
