#!/usr/bin/env python3
"""Archive an exact, reviewed ARM runtime inventory without touching devices."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
from usb_root_profile import digest, require


def relative_name(name):
  require(isinstance(name, str) and name and not name.startswith('/'), 'Unsafe runtime path')
  require(all(part not in ('', '.', '..') for part in name.split('/')), 'Unsafe runtime component')
  require(PurePosixPath(name).parts[0] not in {'dev', 'proc', 'sys', 'run', 'tmp'}, 'Virtual runtime path')
  return name


def prepare(inventory_path, expected_sha256, output):
  inventory_path, output = Path(inventory_path), Path(output)
  require(digest(inventory_path) == expected_sha256, 'Unreviewed inventory bytes')
  inventory = json.loads(inventory_path.read_text())
  root = Path(inventory['root']).resolve(strict=True)
  require(root != Path('/'), 'Refuse host root')
  names = inventory['runtime_without_python_extension_build_config']['paths']
  require(len(names) == len(set(names)), 'Duplicate runtime path')
  selected = {}
  # Read and admit every byte before publishing any output directory.
  for name in sorted(names):
    relative_name(name)
    item = inventory['paths'][name]
    source = root / name
    require(source.parent.resolve(strict=True).is_relative_to(root), 'Runtime parent escapes root')
    info = source.lstat()
    require(stat.S_IMODE(info.st_mode) == item['mode'] and info.st_uid == item['uid']
            and info.st_gid == item['gid'], 'Runtime metadata differs: ' + name)
    require(item['uid'] == 0 and item['gid'] == 0, 'Runtime must be root owned')
    if item['type'] == 'file':
      require(stat.S_ISREG(info.st_mode), 'Runtime file type differs')
      data = source.read_bytes()
      require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
              'Runtime bytes differ: ' + name)
    elif item['type'] == 'directory':
      require(stat.S_ISDIR(info.st_mode), 'Runtime directory type differs')
      data = b''
    elif item['type'] == 'symlink':
      require(stat.S_ISLNK(info.st_mode) and os.readlink(source) == item['target'], 'Runtime link differs')
      target = source.resolve(strict=True)
      require(target.is_relative_to(root) and str(target.relative_to(root)) in names,
              'Runtime link target is outside selected runtime')
      data = b''
    else:
      raise ValueError('Unsupported runtime type')
    selected[name] = (item, data)
  for name in names:
    for parent in PurePosixPath(name).parents:
      if str(parent) != '.':
        require(str(parent) in selected and selected[str(parent)][0]['type'] == 'directory',
                'Missing real runtime ancestor')
  # These are runtime imports, not entrypoints granting device/mount authority.
  module_dir = 'usr/lib/shield-maintenance'
  require(module_dir not in selected, 'Runtime module destination already exists')
  selected[module_dir] = ({'type': 'directory', 'mode': 0o755}, b'')
  modules = {}
  for name in ['usb_root_profile.py', 'usb_candidate_transaction.py']:
    source = Path(__file__).resolve().parent / name
    data = source.read_bytes()
    modules[name] = hashlib.sha256(data).hexdigest()
    selected[module_dir + '/' + name] = ({'type': 'file', 'mode': 0o644}, data)
  require(not output.exists() and not output.is_symlink(), 'Output must be a new directory')
  output.mkdir(mode=0o700)
  archive = output / 'toolroot.tar.gz'
  normalized_modes = {}
  with archive.open('xb') as raw:
    with gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0, compresslevel=9) as compressed:
      with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
        for name, (item, data) in sorted(selected.items()):
          entry = tarfile.TarInfo(name)
          entry.uid = entry.gid = entry.mtime = 0
          entry.mode = item['mode']
          if item['type'] == 'directory':
            entry.type = tarfile.DIRTYPE
          elif item['type'] == 'symlink':
            entry.type = tarfile.SYMTYPE
            entry.linkname = item['target']
          else:
            # The maintenance runtime is root-only. Admit the original package
            # metadata above, but do not grant set-ID authority in this RAM root.
            entry.mode &= ~0o6000
            if entry.mode != item['mode']:
              normalized_modes[name] = {'source': item['mode'], 'runtime': entry.mode}
            entry.size = len(data)
          tar.addfile(entry, io.BytesIO(data) if entry.isfile() else None)
  receipt = {'format_version': 1, 'inventory_sha256': expected_sha256,
    'source_root': str(root), 'builder_sha256': digest(__file__), 'modules': modules,
    'paths': len(selected), 'regular_bytes': sum(len(data) for item, data in selected.values()),
    'archive_bytes': archive.stat().st_size, 'archive_sha256': digest(archive),
    'root_only_mode_normalizations': normalized_modes,
    'arm_execution_verified': False, 'complete_initramfs_fit_verified': False,
    'device_operations': False, 'boot_ready': False}
  with (output / 'receipt.json').open('x') as stream:
    json.dump(receipt, stream, indent=2)
    stream.write('\n')
  print(json.dumps(receipt, indent=2))


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--inventory', required=True, type=Path)
  parser.add_argument('--inventory-sha256', required=True)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  prepare(args.inventory, args.inventory_sha256, args.output)


if __name__ == '__main__':
  main()
