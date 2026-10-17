#!/usr/bin/env python3
"""Pack an admitted host qualification layer; never write a device or root."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile

from usb_root_profile import digest, file_identity, require, rooted

TOOLS = Path(__file__).resolve().parent
PORT = TOOLS.parent
SPEC = importlib.util.spec_from_file_location('qualification_layer_host_admission', TOOLS / 'prepare-systemd-vm.py')
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
PURPOSE = 'host-only exact native qualification layer'
ACCOUNTS = {'etc/' + name for name in ['passwd', 'group', 'shadow', 'gshadow']}
HOME = 'home/shieldqual'
RUNTIME = 'usr/lib/omarchy/shield/qualification'


def inventory(root, prepared, installation):
  """Desired postimages only: no physical preimage or write authority."""
  roles = {}
  def add(name, role):
    roles.setdefault(name, set()).add(role)
  for name in ACCOUNTS: add(name, 'account')
  for name in prepared['applied_files']: add(name, 'overlay')
  for name in prepared['service_masks']: add('etc/systemd/system/' + name, 'mask')
  for name in installation['installed_files']: add(RUNTIME + '/' + name, 'runtime')
  add(HOME, 'home')
  for name in prepared['home_files']: add(HOME + '/' + name, 'home')
  add('etc/machine-id', 'machine-id')
  dbus = root / 'var/lib/dbus/machine-id'
  if dbus.exists() or dbus.is_symlink(): add('var/lib/dbus/machine-id', 'dbus-identity')
  for name in list(roles):
    for parent in Path(name).parents:
      if str(parent) != '.': add(str(parent), 'ancestor')
  require(len(roles) <= 12000, 'Excessive layer inventory')
  result = {}
  regular_bytes, xattr_hex_bytes = 0, 0
  for name, purposes in sorted(roles.items()):
    path = rooted(root, name)
    item = file_identity(root, name)
    require(item['type'] in {'file', 'directory', 'symlink'}, 'Unexpected layer object')
    if 'ancestor' in purposes: require(item['type'] == 'directory', 'Unsafe layer ancestor')
    if item['type'] == 'file':
      require(path.lstat().st_nlink == 1, 'Shared layer file')
      require(item['bytes'] <= 32 * 1024**2, 'Excessive individual layer file')
      regular_bytes += item['bytes']
      require(regular_bytes <= 256 * 1024**2, 'Excessive total layer bytes')
    require(not item['mode'] & 0o6000, 'Privileged mode in layer')
    require(len(item['xattrs']) <= 16 and sum(len(value) for value in item['xattrs'].values()) <= 131072,
            'Excessive layer extended attributes')
    xattr_hex_bytes += sum(len(value) for value in item['xattrs'].values())
    require(xattr_hex_bytes <= 4 * 1024**2, 'Excessive total layer extended attributes')
    if name == 'etc/polkit-1/rules.d':
      # The admitted Arch polkit parent is root:polkitd (GID102), 0750.
      # This is an ancestor precondition, not authority to chown it on USB.
      require(purposes == {'ancestor'} and item['type'] == 'directory'
              and (item['uid'], item['gid'], item['mode']) == (0, 102, 0o750),
              'Polkit ancestor identity differs')
    else:
      require(item['uid'] == item['gid'] == (1001 if name == HOME or name.startswith(HOME + '/') else 0),
              'Unexpected layer ownership')
    result[name] = {'identity': item, 'roles': sorted(purposes)}
  require(len(result) <= 12000, 'Excessive layer inventory')
  require(rooted(root, 'etc/machine-id').read_bytes() == b'', 'Host machine identity must not be packed')
  return result


def pack(root, entries, manifest, output):
  """Only regular content-addressed members, never destination path members."""
  canonical = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
  require(len(canonical) <= 16 * 1024**2, 'Excessive layer manifest')
  seen = set()
  with output.open('xb') as raw:
    with gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0, compresslevel=6) as compressed:
      with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
        def member(name, data):
          info = tarfile.TarInfo(name)
          info.uid = info.gid = info.mtime = 0
          info.mode = 0o600; info.size = len(data)
          archive.addfile(info, io.BytesIO(data))
        member('manifest.json', canonical)
        for name, record in entries.items():
          item = record['identity']
          require(file_identity(root, name) == item, 'Layer source moved before packing')
          if item['type'] != 'file' or item['sha256'] in seen: continue
          descriptor = os.open(rooted(root, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
          with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Layer source type moved')
            data = stream.read(item['bytes'] + 1)
          require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256']
                  and file_identity(root, name) == item, 'Layer source bytes or metadata moved')
          member('blobs/' + item['sha256'], data)
          seen.add(item['sha256'])
    raw.flush(); os.fsync(raw.fileno())
  return hashlib.sha256(canonical).hexdigest(), len(seen)


def verify_pack(path, manifest):
  """Read back this trusted USTAR producer without extracting paths.

  This is not an untrusted native archive parser: tarfile normalizes extension
  headers and EOF handling. A future physical receiver needs its own reviewed
  bounded parser and admission before accepting any archive.
  """
  canonical = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
  expected = {}
  for record in manifest['entries'].values():
    item = record['identity']
    if item['type'] == 'file':
      name = 'blobs/' + item['sha256']
      require(name not in expected or expected[name] == item['bytes'], 'Conflicting blob size')
      expected[name] = item['bytes']
  require(len(canonical) <= 16 * 1024**2 and sum(expected.values()) <= 256 * 1024**2,
          'Excessive layer readback')
  seen = set()
  with tarfile.open(path, mode='r|gz') as archive:
    for item in archive:
      require(item.name not in seen and item.isfile() and not item.pax_headers
              and item.uid == item.gid == item.mtime == 0 and item.mode == 0o600,
              'Unexpected layer archive member')
      require(item.name == 'manifest.json' or item.name in expected, 'Undeclared layer blob')
      length = len(canonical) if item.name == 'manifest.json' else expected[item.name]
      require(item.size == length and 0 <= length <= 32 * 1024**2, 'Layer member size differs')
      with archive.extractfile(item) as stream: data = stream.read(length + 1)
      require(len(data) == length, 'Truncated layer member')
      if item.name == 'manifest.json': require(data == canonical, 'Layer manifest differs')
      else: require(hashlib.sha256(data).hexdigest() == item.name[6:], 'Layer blob differs')
      seen.add(item.name)
  require(seen == set(expected) | {'manifest.json'}, 'Missing layer archive members')


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  for name in ['installation', 'prepared', 'payload-manifest', 'output']:
    parser.add_argument('--' + name, type=Path, required=True)
  for name in ['installation-receipt-sha256', 'prepared-receipt-sha256', 'payload-manifest-sha256']:
    parser.add_argument('--' + name, required=True)
  args = parser.parse_args()
  HOST.PREPARER.wsl_root()
  payload = HOST.PREPARER.matched_json(args.payload_manifest, args.payload_manifest_sha256)
  _source, prepared = HOST.ACTOR.prepared_root(args.prepared, args.prepared_receipt_sha256,
                                            payload, args.payload_manifest_sha256)
  root, installation, profile = HOST.admit_installation(args.installation,
    args.installation_receipt_sha256, prepared, payload, args.payload_manifest_sha256)
  require(installation['prepared_receipt_sha256'] == args.prepared_receipt_sha256, 'Prepared ancestor differs')
  names = HOST.SOURCES | HOST.ACTOR.SOURCE_NAMES | {'tools/prepare-native-qualification-layer.py',
    'tools/install-qualification-artifacts.py', 'tools/stock_boot.py', 'chroot.sh'}
  sources = {name: digest(PORT / name) for name in sorted(names)}
  entries = inventory(root, prepared, installation)
  manifest = {'format_version': 1, 'purpose': PURPOSE, 'state': 'HOST_LAYER_PREPARED',
    'payload_manifest_sha256': args.payload_manifest_sha256,
    'prepared_receipt_sha256': args.prepared_receipt_sha256,
    'installation_receipt_sha256': args.installation_receipt_sha256,
    'profile_sha256': installation['profile_sha256'], 'filesystem': profile['filesystem'],
    'sources': sources, 'entries': entries, 'copy_exclusion_requirements': prepared['copy_exclusions'],
    'xattrs_provenance': 'new exact observation from admitted host root; native application requires separate review',
    'physical_preimages_admitted': False, 'physical_write_released': False, 'boot_ready': False,
    'required_before_native_apply': ['reviewed actual phase-A postimages',
      'phase-A clean USB release and observed authenticated recovery receipt',
      'fresh role1 guardian and exclusive phase-B journal',
      'exact account/home/exclusion/parent preimage admission'],
    'required_after_native_apply': ['full prepared/installed layer and matched package readback',
      'original roots and default selection unchanged', 'clean USB release and observed authenticated recovery']}
  output = args.output.parent.resolve(strict=True) / args.output.name
  require(not output.exists() and not output.is_symlink(), 'Output must be new; preserve failures')
  for source in [args.installation.resolve(strict=True), args.prepared.resolve(strict=True),
                 args.payload_manifest.resolve(strict=True).parent]:
    require(not output.is_relative_to(source) and not source.is_relative_to(output), 'Input/output overlap')
  require(output.parent.stat().st_dev == root.stat().st_dev == Path('/').stat().st_dev,
          'Native WSL filesystem required')
  output.mkdir(mode=0o700)
  (output / 'ATTEMPTED').write_text('Host artifact preparation only; never retry this derivative.\n')
  manifest_sha, blobs = pack(root, entries, manifest, output / 'layer.tar.gz')
  verify_pack(output / 'layer.tar.gz', manifest)
  require(inventory(root, prepared, installation) == entries, 'Layer source moved after packing')
  HOST.admit_installation(args.installation, args.installation_receipt_sha256,
                         prepared, payload, args.payload_manifest_sha256)
  require(digest(args.prepared / 'receipt.json') == args.prepared_receipt_sha256
          and digest(args.payload_manifest) == args.payload_manifest_sha256,
          'Prepared receipt or payload manifest moved')
  require(all(digest(PORT / name) == value for name, value in sources.items()), 'Layer source closure moved')
  receipt = {'format_version': 1, 'purpose': PURPOSE, 'state': 'HOST_LAYER_PREPARED',
    'sources': sources, 'manifest_sha256': manifest_sha,
    'archive_sha256': digest(output / 'layer.tar.gz'), 'archive_bytes': (output / 'layer.tar.gz').stat().st_size,
    'entries': len(entries), 'unique_regular_blobs': blobs,
    'physical_preimages_admitted': False, 'physical_USB_changed': False,
    'archive_readback_scope': 'own fixed USTAR producer only; untrusted native parser not implemented',
    'native_materializer_implemented': False, 'boot_ready': False}
  descriptor = os.open(output / 'receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(descriptor, 'w') as stream:
    stream.write(json.dumps(receipt, indent=2) + '\n'); stream.flush(); os.fsync(stream.fileno())
  for directory in [output, output.parent]:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
  print('Prepared private host layer only; no device/root installation or boot selection.')


if __name__ == '__main__':
  main()
