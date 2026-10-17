"""Read-only account preimage admission shared by host plans and VM witness."""
import os
import json
import hashlib
from pathlib import Path
import stat
from usb_root_profile import digest, require

ACCOUNT_NAMES = {'etc/' + name for name in ['passwd', 'group', 'shadow', 'gshadow']}
DESKTOP_GROUPS = frozenset({'audio', 'input', 'render', 'video'})


def account_preimages(root, expected):
  """Check independently pinned original accounts; return full live identities.

  This VM witness grants no native write authority. The physical broker must
  perform its own admission and bind observed postimages to its clean release.
  Password rows are never logged; these are hashes of complete database files.
  """
  require(type(expected) is dict and set(expected) == ACCOUNT_NAMES,
          'Four original account preimages required')
  result = {}
  for name, item in sorted(expected.items()):
    require(type(item) is dict and set(item) == {'sha256', 'bytes', 'mode', 'uid', 'gid'},
            'Wrong account preimage fields')
    require(type(item['sha256']) is str and len(item['sha256']) == 64
            and all(c in '0123456789abcdef' for c in item['sha256'])
            and item['sha256'] != '0' * 64, 'Wrong account preimage digest')
    require(all(type(item[key]) is int for key in ['bytes', 'mode', 'uid', 'gid'])
            and 0 < item['bytes'] <= 1024**2 and item['uid'] == 0
            and 0 <= item['gid'] <= 65535 and 0 <= item['mode'] <= 0o777
            and not item['mode'] & 0o022,
            'Unsafe account preimage metadata')
    # Admission happens inside the sole owned VM mount, before any RW remount.
    # Reject link ancestors as well as special or multiply linked leaf files.
    base = Path(root)
    for parent in [base, base / 'etc']:
      info = parent.lstat()
      require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
              and not info.st_mode & 0o022, 'Unsafe account parent')
    path = base / name
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_size == item['bytes'], 'Unsafe account object')
    actual = {'sha256': digest(path), 'bytes': info.st_size,
      'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    require(actual == item, 'Original account preimage differs')
    result[name] = {**actual, 'type': 'file', 'xattrs': {
      key: os.getxattr(path, key, follow_symlinks=False).hex()
      for key in sorted(os.listxattr(path, follow_symlinks=False))}}
  return result



def original_account_baseline(root, receipt_path, receipt_sha256, image_sha256):
  """Admit exact host bytes witnessed in the immutable original root image.

  The returned provenance contains only paths and hashes, never password rows.
  Raw bytes are kept in memory for the sole new-copy seeder and delta checker.
  This does not admit physical media or authorize an account write on a device.
  """
  for value in [receipt_sha256, image_sha256]:
    require(type(value) is str and len(value) == 64 and value != '0' * 64
            and all(c in '0123456789abcdef' for c in value), 'Invalid original account evidence pin')
  root, receipt_path = Path(root), Path(receipt_path)
  require(root.is_absolute() and receipt_path.is_absolute()
          and not root.is_symlink() and root.resolve(strict=True) == root
          and not receipt_path.is_symlink()
          and receipt_path.parent.resolve(strict=True) == receipt_path.parent,
          'Original account input alias')
  def read_held(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
      before = os.fstat(fd)
      require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
              and 0 < before.st_size <= maximum, 'Unsafe original account input')
      with os.fdopen(os.dup(fd), 'rb') as stream: raw = stream.read(maximum + 1)
      after = os.fstat(fd)
      fields = ['st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns']
      require(all(getattr(before, key) == getattr(after, key) for key in fields)
              and len(raw) == before.st_size, 'Original account input changed')
      return raw, before
    finally: os.close(fd)
  raw, _info = read_held(receipt_path, 1024**2)
  require(hashlib.sha256(raw).hexdigest() == receipt_sha256, 'Original account evidence pin differs')
  def unique(pairs):
    result = {}
    for key, value in pairs:
      require(key not in result, 'Duplicate original account evidence field')
      result[key] = value
    return result
  evidence = json.loads(raw, object_pairs_hook=unique)
  require(type(evidence['format_version']) is int and evidence['format_version'] == 1
          and evidence['scope'] == 'Original immutable host image account evidence only'
          and evidence['image_unchanged'] is True
          and type(evidence['root_id']) is int and evidence['root_id'] == 256
          and evidence['image_sha256'] == image_sha256
          and evidence['actual_physical_USB_preimages_verified'] is False
          and evidence['physical_write_authority'] is False and evidence['boot_ready'] is False,
          'Wrong immutable original account evidence')
  expected = evidence['account_preimages']
  observed = account_preimages(root, expected)
  contents = {}
  for name, item in sorted(expected.items()):
    data, info = read_held(root / name, 1024**2)
    require(hashlib.sha256(data).hexdigest() == item['sha256']
            and len(data) == item['bytes'] and stat.S_IMODE(info.st_mode) == item['mode']
            and info.st_uid == item['uid'] and info.st_gid == item['gid']
            and observed[name]['xattrs'] == {}, 'Original account bytes or metadata differ')
    contents[name] = data
  require(account_preimages(root, expected) == observed
          and read_held(receipt_path, 1024**2)[0] == raw, 'Original account evidence moved')
  provenance = {'rootfs': str(root), 'receipt': str(receipt_path),
    'receipt_sha256': receipt_sha256, 'image_sha256': image_sha256,
    'account_preimages': expected}
  return provenance, contents


def original_baseline_from_record(record):
  require(type(record) is dict and set(record) == {'rootfs', 'receipt', 'receipt_sha256',
          'image_sha256', 'account_preimages'}, 'Wrong original baseline provenance')
  observed, contents = original_account_baseline(record['rootfs'], record['receipt'],
    record['receipt_sha256'], record['image_sha256'])
  require(observed == record, 'Original baseline provenance changed')
  return contents


def validate_accounts(before, after):
  """Exact desired bytes are pinned; additionally reject cross-file privilege drift."""
  def tables(value):
    require(set(value) == ACCOUNT_NAMES, 'All four account databases required')
    result = {}
    for name, width in [('passwd', 7), ('group', 4), ('shadow', 9), ('gshadow', 4)]:
      raw = value['etc/' + name]
      require(type(raw) is bytes and 0 < len(raw) <= 1024**2 and raw.endswith(b'\n')
              and b'\0' not in raw and b'\r' not in raw, 'Malformed account bytes')
      rows = {}
      for line in raw.decode('ascii').splitlines():
        fields = line.split(':')
        require(len(fields) == width and fields[0] and fields[0] not in rows,
                'Malformed or duplicate account row')
        rows[fields[0]] = fields
      result[name] = rows
    return result
  old, new = tables(before), tables(after)
  for name in old:
    require('portbuild' not in old[name] and 'portbuild' not in new[name],
            'Build account cannot enter the original or runtime baseline')
    require('shieldqual' not in old[name] and set(new[name]) == set(old[name]) | {'shieldqual'},
            'Unexpected account addition/removal')
  p, g, s, gs = [new[key] for key in ['passwd', 'group', 'shadow', 'gshadow']]
  require('root' in p and all(group in g for group in DESKTOP_GROUPS)
          and set(p) == set(s) and set(g) == set(gs), 'Account cross-file names differ')
  require(p['shieldqual'] == ['shieldqual', 'x', '1001', '1001', '', '/home/shieldqual', '/bin/bash']
          and g['shieldqual'] == ['shieldqual', 'x', '1001', '']
          and gs['shieldqual'][2:] == ['', ''], 'Wrong qualification identity')
  for fields in p.values():
    require(fields[2].isascii() and fields[2].isdigit() and fields[3].isascii()
            and fields[3].isdigit(), 'Wrong UID/GID syntax')
  require([name for name, row in p.items() if int(row[2]) == 0] == ['root']
          and p['root'][2:4] == ['0', '0']
          and [name for name, row in p.items() if int(row[2]) == 1001] == ['shieldqual'],
          'Duplicate privileged/qualification UID')
  require(all(int(row[2]) != 1001 and int(row[3]) != 1001 for row in old['passwd'].values()),
          'Qualification UID/GID already used by an original account')
  require(all(row[2].isascii() and row[2].isdigit() for row in g.values())
          and [name for name, row in g.items() if int(row[2]) == 1001] == ['shieldqual'],
          'Duplicate qualification GID')
  for name, row in old['passwd'].items():
    require(p[name] == row, 'Existing passwd identity changed')
  for name, row in old['shadow'].items():
    allowed = {1, 2} if name == 'root' else set()
    require(all(s[name][index] == value for index, value in enumerate(row) if index not in allowed),
            'Unrelated shadow fields changed')
  require(all(p[name][1] == 'x' and s[name][1] == '!' for name in ['root', 'shieldqual']),
          'Root/qualification passwords not locked')
  require(s['root'][2].isascii() and s['root'][2].isdigit()
          and 0 <= int(s['root'][2]) <= (1 << 31) - 1, 'Root password date is not bounded')
  for database in ['group', 'gshadow']:
    for name, row in old[database].items():
      wanted = set(row[3].split(',')) - {''}
      if name in DESKTOP_GROUPS: wanted.add('shieldqual')
      members = new[database][name][3].split(',') if new[database][name][3] else []
      require(new[database][name][:3] == row[:3] and len(members) == len(set(members))
              and set(members) == wanted and set(members) <= set(p), 'Unexpected group membership/privilege')
  require({name for name, row in g.items() if 'shieldqual' in row[3].split(',')} == DESKTOP_GROUPS,
          'Qualification supplementary groups differ')

