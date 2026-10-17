"""Read-only account preimage admission shared by host plans and VM witness."""
import os
from pathlib import Path
import stat
from usb_root_profile import digest, require

ACCOUNT_NAMES = {'etc/' + name for name in ['passwd', 'group', 'shadow', 'gshadow']}


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

