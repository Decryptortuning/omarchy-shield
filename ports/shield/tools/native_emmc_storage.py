"""Initial-RAM read-only admission of the enrolled internal UDA Btrfs root.

Normal OWNER only. No partition write, format, mount, BLKROSET, boot/RPMB
access, default-root selection or USB admission change occurs in this module.
The initial PID1 caller still owns actors, namespace and subsequent mounts.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

from native_boot_context import directory, filesystem_magic
from native_root_storage import BLKGETSIZE64, DEVTMPFS_MAGIC, number, rdev, read_sysfs, superblock
from owner_profile import require, validate_emmc


def canonical(value):
  return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def admit_table(rows, expected, boot_store):
  """Admit the exact enrolled active GPT rows, including legitimate empty slots."""
  require(type(rows) is list and 1 <= len(rows) <= 128, 'Internal partition count differs')
  for row in rows:
    require(type(row) is dict and set(row) == {'index', 'start_bytes', 'bytes', 'label'}
            and type(row['index']) is int and 1 <= row['index'] <= 128
            and type(row['start_bytes']) is int and row['start_bytes'] >= 34 * 512
            and type(row['bytes']) is int and row['bytes'] > 0
            and row['start_bytes'] % 512 == row['bytes'] % 512 == 0
            and row['start_bytes'] + row['bytes'] <= expected['disk_bytes']
            and type(row['label']) is str and re.fullmatch('[A-Za-z0-9_-]{1,36}', row['label']),
            'Internal partition record differs')
  indices = [row['index'] for row in rows]
  require(indices == sorted(set(indices))
          and len({row['label'] for row in rows}) == len(rows),
          'Internal partition indices or labels are ambiguous')
  physical = sorted(rows, key=lambda row: row['start_bytes'])
  require(all(left['start_bytes'] + left['bytes'] <= right['start_bytes']
              for left, right in zip(physical, physical[1:])), 'Internal partitions overlap')
  require(hashlib.sha256(canonical(rows)).hexdigest() == expected['partition_table_sha256'],
          'Internal complete partition geometry differs')
  selected = [row for row in rows if row['index'] == expected['partition_index']]
  require(selected == [{'index': expected['partition_index'],
                        'start_bytes': expected['partition_start_bytes'],
                        'bytes': expected['partition_bytes'], 'label': expected['partition_label']}],
          'Internal selected UDA table record differs')
  boot = [row for row in rows if row['index'] == boot_store['partition_index']]
  require(boot == [{'index': boot_store['partition_index'],
                    'start_bytes': boot_store['partition_start_bytes'],
                    'bytes': boot_store['partition_bytes'], 'label': boot_store['partition_label']}],
          'Internal selected APP table record differs')


def controller():
  root = Path('/sys/bus/platform/devices/700b0600.mmc').resolve(strict=True)
  require(root.is_relative_to(Path('/sys/devices'))
          and (root / 'driver').resolve(strict=True) == Path('/sys/bus/platform/drivers/sdhci-tegra')
          and (root / 'of_node').resolve(strict=True) == Path('/sys/firmware/devicetree/base/mmc@700b0600'),
          'Selected internal MMC controller differs')
  return root


def discover(bundle):
  require(bundle.epoch == 'early' and bundle.phase == 'owner', 'Internal discovery requires normal OWNER')
  expected = validate_emmc(bundle.profile['filesystem']['emmc'])
  link = Path('/sys/bus/platform/devices/700b0600.mmc')
  if not link.exists() or not (link / 'driver').exists():
    return None  # Device/driver may still be registering; caller owns the deadline.
  platform = controller()
  matches = []
  for entry in Path('/sys/class/block').iterdir():
    if not re.fullmatch('mmcblk[0-9]+', entry.name):
      continue  # Never boot partitions, RPMB or a partition alias.
    parent = entry.resolve(strict=True)
    if not parent.is_relative_to(platform):
      continue
    card = (parent / 'device').resolve(strict=True)
    require(card.is_relative_to(platform) and read_sysfs(card / 'type') == 'MMC',
            'Internal storage is not the selected MMC card')
    for part in parent.iterdir():
      if (part / 'partition').is_file() and number(part / 'partition') == expected['partition_index']:
        matches.append((part, platform))
  require(len(matches) <= 1, 'Ambiguous internal UDA; never guess')
  return matches[0] if matches else None


class EmmcRoot:
  """Two owned O_RDONLY descriptors, matching the existing MountDomain contract."""
  def __init__(self, bundle, observed):
    require(os.getpid() == 1 and bundle.epoch == 'early' and bundle.phase == 'owner'
            and bundle.profile.get('purpose') == 'omarchy-shield-owner',
            'Internal root admission requires normal initial-RAM PID1')
    self.bundle = bundle
    self.expected = validate_emmc(bundle.profile['filesystem']['emmc'])
    require(bundle.configuration == {'emmc_storage': self.expected}, 'Internal configuration differs')
    self.partition, self.platform = observed
    self.parent = self.partition.parent
    self.fds = []
    self.identities = []
    try:
      self._geometry()
      directory('/dev')
      for node in (self.parent, self.partition):
        fd = os.open(Path('/dev') / node.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.fds.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISBLK(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022 and info.st_rdev == rdev(node)
                and filesystem_magic(fd) == DEVTMPFS_MAGIC, 'Internal block descriptor differs')
        self.identities.append((info.st_dev, info.st_ino, info.st_rdev))
      self.verify_superblock()
    except BaseException:
      self.close()
      raise

  def _geometry(self):
    expected = self.expected
    require(controller() == self.platform and self.parent.is_relative_to(self.platform)
            and self.partition.parent == self.parent
            and re.fullmatch('mmcblk[0-9]+', self.parent.name), 'Internal controller ancestry changed')
    card = (self.parent / 'device').resolve(strict=True)
    require(card.is_relative_to(self.platform) and read_sysfs(card / 'type') == 'MMC',
            'Internal MMC card type changed')
    cid = read_sysfs(card / 'cid')
    require(re.fullmatch('[0-9a-f]{32}', cid)
            and hashlib.sha256(cid.encode('ascii')).hexdigest() == expected['cid_sha256'],
            'Internal card identity differs')
    rows = []
    for part in self.parent.iterdir():
      if not (part / 'partition').is_file():
        continue
      require(part.resolve(strict=True) == part and part.parent == self.parent,
              'Internal partition path differs')
      fields = [line.split('=', 1) for line in read_sysfs(part / 'uevent').splitlines()]
      labels = [row[1] for row in fields if len(row) == 2 and row[0] == 'PARTNAME']
      require(len(labels) == 1 and re.fullmatch('[A-Za-z0-9_-]{1,36}', labels[0]),
              'Internal partition label differs')
      rows.append({'index': number(part / 'partition'), 'start_bytes': 512 * number(part / 'start'),
                   'bytes': 512 * number(part / 'size'), 'label': labels[0]})
    rows.sort(key=lambda row: row['index'])
    admit_table(rows, expected, self.bundle.profile['boot_store'])
    require(number(self.partition / 'partition') == expected['partition_index']
            and 512 * number(self.partition / 'start') == expected['partition_start_bytes']
            and 512 * number(self.partition / 'size') == expected['partition_bytes']
            and 512 * number(self.parent / 'size') == expected['disk_bytes'],
            'Internal selected UDA geometry changed')
    for node in (self.parent, self.partition):
      require(not os.listdir(node / 'holders'), 'Internal root has a foreign block holder')

  def check(self):
    require(len(self.fds) == len(self.identities) == 2, 'Closed internal block ownership')
    self._geometry()
    for node, fd, identity, size in zip((self.parent, self.partition), self.fds, self.identities,
        (self.expected['disk_bytes'], self.expected['partition_bytes']), strict=True):
      actual = os.fstat(fd)
      live = (Path('/dev') / node.name).lstat()
      require(stat.S_ISBLK(live.st_mode)
              and (actual.st_dev, actual.st_ino, actual.st_rdev) == identity
              and (live.st_dev, live.st_ino, live.st_rdev) == identity
              and actual.st_rdev == rdev(node), 'Internal block descriptor was replaced')
      output = bytearray(8)
      fcntl.ioctl(fd, BLKGETSIZE64, output, True)
      require(struct.unpack('<Q', output)[0] == size, 'Internal block size differs')

  def require_unmounted(self):
    devices = {f'{os.major(item[2])}:{os.minor(item[2])}' for item in self.identities}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
      before, after = line.split(' - ', 1)
      fields, filesystem = before.split(), after.split()
      require(len(fields) >= 6 and len(filesystem) == 3, 'Internal mount observation differs')
      require(fields[2] not in devices and filesystem[0] != 'btrfs',
              'Internal root or another Btrfs filesystem is already mounted')

  def verify_superblock(self):
    self.check()
    self.require_unmounted()
    superblock(os.pread(self.fds[1], 4096, 65536),
               self.bundle.profile['filesystem']['uuid'], self.expected['partition_bytes'])

  def close(self):
    fds, self.fds = self.fds, []
    for fd in fds:
      os.close(fd)
