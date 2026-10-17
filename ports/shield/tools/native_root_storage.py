"""Read-only admission of the selected physical USB Btrfs root.

No mount, RW transition, package install or reboot occurs here. Retained block
fds and repeated identity checks supplement the caller's exclusive initial-RAM
actor/mount ownership; they do not magically sandbox privileged code. Only the
USB device's Btrfs primary superblock is read. Internal MMC is never opened.
"""
import array
import fcntl
import os
from pathlib import Path
import stat
import struct
import uuid

from native_boot_context import USB_STORAGE, directory, filesystem_magic
from usb_root_profile import require

BLKGETSIZE64, BLKROSET, BLKROGET = 0x80081272, 0x125d, 0x125e
SYSFS_MAGIC, DEVTMPFS_MAGIC = 0x62656572, 0x01021994


def read_sysfs(path):
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    require(filesystem_magic(fd) == SYSFS_MAGIC, 'USB observation is outside sysfs')
    raw = os.read(fd, 4097)
    require(0 < len(raw) <= 4096 and b'\0' not in raw, 'Wrong USB sysfs record')
    return raw.decode('ascii').strip()
  finally: os.close(fd)


def number(path):
  value = read_sysfs(path)
  require(value.isascii() and value.isdigit() and len(value) <= 20,
          'Wrong unsigned USB sysfs integer')
  result = int(value)
  require(result <= 0xffffffffffffffff, 'USB sysfs integer overflow')
  return result


def rdev(path):
  value = read_sysfs(path / 'dev').split(':')
  require(len(value) == 2 and all(part.isascii() and part.isdigit() for part in value),
          'Wrong USB block device number')
  return os.makedev(*map(int, value))


def usb_ancestor(path, expected):
  usb = host = None
  for ancestor in [path, *path.parents]:
    vendor, product = ancestor / 'idVendor', ancestor / 'idProduct'
    if vendor.is_file() and product.is_file() and usb is None:
      if {'vendor': read_sysfs(vendor), 'product': read_sysfs(product)} == expected:
        usb = ancestor
      else:
        return None  # Nearest USB device differs; never adopt its root hub.
    driver = ancestor / 'driver'
    if driver.is_symlink() and driver.resolve(strict=True).name == 'tegra-xusb':
      compatible = ancestor / 'of_node/compatible'
      if b'nvidia,tegra210-xusb' in compatible.read_bytes().split(b'\0'):
        host = ancestor
  return (usb, host) if usb is not None and host is not None else None


def discover(bundle):
  """One current sysfs snapshot; the PID1 caller owns bounded uevent waiting."""
  require(bundle.epoch == 'early', 'Only initial RAM admits an unmounted USB root')
  matches = []
  for entry in Path('/sys/class/block').iterdir():
    node = entry.resolve(strict=True)
    require(node.is_relative_to(Path('/sys/devices')), 'Block class escapes devices')
    if not (node / 'partition').is_file(): continue
    ancestry = usb_ancestor(node, bundle.profile['filesystem']['usb'])
    if ancestry is not None: matches.append((node, ancestry))
  require(len(matches) <= 1, 'Multiple selected USB partitions; never guess')
  return matches[0] if matches else None


def crc32c(data):
  crc = 0xffffffff
  for byte in data:
    crc ^= byte
    for _bit in range(8): crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
  return crc ^ 0xffffffff


def superblock(raw, expected_uuid, maximum_bytes):
  require(type(raw) is bytes and len(raw) == 4096 and raw[64:72] == b'_BHRfS_M'
          and raw[4:32] == b'\0' * 28 and struct.unpack_from('<H', raw, 196)[0] == 0
          and struct.unpack_from('<I', raw)[0] == crc32c(raw[32:]),
          'USB primary superblock checksum/type differs')
  require(str(uuid.UUID(bytes=raw[32:48])) == expected_uuid
          and struct.unpack_from('<Q', raw, 48)[0] == 65536
          and struct.unpack_from('<Q', raw, 136)[0] == 1
          and struct.unpack_from('<Q', raw, 96)[0] == 0,
          'USB Btrfs identity/device count/log replay differs')
  total, used = struct.unpack_from('<QQ', raw, 112)
  require(0 < used <= total <= maximum_bytes, 'USB Btrfs geometry differs')


class USBRoot:
  """Two owned O_RDONLY fds; no O_EXCL claim which would prevent mounting.

  Do not describe this as kernel-enforced exclusive mount ownership. The fixed
  PID1 supervisor must account for every actor, mount and descendant separately.
  """

  def __init__(self, bundle, observed):
    require(bundle.epoch == 'early' and bundle.configuration['usb_storage'] == USB_STORAGE,
            'Wrong USB admission context')
    self.bundle = bundle
    self.partition, self.ancestry = observed
    self.parent = self.partition.parent
    self.fds = []
    self.identities = []
    self.ro_attempted = False
    try:
      self._geometry()
      directory('/dev')
      for node in [self.parent, self.partition]:
        fd = os.open(Path('/dev') / node.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.fds.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISBLK(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022 and info.st_rdev == rdev(node)
                and filesystem_magic(fd) == DEVTMPFS_MAGIC, 'Wrong owned USB block node')
        self.identities.append((info.st_dev, info.st_ino, info.st_rdev))
      self.check()
      self.verify_superblock()
    except BaseException:
      self.close()
      raise

  def _geometry(self):
    require(self.partition.is_relative_to(Path('/sys/devices'))
            and usb_ancestor(self.partition, self.bundle.profile['filesystem']['usb']) == self.ancestry,
            'Selected USB ancestry changed')
    partitions = [p for p in self.parent.iterdir() if p.is_dir() and (p / 'partition').is_file()]
    require(partitions == [self.partition]
            and number(self.partition / 'partition') == USB_STORAGE['partition_index']
            and 512 * number(self.partition / 'start') == USB_STORAGE['partition_start_bytes']
            and 512 * number(self.partition / 'size') == USB_STORAGE['partition_bytes']
            and 512 * number(self.parent / 'size') == USB_STORAGE['disk_bytes'],
            'Selected USB partition/geometry changed')
    for node in [self.parent, self.partition]:
      require(not os.listdir(node / 'holders'), 'USB block has another holder')

  def check(self):
    require(len(self.fds) == len(self.identities) == 2, 'Closed or incomplete USB ownership')
    self._geometry()
    for node, fd, identity, size in zip([self.parent, self.partition], self.fds,
        self.identities, [USB_STORAGE['disk_bytes'], USB_STORAGE['partition_bytes']], strict=True):
      actual = os.fstat(fd)
      live = (Path('/dev') / node.name).lstat()
      require(stat.S_ISBLK(live.st_mode)
              and (actual.st_dev, actual.st_ino, actual.st_rdev) == identity
              and (live.st_dev, live.st_ino, live.st_rdev) == identity
              and actual.st_rdev == rdev(node), 'USB block descriptor/node changed')
      output = bytearray(8)
      fcntl.ioctl(fd, BLKGETSIZE64, output, True)
      require(struct.unpack('<Q', output)[0] == size, 'USB block size readback differs')

  def require_unmounted(self):
    devices = {f'{os.major(identity[2])}:{os.minor(identity[2])}' for identity in self.identities}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
      before, after = line.split(' - ', 1)
      fields, filesystem = before.split(), after.split()
      require(len(fields) >= 6 and len(filesystem) == 3, 'Wrong native mount observation')
      # Btrfs subvolumes use anonymous mount st_dev values, NOT their physical
      # source rdev. Any Btrfs mount in this initial RAM ownership domain blocks
      # unmounted admission/release; do not miss it by comparing field2 alone.
      require(fields[2] not in devices and filesystem[0] != 'btrfs',
              'USB block or another Btrfs filesystem still mounted')

  def verify_superblock(self):
    self.check()
    self.require_unmounted()
    superblock(os.pread(self.fds[1], 4096, 65536),
               self.bundle.profile['filesystem']['uuid'], USB_STORAGE['partition_bytes'])

  def restrict_readonly(self):
    """After caller-proven unmount/reap only; never clears restrictive state."""
    require(not self.ro_attempted, 'USB restriction attempt cannot replay')
    self.ro_attempted = True  # Any partial/uncertain failure consumes the attempt.
    self.check()
    self.require_unmounted()
    for fd in reversed(self.fds):
      one = array.array('i', [1])
      fcntl.ioctl(fd, BLKROSET, one, True)  # No clearing, rollback or retry.
      actual = array.array('i', [0])
      fcntl.ioctl(fd, BLKROGET, actual, True)
      require(actual[0] == 1, 'USB read-only restriction did not read back')
    self.verify_superblock()

  def close(self):
    for descriptor in self.fds: os.close(descriptor)
    self.fds.clear()
