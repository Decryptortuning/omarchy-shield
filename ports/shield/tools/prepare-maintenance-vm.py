#!/usr/bin/env python3
"""Prepare a new COW-disk QEMU test; never run it or accept block devices."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import sys

from stock_boot import read_newc, write_newc
from usb_candidate_transaction import validate_plan
from usb_root_profile import admit_payload, digest, host_metadata_execute, require

BUSYBOX_SHA256 = '3f8cea86400f302ca3e798ccabb1c2b2594026c1e6b281ce986de8b79d92d0a8'


def regular(path):
  path = Path(path)
  require(stat.S_ISREG(path.lstat().st_mode), 'Input must be a real regular file')
  return path


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--toolroot', type=Path, required=True)
  parser.add_argument('--payload', type=Path, required=True)
  parser.add_argument('--plan', type=Path, required=True)
  parser.add_argument('--base-image', type=Path, required=True)
  parser.add_argument('--base-image-sha256', required=True)
  parser.add_argument('--kernel', type=Path, required=True)
  parser.add_argument('--base-components', type=Path, required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  image = regular(args.base_image).resolve(strict=True)
  require(digest(image) == args.base_image_sha256, 'Original image hash differs')
  require(image.stat().st_size >= 8 * 1024**3, 'Expected the complete baseline Btrfs image')
  plan = json.loads(regular(args.plan).read_text())
  manifest_path = regular(args.payload / 'manifest.json')
  manifest = json.loads(manifest_path.read_text())
  validate_plan(plan, manifest)
  require(plan['base_image_sha256'] == args.base_image_sha256,
          'Account plan and original image differ')
  admit_payload(manifest, args.payload / 'packages', execute=host_metadata_execute)
  toolroot_receipt = json.loads(regular(args.toolroot / 'receipt.json').read_text())
  toolroot_archive = regular(args.toolroot / 'toolroot.tar.gz')
  require(digest(toolroot_archive) == toolroot_receipt['archive_sha256'], 'Toolroot archive differs')
  require(toolroot_receipt['builder_sha256'] == digest(Path(__file__).with_name('prepare-maintenance-toolroot.py')),
          'Toolroot was built by another producer')
  for name, expected in toolroot_receipt['modules'].items():
    require(digest(Path(__file__).with_name(name)) == expected, 'Toolroot runtime module differs')
  parent = json.loads(regular(args.base_components / 'manifest.json').read_text())
  base_cpio = regular(args.base_components / 'initramfs.cpio.gz')
  require(digest(base_cpio) == parent['artifacts']['initramfs.cpio.gz']['sha256'], 'Base CPIO differs')
  old = read_newc(gzip.decompress(base_cpio.read_bytes()))
  require(hashlib.sha256(old['bin/busybox']['data']).hexdigest() == BUSYBOX_SHA256, 'BusyBox differs')
  entries = {}

  def add(name, mode, data=b'', **extra):
    require(name not in entries, 'CPIO collision: ' + name)
    require(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')), 'Unsafe CPIO name')
    entries[name] = {'mode': mode, 'data': data, 'rdevmajor': 0, 'rdevminor': 0, **extra}

  with tarfile.open(toolroot_archive, 'r:gz') as archive:
    for member in archive:
      require(member.uid == 0 and member.gid == 0, 'Toolroot ownership differs')
      if member.isdir():
        add(member.name, stat.S_IFDIR | member.mode)
      elif member.isfile():
        require(not member.mode & 0o6000, 'Root-only runtime must not contain set-ID files')
        add(member.name, stat.S_IFREG | member.mode, archive.extractfile(member).read())
      elif member.issym():
        add(member.name, stat.S_IFLNK | member.mode, member.linkname.encode())
      else:
        raise ValueError('Unsupported toolroot archive member')
  for name in ['dev', 'proc', 'sys', 'run', 'tmp', 'opt', 'etc', 'bin', 'sbin', 'usr/sbin',
               'opt/maintenance-input', 'opt/maintenance-input/packages']:
    add(name, stat.S_IFDIR | 0o755)
  # Only static BusyBox and its existing applet links; no old drivers, guards,
  # board DT, graphics payload or init is inherited into this VM profile.
  for name, item in old.items():
    if name == 'bin/busybox' or (name.startswith(('bin/', 'usr/bin/')) and stat.S_ISLNK(item['mode'])):
      add(name, item['mode'], item['data'])
  for name in ['poweroff', 'reboot']:
    add('sbin/' + name, stat.S_IFLNK | 0o777, b'../bin/busybox')
  add('dev/console', stat.S_IFCHR | 0o600, rdevmajor=5, rdevminor=1)
  add('dev/null', stat.S_IFCHR | 0o666, rdevmajor=1, rdevminor=3)
  add('etc/mtab', stat.S_IFLNK | 0o777, b'/proc/mounts')
  for source, destination in [(manifest_path, 'manifest.json'), (args.plan, 'plan.json')]:
    add('opt/maintenance-input/' + destination, stat.S_IFREG | 0o600, source.read_bytes())
  for path in sorted((args.payload / 'packages').iterdir()):
    add('opt/maintenance-input/packages/' + path.name, stat.S_IFREG | 0o600, regular(path).read_bytes())
  identity = {'manifest_sha256': digest(manifest_path), 'plan_sha256': digest(args.plan),
              'image_bytes': image.stat().st_size, 'base_image_sha256': args.base_image_sha256}
  add('opt/maintenance-input/vm-identity.json', stat.S_IFREG | 0o600, json.dumps(identity).encode())
  guest = Path(__file__).with_name('maintenance-vm-guest.py')
  add('opt/maintenance-vm.py', stat.S_IFREG | 0o600, guest.read_bytes())
  accounts = Path(__file__).with_name('maintenance_accounts.py')
  add('usr/lib/shield-maintenance/maintenance_accounts.py', stat.S_IFREG | 0o644, accounts.read_bytes())
  init = b'''#!/bin/sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
ln -s /proc/self/fd /dev/fd || exit 1
ln -s fd/0 /dev/stdin || exit 1
ln -s fd/1 /dev/stdout || exit 1
ln -s fd/2 /dev/stderr || exit 1
mount -t tmpfs -o mode=0700 tmpfs /run || exit 1
mv /opt/maintenance-input /run/maintenance-input || exit 1
/usr/bin/python3.14 -I -S -B /opt/maintenance-vm.py
STATUS=$?
echo "SHIELD_MAINTENANCE_VM_EXIT $STATUS"
poweroff -f
while :; do sleep 1; done
'''
  add('init', stat.S_IFREG | 0o700, init)
  require(entries['lib']['data'] == b'usr/lib' and stat.S_ISLNK(entries['lib']['mode']), 'Canonical library alias missing')
  for command in ['chroot', 'mount', 'umount', 'btrfs', 'bsdtar', 'python3.14']:
    require(stat.S_ISREG(entries['usr/bin/' + command]['mode']), 'Actual ARM command missing: ' + command)
  output = args.output
  require(not output.exists() and not output.is_symlink(), 'Output must be a new directory')
  output.mkdir(mode=0o700)
  ramdisk = gzip.compress(write_newc(entries), compresslevel=6, mtime=0)
  require(read_newc(gzip.decompress(ramdisk)) == entries, 'CPIO roundtrip differs')
  (output / 'initramfs.cpio.gz').write_bytes(ramdisk)
  shutil.copyfile(regular(args.kernel / 'Image'), output / 'Image')
  subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'raw', '-b', str(image),
                  str(output / 'test-disk.qcow2')], check=True)
  receipt = {'format_version': 1, 'scope': 'owned QEMU disk derivative only',
    'base_image': str(image), 'base_image_sha256': args.base_image_sha256,
    'image_bytes': image.stat().st_size, 'kernel_sha256': digest(output / 'Image'),
    'toolroot_archive_sha256': toolroot_receipt['archive_sha256'],
    'manifest_sha256': identity['manifest_sha256'], 'plan_sha256': identity['plan_sha256'],
    'guest_sha256': digest(guest), 'builder_sha256': digest(__file__),
    'account_helper_sha256': digest(accounts),
    'initramfs_sha256': digest(output / 'initramfs.cpio.gz'), 'initramfs_bytes': len(ramdisk),
    'initial_overlay_sha256': digest(output / 'test-disk.qcow2'),
    'cpio_paths': len(entries), 'executed': False, 'physical_qualified': False, 'boot_ready': False}
  (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
  print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
  main()
