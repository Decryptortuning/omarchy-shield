"""Actual Btrfs/ALPM test on an owned QEMU disk; never a Shield entrypoint."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, '/usr/lib/shield-maintenance')
from usb_candidate_transaction import base_unchanged, default_subvolume, update_candidate, validate_plan
from usb_root_profile import digest, require, verify_root

DEADLINE = time.monotonic() + 720
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'HOME': '/root'}
from maintenance_accounts import account_preimages


def budget(seconds):
  require(DEADLINE - time.monotonic() >= seconds, 'VM deadline reserve exhausted')


def execute(command):
  budget(25)
  # A process-group timeout supplements the outer QEMU timeout. Neither is a
  # physical watchdog nor a guarantee to cancel blocked kernel I/O.
  print('VM_COMMAND ' + json.dumps(command), flush=True)
  with Path('/run/command.log').open('wb') as log:
    process = subprocess.Popen(command, env=ENV, stdin=subprocess.DEVNULL,
      stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
      status = process.wait(timeout=min(180, DEADLINE - time.monotonic() - 20))
    except subprocess.TimeoutExpired:
      os.killpg(process.pid, signal.SIGKILL)
      try:
        process.wait(timeout=5)
      except subprocess.TimeoutExpired:
        pass
      raise
  with Path('/run/command.log').open('rb') as log:
    log.seek(0, os.SEEK_END)
    log.seek(max(0, log.tell() - 262144))
    output = log.read(262144).decode(errors='replace')
  print(output, end='', flush=True)
  require(status == 0, 'VM command failed: ' + str(status))
  return output


def disk_mounts():
  # This guest owns one virtio disk; no host block devices are passed through.
  return [line for line in Path('/proc/self/mountinfo').read_text().splitlines()
          if ' - btrfs ' in line]


def verify_top_mount(top, readonly):
  mounts = disk_mounts()
  require(len(mounts) == 1, 'Expected one owned Btrfs mount')
  before, after = mounts[0].split(' - ', 1)
  fields, filesystem = before.split(), after.split()
  require(fields[3] == '/' and fields[4] == str(top)
          and filesystem[:2] == ['btrfs', '/dev/vda'], 'Wrong owned top-level mount')
  required = 'ro' if readonly else 'rw'
  require(required in fields[5].split(',') and required in filesystem[2].split(','), 'Mount access differs')
  rescue = [option for option in filesystem[2].split(',') if option.startswith('rescue=')]
  require(rescue == (['rescue=nologreplay'] if readonly else []), 'Mount rescue state differs')


def main():
  require(os.geteuid() == 0, 'VM root required')
  compatible = Path('/proc/device-tree/compatible').read_bytes().split(b'\0')
  require(b'linux,dummy-virt' in compatible, 'QEMU virt only')
  tokens = Path('/proc/cmdline').read_text().split()
  require(tokens.count('shield.maintenance-vm=1') == 1
          and not any(token.startswith('shield.first-ram-probe=') for token in tokens), 'VM-only command line required')
  inputs = Path('/run/maintenance-input')
  manifest = json.loads((inputs / 'manifest.json').read_text())
  plan = json.loads((inputs / 'plan.json').read_text())
  identity = json.loads((inputs / 'vm-identity.json').read_text())
  require(digest(inputs / 'manifest.json') == identity['manifest_sha256'], 'VM manifest differs')
  require(digest(inputs / 'plan.json') == identity['plan_sha256'], 'VM plan differs')
  validate_plan(plan, manifest)
  require(plan['base_image_sha256'] == identity['base_image_sha256'], 'Account plan/image differs')
  device = Path('/dev/vda')
  require(stat.S_ISBLK(device.stat().st_mode), 'Owned virtio test disk absent')
  require(Path('/sys/class/block/vda/size').read_text().strip() == str(identity['image_bytes'] // 512), 'VM disk size differs')
  require(not disk_mounts(), 'Unexpected existing Btrfs mount')
  with device.open('rb', buffering=0) as source:
    superblock = os.pread(source.fileno(), 4096, 65536)
  require(len(superblock) == 4096 and superblock[64:72] == b'_BHRfS_M', 'VM Btrfs superblock absent')
  require(str(uuid.UUID(bytes=superblock[32:48])) == manifest['filesystem_uuid'], 'VM filesystem identity differs')
  require(struct.unpack_from('<Q', superblock, 136)[0] == 1, 'VM requires single device')
  require(struct.unpack_from('<Q', superblock, 96)[0] == 0, 'VM baseline has pending log replay')
  top = Path('/run/usb-top')
  top.mkdir(mode=0o700)
  execute(['/usr/bin/mount', '-t', 'btrfs', '-o', 'ro,rescue=nologreplay,subvolid=5', str(device), str(top)])
  verify_top_mount(top, readonly=True)
  base_unchanged(top, plan)
  # Mandatory for this fresh VM cohort; old plans without account pins fail
  # before any RW mount, snapshot, ALPM command or transaction journal.
  original_accounts = account_preimages(top / '@', plan['base_account_preimages'])
  default = default_subvolume(execute(['/usr/bin/btrfs', 'subvolume', 'get-default', str(top)]))
  execute(['/usr/bin/umount', str(top)])
  require(not disk_mounts(), 'Read-only admission mount remains')
  execute(['/usr/bin/mount', '-t', 'btrfs', '-o', 'rw,subvolid=5', str(device), str(top)])
  verify_top_mount(top, readonly=False)
  result = update_candidate(plan, manifest, inputs / 'packages', top,
                            guard_check=budget, execute=execute)
  require(result['state'] == 'VERIFIED' and not result['boot_ready'], 'Unexpected core result')
  candidate_accounts = account_preimages(top / manifest['subvolumes']['root'],
                                        plan['base_account_preimages'])
  require(candidate_accounts == original_accounts, 'Package phase changed account databases')
  execute(['/usr/bin/btrfs', 'filesystem', 'sync', str(top)])
  execute(['/usr/bin/umount', str(top)])
  require(not disk_mounts(), 'Transaction mount remains')
  execute(['/usr/bin/mount', '-t', 'btrfs', '-o', 'ro,rescue=nologreplay,subvolid=5', str(device), str(top)])
  verify_top_mount(top, readonly=True)
  verify_root(manifest, top / manifest['subvolumes']['root'])
  base_unchanged(top, plan)
  require(account_preimages(top / '@', plan['base_account_preimages']) == original_accounts
          and account_preimages(top / manifest['subvolumes']['root'],
                                plan['base_account_preimages']) == candidate_accounts,
          'Account readback changed across clean unmount')
  require(default_subvolume(execute(['/usr/bin/btrfs', 'subvolume', 'get-default', str(top)])) == default,
          'Original default changed')
  journal = json.loads((top / '.shield-qualification' / manifest['candidate_id'] / 'state.json').read_text())
  require(journal['state'] == 'VERIFIED', 'Durable transaction journal differs')
  execute(['/usr/bin/umount', str(top)])
  require(not disk_mounts(), 'Readback mount remains')
  receipt = {'passed': True, 'scope': 'owned QEMU COW disk only',
    'manifest_sha256': identity['manifest_sha256'], 'plan_sha256': identity['plan_sha256'],
    'actual_btrfs_alpm_transaction': True, 'clean_unmount_and_readonly_readback': True,
    'original_root_profile_and_default_preserved': True,
    'original_account_preimages_verified_before_RW_and_after_clean_unmount': True,
    'package_candidate_account_postimages_equal_original': True,
    'candidate_account_postimages': candidate_accounts,
    'physical_device_or_watchdog_qualified': False, 'boot_ready': False}
  print('SHIELD_MAINTENANCE_VM_RESULT ' + json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException as error:
    print('SHIELD_MAINTENANCE_VM_FAILED ' + repr(error), flush=True)
    raise
