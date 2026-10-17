#!/usr/bin/env python3
"""Build a new isolated Btrfs/full-system ARM VM; never run or install it."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess

from guardian_binding import IMAGE_SHA256, INSTALL
from stock_boot import read_newc, write_newc
from systemd_vm_profile import MARKER, PREFIX, PURPOSE, SOURCES, USER_PREFIX, validate_identity
from usb_root_profile import digest, require

TOOLS = Path(__file__).resolve().parent
PORT = TOOLS.parent
SPEC = importlib.util.spec_from_file_location('qualification_installer', TOOLS / 'install-qualification-artifacts.py')
ACTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACTOR)
PREPARER = ACTOR.PREPARER
BUSYBOX_SHA256 = '3f8cea86400f302ca3e798ccabb1c2b2594026c1e6b281ce986de8b79d92d0a8'
IMAGE_BYTES = 24 * 1024**3


def admit_installation(directory, expected, prepared, payload, payload_sha):
  PREPARER.locked_directory(directory)
  record = PREPARER.matched_json(directory / 'receipt.json', expected)
  require(record['format_version'] == 1 and record['purpose'] == 'new host-only runtime installation'
          and record['payload_manifest_sha256'] == payload_sha, 'Wrong installed root receipt')
  for key in ['source_root_unchanged', 'matched_payload_verified_after_installation',
              'default_selection_unchanged', 'guardian_installed_into_host_copy']:
    require(record[key] is True, 'Incomplete installation proof')
  for key in ['enabled_guardian_executed', 'physical_USB_changed', 'boot_ready', 'native_qualified']:
    require(record[key] is False, 'Wrong installed root release state')
  expected_sources = {str(TOOLS / name) for name in ['install-qualification-artifacts.py',
    'prepare-qualification-root.py', 'guardian_binding.py', 'usb_root_profile.py', 'qualification_profile.py']}
  require(set(record['source_inputs']) == expected_sources
          and all(digest(path) == value for path, value in record['source_inputs'].items()),
          'Installation producer/consumer moved')
  root = PREPARER.real_directory(directory / 'rootfs')
  ACTOR.verify_prepared(root, prepared, payload)
  require(ACTOR.account_hashes(root) == record['account_databases_sha256'], 'Installed account databases changed')
  destination = root / str(INSTALL).lstrip('/')
  require(set(record['installed_files']) == ACTOR.RUNTIME | {'profile.json', 'artifacts.json'}
          and set(os.listdir(destination)) == set(record['installed_files']), 'Installed file closure differs')
  for name, item in record['installed_files'].items():
    path = destination / name; info = PREPARER.regular(path)
    require(item == {'sha256': digest(path), 'bytes': info.st_size,
      'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}, 'Installed readback differs')
  metadata, profile = ACTOR.artifact_inputs(destination, record['artifact_manifest_sha256'],
      record['profile_sha256'], payload, prepared)
  require(digest(root / 'usr/lib/omarchy/shield/kernel/Image') == IMAGE_SHA256, 'Installed kernel differs')
  for path in [PREFIX, USER_PREFIX]:
    require(not (root / str(path).lstrip('/')).exists(), 'VM fixture already present')
  return root, record, profile


def make_initramfs(components, filesystem, handoff):
  parent = json.loads((components / 'manifest.json').read_text())
  archive = components / 'initramfs.cpio.gz'
  require(digest(archive) == parent['artifacts']['initramfs.cpio.gz']['sha256'], 'BusyBox parent differs')
  old = read_newc(gzip.decompress(archive.read_bytes()))
  busybox = old['bin/busybox']['data']
  require(hashlib.sha256(busybox).hexdigest() == BUSYBOX_SHA256, 'BusyBox source differs')
  entries = {}
  def add(name, mode, data=b'', **extra):
    require(name not in entries, 'CPIO collision')
    entries[name] = {'mode': mode, 'data': data, 'rdevmajor': 0, 'rdevminor': 0, **extra}
  for name in ['bin', 'sbin', 'dev', 'proc', 'sys', 'run', 'newroot']:
    add(name, stat.S_IFDIR | 0o755)
  add('bin/busybox', stat.S_IFREG | 0o755, busybox)
  for name in ['sh', 'mount', 'mkdir', 'grep', 'tr', 'sleep', 'poweroff']:
    add('bin/' + name, stat.S_IFLNK | 0o777, b'busybox')
  add('dev/console', stat.S_IFCHR | 0o600, rdevmajor=5, rdevminor=1)
  add('dev/null', stat.S_IFCHR | 0o666, rdevmajor=1, rdevminor=3)
  add('bin/vm-switch-root', stat.S_IFREG | 0o700, handoff)
  root = filesystem['subvolumes']['root']
  init = '''#!/bin/sh
PATH=/bin
export PATH
set -eu
fail() { echo SHIELD_SYSTEMD_VM_INIT_FAIL; poweroff -f; while :; do sleep 1; done; }
mount -t proc proc /proc || fail
mount -t sysfs sysfs /sys || fail
mount -t devtmpfs devtmpfs /dev || fail
mount -t tmpfs -o mode=0755 tmpfs /run || fail
tr '\\000' '\\n' < /proc/device-tree/compatible | grep -qx 'linux,dummy-virt' || fail
count=0
for token in $(cat /proc/cmdline); do
  case "$token" in
    shield.systemd-vm=1) count=$((count + 1));;
    shield.systemd-vm=*|shield.first-ram-probe=*) fail;;
  esac
done
[ "$count" = 1 ] || fail
count=0
while [ ! -b /dev/vda ]; do
  count=$((count + 1)); [ "$count" -lt 30 ] || fail; sleep 1
done
mount -t btrfs -o rw,subvol=ROOT_VOLUME /dev/vda /newroot || fail
exec /bin/vm-switch-root
'''.replace('ROOT_VOLUME', root).replace('$(cat /proc/cmdline)', '$(/bin/busybox cat /proc/cmdline)')
  add('init', stat.S_IFREG | 0o700, init.encode())
  data = gzip.compress(write_newc(entries), compresslevel=6, mtime=0)
  require(read_newc(gzip.decompress(data)) == entries, 'CPIO roundtrip differs')
  return data


def write_file(root, relative, data, mode):
  path = PREPARER.parents(root, relative)
  require(not path.exists() and not path.is_symlink(), 'VM destination already exists')
  descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
  with os.fdopen(descriptor, 'wb') as stream:
    stream.write(data); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
  return path


def new_directory(path, mode):
  # The host output stays private, while guest directories have exact declared
  # modes. mkdir(mode) alone is filtered by a private build-host umask.
  path.mkdir(mode=mode)
  descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    os.fchmod(descriptor, mode)
  finally:
    os.close(descriptor)
  return path


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  for name in ['installation', 'prepared', 'payload-manifest', 'base-components', 'output']:
    parser.add_argument('--' + name, type=Path, required=True)
  for name in ['installation-receipt-sha256', 'prepared-receipt-sha256', 'payload-manifest-sha256']:
    parser.add_argument('--' + name, required=True)
  args = parser.parse_args()
  PREPARER.wsl_root()
  def interrupted(_signum, _frame):
    raise InterruptedError('Owned VM construction interrupted')
  signal.signal(signal.SIGTERM, interrupted)
  payload = PREPARER.matched_json(args.payload_manifest, args.payload_manifest_sha256)
  _source, prepared = ACTOR.prepared_root(args.prepared, args.prepared_receipt_sha256,
                                         payload, args.payload_manifest_sha256)
  source, installation, profile = admit_installation(args.installation,
      args.installation_receipt_sha256, prepared, payload, args.payload_manifest_sha256)
  require(installation['prepared_receipt_sha256'] == args.prepared_receipt_sha256, 'Prepared ancestor differs')
  output = args.output.parent.resolve(strict=True) / args.output.name
  require(not output.exists() and not output.is_symlink(), 'Output must be new; preserve failed derivatives')
  for path in [args.installation.resolve(strict=True), args.prepared.resolve(strict=True),
               args.payload_manifest.resolve(strict=True).parent, args.base_components.resolve(strict=True)]:
    require(not output.is_relative_to(path) and not path.is_relative_to(output), 'Input/output overlap')
  require(output.parent.stat().st_dev == source.stat().st_dev == Path('/').stat().st_dev, 'Use native WSL filesystem')
  hashes = {name: digest(PORT / name) for name in SOURCES}
  output.mkdir(mode=0o700)
  (output / 'ATTEMPTED').write_text('VM construction is one attempt; preserve failures.\n')
  def run(argv, log_name, seconds=900):
    with (output / log_name).open('xb') as log:
      process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}, start_new_session=True)
      try:
        status = process.wait(timeout=seconds)
      except BaseException:
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=3)
        except subprocess.TimeoutExpired:
          try: os.killpg(process.pid, signal.SIGKILL)
          except ProcessLookupError: pass
          process.wait(timeout=3)
        raise
      require(status == 0, 'Owned VM construction command failed; retain derivative')
  binary = output / 'uid-probe'
  run(['aarch64-linux-gnu-gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
       '-Wl,--build-id=none', str(PORT / 'qualification/vm-uid-probe.c'), '-o', str(binary)], 'uid-build.log')
  binary.chmod(0o700); ACTOR.static_arm(binary)
  handoff = output / 'vm-switch-root'
  run(['aarch64-linux-gnu-gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
       '-Wl,--build-id=none', str(PORT / 'qualification/vm-switch-root.c'), '-o', str(handoff)], 'handoff-build.log')
  handoff.chmod(0o700); ACTOR.static_arm(handoff)
  initramfs = make_initramfs(args.base_components, profile['filesystem'], handoff.read_bytes())
  identity = validate_identity({'format_version': 1, 'purpose': PURPOSE, 'marker': MARKER,
    'kernel': {'release': '7.1.0-shield-bringup', 'sha256': IMAGE_SHA256},
    'filesystem': {'uuid': profile['filesystem']['uuid'], 'subvolumes': profile['filesystem']['subvolumes']},
    'payload_manifest_sha256': args.payload_manifest_sha256,
    'prepared_receipt_sha256': args.prepared_receipt_sha256,
    'installation_receipt_sha256': args.installation_receipt_sha256,
    'native_profile_sha256': installation['profile_sha256'], 'sources': hashes,
    'uid_probe': {'sha256': digest(binary), 'bytes': binary.stat().st_size}})
  seed = new_directory(output / 'seed', 0o700)
  root = new_directory(seed / profile['filesystem']['subvolumes']['root'], 0o755)
  with (output / 'copy.log').open('xb') as log: ACTOR.copy_root(source, root, log)
  for name, mode in [('dev', 0o755), ('proc', 0o755), ('sys', 0o755), ('run', 0o755),
                     ('tmp', 0o1777), ('root', 0o700), ('mnt', 0o755), ('media', 0o755)]:
    path = root / name; path.mkdir(exist_ok=True); path.chmod(mode)
  ACTOR.verify_prepared(root, prepared, payload)
  private = new_directory(root / str(PREFIX).lstrip('/'), 0o700)
  public = new_directory(root / str(USER_PREFIX).lstrip('/'), 0o755)
  for origin, target, mode in [(TOOLS / 'systemd-vm-guest.py', private / 'guest.py', 0o644),
      (TOOLS / 'systemd_vm_profile.py', private / 'systemd_vm_profile.py', 0o644),
      (PORT / 'qualification/vm-user-probe.py', public / 'user-probe.py', 0o644),
      (binary, public / 'uid-probe', 0o4755),
      (args.payload_manifest, private / 'payload-manifest.json', 0o600),
      (args.prepared / 'receipt.json', private / 'prepared-receipt.json', 0o600),
      (args.installation / 'receipt.json', private / 'installation-receipt.json', 0o600)]:
    write_file(root, str(target.relative_to(root)), origin.read_bytes(), mode)
  write_file(root, str((private / 'identity.json').relative_to(root)), (json.dumps(identity, indent=2) + '\n').encode(), 0o600)
  unit = b'''[Unit]
Description=Owned full-system ARM VM qualification
Requires=basic.target systemd-user-sessions.service systemd-logind.service polkit.service
After=basic.target systemd-user-sessions.service systemd-logind.service polkit.service
SuccessAction=poweroff
FailureAction=poweroff
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B /usr/lib/shield-systemd-vm/guest.py
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TimeoutStartSec=300
'''
  write_file(root, 'etc/systemd/system/shield-systemd-vm.service', unit, 0o644)
  write_file(root, 'etc/systemd/system/shield-systemd-vm.target', b'''[Unit]
Description=Owned virtual ARM systemd checks
Requires=shield-systemd-vm.service
After=shield-systemd-vm.service
AllowIsolate=yes
''', 0o644)
  write_file(root, 'etc/systemd/system/shield-systemd-vm-user.service', b'''[Unit]
Description=VM-only real PAM local user probe
ConditionKernelCommandLine=shield.systemd-vm=1
Requires=systemd-logind.service systemd-user-sessions.service
After=systemd-logind.service systemd-user-sessions.service
[Service]
Type=exec
User=shieldqual
Group=shieldqual
PAMName=login
Environment=XDG_SESSION_TYPE=tty XDG_SESSION_CLASS=user XDG_SEAT=seat0 XDG_VTNR=1
ExecStart=/usr/bin/python3 -I -B /usr/lib/shield-systemd-vm-user/user-probe.py
StandardInput=tty
StandardOutput=journal
StandardError=journal
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
UtmpIdentifier=tty1
UtmpMode=user
NoNewPrivileges=no
RestrictSUIDSGID=no
Restart=no
TimeoutStartSec=20
TimeoutStopSec=5
''', 0o644)
  write_file(root, 'etc/systemd/system/shield-systemd-vm-native-refusal.service', b'''[Unit]
Description=VM-only exact native guardian refusal check
ConditionKernelCommandLine=shield.systemd-vm=1
[Service]
Type=oneshot
ExecStart=/usr/lib/omarchy/shield/qualification/shield-guardian --run
SuccessExitStatus=64
RemainAfterExit=yes
Restart=no
TimeoutStartSec=5
''', 0o644)
  ACTOR.verify_prepared(root, prepared, payload)
  for purpose, relative in [('home', 'home'), ('log', 'var/log')]:
    original = root / relative
    original.rename(seed / profile['filesystem']['subvolumes'][purpose])
    new_directory(original, 0o755)
  image = output / 'root.btrfs'
  with image.open('xb') as stream: stream.truncate(IMAGE_BYTES)
  volumes = profile['filesystem']['subvolumes']
  run(['qemu-aarch64-static', '-L', str(source), str(source / 'usr/bin/mkfs.btrfs'),
       '--nodiscard', '--force', '--uuid', profile['filesystem']['uuid'],
       '--rootdir', str(seed), '--subvol', 'default:' + volumes['root'],
       '--subvol', 'rw:' + volumes['home'], '--subvol', 'rw:' + volumes['log'], str(image)], 'mkfs.log')
  shutil.copyfile(source / 'usr/lib/omarchy/shield/kernel/Image', output / 'Image')
  (output / 'initramfs.cpio.gz').write_bytes(initramfs)
  run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'raw', '-b', str(image), str(output / 'test-disk.qcow2')], 'cow.log')
  admit_installation(args.installation, args.installation_receipt_sha256, prepared, payload, args.payload_manifest_sha256)
  require(all(digest(PORT / name) == value for name, value in hashes.items()), 'VM source changed during build')
  receipt = {'format_version': 1, 'purpose': PURPOSE, 'sources': hashes,
    'native_sources': profile['sources'],
    'supporting_sources': {name: digest(PORT / name) for name in
      ['tools/install-qualification-artifacts.py', 'tools/stock_boot.py', 'chroot.sh']},
    'installation_receipt_sha256': args.installation_receipt_sha256,
    'identity': identity,
    'identity_sha256': hashlib.sha256((json.dumps(identity, indent=2) + '\n').encode()).hexdigest(),
    'base_image_sha256': digest(image), 'image_bytes': IMAGE_BYTES,
    'initial_mkfs_compression': 'none', 'required_runtime_compression': 'zstd:1',
    'kernel_sha256': digest(output / 'Image'), 'initramfs_sha256': digest(output / 'initramfs.cpio.gz'),
    'initial_overlay_sha256': digest(output / 'test-disk.qcow2'),
    'uid_probe_sha256': digest(binary), 'executed': False, 'native_qualified': False, 'boot_ready': False}
  (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
  print('Prepared a new full-system VM only; no VM or physical boot executed.')


if __name__ == '__main__':
  main()
