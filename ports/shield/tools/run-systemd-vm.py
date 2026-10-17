#!/usr/bin/env python3
"""Run one owned full-system VM on its persistent COW; never replay an attempt."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess

from guardian_binding import IMAGE_SHA256, SOURCE_NAMES
from qualification_profile import DENIED_ACTIONS
from systemd_vm_profile import MARKER, PURPOSE, SOURCES, validate_identity
from usb_root_profile import digest, require

PORT = Path(__file__).resolve().parent.parent


def guest_accepted(result):
  try:
    require(type(result['format_version']) is int and result['format_version'] == 1
            and result['scope'] == PURPOSE and result['passed'] is True, 'Wrong guest result scope')
    require(all(result[name] is False for name in ['native_guardian_admitted', 'Shield_native_qualified',
      'hardware_or_performance_qualified', 'graphics_qualified', 'boot_ready']), 'Overclaimed guest result')
    checks = result['checks']
    require(all(checks[name]['passed'] is True for name in ['boot_mount_admission',
      'actual_package_module_loader_payload', 'emulated_kms_seat_prerequisite', 'installed_software_policy', 'native_fail_closed',
      'root_sudo_policy', 'session_setuid_power']), 'Missing positive guest evidence')
    require(checks['boot_mount_admission']['runtime_compression'] == 'zstd:1'
            and checks['boot_mount_admission']['emulated_NOR_only'] is True,
            'Missing actual mount compression or emulated flash admission')
    kms = checks['emulated_kms_seat_prerequisite']
    require(kms['version_1_negotiated'] is True and kms['gpu_transport_link_verified'] is True
            and kms['renderer_qualified'] is False, 'Missing actual modern GPU transport/card evidence')
    require(checks['manager'] == {'RuntimeWatchdogUSec': '0', 'RebootWatchdogUSec': '0',
      'KExecWatchdogUSec': '0', 'CtrlAltDelBurstAction': 'none'}, 'Wrong live manager settings')
    require(checks['native_fail_closed']['native_READY'] is False and
            checks['native_fail_closed']['native_desktop_started'] is False, 'False native readiness')
    require(checks['root_sudo_policy']['negative_only'] is True
            and checks['root_sudo_policy']['true_query_denied'] is True, 'Missing independent root sudo policy proof')
    session = checks['session_setuid_power']
    require(session['actual_session']['Active'] == 'yes' and session['actual_session']['Remote'] == 'no'
            and session['actual_session']['Seat'] == 'seat0' and session['actual_session']['Type'] == 'tty'
            and session['peer_starttime_verified'] is True, 'Missing real active local session')
    denials = session['actual_policy_denials']
    require(len(denials) == len(DENIED_ACTIONS) and {item['action'] for item in denials} == set(DENIED_ACTIONS)
            and all(type(item['returncode']) is int and item['returncode'] == 1
              and item['explicit_no'] is True
              and item['output'] == r'polkit\56result=no' + '\nNot authorized.\n' for item in denials),
            'Missing actual power authorization denials')
    user = session['user_probe']
    require(user['passed'] is True and all(user['checks'][name]['passed'] is True for name in
      ['setuid', 'sudo_root_true_blocked_without_authentication', 'user_bus', 'login1_poweroff', 'login1_reboot',
       'systemd_reboot_target', 'systemd_poweroff_target']), 'Missing actual fixed user probes')
    sudo = user['checks']['sudo_root_true_blocked_without_authentication']
    require(sudo['authentication_barrier_observed'] is True
            and sudo['authorization_denial_observed_in_user_execution'] is False
            and type(sudo['returncode']) is int and sudo['returncode'] == 1
            and sudo['output'] == 'sudo: a password is required\n', 'Wrong sudo proof scope')
    elevated = user['checks']['setuid']['record']
    require(type(elevated['euid_before']) is int and elevated['euid_before'] == 0
            and type(elevated['euid_after']) is int and elevated['euid_after'] == 1001
            and elevated['root_regain_denied'] is True
            and type(elevated['nnp_after']) is int and elevated['nnp_after'] == 1,
            'Missing actual setuid elevation and irreversible drop')
    return True
  except (KeyError, TypeError, ValueError):
    return False


def regular(path):
  info = path.lstat()
  require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
          and info.st_nlink == 1, 'Expected owned regular VM artifact')
  return path


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--candidate', type=Path, required=True)
  parser.add_argument('--candidate-receipt-sha256', required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'Run owned VM as WSL root')
  candidate = args.candidate.resolve(strict=True)
  info = candidate.stat()
  require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == info.st_gid == 0, 'Untrusted candidate directory')
  record_path = regular(candidate / 'receipt.json')
  require(digest(record_path) == args.candidate_receipt_sha256, 'Candidate receipt differs')
  record = json.loads(record_path.read_text())
  require(record['format_version'] == 1 and record['purpose'] == PURPOSE
          and record['executed'] is False and record['native_qualified'] is False
          and record['boot_ready'] is False
          and record['initial_mkfs_compression'] == 'none'
          and record['required_runtime_compression'] == 'zstd:1', 'Wrong VM candidate scope')
  identity = validate_identity(record['identity'])
  require(hashlib.sha256((json.dumps(identity, indent=2) + '\n').encode()).hexdigest()
          == record['identity_sha256'], 'VM identity bytes differ')
  require(set(record['sources']) == SOURCES and record['sources'] == identity['sources']
          and all(digest(PORT / name) == value for name, value in record['sources'].items()),
          'VM producer/consumer source moved')
  require(set(record['native_sources']) == SOURCE_NAMES and
          all(digest(PORT / name) == value for name, value in record['native_sources'].items()), 'Native source moved')
  require(set(record['supporting_sources']) == {'tools/install-qualification-artifacts.py', 'tools/stock_boot.py', 'chroot.sh'}
          and all(digest(PORT / name) == value for name, value in record['supporting_sources'].items()),
          'VM supporting source moved')
  base = regular(candidate / 'root.btrfs'); disk = regular(candidate / 'test-disk.qcow2')
  require(base.stat().st_size == record['image_bytes'] == 24 * 1024**3
          and digest(base) == record['base_image_sha256'], 'VM baseline changed')
  for name, key in [('Image', 'kernel_sha256'), ('initramfs.cpio.gz', 'initramfs_sha256'),
                    ('test-disk.qcow2', 'initial_overlay_sha256')]:
    require(digest(regular(candidate / name)) == record[key], 'VM input changed')
  require(record['kernel_sha256'] == IMAGE_SHA256, 'Wrong selected kernel')
  chain = json.loads(subprocess.run(['qemu-img', 'info', '--backing-chain', '--output=json', str(disk)],
    stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=10).stdout)
  require(len(chain) == 2 and chain[0]['format'] == 'qcow2' and chain[1]['format'] == 'raw'
          and Path(chain[0]['filename']).resolve() == disk and Path(chain[1]['filename']).resolve() == base
          and chain[0]['virtual-size'] == chain[1]['virtual-size'] == record['image_bytes'], 'Wrong virtual backing chain')
  output = args.output.parent.resolve(strict=True) / args.output.name
  require(not output.exists() and not output.is_symlink()
          and not output.is_relative_to(candidate) and not candidate.is_relative_to(output), 'Output must be new and separate')
  output.mkdir(mode=0o700)
  with (candidate / 'attempt.json').open('x') as stream:
    json.dump({'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'runner_sha256': digest(__file__), 'output': str(output)}, stream)
    stream.flush(); os.fsync(stream.fileno())
  block = {'driver': 'qcow2', 'node-name': 'ownedtest', 'file': {'driver': 'file', 'filename': str(disk)}}
  command = ['qemu-system-aarch64', '-machine', 'virt', '-cpu', 'cortex-a57', '-smp', '2',
    '-m', '3072M', '-nographic', '-no-reboot', '-nic', 'none',
    '-global', 'virtio-mmio.force-legacy=false', '-device', 'virtio-gpu-device',
    '-kernel', str(candidate / 'Image'), '-initrd', str(candidate / 'initramfs.cpio.gz'),
    '-blockdev', json.dumps(block), '-device', 'virtio-blk-device,drive=ownedtest',
    '-append', 'console=ttyAMA0 root=/dev/vda rootfstype=btrfs rw systemd.unit=shield-systemd-vm.target '
               + MARKER + ' panic=-1']
  def interrupted(_signum, _frame):
    raise InterruptedError('Owned VM interrupted')
  signal.signal(signal.SIGTERM, interrupted)
  error, status = None, None
  with (output / 'console.log').open('xb') as log:
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
      env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, start_new_session=True)
    try:
      status = process.wait(timeout=900)
    except (subprocess.TimeoutExpired, InterruptedError, KeyboardInterrupt) as failure:
      error = type(failure).__name__
      try: os.killpg(process.pid, signal.SIGTERM)
      except ProcessLookupError: pass
      try: process.wait(timeout=3)
      except subprocess.TimeoutExpired:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=3)
  unchanged = digest(base) == record['base_image_sha256']
  log = (output / 'console.log').read_text(errors='replace')
  prefix = 'SHIELD_SYSTEMD_VM_RESULT '
  results = []
  parse_error = False
  for line in log.splitlines():
    if line.strip().startswith(prefix):
      try:
        require(len(line) <= 131072, 'Oversized result')
        result = json.loads(line.strip()[len(prefix):]); require(isinstance(result, dict), 'Non-object result')
        results.append(result)
      except (ValueError, TypeError): parse_error = True
  passed = (status == 0 and error is None and unchanged and not parse_error and len(results) == 1
            and guest_accepted(results[0])
            and 'SHIELD_SYSTEMD_VM_INIT_FAIL' not in log)
  receipt = {'format_version': 1, 'scope': PURPOSE, 'passed': passed, 'qemu_exit': status, 'error': error,
    'base_image_unchanged': unchanged, 'base_image_sha256': record['base_image_sha256'],
    'guest_results': results, 'console_sha256': digest(output / 'console.log'),
    'candidate_receipt_sha256': args.candidate_receipt_sha256, 'runner_sha256': digest(__file__),
    'physical_USB_changed': False, 'native_qualified': False, 'boot_ready': False}
  (output / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
  print('Full-system VM passed.' if passed else 'Full-system VM failed; preserve this attempt.')
  require(passed, 'VM failed; do not replay this derivative')


if __name__ == '__main__':
  main()
