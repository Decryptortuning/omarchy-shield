#!/usr/bin/env python3
"""Run exactly one prepared QEMU transaction on an owned COW image."""
import argparse
import datetime
import json
from pathlib import Path
import stat
import subprocess

from usb_root_profile import digest, require


def real_file(path):
  path = Path(path)
  require(stat.S_ISREG(path.lstat().st_mode), 'Expected real regular input')
  return path.resolve(strict=True)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--candidate', type=Path, required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  candidate = args.candidate.resolve(strict=True)
  receipt = json.loads(real_file(candidate / 'receipt.json').read_text())
  require(receipt['scope'] == 'owned QEMU disk derivative only' and not receipt['executed'], 'Wrong VM candidate')
  require(digest(Path(__file__).with_name('maintenance-vm-guest.py')) == receipt['guest_sha256'], 'Guest source differs')
  require(digest(Path(__file__).with_name('prepare-maintenance-vm.py')) == receipt['builder_sha256'], 'Builder source differs')
  for filename, key in [('Image', 'kernel_sha256'), ('initramfs.cpio.gz', 'initramfs_sha256'),
                        ('test-disk.qcow2', 'initial_overlay_sha256')]:
    require(digest(real_file(candidate / filename)) == receipt[key], 'VM artifact differs: ' + filename)
  base = real_file(receipt['base_image'])
  require(digest(base) == receipt['base_image_sha256'], 'Baseline image differs')
  disk = real_file(candidate / 'test-disk.qcow2')
  require(disk != base, 'Never write the baseline image')
  chain = json.loads(subprocess.run(['qemu-img', 'info', '--backing-chain', '--output=json', str(disk)],
                                   check=True, capture_output=True, text=True).stdout)
  require(len(chain) == 2 and chain[0]['format'] == 'qcow2' and chain[1]['format'] == 'raw', 'Wrong backing chain')
  require(Path(chain[0]['filename']).resolve() == disk and Path(chain[1]['filename']).resolve() == base,
          'Backing chain path differs')
  require(chain[0]['virtual-size'] == chain[1]['virtual-size'] == receipt['image_bytes'], 'Backing geometry differs')
  output = args.output
  require(not output.exists() and not output.is_symlink(), 'Output must be a new directory')
  output.mkdir(mode=0o700)
  # Permanent one-attempt latch; failure or timeout must not replay effects.
  with (candidate / 'attempt.json').open('x') as attempt:
    json.dump({'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'runner_sha256': digest(__file__), 'output': str(output.resolve())}, attempt)
  block = {'driver': 'qcow2', 'node-name': 'ownedtest', 'file': {'driver': 'file', 'filename': str(disk)}}
  command = ['qemu-system-aarch64', '-machine', 'virt', '-cpu', 'cortex-a57', '-smp', '2',
    '-m', '2048M', '-nographic', '-no-reboot', '-nic', 'none',
    '-kernel', str(candidate / 'Image'), '-initrd', str(candidate / 'initramfs.cpio.gz'),
    '-blockdev', json.dumps(block), '-device', 'virtio-blk-device,drive=ownedtest',
    '-append', 'console=ttyAMA0 rdinit=/init panic=-1 shield.maintenance-vm=1']
  error = None
  status = None
  with (output / 'console.log').open('xb') as console:
    try:
      status = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=console,
                              stderr=subprocess.STDOUT, timeout=900).returncode
    except subprocess.TimeoutExpired:
      error = 'outer-qemu-timeout'
  baseline_unchanged = digest(base) == receipt['base_image_sha256']
  log = (output / 'console.log').read_text(errors='replace')
  prefix = 'SHIELD_MAINTENANCE_VM_RESULT '
  results = [json.loads(line.strip()[len(prefix):]) for line in log.splitlines() if line.strip().startswith(prefix)]
  passed = (status == 0 and error is None and baseline_unchanged and len(results) == 1
            and results[0]['passed'] is True and 'SHIELD_MAINTENANCE_VM_EXIT 0' in log)
  result = {'passed': passed, 'exit_code': status, 'error': error,
    'base_image_sha256': receipt['base_image_sha256'], 'baseline_unchanged': baseline_unchanged,
    'guest_results': results, 'console_sha256': digest(output / 'console.log'),
    'candidate_receipt_sha256': digest(candidate / 'receipt.json'), 'runner_sha256': digest(__file__),
    'hardware_or_performance_qualified': False, 'boot_ready': False}
  with (output / 'result.json').open('x') as stream:
    json.dump(result, stream, indent=2)
    stream.write('\n')
  print(json.dumps(result, indent=2))
  require(passed, 'VM integration failed; preserve this attempt and do not replay it')


if __name__ == '__main__':
  main()
