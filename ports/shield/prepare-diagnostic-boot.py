#!/usr/bin/env python3
"""Verify and bundle diagnostic components without creating a boot/flash command."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from tools.board_firmware import checked_path, verify_bytes
from tools.kernel_profile import verify_kernel_profile
from tools.fan_profile import inspect_fan_contract


def aligned(value, alignment):
  return (value + alignment - 1) // alignment * alignment


def inspect_stock(data, profile):
  if len(data) < 1648 or data[:8] != b'ANDROID!':
    raise ValueError('Stock image lacks Android magic')
  header = profile['android_header']
  page = header['page_bytes']
  if struct.unpack_from('<I', data, 40)[0] != header['version'] or struct.unpack_from('<I', data, 36)[0] != page:
    raise ValueError('Stock header differs from the measured v1/2048 profile')
  kernel_bytes = struct.unpack_from('<I', data, 8)[0]
  if data[page:page + 2] != b'\x1f\x8b' or kernel_bytes > len(data) - page:
    raise ValueError('Stock compressed-kernel bounds differ')


def prepare(kernel, stock_root, output):
  port = Path(__file__).resolve().parent
  profile_raw = (port / 'diagnostic-boot.lock.json').read_bytes()
  profile = json.loads(profile_raw)
  lock, dtb = verify_kernel_profile(kernel)
  if lock['board_variant'] != profile['board_variant']:
    raise ValueError('Diagnostic profile and kernel variant disagree')
  if lock != json.loads((port / 'kernel.lock.json').read_text()):
    raise ValueError('Use the current combined kernel candidate, not a historical bundle')
  fan_contract = inspect_fan_contract(dtb)
  if not fan_contract['binding_contract_matches']:
    raise ValueError('Compiled fan/GPU PWM specifiers differ from the reviewed contract')
  subprocess.run(['sha256sum', '--check', '--status', 'SHA256SUMS'], cwd=kernel, check=True)
  stock = []
  for entry in profile['stock_inputs']:
    path = checked_path(stock_root, entry['path'])
    if not path.is_file() or path.is_symlink():
      raise ValueError('Supply saved stock image files')
    data = path.read_bytes()
    verify_bytes(data, {**entry, 'id': entry['path']})
    inspect_stock(data, profile)
    stock.append({**entry, 'matches_pinned_release_input': True})
  image = (kernel / 'Image').read_bytes()
  if image[56:60] != b'ARM\x64' or gzip.decompress((kernel / 'Image.gz').read_bytes()) != image:
    raise ValueError('Compressed kernel and ARM64 Image differ')
  ramdisk = json.loads((kernel / 'ramdisk-profile.json').read_text())
  if ramdisk['usb_console_included'] is not True:
    raise ValueError('Use the USB diagnostic ramdisk build')
  page = profile['android_header']['page_bytes']
  # Conservative size budget only: one header page and one reserved footer page.
  budget = 2 * page + aligned((kernel / 'Image.gz').stat().st_size, page) + aligned((kernel / 'initramfs.cpio.gz').stat().st_size, page)
  limit = min(profile['observed_limits'].values())
  if budget > limit:
    raise ValueError('Compressed kernel/ramdisk budget exceeds observed limits')
  output = output.resolve()
  if output.exists():
    raise ValueError('Use a new diagnostic bundle directory')
  output.parent.mkdir(parents=True, exist_ok=True)
  temporary = Path(tempfile.mkdtemp(prefix='.shield-diagnostic-', dir=output.parent))
  try:
    names = ['Image', 'Image.gz', 'initramfs.cpio.gz', dtb.name, 'kernel.config',
             'sources.lock.json', 'hardware.json', 'ramdisk-profile.json', 'kernel-release.txt',
             'applied-patches.json', 'device-tree-overlays.json', 'source-verification.json']
    files = []
    for name in names:
      source = kernel / name
      if not source.is_file() or source.is_symlink():
        raise ValueError('Expected a regular diagnostic component')
      shutil.copyfile(source, temporary / name)
      files.append({'path': name, 'bytes': source.stat().st_size,
                    'sha256': hashlib.sha256(source.read_bytes()).hexdigest()})
    shutil.copyfile(port / 'diagnostic-boot.lock.json', temporary / 'diagnostic-boot.lock.json')
    report = {'board_variant': lock['board_variant'], 'profile_sha256': hashlib.sha256(profile_raw).hexdigest(),
              'stock_inputs': stock, 'files': files, 'android_compressed_payload_budget_bytes': budget,
              'compiled_fan_contract': fan_contract,
              'observed_limit_bytes': limit, 'dtb_bytes_separate_from_android_dtbo': dtb.stat().st_size,
              'unresolved_native_gates': profile['unresolved_native_gates'],
              'planned_ramdisk_arguments': ['rdinit=/init', 'shield.usb-console=1'],
              'native_boot_ready': False, 'android_boot_image_created': False, 'boot_command_generated': False,
              'physical_shield_boot_tested': False, 'device_actions_performed': []}
    (temporary / 'diagnostic-review.json').write_text(json.dumps(report, indent=2) + '\n')
    (temporary / 'SHA256SUMS').write_text(''.join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                                               for path in sorted(temporary.iterdir()) if path.is_file()))
    temporary.rename(output)
  except BaseException:
    shutil.rmtree(temporary)
    raise
  return report


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--kernel-dir', required=True, type=Path)
  parser.add_argument('--stock-root', required=True, type=Path, help='Exact-build boot/current-build harvest directory')
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  try:
    report = prepare(args.kernel_dir.resolve(), args.stock_root.resolve(), args.output)
  except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
    raise SystemExit(str(error)) from error
  print(json.dumps({key: report[key] for key in ('android_compressed_payload_budget_bytes',
                   'observed_limit_bytes', 'native_boot_ready', 'android_boot_image_created')}, indent=2))


if __name__ == '__main__':
  main()
