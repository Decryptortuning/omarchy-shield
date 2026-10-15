#!/usr/bin/env python3
"""Build a local unsigned inventory image from the exact stock recovery kernel."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
from tools.board_firmware import verify_bytes
from tools.stock_boot import read_newc, write_newc, stock_parts, replace_ramdisk


def elf_arm64(data):
  if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
    raise ValueError('Expected ARM64 ELF payload')
  offset = struct.unpack_from('<Q', data, 32)[0]
  size, count = struct.unpack_from('<HH', data, 54)
  if offset + size * count > len(data) or any(struct.unpack_from('<I', data, offset + i * size)[0] == 3 for i in range(count)):
    raise ValueError('Unexpected dynamic interpreter or ELF program-header bounds')


def build(recovery, busybox_root, kexec_root, output):
  port = Path(__file__).resolve().parent
  lock_raw = (port / 'stock-bootstrap.lock.json').read_bytes()
  lock = json.loads(lock_raw)
  seconds, temperature = lock['inventory_window_seconds'], lock['maximum_temperature_millicelsius']
  if type(seconds) is not int or not 0 < seconds <= 60 or type(temperature) is not int or not 30000 <= temperature <= 70000:
    raise ValueError('Inventory limits exceed the reviewed bounded idle session')
  original = recovery.read_bytes()
  verify_bytes(original, {**lock['stock_recovery'], 'id': 'exact stock recovery'})
  _, kernel, compressed_stock_ramdisk = stock_parts(original)
  stock = read_newc(gzip.decompress(compressed_stock_ramdisk))
  entries = {}
  for path in sorted(busybox_root.rglob('*')):
    relative = path.relative_to(busybox_root).as_posix()
    mode = path.lstat().st_mode
    if path.is_symlink():
      data = os.readlink(path).encode()
    elif path.is_dir():
      data = b''
    elif path.is_file():
      data = path.read_bytes()
    else:
      raise ValueError('Unexpected BusyBox staging entry')
    entries[relative] = {'mode': mode, 'data': data}
  elf_arm64(entries['bin/busybox']['data'])
  for name in ('dev', 'proc', 'sys', 'run', 'tmp', 'lib', 'lib/modules', 'lib/firmware', 'notices'):
    entries[name] = {'mode': stat.S_IFDIR | 0o755, 'data': b''}
  for name, major, minor in (('dev/console', 5, 1), ('dev/null', 1, 3)):
    entries[name] = {'mode': stat.S_IFCHR | 0o600, 'data': b'', 'rdevmajor': major, 'rdevminor': minor}
  for entry in lock['stock_ramdisk_inputs']:
    data = stock[entry['path']]['data']
    verify_bytes(data, {**entry, 'id': entry['path']})
    if entry['path'].endswith('.ko'):
      elf_arm64(data)
      if b'vermagic=4.9.141-tegra ' not in data:
        raise ValueError('Stock module kernel release differs')
    entries[entry['path']] = {'mode': stat.S_IFREG | 0o644, 'data': data}
  helper = json.loads((kexec_root / 'shield-build.json').read_text())
  data = (kexec_root / helper['path']).read_bytes()
  verify_bytes(data, {**helper, 'id': 'static ARM64 kexec'})
  elf_arm64(data)
  if helper['source_commit'] != lock['kexec']['commit'] or helper['dynamic_interpreter'] is not False:
    raise ValueError('Unexpected kexec source/loader')
  entries['bin/kexec'] = {'mode': stat.S_IFREG | 0o755, 'data': data}
  for source, destination in (('init.sh', 'init'), ('identity.sh', 'identity.sh')):
    entries[destination] = {'mode': stat.S_IFREG | 0o755, 'data': (port / 'stock-bootstrap' / source).read_bytes()}
  entries['inventory.conf'] = {'mode': stat.S_IFREG | 0o644,
                               'data': f'inventory_window_seconds={seconds}\ninventory_temperature_limit={temperature}\n'.encode()}
  entries['notices/README'] = {'mode': stat.S_IFREG | 0o644, 'data': b'Contains unmodified local stock kernel/module/firmware inputs from the pinned NVIDIA recovery release. No redistribution permission is inferred. BusyBox GPL-2.0 and kexec source pins/licenses accompany the external build directories.\n'}
  ramdisk = gzip.compress(write_newc(entries), mtime=0)
  image = replace_ramdisk(original, ramdisk)
  if len(image) > 26738688 or len(image) > 33554432:
    raise ValueError('Inventory image exceeds observed partition/download limits')
  original_header, _, _ = stock_parts(original)
  new_header, new_kernel, new_ramdisk = stock_parts(image)
  changed = set(range(16, 20)) | set(range(64, 1632))
  if new_kernel != kernel or any(a != b for i, (a, b) in enumerate(zip(original_header, new_header)) if i not in changed):
    raise ValueError('Unexpected change outside ramdisk/cmdline/digest fields')
  if gzip.decompress(new_ramdisk) != write_newc(entries):
    raise ValueError('Inventory ramdisk roundtrip differs')
  output = output.resolve()
  if output.exists():
    raise ValueError('Use a new inventory output directory')
  output.parent.mkdir(parents=True, exist_ok=True)
  temporary = Path(tempfile.mkdtemp(prefix='.shield-stock-inventory-', dir=output.parent))
  try:
    (temporary / 'stock-inventory.img').write_bytes(image)
    (temporary / 'initramfs.cpio.gz').write_bytes(ramdisk)
    (temporary / 'stock-kernel.gz').write_bytes(kernel)
    shutil.copyfile(port / 'stock-bootstrap.lock.json', temporary / 'stock-bootstrap.lock.json')
    report = {'source_recovery_sha256': hashlib.sha256(original).hexdigest(), 'profile_sha256': hashlib.sha256(lock_raw).hexdigest(),
              'image_bytes': len(image), 'image_sha256': hashlib.sha256(image).hexdigest(),
              'stock_kernel_unchanged': new_kernel == kernel, 'stock_kernel_sha256': hashlib.sha256(kernel).hexdigest(),
              'raw_load_address_fields_preserved': True, 'effective_load_addresses_qualified': False,
              'dtb_or_early_firmware_packaged': False, 'signed': False, 'requires_unlocked_bootloader': True,
              'temporary_boot_support_verified': False, 'physical_boot_or_restore_tested': False,
              'automatic_partition_writes': [], 'automatic_kexec_operations': [], 'inventory_window_seconds': seconds,
              'files': [{'path': name, 'bytes': len(e['data']), 'sha256': hashlib.sha256(e['data']).hexdigest()}
                        for name, e in entries.items() if stat.S_ISREG(e['mode'])],
              'device_actions_performed': []}
    (temporary / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    (temporary / 'SHA256SUMS').write_text(''.join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(temporary.iterdir())))
    temporary.rename(output)
  except BaseException:
    shutil.rmtree(temporary)
    raise
  return report


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--recovery', required=True, type=Path)
  parser.add_argument('--busybox-root', required=True, type=Path)
  parser.add_argument('--kexec-root', required=True, type=Path)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  report = build(args.recovery, args.busybox_root, args.kexec_root, args.output)
  print(json.dumps({key: report[key] for key in ('image_bytes', 'image_sha256', 'stock_kernel_unchanged',
                   'signed', 'temporary_boot_support_verified', 'physical_boot_or_restore_tested')}, indent=2))


if __name__ == '__main__':
  main()
