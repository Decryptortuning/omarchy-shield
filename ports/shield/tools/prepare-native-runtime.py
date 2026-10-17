"""Convert a fresh matched toolroot to a nonbootable early runtime component.

Explicit host Python invocation only, after the combined source gate. Nothing
is extracted onto the host and no target executable, device, mount or VM runs.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

from stock_boot import read_newc, write_newc
from usb_root_profile import require

PORT = Path(__file__).resolve().parent.parent
MODULE_PREFIX = 'usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/'
ADDITIONS = {'usr/bin/switch_root', 'usr/lib/firmware/nvidia/tegra210/xusb.bin',
  *[MODULE_PREFIX + name for name in ['libcomposite.ko', 'function/u_serial.ko',
    'function/usb_f_acm.ko', 'udc/tegra-xudc.ko']]}
LIBRARIES = {'usr/lib/libc.so.6', 'usr/lib/ld-linux-aarch64.so.1'}
MAX_EXPANDED = 160 * 1024**2


def sha(raw): return hashlib.sha256(raw).hexdigest()


def helpers():
  # Reuse the capsule's archive graph and descriptor-based input admission.
  # This host-only module import happens only after the combined source gate.
  spec = importlib.util.spec_from_file_location('native_capsule_producer',
    PORT / 'tools/prepare-native-capsule.py')
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def base_entries(raw, receipt, api):
  with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
    expanded = stream.read(MAX_EXPANDED + 1)
  require(len(expanded) <= MAX_EXPANDED, 'Expanded toolroot exceeds budget')
  entries, regular_bytes = {}, 0
  with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
    for item in archive:
      require(len(entries) < 4096, 'Toolroot member budget exceeded')
      name = api.safe_name(item.name.rstrip('/'))
      require(name not in entries and not item.pax_headers
              and item.uid == item.gid == item.mtime == 0
              and not item.mode & ~0o1777
              and PurePosixPath(name).parts[0] not in {'dev', 'proc', 'sys', 'run', 'tmp'}
              and item.uname == item.gname == '', 'Unexpected own-producer metadata')
      entry = {'mode': item.mode, 'data': b'', 'rdevmajor': 0, 'rdevminor': 0}
      if item.isdir():
        require(item.size == 0, 'Directory payload refused')
        entry['mode'] |= stat.S_IFDIR
      elif item.issym():
        require(item.size == 0 and 0 < len(item.linkname) <= 4096
                and '\0' not in item.linkname, 'Invalid runtime symlink')
        entry['mode'] |= stat.S_IFLNK
        entry['data'] = item.linkname.encode('ascii')
      else:
        require(item.isfile() and 0 <= item.size <= 32 * 1024**2,
                'Unexpected runtime object')
        stream = archive.extractfile(item)
        entry['data'] = stream.read(item.size + 1)
        require(len(entry['data']) == item.size, 'Truncated runtime member')
        regular_bytes += item.size
        entry['mode'] |= stat.S_IFREG
      entries[name] = entry
  require(len(entries) == receipt['paths'] and regular_bytes == receipt['regular_bytes']
          and 'init' not in entries and 'bin/busybox' not in entries,
          'Runtime inventory differs or contains a bootstrap entrypoint')
  require(entries['lib']['mode'] == stat.S_IFLNK | 0o777
          and entries['lib']['data'] == b'usr/lib', 'Loader/firmware alias differs')
  api.archive_graph(entries)
  return entries


def prepare(contract, output):
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
          'Build private components as WSL root')
  os.umask(0o077)
  require(type(contract) is dict and set(contract) == {'format_version', 'purpose',
    'source_sha256', 'base_archive', 'base_receipt', 'additions', 'handoff_libraries'}
    and type(contract['format_version']) is int and contract['format_version'] == 1
    and contract['purpose'] == 'host-only matched early runtime component'
    and set(contract['additions']) == ADDITIONS
    and set(contract['handoff_libraries']) == LIBRARIES, 'Wrong runtime contract')
  api = helpers()
  api.source_snapshot(contract['source_sha256'])
  require({'tools/prepare-native-runtime.py', 'tools/prepare-native-bootstrap.py'}
          <= set(contract['source_sha256']), 'Missing producer source pins')
  archive_raw = api.pinned(contract['base_archive'], 64 * 1024**2)
  receipt = json.loads(api.pinned(contract['base_receipt'], 1024**2))
  require(receipt['format_version'] == 1
          and receipt['builder_sha256'] == contract['source_sha256']['tools/prepare-maintenance-toolroot.py']
          and receipt['archive_sha256'] == sha(archive_raw)
          and receipt['archive_bytes'] == len(archive_raw)
          and receipt['modules'] == {name: contract['source_sha256']['tools/' + name]
            for name in ['usb_root_profile.py', 'usb_candidate_transaction.py']}
          and receipt['device_operations'] is False and receipt['boot_ready'] is False,
          'Base archive is not a fresh source-matched toolroot')
  entries = base_entries(archive_raw, receipt, api)
  for name, pin in sorted(contract['additions'].items()):
    mode = 0o755 if name == 'usr/bin/switch_root' else 0o644
    require(pin['mode'] == mode, 'Wrong runtime addition mode')
    raw = api.pinned(pin, 8 * 1024**2)
    api.add(entries, name, raw, mode)
  for name, expected in contract['handoff_libraries'].items():
    entry = entries[name]
    require(stat.S_ISREG(entry['mode']) and sha(entry['data']) == expected,
            'switch_root loader/libc input differs')
  api.archive_graph(entries)
  compressed = gzip.compress(write_newc(entries), compresslevel=9, mtime=0)
  require(len(compressed) <= 64 * 1024**2
          and api.component_entries(compressed) == entries,
          'Runtime CPIO roundtrip/current API admission failed')
  api.source_snapshot(contract['source_sha256'])
  require(api.pinned(contract['base_archive'], 64 * 1024**2) == archive_raw,
          'Toolroot archive changed')
  require(json.loads(api.pinned(contract['base_receipt'], 1024**2)) == receipt,
          'Toolroot receipt changed')
  for name, pin in contract['additions'].items():
    require(api.pinned(pin, 8 * 1024**2) == entries[name]['data'], 'Runtime addition changed')
  require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
          and not output.exists() and not output.is_symlink(), 'Use a new canonical output')
  output.mkdir(mode=0o700)

  def write(name, raw):
    fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
      stream.write(raw); stream.flush(); os.fsync(stream.fileno())

  write('early-runtime.cpio.gz', compressed)
  pin = {'path': str(output / 'early-runtime.cpio.gz'), 'sha256': sha(compressed),
         'bytes': len(compressed), 'mode': 0o600}
  require(api.component_entries(api.pinned(pin, 64 * 1024**2)) == entries,
          'Published component readback differs')
  result = {'format_version': 1, 'purpose': contract['purpose'],
    'source_sha256': contract['source_sha256'],
    'contract_sha256': sha(json.dumps(contract, sort_keys=True, separators=(',', ':')).encode()),
    'component': pin, 'base_archive_sha256': sha(archive_raw), 'entries': len(entries),
    'module_load_order': ['libcomposite', 'u_serial', 'usb_f_acm', 'tegra-xudc'],
    'firmware_available_before_usb_root': True, 'contains_init': False,
    'CPIO_roundtrip_and_disk_readback': True, 'physical_device_access': False,
    'target_artifacts_executed': False, 'actual_loaded_segment_fit_verified': False,
    'native_execution_released': False, 'boot_ready': False}
  write('receipt.json', json.dumps(result, sort_keys=True, indent=2).encode() + b'\n')
  fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
  try: os.fsync(fd)
  finally: os.close(fd)
  return result


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--contract', type=Path, required=True)
  parser.add_argument('--contract-sha256', required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  api = helpers()
  info = args.contract.lstat()
  raw = api.pinned({'path': str(args.contract), 'sha256': args.contract_sha256,
    'bytes': info.st_size, 'mode': 0o600}, 1024**2)
  prepare(json.loads(raw), args.output)


if __name__ == '__main__': main()
