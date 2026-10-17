#!/usr/bin/env python3
"""Assemble a private source-pinned native boot set; never load or flash it.

The contract independently pins a regenerated host runtime component, built
helpers, guardian artifacts and phase inputs. A successful readback is host
assembly evidence only: native release additionally needs the outer controller,
fresh predecessor evidence, memory admission and the combined qualification.
Do not execute/import this producer before the whole source gate has closed.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import struct
from types import SimpleNamespace

from guardian_binding import (CONFIG_SHA256, DTB_SHA256, IMAGE_SHA256, INSTALL,
                              SOURCE_NAMES, validate)
from native_boot_context import (COMMON_RUNTIME, EARLY_FILES, INPUT_NAMES, INPUT_PATHS,
  PHASE_ROLE, RUNTIME_PREFIX, USB_STORAGE, admit, canonical, json_bytes, sha, source_path)
from native_phase_plan import admit_plan, admit_predecessor, decode
from native_layer_reader import read_layer
from native_unit_policy import files as policy_files
from stock_boot import read_newc, write_newc
from usb_root_profile import require

PORT = Path(__file__).resolve().parent.parent
SEED = 'usr/lib/shield-maintenance/native-seed/'
MAX_COMPONENT = 64 * 1024**2
MAX_EXPANDED = 768 * 1024**2
MAX_CAPSULE = 384 * 1024**2
ARTIFACT_NAMES = {'shield-guardian', 'shield-restart-recovery', 'guardian_binding.py',
  'guardian_client.py', 'qualification_recovery.py', 'usb_root_profile.py', 'overlay-manifest.json'}
SOURCE_REQUIRED = SOURCE_NAMES | {'tools/prepare-native-capsule.py', 'tools/stock_boot.py',
  'tools/prepare-maintenance-toolroot.py',
  'tools/prepare-native-bootstrap.py', 'tools/prepare-native-runtime.py',
  'tools/prepare-native-preimages.py',
  'qualification/native-init.c', 'qualification/bootstrap-io.c', 'qualification/bootstrap-io.h',
  'qualification/legacy-handoff.inc', 'qualification/legacy-watchdog-exec.c',
  'qualification/internal-ro.c', 'qualification/internal-ro-profile.h', 'qualification/early-health.c',
  'qualification/native-serial-transport.ps1'} | {
  'tools/' + name for name in COMMON_RUNTIME | {'native-boot.py', 'native-root-control.py',
    'native_children.py', 'native_mounts.py', 'native_root_storage.py', 'native_maintenance.py',
    'native_ram_recovery.py', 'native_work_guard.py', 'native_worker_reaper.py',
    'maintenance-worker.py', 'native_cleanup_rpc.py', 'native_unit_policy.py', 'native_host_link.py',
    'native_host_controller.py', 'native_recovery_observer.py', 'native_attempt_journal.py',
    'native_legacy_memory.py', 'native_phase_coordinator.py'}}


def digest(raw): return hashlib.sha256(raw).hexdigest()


def safe_name(name):
  require(type(name) is str and 0 < len(name) <= 512 and not name.startswith('/')
          and all(32 <= ord(char) <= 126 for char in name)
          and all(piece not in {'', '.', '..'} for piece in name.split('/')),
          'Unsafe archive/source name')
  return name


def pinned(item, limit):
  require(type(item) is dict and set(item) == {'path', 'sha256', 'bytes', 'mode'}
          and type(item['path']) is str and type(item['bytes']) is int
          and 0 < item['bytes'] <= limit and type(item['mode']) is int
          and item['mode'] in {0o600, 0o644, 0o700, 0o755}, 'Wrong host input pin')
  sha(item['sha256'])
  path = Path(item['path'])
  require(path.is_absolute() and path.is_relative_to(Path('/home/jresp'))
          and path.parent.resolve(strict=True) == path.parent, 'Host input outside native workspace')
  descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    before = os.fstat(descriptor)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size == item['bytes'], 'Host input object differs')
    with os.fdopen(os.dup(descriptor), 'rb') as stream: raw = stream.read(item['bytes'] + 1)
    after = os.fstat(descriptor)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'Host input changed')
    return raw
  finally: os.close(descriptor)


def source_snapshot(expected):
  require(type(expected) is dict and SOURCE_REQUIRED <= set(expected) and len(expected) <= 160,
          'Incomplete combined source cohort')
  for name, value in expected.items():
    safe_name(name); sha(value)
    path = PORT / name
    require(path.parent.resolve(strict=True).is_relative_to(PORT)
            and not path.is_symlink() and path.is_file() and digest(path.read_bytes()) == value,
            'Current producer/consumer source differs')


def component_entries(raw):
  # This is an independently hash-pinned own-producer component. Never extract
  # it on the host. Bounded decompression precedes the existing newc reader.
  with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as stream:
    expanded = stream.read(160 * 1024**2 + 1)
  require(len(expanded) <= 160 * 1024**2, 'Expanded base runtime exceeds host assembly budget')
  entries = read_newc(expanded)
  require(0 < len(entries) <= 4096 and 'init' not in entries, 'Base component must not have an init')
  for name, entry in entries.items():
    safe_name(name)
    kind, mode = stat.S_IFMT(entry['mode']), stat.S_IMODE(entry['mode'])
    require(kind in {stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK} and not mode & 0o6000
            and entry['rdevmajor'] == entry['rdevminor'] == 0
            and not name.startswith(('run/', 'dev/', 'proc/', 'sys/')),
            'Unexpected base runtime object')
  copies = {name for name in entries if name.startswith('usr/lib/shield-maintenance/')}
  require(copies == {'usr/lib/shield-maintenance/' + name for name in
                     ['usb_root_profile.py', 'usb_candidate_transaction.py']},
          'Unreviewed extra maintenance runtime copy in the base component')
  # Old components embedded the old implicit subprocess executor API. Refuse
  # those bytes rather than silently replacing an independently sealed base.
  for name in ['usb_root_profile.py', 'usb_candidate_transaction.py']:
    expected = (PORT / 'tools' / name).read_bytes()
    entry = entries.get('usr/lib/shield-maintenance/' + name)
    require(entry is not None and stat.S_ISREG(entry['mode']) and entry['data'] == expected,
            'Base runtime embeds stale maintenance APIs; regenerate it')
  archive_graph(entries)
  return entries


def archive_graph(entries):
  """Every member has real parents; symlinks are aliases, never write paths.

  The encoder orders each directory before its children. No kernel unpack
  write can traverse an alias. Link targets may resolve through declared
  aliases, but must finish at a declared real object without leaving root.
  """
  for name, entry in entries.items():
    safe_name(name)
    for parent in PurePosixPath(name).parents:
      if str(parent) == '.': continue
      require(str(parent) in entries and stat.S_ISDIR(entries[str(parent)]['mode']),
              'CPIO member has a missing or non-real parent')
    if not stat.S_ISLNK(entry['mode']): continue
    pending = list(PurePosixPath(name).parts)
    resolved, links = [], 0
    while pending:
      part = pending.pop(0)
      if part in {'', '.'}: continue
      if part == '..':
        require(resolved, 'CPIO symlink leaves the declared root')
        resolved.pop(); continue
      resolved.append(part)
      current = '/'.join(resolved)
      require(current in entries, 'CPIO symlink target is outside the selected inventory')
      target = entries[current]
      if stat.S_ISLNK(target['mode']):
        links += 1
        require(links <= 32 and 0 < len(target['data']) <= 4096 and b'\0' not in target['data'],
                'CPIO symlink cycle/target budget')
        text = target['data'].decode('ascii')
        resolved.pop()
        if text.startswith('/'): resolved.clear()
        pending = text.split('/') + pending
      elif pending:
        require(stat.S_ISDIR(target['mode']), 'CPIO alias traverses a non-directory')
    require(resolved, 'Broad CPIO root alias is not admitted')


def add(entries, name, data, mode):
  safe_name(name)
  require(name not in entries, 'Capsule member collision; never replace an admitted component')
  for parent in reversed(PurePosixPath(name).parents):
    parent = str(parent)
    if parent == '.': continue
    if parent not in entries:
      private = parent == SEED.rstrip('/') or parent.startswith(SEED)
      entries[parent] = {'mode': stat.S_IFDIR | (0o700 if private else 0o755),
                         'data': b'', 'rdevmajor': 0, 'rdevminor': 0}
    require(stat.S_ISDIR(entries[parent]['mode']), 'Capsule ancestor is not a real directory')
  entries[name] = {'mode': stat.S_IFREG | mode, 'data': data, 'rdevmajor': 0, 'rdevminor': 0}


def record(entry):
  require(stat.S_ISREG(entry['mode']), 'Pinned executable/module must be a regular file')
  return {'sha256': digest(entry['data']), 'bytes': len(entry['data']), 'mode': stat.S_IMODE(entry['mode'])}


def static_arm(raw):
  require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
          and struct.unpack_from('<HHI', raw, 16) == (2, 183, 1),
          'Expected static AArch64 executable')
  offset = struct.unpack_from('<Q', raw, 32)[0]
  header, step, count = struct.unpack_from('<HHH', raw, 52)
  require(header == 64 and step == 56 and 0 < count <= 128
          and 64 <= offset <= len(raw) - count * step, 'Invalid executable program headers')
  kinds = [struct.unpack_from('<I', raw, offset + index * step)[0] for index in range(count)]
  require(1 in kinds and 2 not in kinds and 3 not in kinds,
          'Bootstrap/guardian helper must not depend on a dynamic loader')


def command_line(phase, candidate, bundle_sha):
  tokens = ['console=tty0', 'loglevel=7', 'rdinit=/init', 'nokaslr', 'clk_ignore_unused',
    'regulator_ignore_unused', 'maxcpus=1', 'nr_cpus=1', 'cpuidle.off=1',
    'initcall_blacklist=tegra_cpufreq_init', 'shield.first-ram-probe=1',
    'tegra_smmu.reset_inherited=1', 'tegra_smmu.quarantine_gpub_inherited=1',
    'watchdog.open_timeout=240', 'watchdog.stop_on_reboot=0',
    'shield.guardian=' + candidate, 'shield.native-bundle=' + bundle_sha]
  if phase == 'systemd': tokens.append('systemd.unit=shield-qualification.target')
  return (' '.join(tokens) + '\n').encode('ascii')


def assemble(contract):
  require(type(contract) is dict and set(contract) == {'format_version', 'purpose', 'phase',
    'source_sha256', 'component', 'files', 'inputs', 'packages', 'kernel', 'kernel_config', 'dtb'}
    and type(contract['format_version']) is int and contract['format_version'] == 1
    and contract['purpose'] == 'host-only native capsule inputs'
    and contract['phase'] in PHASE_ROLE, 'Wrong host capsule contract')
  source_snapshot(contract['source_sha256'])
  phase = contract['phase']
  raw_component = pinned(contract['component'], MAX_COMPONENT)
  entries = component_entries(raw_component)
  early, data_by_destination = {}, {}
  require(type(contract['files']) is dict and 0 < len(contract['files']) <= 128,
          'Wrong capsule source file inventory')
  for name, item in contract['files'].items():
    source_path(name)
    require(name not in entries and name not in {'boot.json', *INPUT_PATHS.values()},
            'Capsule source must be an explicit noncolliding addition')
    raw = pinned(item, 8 * 1024**2)
    if name.endswith('.py'):
      require(raw == (PORT / 'tools' / PurePosixPath(name).name).read_bytes(),
              'Runtime Python copy differs from the current source cohort')
      require(item['mode'] == 0o644, 'Runtime Python must use the explicit fixed interpreter')
    if name in {'init', 'bin/busybox'} or PurePosixPath(name).name in {
        'shield-early-health', 'shield-internal-ro', 'shield-guardian', 'shield-restart-recovery'}:
      require(item['mode'] == (0o755 if name == 'bin/busybox' else 0o700),
              'Native bootstrap/guardian helper mode differs')
      static_arm(raw)
    if name.endswith('.json'): require(item['mode'] == 0o600, 'Private runtime sidecar mode differs')
    destination = SEED + name[len('run/shield-native/'):] if name.startswith('run/shield-native/') else name
    add(entries, destination, raw, item['mode'])
    early[name] = record(entries[destination]); data_by_destination[name] = raw
  for name in EARLY_FILES:
    require(name in entries, 'Mandatory early runtime file absent')
    early[name] = record(entries[name])
    expected_mode = (0o700 if name == 'init' else 0o755 if name in
      {'bin/busybox', 'usr/bin/python3.14', 'usr/bin/switch_root'} else 0o644)
    require(early[name]['mode'] == expected_mode, 'Early executable/firmware/module mode differs')
  prefix = str(INSTALL).lstrip('/') + '/'
  profile_raw, artifact_raw = [data_by_destination[prefix + name] for name in ['profile.json', 'artifacts.json']]
  profile, artifacts = validate(decode(profile_raw)), decode(artifact_raw)
  require(profile['role'] == PHASE_ROLE[phase] and artifacts['role'] == profile['role']
          and artifacts['candidate'] == profile['candidate'] and artifacts['compiled_enabled'] is True
          and artifacts['profile_sha256'] == digest(profile_raw)
          and artifacts['source_inputs_sha256'] == profile['sources']
          and set(artifacts['files']) == ARTIFACT_NAMES, 'Guardian artifact/profile closure differs')
  for name, value in profile['sources'].items():
    require(contract['source_sha256'][name] == value, 'Guardian was built from another source cohort')
  for name, identity in artifacts['files'].items():
    item = early[prefix + name]
    require(identity == {key: item[key] for key in ['sha256', 'bytes']}, 'Guardian runtime artifact differs')
  require(artifacts['files']['shield-restart-recovery'] == profile['recovery_helper'],
          'Recovery helper/profile differs')
  require(type(contract['inputs']) is dict and set(contract['inputs']) == INPUT_NAMES[phase],
          'Wrong phase input closure')
  inputs, input_bytes = {}, {}
  for name, item in contract['inputs'].items():
    raw = pinned(item, 64 * 1024**2 if name == 'layer' else 16 * 1024**2)
    require(item['mode'] == 0o600, 'Phase input must be private')
    inputs[name] = {'sha256': digest(raw), 'bytes': len(raw)}
    input_bytes[name] = raw
    add(entries, SEED + 'inputs/' + INPUT_PATHS[name], raw, 0o600)
  require(type(contract['packages']) is dict and len(contract['packages']) <= 12
          and (phase == 'packages' or not contract['packages']),
          'Only package phase stages archives and required signatures')
  if phase == 'packages':
    payload = decode(input_bytes['payload'])
    expected = {item['filename']: item for item in payload['packages'].values()}
    expected.update({item['signature']['filename']: item['signature']
                     for item in payload['packages'].values() if 'signature' in item})
    require(set(contract['packages']) == set(expected), 'Wrong exact package archive/signature names')
    for name, pin in contract['packages'].items():
      require('/' not in name and name not in {'', '.', '..'}, 'Unsafe package archive name')
      raw = pinned(pin, 256 * 1024**2)
      require(digest(raw) == expected[name]['sha256'] and len(raw) == expected[name]['bytes'],
              'Staged package differs from matched payload')
      add(entries, SEED + 'packages/' + name, raw, 0o600)
  root = {}
  if phase == 'systemd':
    root = {name: dict(item) for name, item in early.items()
            if name.startswith(RUNTIME_PREFIX) or name.startswith(prefix)}
    root.update({name: {'sha256': digest(raw), 'bytes': len(raw), 'mode': 0o644}
                 for name, raw in policy_files().items()})
  configuration = {'phase': phase,
    'kernel': {'image_sha256': IMAGE_SHA256, 'config_sha256': CONFIG_SHA256, 'release': '7.1.0-shield-bringup'},
    'dtb_sha256': DTB_SHA256, 'guardian_profile_sha256': digest(profile_raw),
    'guardian_artifacts_sha256': digest(artifact_raw), 'sources': {'early': early},
    'inputs': inputs, 'early_runtime_component': {'cpio_sha256': digest(raw_component),
      'cpio_bytes': len(raw_component)}, 'usb_storage': dict(USB_STORAGE)}
  if root: configuration['sources']['root'] = root
  # Exercise the SAME pure content contract the native filesystem reader will
  # use. This does not stand in for physical preimages or a running boot ID.
  reference = SimpleNamespace(phase=phase, profile=profile, configuration=configuration)
  phase_plan = admit_plan(reference, decode(input_bytes['payload']), decode(input_bytes['plan']))
  if phase == 'layer':
    admit_predecessor(reference, phase_plan, 'predecessor', 'packages', decode(input_bytes['predecessor']))
  if phase == 'systemd':
    a = admit_predecessor(reference, phase_plan, 'predecessorA', 'packages', decode(input_bytes['predecessorA']))
    b = admit_predecessor(reference, phase_plan, 'predecessorB', 'layer', decode(input_bytes['predecessorB']))
    require(a['boot_id'] != b['boot_id'] and a['session_id'] != b['session_id'],
            'Preparation predecessors must be distinct boots and sessions')
  if phase != 'packages':
    for name, expected in phase_plan.writer.layer.sources:
      require(contract['source_sha256'].get(name) == expected,
              'Layer producer source differs from the independent current cohort')
    content = read_layer(contract['inputs']['layer']['path'], phase_plan.writer.layer)
    if phase == 'layer':
      from native_layer_writer import admit as admit_layer
      admit_layer(content, phase_plan.writer, input_bytes['preimages'])
    else:
      for name, item in root.items():
        if not name.startswith(prefix): continue
        wanted = content.manifest['entries'][name]['identity']
        require(wanted['type'] == 'file' and wanted['uid'] == wanted['gid'] == 0
                and all(wanted[key] == item[key] for key in ['sha256', 'bytes', 'mode']),
                'Selected root guardian/runtime copy differs from the completed layer')
  config_sha = digest(canonical(configuration))
  channels, keys = {}, {}
  for epoch in configuration['sources']:
    keys[epoch] = secrets.token_bytes(32)
    channels[epoch] = {'version': 1, 'session_id': secrets.token_hex(32), 'phase': phase,
      'role': PHASE_ROLE[phase], 'candidate': profile['candidate'], 'config_sha256': config_sha}
    add(entries, SEED + 'keys/' + epoch + '.key', keys[epoch], 0o600)
  bundle = {'format_version': 1, 'configuration': configuration, 'configuration_sha256': config_sha,
    'channels': channels, 'key_sha256': {name: digest(raw) for name, raw in keys.items()}}
  admit(bundle)
  boot_raw = canonical(bundle)
  add(entries, SEED + 'boot.json', boot_raw, 0o600)
  archive_graph(entries)
  require(sum(len(item['data']) for item in entries.values()) <= MAX_EXPANDED,
          'Capsule expanded assembly budget exceeded; no physical-fit claim')
  archive = gzip.compress(write_newc(entries), compresslevel=9, mtime=0)
  require(len(archive) <= MAX_CAPSULE and read_newc(gzip.decompress(archive)) == entries,
          'Capsule assembly/readback differs or exceeds host budget')
  blobs = {'initramfs.cpio.gz': archive, 'boot.json': boot_raw,
    'cmdline.txt': command_line(phase, profile['candidate'], digest(boot_raw))}
  for name, field, expected in [('Image', 'kernel', IMAGE_SHA256),
      ('kernel.config', 'kernel_config', CONFIG_SHA256), ('board.dtb', 'dtb', DTB_SHA256)]:
    raw = pinned(contract[field], 64 * 1024**2)
    require(digest(raw) == expected, 'Selected kernel/config/DT differs')
    blobs[name] = raw
  # Keys stay in the private host artifact and RAM seed. They never enter a
  # command line, the Windows serial process, stdout or public receipts.
  for epoch, raw in keys.items(): blobs[epoch + '.key'] = raw
  source_snapshot(contract['source_sha256'])
  return blobs, {'format_version': 1, 'purpose': 'host-only assembled native boot set',
    'phase': phase, 'entries': len(entries), 'regular_bytes': sum(len(item['data']) for item in entries.values()
      if stat.S_ISREG(item['mode'])), 'source_sha256': contract['source_sha256'],
    'configuration_sha256': config_sha, 'bundle_sha256': digest(boot_raw),
    'files': {name: {'sha256': digest(raw), 'bytes': len(raw)} for name, raw in blobs.items()},
    'roundtrip_verified': True, 'actual_loaded_segment_fit_verified': False,
    'native_execution_released': False, 'device_operations': False, 'boot_ready': False}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--contract', type=Path, required=True)
  parser.add_argument('--contract-sha256', required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'Private WSL root assembly required')
  os.umask(0o077)
  raw = args.contract.read_bytes()
  require(0 < len(raw) <= 512 * 1024 and digest(raw) == sha(args.contract_sha256), 'Contract pin differs')
  contract = json_bytes(raw)
  blobs, receipt = assemble(contract)
  require(args.output.is_absolute() and args.output.is_relative_to(Path('/home/jresp/build/omarchy-shield'))
          and args.output.parent.resolve(strict=True) == args.output.parent, 'Unsafe host output location')
  args.output.mkdir(mode=0o700)  # Existing/uncertain outputs are never adopted.
  for name, data in blobs.items():
    with (args.output / name).open('xb') as stream:
      os.fchmod(stream.fileno(), 0o600); stream.write(data); stream.flush(); os.fsync(stream.fileno())
    require((args.output / name).read_bytes() == data, 'Published boot set readback differs')
  receipt['contract_sha256'] = digest(raw)
  with (args.output / 'receipt.json').open('xb') as stream:
    stream.write(canonical(receipt)); stream.flush(); os.fsync(stream.fileno())
  fd = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try: os.fsync(fd)
  finally: os.close(fd)
  print('Private native boot set assembled and read back; execution remains unreleased.')


if __name__ == '__main__': main()
