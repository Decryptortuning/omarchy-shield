"""Compile private native bootstrap helpers; never execute or install them.

Run explicitly with the host Python after the combined source review. The
contract pins the compiler, both fresh guardian outputs, retained MMC metadata,
and the complete source cohort. Unknown MMC starts/sectors remain unknown.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess

from guardian_binding import SOURCE_NAMES, canonical, validate
from usb_root_profile import require

PORT = Path(__file__).resolve().parent.parent
SOURCES = SOURCE_NAMES | {
  'tools/prepare-native-bootstrap.py', 'qualification/native-init.c',
  'qualification/legacy-watchdog-exec.c', 'qualification/bootstrap-io.c',
  'qualification/bootstrap-io.h', 'qualification/early-health.c',
  'qualification/internal-ro.c', 'qualification/internal-ro-profile.h'}
FLAGS = ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-static',
         '-Wl,--build-id=none']


def sha(raw): return hashlib.sha256(raw).hexdigest()


def read(path, limit=8 * 1024**2):
  path = Path(path)
  require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
          'Input parent must be a canonical absolute directory')
  fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
  try:
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 < before.st_size <= limit, 'Wrong bounded regular input')
    with os.fdopen(os.dup(fd), 'rb') as stream: raw = stream.read(limit + 1)
    after = os.fstat(fd)
    fields = ['st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
              'st_size', 'st_mtime_ns', 'st_ctime_ns']
    require(all(getattr(before, key) == getattr(after, key) for key in fields)
            and len(raw) == before.st_size, 'Input changed while reading')
    return raw
  finally:
    os.close(fd)


def pinned(item, limit=8 * 1024**2):
  require(type(item) is dict and set(item) == {'path', 'sha256', 'bytes'}
          and type(item['bytes']) is int and 0 < item['bytes'] <= limit
          and type(item['sha256']) is str
          and re.fullmatch('[0-9a-f]{64}', item['sha256']), 'Wrong input pin')
  raw = read(item['path'], limit)
  require(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'Pinned input differs')
  return raw


def snapshot(expected):
  require(type(expected) is dict and SOURCES <= set(expected) and len(expected) <= 160,
          'Incomplete source cohort')
  for name, value in expected.items():
    require(type(name) is str and not name.startswith('/')
            and all(x not in {'', '.', '..'} for x in name.split('/'))
            and type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'Unsafe source pin')
    require(sha(read(PORT / name)) == value, 'Source cohort changed: ' + name)


def guardian(item, role, sources):
  require(type(item) is dict and set(item) == {'directory', 'artifacts_sha256'},
          'Wrong guardian input')
  base = Path(item['directory'])
  require(base.is_absolute() and base.resolve(strict=True) == base
          and base.stat().st_uid == 0 and not base.stat().st_mode & 0o077,
          'Guardian artifacts must be private and root owned')
  artifact_raw = read(base / 'artifacts.json')
  require(sha(artifact_raw) == item['artifacts_sha256'], 'Guardian artifact pin differs')
  artifact = json.loads(artifact_raw)
  profile_raw = read(base / 'profile.json')
  profile = validate(json.loads(profile_raw))
  expected = {name: sources[name] for name in SOURCE_NAMES}
  require(artifact['source_inputs_sha256'] == profile['sources'] == expected
          and artifact['role'] == profile['role'] == role
          and artifact['candidate'] == profile['candidate']
          and artifact['profile_sha256'] == sha(profile_raw)
          and artifact['compiled_enabled'] is True
          and artifact['installed'] is False
          and artifact['native_execution_released'] is False
          and artifact['boot_ready'] is False, 'Guardian binding differs')
  require(set(artifact['files']) == {'shield-guardian', 'shield-restart-recovery',
    'guardian_binding.py', 'guardian_client.py', 'qualification_recovery.py',
    'usb_root_profile.py', 'overlay-manifest.json'}, 'Incomplete guardian artifact closure')
  for name, pin in artifact['files'].items():
    require('/' not in name and name not in {'.', '..'}, 'Unsafe guardian artifact name')
    raw = read(base / name)
    require(pin == {'sha256': sha(raw), 'bytes': len(raw)}, 'Guardian artifact changed')
  header = read(base / 'build/profile.h')
  template = read(PORT / 'guardian/profile.h').decode('ascii')
  for before, after in {
      '#define SG_PROFILE_ENABLED 0': '#define SG_PROFILE_ENABLED 1',
      '#define SG_PROFILE_ROLE 1': '#define SG_PROFILE_ROLE ' + str(role),
      '"' + '0' * 64 + '"': '"' + profile['candidate'] + '"'}.items():
    require(template.count(before) == 1, 'Guardian template changed')
    template = template.replace(before, after)
  require(header == template.encode('ascii')
          and sha(header) == artifact['generated_profile_header_sha256'],
          'Generated guardian header differs')
  return profile, header


def mmc_header(value, candidate):
  controller = value['controller']
  require(controller['platform_node'] == '700b0600.mmc'
          and controller['compatible'] == 'nvidia,tegra210-sdhci'
          and controller['card_type'] == 'MMC'
          and controller['USER_parent_sectors'] == 30777344
          and controller['USER_partition_count'] == 33
          and controller['boot_and_RPMB_open_forbidden'] is True,
          'Retained MMC identity differs')
  rows = value['partition_rows']
  require(type(rows) is list and len(rows) == 33, 'Incomplete retained partition metadata')
  indices, labels, lines = set(), set(), []
  for row in rows:
    index, label, blocks = row['index'], row['label'], row['blocks_1024']
    start, sectors = row['start'], row['sectors']
    require(type(index) is int and 1 <= index <= 33 and index not in indices
            and type(label) is str and re.fullmatch('[A-Za-z0-9_-]{1,31}', label)
            and label not in labels and type(blocks) is int and 0 < blocks < 30777344 // 2
            and type(row['start_pinned']) is bool
            and row['start_pinned'] == (start is not None), 'Invalid retained partition row')
    for number in [start, sectors]:
      require(number is None or type(number) is int and 0 < number < 30777344,
              'Invalid retained exact geometry')
    require(sectors is None or sectors >> 1 == blocks, 'Retained sector/block disagreement')
    require(start is None or sectors is None or start + sectors <= 30777344,
            'Retained partition exceeds parent')
    indices.add(index); labels.add(label)
    # /proc blocks establish an interval only. Never substitute blocks * 2.
    number = lambda x: 'UINT64_MAX' if x is None else 'UINT64_C(' + str(x) + ')'
    lines.append('  { .index = %d, .start = %s, .sectors = %s, '
                 '.blocks1024 = UINT64_C(%d), .label = "%s" }' %
                 (index, number(start), number(sectors), blocks, label))
  template = read(PORT / 'qualification/internal-ro-profile.h').decode('ascii')
  begin = template.index('static const struct sir_partition sir_partitions[SIR_PARTITIONS] = {')
  end = template.index('\n};', begin) + len('\n};')
  template = template[:begin] + (
    'static const struct sir_partition sir_partitions[SIR_PARTITIONS] = {\n'
    + ',\n'.join(lines) + '\n};') + template[end:]
  for before, after in {
      '#define SIR_PROFILE_ENABLED 0': '#define SIR_PROFILE_ENABLED 1',
      '#define SIR_PARTITIONS 1': '#define SIR_PARTITIONS 33',
      '"' + '0' * 64 + '"': '"' + candidate + '"'}.items():
    require(template.count(before) == 1, 'Internal RO template changed')
    template = template.replace(before, after)
  return template.encode('ascii')


def static_arm(raw):
  require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
          and struct.unpack_from('<HH', raw, 16) == (2, 183), 'Not static AArch64 ET_EXEC')
  offset = struct.unpack_from('<Q', raw, 32)[0]
  size, step, count = struct.unpack_from('<HHH', raw, 52)
  require(size == 64 and step == 56 and 0 < count <= 128
          and 64 <= offset <= len(raw) - step * count, 'Invalid ELF program headers')
  kinds = [struct.unpack_from('<I', raw, offset + step * x)[0] for x in range(count)]
  require(1 in kinds and 2 not in kinds and 3 not in kinds, 'Dynamic bootstrap helper refused')


def prepare(contract, output):
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
          'Compile private helpers as WSL root')
  os.umask(0o077)
  require(type(contract) is dict and set(contract) == {'format_version', 'purpose',
    'source_sha256', 'compiler', 'guardians', 'retained_mmc'}
    and type(contract['format_version']) is int and contract['format_version'] == 1
    and contract['purpose'] == 'host-only native bootstrap compilation'
    and set(contract['guardians']) == {'maintenance', 'systemd'}, 'Wrong bootstrap contract')
  snapshot(contract['source_sha256'])
  pinned(contract['compiler'], 64 * 1024**2)
  compiler = Path(contract['compiler']['path'])
  require(compiler.stat().st_uid == 0 and os.access(compiler, os.X_OK), 'Unowned compiler')
  retained_raw = pinned(contract['retained_mmc'])
  retained = json.loads(retained_raw)
  # Source provenance is pinned as well as the retained interpretation.
  for item in retained['source_pins']: pinned(item, 64 * 1024**2)
  profiles = {name: guardian(item, role, contract['source_sha256'])
    for name, role, item in [(name, role, contract['guardians'][name])
      for name, role in [('maintenance', 1), ('systemd', 2)]]}
  require(all(profiles['maintenance'][0][key] == profiles['systemd'][0][key]
              for key in profiles['maintenance'][0] if key not in {'role', 'candidate'}),
          'Maintenance/systemd guardians must bind the same filesystem and inputs')
  require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
          and not output.exists() and not output.is_symlink(), 'Use a new canonical output')
  output.mkdir(mode=0o700)
  env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': '0'}
  records = {}

  def build(directory, name, sources):
    target = directory / name
    subprocess.run([str(compiler), *FLAGS, *map(str, sources), '-o', str(target)],
                   env=env, cwd=directory, check=True, timeout=120)
    target.chmod(0o700)
    raw = read(target)
    static_arm(raw)
    records[str(target.relative_to(output))] = {'sha256': sha(raw), 'bytes': len(raw), 'mode': 0o700}

  common = output / 'common'
  common.mkdir(mode=0o700)
  for source, target in [('native-init.c', 'native-init'),
                         ('legacy-watchdog-exec.c', 'legacy-watchdog-exec')]:
    shutil.copyfile(PORT / 'qualification' / source, common / source)
    build(common, target, [common / source])
  for name, (profile, header) in profiles.items():
    directory = output / name
    directory.mkdir(mode=0o700)
    for source in ['guardian.h', 'sampler.c', 'state.c']:
      shutil.copyfile(PORT / 'guardian' / source, directory / source)
    for source in ['internal-ro.c', 'early-health.c', 'bootstrap-io.c', 'bootstrap-io.h']:
      shutil.copyfile(PORT / 'qualification' / source, directory / source)
    (directory / 'profile.h').write_bytes(header)
    (directory / 'internal-ro-profile.h').write_bytes(mmc_header(retained, profile['candidate']))
    for generated in ['profile.h', 'internal-ro-profile.h']:
      (directory / generated).chmod(0o600)
    shared = [directory / x for x in ['sampler.c', 'state.c', 'bootstrap-io.c']]
    build(directory, 'shield-internal-ro', [directory / 'internal-ro.c', *shared])
    if name == 'systemd':
      build(directory, 'shield-early-health', [directory / 'early-health.c', *shared])
  snapshot(contract['source_sha256'])
  pinned(contract['compiler'], 64 * 1024**2)
  require(pinned(contract['retained_mmc']) == retained_raw, 'Retained metadata changed')
  for item in retained['source_pins']: pinned(item, 64 * 1024**2)
  for name, role in [('maintenance', 1), ('systemd', 2)]:
    require(guardian(contract['guardians'][name], role, contract['source_sha256']) == profiles[name],
            'Guardian changed during compilation')
  receipt = {'format_version': 1, 'purpose': 'host-only native bootstrap compilation',
    'contract_sha256': sha(canonical(contract)), 'source_sha256': contract['source_sha256'],
    'files': records, 'generated_header_sha256': {name: {
      leaf: sha(read(output / name / leaf)) for leaf in ['profile.h', 'internal-ro-profile.h']}
      for name in profiles}, 'compiler': contract['compiler'],
    'target_artifacts_executed': False, 'installed': False,
    'native_execution_released': False, 'boot_ready': False}
  with (output / 'receipt.json').open('xb') as stream:
    stream.write(canonical(receipt) + b'\n')
    stream.flush(); os.fsync(stream.fileno())
  (output / 'receipt.json').chmod(0o600)
  return receipt


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--contract', type=Path, required=True)
  parser.add_argument('--contract-sha256', required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  raw = read(args.contract)
  require(sha(raw) == args.contract_sha256, 'Bootstrap contract pin differs')
  prepare(json.loads(raw), args.output)


if __name__ == '__main__': main()
