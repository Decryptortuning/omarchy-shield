#!/usr/bin/env python3
"""Report build coverage separately from physical Shield qualification."""
import argparse
import json
from pathlib import Path
import re
import subprocess
from tools.kernel_profile import verify_kernel_profile
from tools.board_firmware import verify_stage, installed_identity
from tools.fan_profile import inspect_fan_contract


def device_tree_status(dtb, path):
  nodes = ['/' + '/'.join(path.strip('/').split('/')[:count])
      for count in range(1, len(path.strip('/').split('/')) + 1)]
  for node in nodes:
    present = subprocess.run(['fdtget', '-p', str(dtb), node], capture_output=True)
    if present.returncode:
      return {'enabled': False, 'reason': f'missing node {node}'}
    value = subprocess.run(['fdtget', str(dtb), node, 'status'], capture_output=True, text=True)
    if value.returncode == 0 and value.stdout.strip() not in ('okay', 'ok'):
      return {'enabled': False, 'reason': f'{node}: {value.stdout.strip()}'}
  return {'enabled': True, 'reason': 'node and ancestors enabled by explicit or default status'}


def main():
  port = Path(__file__).resolve().parent
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--kernel-dir', type=Path, default=port / 'build/kernel')
  parser.add_argument('--rootfs', type=Path)
  parser.add_argument('--firmware-stage', type=Path, help='Verify inactive Darcy staging separately from installed firmware')
  parser.add_argument('--output', type=Path, default=port / 'build/hardware-audit.json')
  args = parser.parse_args()
  try:
    lock, dtb = verify_kernel_profile(args.kernel_dir, allow_legacy=True)
  except (ValueError, OSError, KeyError) as error:
    raise SystemExit(str(error)) from error
  matrix = args.kernel_dir / 'hardware.json'
  if 'hardware_matrix' not in lock:
    # Historical B01 bundles predate portable acceptance-matrix snapshots.
    matrix = port / 'hardware.json'
  requirements = json.loads(matrix.read_text())
  staged = []
  staging_report = None
  if args.firmware_stage:
    try:
      firmware_name = 'firmware-darcy-a08.lock.json' if lock['board_variant'] == 'darcy-t210-a08' else 'firmware-darcy.lock.json'
      firmware_lock, staging_report = verify_stage(args.firmware_stage, port / firmware_name, lock['board_variant'])
    except (ValueError, OSError, KeyError) as error:
      raise SystemExit(str(error)) from error
    for entry in firmware_lock['entries']:
      if entry['usage'] == 'notice':
        continue
      staged.append({'id': entry['id'], 'subsystem': entry['subsystem'], 'usage': entry['usage'],
                     'runtime_request': entry['runtime_request'], 'staged_bytes_verified': True,
                     'installed_identity': installed_identity(args.rootfs / 'usr/lib/firmware', entry)
                     if args.rootfs else {'status': 'not-inspected'}, 'physical_status': 'untested'})
  config = {}
  for line in (args.kernel_dir / 'kernel.config').read_text().splitlines():
    if re.match(r'^CONFIG_\w+=', line):
      key, value = line.split('=', 1)
      config[key] = value
  modules = []
  archive = args.kernel_dir / 'kernel-modules.tar.zst'
  if archive.exists():
    result = subprocess.check_output(['tar', '--zstd', '-tf', str(archive)], text=True)
    modules = result.splitlines()
  module_names = {Path(entry).name.split('.ko', 1)[0].replace('_', '-')
          for entry in modules if '.ko' in Path(entry).name}
  items = []
  for item in requirements['subsystems']:
    symbols = {name: config.get(name, 'n') for name in item.get('config', [])}
    absent = [name for name, value in symbols.items() if value not in ('m', 'y')]
    module_checks = {name: name.replace('_', '-') in module_names
            for name in item.get('modules', [])}
    firmware = {}
    if args.rootfs:
      firmware_root = args.rootfs / 'usr/lib/firmware'
      for pattern in item.get('firmware_patterns', []):
        firmware[pattern] = [str(path.relative_to(firmware_root)) for path in firmware_root.glob(pattern)]
    tree = {path: device_tree_status(dtb, path) for path in item.get('device_tree_nodes', [])}
    items.append({**item, 'config_values': symbols, 'missing_config': absent,
           'packaged_modules': module_checks, 'firmware_candidates': firmware,
           'compiled_device_tree': tree,
           'staged_firmware': [entry for entry in staged if entry['subsystem'] == item['id']],
           'physical_status': 'untested',
           'build_config_complete': (not absent and all(module_checks.values())) if symbols else None})
  report = {'target': requirements['target'], 'board_variant': lock.get('board_variant', 'mdarcy-t210b01'),
       'device_tree': dtb.name, 'subsystems': items,
       'darcy_fan_contract': inspect_fan_contract(dtb) if lock.get('board_variant', '').startswith('darcy-t210-') else None,
       'inactive_firmware_stage': {'lock_sha256': staging_report['lock_sha256'], 'verified_files': len(staging_report['files'])}
       if staging_report else None,
       'all_physical_tests_passed': False, 'physical_shield_boot_tested': False,
       'meaning': 'Configured/packaged drivers and firmware candidates are not proof that hardware works.'}
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print(json.dumps({'subsystems': len(items),
           'missing_config': {item['id']: item['missing_config'] for item in items if item['missing_config']},
           'missing_modules': {item['id']: [name for name, present in item['packaged_modules'].items() if not present]
                     for item in items if not all(item['packaged_modules'].values())},
           'disabled_device_tree_nodes': {item['id']: {path: state['reason'] for path, state in item['compiled_device_tree'].items() if not state['enabled']}
                          for item in items if any(not state['enabled'] for state in item['compiled_device_tree'].values())},
           'missing_firmware_candidates': {item['id']: [pattern for pattern, matches in item['firmware_candidates'].items() if not matches]
                           for item in items if any(not matches for matches in item['firmware_candidates'].values())},
           'staged_files_verified': len(staging_report['files']) if staging_report else 0,
           'installed_firmware_identity': {entry['id']: entry['installed_identity']['status'] for entry in staged
                                           if entry['usage'] == 'driver-candidate'},
           'physical_tests_passed': 0}, indent=2))


if __name__ == '__main__':
  main()
