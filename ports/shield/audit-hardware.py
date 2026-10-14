#!/usr/bin/env python3
"""Report build coverage separately from physical Shield qualification."""
import argparse
import json
from pathlib import Path
import re
import subprocess


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
  parser.add_argument('--output', type=Path, default=port / 'build/hardware-audit.json')
  args = parser.parse_args()
  requirements = json.loads((port / 'hardware.json').read_text())
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
  dtb = args.kernel_dir / 'tegra210b01-p2894-2551-b00.dtb'
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
           'physical_status': 'untested',
           'build_config_complete': (not absent and all(module_checks.values())) if symbols else None})
  report = {'target': requirements['target'], 'subsystems': items,
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
           'physical_tests_passed': 0}, indent=2))


if __name__ == '__main__':
  main()
