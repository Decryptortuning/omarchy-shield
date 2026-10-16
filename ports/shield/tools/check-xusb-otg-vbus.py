#!/usr/bin/env python3
"""Exercise the actual Tegra210 OTG callback with regulator ownership checks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import tempfile


def function(source, name):
  match = re.search(r'^static int ' + re.escape(name) + r'\([^;]+?\n\{', source, re.M)
  if not match:
    raise ValueError(f'Missing actual driver function: {name}')
  end, depth = match.end(), 1
  while depth:
    if source[end] == '{':
      depth += 1
    elif source[end] == '}':
      depth -= 1
    end += 1
  return source[match.start():end] + '\n'


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--kernel-source', required=True, type=Path)
  parser.add_argument('--baseline-kernel-source', type=Path)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  relative = Path('drivers/phy/tegra/xusb-tegra210.c')
  source = (args.kernel_source / relative).read_text()
  header = (args.kernel_source / 'drivers/phy/tegra/xusb.h').read_text()
  port = re.search(r'^struct tegra_xusb_usb2_port \{.*?^\};', header, re.M | re.S)
  if not port or 'bool otg_vbus_enabled;' not in port[0]:
    raise ValueError('Missing actual per-port OTG VBUS ownership field')
  callback = function(source, 'tegra210_usb2_phy_set_mode')
  template = (Path(__file__).resolve().parent.parent / 'tests/xusb-otg-vbus-harness.c').read_text()
  code = template.replace('/* PORT */', port[0]).replace('/* DRIVER */', callback)
  controls = {}
  if args.baseline_kernel_source:
    baseline = (args.baseline_kernel_source / relative).read_text()
    # Fixed-host init/exit own a separate reference. They must not change.
    for name in ('tegra210_usb2_phy_init', 'tegra210_usb2_phy_exit'):
      if function(source, name) != function(baseline, name):
        raise ValueError(f'Fixed-host ownership changed: {name}')
    controls['baseline_unowned_disable'] = code.replace(
      callback, function(baseline, 'tegra210_usb2_phy_set_mode'))
  mutations = {
    'shared_supply_is_not_consumer_ownership': ('if (port->otg_vbus_enabled) {',
                                               'if (regulator_is_enabled(port->supply)) {'),
    'duplicate_host_leaks_reference': ('if (!port->otg_vbus_enabled) {', 'if (true) {'),
    'failed_enable_must_propagate': ('if (err)\n\t\t\t\t\tgoto unlock;',
                                   'if (false)\n\t\t\t\t\tgoto unlock;'),
    'successful_disable_releases_ownership': ('port->otg_vbus_enabled = false;',
                                             'port->otg_vbus_enabled = true;'),
  }
  for name, (old, new) in mutations.items():
    if old not in callback:
      raise ValueError(f'Missing negative control target: {name}')
    controls[name] = code.replace(callback, callback.replace(old, new, 1))
  with tempfile.TemporaryDirectory(prefix='shield-xusb-otg-') as directory:
    root = Path(directory)
    results = {}
    for name, text in {'actual_driver': code, **controls}.items():
      unit, binary = root / f'{name}.c', root / name
      unit.write_text(text)
      subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                      '-fsanitize=undefined', '-o', str(binary), str(unit)], check=True)
      # Failed controls intentionally assert; keep core files out of the workspace.
      result = subprocess.run([str(binary)], cwd=root, capture_output=True, text=True,
                              preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
      if name == 'actual_driver':
        result.check_returncode()
        passed = result.stdout.strip()
      elif result.returncode == 0 or 'Assertion' not in result.stderr:
        raise ValueError(f'Negative control did not fail by assertion: {name}')
      results[name] = {'returncode': result.returncode, 'expected_failure': name != 'actual_driver'}
  report = {
    'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
    'header_sha256': hashlib.sha256(header.encode()).hexdigest(),
    'actual_driver_function': 'tegra210_usb2_phy_set_mode',
    'result': passed,
    'controls': results,
    'fixed_host_init_exit_compared_with_baseline': args.baseline_kernel_source is not None,
    'scope': 'Actual C callback and port declaration with fake regulator/MMIO helpers; no physical role switching, workqueue ordering or external-drive enumeration qualification',
    'device_actions_performed': [],
  }
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print(passed)
  print(f'PASS: {len(controls)} negative controls rejected')


if __name__ == '__main__':
  main()
