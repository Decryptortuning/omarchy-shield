#!/usr/bin/env python3
"""Check actual padctl supplier preflight and resource cleanup without hardware."""
import argparse
import hashlib
import json
from pathlib import Path
import re
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
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  source_path = args.kernel_source / 'drivers/phy/tegra/xusb.c'
  source = source_path.read_text()
  probe = function(source, 'tegra_xusb_padctl_probe')
  ordered = ['err = tegra_xusb_check_vbus_supplies(&pdev->dev, soc);',
             'soc->ops->probe(', 'devm_platform_ioremap_resource(',
             'reset_control_deassert(', 'tegra_xusb_setup_pads(',
             'tegra_xusb_setup_ports(']
  offsets = [probe.index(value) for value in ordered]
  if offsets != sorted(offsets):
    raise ValueError('VBUS supplier check must precede hardware probe/MMIO/reset')
  between = probe[offsets[0]:offsets[1]]
  if 'if (err)\n\t\treturn err;' not in between:
    raise ValueError('Supplier errors must return before touching hardware')
  driver = function(source, 'tegra_xusb_check_vbus_supplies')
  if any(name in driver for name in ('regulator_enable', 'regulator_disable',
                                    'reset_control_', 'padctl_writel')):
    raise ValueError('Preflight must not change regulator, reset or PHY state')
  template = (Path(__file__).resolve().parent.parent / 'tests/xusb-supplies-harness.c').read_text()
  code = template.replace('/* DRIVER */', driver)
  with tempfile.TemporaryDirectory(prefix='shield-xusb-supplies-') as directory:
    root = Path(directory)
    (root / 'test.c').write_text(code)
    subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', '-o', str(root / 'test'), str(root / 'test.c')], check=True)
    result = subprocess.run([str(root / 'test')], capture_output=True, text=True, check=True)
  report = {'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'actual_driver_function': 'tegra_xusb_check_vbus_supplies',
            'supplier_errors_precede_hardware_probe_MMIO_and_reset': True,
            'result': result.stdout.strip(),
            'scope': 'Actual source with fake OF/regulator providers; no physical USB or kernel build qualification',
            'device_actions_performed': []}
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print(result.stdout.strip())


if __name__ == '__main__':
  main()
