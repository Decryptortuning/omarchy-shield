#!/usr/bin/env python3
"""Verify the compiled Darcy A04 VBUS enable GPIO contract."""
import argparse
import json
from pathlib import Path
import subprocess


def inspect(dtb):
  def cells(node, name):
    value = subprocess.check_output(['fdtget', '-t', 'u', str(dtb), node, name], text=True)
    return [int(cell) for cell in value.split()]

  compatible = subprocess.check_output(['fdtget', str(dtb), '/', 'compatible'], text=True).split()
  if compatible != ['nvidia,p2894-0050-a04', 'nvidia,darcy', 'nvidia,tegra210']:
    raise ValueError('VBUS GPIO check requires the exact Darcy A04 profile')
  controller = cells('/gpio@6000d000', 'phandle')
  if len(controller) != 1:
    raise ValueError('Invalid Tegra GPIO controller phandle')
  rows = []
  for name, offset in [('usb-vbus1', 229), ('usb-vbus2', 228)]:
    node = f'/regulator-{name}'
    gpio = cells(node, 'gpio')
    regulator_type = subprocess.check_output(['fdtget', str(dtb), node, 'compatible'], text=True).strip()
    minimum = cells(node, 'regulator-min-microvolt')
    maximum = cells(node, 'regulator-max-microvolt')
    properties = subprocess.check_output(['fdtget', '-p', str(dtb), node], text=True).split()
    if (regulator_type != 'regulator-fixed' or gpio != [controller[0], offset, 6] or minimum != [5000000]
        or maximum != [5000000] or 'enable-active-high' not in properties):
      raise ValueError(f'{name}: expected original GPIO, active-high open-drain flags and fixed 5V')
    rows.append({'regulator': name, 'gpio_offset': offset, 'flags': 6,
                 'active_high': True, 'open_drain': True, 'fixed_microvolts': 5000000})
  return {'board_variant': 'darcy-t210-a04', 'compiled_VBUS_GPIO_contract_matches': True,
          'regulators': rows, 'physical_rail_voltage_measured': False,
          'external_USB_storage_qualified': False}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--dtb', type=Path, required=True)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  try:
    report = inspect(args.dtb)
  except (ValueError, OSError, subprocess.CalledProcessError) as error:
    raise SystemExit(str(error)) from error
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print('Darcy A04 compiled VBUS GPIO contract passed')


if __name__ == '__main__':
  main()
