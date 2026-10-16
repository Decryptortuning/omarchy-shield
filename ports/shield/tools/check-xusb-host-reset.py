#!/usr/bin/env python3
"""Verify that Darcy A04 XUSB startup releases its memory-client reset."""
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
    raise ValueError('XUSB host reset check requires the exact Darcy A04 profile')
  mc = cells('/memory-controller@70019000', 'phandle')
  car = cells('/clock@60006000', 'phandle')
  if len(mc) != 1 or len(car) != 1:
    raise ValueError('Invalid memory/clock controller phandle')
  if cells('/memory-controller@70019000', '#reset-cells') != [1]:
    raise ValueError('Unexpected memory-controller reset specifier width')
  actual = cells('/pmc@7000e400/powergates/xusbc', 'resets')
  if actual != [mc[0], 13, car[0], 89]:
    raise ValueError('XUSBC requires MC_XUSB_HOST reset 13 followed by its original CAR reset 89')
  return {'board_variant': 'darcy-t210-a04', 'compiled_XUSB_host_reset_contract_matches': True,
          'reset_order': ['MC_XUSB_HOST', 'CAR_XUSB_HOST'], 'reset_ids': [13, 89],
          'uses_existing_PMC_and_MC_reset_framework': True,
          'physical_USB_storage_qualified_by_this_check': False}


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
  print('Darcy A04 compiled XUSB host reset contract passed')


if __name__ == '__main__':
  main()
