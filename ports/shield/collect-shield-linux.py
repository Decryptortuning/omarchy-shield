#!/usr/bin/env python3
"""Collect bounded Shield hardware evidence without changing device settings."""
import argparse
import datetime
import glob
import json
from pathlib import Path
import platform
import shutil
import subprocess


def read(path, limit=131072):
  try:
    return Path(path).read_bytes()[:limit].decode('utf-8', 'replace').replace('\0', '\n').strip()
  except OSError as error:
    return {'unavailable': str(error)}


def command(arguments):
  if not shutil.which(arguments[0]):
    return {'unavailable': f'{arguments[0]} is not installed'}
  try:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=20, errors='replace')
    return {'command': arguments, 'exit_code': result.returncode,
        'stdout': result.stdout[:262144], 'stderr': result.stderr[:32768]}
  except (OSError, subprocess.TimeoutExpired) as error:
    return {'command': arguments, 'unavailable': str(error)}


def board_variant(compatible):
  tokens = set(compatible)
  boards = {
    'nvidia,p2894-0050-a04': ('darcy-t210-a04', 'nvidia,tegra210'),
    'nvidia,p2894-0050-a08': ('darcy-t210-a08', 'nvidia,tegra210'),
    'nvidia,p2894-2551-b00': ('mdarcy-t210b01', 'nvidia,tegra210b01'),
  }
  if any(token.startswith(('apple,', 'qcom,')) for token in tokens):
    return None
  matched = tokens & boards.keys()
  if len(matched) != 1:
    return None
  variant, soc = boards[matched.pop()]
  if soc not in tokens or (variant.startswith('darcy-t210-') and 'nvidia,tegra210b01' in tokens):
    return None
  return variant


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--output', type=Path, required=True)
  parser.add_argument('--graphics', action='store_true', help='Also initialize EGL/Vulkan to inspect rendering; use after cooling is verified')
  args = parser.parse_args()
  compatible = read('/proc/device-tree/compatible')
  if not isinstance(compatible, str):
    compatible = read('/sys/firmware/devicetree/base/compatible')
  variant = board_variant(compatible.splitlines()) if isinstance(compatible, str) else None
  if platform.machine() != 'aarch64' or variant is None:
    raise SystemExit('This collector requires a supported Shield board/SoC pair; it will not inventory the development PC')
  paths = ['/proc/device-tree/model', '/proc/cmdline', '/proc/cpuinfo', '/proc/meminfo', '/proc/partitions',
      '/sys/power/state', '/sys/power/mem_sleep']
  patterns = [
    '/sys/class/thermal/thermal_zone*/type', '/sys/class/thermal/thermal_zone*/temp',
    '/sys/class/thermal/thermal_zone*/trip_point_*',
    '/sys/class/thermal/cooling_device*/type', '/sys/class/thermal/cooling_device*/cur_state',
    '/sys/class/hwmon/hwmon*/name', '/sys/class/hwmon/hwmon*/pwm*', '/sys/class/hwmon/hwmon*/fan*_input',
    '/sys/devices/system/cpu/cpufreq/policy*/scaling_driver',
    '/sys/devices/system/cpu/cpufreq/policy*/scaling_available_frequencies',
    '/sys/class/devfreq/*/name', '/sys/class/devfreq/*/available_frequencies',
    '/sys/class/drm/card*-*/status', '/sys/class/drm/card*-*/modes',
    '/sys/class/net/*/operstate', '/sys/class/net/*/speed', '/sys/class/net/*/address',
    '/sys/class/mmc_host/mmc*/mmc*:*/name', '/sys/class/mmc_host/mmc*/mmc*:*/type',
  ]
  for pattern in patterns:
    paths.extend(sorted(glob.glob(pattern))[:128])
  commands = [['lsusb'], ['lsusb', '-t'], ['lspci', '-nnk'], ['lsmod'], ['lsblk', '-J', '-o', 'NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL'],
        ['ip', '-j', 'link'], ['iw', 'phy'], ['bluetoothctl', 'list'], ['aplay', '-l'],
        ['cec-ctl', '--list-devices'], ['v4l2-ctl', '--list-devices'],
        ['journalctl', '-b', '-k', '--no-pager', '-n', '1200']]
  if args.graphics:
    commands.extend([['eglinfo', '-B'], ['vulkaninfo', '--summary']])
  report = {
    'target': 'NVIDIA Shield TV candidate', 'board_variant': variant,
    'acceptance_matrix': {'darcy-t210-a04': 'hardware-darcy.json',
                          'darcy-t210-a08': 'hardware-darcy-a08.json',
                          'mdarcy-t210b01': 'hardware.json'}[variant],
    'collected_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'uname': list(platform.uname()), 'compatible': compatible.splitlines(),
    'files': {path: read(path) for path in dict.fromkeys(paths)},
    'commands': [command(arguments) for arguments in commands],
    'graphics_probe_requested': args.graphics,
    'qualification': 'Inventory only. A device node, driver name or advertised API does not pass a functional test.',
    'device_mutations_requested': [],
  }
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print(f'Saved hardware inventory: {args.output}')


if __name__ == '__main__':
  main()
