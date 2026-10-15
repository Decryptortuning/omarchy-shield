#!/usr/bin/env python3
"""Compile and exercise actual fan/PWM functions with fake hardware callbacks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
  match = re.search(r'^static (?:int|void)\s+' + re.escape(name) + r'\([^;]+?\n\{', source, re.M)
  if not match:
    raise ValueError(f'Missing kernel function: {name}')
  start, end, depth = match.start(), match.end(), 1
  while depth:
    if source[end] == '{':
      depth += 1
    elif source[end] == '}':
      depth -= 1
    end += 1
  return source[start:end] + '\n'


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--kernel-source', required=True, type=Path)
  parser.add_argument('--output', required=True, type=Path)
  args = parser.parse_args()
  files = {name: (args.kernel_source / name).read_text() for name in
           ('drivers/pwm/pwm-tegra.c', 'drivers/hwmon/pwm-fan.c')}
  fan, pwm = files['drivers/hwmon/pwm-fan.c'], files['drivers/pwm/pwm-tegra.c']
  mode = re.search(r'ctx->enable_mode = ctx->pwm_state.polarity.*?;', fan, re.S).group()
  mode_enum = re.search(r'enum pwm_fan_enable_mode \{.*?\};', fan, re.S).group()
  template = (Path(__file__).resolve().parent.parent / 'tests/fan-harness.c').read_text()
  code = template.replace('/* MODE_ENUM */', mode_enum)
  code = code.replace('/* PROVIDER */', function(pwm, 'tegra_pwm_apply'))
  names = ('pwm_fan_enable_mode_2_state', 'pwm_fan_switch_power', 'pwm_fan_power_on',
           'pwm_fan_power_off', '__set_pwm', 'pwm_fan_update_state', 'pwm_fan_update_enable')
  code = code.replace('/* CONSUMER */', '\n'.join(function(fan, name) for name in names))
  code = code.replace('/* INITIAL_MODE */', mode)
  with tempfile.TemporaryDirectory(prefix='shield-fan-regression-') as temporary:
    root = Path(temporary)
    (root / 'test.c').write_text(code)
    # Match Kbuild's treatment of the existing signed loop counters.
    subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare',
                    '-o', str(root / 'test'), str(root / 'test.c')], check=True)
    result = subprocess.run([str(root / 'test')], capture_output=True, text=True, check=True)
  report = {'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()},
            'tested_actual_kernel_functions': ['tegra_pwm_apply', *names], 'result': result.stdout.strip(),
            'scope': 'Host-compiled actual driver functions with fake PWM, power and delay callbacks; no MMIO, clock, electrical, RPM or thermal qualification',
            'physical_fan_tested': False, 'device_actions_performed': []}
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print(result.stdout.strip())


if __name__ == '__main__':
  main()
