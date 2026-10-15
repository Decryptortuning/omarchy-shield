"""Inspect both consumers when the Darcy PWM specifier width changes."""
import subprocess


def inspect_fan_contract(dtb):
  def cells(node, property_name):
    result = subprocess.run(['fdtget', '-t', 'u', str(dtb), node, property_name],
                            capture_output=True, text=True)
    return [int(value) for value in result.stdout.split()] if not result.returncode else []
  count = cells('/pwm@7000a000', '#pwm-cells')
  fan = cells('/pwm-fan', 'pwms')
  gpu = cells('/regulator-vdd-gpu', 'pwms')
  cooling = cells('/pwm-fan', 'cooling-levels')
  matches = (count == [3] and len(fan) == len(gpu) == 4 and fan[0] == gpu[0]
             and fan[1:] == [3, 65536, 1] and gpu[1:] == [1, 8000, 0]
             and cooling == [0, 127, 191, 255])
  return {'pwm_cells': count, 'fan_specifier': fan, 'gpu_regulator_specifier': gpu,
          'cooling_levels': cooling, 'binding_contract_matches': matches,
          'physical_fan_qualified': False}
