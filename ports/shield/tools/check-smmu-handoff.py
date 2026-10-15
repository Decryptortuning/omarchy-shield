#!/usr/bin/env python3
"""Exercise the actual optional SMMU handoff reset against fake MMIO."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
  match = re.search(r'^static\s+(?:inline\s+)?(?:int|void)\s+(?:__init\s+)?' + re.escape(name) + r'\([^;]+?\n\{', source, re.M)
  if not match:
    raise ValueError(f'Missing kernel function: {name}')
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
  paths = ('drivers/iommu/tegra-smmu.c', 'drivers/memory/tegra/tegra210.c', 'drivers/memory/tegra/mc.c')
  files = {name: (args.kernel_source / name).read_text() for name in paths}
  source, soc, parent = (files[name] for name in paths)
  table = re.search(r'static const struct tegra_smmu_swgroup tegra210_swgroups\[\] = \{(.*?)\n\};', soc, re.S).group(1)
  registers = [int(value, 16) for value in re.findall(r'\.reg = (0x[0-9a-fA-F]+)', table)]
  if len(registers) != 39 or len(set(registers)) != 39 or 0xaa8 in registers:
    raise ValueError('Re-review the documented original T210 SWGROUP register set')
  if 'module_param_named(reset_inherited, reset_inherited, bool, 0400);' not in source:
    raise ValueError('The handoff reset must remain a read-only, default-off module parameter')
  if 'static bool reset_inherited;' not in source or 'arch_initcall_sync(tegra_smmu_check_handoff_reset);' not in source:
    raise ValueError('Missing default-off state or pre-device completion gate')
  if 'arch_initcall(tegra_mc_init);' not in parent:
    raise ValueError('Re-review parent MC probe ordering')
  probe = source.split('struct tegra_smmu *tegra_smmu_probe(', 1)[1].split('\nvoid tegra_smmu_remove', 1)[0]
  ordered = ['tegra_smmu_reset_handoff(smmu);', 'SMMU_PTC_CONFIG_ENABLE',
             'smmu_flush_ptc_all(smmu);', 'smmu_flush_tlb(smmu);',
             'smmu_writel(smmu, SMMU_CONFIG_ENABLE, SMMU_CONFIG);', 'smmu_flush(smmu);',
             'err = iommu_device_register(', 'handoff_reset_complete = true;', 'return smmu;']
  offsets = [probe.index(value) for value in ordered]
  if offsets != sorted(offsets) or 'if (reset_inherited)\n\t\thandoff_reset_complete = true;' not in probe:
    raise ValueError('Reset/flush/enable/register/completion ordering changed')
  template = (Path(__file__).resolve().parent.parent / 'tests/smmu-harness.c').read_text()
  code = template.replace('/* GROUPS */', ',\n'.join(f'  {{ .reg = 0x{reg:x} }}' for reg in registers))
  names = ('smmu_flush', 'tegra_smmu_reset_handoff', 'tegra_smmu_check_handoff_reset')
  code = code.replace('/* DRIVER */', '\n'.join(function(source, name) for name in names))
  with tempfile.TemporaryDirectory(prefix='shield-smmu-regression-') as temporary:
    root = Path(temporary)
    (root / 'test.c').write_text(code)
    subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                    '-fsanitize=undefined', '-o', str(root / 'test'), str(root / 'test.c')], check=True)
    result = subprocess.run([str(root / 'test')], capture_output=True, text=True, check=True)
  report = {'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()},
            'actual_driver_functions': list(names), 'documented_soc_registers': registers,
            'probe_completion_order_checked': True, 'result': result.stdout.strip(),
            'scope': 'Actual source functions and SoC table with fake MMIO; no physical DMA, SMMU or native handoff qualification',
            'native_handoff_qualified': False, 'device_actions_performed': []}
  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_text(json.dumps(report, indent=2) + '\n')
  print(result.stdout.strip())


if __name__ == '__main__':
  main()
