"""Validate the actual compiled DTB and acceptance matrix against a board lock."""
import hashlib
import json
from pathlib import Path
import subprocess

PROFILES = {
  'darcy-t210-a04': ('tegra210-p2894-0050-a04.dtb', 'nvidia,p2894-0050-a04', 'nvidia,tegra210'),
  'darcy-t210-a08': ('tegra210-p2894-0050-a08.dtb', 'nvidia,p2894-0050-a08', 'nvidia,tegra210'),
  'mdarcy-t210b01': ('tegra210b01-p2894-2551-b00.dtb', 'nvidia,p2894-2551-b00', 'nvidia,tegra210b01'),
}


def verify_kernel_profile(directory, allow_legacy=False):
  directory = Path(directory)
  lock = json.loads((directory / 'sources.lock.json').read_text())
  variant = lock.get('board_variant', 'mdarcy-t210b01' if allow_legacy else None)
  if variant not in PROFILES:
    raise ValueError('Unknown or missing Shield board variant')
  filename, board, soc = PROFILES[variant]
  if lock['kernel']['device_tree'] != 'nvidia/' + filename:
    raise ValueError('The selected board and locked DTB name disagree')
  dtb = directory / filename
  result = subprocess.run(['fdtget', '-t', 's', str(dtb), '/', 'compatible'], capture_output=True, text=True)
  tokens = set(result.stdout.split())
  boards = {profile[1] for profile in PROFILES.values()}
  if result.returncode or tokens & boards != {board} or soc not in tokens:
    raise ValueError('The compiled DTB does not match the selected Shield board/SoC pair')
  if (variant.startswith('darcy-t210-') and 'nvidia,tegra210b01' in tokens) or any(token.startswith(('apple,', 'qcom,')) for token in tokens):
    raise ValueError('The compiled DTB has conflicting silicon or hardware-family identities')
  matrix = directory / 'hardware.json'
  if 'hardware_matrix' in lock:
    if hashlib.sha256(matrix.read_bytes()).hexdigest() != lock['hardware_matrix']['sha256']:
      raise ValueError('The acceptance matrix differs from the locked board input')
  elif not allow_legacy:
    raise ValueError('A portable locked acceptance matrix is required')
  return lock, dtb


PROFILE_LOCKS = {
  'darcy-t210-a04': 'kernel.lock.json',
  'darcy-t210-a08': 'kernel-darcy-a08.lock.json',
  'mdarcy-t210b01': 'kernel-mdarcy.lock.json',
}


def verify_kernel_intent(directory, source_tree):
  """Reject a stale self-consistent bundle against the chosen source tree's intent."""
  directory = Path(directory)
  source_tree = Path(source_tree).resolve(strict=True)
  lock, dtb = verify_kernel_profile(directory)
  expected = json.loads((source_tree / 'ports/shield' / PROFILE_LOCKS[lock['board_variant']]).read_text())
  if lock != expected:
    raise ValueError('Kernel bundle lock differs from the exported source commit intent')
  def locked_input(relative, digest):
    path = (source_tree / relative).resolve(strict=True)
    if not path.is_relative_to(source_tree) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
      raise ValueError('Exported source input differs from its lock: ' + relative)

  locked_input(expected['hardware_matrix']['path'], expected['hardware_matrix']['sha256'])
  patches = expected['kernel'].get('patches', [])
  for patch in patches:
    locked_input(patch['path'], patch['sha256'])
  for overlay in expected['kernel'].get('device_tree_overlays', []):
    locked_input(overlay['path'], overlay['sha256'])
  applied = json.loads((directory / 'applied-patches.json').read_text()) if patches else None
  if patches and applied != {'base_commit': expected['kernel']['commit'], 'patches': patches}:
    raise ValueError('Applied kernel patches differ from the intended ordered patch set')
  paths = ['ports/shield/config/bringup.fragment']
  if expected['kernel'].get('config_fragment'):
    paths.append(expected['kernel']['config_fragment'])
  paths.extend(expected['kernel'].get('additional_config_fragments', []))
  inputs = []
  for relative in paths:
    path = (source_tree / relative).resolve(strict=True)
    if not path.is_relative_to(source_tree):
      raise ValueError('Kernel configuration input escapes the source tree')
    inputs.append({'path': relative, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
  config = (directory / 'kernel.config').read_bytes()
  provenance = json.loads((directory / 'config-fragments.json').read_text())
  if provenance != {'inputs': inputs, 'resolved_config_sha256': hashlib.sha256(config).hexdigest()}:
    raise ValueError('Kernel configuration provenance differs from the intended inputs or actual config')
  if lock['board_variant'] == 'darcy-t210-a04':
    required = {'CONFIG_WATCHDOG=y', 'CONFIG_WATCHDOG_CORE=y', 'CONFIG_TEGRA_WATCHDOG=y',
                'CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y', 'CONFIG_WATCHDOG_OPEN_TIMEOUT=600'}
    if not required.issubset(set(config.decode().splitlines())):
      raise ValueError('A04 requires the intended built-in inherited watchdog configuration')
  overlays = expected['kernel'].get('device_tree_overlays', [])
  if overlays:
    proof = json.loads((directory / 'device-tree-overlays.json').read_text())
    if proof['overlays'] != overlays or proof['result_dtb_sha256'] != hashlib.sha256(dtb.read_bytes()).hexdigest():
      raise ValueError('Applied overlays or resulting DTB differ from the intended bundle')
  return lock, dtb
