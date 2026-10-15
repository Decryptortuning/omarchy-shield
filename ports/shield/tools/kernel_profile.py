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
