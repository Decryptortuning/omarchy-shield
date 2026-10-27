"""One current OWNER boot command line per distinct purpose; pure formatting.

Retain the currently exercised conservative hardware settings. CPU/DVFS/idle
performance parity is a later acceptance track, not implied by these settings.
"""
import hashlib
import re

HARDWARE = ('console=tty0', 'loglevel=7', 'rdinit=/init', 'nokaslr',
  'clk_ignore_unused', 'regulator_ignore_unused', 'maxcpus=1', 'nr_cpus=1',
  'cpuidle.off=1', 'initcall_blacklist=tegra_cpufreq_init',
  'tegra_smmu.reset_inherited=1', 'tegra_smmu.quarantine_gpub_inherited=1',
  'watchdog.open_timeout=240', 'watchdog.stop_on_reboot=0', 'pstore.compress=none',
  'ignore_loglevel', 'modprobe.blacklist=r8169')


def normal(boot_raw, context_raw):
  if type(boot_raw) is not bytes or type(context_raw) is not bytes or not boot_raw or not context_raw:
    raise ValueError('Exact normal boot/context bytes required')
  return (' '.join([*HARDWARE, 'shield.omarchy-owner=1',
    'shield.owner-boot=' + hashlib.sha256(boot_raw).hexdigest(),
    'shield.owner-context=' + hashlib.sha256(context_raw).hexdigest(),
    'systemd.unit=graphical.target', 'systemd.log_target=kmsg', 'systemd.log_level=info']) + '\n').encode('ascii')


def preparation(config_raw):
  if type(config_raw) is not bytes or not config_raw:
    raise ValueError('Exact preparation bytes required')
  return (' '.join([*HARDWARE, 'shield.omarchy-owner-prepare=1',
    'shield.owner-preparation=' + hashlib.sha256(config_raw).hexdigest()]) + '\n').encode('ascii')


INTERNAL_GENERATION = 'shield.owner-internal-generation='
INTERNAL_SEQUENCE = 'shield.owner-internal-sequence='


def internal_normal(boot_raw, context_raw, generation, sequence):
  """Bind one internal attempt; the generation is not a bootset self-hash."""
  if type(generation) is not str or re.fullmatch(r'[0-9a-f]{64}', generation) is None:
    raise ValueError('Exact internal generation required')
  if (type(sequence) is not str or re.fullmatch(r'[0-9a-f]{16}', sequence) is None
      or int(sequence, 16) == 0):
    raise ValueError('Nonzero uint64 internal attempt sequence required')
  base = normal(boot_raw, context_raw).decode('ascii').removesuffix('\n')
  return (base + ' ' + INTERNAL_GENERATION + generation + ' '
          + INTERNAL_SEQUENCE + sequence + '\n').encode('ascii')


def admit_normal(tokens, boot_raw, context_raw, enrollment):
  """Check every token, including order and uniqueness, at initial RAM entry."""
  if type(tokens) is not list or any(type(token) is not str for token in tokens):
    raise ValueError('Exact command line tokens required')
  if 'emmc' in enrollment['filesystem']:
    generations = [t[len(INTERNAL_GENERATION):] for t in tokens if t.startswith(INTERNAL_GENERATION)]
    sequences = [t[len(INTERNAL_SEQUENCE):] for t in tokens if t.startswith(INTERNAL_SEQUENCE)]
    if len(generations) != 1 or len(sequences) != 1:
      raise ValueError('Unique internal attempt tokens required')
    if generations[0] != enrollment['boot_store']['generation_id']:
      raise ValueError('Internal attempt generation differs from enrollment')
    expected = internal_normal(boot_raw, context_raw, generations[0], sequences[0])
  else:
    expected = normal(boot_raw, context_raw)
  if tokens != expected.decode('ascii').split():
    raise ValueError('Complete normal OWNER command line differs')
