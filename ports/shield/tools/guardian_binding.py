"""One source/artifact binding for the finite A04 qualification roles."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from usb_root_profile import digest, require

INSTALL = Path('/usr/lib/omarchy/shield/qualification')
PROFILE = INSTALL / 'profile.json'
BOARD = {'model': 'NVIDIA Shield TV (Darcy A04)',
         'compatible': ['nvidia,p2894-0050-a04', 'nvidia,darcy', 'nvidia,tegra210'],
         'stamp': 'a04-first-ram-probe-v1'}
IMAGE_SHA256 = 'b7865e9b7e077ea3f75ed740e66566811e704641b8cc7840843d8f94a3452186'
CONFIG_SHA256 = 'ce00a1be7b8b2a800f57bc8a8bd7b8b261515221e444cc327c0959af963ce11b'
DTB_SHA256 = '378996e1e9ff1c5d434b125d8ef543555a9f661d02779c0ca9b22e9cb7b9d96d'
TIMING = {'open_seconds': 120, 'work_seconds': 540, 'final_seconds': 600,
          'cleanup_seconds': 60, 'ping_seconds': 30, 'sample_age_seconds': 3}
USB = {'vendor': '0781', 'product': '5591'}
SOURCE_NAMES = frozenset(['guardian/main.c', 'guardian/sampler.c', 'guardian/state.c', 'guardian/guardian.h',
  'guardian/profile.h', 'qualification/restart-recovery.c', 'tools/guardian_binding.py',
  'tools/guardian_client.py', 'tools/qualification_recovery.py', 'tools/usb_root_profile.py',
  'tools/qualification_profile.py', 'tools/prepare-qualification-overlay.py',
  'tools/prepare-qualification-root.py', 'tools/prepare-guardian.py', 'tools/maintenance_accounts.py'])
BODY_FIELDS = {'format_version', 'role', 'board', 'kernel', 'dtb', 'filesystem',
               'overlay_sha256', 'sources', 'recovery_helper', 'account', 'timing'}


def canonical(value):
  return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(value):
  require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
          and value != '0' * 64, 'Invalid artifact digest')
  return value


def validate(profile):
  require(set(profile) == BODY_FIELDS | {'candidate'}, 'Wrong guardian binding fields')
  body = {key: profile[key] for key in BODY_FIELDS}
  require(type(profile['format_version']) is int and profile['format_version'] == 1
          and type(profile['role']) is int and profile['role'] in (1, 2), 'Wrong binding version/role')
  require(profile['candidate'] == hashlib.sha256(canonical(body)).hexdigest(), 'Binding digest differs')
  require(profile['board'] == BOARD and profile['timing'] == TIMING, 'Unreviewed board or timing')
  require(profile['kernel'] == {'release': '7.1.0-shield-bringup', 'image_sha256': IMAGE_SHA256,
                                'config_sha256': CONFIG_SHA256}, 'Unreviewed kernel binding')
  require(set(profile['dtb']) == {'sha256', 'bytes'} and profile['dtb']['sha256'] == DTB_SHA256
          and type(profile['dtb']['bytes']) is int and profile['dtb']['bytes'] > 0, 'Unreviewed restricted DT')
  filesystem = profile['filesystem']
  require(set(filesystem) == {'uuid', 'candidate_id', 'subvolumes', 'usb'}
          and filesystem['usb'] == USB, 'Wrong filesystem/USB binding')
  require(str(uuid.UUID(filesystem['uuid'])) == filesystem['uuid'], 'Invalid filesystem UUID')
  require(re.fullmatch('[0-9a-f]{32}', filesystem['candidate_id']), 'Invalid root candidate')
  root = '@shield-' + filesystem['candidate_id']
  require(filesystem['subvolumes'] == {'root': root, 'home': root + '-home', 'log': root + '-log'},
          'Unreviewed candidate subvolume names')
  require(profile['account'] == {'name': 'shieldqual', 'uid': 1001, 'gid': 1001}, 'Wrong qualification account')
  sha(profile['overlay_sha256'])
  require(set(profile['sources']) == SOURCE_NAMES, 'Wrong source closure')
  for name, value in profile['sources'].items():
    require(isinstance(name, str) and name and not name.startswith('/')
            and all(part not in ('', '.', '..') for part in name.split('/')), 'Unsafe source name')
    sha(value)
  require(set(profile['recovery_helper']) == {'sha256', 'bytes'}
          and type(profile['recovery_helper']['bytes']) is int
          and profile['recovery_helper']['bytes'] > 0, 'Incomplete recovery helper')
  sha(profile['recovery_helper']['sha256'])
  return profile


def seal(body):
  require(set(body) == BODY_FIELDS, 'Incomplete guardian binding body')
  return validate({**body, 'candidate': hashlib.sha256(canonical(body)).hexdigest()})


def owned_file(path, mode=None):
  path = Path(path)
  info = path.lstat()
  require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0, 'Expected root-owned regular input')
  if mode is not None:
    require(stat.S_IMODE(info.st_mode) == mode, 'Wrong private input mode')
  return path


def load_runtime():
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'Qualification runtime requires root')
  profile = validate(json.loads(owned_file(PROFILE, 0o600).read_text()))
  require(profile['role'] == 2, 'Recovery service requires early-systemd profile')
  require(os.getppid() == 1 and os.readlink('/proc/1/exe') == '/usr/lib/systemd/systemd', 'Real systemd parent required')
  require(os.uname().release == profile['kernel']['release'], 'Running kernel release differs')
  base = Path('/proc/device-tree')
  require((base / 'compatible').read_bytes() == b'\0'.join(x.encode() for x in BOARD['compatible']) + b'\0'
          and (base / 'model').read_bytes() == BOARD['model'].encode() + b'\0'
          and (base / 'chosen/shield,first-ram-probe').read_bytes() == BOARD['stamp'].encode() + b'\0',
          'Exact native board/DT identity required')
  tokens = Path('/proc/cmdline').read_text().split()
  for key, value in {'shield.first-ram-probe': '1', 'tegra_smmu.reset_inherited': '1',
      'tegra_smmu.quarantine_gpub_inherited': '1', 'watchdog.open_timeout': '240',
      'watchdog.stop_on_reboot': '0', 'shield.guardian': profile['candidate']}.items():
    require([item for item in tokens if item.startswith(key + '=')] == [key + '=' + value], 'Wrong unique boot binding')
  helper = owned_file(INSTALL / 'shield-restart-recovery', 0o700)
  require(helper.stat().st_size == profile['recovery_helper']['bytes']
          and digest(helper) == profile['recovery_helper']['sha256'], 'Recovery helper differs')
  return profile
