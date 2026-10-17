"""Exact identity for the isolated full-system ARM VM, never native admission."""
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

sys.path.insert(0, '/usr/lib/omarchy/shield/qualification')
from guardian_binding import IMAGE_SHA256, INSTALL
from usb_root_profile import digest, require

PREFIX = Path('/usr/lib/shield-systemd-vm')
USER_PREFIX = Path('/usr/lib/shield-systemd-vm-user')
MARKER = 'shield.systemd-vm=1'
PURPOSE = 'owned full-system ARM VM'
SOURCES = frozenset(['tools/systemd_vm_profile.py', 'tools/prepare-systemd-vm.py',
  'tools/run-systemd-vm.py', 'tools/systemd-vm-guest.py',
  'qualification/vm-user-probe.py', 'qualification/vm-uid-probe.c', 'qualification/vm-switch-root.c'])
FIELDS = {'format_version', 'purpose', 'marker', 'kernel', 'filesystem',
  'payload_manifest_sha256', 'prepared_receipt_sha256', 'installation_receipt_sha256',
  'native_profile_sha256', 'sources', 'uid_probe'}


def sha(value):
  require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
          and value != '0' * 64, 'Invalid VM digest')


def validate_identity(value):
  require(set(value) == FIELDS and type(value['format_version']) is int
          and value['format_version'] == 1 and value['purpose'] == PURPOSE
          and value['marker'] == MARKER, 'Wrong VM identity dialect')
  require(value['kernel'] == {'release': '7.1.0-shield-bringup', 'sha256': IMAGE_SHA256},
          'Wrong VM kernel')
  filesystem = value['filesystem']
  require(set(filesystem) == {'uuid', 'subvolumes'} and
          str(uuid.UUID(filesystem['uuid'])) == filesystem['uuid'], 'Wrong VM filesystem identity')
  volumes = filesystem['subvolumes']
  require(set(volumes) == {'root', 'home', 'log'} and
          re.fullmatch('@shield-[0-9a-f]{32}', volumes['root']) and
          volumes['home'] == volumes['root'] + '-home' and volumes['log'] == volumes['root'] + '-log',
          'Wrong VM subvolume identities')
  for name in ['payload_manifest_sha256', 'prepared_receipt_sha256',
               'installation_receipt_sha256', 'native_profile_sha256']:
    sha(value[name])
  require(set(value['sources']) == SOURCES, 'Wrong VM source closure')
  for expected in value['sources'].values(): sha(expected)
  require(set(value['uid_probe']) == {'sha256', 'bytes'} and
          type(value['uid_probe']['bytes']) is int and value['uid_probe']['bytes'] > 0,
          'Wrong VM uid probe metadata')
  sha(value['uid_probe']['sha256'])
  return value


def regular(path, mode):
  info = path.lstat()
  require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1, 'Untrusted VM input')
  return path


def load_identity():
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'VM probe requires root')
  info = PREFIX.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == 0o700, 'Untrusted VM private prefix')
  value = validate_identity(json.loads(regular(PREFIX / 'identity.json', 0o600).read_text()))
  require(digest(regular(INSTALL / 'profile.json', 0o600)) == value['native_profile_sha256'],
          'Installed native profile differs from VM binding')
  inputs = {'payload-manifest.json': 'payload_manifest_sha256',
    'prepared-receipt.json': 'prepared_receipt_sha256',
    'installation-receipt.json': 'installation_receipt_sha256'}
  for name, key in inputs.items():
    require(digest(regular(PREFIX / name, 0o600)) == value[key], 'VM receipt input changed')
  for name, source in {'guest.py': 'tools/systemd-vm-guest.py',
                       'systemd_vm_profile.py': 'tools/systemd_vm_profile.py'}.items():
    require(digest(regular(PREFIX / name, 0o644)) == value['sources'][source], 'VM runtime source changed')
  info = USER_PREFIX.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == 0o755, 'Untrusted VM user probe prefix')
  require(digest(regular(USER_PREFIX / 'user-probe.py', 0o644)) ==
          value['sources']['qualification/vm-user-probe.py'], 'VM user source changed')
  probe = regular(USER_PREFIX / 'uid-probe', 0o4755)
  require(digest(probe) == value['uid_probe']['sha256'] and probe.stat().st_size == value['uid_probe']['bytes'],
          'VM uid probe changed')
  return value
