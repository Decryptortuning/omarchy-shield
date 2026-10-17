#!/usr/bin/env python3
"""Install the admitted guardian into a NEW host root copy; never select a boot."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess

from guardian_binding import INSTALL, SOURCE_NAMES, validate
from usb_root_profile import digest, require, rooted, verify_root

TOOLS = Path(__file__).resolve().parent
PORT = TOOLS.parent
SPEC = importlib.util.spec_from_file_location('qualification_root_preparer', TOOLS / 'prepare-qualification-root.py')
PREPARER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARER)
RUNTIME = {'shield-guardian', 'shield-restart-recovery', 'guardian_binding.py',
  'guardian_client.py', 'qualification_recovery.py', 'usb_root_profile.py', 'overlay-manifest.json'}


def static_arm(path):
  """Inspect ELF program headers without running the enabled entrypoint."""
  data = path.read_bytes()
  require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01'
          and struct.unpack_from('<HHI', data, 16) == (2, 183, 1)
          and struct.unpack_from('<H', data, 52)[0] == 64, 'Expected AArch64 ELF executable')
  offset = struct.unpack_from('<Q', data, 32)[0]
  size, count = struct.unpack_from('<HH', data, 54)
  require(size == 56 and 0 < count <= 32 and offset >= 64
          and offset + size * count <= len(data), 'Malformed ELF program headers')
  kinds = [struct.unpack_from('<I', data, offset + size * index)[0] for index in range(count)]
  require(1 in kinds and 2 not in kinds and 3 not in kinds, 'Expected static ELF without loader')


def mode_for(name):
  return 0o700 if name.startswith('shield-') else (0o600 if name.endswith('.json') else 0o644)


def artifact_inputs(directory, manifest_sha, profile_sha, payload, prepared):
  PREPARER.locked_directory(directory)
  metadata = PREPARER.matched_json(directory / 'artifacts.json', manifest_sha)
  profile = validate(PREPARER.matched_json(directory / 'profile.json', profile_sha))
  require(profile['role'] == metadata['role'] == 2 and metadata['format_version'] == 1
          and metadata['candidate'] == profile['candidate'] and metadata['profile_sha256'] == profile_sha
          and metadata['compiled_enabled'] is True and metadata['installed'] is False
          and metadata['native_execution_released'] is False and metadata['boot_ready'] is False,
          'Artifact build identity or release scope differs')
  require(metadata['source_inputs_sha256'] == profile['sources']
          and set(profile['sources']) == SOURCE_NAMES
          and all(digest(PORT / name) == value for name, value in profile['sources'].items()),
          'Artifact source closure differs from current producers/consumers')
  require(profile['filesystem']['uuid'] == payload['filesystem_uuid']
          and profile['filesystem']['candidate_id'] == payload['candidate_id']
          and profile['filesystem']['subvolumes'] == payload['subvolumes']
          and profile['overlay_sha256'] == prepared['overlay_manifest_sha256'], 'Prepared root/artifact binding differs')
  require(set(metadata['files']) == RUNTIME, 'Runtime file closure differs')
  for name in sorted(RUNTIME):
    path = directory / name
    info = PREPARER.regular(path)
    require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == mode_for(name)
            and metadata['files'][name] == {'sha256': digest(path), 'bytes': info.st_size},
            'Runtime artifact bytes or metadata differ')
    if name.endswith('.py'):
      require(digest(path) == profile['sources']['tools/' + name], 'Runtime Python/source mismatch')
    if name.startswith('shield-'):
      static_arm(path)
  require(metadata['files']['shield-restart-recovery'] == profile['recovery_helper']
          and digest(directory / 'overlay-manifest.json') == profile['overlay_sha256'], 'Helper/overlay differs')
  template = (PORT / 'guardian/profile.h').read_text()
  for before, after in {'#define SG_PROFILE_ENABLED 0': '#define SG_PROFILE_ENABLED 1',
      '#define SG_PROFILE_ROLE 1': '#define SG_PROFILE_ROLE 2',
      '"' + '0' * 64 + '"': '"' + profile['candidate'] + '"'}.items():
    require(template.count(before) == 1, 'Guardian template changed')
    template = template.replace(before, after)
  require(metadata['generated_profile_header_sha256'] == hashlib.sha256(template.encode()).hexdigest(),
          'Generated guardian header differs')
  return metadata, profile


def prepared_root(directory, receipt_sha, payload, payload_sha):
  PREPARER.locked_directory(directory)
  receipt = PREPARER.matched_json(directory / 'receipt.json', receipt_sha)
  require(receipt['format_version'] == 1 and receipt['producer_sha256'] == digest(TOOLS / 'prepare-qualification-root.py')
          and receipt['payload_manifest_sha256'] == payload_sha
          and receipt['chroot_helper_sha256'] == PREPARER.CHROOT_SHA256, 'Prepared producer/payload differs')
  for key in ['source_reference_verified_before_and_after', 'source_accounts_unchanged',
      'network_isolated_chroot_commands', 'account_created', 'theme_seeded', 'service_masks_applied',
      'matched_package_payload_verified_after_configuration', 'sudo_policy_denied',
      'runtime_accounts_seeded_from_original', 'original_account_source_verified_before_and_after']:
    require(receipt[key] is True, 'Incomplete prepared root proof')
  for key in ['reference_root_modified', 'native_sudo_execution_verified', 'guardian_installed',
              'root_selected', 'boot_ready', 'native_qualified', 'normal_first_run_complete']:
    require(receipt[key] is False, 'Unexpected prepared root release/state')
  expected_sources = {TOOLS / name for name in ['prepare-qualification-root.py', 'qualification_profile.py',
    'usb_root_profile.py', 'prepare-qualification-overlay.py', 'maintenance_accounts.py']} | {PORT / 'chroot.sh'}
  require(set(receipt['source_hashes']) == {str(path) for path in expected_sources}
          and all(digest(path) == receipt['source_hashes'][str(path)] for path in expected_sources),
          'Prepared source consumers changed')
  root = PREPARER.real_directory(directory / 'rootfs')
  verify_prepared(root, receipt, payload)
  return root, receipt


def verify_prepared(root, receipt, payload):
  verify_root(payload, root)
  rendered = PREPARER.render(root, payload)
  expected_files = {}
  for purpose in ['root', 'home']:
    for name, content in rendered[purpose].items():
      relative = name if purpose == 'root' else 'home/' + name
      owner = 0 if purpose == 'root' else 1001
      expected_files[relative] = {'sha256': hashlib.sha256(content.encode()).hexdigest(),
                                 'mode': 0o644, 'uid': owner, 'gid': owner}
  require(receipt['applied_files'] == expected_files, 'Prepared file policy differs from current renderer')
  require(receipt['service_masks'] == {name: {'type': 'symlink', 'target': '/dev/null',
          'uid': 0, 'gid': 0, 'reason': reason} for name, reason in rendered['policy']['masked_services'].items()},
          'Prepared mask policy differs from current renderer')
  baseline = PREPARER.original_baseline_from_record(receipt['original_account_baseline'])
  account = PREPARER.account_proof(root, baseline)
  require(all(receipt['account'][key] == value for key, value in account.items()), 'Account proof differs')
  accounts = PREPARER.tables(root)['passwd']
  require([name for name, row in accounts.items() if row[2] == '0'] == ['root']
          and 'portbuild' not in accounts, 'Unexpected privileged or build identity')
  require(PREPARER.home_proof(root) == receipt['home_files'], 'Prepared home changed')
  for name, identity in receipt['applied_files'].items():
    path = rooted(root, name); info = PREPARER.regular(path)
    require({'sha256': digest(path), 'uid': info.st_uid, 'gid': info.st_gid,
             'mode': stat.S_IMODE(info.st_mode)} == identity, 'Applied qualification file changed')
  for name, identity in receipt['service_masks'].items():
    require(identity['target'] == '/dev/null' and identity['type'] == 'symlink', 'Wrong mask proof')
    path = root / 'etc/systemd/system' / name
    info = path.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0
            and os.readlink(path) == '/dev/null', 'Prepared mask changed')
  for name in ['build', 'home/portbuild', 'root/.ssh', 'root/.gnupg', 'etc/pacman.d/gnupg']:
    path = root / name
    require(not path.exists() and not path.is_symlink(), 'Excluded state appeared')
  require(not list((root / 'etc/ssh').glob('ssh_host_*')), 'SSH host keys appeared')
  require(rooted(root, 'etc/machine-id').read_bytes() == b'', 'Prepared root already has a machine identity')


def account_hashes(root):
  return {name: digest(rooted(root, 'etc/' + name)) for name in ['passwd', 'group', 'shadow', 'gshadow']}


def copy_root(source, target, log):
  process = subprocess.Popen(['/usr/bin/rsync', '-aHAXx', '--numeric-ids',
    *['--exclude=' + name for name in PREPARER.EXCLUDES], str(source) + '/', str(target) + '/'],
    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
  try:
    status = process.wait(timeout=600)
  except BaseException:
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    try: process.wait(timeout=3)
    except subprocess.TimeoutExpired:
      try: os.killpg(process.pid, signal.SIGKILL)
      except ProcessLookupError: pass
      process.wait(timeout=3)
    raise
  require(status == 0, 'Owned root copy failed; preserve partial output')


def selection(root):
  result = {}
  for name in ['etc/systemd/system/default.target', 'usr/lib/systemd/system/default.target']:
    path = root / name
    if path.exists() or path.is_symlink():
      info = path.lstat()
      require(stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0, 'Unexpected default selection')
      result[name] = os.readlink(path)
  return result


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  for name in ['prepared', 'payload-manifest', 'artifacts', 'output']:
    parser.add_argument('--' + name, type=Path, required=True)
  for name in ['prepared-receipt-sha256', 'payload-manifest-sha256', 'artifact-manifest-sha256', 'profile-sha256']:
    parser.add_argument('--' + name, required=True)
  args = parser.parse_args()
  PREPARER.wsl_root()
  def interrupted(_signum, _frame):
    raise InterruptedError('Owned artifact installation interrupted')
  signal.signal(signal.SIGTERM, interrupted)
  payload = PREPARER.matched_json(args.payload_manifest, args.payload_manifest_sha256)
  source, receipt = prepared_root(args.prepared, args.prepared_receipt_sha256, payload, args.payload_manifest_sha256)
  metadata, profile = artifact_inputs(args.artifacts, args.artifact_manifest_sha256, args.profile_sha256, payload, receipt)
  original_selection = selection(source)
  accounts = account_hashes(source)
  require(not args.output.exists() and not args.output.is_symlink(), 'Output must be new; retain failed outputs')
  output = args.output.parent.resolve(strict=True) / args.output.name
  require(output.name not in ('', '.', '..'), 'Invalid new output')
  for path in [args.prepared.resolve(strict=True), args.artifacts.resolve(strict=True), args.payload_manifest.resolve(strict=True).parent]:
    require(not output.is_relative_to(path) and not path.is_relative_to(output), 'Output/input overlap')
  require(all(path.stat().st_dev == Path('/').stat().st_dev
          for path in [source, args.artifacts, args.payload_manifest, output.parent]), 'Native WSL filesystem required')
  install_relative = str(INSTALL).lstrip('/')
  require(not (source / install_relative).exists() and not (source / install_relative).is_symlink(),
          'Reference already contains a runtime installation')
  sources = {str(path): digest(path) for path in [Path(__file__).resolve(), *[TOOLS / name for name in
    ['prepare-qualification-root.py', 'guardian_binding.py', 'usb_root_profile.py', 'qualification_profile.py']]]}
  output.mkdir(mode=0o700)
  (output / 'ATTEMPTED').write_text('Partial host copy is never boot ready; do not reuse.\n')
  target = output / 'rootfs'; target.mkdir()
  with (output / 'copy.log').open('xb') as log:
    copy_root(source, target, log)
  for name, mode in [('proc', 0o755), ('dev', 0o755), ('run', 0o755), ('tmp', 0o1777),
                     ('sys', 0o755), ('root', 0o700), ('mnt', 0o755), ('media', 0o755)]:
    path = target / name
    path.mkdir(mode=mode, exist_ok=True)
    require(not path.is_symlink() and path.is_dir(), 'Unsafe copied runtime directory')
    os.chown(path, 0, 0); path.chmod(mode)
  verify_prepared(target, receipt, payload)
  require(account_hashes(target) == accounts, 'Copied account databases differ')
  destination = PREPARER.parents(target, install_relative + '/profile.json').parent
  require(not destination.exists() or not list(destination.iterdir()), 'Installation directory is not empty')
  os.chown(destination, 0, 0); destination.chmod(0o700)
  installed = {}
  for name in sorted(RUNTIME | {'profile.json', 'artifacts.json'}):
    path = args.artifacts / name
    mode = mode_for(name)
    data = path.read_bytes()
    out = destination / name
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
      stream.write(data); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
    require(digest(out) == digest(path), 'Installed readback differs')
    installed[name] = {'sha256': digest(out), 'bytes': out.stat().st_size, 'mode': mode, 'uid': 0, 'gid': 0}
  descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
  try: os.fsync(descriptor)
  finally: os.close(descriptor)
  verify_prepared(target, receipt, payload)
  require(selection(target) == original_selection == selection(source), 'Default boot selection changed')
  verify_prepared(source, receipt, payload)
  require(account_hashes(source) == account_hashes(target) == accounts, 'Account databases changed')
  artifact_inputs(args.artifacts, args.artifact_manifest_sha256, args.profile_sha256, payload, receipt)
  require(all(digest(path) == value for path, value in sources.items())
          and digest(args.prepared / 'receipt.json') == args.prepared_receipt_sha256
          and digest(args.payload_manifest) == args.payload_manifest_sha256, 'Installation inputs changed')
  record = {'format_version': 1, 'purpose': 'new host-only runtime installation', 'source_inputs': sources,
    'prepared_receipt_sha256': args.prepared_receipt_sha256, 'payload_manifest_sha256': args.payload_manifest_sha256,
    'artifact_manifest_sha256': args.artifact_manifest_sha256, 'profile_sha256': args.profile_sha256,
    'installed_files': installed, 'source_root_unchanged': True, 'matched_payload_verified_after_installation': True,
    'account_databases_sha256': accounts,
    'default_selection_unchanged': True, 'guardian_installed_into_host_copy': True,
    'enabled_guardian_executed': False, 'physical_USB_changed': False, 'boot_ready': False,
    'native_qualified': False, 'remaining': ['full-system VM and native systemd graph',
      'native power/shutdown ownership policy', 'complete physical controller/root handoff and qualification']}
  with (output / 'receipt.json').open('x') as stream:
    json.dump(record, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
  print('Installed exact artifacts into a new host copy only; no boot selected.')


if __name__ == '__main__':
  main()
