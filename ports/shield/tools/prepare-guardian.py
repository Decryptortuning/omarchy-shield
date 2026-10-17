#!/usr/bin/env python3
"""Build source-bound guardian artifacts; never install, boot or release them."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from guardian_binding import BOARD, CONFIG_SHA256, DTB_SHA256, IMAGE_SHA256, SOURCE_NAMES, TIMING, USB, seal
from usb_root_profile import digest, require, verify_root


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  for name in ['rootfs', 'payload-manifest', 'overlay', 'kernel', 'dtb', 'output']:
    parser.add_argument('--' + name, type=Path, required=True)
  parser.add_argument('--payload-manifest-sha256', required=True)
  parser.add_argument('--overlay-manifest-sha256', required=True)
  parser.add_argument('--role', choices=['maintenance', 'systemd'], required=True)
  args = parser.parse_args()
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'Build private artifacts as WSL root')
  port = Path(__file__).resolve().parent.parent
  tools = port / 'tools'
  root = args.rootfs.resolve(strict=True)
  require(root != Path('/'), 'Use the matched reference root')
  require(digest(args.payload_manifest) == args.payload_manifest_sha256, 'Payload manifest differs')
  manifest = json.loads(args.payload_manifest.read_text())
  verify_root(manifest, root)
  specification = importlib.util.spec_from_file_location('qualification_preparer', tools / 'prepare-qualification-root.py')
  preparer = importlib.util.module_from_spec(specification)
  specification.loader.exec_module(preparer)
  preparer.admit_overlay(root, manifest, args.overlay, args.overlay_manifest_sha256, args.payload_manifest_sha256)
  require(digest(args.kernel / 'Image') == IMAGE_SHA256
          and digest(args.kernel / 'kernel.config') == CONFIG_SHA256
          and (args.kernel / 'kernel-release.txt').read_text().strip() == '7.1.0-shield-bringup', 'Kernel input differs')
  require(not args.dtb.is_symlink() and stat.S_ISREG(args.dtb.stat().st_mode)
          and digest(args.dtb) == DTB_SHA256, 'Restricted DT differs')
  source_names = sorted(SOURCE_NAMES)
  hashes = {name: digest(port / name) for name in source_names}
  output = args.output
  require(not output.exists() and not output.is_symlink(), 'Output must be new; retain failed artifacts')
  require(not output.resolve().is_relative_to(root), 'Output must be outside the reference root')
  output.mkdir(mode=0o700)
  build = output / 'build'
  build.mkdir()
  env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
  flags = ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-static', '-Wl,--build-id=none']
  helper = output / 'shield-restart-recovery'
  subprocess.run(['aarch64-linux-gnu-gcc', *flags, str(port / 'qualification/restart-recovery.c'),
                  '-o', str(helper)], env=env, check=True)
  helper.chmod(0o700)
  profile = seal({'format_version': 1, 'role': 1 if args.role == 'maintenance' else 2,
    'board': BOARD, 'kernel': {'release': '7.1.0-shield-bringup', 'image_sha256': IMAGE_SHA256,
                              'config_sha256': CONFIG_SHA256},
    'dtb': {'sha256': DTB_SHA256, 'bytes': args.dtb.stat().st_size},
    'filesystem': {'uuid': manifest['filesystem_uuid'], 'candidate_id': manifest['candidate_id'],
                   'subvolumes': manifest['subvolumes'], 'usb': USB},
    'overlay_sha256': args.overlay_manifest_sha256, 'sources': hashes,
    'recovery_helper': {'sha256': digest(helper), 'bytes': helper.stat().st_size},
    'account': {'name': 'shieldqual', 'uid': 1001, 'gid': 1001}, 'timing': TIMING})
  for name in ['main.c', 'sampler.c', 'state.c', 'guardian.h']:
    shutil.copyfile(port / 'guardian' / name, build / name)
  template = (port / 'guardian/profile.h').read_text()
  replacements = {'#define SG_PROFILE_ENABLED 0': '#define SG_PROFILE_ENABLED 1',
    '#define SG_PROFILE_ROLE 1': '#define SG_PROFILE_ROLE ' + str(profile['role']),
    '"' + '0' * 64 + '"': '"' + profile['candidate'] + '"'}
  for before, after in replacements.items():
    require(template.count(before) == 1, 'Unreviewed guardian profile template')
    template = template.replace(before, after)
  (build / 'profile.h').write_text(template)
  guardian = output / 'shield-guardian'
  subprocess.run(['aarch64-linux-gnu-gcc', *flags, str(build / 'main.c'), str(build / 'sampler.c'),
                  str(build / 'state.c'), '-o', str(guardian)], env=env, check=True)
  guardian.chmod(0o700)
  for name in ['guardian_binding.py', 'guardian_client.py', 'qualification_recovery.py', 'usb_root_profile.py']:
    shutil.copyfile(tools / name, output / name)
    (output / name).chmod(0o644)
  shutil.copyfile(args.overlay / 'manifest.json', output / 'overlay-manifest.json')
  (output / 'overlay-manifest.json').chmod(0o600)
  with (output / 'profile.json').open('x') as stream:
    stream.write(json.dumps(profile, indent=2) + '\n')
  (output / 'profile.json').chmod(0o600)
  files = {name: {'sha256': digest(output / name), 'bytes': (output / name).stat().st_size}
    for name in ['shield-guardian', 'shield-restart-recovery', 'guardian_binding.py', 'guardian_client.py',
                 'qualification_recovery.py', 'usb_root_profile.py', 'overlay-manifest.json']}
  artifact = {'format_version': 1, 'candidate': profile['candidate'], 'files': files,
    'source_inputs_sha256': hashes, 'generated_profile_header_sha256': digest(build / 'profile.h'),
    'profile_sha256': digest(output / 'profile.json'), 'compiled_enabled': True,
    'role': profile['role'], 'installed': False, 'native_execution_released': False, 'boot_ready': False}
  require(all(digest(port / name) == value for name, value in hashes.items()), 'Source changed during build')
  require(digest(args.payload_manifest) == args.payload_manifest_sha256
          and digest(args.overlay / 'manifest.json') == args.overlay_manifest_sha256
          and digest(args.kernel / 'Image') == IMAGE_SHA256
          and digest(args.kernel / 'kernel.config') == CONFIG_SHA256
          and digest(args.dtb) == DTB_SHA256, 'Artifact input changed during build')
  with (output / 'artifacts.json').open('x') as stream:
    stream.write(json.dumps(artifact, indent=2) + '\n')
  (output / 'artifacts.json').chmod(0o600)
  print('Built bound ARM artifacts only; native execution remains unreleased.')


if __name__ == '__main__':
  main()
