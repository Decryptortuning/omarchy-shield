#!/usr/bin/env python3
"""Build a coherent ARM Mesa library set without installing or booting it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess


def run(command, **kwargs):
  return subprocess.run(command, check=True, **kwargs)


def quote(value):
  return "'" + str(value).replace('\\', '\\\\').replace("'", "\\'") + "'"


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--source', type=Path, required=True, help='Mesa checkout with exactly the locked patch applied')
  parser.add_argument('--rootfs', type=Path, required=True, help='Prepared ARM sysroot; only read')
  parser.add_argument('--output', type=Path, required=True, help='New build directory')
  parser.add_argument('--meson', default='meson', help='Meson executable; its Python must have Mako, PyYAML and packaging')
  parser.add_argument('--jobs', type=int, default=min(16, os.cpu_count() or 1))
  parser.add_argument('--with-x11', action='store_true', help='Also build the paired X11/GLX libraries for installed-desktop preparation')
  parser.add_argument('--with-va', action='store_true', help='Build the Nouveau VA-API frontend and codec parsers; hardware decoding is not qualified by this build')
  args = parser.parse_args()
  port = Path(__file__).resolve().parent.parent
  repository = port.parent.parent
  lock = json.loads((port / 'mesa.lock.json').read_text())
  source = args.source.resolve(strict=True)
  rootfs = args.rootfs.resolve(strict=True)
  output = args.output.resolve()
  if args.jobs < 1 or args.jobs > 64:
    parser.error('--jobs must be between 1 and 64')
  if output.exists() or output == source or output == rootfs or source in output.parents or rootfs in output.parents:
    parser.error('Use a new output directory outside the source and ARM root')
  if not (rootfs / 'var/lib/shield-linux/sources.lock.json').is_file():
    parser.error('Use the separately prepared Shield ARM filesystem')
  revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
  if revision != lock['mesa']['commit']:
    parser.error('Mesa HEAD does not match mesa.lock.json')
  patches = lock['mesa']['patches']
  if len(patches) != 1:
    parser.error('This builder expects the one combined Tegra API patch')
  patch = repository / patches[0]['path']
  expected_diff = patch.read_bytes()
  if hashlib.sha256(expected_diff).hexdigest() != patches[0]['sha256']:
    parser.error('Locked Mesa patch checksum mismatch')
  actual_diff = subprocess.check_output(['git', '-C', str(source), 'diff', '--no-ext-diff', '--binary', 'HEAD'])
  if actual_diff != expected_diff:
    parser.error('Mesa must contain exactly the locked patch; unrelated edits are not build inputs')
  for name in ['aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-g++', 'qemu-aarch64-static', 'pkg-config', 'ninja']:
    if not shutil.which(name):
      parser.error(f'Missing build prerequisite: {name}')
  meson = shutil.which(args.meson)
  if not meson:
    parser.error('Meson was not found')
  scanner = rootfs / 'usr/bin/wayland-scanner'
  if not scanner.is_file():
    parser.error('The ARM root must include its matching Wayland scanner')
  output.mkdir(parents=True, mode=0o700)
  generators = output / 'generators'
  generators.mkdir()
  wrapper = generators / 'wayland-scanner'
  wrapper.write_text('#!/bin/bash\nset -euo pipefail\nexec qemu-aarch64-static -L '
                     + shlex.quote(str(rootfs)) + ' ' + shlex.quote(str(scanner)) + ' "$@"\n')
  wrapper.chmod(0o755)
  cross = output / 'cross.ini'
  cross.write_text(f'''[binaries]
c = ['aarch64-linux-gnu-gcc', {quote('--sysroot=' + str(rootfs))}]
cpp = ['aarch64-linux-gnu-g++', {quote('--sysroot=' + str(rootfs))}]
ar = 'aarch64-linux-gnu-ar'
strip = 'aarch64-linux-gnu-strip'
pkg-config = 'pkg-config'
[properties]
sys_root = {quote(rootfs)}
pkg_config_libdir = {quote(str(rootfs / 'usr/lib/pkgconfig') + ':' + str(rootfs / 'usr/share/pkgconfig'))}
needs_exe_wrapper = true
[host_machine]
system = 'linux'
cpu_family = 'aarch64'
cpu = 'cortex-a57'
endian = 'little'
[built-in options]
c_args = ['-mcpu=cortex-a57']
cpp_args = ['-mcpu=cortex-a57']
''')
  env = os.environ.copy()
  env['PATH'] = str(generators) + ':' + str(Path(meson).parent) + ':' + env['PATH']
  build = output / 'build'
  platforms = 'x11,wayland' if args.with_x11 else 'wayland'
  glx = 'dri' if args.with_x11 else 'disabled'
  options = [
    '--prefix=/usr', '--libdir=lib', '--buildtype=release',
    '-Dgallium-drivers=nouveau,tegra', '-Dvulkan-drivers=', f'-Dplatforms={platforms}',
    '-Degl=enabled', f'-Dglx={glx}', '-Dgbm=enabled', '-Dllvm=disabled',
    '-Dgallium-va=' + ('enabled' if args.with_va else 'disabled'),
    '-Dgallium-rusticl=false', '-Dvideo-codecs=' + ('all' if args.with_va else ''),
    '-Dglvnd=enabled', '-Dvalgrind=disabled', '-Dlibunwind=disabled',
    '-Dbuild-tests=false', '-Dmicrosoft-clc=disabled', '-Dtools=',
  ]
  run([meson, 'setup', str(build), str(source), '--cross-file', str(cross), *options], env=env)
  run(['ninja', '-C', str(build), '-j', str(args.jobs)], env=env)
  install = output / 'install'
  run([meson, 'install', '-C', str(build), '--no-rebuild'], env={**env, 'DESTDIR': str(install)})
  license_path = install / 'usr/share/licenses/mesa/license.rst'
  license_path.parent.mkdir(parents=True)
  shutil.copyfile(source / 'docs/license.rst', license_path)
  libraries = {}
  for path in sorted((install / 'usr/lib').rglob('*')):
    if path.is_file() and not path.is_symlink() and '.so' in path.name:
      header = path.read_bytes()[:20]
      if header[:4] != b'\x7fELF' or int.from_bytes(header[18:20], 'little') != 183:
        raise RuntimeError(f'Expected an AArch64 library: {path}')
      libraries[str(path.relative_to(install))] = hashlib.sha256(path.read_bytes()).hexdigest()
  files = {}
  for path in sorted(install.rglob('*')):
    relative = str(path.relative_to(install))
    if path.is_symlink():
      if not path.resolve(strict=True).is_relative_to(install):
        raise RuntimeError(f'Installed symlink escapes the library bundle: {path}')
      files[relative] = {'type': 'symlink', 'target': os.readlink(path)}
    elif path.is_file():
      files[relative] = {'type': 'file', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                         'mode': path.stat().st_mode & 0o777}
    elif not path.is_dir():
      raise RuntimeError(f'Unexpected installed file type: {path}')
  manifest = {
    'format_version': 1,
    'mesa_commit': revision, 'patch_sha256': patches[0]['sha256'], 'cpu': 'cortex-a57',
    'with_x11_glx': args.with_x11, 'with_va_api': args.with_va,
    'meson_options': options, 'libraries': libraries, 'files': files,
    'installed_on_owner_root': False, 'native_tested': False, 'flashable_image': False,
  }
  (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
  print(f'Built paired ARM Mesa libraries in {install}; no system installation or device action.')


if __name__ == '__main__':
  main()
