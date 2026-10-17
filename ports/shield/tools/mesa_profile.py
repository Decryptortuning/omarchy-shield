"""Validate the current complete Mesa desktop payload against source intent."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


def require(condition, message):
  if not condition:
    raise ValueError(message)


def verify_mesa_profile(directory, source_tree):
  directory = Path(directory)
  source_tree = Path(source_tree).resolve(strict=True)
  lock = json.loads((source_tree / 'ports/shield/mesa.lock.json').read_text())
  manifest = json.loads((directory / 'manifest.json').read_text())
  require(manifest['format_version'] == 1, 'Unknown Mesa build manifest')
  require(len(lock['mesa']['patches']) == 1, 'Expected one combined Tegra API patch')
  patch = lock['mesa']['patches'][0]
  path = (source_tree / patch['path']).resolve(strict=True)
  require(path.is_relative_to(source_tree) and hashlib.sha256(path.read_bytes()).hexdigest() == patch['sha256'], 'Exported Mesa patch differs from its lock')
  require(manifest['mesa_commit'] == lock['mesa']['commit'], 'Mesa source differs from exported intent')
  require(manifest['patch_sha256'] == patch['sha256'], 'Mesa patch differs from exported intent')
  require(manifest['cpu'] == lock['diagnostic_build']['cpu'], 'Wrong Mesa target CPU')
  require(manifest['with_x11_glx'] is True and manifest['with_va_api'] is True, 'Build X11/GLX and VA together')
  required_options = {'-Dgallium-drivers=' + ','.join(lock['diagnostic_build']['gallium_drivers']),
                      '-Dvulkan-drivers=' + ','.join(lock['diagnostic_build']['vulkan_drivers']),
                      '-Dplatforms=x11,wayland', '-Dglx=dri', '-Degl=enabled',
                      '-Dgbm=enabled', '-Dgallium-va=enabled', '-Dglvnd=enabled', '-Dllvm=disabled'}
  option_keys = [option.split('=', 1)[0] for option in manifest['meson_options']]
  require(len(option_keys) == len(set(option_keys)), 'Duplicate Mesa option can override the desktop profile')
  require(required_options.issubset(set(manifest['meson_options'])), 'Mesa options differ from the complete desktop profile')
  root = (directory / 'install').resolve(strict=True)
  actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_symlink() or not p.is_dir()}
  require(actual == set(manifest['files']), 'Installed Mesa tree differs from its manifest')
  for name, item in manifest['files'].items():
    relative = PurePosixPath(name)
    require(relative.parts and not relative.is_absolute() and relative.parts[0] == 'usr' and '..' not in relative.parts, 'Unsafe installed Mesa path')
    source = root / name
    mode = source.lstat().st_mode
    require(source.resolve(strict=True).is_relative_to(root), 'Installed Mesa path escapes build')
    if item['type'] == 'symlink':
      require(stat.S_ISLNK(mode) and os.readlink(source) == item['target'], 'Changed installed Mesa symlink')
    else:
      require(item['type'] == 'file' and stat.S_ISREG(mode), 'Unexpected installed Mesa file type')
      require(stat.S_IMODE(mode) == item['mode'] and mode & 0o7000 == 0, 'Changed or special installed Mesa mode')
      require(hashlib.sha256(source.read_bytes()).hexdigest() == item['sha256'], 'Changed installed Mesa file')
  for name, digest in manifest['libraries'].items():
    require(name in manifest['files'] and manifest['files'][name].get('sha256') == digest, 'Mesa library index differs from file manifest')
  for name in ['libEGL_mesa.so.0.0.0', 'libGLX_mesa.so.0.0.0', 'libgbm.so.1.0.0',
               'gbm/dri_gbm.so', 'dri/libdril_dri.so', 'dri/nouveau_drv_video.so']:
    library = root / 'usr/lib' / name
    require(library.is_file(), 'Missing Mesa library: ' + name)
    header = library.read_bytes()[:20]
    require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == 183,
            'Not AArch64 Mesa: ' + name)
  return manifest, root
