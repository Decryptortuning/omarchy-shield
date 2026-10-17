"""Exercise the actual Mesa admission and package prepare boundary."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PORT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('mesa_profile', PORT / 'tools/mesa_profile.py')
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class MesaProfileTests(unittest.TestCase):
  def setUp(self):
    temporary = tempfile.TemporaryDirectory(prefix='shield-mesa-intent-')
    self.addCleanup(temporary.cleanup)
    self.root = Path(temporary.name)
    self.source = self.root / 'source'
    self.bundle = self.root / 'mesa'
    self.install = self.bundle / 'install'
    lock = json.loads((PORT / 'mesa.lock.json').read_text())
    for relative in ['ports/shield/mesa.lock.json', lock['mesa']['patches'][0]['path'],
                     'ports/shield/tools/mesa_profile.py']:
      target = self.source / relative
      target.parent.mkdir(parents=True, exist_ok=True)
      shutil.copy2(PORT.parent.parent / relative, target)
    names = ['libEGL_mesa.so.0.0.0', 'libGLX_mesa.so.0.0.0', 'libgbm.so.1.0.0',
             'gbm/dri_gbm.so', 'dri/libdril_dri.so', 'dri/nouveau_drv_video.so']
    header = b'\x7fELF\x02\x01' + bytes(12) + (183).to_bytes(2, 'little')
    for name in names:
      target = self.install / 'usr/lib' / name
      target.parent.mkdir(parents=True, exist_ok=True)
      target.write_bytes(header)
      target.chmod(0o755)
    license_file = self.install / 'usr/share/licenses/mesa/license.rst'
    license_file.parent.mkdir(parents=True)
    license_file.write_text('fixture license\n')
    license_file.chmod(0o644)
    (self.install / 'usr/lib/libgbm.so').symlink_to('libgbm.so.1.0.0')
    self.manifest = {
      'format_version': 1, 'mesa_commit': lock['mesa']['commit'],
      'patch_sha256': lock['mesa']['patches'][0]['sha256'],
      'cpu': lock['diagnostic_build']['cpu'], 'with_x11_glx': True, 'with_va_api': True,
      'meson_options': ['-Dgallium-drivers=nouveau,tegra', '-Dvulkan-drivers=',
                        '-Dplatforms=x11,wayland', '-Dglx=dri', '-Degl=enabled',
                        '-Dgbm=enabled', '-Dgallium-va=enabled', '-Dglvnd=enabled', '-Dllvm=disabled'],
      'files': {}, 'libraries': {}}
    self.index_tree()

  def index_tree(self):
    self.manifest['files'] = {}
    self.manifest['libraries'] = {}
    for path in self.install.rglob('*'):
      name = str(path.relative_to(self.install))
      if path.is_symlink():
        self.manifest['files'][name] = {'type': 'symlink', 'target': os.readlink(path)}
      elif path.is_file():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.manifest['files'][name] = {'type': 'file', 'sha256': digest, 'mode': path.stat().st_mode & 0o7777}
        if name.startswith('usr/lib/'):
          self.manifest['libraries'][name] = digest
    self.save()

  def save(self):
    (self.bundle / 'manifest.json').write_text(json.dumps(self.manifest))

  def verify(self):
    self.save()
    return PROFILE.verify_mesa_profile(self.bundle, self.source)

  def test_complete_current_payload_admitted(self):
    self.assertEqual(self.verify(), (self.manifest, self.install))

  def test_stale_source_patch_and_cpu_refused(self):
    for key, wrong in [('mesa_commit', '0' * 40), ('patch_sha256', '0' * 64), ('cpu', 'cortex-a53')]:
      with self.subTest(key=key):
        original = self.manifest[key]
        self.manifest[key] = wrong
        with self.assertRaises(ValueError):
          self.verify()
        self.manifest[key] = original

  def test_incomplete_desktop_frontends_refused(self):
    for key in ['with_x11_glx', 'with_va_api']:
      with self.subTest(key=key):
        self.manifest[key] = False
        with self.assertRaisesRegex(ValueError, 'X11/GLX and VA'):
          self.verify()
        self.manifest[key] = True

  def test_overriding_option_refused(self):
    self.manifest['meson_options'].append('-Dgallium-drivers=swrast')
    with self.assertRaisesRegex(ValueError, 'Duplicate Mesa option'):
      self.verify()

  def test_changed_payload_and_unexpected_file_refused(self):
    path = self.install / 'usr/lib/libgbm.so.1.0.0'
    original = path.read_bytes()
    path.write_bytes(original + b'changed')
    with self.assertRaisesRegex(ValueError, 'Changed installed Mesa file'):
      self.verify()
    path.write_bytes(original)
    (self.install / 'usr/lib/unlisted').write_text('extra')
    with self.assertRaisesRegex(ValueError, 'tree differs'):
      self.verify()

  def test_escaping_manifested_symlink_refused(self):
    path = self.install / 'usr/lib/libgbm.so'
    path.unlink()
    outside = self.root / 'outside'
    outside.write_text('outside')
    path.symlink_to(outside)
    self.index_tree()
    with self.assertRaisesRegex(ValueError, 'escapes build'):
      self.verify()

  def test_consistent_wrong_architecture_refused(self):
    path = self.install / 'usr/lib/libgbm.so.1.0.0'
    header = bytearray(path.read_bytes())
    header[18:20] = (62).to_bytes(2, 'little')
    path.write_bytes(header)
    self.index_tree()
    with self.assertRaisesRegex(ValueError, 'Not AArch64 Mesa'):
      self.verify()

  def test_current_export_patch_mutation_refused(self):
    lock = json.loads((PORT / 'mesa.lock.json').read_text())
    (self.source / lock['mesa']['patches'][0]['path']).write_text('changed')
    with self.assertRaisesRegex(ValueError, 'Exported Mesa patch'):
      self.verify()

  def package_prepare(self):
    binaries = self.root / 'bin'
    binaries.mkdir()
    (binaries / 'python').symlink_to(sys.executable)
    env = dict(os.environ, OMARCHY_SRC=str(self.source), SHIELD_MESA_DIR=str(self.bundle),
               srcdir=str(self.root / 'package-source'), PATH=str(binaries) + ':' + os.environ['PATH'])
    return subprocess.run(['bash', '-c', 'source "$1"; prepare', 'bash',
                           str(PORT / 'mesa-shield/PKGBUILD')], env=env, capture_output=True, text=True)

  def test_package_prepare_copies_complete_payload(self):
    result = self.package_prepare()
    self.assertEqual(result.returncode, 0, result.stderr)
    payload = self.root / 'package-source/payload'
    self.assertTrue((payload / 'usr/lib/libgbm.so').is_symlink())
    self.assertEqual(json.loads((payload / 'usr/share/licenses/mesa/shield-build.json').read_text()), self.manifest)

  def test_package_prepare_refuses_stale_input_before_copy(self):
    self.manifest['mesa_commit'] = '0' * 40
    self.save()
    result = self.package_prepare()
    self.assertNotEqual(result.returncode, 0)
    self.assertIn('Mesa source differs', result.stderr)
    self.assertFalse((self.root / 'package-source/payload').exists())


if __name__ == '__main__':
  unittest.main()
