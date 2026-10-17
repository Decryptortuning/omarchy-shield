"""Source-bound qualification policy rendering; no account or root mutation."""
import importlib.util
from pathlib import Path
import sys
import unittest

PORT = Path(__file__).resolve().parent.parent
REPO = PORT.parent.parent
sys.path.insert(0, str(PORT / 'tools'))
from qualification_profile import UID, render
from usb_root_profile import file_identity

SPEC = importlib.util.spec_from_file_location('qualification_usb_fixture', PORT / 'tests/test_usb_root_profile.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class QualificationProfileTests(unittest.TestCase):
  def setUp(self):
    self.fixture = FIXTURE.UsbRootProfileTests()
    self.fixture.setUp()
    self.addCleanup(self.fixture.doCleanups)
    self.root, self.manifest = self.fixture.root, self.fixture.manifest
    for installed, source in {
      'usr/share/omarchy/config/hypr/hyprland.lua': 'config/hypr/hyprland.lua',
      'usr/share/omarchy/default/hypr/autostart.lua': 'default/hypr/autostart.lua',
      'usr/share/omarchy/default/wayland-sessions/omarchy.desktop': 'default/wayland-sessions/omarchy.desktop',
    }.items():
      target = self.root / installed
      target.parent.mkdir(parents=True, exist_ok=True)
      target.write_bytes((REPO / source).read_bytes())
      self.manifest['root_files'][installed] = file_identity(self.root, installed)

  def test_mounts_select_only_new_candidate_subvolumes(self):
    profile = render(self.root, self.manifest)
    fstab = profile['root']['etc/fstab']
    for value in self.manifest['subvolumes'].values():self.assertIn('subvol=' + value + ' ', fstab)
    for old in ['@', '@home', '@log']:self.assertNotIn('subvol=' + old + ' ', fstab)
    self.assertFalse(profile['policy']['boot_ready'])
    self.assertEqual(UID, 1001)
    self.assertNotIn('wheel', profile['policy']['account']['supplementary_groups'])

  def test_real_session_retains_normal_config_and_defers_online_first_run(self):
    profile = render(self.root, self.manifest)
    lua = profile['home']['shieldqual/.config/hypr/hyprland.lua']
    self.assertIn('require("default.hypr.omarchy")', lua)
    self.assertIn('package.loaded["default.hypr.autostart"] = true', lua)
    self.assertIn('omarchy-launch-shell', lua)
    self.assertFalse(profile['policy']['normal_first_run_complete'])
    self.assertFalse(any('/done/' in name for name in profile['home']))
    self.assertIn('uwsm start -g -1 -e -D Hyprland hyprland.desktop',
                  profile['home']['shieldqual/.bash_profile'])
    self.assertIn('Requires=shield-guardian.service',
                  profile['root']['etc/systemd/system/shield-qualification-desktop.service'])

  def test_changed_upstream_bytes_require_new_admission(self):
    (self.root / 'usr/share/omarchy/config/hypr/hyprland.lua').write_text('-- changed\n')
    with self.assertRaisesRegex(ValueError, 'source differs'):
      render(self.root, self.manifest)

  def test_changed_session_contract_requires_review_even_after_hash_update(self):
    name = 'usr/share/omarchy/default/wayland-sessions/omarchy.desktop'
    path = self.root / name
    path.write_text('[Desktop Entry]\nExec=Hyprland\n')
    self.manifest['root_files'][name] = file_identity(self.root, name)
    with self.assertRaisesRegex(ValueError, 'Unreviewed UWSM'):
      render(self.root, self.manifest)


if __name__ == '__main__':
  unittest.main()
