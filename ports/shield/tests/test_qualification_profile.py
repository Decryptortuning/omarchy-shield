"""Source-bound qualification policy rendering; no account or root mutation."""
import gzip
import hashlib
import importlib.util
import re
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

PORT = Path(__file__).resolve().parent.parent
REPO = PORT.parent.parent
sys.path.insert(0, str(PORT / 'tools'))
import qualification_profile as POLICY
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
    # Explicit synthetic primary inputs. Unit fixtures replace only expected
    # digest admission; actual host preparation still requires the reviewed XML
    # and compressed manuals from the matched reference.
    self.primary = {
      POLICY.LOGIN1_POLICY: ('<policyconfig>' + ''.join('<action id="' + name + '"/>'
        for name in POLICY.LOGIN1_DENIED + ('org.freedesktop.login1.inhibit-delay-sleep',)) + '</policyconfig>').encode(),
      POLICY.SYSTEMD1_POLICY: ('<policyconfig>' + ''.join('<action id="' + name + '"/>'
        for name in POLICY.SYSTEMD1_DENIED + ('org.freedesktop.systemd1.reply-password',)) + '</policyconfig>').encode(),
      POLICY.LOGIND_MAN: gzip.compress(' '.join(name + '=' for name in POLICY.LOGIND_IGNORE_KEYS).encode(), mtime=0),
      POLICY.MANAGER_MAN: gzip.compress(b'CtrlAltDelBurstAction= "none"', mtime=0),
    }
    self.primary_hashes = {}
    for name, content in self.primary.items():
      path = self.root / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_bytes(content)
      self.primary_hashes[name] = hashlib.sha256(content).hexdigest()
    admission = patch.object(POLICY, 'PRIMARY_SHA256', self.primary_hashes)
    admission.start()
    self.addCleanup(admission.stop)

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


  def test_exact_installed_privileged_action_matrix_is_explicitly_denied(self):
    profile = render(self.root, self.manifest)
    expected = {'org.freedesktop.login1.' + family + suffix
      for family in ['power-off', 'reboot', 'halt', 'suspend', 'hibernate']
      for suffix in ['', '-multiple-sessions', '-ignore-inhibit']}
    expected.update('org.freedesktop.login1.' + name for name in [
      'manage', 'set-reboot-parameter', 'set-reboot-to-firmware-setup',
      'set-reboot-to-boot-loader-menu', 'set-reboot-to-boot-loader-entry'])
    expected.update('org.freedesktop.systemd1.' + name for name in [
      'manage-units', 'manage-unit-files', 'set-environment', 'reload-daemon'])
    rule = profile['root'][POLICY.POLKIT_PATH]
    actual = re.findall(r'^    case "([^"]+)":$', rule, re.MULTILINE)
    self.assertEqual(len(actual), 24)
    self.assertEqual(set(actual), expected)
    self.assertEqual(set(profile['policy']['user_power_policy']['denied_actions']), expected)
    self.assertEqual(rule.count('return polkit.Result.NO;'), 1)
    self.assertNotIn('hybrid-sleep', rule)
    self.assertNotIn('suspend-then-hibernate', rule)

  def test_root_other_users_and_unrelated_actions_fall_through(self):
    rule = render(self.root, self.manifest)['root'][POLICY.POLKIT_PATH]
    # These structural invariants constrain the actual emitted rule, not a
    # second Python implementation of its decision function.
    guard = '  if (subject.user !== "shieldqual") { return; }'
    self.assertIn(guard + '\n  switch (action.id) {', rule)
    self.assertLess(rule.index(guard), rule.index('return polkit.Result.NO;'))
    self.assertEqual(rule.count('subject.user'), 1)
    self.assertNotIn('polkit.Result.YES', rule)
    self.assertNotIn('subject.active', rule)
    self.assertNotIn('subject.local', rule)
    self.assertIn('    default: return;', rule)
    self.assertNotIn('org.freedesktop.login1.inhibit-delay-sleep', rule)
    self.assertNotIn('org.freedesktop.systemd1.reply-password', rule)

  def test_hardware_keys_idle_and_ctrl_alt_delete_have_explicit_controls(self):
    profile = render(self.root, self.manifest)
    lines = profile['root'][POLICY.LOGIND_PATH].splitlines()
    expected = {name + '=ignore' for name in [
      'HandlePowerKey', 'HandlePowerKeyLongPress', 'HandleRebootKey', 'HandleRebootKeyLongPress',
      'HandleSuspendKey', 'HandleSuspendKeyLongPress', 'HandleHibernateKey', 'HandleHibernateKeyLongPress',
      'HandleLidSwitch', 'HandleLidSwitchExternalPower', 'HandleLidSwitchDocked',
      'HandleSecureAttentionKey', 'IdleAction']}
    self.assertEqual(lines[0], '[Login]')
    self.assertEqual(set(lines[1:]), expected)
    self.assertEqual(len(lines[1:]), len(expected))
    self.assertIn('CtrlAltDelBurstAction=none\n',
                  profile['root']['etc/systemd/system.conf.d/90-shield-qualification.conf'])
    self.assertIn('ctrl-alt-del.target', profile['policy']['masked_services'])
    self.assertFalse(profile['policy']['user_power_policy']['native_effective_policy_verified'])

  def test_changed_primary_policy_or_manual_bytes_require_admission(self):
    for name, original in self.primary.items():
      with self.subTest(name=name):
        path = self.root / name
        path.write_bytes(original + b'changed')
        try:
          with self.assertRaisesRegex(ValueError, 'primary source differs'):
            render(self.root, self.manifest)
        finally:
          path.write_bytes(original)

  def test_missing_privileged_action_after_digest_refresh_still_refuses(self):
    name = POLICY.LOGIN1_POLICY
    altered = self.primary[name].replace(b'<action id="org.freedesktop.login1.reboot"/>', b'')
    (self.root / name).write_bytes(altered)
    self.primary_hashes[name] = hashlib.sha256(altered).hexdigest()
    with self.assertRaisesRegex(ValueError, 'action catalog differs'):
      render(self.root, self.manifest)

  def test_unsupported_configuration_key_after_digest_refresh_still_refuses(self):
    name = POLICY.LOGIND_MAN
    altered = gzip.compress(b'HandlePowerKey=', mtime=0)
    (self.root / name).write_bytes(altered)
    self.primary_hashes[name] = hashlib.sha256(altered).hexdigest()
    with self.assertRaisesRegex(ValueError, 'configuration keys differ'):
      render(self.root, self.manifest)

  def test_primary_sources_are_recorded_and_render_never_changes_them(self):
    profile = render(self.root, self.manifest)
    self.assertEqual(profile['policy']['power_policy_primary_sources'], self.primary_hashes)
    for name, content in self.primary.items():
      self.assertEqual((self.root / name).read_bytes(), content)


if __name__ == '__main__':
  unittest.main()
