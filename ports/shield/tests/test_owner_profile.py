"""OWNER enrollment and pre-effect boundaries; no target or network actions."""
import base64
import copy
import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import owner_profile as profile
import owner_runtime
import native_mounts
spec = importlib.util.spec_from_file_location('owner_network_target', TOOLS / 'owner-network.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


def key(byte):
  wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes([byte]) * 32
  return 'ssh-ed25519 ' + base64.b64encode(wire).decode('ascii') + '\n'


def enrollment():
  owner = 'a' * 32
  root = '@shield-' + owner
  return {'purpose': 'omarchy-shield-owner', 'owner_id': owner,
    'filesystem': {'uuid': '11111111-2222-4333-8444-555555555555',
      'usb': {'vendor': '0781', 'product': '5581'},
      'subvolumes': {'root': root, 'home': root + '-home', 'log': root + '-log'}},
    'ssh': {'operator_public_key': key(1), 'host_public_key': key(2),
      'host_private_identity': {'bytes': 411, 'sha256': 'b' * 64}},
    'ethernet': {'module': {'bytes': 257392, 'sha256': 'c' * 64},
      'firmware': {'usr/lib/firmware/rtl_nic/rtl8168h-2.fw': {'bytes': 1234, 'sha256': 'd' * 64}}}}


def context(enrolled):
  return {'purpose': 'omarchy-shield-owner', 'owner_id': enrolled['owner_id'],
    'enrollment_sha256': 'e' * 64, 'kernel_release': '7.1.0-shield-bringup',
    'filesystem': copy.deepcopy(enrolled['filesystem']), 'sources_sha256': {
      name: 'f' * 64 for name in ['owner_profile.py', 'owner_runtime.py', 'owner_layer.py', 'owner_command_line.py', 'owner-init.py', 'owner-network.py',
                                 'owner-ready.py', 'owner-thermal.py']}}


class OwnerEnrollmentTests(unittest.TestCase):
  def test_exact_enrollment_is_pure_and_does_not_claim_activation(self):
    data = enrollment()
    before = copy.deepcopy(data)
    rendered = profile.render(data)
    self.assertEqual(data, before)
    self.assertFalse(rendered['ready_to_activate'])
    self.assertFalse(rendered['normal_first_run_complete'])
    self.assertIn('owner-ready.py', rendered['required_programs'])

  def test_no_key_options_comments_multiple_lines_or_other_algorithms(self):
    for raw in ['command="x" ' + key(1), key(1).rstrip() + ' comment\n', key(1) + key(2),
                key(1).replace('ssh-ed25519', 'ssh-rsa', 1), key(1).rstrip(), 'ssh-ed25519 bad\n']:
      with self.subTest(raw=raw[:30]), self.assertRaises(ValueError): profile.public_key(raw)

  def test_wrong_wire_type_length_or_noncanonical_encoding_is_refused(self):
    for wire in [b'', b'A' * 51, struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 31) + b'A' * 32]:
      with self.subTest(size=len(wire)), self.assertRaises(ValueError):
        profile.public_key('ssh-ed25519 ' + base64.b64encode(wire).decode() + '\n')

  def test_host_and_operator_are_distinct(self):
    data = enrollment()
    data['ssh']['host_public_key'] = data['ssh']['operator_public_key']
    with self.assertRaises(ValueError): profile.validate(data)

  def test_unenrolled_or_unknown_purpose_is_refused(self):
    for value in ['bounded native systemd Omarchy qualification', '', None]:
      data = enrollment()
      data['purpose'] = value
      with self.subTest(value=value), self.assertRaises(ValueError): profile.validate(data)

  def test_unknown_profile_fields_are_refused(self):
    for target in ['root', 'ssh', 'ethernet', 'filesystem']:
      data = enrollment()
      selected = data if target == 'root' else data[target]
      selected['unreviewed'] = True
      with self.subTest(target=target), self.assertRaises(ValueError): profile.validate(data)

  def test_candidate_and_filesystem_paths_cannot_be_retargeted(self):
    for change in [('root', '@other'), ('home', '../other'), ('log', '/var/log')]:
      data = enrollment()
      data['filesystem']['subvolumes'][change[0]] = change[1]
      with self.subTest(change=change), self.assertRaises(ValueError): profile.validate(data)

  def test_invalid_artifact_types_hashes_and_paths_are_refused(self):
    for item in [{'bytes': True, 'sha256': 'a' * 64}, {'bytes': 0, 'sha256': 'a' * 64},
                 {'bytes': 1, 'sha256': 'G' * 64}, {'bytes': 1, 'sha256': 'a' * 64, 'extra': 1}]:
      with self.subTest(item=item), self.assertRaises(ValueError): profile.identity(item)
    data = enrollment()
    data['ethernet']['firmware'] = {'usr/lib/firmware/rtl_nic/../evil.fw': {'bytes': 1, 'sha256': 'a' * 64}}
    with self.assertRaises(ValueError): profile.validate(data)

  def test_ssh_privilege_and_key_readability_are_explicit(self):
    rendered = profile.render(enrollment())
    files = rendered['files']
    config = files['etc/ssh/sshd_config']['data'].decode()
    for line in ['AuthenticationMethods publickey', 'PasswordAuthentication no',
      'KbdInteractiveAuthentication no', 'PermitRootLogin prohibit-password', 'AllowUsers root shieldqual']:
      self.assertIn(line + '\n', config)
    self.assertNotIn('Include ', config)
    self.assertEqual(files['etc/ssh/authorized_keys/root']['mode'], 0o600)
    self.assertEqual(files['etc/ssh/authorized_keys/shieldqual']['mode'], 0o644)
    self.assertNotIn('etc/ssh/ssh_host_ed25519_key', files)
    self.assertEqual(rendered['private_files']['etc/ssh/ssh_host_ed25519_key']['mode'], 0o600)

  def test_normal_pid1_watchdog_and_user_session_replace_c_services(self):
    rendered = profile.render(enrollment())
    manager = rendered['files']['etc/systemd/system.conf.d/90-shield-owner.conf']['data'].decode()
    self.assertIn('RuntimeWatchdogSec=240s\n', manager)
    self.assertNotIn('RuntimeWatchdogSec=0', manager)
    self.assertIn('etc/systemd/system/shield-guardian.service', rendered['removals'])
    self.assertIn('etc/systemd/system/sshd.service', rendered['removals'])
    self.assertIn(b'Requires=shield-owner-ethernet.service\n',
      rendered['files']['etc/systemd/system/NetworkManager.service.d/10-shield-owner.conf']['data'])
    for name in ['systemd-networkd.service', 'dbus-org.freedesktop.network1.service',
                 'systemd-networkd.socket', 'systemd-networkd-varlink.socket']:
      self.assertEqual(rendered['links']['etc/systemd/system/' + name], '/dev/null')
    login = rendered['files']['home/shieldqual/.bash_profile']
    self.assertEqual((login['uid'], login['gid']), (1001, 1001))
    self.assertIn(b'-z ${SSH_CONNECTION:-}', login['data'])
    self.assertEqual(rendered['links']['etc/systemd/system/default.target'],
                     '/usr/lib/systemd/system/graphical.target')

  def test_guard_units_have_normal_recovery_and_no_healthy_lifetime(self):
    rendered = profile.render(enrollment())
    files = rendered['files']
    recovery = files['etc/systemd/system/shield-owner-recovery.service']['data']
    self.assertIn(b'FailureAction=reboot\nRebootArgument=recovery\n', recovery)
    self.assertIn(b'ExecStart=/usr/bin/false\n', recovery)
    thermal = files['etc/systemd/system/shield-owner-thermal.service']['data']
    self.assertIn(b'Type=notify\n', thermal)
    self.assertIn(b'WatchdogSec=12s\n', thermal)
    self.assertNotIn(b'RuntimeMaxSec=', thermal)
    ready = files['etc/systemd/system/shield-owner-ready.service']['data']
    self.assertIn(b'OnFailure=shield-owner-recovery.service\n', ready)
    self.assertIn(b'TimeoutStartSec=70s\n', ready)
    for unit in ['sshd.service', 'getty@tty1.service']:
      self.assertIn(b'Requires=shield-owner-thermal.service\n',
        files['etc/systemd/system/' + unit + '.d/20-shield-owner-cooling.conf']['data'])
    self.assertTrue(rendered['trial_preconditions'])
    self.assertFalse(rendered['ready_to_activate'])
    self.assertEqual(rendered['links']['etc/systemd/system/sshdgenkeys.service'], '/dev/null')

  def test_owner_retires_diagnostic_session_logging_and_stop_policy(self):
    rendered = profile.render(enrollment())
    self.assertIn('etc/systemd/journald.conf.d/90-shield-qualification.conf', rendered['removals'])
    self.assertIn('etc/systemd/system/user@1001.service.d/90-shield-qualification.conf', rendered['removals'])
    journal = rendered['files']['etc/systemd/journald.conf.d/90-shield-owner.conf']['data']
    self.assertIn(b'Storage=persistent\n', journal)
    self.assertIn(b'SystemMaxUse=256M\n', journal)
    self.assertEqual(rendered['home_seed'], {
      'source': 'usr/share/omarchy/config/hypr/hyprland.lua',
      'target': 'home/shieldqual/.config/hypr/hyprland.lua', 'mode': 0o644, 'uid': 1001, 'gid': 1001})
    self.assertEqual(rendered['home_removals'], ['home/shieldqual/.local/state/omarchy/shield-qualification.json'])
    self.assertFalse(rendered['normal_first_run_complete'])

  def test_home_mount_keeps_execution_and_normal_user_safety(self):
    lines = profile.render(enrollment())['files']['etc/fstab']['data'].decode().splitlines()
    home = next(line for line in lines if ' /home ' in line)
    self.assertIn('nosuid,nodev', home)
    self.assertNotIn('noexec', home)
    self.assertTrue(all(line.startswith('UUID=') for line in lines))
    self.assertTrue(all('mmcblk' not in line for line in lines))

  def test_owner_context_requires_exact_source_and_enrollment_binding(self):
    data = enrollment()
    self.assertEqual(profile.validate_context(context(data), data)['owner_id'], data['owner_id'])
    for field, value in [('purpose', 'systemd'), ('owner_id', 'b' * 32),
                         ('kernel_release', 'other'), ('enrollment_sha256', 'short')]:
      raw = context(data)
      raw[field] = value
      with self.subTest(field=field), self.assertRaises(ValueError): profile.validate_context(raw, data)
    raw = context(data)
    del raw['sources_sha256']['owner-ready.py']
    with self.assertRaises(ValueError): profile.validate_context(raw, data)


class OwnerEthernetSelectionTests(unittest.TestCase):
  def row(self, **changes):
    return dict(vendor='0x10ec', device='0x8168', **{'class': '0x020000'},
      onboard_controller=True, driver=None, command=0) | changes

  def test_one_observed_onboard_unbound_device_is_selected(self):
    row = self.row()
    self.assertEqual(network.choose_endpoint([row]), row)

  def test_unknown_ambiguous_or_already_bound_device_is_refused(self):
    for rows in [[], [self.row(), self.row()], [self.row(vendor='0x1234')],
      [self.row(onboard_controller=False)], [self.row(driver='r8169')],
      [self.row(command=4)], [self.row(command=True)]]:
      with self.subTest(rows=rows), self.assertRaises(ValueError): network.choose_endpoint(rows)

  def test_refusal_precedes_any_driver_effect_or_claim(self):
    with patch.object(network, 'admit', return_value=(enrollment(), 'e' * 64)), \
      patch.object(network, 'inventory', return_value=[self.row(command=4)]), \
      patch.object(network, 'load_module') as load, patch.object(network, 'save') as save:
      with self.assertRaises(ValueError): network.main()
    load.assert_not_called()
    save.assert_not_called()

  def test_expired_loader_budget_cannot_spawn_or_claim(self):
    with patch.object(network.subprocess, 'Popen') as spawned, patch.object(network, 'save') as save:
      with self.assertRaises(ValueError): network.load_module(0)
    spawned.assert_not_called()
    save.assert_not_called()

  def test_elapsed_admission_cannot_claim_or_start_the_driver(self):
    with patch.object(network, 'admit', return_value=(enrollment(), 'e' * 64)), \
      patch.object(network, 'inventory', return_value=[self.row()]), \
      patch.object(network.Path, 'exists', return_value=False), \
      patch.object(network.time, 'monotonic', side_effect=[0, 26]), \
      patch.object(network, 'load_module') as load, patch.object(network, 'save') as save:
      with self.assertRaises(ValueError): network.main()
    load.assert_not_called()
    save.assert_not_called()

  def test_existing_module_is_not_adopted(self):
    with patch.object(network, 'admit', return_value=(enrollment(), 'e' * 64)), \
      patch.object(network, 'inventory', return_value=[self.row()]), \
      patch.object(network.Path, 'exists', return_value=True), \
      patch.object(network, 'load_module') as load, patch.object(network, 'save') as save:
      with self.assertRaises(ValueError): network.main()
    load.assert_not_called()
    save.assert_not_called()

  def test_dynamic_interface_dhcp_keyfile_cannot_inject_settings(self):
    self.assertIn(b'interface-name=enp1s0\n', network.connection('enp1s0'))
    self.assertIn(b'method=auto', network.connection('eth0'))
    for name in ['lo', 'eth0\nmethod=manual', '../eth0', 'eth0=x', '', 'x' * 16]:
      with self.subTest(name=name), self.assertRaises(ValueError): network.connection(name)

  def test_json_duplicate_context_keys_are_refused(self):
    with self.assertRaises(ValueError): owner_runtime.decode(b'{"purpose":1,"purpose":2}')


class OwnerMountPurposeTests(unittest.TestCase):
  def domain(self, phase, purpose):
    value = object.__new__(native_mounts.MountDomain)
    value.bundle = SimpleNamespace(phase=phase, profile={'purpose': purpose})
    value.mounted = {native_mounts.TOP: (11, True)}
    return value

  def test_owner_entry_accepts_only_explicit_owner_purpose(self):
    domain = self.domain('owner', 'omarchy-shield-owner')
    with patch.object(domain, '_candidate_mounts', return_value=native_mounts.NEWROOT) as mounted:
      self.assertEqual(domain.owner_candidate(123), native_mounts.NEWROOT)
    mounted.assert_called_once_with(123)

  def test_c_and_owner_entries_do_not_adopt_each_others_purposes(self):
    for phase, purpose in [('systemd', 'omarchy-shield-owner'), ('owner', 'qualification')]:
      domain = self.domain(phase, purpose)
      with patch.object(domain, '_candidate_mounts') as mounted, self.assertRaises(ValueError):
        domain.owner_candidate(123)
      mounted.assert_not_called()
    domain = self.domain('owner', 'omarchy-shield-owner')
    with patch.object(domain, '_candidate_mounts') as mounted, self.assertRaises(ValueError):
      domain.candidate(123)
    mounted.assert_not_called()

  def test_owner_cannot_mount_without_completed_readonly_admission(self):
    domain = self.domain('owner', 'omarchy-shield-owner')
    domain.mounted = {}
    domain._unmount = Mock()
    with self.assertRaises(ValueError): domain.owner_candidate(123)
    domain._unmount.assert_not_called()
