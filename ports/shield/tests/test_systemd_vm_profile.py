"""VM identity cannot authorize another kernel, root layout or source closure."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools'))
from guardian_binding import IMAGE_SHA256
from systemd_vm_profile import MARKER, PURPOSE, SOURCES, validate_identity


class SystemdVmProfileTests(unittest.TestCase):
  def identity(self):
    root = '@shield-' + '1' * 32
    return {'format_version': 1, 'purpose': PURPOSE, 'marker': MARKER,
      'kernel': {'release': '7.1.0-shield-bringup', 'sha256': IMAGE_SHA256},
      'filesystem': {'uuid': '11111111-1111-4111-8111-111111111111',
        'subvolumes': {'root': root, 'home': root + '-home', 'log': root + '-log'}},
      'payload_manifest_sha256': '2' * 64, 'prepared_receipt_sha256': '3' * 64,
      'installation_receipt_sha256': '4' * 64, 'native_profile_sha256': '5' * 64,
      'sources': {name: '6' * 64 for name in SOURCES},
      'uid_probe': {'sha256': '7' * 64, 'bytes': 1000}}

  def test_exact_isolated_identity(self):
    value = self.identity()
    self.assertIs(validate_identity(value), value)

  def test_native_marker_or_unknown_kernel_cannot_be_a_vm_alias(self):
    for field, value in [('marker', 'shield.first-ram-probe=1'), ('purpose', 'native'),
                         ('kernel', {'release': '7.1.0-shield-bringup', 'sha256': '8' * 64})]:
      data = self.identity(); data[field] = value
      with self.subTest(field=field), self.assertRaises(ValueError): validate_identity(data)

  def test_old_default_or_mixed_subvolume_root_is_rejected(self):
    for names in [{'root': '@', 'home': '@home', 'log': '@log'},
                  {**self.identity()['filesystem']['subvolumes'], 'home': '@other'}]:
      value = self.identity(); value['filesystem']['subvolumes'] = names
      with self.assertRaises(ValueError): validate_identity(value)

  def test_missing_handoff_or_extra_source_is_rejected(self):
    for remove in [True, False]:
      value = self.identity()
      if remove: del value['sources']['qualification/vm-switch-root.c']
      else: value['sources']['../outside'] = '6' * 64
      with self.assertRaises(ValueError): validate_identity(value)

  def test_missing_receipt_or_zero_digest_is_rejected(self):
    value = self.identity(); del value['installation_receipt_sha256']
    with self.assertRaises(ValueError): validate_identity(value)
    value = self.identity(); value['native_profile_sha256'] = '0' * 64
    with self.assertRaises(ValueError): validate_identity(value)

  def test_boolean_format_or_probe_size_is_rejected(self):
    value = self.identity(); value['format_version'] = True
    with self.assertRaises(ValueError): validate_identity(value)
    value = self.identity(); value['uid_probe']['bytes'] = True
    with self.assertRaises(ValueError): validate_identity(value)

# Exercise the actual host result consumer against missing or overclaimed data.
import importlib.util
SPEC = importlib.util.spec_from_file_location('systemd_vm_runner_source',
  Path(__file__).resolve().parent.parent / 'tools/run-systemd-vm.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
from qualification_profile import DENIED_ACTIONS


class SystemdVmResultTests(unittest.TestCase):
  def result(self):
    checks = {name: {'passed': True} for name in ['boot_mount_admission',
      'actual_package_module_loader_payload', 'emulated_kms_seat_prerequisite', 'installed_software_policy',
      'native_fail_closed', 'root_sudo_policy', 'session_setuid_power']}
    checks['manager'] = {'RuntimeWatchdogUSec': '0', 'RebootWatchdogUSec': '0',
      'KExecWatchdogUSec': '0', 'CtrlAltDelBurstAction': 'none'}
    checks['boot_mount_admission'].update(runtime_compression='zstd:1', emulated_NOR_only=True)
    checks['emulated_kms_seat_prerequisite'].update(version_1_negotiated=True,
      gpu_transport_link_verified=True, renderer_qualified=False)
    checks['native_fail_closed'].update(native_READY=False, native_desktop_started=False)
    checks['root_sudo_policy'].update(negative_only=True, true_query_denied=True)
    checks['session_setuid_power'].update(actual_session={'Active': 'yes', 'Remote': 'no',
      'Seat': 'seat0', 'Type': 'tty'}, peer_starttime_verified=True,
      actual_policy_denials=[{'action': name, 'returncode': 1, 'explicit_no': True,
        'output': r'polkit\56result=no' + '\nNot authorized.\n'} for name in DENIED_ACTIONS],
      user_probe={'passed': True, 'checks': {name: {'passed': True} for name in ['setuid',
        'sudo_root_true_blocked_without_authentication', 'user_bus', 'login1_poweroff', 'login1_reboot',
        'systemd_reboot_target', 'systemd_poweroff_target']}})
    user = checks['session_setuid_power']['user_probe']['checks']
    user['sudo_root_true_blocked_without_authentication'].update(authentication_barrier_observed=True,
      authorization_denial_observed_in_user_execution=False, returncode=1, output='sudo: a password is required\n')
    user['setuid']['record'] = {'euid_before': 0, 'euid_after': 1001, 'root_regain_denied': True, 'nnp_after': 1}
    return {'format_version': 1, 'scope': PURPOSE, 'passed': True, 'checks': checks,
      **{name: False for name in ['native_guardian_admitted', 'Shield_native_qualified',
        'hardware_or_performance_qualified', 'graphics_qualified', 'boot_ready']}}

  def test_complete_scoped_result_can_be_consumed(self):
    self.assertTrue(RUNNER.guest_accepted(self.result()))

  def test_generic_pass_does_not_replace_actual_checks(self):
    self.assertFalse(RUNNER.guest_accepted({'passed': True}))
    result = self.result(); del result['checks']['actual_package_module_loader_payload']
    self.assertFalse(RUNNER.guest_accepted(result))

  def test_missing_mount_or_flash_admission_is_not_a_positive_boot(self):
    for key, value in [('runtime_compression', 'none'), ('emulated_NOR_only', False)]:
      result = self.result(); result['checks']['boot_mount_admission'][key] = value
      self.assertFalse(RUNNER.guest_accepted(result))

  def test_missing_modern_card_link_or_rendering_overclaim_is_rejected(self):
    for key, value in [('version_1_negotiated', False), ('gpu_transport_link_verified', False),
                       ('renderer_qualified', True)]:
      result = self.result(); result['checks']['emulated_kms_seat_prerequisite'][key] = value
      self.assertFalse(RUNNER.guest_accepted(result))

  def test_vm_cannot_claim_native_graphics_or_hardware_parity(self):
    for name in ['native_guardian_admitted', 'Shield_native_qualified', 'graphics_qualified', 'boot_ready']:
      result = self.result(); result[name] = True
      self.assertFalse(RUNNER.guest_accepted(result))

  def test_inactive_or_remote_session_is_not_power_denial_evidence(self):
    for key, value in [('Active', 'no'), ('Remote', 'yes'), ('Seat', '')]:
      result = self.result(); result['checks']['session_setuid_power']['actual_session'][key] = value
      self.assertFalse(RUNNER.guest_accepted(result))

  def test_missing_action_or_boolean_exit_is_not_actual_denial(self):
    result = self.result(); result['checks']['session_setuid_power']['actual_policy_denials'].pop()
    self.assertFalse(RUNNER.guest_accepted(result))
    result = self.result(); result['checks']['session_setuid_power']['actual_policy_denials'][0]['returncode'] = True
    self.assertFalse(RUNNER.guest_accepted(result))

  def test_authentication_barrier_requires_independent_policy_and_setuid_proofs(self):
    for field in ['negative_only', 'true_query_denied']:
      result = self.result(); result['checks']['root_sudo_policy'][field] = False
      self.assertFalse(RUNNER.guest_accepted(result))
    result = self.result(); result['checks']['session_setuid_power']['user_probe']['checks']['setuid']['record']['euid_before'] = 1001
    self.assertFalse(RUNNER.guest_accepted(result))
    result = self.result(); result['checks']['session_setuid_power']['user_probe']['checks']['setuid']['record']['nnp_after'] = True
    self.assertFalse(RUNNER.guest_accepted(result))
    result = self.result()
    result['checks']['session_setuid_power']['user_probe']['checks']['sudo_root_true_blocked_without_authentication']['authorization_denial_observed_in_user_execution'] = True
    self.assertFalse(RUNNER.guest_accepted(result))

  def test_polkit_fallback_metadata_is_not_an_explicit_no(self):
    result = self.result()
    result['checks']['session_setuid_power']['actual_policy_denials'][-1]['output'] = 'polkit\\56result=auth_admin_keep\nNot authorized.\n'
    self.assertFalse(RUNNER.guest_accepted(result))


class SystemdVmDecisionEvidenceTests(unittest.TestCase):
  def module(self, filename):
    path = Path(__file__).resolve().parent.parent / filename
    spec = importlib.util.spec_from_file_location('fixed_probe_predicate_' + path.stem, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

  def test_polkit_no_rejects_shared_challenge_metadata_and_trailing_output(self):
    guest = self.module('tools/systemd-vm-guest.py')
    no = r'polkit\56result=no' + '\nNot authorized.\n'
    self.assertTrue(guest.explicit_polkit_no({'returncode': 1, 'output': no}))
    for code, output in [(True, no), (2, no), (1, 'Not authorized.\n'),
                         (1, no + 'polkit\\56result=auth_admin_keep\n'), (1, no + 'x' * 32768)]:
      with self.subTest(code=code, length=len(output)):
        self.assertFalse(guest.explicit_polkit_no({'returncode': code, 'output': output}))

  def test_sudo_authentication_barrier_is_not_an_authorization_or_setuid_failure(self):
    user = self.module('qualification/vm-user-probe.py')
    self.assertTrue(user.authentication_barrier({'returncode': 1, 'output': 'sudo: a password is required\n'}))
    for code, output in [(True, 'sudo: a password is required\n'), (0, ''),
                         (1, 'sudo: effective uid is not 0\n'), (1, 'Permission denied\n')]:
      with self.subTest(code=code, output=output):
        self.assertFalse(user.authentication_barrier({'returncode': code, 'output': output}))


class SystemdVmInitramfsTests(unittest.TestCase):
  def fixture(self):
    import gzip, hashlib, json, stat, tempfile
    from stock_boot import write_newc
    directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
    root = Path(directory.name)
    busybox = b'explicit synthetic BusyBox fixture, never executed'
    data = gzip.compress(write_newc({
      'bin/busybox': {'mode': stat.S_IFREG | 0o755, 'data': busybox},
      'old-native-payload': {'mode': stat.S_IFREG | 0o700, 'data': b'never inherit'}}), mtime=0)
    (root / 'initramfs.cpio.gz').write_bytes(data)
    (root / 'manifest.json').write_text(json.dumps({'artifacts': {'initramfs.cpio.gz':
      {'sha256': hashlib.sha256(data).hexdigest()}}}))
    spec = importlib.util.spec_from_file_location('systemd_vm_builder_source',
      Path(__file__).resolve().parent.parent / 'tools/prepare-systemd-vm.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return root, module, hashlib.sha256(busybox).hexdigest()

  def test_minimal_cpio_uses_fixed_handoff_not_missing_busybox_applet(self):
    import gzip
    from unittest.mock import patch
    from stock_boot import read_newc
    root, builder, expected = self.fixture()
    with patch.object(builder, 'BUSYBOX_SHA256', expected):
      result = builder.make_initramfs(root, SystemdVmProfileTests().identity()['filesystem'], b'synthetic handoff')
    entries = read_newc(gzip.decompress(result))
    self.assertIn('bin/vm-switch-root', entries)
    self.assertNotIn('bin/switch_root', entries)
    self.assertNotIn('old-native-payload', entries)
    self.assertIn(b'exec /bin/vm-switch-root', entries['init']['data'])
    self.assertNotIn(b'mount --move', entries['init']['data'])
    self.assertIn(b'sleep 1', entries['init']['data'])
    self.assertNotIn(b'sleep 0.1', entries['init']['data'])
    self.assertEqual(entries['dev/console']['rdevmajor'], 5)
    self.assertEqual(entries['dev/console']['rdevminor'], 1)

  def test_changed_cpio_or_unreviewed_busybox_bytes_are_rejected(self):
    root, builder, _expected = self.fixture()
    with self.assertRaises(ValueError):
      builder.make_initramfs(root, SystemdVmProfileTests().identity()['filesystem'], b'handoff')
    (root / 'initramfs.cpio.gz').write_bytes(b'changed')
    with self.assertRaises(ValueError):
      builder.make_initramfs(root, SystemdVmProfileTests().identity()['filesystem'], b'handoff')


class SystemdVmDirectoryTests(unittest.TestCase):
  def setUp(self):
    import tempfile
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.root = Path(self.temporary.name)
    spec = importlib.util.spec_from_file_location('systemd_vm_directory_builder',
      Path(__file__).resolve().parent.parent / 'tools/prepare-systemd-vm.py')
    self.builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(self.builder)

  def test_guest_directory_modes_survive_private_host_umask(self):
    import os, stat
    for mask in [0o077, 0o022]:
      for mode in [0o700, 0o755]:
        path = self.root / ('directory-%o-%o' % (mask, mode))
        previous = os.umask(mask)
        try:
          self.assertEqual(self.builder.new_directory(path, mode), path)
        finally:
          os.umask(previous)
        self.assertTrue(path.is_dir())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

  def test_existing_directory_or_alias_is_not_repaired(self):
    import stat
    target = self.root / 'existing'
    target.mkdir(mode=0o700)
    alias = self.root / 'alias'; alias.symlink_to(target)
    for path in [target, alias]:
      with self.assertRaises(FileExistsError): self.builder.new_directory(path, 0o755)
    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
    self.assertTrue(alias.is_symlink())


if __name__ == '__main__':
  unittest.main()
