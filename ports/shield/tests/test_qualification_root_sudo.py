"""Pure sudo authorization-output admission; no subprocess, account or root IO."""
import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parent.parent / 'tools'
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location('qualification_root_sudo_source', TOOLS / 'prepare-qualification-root.py')
PREPARER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARER)

# Actual admitted C-locale dialect, with a synthetic non-private host name.
NEGATIVE_ONLY = b'''Matching Defaults entries for shieldqual on shield-host:
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/bin, passwd_tries=10

Runas and Command-specific defaults for shieldqual:
    Defaults!/usr/bin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User shieldqual may run the following commands on shield-host:
    (ALL) !/usr/bin/asdcontrol
'''


class QualificationRootSudoTests(unittest.TestCase):
  def test_successful_listing_with_only_canonical_negative_rule_is_not_a_grant(self):
    PREPARER.admit_sudo_diagnostic('listing', 0, NEGATIVE_ONLY)

  def test_any_positive_command_grant_is_rejected(self):
    for grant in [b'(ALL) ALL', b'(root) NOPASSWD: /usr/bin/true',
                  b'(ALL) /usr/bin/asdcontrol', b'(ALL) !/usr/bin/asdcontrol, ALL']:
      with self.subTest(grant=grant):
        output = NEGATIVE_ONLY.replace(b'(ALL) !/usr/bin/asdcontrol', grant)
        with self.assertRaises(ValueError):
          PREPARER.admit_sudo_diagnostic('listing', 0, output)

  def test_negative_entry_cannot_hide_an_additional_grant(self):
    with self.assertRaises(ValueError):
      PREPARER.admit_sudo_diagnostic('listing', 0, NEGATIVE_ONLY + b'    (root) /usr/bin/true\n')

  def test_user_host_defaults_and_runas_changes_require_review(self):
    for before, after in [(b'User shieldqual', b'User portbuild'),
                          (b'on shield-host:\n    (ALL)', b'on other-host:\n    (ALL)'),
                          (b'passwd_tries=10', b'passwd_tries=10, !authenticate'),
                          (b'(ALL) !', b'(root) !')]:
      with self.subTest(after=after), self.assertRaises(ValueError):
        PREPARER.admit_sudo_diagnostic('listing', 0, NEGATIVE_ONLY.replace(before, after))

  def test_policy_query_requires_nonzero_denial_without_diagnostic_errors(self):
    PREPARER.admit_sudo_diagnostic('true-policy', 1, b'')
    for code, output in [(0, b''), (1, b'sudo: unable to initialize policy plugin\n'),
                         (127, b''), (-9, b''), (True, b'')]:
      with self.subTest(code=code, output=output), self.assertRaises(ValueError):
        PREPARER.admit_sudo_diagnostic('true-policy', code, output)

  def test_listing_errors_do_not_count_as_policy_denial(self):
    for code, output in [(1, NEGATIVE_ONLY), (1, b'User shieldqual is not allowed to run sudo\n'),
                         (0, b'sudo: a password is required\n'),
                         (1, b'sudo: account validation failure\n')]:
      with self.subTest(code=code), self.assertRaises(ValueError):
        PREPARER.admit_sudo_diagnostic('listing', code, output)

  def test_warnings_binary_controls_or_truncation_are_refused(self):
    for output in [b'sudo: parse error\n' + NEGATIVE_ONLY,
                   NEGATIVE_ONLY + b'\x00', NEGATIVE_ONLY + b'\x1b[0m',
                   NEGATIVE_ONLY + b'\xff', b'x' * 32769]:
      with self.subTest(prefix=output[:20]), self.assertRaises(ValueError):
        PREPARER.admit_sudo_diagnostic('listing', 0, output)

  def test_qemu_setuid_failure_is_not_native_authorization_proof(self):
    output = b"sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set?\n"
    for kind in ['listing', 'true-policy', 'user-exec']:
      with self.subTest(kind=kind), self.assertRaises(ValueError):
        PREPARER.admit_sudo_diagnostic(kind, 1, output)

  def test_unknown_diagnostic_operations_are_rejected(self):
    with self.assertRaises(ValueError):
      PREPARER.admit_sudo_diagnostic('skip-checks', 0, NEGATIVE_ONLY)


if __name__ == '__main__':
  unittest.main()
