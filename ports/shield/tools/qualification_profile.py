"""Source-bound user/systemd overlay for a bounded native desktop qualification.

This module renders configuration only. It never modifies an installed root,
creates an account, mounts storage, enables a boot or claims a guardian ready.
"""
import gzip
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from usb_root_profile import digest, require, rooted, validate_manifest

USER = 'shieldqual'
UID = GID = 1001
HOME = '/home/' + USER


# Reviewed installed policy/man inputs from the matched reference. A new base
# policy version requires one coordinated review, not guessed action aliases.
LOGIN1_POLICY = 'usr/share/polkit-1/actions/org.freedesktop.login1.policy'
SYSTEMD1_POLICY = 'usr/share/polkit-1/actions/org.freedesktop.systemd1.policy'
LOGIND_MAN = 'usr/share/man/man5/logind.conf.5.gz'
MANAGER_MAN = 'usr/share/man/man5/systemd-system.conf.5.gz'
PRIMARY_SHA256 = {
  LOGIN1_POLICY: 'b2c416657bac00b38e66d37a3c4a541bdd0000d06aabe0a5f6e94580ea4c7807',
  SYSTEMD1_POLICY: '05b867df07111f0693828fce4db65e6d14d653244952f7a598f4a4b600164d3b',
  LOGIND_MAN: 'db2f19443c24d2a7e563e15bdc4a36ef57d1e50b543f7467647f29c7a63a0051',
  MANAGER_MAN: 'a7b6f501710ecbdd1cb81c5201718f26dabeec30085b2de163f6430ebaa12aed',
}
LOGIN1_DENIED = (
  'org.freedesktop.login1.power-off',
  'org.freedesktop.login1.power-off-multiple-sessions',
  'org.freedesktop.login1.power-off-ignore-inhibit',
  'org.freedesktop.login1.reboot',
  'org.freedesktop.login1.reboot-multiple-sessions',
  'org.freedesktop.login1.reboot-ignore-inhibit',
  'org.freedesktop.login1.halt',
  'org.freedesktop.login1.halt-multiple-sessions',
  'org.freedesktop.login1.halt-ignore-inhibit',
  'org.freedesktop.login1.suspend',
  'org.freedesktop.login1.suspend-multiple-sessions',
  'org.freedesktop.login1.suspend-ignore-inhibit',
  'org.freedesktop.login1.hibernate',
  'org.freedesktop.login1.hibernate-multiple-sessions',
  'org.freedesktop.login1.hibernate-ignore-inhibit',
  'org.freedesktop.login1.manage',
  'org.freedesktop.login1.set-reboot-parameter',
  'org.freedesktop.login1.set-reboot-to-firmware-setup',
  'org.freedesktop.login1.set-reboot-to-boot-loader-menu',
  'org.freedesktop.login1.set-reboot-to-boot-loader-entry',
)
SYSTEMD1_DENIED = (
  'org.freedesktop.systemd1.manage-units',
  'org.freedesktop.systemd1.manage-unit-files',
  'org.freedesktop.systemd1.set-environment',
  'org.freedesktop.systemd1.reload-daemon',
)
LOGIND_IGNORE_KEYS = (
  'HandlePowerKey', 'HandlePowerKeyLongPress',
  'HandleRebootKey', 'HandleRebootKeyLongPress',
  'HandleSuspendKey', 'HandleSuspendKeyLongPress',
  'HandleHibernateKey', 'HandleHibernateKeyLongPress',
  'HandleLidSwitch', 'HandleLidSwitchExternalPower', 'HandleLidSwitchDocked',
  'HandleSecureAttentionKey', 'IdleAction',
)
POLKIT_PATH = 'etc/polkit-1/rules.d/00-shield-qualification.rules'
LOGIND_PATH = 'etc/systemd/logind.conf.d/90-shield-qualification.conf'


def power_policy(root):
  primary = {}
  for name, expected in PRIMARY_SHA256.items():
    path = rooted(root, name)
    require(not path.is_symlink() and path.is_file() and digest(path) == expected,
            'Power policy primary source differs: ' + name)
    primary[name] = path.read_bytes()
  for name, denied in [(LOGIN1_POLICY, LOGIN1_DENIED), (SYSTEMD1_POLICY, SYSTEMD1_DENIED)]:
    actions = [node.attrib['id'] for node in ET.fromstring(primary[name]).findall('action')]
    require(len(actions) == len(set(actions)) and set(denied).issubset(actions),
            'Installed privileged action catalog differs')
  logind = gzip.decompress(primary[LOGIND_MAN]).decode('utf-8')
  manager = gzip.decompress(primary[MANAGER_MAN]).decode('utf-8')
  require(all(key + '=' in logind for key in LOGIND_IGNORE_KEYS) and
          'CtrlAltDelBurstAction=' in manager and '"none"' in manager,
          'Installed systemd power configuration keys differ')
  # A literal action switch and user guard avoid granting anything to root or
  # to another subject. Unrelated actions fall through to the installed policy.
  rule = ('// Bounded qualification only; root recovery uses its owned syscall path.\n'
          'polkit.addRule(function(action, subject) {\n'
          '  if (subject.user !== "shieldqual") { return; }\n'
          '  switch (action.id) {\n')
  rule += ''.join('    case ' + json.dumps(action) + ':\n' for action in LOGIN1_DENIED + SYSTEMD1_DENIED)
  rule += ('      return polkit.Result.NO;\n'
           '    default: return;\n'
           '  }\n'
           '});\n')
  return {POLKIT_PATH: rule, LOGIND_PATH: '[Login]\n' +
          ''.join(key + '=ignore\n' for key in LOGIND_IGNORE_KEYS)}


def account_plan():
  return {'name': USER, 'uid': UID, 'gid': GID, 'home': HOME, 'shell': '/bin/bash',
    'supplementary_groups': ['video', 'render', 'audio', 'input'],
    'password_locked': True, 'administrative': False, 'physical_tty_autologin': 'tty1'}


def admitted_text(root, manifest, name):
  item = manifest['root_files'][name]
  path = Path(root) / name
  require(item['type'] == 'file' and not path.is_symlink() and digest(path) == item['sha256'],
          'Qualification source differs: ' + name)
  return path.read_text()


def render(root, manifest):
  validate_manifest(manifest)
  power_files = power_policy(root)
  source = admitted_text(root, manifest, 'usr/share/omarchy/config/hypr/hyprland.lua')
  autostart = admitted_text(root, manifest, 'usr/share/omarchy/default/hypr/autostart.lua')
  session = admitted_text(root, manifest, 'usr/share/omarchy/default/wayland-sessions/omarchy.desktop')
  command = 'uwsm start -g -1 -e -D Hyprland hyprland.desktop'
  require(('Exec=' + command + '\n') in session, 'Unreviewed UWSM session command')
  marker = 'require("default.hypr.omarchy")'
  require(source.count(marker) == 1, 'Unreviewed Omarchy Hyprland bootstrap')
  require('omarchy-provision-first-run' in autostart and 'udiskie --automount' in autostart,
          'Review changed default autostart before rendering the qualification profile')
  override = '''-- Bounded qualification: preserve normal Omarchy config and bindings while
-- replacing only startup orchestration. Online enrollment, automounts, power
-- tuning and owner hooks remain pending; no first-run done marker is written.
package.loaded["default.hypr.autostart"] = true
'''
  hyprland = source.replace(marker, override + marker)
  hyprland += '''
-- Normal UWSM/logind session; real Omarchy shell and a terminal for this run.
hl.on("hyprland.start", function()
  if omarchy_startup_cursor_pending then
    hl.env("XCURSOR_PATH", omarchy_startup_cursor.path)
    hl.env("XCURSOR_THEME", omarchy_startup_cursor.xcursor)
  end
  hl.exec_cmd("systemctl --user import-environment $(env | cut -d'=' -f 1)")
  hl.exec_cmd("dbus-update-activation-environment --systemd --all")
  hl.exec_cmd("omarchy-launch-shell")
  hl.exec_cmd(o.launch("omarchy-hyprland-monitor-watch"))
  hl.exec_cmd("foot")
end)
'''
  root_files = {
    'usr/share/wayland-sessions/omarchy.desktop': session,
    'etc/fstab': ''.join(f"UUID={manifest['filesystem_uuid']} {mount} btrfs rw,noatime,compress=zstd:1,subvol={manifest['subvolumes'][purpose]} 0 0\n"
      for purpose, mount in [('root', '/'), ('home', '/home'), ('log', '/var/log')]),
    'etc/systemd/system.conf.d/90-shield-qualification.conf': '''[Manager]
RuntimeWatchdogSec=0
RebootWatchdogSec=0
KExecWatchdogSec=0
CtrlAltDelBurstAction=none
DefaultTimeoutStopSec=5s
''',
    'etc/systemd/journald.conf.d/90-shield-qualification.conf': '''[Journal]
Storage=volatile
RuntimeMaxUse=32M
ForwardToKMsg=no
''',
    f'etc/systemd/system/user@{UID}.service.d/90-shield-qualification.conf': '''[Service]
TimeoutStopSec=5s
KillMode=control-group
''',
    'etc/systemd/system/shield-qualification-desktop.service': f'''[Unit]
Description=Bounded SHIELD Omarchy PAM and UWSM desktop
Requires=shield-guardian.service systemd-logind.service systemd-user-sessions.service
BindsTo=shield-guardian.service
After=shield-guardian.service systemd-logind.service systemd-user-sessions.service
Conflicts=getty@tty1.service sddm.service
Before=shield-qualification.target

[Service]
Type=idle
ExecStart=/usr/bin/agetty --noreset --noclear --autologin {USER} tty1 linux
Restart=no
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
SendSIGHUP=yes
KillMode=control-group
TimeoutStopSec=5s
''',
    'etc/systemd/system/shield-guardian.service': '''[Unit]
Description=Finite SHIELD watchdog and cooling guardian
DefaultDependencies=no
Requires=shield-qualification-recovery.service
After=systemd-udev-trigger.service shield-qualification-recovery.service
Before=shield-qualification-desktop.service
IgnoreOnIsolate=yes
RefuseManualStop=yes
AssertFileNotEmpty=/usr/lib/omarchy/shield/qualification/profile.json

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/lib/omarchy/shield/qualification/shield-guardian --run
RuntimeDirectory=shield-guardian
RuntimeDirectoryMode=0700
Restart=no
TimeoutStartSec=infinity
TimeoutStopSec=infinity
SendSIGKILL=no
KillMode=process
OOMScoreAdjust=-1000
''',
    'etc/systemd/system/shield-qualification-recovery.service': '''[Unit]
Description=Owned SHIELD qualification cleanup and recovery receiver
DefaultDependencies=no
Requires=local-fs.target
After=local-fs.target systemd-udev-trigger.service
Before=shield-guardian.service
IgnoreOnIsolate=yes
RefuseManualStop=yes
AssertFileNotEmpty=/usr/lib/omarchy/shield/qualification/profile.json

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/bin/python3 -I -B /usr/lib/omarchy/shield/qualification/qualification_recovery.py
RuntimeDirectory=shield-recovery
RuntimeDirectoryMode=0700
Restart=no
TimeoutStartSec=infinity
TimeoutStopSec=infinity
SendSIGKILL=no
KillMode=process
OOMScoreAdjust=-900
''',
    'etc/systemd/system/shield-qualification.target': '''[Unit]
Description=Bounded native SHIELD Omarchy qualification
Requires=basic.target shield-qualification-recovery.service shield-guardian.service shield-qualification-desktop.service
After=basic.target shield-guardian.service shield-qualification-desktop.service
AllowIsolate=yes
''',
  }
  root_files.update(power_files)
  home_files = {
    f'{USER}/.config/hypr/hyprland.lua': hyprland,
    f'{USER}/.config/hypr/monitors.lua': '''-- Previously exercised native display mode; wider modes remain unqualified.
hl.monitor({ output = "HDMI-A-1", mode = "1280x720@60", position = "0x0", scale = 1 })
hl.env("GDK_SCALE", "1")
''',
    f'{USER}/.bash_profile': f'''# Qualification console only; SSH/other TTY shells do not start a compositor.
[[ -f ~/.bashrc ]] && source ~/.bashrc
if [[ $(tty) == /dev/tty1 && -z ${{SSH_CONNECTION:-}} && -z ${{WAYLAND_DISPLAY:-}} ]]; then
  exec {command}
fi
''',
  }
  policy = {'format_version': 1, 'purpose': 'bounded native systemd Omarchy qualification',
    'payload_candidate_id': manifest['candidate_id'], 'account': account_plan(),
    'normal_first_run_complete': False,
    'deferred_actions': ['online first-run provisioning and tool installation', 'automatic storage mounting',
                         'power-profile initialization', 'owner post-boot hooks'],
    'masked_services': {'ctrl-alt-del.target': 'qualification recovery owns restart requests',
      'sddm.service': 'qualification owns tty1',
      'getty@tty1.service': 'qualification owns tty1',
      'omarchy-provision-hardware.service': 'deferred hardware leaves require separate admission',
      'power-profiles-daemon.service': 'DVFS and power policy remain unqualified',
      'udisks2.service': 'filesystem admission belongs to the qualification owner',
      'ssh.service': 'qualification has no remote login enrollment',
      'sshd.service': 'qualification has no remote login enrollment',
      'sleep.target': 'sleep and wake remain separately unqualified',
      'systemd-suspend.service': 'sleep and wake remain separately unqualified',
      'systemd-hibernate.service': 'sleep and wake remain separately unqualified',
      'systemd-hybrid-sleep.service': 'sleep and wake remain separately unqualified',
      'systemd-suspend-then-hibernate.service': 'sleep and wake remain separately unqualified'},
    'user_power_policy': {'subject_user': USER, 'denied_actions': list(LOGIN1_DENIED + SYSTEMD1_DENIED),
      'unrelated_subjects_and_actions': 'fall through', 'logind_ignored_keys': list(LOGIND_IGNORE_KEYS),
      'ctrl_alt_del_burst_action': 'none', 'native_effective_policy_verified': False},
    'guardian_required_before_desktop': True, 'boot_ready': False, 'physical_qualified': False,
    'source_files': {name: hashlib.sha256(value.encode()).hexdigest() for name, value in
      [('usr/share/omarchy/config/hypr/hyprland.lua', source),
       ('usr/share/omarchy/default/hypr/autostart.lua', autostart),
       ('usr/share/omarchy/default/wayland-sessions/omarchy.desktop', session)]},
    'power_policy_primary_sources': dict(PRIMARY_SHA256)}
  home_files[f'{USER}/.local/state/omarchy/shield-qualification.json'] = json.dumps(policy, indent=2) + '\n'
  return {'root': root_files, 'home': home_files, 'policy': policy}
