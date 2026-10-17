"""Source-bound user/systemd overlay for a bounded native desktop qualification.

This module renders configuration only. It never modifies an installed root,
creates an account, mounts storage, enables a boot or claims a guardian ready.
"""
import hashlib
import json
from pathlib import Path
from usb_root_profile import digest, require, validate_manifest

USER = 'shieldqual'
UID = GID = 1001
HOME = '/home/' + USER


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
  }
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
    'masked_services': {'sddm.service': 'qualification owns tty1',
      'getty@tty1.service': 'qualification owns tty1',
      'omarchy-provision-hardware.service': 'deferred hardware leaves require separate admission',
      'power-profiles-daemon.service': 'DVFS and power policy remain unqualified',
      'udisks2.service': 'filesystem admission belongs to the qualification owner'},
    'guardian_required_before_desktop': True, 'boot_ready': False, 'physical_qualified': False,
    'source_files': {name: hashlib.sha256(value.encode()).hexdigest() for name, value in
      [('usr/share/omarchy/config/hypr/hyprland.lua', source),
       ('usr/share/omarchy/default/hypr/autostart.lua', autostart),
       ('usr/share/omarchy/default/wayland-sessions/omarchy.desktop', session)]}}
  home_files[f'{USER}/.local/state/omarchy/shield-qualification.json'] = json.dumps(policy, indent=2) + '\n'
  return {'root': root_files, 'home': home_files, 'policy': policy}
