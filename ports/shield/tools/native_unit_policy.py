"""Single producer/consumer contract for native RAM systemd additions.

The real-root receiver retains its existing cleanup lifetime if USB control
fails. Wants+After orders startup; its held-connection admission supplies the
mandatory readiness gate. BindsTo/Requires on the control service would stop the
receiver on transport failure precisely when filesystem cleanup is needed.
"""
from pathlib import Path
import os
import stat
import re
import subprocess

from native_boot_context import POLICY_PATHS, RUNTIME, UDEV_PATH, STARTUP_SCRIPT, CLEANUP_SCRIPT, owned_bytes
from usb_root_profile import require

CONTROL_UNIT = 'shield-native-control.service'
RECEIVER_UNIT = 'shield-qualification-recovery.service'
CONTROL_PATH = 'run/systemd/system/' + CONTROL_UNIT
DROPIN_PATH = 'run/systemd/system/' + RECEIVER_UNIT + '.d/10-native-control.conf'

STARTUP_HELPER = r'''#!/usr/bin/bash
# Fixed diagnostic summaries only. Never a control, cleanup or watchdog owner.
startup_units=(shield-native-control.service shield-qualification-recovery.service
  shield-guardian.service shield-qualification-desktop.service local-fs.target
  sysinit.target basic.target home.mount var-log.mount swap.target dev-zram0.device
  systemd-zram-setup@zram0.service systemd-udev-trigger.service systemd-udevd.service
  systemd-journald.service plymouth-start.service)

startup_normalize() {
  local startup_key=$1 startup_value=$2 startup_known
  case $startup_key in
    Id)
      for startup_known in "${startup_units[@]}"; do
        if [[ $startup_value == "$startup_known" ]]; then printf '%s' "$startup_known"; return; fi
      done
      printf 'unknown'
      ;;
    LoadState)
      case $startup_value in stub|loaded|not-found|bad-setting|error|merged|masked) printf '%s' "$startup_value";; *) printf 'invalid';; esac
      ;;
    ActiveState)
      case $startup_value in active|reloading|inactive|failed|activating|deactivating|maintenance|refreshing) printf '%s' "$startup_value";; *) printf 'invalid';; esac
      ;;
    SubState)
      case $startup_value in dead|condition|start-pre|start|start-post|running|exited|reload|reload-signal|reload-notify|stop|stop-watchdog|stop-sigterm|stop-sigkill|stop-post|final-watchdog|final-sigterm|final-sigkill|failed|dead-before-auto-restart|failed-before-auto-restart|auto-restart|auto-restart-queued|cleaning|waiting|elapsed|plugged|tentative|mounted|mounting|mounting-done|remounting|remounting-sigterm|remounting-sigkill|unmounting|unmounting-sigterm|unmounting-sigkill|mounting-sigterm|mounting-sigkill|listening|active|inactive) printf '%s' "$startup_value";; *) printf 'invalid';; esac
      ;;
    Result)
      case $startup_value in success|resources|protocol|timeout|exit-code|signal|core-dump|watchdog|start-limit-hit|oom-kill|skip-condition|exec-condition) printf '%s' "$startup_value";; '') printf 'unavailable';; *) printf 'invalid';; esac
      ;;
    MainPID)
      if [[ $startup_value == 0 ]]; then printf 'absent'
      elif [[ $startup_value =~ ^[1-9][0-9]{0,9}$ ]]; then printf 'present'
      else printf 'invalid'; fi
      ;;
    Job)
      if [[ -z $startup_value || $startup_value == 0 ]]; then printf 'none'
      elif [[ $startup_value =~ ^[1-9][0-9]{0,9}([[:space:]]/org/freedesktop/systemd1/job/[0-9]{1,10})?$ ]]; then printf 'pending'
      else printf 'invalid'; fi
      ;;
    ExecMainCode|ExecMainStatus)
      if [[ $startup_value =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( startup_value <= 255 )); then printf '%s' "$startup_value"
      else printf 'invalid'; fi
      ;;
    FragmentPath)
      case $startup_value in '') printf 'none';; /run/systemd/system/*) printf 'ram';; /etc/systemd/system/*) printf 'etc';; /usr/lib/systemd/system/*) printf 'usr';; /run/systemd/generator/*|/run/systemd/generator.early/*|/run/systemd/generator.late/*) printf 'generated';; *) printf 'other';; esac
      ;;
    DropInPaths)
      if [[ -z $startup_value ]]; then printf 'none'; return; fi
      local -a startup_tokens=()
      local startup_token
      IFS=$' \t' read -r -a startup_tokens <<< "$startup_value"
      for startup_token in "${startup_tokens[@]}"; do
        if [[ $startup_token == /run/systemd/system/shield-qualification-recovery.service.d/10-native-control.conf ]]; then
          printf 'owned-receiver-present'; return
        fi
      done
      printf 'other-present'
      ;;
    *) printf 'invalid';;
  esac
}

startup_summarize() {
  local startup_line startup_key startup_value startup_normalized startup_lines=0 startup_groups=0 startup_entries=0
  local -A startup_fields=()
  startup_flush() {
    if (( startup_entries == 0 )); then return 0; fi
    startup_groups=$((startup_groups + 1))
    if (( startup_groups > 20 )); then printf 'probe=group-cap\n'; return 2; fi
    if [[ ${startup_fields[Id]-unknown} == unknown ]]; then printf 'probe=unknown-unit\n'; return 0; fi
    printf 'unit=%s load=%s active=%s sub=%s result=%s job=%s pid=%s exec-code=%s exec-status=%s fragment=%s dropins=%s\n' \
      "${startup_fields[Id]}" "${startup_fields[LoadState]-unavailable}" \
      "${startup_fields[ActiveState]-unavailable}" "${startup_fields[SubState]-unavailable}" \
      "${startup_fields[Result]-unavailable}" "${startup_fields[Job]-unavailable}" \
      "${startup_fields[MainPID]-unavailable}" "${startup_fields[ExecMainCode]-unavailable}" \
      "${startup_fields[ExecMainStatus]-unavailable}" "${startup_fields[FragmentPath]-unavailable}" \
      "${startup_fields[DropInPaths]-unavailable}"
  }
  while IFS= read -r -n 513 startup_line || [[ -n $startup_line ]]; do
    startup_lines=$((startup_lines + 1))
    if (( startup_lines > 256 )); then printf 'probe=line-count-cap\n'; return 2; fi
    if (( ${#startup_line} > 512 )); then printf 'probe=line-size-cap\n'; return 2; fi
    if [[ -z $startup_line ]]; then
      startup_flush || return $?
      startup_fields=()
      startup_entries=0
      continue
    fi
    [[ $startup_line == *=* ]] || continue
    startup_key=${startup_line%%=*}
    startup_value=${startup_line#*=}
    case $startup_key in Id|LoadState|ActiveState|SubState|Result|Job|MainPID|ExecMainCode|ExecMainStatus|FragmentPath|DropInPaths) ;; *) continue;; esac
    if [[ -v startup_fields[$startup_key] ]]; then printf 'probe=duplicate-field\n'; return 2; fi
    startup_normalized=$(startup_normalize "$startup_key" "$startup_value")
    startup_fields[$startup_key]=$startup_normalized
    startup_entries=$((startup_entries + 1))
  done
  startup_flush
}

startup_main() {
  [[ $# == 1 && ( $1 == 45 || $1 == 90 ) ]] || return 64
  [[ $UID == 0 && $EUID == 0 && $PPID == 1 ]] || return 64
  [[ $(/usr/bin/uname -m) == aarch64 && $(/usr/bin/uname -r) == 7.1.0-shield-bringup ]] || return 64
  local startup_comm startup_cmdline startup_phase=$1 startup_uptime startup_unused
  IFS= read -r startup_comm < /proc/1/comm
  [[ $startup_comm == systemd ]] || return 64
  IFS= read -r startup_cmdline < /proc/cmdline
  case " $startup_cmdline " in *' shield.first-ram-probe=1 '*) ;; *) return 64;; esac
  case " $startup_cmdline " in *' systemd.unit=shield-qualification.target '*) ;; *) return 64;; esac
  [[ -c /dev/kmsg && ! -L /dev/kmsg ]] || return 64
  local startup_meta startup_uid startup_gid startup_mode startup_major startup_minor
  startup_meta=$(/usr/bin/timeout --signal=TERM --kill-after=1s 1s /usr/bin/stat -Lc '%u %g %a %t %T' -- /dev/kmsg 2>/dev/null) || return 65
  [[ ${#startup_meta} -le 64 ]] || return 65
  read -r startup_uid startup_gid startup_mode startup_major startup_minor <<< "$startup_meta"
  [[ $startup_uid == 0 && $startup_gid =~ ^[0-9]{1,10}$ && $startup_mode =~ ^[0-7]{3,4}$ && $startup_major == 1 && $startup_minor == b ]] || return 65
  (( (8#$startup_mode & 8#22) == 0 )) || return 65
  startup_emit() {
    local startup_record=$1
    [[ ${#startup_record} -le 512 && $startup_record != *$'\n'* ]] || return 65
    # Each small record uses a fresh open, not a shared journal stream limit.
    printf '<3>shield-startup phase=%s %s\n' "$startup_phase" "$startup_record" > /dev/kmsg
  }
  read -r startup_uptime startup_unused < /proc/uptime
  [[ $startup_uptime =~ ^[0-9]{1,8}\.[0-9]{1,3}$ ]] || return 65
  startup_emit "begin uptime=$startup_uptime"
  startup_emit "kmsg uid=$startup_uid gid=$startup_gid mode=$startup_mode"
  local startup_result
  if /usr/bin/timeout --signal=TERM --kill-after=1s 2s /usr/bin/systemctl --system --no-pager --no-ask-password show \
      --property=Id,LoadState,ActiveState,SubState,Result,Job,MainPID,ExecMainCode,ExecMainStatus,FragmentPath,DropInPaths \
      -- "${startup_units[@]}" 2>/dev/null | startup_summarize | \
      while IFS= read -r startup_line; do startup_emit "$startup_line" || exit 65; done; then
    startup_result=0
  else
    startup_result=$?
  fi
  startup_emit "end query-exit=$startup_result"
  return "$startup_result"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  set -euo pipefail
  startup_main "$@"
fi
'''


CLEANUP_HELPER = r'''#!/usr/bin/python3.14
"""Finite read-only RAM diagnostics; no recovery or watchdog authority."""
import json
import os
import stat
import time

PHASES = frozenset(('listening', 'cleanup-started', 'cleanup-failed',
  'cleanup-post-readonly-failed', 'filesystem-readonly', 'cleanup-control-failed',
  'restart-returned', 'restart-stalled'))
ERRORS = frozenset(('ValueError', 'OSError', 'TimeoutExpired', 'KeyError',
  'PermissionError', 'FileNotFoundError', 'ProcessLookupError', 'BlockingIOError'))


def summarize(state, command):
  # Select values explicitly. Never serialize arbitrary JSON keys or log text.
  if type(state) is not dict:
    phase, error, readonly = 'unavailable', 'unavailable', 'unavailable'
  else:
    phase = state.get('phase')
    phase = phase if type(phase) is str and phase in PHASES else 'unknown'
    error = state.get('error')
    error = error if type(error) is str and error in ERRORS else 'none' if error is None else 'unknown'
    ro = state.get('readonly_state_verified')
    readonly = 'yes' if ro is True else 'no' if ro is False else 'unavailable'
  classification = 'empty' if not command else 'other'
  for needle, label in ((b'target is busy', 'busy'), (b'not mounted', 'not-mounted'),
      (b'permission denied', 'permission'), (b'operation not permitted', 'permission'),
      (b'timed out', 'timeout'), (b'no such file', 'missing'), (b'read-only file system', 'readonly')):
    if needle in command.lower():
      classification = label
      break
  return 'phase=%s error=%s readonly=%s command=%s' % (phase, error, readonly, classification)


def read_file(directory, leaf, limit):
  if leaf not in ('state.json', 'command.log'):
    return b'', 'refused'
  allowed_modes = (0o600,) if leaf == 'state.json' else (0o600, 0o644)
  try:
    fd = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
  except FileNotFoundError:
    return b'', 'absent'
  try:
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
        and stat.S_IMODE(info.st_mode) in allowed_modes and info.st_nlink == 1):
      return b'', 'refused'
    data = os.read(fd, limit + 1)
    return data[:limit], 'clipped' if len(data) > limit or info.st_size > limit else 'bounded'
  finally:
    os.close(fd)


def main():
  if os.getuid() != 0 or os.geteuid() != 0 or os.getppid() != 1:
    return 64
  if os.uname().machine != 'aarch64' or os.uname().release != '7.1.0-shield-bringup':
    return 64
  with open('/proc/cmdline', 'r') as stream:
    tokens = stream.read(8193).split()
  if tokens.count('shield.first-ram-probe=1') != 1 or tokens.count('systemd.unit=shield-qualification.target') != 1:
    return 64
  directory = os.open('/run/shield-recovery', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  info = os.fstat(directory)
  if not (info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700):
    os.close(directory)
    return 64
  output = os.open('/dev/kmsg', os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    info = os.fstat(output)
    if not (stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 11)
        and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022):
      return 64
    end = time.monotonic() + 23
    previous = None
    emitted = 0
    for sample in range(115):
      if time.monotonic() >= end:
        break
      raw, state_status = read_file(directory, 'state.json', 8192)
      command, command_status = read_file(directory, 'command.log', 8192)
      try:
        state = json.loads(raw) if state_status == 'bounded' else None
      except (ValueError, UnicodeError):
        state = None
      record = summarize(state, command) + ' state-read=%s command-read=%s' % (state_status, command_status)
      if record != previous and emitted < 48:
        uptime = int(time.clock_gettime(time.CLOCK_BOOTTIME))
        message = ('<3>shield-cleanup-observer uptime=%d %s\n' % (uptime, record)).encode('ascii')
        os.write(output, message)
        emitted += 1
        previous = record
      time.sleep(min(0.2, max(0, end - time.monotonic())))
    os.write(output, b'<3>shield-cleanup-observer complete=1\n')
    return 0
  finally:
    os.close(output)
    os.close(directory)


if __name__ == '__main__':
  try:
    raise SystemExit(main())
  except (OSError, ValueError):
    raise SystemExit(65)
'''


def files(profile):
  candidate = profile['filesystem']['candidate_id']
  require(type(candidate) is str and re.fullmatch('[0-9a-f]{32}', candidate),
          'Fixed candidate identity required for runtime home policy')
  root = '@shield-' + candidate
  require(profile['filesystem']['subvolumes'] == {'root': root, 'home': root + '-home', 'log': root + '-log'}
          and profile['account'] == {'name': 'shieldqual', 'uid': 1001, 'gid': 1001},
          'Runtime home policy differs from the sealed qualification profile')
  result = {CONTROL_PATH: f'''[Unit]
Description=Authenticated bounded SHIELD native USB control
DefaultDependencies=no
Wants=local-fs.target plymouth-quit.service
After=local-fs.target systemd-udev-trigger.service plymouth-quit.service
Before={RECEIVER_UNIT}
IgnoreOnIsolate=yes
RefuseManualStop=yes

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/bin/python3.14 -I -S -B {RUNTIME}/native-root-control.py --run
Restart=no
TimeoutStartSec=20s
TimeoutStopSec=infinity
SendSIGKILL=no
KillMode=process
Slice=system.slice
StandardInput=null
StandardOutput=null
StandardError=null
OOMScoreAdjust=-950
'''.encode('ascii'), DROPIN_PATH: f'''[Unit]
Wants={CONTROL_UNIT}
After={CONTROL_UNIT}
'''.encode('ascii'), UDEV_PATH:
    b'ACTION=="add|change", SUBSYSTEM=="tty", KERNEL=="ttyGS0", OWNER:="root", GROUP:="root", MODE:="0600"\n'}
  result['run/systemd/system/home.mount.d/10-user-data.conf'] = f'''[Mount]
Options=rw,noatime,nosuid,nodev,exec,compress=zstd:1,subvol={root}-home
'''.encode('ascii')
  result[STARTUP_SCRIPT] = STARTUP_HELPER.encode('ascii')
  result[CLEANUP_SCRIPT] = CLEANUP_HELPER.encode('ascii')
  result['run/systemd/system/shield-native-cleanup-observer.service'] = b'''[Unit]
Description=Finite read-only SHIELD cleanup observation
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
ConditionKernelCommandLine=shield.first-ram-probe=1
ConditionKernelCommandLine=systemd.unit=shield-qualification.target

[Service]
Type=exec
User=root
Group=root
ExecStart=/usr/bin/python3.14 -I -S -B /run/shield-native/cleanup-diagnostics.py
Restart=no
RuntimeMaxSec=25s
TimeoutStopSec=2s
KillMode=control-group
Nice=10
OOMScoreAdjust=500
NoNewPrivileges=yes
StandardInput=null
StandardOutput=null
StandardError=null
'''
  result['run/systemd/system/shield-native-cleanup-observer.timer'] = b'''[Unit]
Description=One SHIELD cleanup observation window
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
ConditionKernelCommandLine=shield.first-ram-probe=1
ConditionKernelCommandLine=systemd.unit=shield-qualification.target

[Timer]
OnBootSec=539s
AccuracySec=1s
RandomizedDelaySec=0
Unit=shield-native-cleanup-observer.service
RemainAfterElapse=yes
'''
  result['run/systemd/system/shield-native-startup@.service'] = b'''[Unit]
Description=Bounded SHIELD startup state snapshot %i
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
ConditionKernelCommandLine=shield.first-ram-probe=1
ConditionKernelCommandLine=systemd.unit=shield-qualification.target

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=/
Environment=LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0 SYSTEMD_PAGERSECURE=1
UnsetEnvironment=BASH_ENV ENV SHELLOPTS BASHOPTS CDPATH GLOBIGNORE
ExecStart=/usr/bin/bash --noprofile --norc -p /run/shield-native/startup-diagnostics.sh %i
Restart=no
TimeoutStartSec=10s
TimeoutStopSec=3s
KillMode=control-group
Nice=10
OOMScoreAdjust=500
NoNewPrivileges=yes
StandardInput=null
StandardOutput=null
StandardError=null
'''
  for phase in (45, 90):
    result[f'run/systemd/system/shield-native-startup-{phase}.timer'] = f'''[Unit]
Description=One bounded SHIELD startup snapshot at {phase} seconds
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target
ConditionKernelCommandLine=shield.first-ram-probe=1
ConditionKernelCommandLine=systemd.unit=shield-qualification.target

[Timer]
OnBootSec={phase}s
AccuracySec=1s
RandomizedDelaySec=0
Unit=shield-native-startup@{phase}.service
RemainAfterElapse=yes
'''.encode('ascii')
  result['run/systemd/system/shield-qualification.target.d/20-startup-observer.conf'] = (
    b'[Unit]\nWants=shield-native-startup-45.timer shield-native-startup-90.timer shield-native-cleanup-observer.timer\n')
  require(set(result) == POLICY_PATHS, 'Native runtime policy source set differs')
  return result


def validate_home_mount(raw):
  """Verify the actual post-PID1 home boundary before control becomes ready."""
  require(type(raw) is bytes and 0 < len(raw) <= 256 * 1024,
          'Bounded kernel mount table required')
  homes = []
  for line in raw.splitlines():
    head, separator, tail = line.partition(b' - ')
    fields, filesystem = head.split(), tail.split()
    require(separator and len(fields) >= 6 and len(filesystem) == 3,
            'Malformed kernel mount table')
    if fields[4] == b'/home': homes.append((fields, filesystem))
  require(len(homes) == 1, 'One runtime home mount required')
  fields, filesystem = homes[0]
  options, super_options = set(fields[5].split(b',')), set(filesystem[2].split(b','))
  require(filesystem[0] == b'btrfs' and {b'rw', b'nosuid', b'nodev'} <= options
          and b'rw' in super_options and b'noexec' not in options | super_options,
          'Runtime home must retain nosuid,nodev and execution')
  return True


SPLASH_UNIT_BYTES = {
  'plymouth-quit.service': b'[Unit]\nDescription=Terminate Plymouth Boot Screen\nAfter=rc-local.service plymouth-start.service systemd-user-sessions.service\n\n[Service]\nExecStart=-/usr/bin/plymouth quit\nType=oneshot\nRemainAfterExit=yes\nTimeoutSec=20\n',
  'plymouth-start.service': b'[Unit]\nDescription=Show Plymouth Boot Screen\nDefaultDependencies=no\nWants=systemd-ask-password-plymouth.path systemd-vconsole-setup.service\nAfter=systemd-vconsole-setup.service systemd-udev-trigger.service systemd-udevd.service\nBefore=systemd-ask-password-plymouth.service\nConditionKernelCommandLine=!plymouth.enable=0\nConditionVirtualization=!container\nIgnoreOnIsolate=true\n\n[Service]\nExecStart=/usr/bin/plymouthd --mode=boot --pid-file=/run/plymouth/pid --attach-to-session\nExecStartPost=-/usr/bin/plymouth show-splash\nType=forking\nRemainAfterExit=yes\nKillMode=mixed\nSendSIGKILL=no\n',
}


def unit_properties(unit, names):
  result = subprocess.run(['/usr/bin/systemctl', 'show', unit,
    *('--property=' + name for name in names)], stdin=subprocess.DEVNULL,
    capture_output=True, text=True, timeout=1,
    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
  rows = result.stdout.splitlines()
  require(result.returncode == 0 and not result.stderr and len(rows) == len(names)
          and all('=' in row for row in rows), 'Splash unit observation failed')
  values = dict(row.split('=', 1) for row in rows)
  require(len(values) == len(names) and set(values) == set(names),
          'Splash unit properties differ')
  return values


def validate_splash_cgroup():
  # Always inspect the fixed former unit path, including when PID1 reports no
  # current ControlGroup. A populated leftover must not pass as daemon closure.
  path = '/sys/fs/cgroup/system.slice/plymouth-start.service/cgroup.procs'
  try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  except FileNotFoundError:
    return
  try:
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and not info.st_mode & 0o022, 'Unowned splash cgroup state')
    require(os.read(fd, 4097) == b'', 'Splash service cgroup remains populated')
  finally:
    os.close(fd)


def validate_splash_exit():
  """A qualification target must finish the normal splash lifecycle itself.

  The stock multi-user target normally starts plymouth-quit. This target does
  not pull multi-user in, so explicitly order that same quit before ROOT READY.
  MainPID zero also covers a legitimately skipped splash; a successful oneshot
  alone cannot prove the long-running daemon released its display/log files.
  """
  for name, expected in SPLASH_UNIT_BYTES.items():
    require(owned_bytes(Path('/usr/lib/systemd/system') / name, len(expected), 0o644) == expected,
            'Stock splash unit bytes differ')
  quit_state = unit_properties('plymouth-quit.service',
    ('FragmentPath', 'DropInPaths', 'ActiveState', 'SubState', 'Result', 'MainPID',
     'ExecMainCode', 'ExecMainStatus'))
  require(quit_state == {
    'FragmentPath': '/usr/lib/systemd/system/plymouth-quit.service',
    'DropInPaths': '', 'ActiveState': 'active', 'SubState': 'exited',
    'Result': 'success', 'MainPID': '0', 'ExecMainCode': '1', 'ExecMainStatus': '0'},
          'Normal splash quit has not completed successfully')
  splash = unit_properties('plymouth-start.service',
    ('FragmentPath', 'DropInPaths', 'MainPID', 'ActiveState', 'SubState', 'ControlGroup'))
  require(splash['FragmentPath'] == '/usr/lib/systemd/system/plymouth-start.service'
          and splash['DropInPaths'] == '' and splash['MainPID'] == '0'
          and (splash['ActiveState'], splash['SubState']) in {
            ('active', 'exited'), ('inactive', 'dead')},
          'Boot splash daemon remains active or its unit differs')
  require(splash['ControlGroup'] in ('', '/system.slice/plymouth-start.service'),
          'Splash service cgroup differs')
  validate_splash_cgroup()


def validate(profile):
  with Path('/proc/self/mountinfo').open('rb') as source:
    raw_mounts = source.read(256 * 1024 + 1)
  validate_home_mount(raw_mounts)
  validate_splash_exit()
  shadow = Path('/etc/udev/rules.d') / Path(UDEV_PATH).name
  require(not shadow.exists() and not shadow.is_symlink(),
          'Higher-priority udev rule shadows the owned RAM policy')
  for relative, expected in files(profile).items():
    require(owned_bytes(Path('/') / relative, len(expected), 0o644) == expected,
            'RAM native unit/drop-in bytes differ')
  for unit, fragment, dropins in [
    (CONTROL_UNIT, '/' + CONTROL_PATH, ''),
    (RECEIVER_UNIT, '/etc/systemd/system/' + RECEIVER_UNIT, '/' + DROPIN_PATH),
  ]:
    result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=FragmentPath',
      '--property=DropInPaths', '--property=DefaultDependencies', '--property=Restart'],
      stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1,
      env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    rows = result.stdout.splitlines()
    require(result.returncode == 0 and len(rows) == 4 and len(set(rows)) == 4,
            'Native effective unit observation failed')
    values = dict(row.split('=', 1) for row in rows)
    require(values == {'FragmentPath': fragment, 'DropInPaths': dropins,
                      'DefaultDependencies': 'no', 'Restart': 'no'},
            'Unexpected effective native unit/drop-in closure')

  result = subprocess.run(['/usr/bin/systemctl', 'show', 'home.mount',
      '--property=FragmentPath', '--property=DropInPaths'], stdin=subprocess.DEVNULL,
      capture_output=True, text=True, timeout=1,
      env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
  rows = result.stdout.splitlines()
  require(result.returncode == 0 and len(rows) == 2 and len(set(rows)) == 2,
          'Runtime home unit observation failed')
  require(dict(row.split('=', 1) for row in rows) == {
    'FragmentPath': '/run/systemd/generator/home.mount',
    'DropInPaths': '/run/systemd/system/home.mount.d/10-user-data.conf'},
    'PID1 did not load the sealed runtime home policy')
