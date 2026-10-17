#!/usr/bin/env python3
"""VM-only fixed user-session probe. No caller-selected commands or paths."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import time
import uuid

RUNTIME = Path('/run/user/1001')
ENDPOINT = RUNTIME / 'shield-systemd-vm.sock'
PREFIX = Path('/usr/lib/shield-systemd-vm-user')
LIMIT = 32768


def require(ok, message):
  if not ok: raise ValueError(message)


def session_id():
  library = ctypes.CDLL('libsystemd.so.0')
  library.sd_pid_get_session.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
  library.sd_pid_get_session.restype = ctypes.c_int
  value = ctypes.c_void_p()
  require(library.sd_pid_get_session(0, ctypes.byref(value)) >= 0 and value.value,
          'No actual PAM/logind session for user probe')
  try: result = ctypes.string_at(value).decode('ascii')
  finally:
    libc = ctypes.CDLL(None)
    libc.free.argtypes = [ctypes.c_void_p]
    libc.free(value)
  require(re.fullmatch('[A-Za-z0-9_-]{1,64}', result), 'Malformed session identity')
  return result


def starttime():
  data = Path('/proc/self/stat').read_text()
  return int(data[data.rfind(')') + 2:].split()[19])


def packet(channel):
  data, ancillary, flags, _ = channel.recvmsg(LIMIT, 0)
  require(data and not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'Bad root packet')
  value = json.loads(data)
  require(set(value) == {'version', 'operation'} and type(value['version']) is int
          and value['version'] == 1 and value['operation'] in {'probe', 'finish'}, 'Unowned probe request')
  return value['operation']


def send(channel, value):
  data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
  require(len(data) <= LIMIT and channel.send(data) == len(data), 'Probe result delivery failed')


def command(argv, timeout=5):
  env = {'PATH': '/usr/bin', 'HOME': '/home/shieldqual', 'USER': 'shieldqual',
    'LOGNAME': 'shieldqual', 'LC_ALL': 'C', 'TERM': 'linux',
    'XDG_RUNTIME_DIR': str(RUNTIME), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(RUNTIME / 'bus')}
  process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
  try:
    output, _ = process.communicate(timeout=timeout)
  except BaseException:
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    process.communicate(timeout=1)
    raise
  require(len(output) <= LIMIT, 'Excessive command output')
  return {'returncode': process.returncode, 'output': output.decode('utf-8', errors='replace')}


def evidence(result):
  return {'returncode': result['returncode'], 'output': result['output'][:2048],
    'output_truncated': len(result['output']) > 2048,
    'output_sha256': hashlib.sha256(result['output'].encode()).hexdigest()}


def authentication_barrier(result):
  # Authentication was refused before command authorization was reported.
  # The parent independently proves the root policy and this probe's setuid
  # transition; this packet makes no root-query or authorization-denial claim.
  return (type(result['returncode']) is int and result['returncode'] == 1
          and result['output'] == 'sudo: a password is required\n')


def denied_method(result, kind):
  text = result['output'].lower()
  excluded = ('failed to connect', 'no such file', 'serviceunknown', 'unknown method',
              'timed out', 'effective uid is not 0', 'nosuid', 'a password is required',
              'interactive authentication required', 'unable to initialize', 'account validation')
  if result['returncode'] == 0 or any(value in text for value in excluded): return False
  if kind == 'busctl':
    return 'call failed:' in text and ('access denied' in text or 'not authorized' in text)
  return ('access denied' in text or 'not authorized' in text or 'permission denied' in text)


def probes(checks):
  uid = command([str(PREFIX / 'uid-probe')], 3)
  expected = {'format_version': 1, 'ruid_before': 1001, 'euid_before': 0, 'suid_before': 0,
    'rgid_before': 1001, 'egid_before': 1001, 'sgid_before': 1001, 'nnp_before': 0,
    'ruid_after': 1001, 'euid_after': 1001, 'suid_after': 1001,
    'rgid_after': 1001, 'egid_after': 1001, 'sgid_after': 1001, 'nnp_after': 1,
    'supplementary_groups_after': 0, 'root_regain_denied': True, 'extra_fds_closed': True}
  checks['setuid'] = {'passed': False, **evidence(uid)}
  require(uid['returncode'] == 0, 'Actual ARM setuid probe failed')
  observed = json.loads(uid['output'])
  require(observed == expected and all(type(observed[k]) is type(v) for k, v in expected.items()),
          'UID elevation/drop record differs')
  checks['setuid'] = {'passed': True, 'record': observed}
  sudo = command(['/usr/bin/sudo', '-n', '-u', 'root', '--', '/usr/bin/true'])
  name = 'sudo_root_true_blocked_without_authentication'
  checks[name] = {'passed': False, **evidence(sudo)}
  require(authentication_barrier(sudo), 'Exact sudo authentication barrier not observed')
  checks[name] = {'passed': True, **evidence(sudo), 'authentication_barrier_observed': True,
    'authorization_denial_observed_in_user_execution': False}
  bus = command(['/usr/bin/busctl', '--user', '--no-pager', 'list'])
  checks['user_bus'] = {'passed': False, **evidence(bus)}
  require(bus['returncode'] == 0 and 'org.freedesktop.systemd1' in bus['output']
          and 'org.freedesktop.DBus' in bus['output'], 'Actual user manager bus unavailable')
  checks['user_bus'] = {'passed': True, 'returncode': 0,
    'actual_manager_and_bus_names_present': True, 'output_sha256': hashlib.sha256(bus['output'].encode()).hexdigest()}
  requests = [
    ('login1_poweroff', 'busctl', ['/usr/bin/busctl', '--system', 'call', 'org.freedesktop.login1',
      '/org/freedesktop/login1', 'org.freedesktop.login1.Manager', 'PowerOff', 'b', 'false']),
    ('login1_reboot', 'busctl', ['/usr/bin/busctl', '--system', 'call', 'org.freedesktop.login1',
      '/org/freedesktop/login1', 'org.freedesktop.login1.Manager', 'Reboot', 'b', 'false']),
    ('systemd_reboot_target', 'systemctl', ['/usr/bin/systemctl', '--no-ask-password',
      '--no-block', 'start', 'reboot.target']),
    ('systemd_poweroff_target', 'systemctl', ['/usr/bin/systemctl', '--no-ask-password',
      '--no-block', 'start', 'poweroff.target']),
  ]
  for name, kind, argv in requests:
    result = command(argv)
    checks[name] = {'passed': False, **evidence(result)}
    require(denied_method(result, kind), 'Global power request denial not proven: ' + name)
    checks[name] = {'passed': True, **evidence(result)}
  config = Path('/home/shieldqual/.config/hypr/hyprland.lua')
  require(config.is_file() and 'require("default.hypr.omarchy")' in config.read_text(),
          'Normal user Hyprland configuration missing')
  checks['user_configuration_inventory'] = {'status': 'inventory only',
    'hyprland_config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
    'Hyprland_binary_present': Path('/usr/bin/Hyprland').is_file(),
    'dri_files': sorted(p.name for p in Path('/usr/lib/dri').iterdir()),
    'compositor_was_not_executed': True}
  # No guessed headless switches or software driver are introduced to make a pass.
  checks['graphics_uwsm'] = {'status': 'blocked', 'passed': False,
    'reason': 'No working software compositor/renderer has been demonstrated on this VM payload',
    'version_or_file_presence_is_not_a_session_pass': True}
  return checks


def main():
  require(len(os.sys.argv) == 1 and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1001,
          'Actual qualification user required')
  require(os.environ.get('XDG_RUNTIME_DIR') == str(RUNTIME), 'PAM runtime directory not supplied')
  info = RUNTIME.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1001
          and stat.S_IMODE(info.st_mode) == 0o700, 'Wrong real user runtime directory')
  require(not ENDPOINT.exists() and not ENDPOINT.is_symlink(), 'Existing probe endpoint refused')
  boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  require(str(uuid.UUID(boot)) == boot, 'Malformed boot identity')
  identity = {'version': 1, 'kind': 'hello', 'pid': os.getpid(), 'starttime': starttime(),
    'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'session': session_id(),
    'boot_id': boot, 'tty': os.ttyname(0)}
  os.umask(0o077)
  with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC) as listener:
    listener.settimeout(60)
    listener.bind(str(ENDPOINT)); os.chmod(ENDPOINT, 0o600); listener.listen(1)
    channel, _ = listener.accept()
    with channel:
      channel.settimeout(180)
      pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
      require(pid > 1 and uid == gid == 0, 'Root-authenticated VM collector required')
      send(channel, identity)
      require(packet(channel) == 'probe', 'Fixed probe must precede finish')
      checks = {}
      try:
        probes(checks)
        result = {'version': 1, 'kind': 'probes', 'passed': True, 'checks': checks}
      except (OSError, ValueError, subprocess.SubprocessError) as error:
        result = {'version': 1, 'kind': 'probes', 'passed': False,
          'checks': checks, 'error': type(error).__name__, 'reason': str(error)[:200]}
      send(channel, result)
      require(packet(channel) == 'finish', 'Only fixed finish follows the single probe')
      send(channel, {'version': 1, 'kind': 'bye'})
  return 0 if result['passed'] else 1


if __name__ == '__main__':
  try: raise SystemExit(main())
  except (OSError, ValueError, subprocess.SubprocessError) as error:
    print('VM_USER_PROBE_REFUSED ' + type(error).__name__ + ': ' + str(error)[:200],
          file=os.sys.stderr, flush=True)
    raise SystemExit(64)
