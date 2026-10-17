"""Single producer/consumer contract for native RAM systemd additions.

The real-root receiver retains its existing cleanup lifetime if USB control
fails. Wants+After orders startup; its held-connection admission supplies the
mandatory readiness gate. BindsTo/Requires on the control service would stop the
receiver on transport failure precisely when filesystem cleanup is needed.
"""
from pathlib import Path
import subprocess

from native_boot_context import POLICY_PATHS, RUNTIME, UDEV_PATH, owned_bytes
from usb_root_profile import require

CONTROL_UNIT = 'shield-native-control.service'
RECEIVER_UNIT = 'shield-qualification-recovery.service'
CONTROL_PATH = 'run/systemd/system/' + CONTROL_UNIT
DROPIN_PATH = 'run/systemd/system/' + RECEIVER_UNIT + '.d/10-native-control.conf'


def files():
  result = {CONTROL_PATH: f'''[Unit]
Description=Authenticated bounded SHIELD native USB control
DefaultDependencies=no
Wants=local-fs.target
After=local-fs.target systemd-udev-trigger.service
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
  require(set(result) == POLICY_PATHS, 'Native runtime policy source set differs')
  return result


def validate():
  shadow = Path('/etc/udev/rules.d') / Path(UDEV_PATH).name
  require(not shadow.exists() and not shadow.is_symlink(),
          'Higher-priority udev rule shadows the owned RAM policy')
  for relative, expected in files().items():
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
