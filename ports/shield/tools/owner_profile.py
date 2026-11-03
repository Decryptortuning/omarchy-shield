"""Render an explicitly enrolled OWNER system; no filesystem or device effects.

The qualification profile remains a separate bounded purpose. OWNER replaces
its startup, remote-login and watchdog policy in a newly prepared root;
this module does not unmask or mutate the existing qualification root.
"""
import base64
import json
import re
import struct
import uuid

INSTALL = '/usr/lib/omarchy/shield/owner'
ACCOUNT = {'name': 'shieldqual', 'uid': 1001, 'gid': 1001}
MODULE = 'usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/net/ethernet/realtek/r8169.ko'


def require(value, message):
  if not value:
    raise ValueError(message)


def exact(value, keys, message):
  require(type(value) is dict and set(value) == set(keys), message)


def public_key(raw):
  """One ordinary Ed25519 key, without authorized_keys options or a comment.

  This checks the wire format. The enrolled key producer and actual OpenSSH
  signing/login witness provide the cryptographic capability evidence.
  """
  require(type(raw) is str and len(raw) <= 256 and raw.isascii()
          and raw.endswith('\n') and raw.count('\n') == 1,
          'One complete public key line required')
  fields = raw[:-1].split(' ')
  require(len(fields) == 2 and fields[0] == 'ssh-ed25519', 'Ed25519 key without options required')
  try:
    binary = base64.b64decode(fields[1], validate=True)
  except (ValueError, TypeError) as error:
    raise ValueError('Invalid public key encoding') from error
  require(base64.b64encode(binary).decode('ascii') == fields[1]
          and binary[:4] == struct.pack('>I', 11)
          and binary[4:15] == b'ssh-ed25519'
          and binary[15:19] == struct.pack('>I', 32) and len(binary) == 51,
          'Public key wire format differs')
  return raw


def identity(value):
  exact(value, ('bytes', 'sha256'), 'Exact artifact identity required')
  require(type(value['bytes']) is int and 0 < value['bytes'] <= 8 * 1024**2
          and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']),
          'Invalid artifact identity')


def validate_emmc(value):
  """One enrolled internal user-area partition; no device access here."""
  exact(value, ('controller', 'driver', 'of_path', 'cid_sha256', 'disk_bytes',
                'partition_index', 'partition_label', 'partition_start_bytes',
                'partition_bytes', 'partition_table_sha256'), 'Internal MMC enrollment fields differ')
  require(value['controller'] == '700b0600.mmc' and value['driver'] == 'sdhci-tegra'
          and value['of_path'] == '/mmc@700b0600'
          and value['partition_index'] == 33 and type(value['partition_index']) is int
          and value['partition_label'] == 'UDA', 'Only selected internal UDA is allowed')
  for key in ('cid_sha256', 'partition_table_sha256'):
    require(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}', value[key]),
            'Internal MMC identity digest differs')
  for key in ('disk_bytes', 'partition_start_bytes', 'partition_bytes'):
    require(type(value[key]) is int and 0 < value[key] < 2**64
            and value[key] % 512 == 0, 'Internal MMC geometry must be exact sectors')
  require(value['disk_bytes'] == 30777344 * 512
          and value['partition_start_bytes'] + value['partition_bytes'] <= value['disk_bytes'],
          'Internal MMC partition escapes selected user area')
  return value


def validate_boot_store(value, filesystem):
  exact(value, ('filesystem_uuid', 'partition_uuid', 'filesystem_type', 'partition_index',
    'partition_label', 'partition_start_bytes', 'partition_bytes', 'generation_id'),
    'Internal boot store fields differ')
  for key in ('filesystem_uuid', 'partition_uuid'):
    require(type(value[key]) is str and str(uuid.UUID(value[key])) == value[key],
            'Canonical boot store UUID required')
  require(value['filesystem_type'] == 'ext4' and type(value['partition_index']) is int
          and value['partition_index'] == 19 and value['partition_label'] == 'APP'
          and value['filesystem_uuid'] != filesystem['uuid']
          and type(value['generation_id']) is str and re.fullmatch('[0-9a-f]{64}', value['generation_id']),
          'Internal boot store identity differs')
  for key in ('partition_start_bytes', 'partition_bytes'):
    require(type(value[key]) is int and value[key] > 0 and value[key] % 1048576 == 0,
            'Internal boot store must use exact aligned geometry')
  require(value['partition_start_bytes'] + value['partition_bytes']
          <= filesystem['emmc']['partition_start_bytes'], 'Boot store overlaps internal root')
  return value


def validate(enrollment):
  require(type(enrollment) is dict, 'OWNER enrollment must be an object')
  internal = type(enrollment.get('filesystem')) is dict and 'emmc' in enrollment['filesystem']
  fields = ('purpose', 'owner_id', 'filesystem', 'ssh', 'ethernet')
  exact(enrollment, fields + (('boot_store',) if internal else ()), 'OWNER enrollment fields differ')
  require(enrollment['purpose'] == 'omarchy-shield-owner'
          and type(enrollment['owner_id']) is str
          and re.fullmatch('[0-9a-f]{32}', enrollment['owner_id']), 'Explicit OWNER enrollment required')
  fs = enrollment['filesystem']
  require(type(fs) is dict and set(fs) in ({'uuid', 'usb', 'subvolumes'},
                                           {'uuid', 'emmc', 'subvolumes'}),
          'OWNER filesystem must select exactly one enrolled storage kind')
  require(type(fs['uuid']) is str and str(uuid.UUID(fs['uuid'])) == fs['uuid'], 'Canonical filesystem UUID required')
  if 'emmc' in fs:
    validate_emmc(fs['emmc'])
    validate_boot_store(enrollment['boot_store'], fs)
    require(fs['subvolumes'] == {'root': '@root', 'home': '@home', 'log': '@log'},
            'Internal OWNER must name its root/home/log explicitly')
  else:
    exact(fs['usb'], ('vendor', 'product'), 'Selected USB identity required')
    require(all(type(x) is str and re.fullmatch('[0-9a-f]{4}', x) for x in fs['usb'].values()),
            'USB identity syntax differs')
    root = '@shield-' + enrollment['owner_id']
    require(fs['subvolumes'] == {'root': root, 'home': root + '-home', 'log': root + '-log'},
            'OWNER must name its newly prepared root/home/log explicitly')
  ssh = enrollment['ssh']
  exact(ssh, ('operator_public_key', 'host_public_key', 'host_private_identity'), 'SSH enrollment fields differ')
  public_key(ssh['operator_public_key'])
  public_key(ssh['host_public_key'])
  require(ssh['operator_public_key'] != ssh['host_public_key'], 'Operator and host keys must be distinct')
  identity(ssh['host_private_identity'])
  network = enrollment['ethernet']
  exact(network, ('module', 'firmware'), 'Ethernet enrollment fields differ')
  identity(network['module'])
  require(type(network['firmware']) is dict and 1 <= len(network['firmware']) <= 64,
          'Explicit local firmware closure required')
  for name, value in network['firmware'].items():
    require(type(name) is str and re.fullmatch('usr/lib/firmware/rtl_nic/[A-Za-z0-9_-]+[.]fw', name),
            'Firmware path escapes the selected local NIC closure')
    identity(value)
  return enrollment


def validate_context(context, enrollment):
  validate(enrollment)
  exact(context, ('purpose', 'owner_id', 'enrollment_sha256', 'kernel_release',
                  'filesystem', 'sources_sha256'), 'OWNER boot context fields differ')
  require(context['purpose'] == 'omarchy-shield-owner'
          and context['owner_id'] == enrollment['owner_id']
          and context['filesystem'] == enrollment['filesystem']
          and context['kernel_release'] == '7.1.0-shield-bringup'
          and type(context['enrollment_sha256']) is str
          and re.fullmatch('[0-9a-f]{64}', context['enrollment_sha256']),
          'OWNER boot context does not bind this enrollment')
  sources = context['sources_sha256']
  required = {'owner_profile.py', 'owner_runtime.py', 'owner_layer.py', 'owner_command_line.py', 'owner-init.py', 'owner-network.py',
              'owner-ready.py', 'owner-thermal.py'}
  if 'emmc' in enrollment['filesystem']:
    required.add('owner_internal_ack.py')
  require(type(sources) is dict and required <= set(sources) and len(sources) <= 64,
          'OWNER source closure is incomplete')
  require(all(type(name) is str and re.fullmatch('[A-Za-z0-9_-]+[.]py', name)
              and type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest)
              for name, digest in sources.items()), 'OWNER source identity differs')
  return context


def render(enrollment):
  validate(enrollment)
  fs, ssh = enrollment['filesystem'], enrollment['ssh']
  files = {}

  def add(path, text, mode=0o644):
    require(path not in files and not path.startswith('/') and '..' not in path.split('/'),
            'Duplicate or unsafe OWNER output')
    files[path] = {'mode': mode, 'uid': 1001 if path.startswith('home/shieldqual/') else 0,
      'gid': 1001 if path.startswith('home/shieldqual/') else 0, 'data': text.encode('utf-8')}

  add('usr/lib/omarchy/shield/owner/enrollment.json',
    json.dumps(enrollment, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n', 0o600)
  add('etc/hostname', 'omarchy-shield\n')
  add('etc/fstab', ''.join('UUID=' + fs['uuid'] + ' ' + mount + ' btrfs ' + options
    + ',compress=zstd:1,subvol=' + fs['subvolumes'][purpose] + ' 0 0\n'
    for mount, purpose, options in [('/', 'root', 'rw,noatime'),
      ('/home', 'home', 'rw,noatime,nosuid,nodev'), ('/var/log', 'log', 'rw,noatime')])
    + ('UUID=' + enrollment['boot_store']['filesystem_uuid']
       + ' /boot ext4 rw,noatime,nosuid,nodev,noexec 0 2\n' if 'emmc' in fs else ''))
  add('etc/ssh/sshd_config', '# Explicitly enrolled OWNER SSH; no password authentication.\n'
    'Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key\n'
    'AuthorizedKeysFile /etc/ssh/authorized_keys/%u\n'
    'AuthenticationMethods publickey\nPubkeyAuthentication yes\n'
    'PasswordAuthentication no\nKbdInteractiveAuthentication no\n'
    'PermitEmptyPasswords no\nPermitRootLogin prohibit-password\n'
    'AllowUsers root shieldqual\nStrictModes yes\nUsePAM yes\nUseDNS no\n'
    'PermitUserEnvironment no\nLoginGraceTime 30\nMaxAuthTries 3\n'
    'Subsystem sftp /usr/lib/ssh/sftp-server\n')
  add('etc/ssh/authorized_keys/root', ssh['operator_public_key'], 0o600)
  add('etc/ssh/authorized_keys/shieldqual', ssh['operator_public_key'], 0o644)
  add('etc/ssh/ssh_host_ed25519_key.pub', ssh['host_public_key'])
  add('etc/systemd/system.conf.d/90-shield-owner.conf', '[Manager]\n'
    'WatchdogDevice=/dev/watchdog0\nRuntimeWatchdogSec=240s\n'
    'RebootWatchdogSec=240s\nKExecWatchdogSec=240s\n'
    'CtrlAltDelBurstAction=none\nDefaultTimeoutStopSec=30s\n')
  add('etc/systemd/journald.conf.d/90-shield-owner.conf', '[Journal]\n'
    'Storage=persistent\nSystemMaxUse=256M\nRuntimeMaxUse=32M\nForwardToKMsg=no\n')
  add('etc/systemd/system/getty@tty1.service.d/10-shield-owner.conf', '[Service]\n'
    'ExecStart=\nExecStart=-/usr/bin/agetty --noreset --noclear --autologin shieldqual tty1 linux\n')
  add('home/shieldqual/.bash_profile', '# OWNER console; SSH never starts another compositor.\n'
    '[[ -f ~/.bashrc ]] && source ~/.bashrc\n'
    'if [[ $(tty) == /dev/tty1 && -z ${SSH_CONNECTION:-} && -z ${WAYLAND_DISPLAY:-} ]]; then\n'
    '  exec uwsm start -g -1 -e -D Hyprland hyprland.desktop\nfi\n')
  add('etc/modprobe.d/90-shield-owner-ethernet.conf', '# Explicit identity admission precedes ordinary module loading.\nblacklist r8169\n')
  add('etc/systemd/system/shield-owner-ethernet.service', '[Unit]\n'
    'Description=Admit the onboard Ethernet device and matched local driver\n'
    'After=systemd-udev-trigger.service\nBefore=NetworkManager.service\n'
    'OnFailure=shield-owner-recovery.service\n'
    'AssertKernelCommandLine=shield.omarchy-owner=1\n'
    '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I -S -B ' + INSTALL + '/owner-network.py --run\n'
    'TimeoutStartSec=30s\nTimeoutStopSec=3s\nKillMode=control-group\nRemainAfterExit=yes\n')
  add('etc/systemd/system/NetworkManager.service.d/10-shield-owner.conf', '[Unit]\n'
    'Requires=shield-owner-ethernet.service\nAfter=shield-owner-ethernet.service\n')
  add('etc/systemd/system/shield-owner-thermal.service', '[Unit]\n'
    'Description=Monitor matched Shield cooling with conservative maximum fan\n'
    'AssertKernelCommandLine=shield.omarchy-owner=1\n'
    'After=systemd-udev-trigger.service\nBefore=getty@tty1.service sshd.service shield-owner-ready.service\n'
    'OnFailure=shield-owner-recovery.service\n'
    '[Service]\nType=notify\nNotifyAccess=main\n'
    'ExecStart=/usr/bin/python3 -I -S -B ' + INSTALL + '/owner-thermal.py --run\n'
    'WatchdogSec=12s\nTimeoutStartSec=20s\nTimeoutStopSec=3s\n'
    'Restart=no\nKillMode=control-group\nNoNewPrivileges=yes\n')
  add('etc/systemd/system/shield-owner-ready.service', '[Unit]\n'
    'Description=Check local Omarchy startup without a network lease\n'
    'AssertKernelCommandLine=shield.omarchy-owner=1\n'
    'Requires=shield-owner-thermal.service shield-owner-ethernet.service sshd.service\n'
    'After=shield-owner-thermal.service shield-owner-ethernet.service sshd.service getty@tty1.service\n'
    + ('RequiresMountsFor=/boot/shield-owner\n' if 'emmc' in fs else '') +
    'OnFailure=shield-owner-recovery.service\n'
    '[Service]\nType=oneshot\n'
    'ExecStart=/usr/bin/python3 -I -S -B ' + INSTALL + '/owner-ready.py --run\n'
    'TimeoutStartSec=70s\nTimeoutStopSec=3s\nKillMode=control-group\nRemainAfterExit=yes\n')
  # Intentionally fail this dedicated unit to invoke PID1's ordinary reboot
  # transaction with the recovery argument. PID1 stops users and unmounts RW
  # filesystems; this is not an immediate reboot syscall or the C stop-writers.
  add('etc/systemd/system/shield-owner-recovery.service', '[Unit]\n'
    'Description=Return a failed OWNER startup to passive recovery\n'
    'AssertKernelCommandLine=shield.omarchy-owner=1\n'
    'FailureAction=reboot\nRebootArgument=recovery\n'
    '[Service]\nType=oneshot\nExecStart=/usr/bin/false\n'
    'Restart=no\nTimeoutStartSec=3s\n')
  for unit in ['sshd.service', 'getty@tty1.service']:
    add('etc/systemd/system/' + unit + '.d/20-shield-owner-cooling.conf', '[Unit]\n'
      'Requires=shield-owner-thermal.service\nAfter=shield-owner-thermal.service\n')
  # A new OWNER root replaces these policies; the previously qualified root is
  # retained separately and is never silently unmasked by this renderer.
  removals = [
    'etc/systemd/system/sshd.service', 'etc/systemd/system/ssh.service',
    'etc/systemd/system/getty@tty1.service', 'etc/systemd/system/sddm.service',
    'etc/systemd/system/shield-qualification.target',
    'etc/systemd/system/shield-qualification-desktop.service',
    'etc/systemd/system/shield-qualification-recovery.service',
    'etc/systemd/system/shield-guardian.service',
    'etc/systemd/system.conf.d/90-shield-qualification.conf',
    'etc/systemd/journald.conf.d/90-shield-qualification.conf',
    'etc/systemd/system/user@1001.service.d/90-shield-qualification.conf',
    'etc/polkit-1/rules.d/00-shield-qualification.rules',
    'etc/systemd/logind.conf.d/90-shield-qualification.conf',
    'etc/systemd/system/multi-user.target.wants/systemd-networkd.service',
    'etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service',
    *['etc/systemd/system/sockets.target.wants/' + name for name in (
      'systemd-networkd.socket', 'systemd-networkd-varlink.socket',
      'systemd-networkd-varlink-metrics.socket', 'systemd-networkd-resolve-hook.socket')]]
  links = {'etc/systemd/system/default.target': '/usr/lib/systemd/system/graphical.target',
    'etc/systemd/system/multi-user.target.wants/NetworkManager.service': '/usr/lib/systemd/system/NetworkManager.service',
    'etc/systemd/system/multi-user.target.wants/sshd.service': '/usr/lib/systemd/system/sshd.service',
    'etc/systemd/system/getty.target.wants/getty@tty1.service': '/usr/lib/systemd/system/getty@.service'}
  for unit in ['shield-owner-thermal.service', 'shield-owner-ready.service']:
    links['etc/systemd/system/multi-user.target.wants/' + unit] = '/etc/systemd/system/' + unit
  # Socket and D-Bus activation must not resurrect a second DHCP manager.
  for name in ('sshdgenkeys.service', 'systemd-networkd.service', 'dbus-org.freedesktop.network1.service',
               'systemd-networkd-wait-online.service', 'systemd-networkd.socket',
               'systemd-networkd-varlink.socket', 'systemd-networkd-varlink-metrics.socket',
               'systemd-networkd-resolve-hook.socket'):
    links['etc/systemd/system/' + name] = '/dev/null'
  directories = {'etc/ssh/authorized_keys': {'mode': 0o755, 'uid': 0, 'gid': 0},
    'usr/lib/omarchy/shield/owner': {'mode': 0o755, 'uid': 0, 'gid': 0}}
  return {'purpose': 'omarchy-shield-owner', 'directories': directories, 'files': files, 'links': links,
    'removals': removals,
    'home_removals': ['home/shieldqual/.local/state/omarchy/shield-qualification.json'],
    'home_seed': {'source': 'usr/share/omarchy/config/hypr/hyprland.lua',
      'target': 'home/shieldqual/.config/hypr/hyprland.lua', 'mode': 0o644, 'uid': 1001, 'gid': 1001},
    'private_files': {'etc/ssh/ssh_host_ed25519_key': {
      'mode': 0o600, 'uid': 0, 'gid': 0, **ssh['host_private_identity']}},
    'required_programs': ['owner-init.py', 'owner_profile.py', 'owner_runtime.py',
      'owner-network.py', 'owner-ready.py', 'owner-thermal.py']
      + (['owner_internal_ack.py'] if 'emmc' in fs else []),
    'trial_preconditions': ['New OWNER snapshot preimages and private host key verified',
      'Combined loader/root/runtime source and actual ARM systemd graph reviewed and verified',
      'Local readiness/thermal recovery guards installed; passive recovery preserved',
      'Trial launch and local startup deadline distinct from healthy desktop lifetime'],
    'activation_preconditions': ['Normal PID1 sole hardware watchdog feeding and lifecycle qualified',
      'Physical Ethernet, DHCP and strict host-key SSH login/reconnect qualified',
      'Unattended cold boot and durable local failure recovery qualified'],
    'normal_first_run_complete': False, 'ready_to_activate': False}
