"""Fixed native boot-bundle admission; no device, mount or reboot entrypoint.

The host pins the complete capsule before loading it. Its canonical boot.json
digest is also a unique kernel command-line assignment. Inner configuration
hashes bind channel contexts without a self-referential capsule hash. Keys are
separate root-only RAM files and never enter a command line or Windows bridge.
This module supplies observations, not a mount lease or writer eligibility.
"""
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from types import MappingProxyType

from guardian_binding import BOARD, CONFIG_SHA256, DTB_SHA256, IMAGE_SHA256, INSTALL, validate
from native_control_protocol import Context
from usb_root_profile import require

DIRECTORY = Path('/run/shield-native')
CONFIGURATION = DIRECTORY / 'boot.json'
RUNTIME = DIRECTORY / 'runtime'
INPUTS = DIRECTORY / 'inputs'
KEYS = DIRECTORY / 'keys'
PHASE_ROLE = {'packages': 1, 'layer': 1, 'systemd': 2}
INPUT_NAMES = {'packages': {'payload', 'plan'},
  'layer': {'payload', 'plan', 'layer', 'preimages', 'predecessor'},
  'systemd': {'payload', 'plan', 'layer', 'predecessorA', 'predecessorB'}}
INPUT_PATHS = {'payload': 'payload.json', 'plan': 'plan.json', 'layer': 'layer.tar.gz',
  'preimages': 'preimages.json',
  'predecessor': 'predecessor.json', 'predecessorA': 'predecessor-A.json',
  'predecessorB': 'predecessor-B.json'}
RUNTIME_PREFIX = 'run/shield-native/runtime/'
UNIT_PATHS = frozenset({'run/systemd/system/shield-native-control.service',
  'run/systemd/system/shield-qualification-recovery.service.d/10-native-control.conf'})
UDEV_PATH = 'run/udev/rules.d/99-omarchy-shield-native-control.rules'
POLICY_PATHS = UNIT_PATHS | {UDEV_PATH}
COMMON_RUNTIME = {'native_boot_context.py', 'native_control_protocol.py', 'native_serial_link.py',
  'native_gadget.py', 'guardian_binding.py', 'guardian_client.py', 'usb_root_profile.py',
  'native_phase_plan.py', 'native_layer_reader.py', 'native_layer_writer.py',
  'maintenance_accounts.py', 'usb_candidate_transaction.py', 'native_unit_policy.py'}
# The independently admitted host component's PRIVATE digest belongs in the
# sealed bundle, not in public source or its own archive. This is provenance,
# not a claim that load() measures every already loaded interpreter/library.
USB_STORAGE = {'disk_bytes': 62109253632, 'partition_bytes': 62108188160,
               'partition_start_bytes': 1048576, 'partition_index': 1}
EARLY_FILES = {'init', 'bin/busybox', 'usr/bin/switch_root', 'usr/bin/python3.14',
  'usr/lib/firmware/nvidia/tegra210/xusb.bin'} | {
  'usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/' + name
  for name in ['libcomposite.ko', 'function/u_serial.ko', 'function/usb_f_acm.ko',
               'udc/tegra-xudc.ko']}
HEX = re.compile('[0-9a-f]{64}\\Z')
UUID = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\Z')


def filesystem_magic(path_or_fd):
  """Selected LP64 Linux statfs ABI; only the first native long is consumed."""
  require(ctypes.sizeof(ctypes.c_long) == 8, 'LP64 filesystem ABI required')
  library = ctypes.CDLL(None, use_errno=True)
  output = ctypes.create_string_buffer(256)
  if type(path_or_fd) is int:
    function = library.fstatfs
    function.argtypes = [ctypes.c_int, ctypes.c_void_p]
    argument = path_or_fd
  else:
    function = library.statfs
    function.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    argument = os.fsencode(path_or_fd)
  function.restype = ctypes.c_int
  require(function(argument, ctypes.byref(output)) == 0, 'Filesystem observation failed')
  return struct.unpack_from('=q', output.raw)[0]


def standard_fds():
  """Same fixed contract as bootstrap-io.c; no serial/terminal result sink."""
  for descriptor in range(3):
    info = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    require(info.st_uid == info.st_gid == 0, 'Unowned standard descriptor')
    if descriptor == 1:
      require(stat.S_ISFIFO(info.st_mode) and filesystem_magic(descriptor) == 0x50495045
              and stat.S_IMODE(info.st_mode) == 0o600
              and flags & os.O_ACCMODE == os.O_WRONLY and flags & os.O_NONBLOCK,
              'Expected owned nonblocking anonymous result pipe')
    else:
      require(stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3)
              and filesystem_magic(descriptor) == 0x01021994,
              'Expected devtmpfs null descriptor')


def close_from(first):
  """Selected libc/kernel close_range; no compatibility syscall fallback."""
  library = ctypes.CDLL(None, use_errno=True)
  function = library.close_range
  function.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
  function.restype = ctypes.c_int
  require(function(first, 0xffffffff, 0) == 0, 'Inherited descriptor closure failed')


def sha(value):
  require(type(value) is str and HEX.fullmatch(value) and value != '0' * 64,
          'Invalid bundle digest')
  return value


def canonical(value):
  return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False) + '\n').encode('ascii')


def unique(pairs):
  result = {}
  for key, value in pairs:
    require(key not in result, 'Duplicate bundle JSON key')
    result[key] = value
  return result


def json_bytes(raw):
  def forbidden(_value): raise ValueError('Noninteger bundle JSON number')
  value = json.loads(raw.decode('ascii'), object_pairs_hook=unique,
                     parse_float=forbidden, parse_constant=forbidden)
  require(canonical(value) == raw, 'Noncanonical bundle JSON')
  return value


def freeze(value):
  if type(value) is dict:
    return MappingProxyType({key: freeze(item) for key, item in value.items()})
  if type(value) is list: return tuple(freeze(item) for item in value)
  return value


def plain(value):
  """A caller-owned projection for older exact profile validators/JSON APIs."""
  if isinstance(value, MappingProxyType): return {key: plain(item) for key, item in value.items()}
  if type(value) is tuple: return [plain(item) for item in value]
  return value


def directory(path, private=False):
  path = Path(path)
  info = path.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and not info.st_mode & 0o022 and (not private or stat.S_IMODE(info.st_mode) == 0o700),
          'Unsafe bundle directory')
  return path


def parents(path):
  path = Path(path)
  require(path.is_absolute(), 'Bundle path must be absolute')
  for parent in reversed(path.parents): directory(parent)


def owned_bytes(path, maximum, mode):
  path = Path(path)
  parents(path)
  descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
  with os.fdopen(descriptor, 'rb') as source:
    before = os.fstat(source.fileno())
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == mode and before.st_size <= maximum,
            'Unsafe bundle file')
    raw = source.read(maximum + 1)
    after = os.fstat(source.fileno())
  require(len(raw) == before.st_size <= maximum
          and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
          == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
          'Bundle input changed while reading')
  return raw


def assignment(tokens, key):
  values = [token[len(key) + 1:] for token in tokens if token.startswith(key + '=')]
  require(len(values) == 1 and values[0], 'Missing/duplicate native assignment')
  return values[0]


def source_path(name):
  require(type(name) is str and len(name) <= 512
          and all(part not in {'', '.', '..'} for part in name.split('/')),
          'Unsafe bundle source name')
  path = PurePosixPath(name)
  require(not path.is_absolute() and (name.startswith('run/shield-native/runtime/')
          or name.startswith('usr/lib/omarchy/shield/qualification/')
          or name.startswith('usr/lib/shield-maintenance/') or name in EARLY_FILES
          or name in POLICY_PATHS),
          'Source outside fixed native runtime prefixes')
  return Path('/') / name


@dataclass(frozen=True)
class BootBundle:
  configuration: object
  contexts: object
  key_hashes: object
  profile: object
  raw_sha256: str
  boot_id: str
  epoch: str

  @property
  def phase(self): return self.configuration['phase']

  def guardian_profile(self): return plain(self.profile)

  def key(self, channel):
    require(channel in self.contexts, 'Unknown sealed channel')
    raw = owned_bytes(KEYS / (channel + '.key'), 32, 0o600)
    require(len(raw) == 32 and any(raw) and hashlib.sha256(raw).hexdigest() == self.key_hashes[channel],
            'Channel key differs from sealed bundle')
    return raw

  def input(self, name):
    require(name in self.configuration['inputs'], 'Input not owned by this phase')
    item = self.configuration['inputs'][name]
    # Archive consumers perform their own hash-first bounded admission. Do not
    # eagerly decompress or load a 44 MiB layer just to discover its path.
    return INPUTS / INPUT_PATHS[name], item


def admit(value):
  """Pure schema admission; physical and source observations belong to load()."""
  require(type(value) is dict and set(value) == {
    'format_version', 'configuration', 'configuration_sha256', 'channels', 'key_sha256'},
    'Wrong boot bundle fields')
  require(type(value['format_version']) is int and value['format_version'] == 1,
          'Wrong boot bundle version')
  config = value['configuration']
  require(type(config) is dict and set(config) == {'phase', 'kernel', 'dtb_sha256',
    'guardian_profile_sha256', 'guardian_artifacts_sha256', 'sources', 'inputs',
    'early_runtime_component', 'usb_storage'},
    'Wrong sealed configuration fields')
  phase = config['phase']
  require(type(phase) is str and phase in PHASE_ROLE, 'Wrong native phase')
  require(config['kernel'] == {'image_sha256': IMAGE_SHA256, 'config_sha256': CONFIG_SHA256,
    'release': '7.1.0-shield-bringup'} and config['dtb_sha256'] == DTB_SHA256,
    'Wrong selected kernel or restricted DT')
  component = config['early_runtime_component']
  require(type(component) is dict and set(component) == {'cpio_sha256', 'cpio_bytes'}
          and type(component['cpio_bytes']) is int and 0 < component['cpio_bytes'] <= 64 * 1024**2,
          'Wrong sealed early runtime component provenance')
  sha(component['cpio_sha256'])
  require(type(config['usb_storage']) is dict and config['usb_storage'] == USB_STORAGE
          and all(type(value) is int for value in config['usb_storage'].values()),
          'Wrong selected USB geometry')
  for name in ['guardian_profile_sha256', 'guardian_artifacts_sha256']: sha(config[name])
  epochs = {'early', 'root'} if phase == 'systemd' else {'early'}
  require(type(config['sources']) is dict and set(config['sources']) == epochs,
          'Wrong explicit source epochs')
  for inventory in config['sources'].values():
    require(type(inventory) is dict and 1 <= len(inventory) <= 128,
            'Wrong source inventory')
    for name, item in inventory.items():
      source_path(name)
      require(type(item) is dict and set(item) == {'sha256', 'bytes', 'mode'}
              and type(item['bytes']) is int and 0 < item['bytes'] <= 8 * 1024**2
              and type(item['mode']) is int and item['mode'] in {0o600, 0o644, 0o700, 0o755},
              'Wrong sealed source record')
      sha(item['sha256'])
  for epoch, inventory in config['sources'].items():
    required = {RUNTIME_PREFIX + name for name in COMMON_RUNTIME}
    if epoch == 'early':
      required |= EARLY_FILES | {RUNTIME_PREFIX + 'native-boot.py',
                                RUNTIME_PREFIX + 'native_root_storage.py',
                                RUNTIME_PREFIX + 'native_children.py',
                                RUNTIME_PREFIX + 'native_mounts.py',
                                str(INSTALL / 'qualification_recovery.py').lstrip('/'),
                                RUNTIME_PREFIX + 'shield-internal-ro'}
      if phase == 'systemd':
        required |= {RUNTIME_PREFIX + name for name in
          ['shield-early-health', 'native_unit_policy.py']}
      else:
        required |= {RUNTIME_PREFIX + name for name in
          ['native_worker_reaper.py', 'maintenance-worker.py', 'native_ram_recovery.py',
           'native_work_guard.py', 'native_maintenance.py']}
        required |= {str(INSTALL / name).lstrip('/') for name in
          ['guardian_binding.py', 'guardian_client.py', 'usb_root_profile.py',
           'qualification_recovery.py', 'shield-guardian', 'shield-restart-recovery']}
    else:
      required |= POLICY_PATHS | {RUNTIME_PREFIX + name for name in
        ['native-root-control.py', 'native_cleanup_rpc.py', 'native_unit_policy.py']}
      required |= {str(INSTALL / name).lstrip('/') for name in
        ['guardian_binding.py', 'guardian_client.py', 'usb_root_profile.py',
         'qualification_recovery.py', 'shield-guardian', 'shield-restart-recovery']}
    require(required.issubset(inventory), 'Mandatory native epoch source closure absent')
  require(type(config['inputs']) is dict and set(config['inputs']) == INPUT_NAMES[phase],
          'Wrong phase input set')
  for name, item in config['inputs'].items():
    limit = 64 * 1024**2 if name == 'layer' else 16 * 1024**2
    require(type(item) is dict and set(item) == {'sha256', 'bytes'}
            and type(item['bytes']) is int and 0 < item['bytes'] <= limit,
            'Wrong sealed input record')
    sha(item['sha256'])
  digest = hashlib.sha256(canonical(config)).hexdigest()
  require(sha(value['configuration_sha256']) == digest, 'Inner configuration digest differs')
  names = {'early', 'root'} if phase == 'systemd' else {'early'}
  require(type(value['channels']) is dict and set(value['channels']) == names
          and type(value['key_sha256']) is dict and set(value['key_sha256']) == names,
          'Wrong sealed channels')
  contexts = {}
  for name, item in value['channels'].items():
    require(type(item) is dict and set(item) == {
      'version', 'session_id', 'phase', 'role', 'candidate', 'config_sha256'},
      'Wrong channel context fields')
    context = Context(item['session_id'], item['phase'], item['candidate'], item['config_sha256'], item['version'])
    require(type(item['role']) is int and item['role'] == PHASE_ROLE[phase] == context.role
            and context.phase == phase and context.config_sha256 == digest,
            'Channel phase/role/configuration mismatch')
    sha(value['key_sha256'][name])
    contexts[name] = context
  if phase == 'systemd':
    require(contexts['early'].session_id != contexts['root'].session_id
            and value['key_sha256']['early'] != value['key_sha256']['root'],
            'Root transition must use distinct contexts and keys')
  return config, contexts


def load(*, epoch):
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
          'Native bundle requires root')
  require(os.uname().machine == 'aarch64' and os.uname().release == '7.1.0-shield-bringup',
          'Wrong native architecture/kernel')
  directory(DIRECTORY, private=True)
  directory(RUNTIME, private=True)
  directory(KEYS, private=True)
  require(filesystem_magic('/proc') == 0x9fa0 and filesystem_magic('/sys') == 0x62656572
          and filesystem_magic(DIRECTORY) == 0x01021994,
          'Native proc/sys/RAM filesystem context required')
  raw = owned_bytes(CONFIGURATION, 128 * 1024, 0o600)
  raw_sha = hashlib.sha256(raw).hexdigest()
  tokens = Path('/proc/cmdline').read_text().split()
  require(sha(assignment(tokens, 'shield.native-bundle')) == raw_sha,
          'Bundle does not match the unique boot assignment')
  value = json_bytes(raw)
  config, contexts = admit(value)
  require(type(epoch) is str and epoch in config['sources'], 'Wrong explicit boot epoch')
  expected_pid1 = '/usr/lib/systemd/systemd' if epoch == 'root' else '/usr/bin/python3.14'
  require(os.readlink('/proc/1/exe') == expected_pid1, 'Unexpected PID1 for native epoch')
  profile_raw = owned_bytes(INSTALL / 'profile.json', 64 * 1024, 0o600)
  require(hashlib.sha256(profile_raw).hexdigest() == config['guardian_profile_sha256'],
          'Guardian profile differs from capsule')
  profile = validate(json.loads(profile_raw))
  require(profile['role'] == PHASE_ROLE[config['phase']]
          and all(item.candidate == profile['candidate'] for item in contexts.values())
          and assignment(tokens, 'shield.guardian') == profile['candidate'],
          'Bundle/profile/cmdline candidate mismatch')
  for key, expected in {'shield.first-ram-probe': '1', 'tegra_smmu.reset_inherited': '1',
                        'tegra_smmu.quarantine_gpub_inherited': '1',
                        'watchdog.open_timeout': '240', 'watchdog.stop_on_reboot': '0',
                        'maxcpus': '1', 'nr_cpus': '1', 'cpuidle.off': '1',
                        'initcall_blacklist': 'tegra_cpufreq_init', 'rdinit': '/init'}.items():
    require(assignment(tokens, key) == expected, 'Native boot assignment differs')
  for flag in ['nokaslr', 'clk_ignore_unused', 'regulator_ignore_unused']:
    require(tokens.count(flag) == 1 and not any(token.startswith(flag + '=') for token in tokens),
            'Native fixed boot flag differs')
  if config['phase'] == 'systemd':
    require(assignment(tokens, 'systemd.unit') == 'shield-qualification.target',
            'Explicit bounded systemd target required')
  else:
    require(not any(token == 'systemd.unit' or token.startswith('systemd.unit=') for token in tokens),
            'RAM maintenance cannot select a systemd target')
  dt = Path('/proc/device-tree')
  require((dt / 'compatible').read_bytes() == b'\0'.join(item.encode() for item in BOARD['compatible']) + b'\0'
          and (dt / 'model').read_bytes() == BOARD['model'].encode() + b'\0'
          and (dt / 'chosen/shield,first-ram-probe').read_bytes() == BOARD['stamp'].encode() + b'\0',
          'Exact A04 native DT required')
  artifacts_raw = owned_bytes(INSTALL / 'artifacts.json', 64 * 1024, 0o600)
  require(hashlib.sha256(artifacts_raw).hexdigest() == config['guardian_artifacts_sha256'],
          'Guardian artifacts differ from capsule')
  for name, item in config['sources'][epoch].items():
    data = owned_bytes(source_path(name), item['bytes'], item['mode'])
    require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
            'Sealed native source changed')
  boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  require(UUID.fullmatch(boot_id) and boot_id != '00000000-0000-0000-0000-000000000000',
          'Wrong native boot identity')
  return BootBundle(freeze(config), MappingProxyType(contexts), freeze(value['key_sha256']),
                    freeze(profile), raw_sha, boot_id, epoch)
