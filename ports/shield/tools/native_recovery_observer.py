"""Read-only secure recovery observations and preparation completion content.

No adb reboot/root/remount/push, flashing, kexec, device write or retry exists
here. A completed transport fence is deliberately distinct from this actual
new SOS boot observation. The fixed outer coordinator must retain both and
publish completion under its one attempt journal before another phase starts.
Unqualified source: do not import before the combined source gate closes.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import time
from types import MappingProxyType

from native_boot_context import UUID, canonical, freeze, plain, sha
from native_host_controller import Attempt, Spec
from native_phase_plan import RECEIPT_FIELDS, decode
from usb_root_profile import require

ADB = Path('/mnt/c/Users/JResp/AppData/Local/Android/Sdk/platform-tools/adb.exe')
SECOND = 1_000_000_000
LEGACY_KERNEL = '4.9.141-g9d1bd583388e'
PARTITIONS = {'LNX': 18, 'SOS': 16}
READ_ONLY_SHELL = frozenset({'id -u', 'id -Z', 'uname -r', 'getprop ro.product.device',
  'getprop ro.adb.secure', 'getprop ro.adb.secure.recovery',
  'cat /proc/sys/kernel/random/boot_id', 'cat /proc/cmdline',
  'cat /sys/class/block/mmcblk0/device/type', 'cat /sys/class/block/mmcblk0/size',
  '/system/bin/toybox readlink -f /sys/class/block/mmcblk0/device',
  '/system/bin/toybox readlink -f /sys/devices/sdhci-tegra.3/of_node',
  '/system/bin/toybox readlink -f /sys/devices/sdhci-tegra.3/driver'} | {
    command for name, index in PARTITIONS.items() for command in [
      '/system/bin/toybox readlink -f /dev/block/by-name/' + name,
      'cat /sys/class/block/mmcblk0p' + str(index) + '/size',
      'sha256sum /dev/block/by-name/' + name]} | {
    command for node in ['mmcblk0', 'mmcblk0p18', 'mmcblk0p16'] for command in [
      "/system/bin/toybox stat -c '%f %t %T' /dev/block/" + node,
      'cat /sys/class/block/' + node + '/dev']})
BASELINE_FIELDS = {'utc', 'board', 'LNX', 'SOS', 'historical_native80_and_older_controllers',
                   'current_context_result', 'autonomous_modern_boot'}


def now(): return time.monotonic_ns()


def boot_uuid(value):
  require(type(value) is str and UUID.fullmatch(value)
          and value != '00000000-0000-0000-0000-000000000000', 'Invalid observed boot UUID')
  return value


@dataclass(frozen=True)
class Baseline:
  """Independent current partition contract, not a same-image assumption."""
  raw: bytes
  expected_sha256: str

  def __post_init__(self):
    require(type(self.raw) is bytes and 0 < len(self.raw) <= 64 * 1024
            and hashlib.sha256(self.raw).hexdigest() == sha(self.expected_sha256), 'Recovery baseline differs')
    value = decode(self.raw)
    require(set(value) == BASELINE_FIELDS and value['board'] == 'darcy A04 original T210 A02'
            and value['autonomous_modern_boot'] is False, 'Wrong current recovery baseline scope')
    partitions = {}
    for name, index in PARTITIONS.items():
      item = value[name]
      require(type(item) is dict and set(item) == {'index', 'bytes', 'sha256', 'role'}
              and type(item['index']) is int and item['index'] == index
              and type(item['bytes']) is int and item['bytes'] == 26738688
              and type(item['role']) is str and item['role'], 'Wrong current critical-partition geometry')
      sha(item['sha256'])
      partitions[name] = dict(item)
    object.__setattr__(self, 'partitions', freeze(partitions))


class Observer:
  """One initial observation, then at most one post-transport return window."""
  def __init__(self, baseline, serial, adb_sha256, overall_deadline_ns):
    require(type(baseline) is Baseline and type(serial) is str
            and re.fullmatch('[A-Za-z0-9_-]{1,64}', serial)
            and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
            'Private fixed USB target and WSL root observer required')
    require(type(overall_deadline_ns) is int and now() < overall_deadline_ns <= now() + 900 * SECOND,
            'Wrong unchanged outer observation deadline')
    info = ADB.lstat()
    require(stat.S_ISREG(info.st_mode) and not ADB.is_symlink()
            and hashlib.sha256(ADB.read_bytes()).hexdigest() == sha(adb_sha256), 'Host ADB binary differs')
    self.baseline, self.serial = baseline, serial
    self.adb_sha256, self.deadline = adb_sha256, overall_deadline_ns
    self.previous = now()
    self.initial = self.returned = None
    self.initial_attempted = self.return_attempted = False

  def check(self, cutoff):
    timestamp = now()
    require(0 < self.previous <= timestamp < cutoff <= self.deadline,
            'Recovery observation clock/existing deadline exhausted')
    self.previous = timestamp
    return timestamp

  def call(self, arguments, cutoff, limit=20):
    # Every argv is fixed by this module. No caller supplies shell syntax.
    require(type(arguments) is list and (arguments in [['get-state'], ['wait-for-recovery']]
            or len(arguments) == 2 and arguments[0] == 'shell' and arguments[1] in READ_ONLY_SHELL),
            'Observer refuses any command outside its fixed read-only set')
    require(type(limit) is int and 1 <= limit <= 100, 'Wrong fixed read-only command budget')
    self.check(cutoff)
    command_cutoff = min(cutoff, now() + limit * SECOND)
    require(len(os.listdir('/proc/self/task')) == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            'Read-only client requires a single waitable process owner')
    process = subprocess.Popen([str(ADB), '-s', self.serial, *arguments],
      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
      streams = {stream.fileno(): bytearray() for stream in [process.stdout, process.stderr]}
      pending = set(streams)
      for fd in pending: os.set_blocking(fd, False)
      while pending:
        self.check(command_cutoff)
        ready, _, _ = select.select(list(pending), [], [],
          min(0.25, max(0, (command_cutoff - now()) / SECOND)))
        self.check(command_cutoff)
        for fd in ready:
          try: chunk = os.read(fd, min(4096, 8193 - len(streams[fd])))
          except BlockingIOError: continue
          if not chunk: pending.remove(fd); continue
          streams[fd].extend(chunk)
          require(len(streams[fd]) <= 8192, 'Recovery client stream byte budget exceeded')
      self.check(command_cutoff)
      process.wait(timeout=(command_cutoff - now()) / SECOND)
      self.check(command_cutoff)
      stdout, stderr = [bytes(streams[stream.fileno()]) for stream in [process.stdout, process.stderr]]
    except BaseException:
      # Only this still-owned, unreaped child. A Windows relay/RO device read
      # may remain unknown; never turn timeout into a successful observation.
      if process.poll() is None: process.kill()
      try: process.wait(timeout=1)
      except subprocess.TimeoutExpired: pass
      raise
    finally:
      process.stdout.close(); process.stderr.close()
    self.check(cutoff)
    require(process.returncode == 0 and len(stdout) <= 8192 and len(stderr) <= 8192,
            'Secure recovery read did not complete successfully')
    return stdout.decode('ascii').strip()

  def shell(self, command, cutoff): return self.call(['shell', command], cutoff)

  def block_identity(self, node, cutoff):
    require(node in {'mmcblk0', 'mmcblk0p18', 'mmcblk0p16'}, 'Unknown recovery block target')
    values = self.shell("/system/bin/toybox stat -c '%f %t %T' /dev/block/" + node, cutoff).split()
    require(len(values) == 3 and all(re.fullmatch('[0-9a-fA-F]+', item) for item in values),
            'Recovery block stat differs')
    mode, major, minor = [int(item, 16) for item in values]
    dev = self.shell('cat /sys/class/block/' + node + '/dev', cutoff)
    require(stat.S_ISBLK(mode) and dev == str(major) + ':' + str(minor)
            and major == 179 and minor == {'mmcblk0': 0, 'mmcblk0p18': 18, 'mmcblk0p16': 16}[node],
            'Actual recovery block node does not match selected sysfs dev_t')
    return {'mode': mode, 'major': major, 'minor': minor}

  def snapshot(self, cutoff, *, require_sos):
    started = self.check(cutoff)
    require(self.call(['get-state'], cutoff) == 'recovery', 'Selected USB target is not recovery')
    boot = boot_uuid(self.shell('cat /proc/sys/kernel/random/boot_id', cutoff))
    require(self.shell('id -u', cutoff) == '0'
            and self.shell('id -Z', cutoff) == 'u:r:su:s0'
            and self.shell('uname -r', cutoff) == LEGACY_KERNEL
            and self.shell('getprop ro.product.device', cutoff) == 'darcy'
            and self.shell('getprop ro.adb.secure', cutoff) == '1'
            and self.shell('getprop ro.adb.secure.recovery', cutoff) in {'', '1'},
            'Recovery root/kernel/device/authentication policy differs')
    tokens = self.shell('cat /proc/cmdline', cutoff).split()
    route = [token.split('=', 1)[1] for token in tokens if token.startswith('android.kerneltype=')]
    require(len(route) == 1 and route[0] in {'normal', 'recovery'}
            and (not require_sos or route == ['recovery']), 'Recovery boot route differs')
    parent = self.block_identity('mmcblk0', cutoff)
    require(self.shell('cat /sys/class/block/mmcblk0/size', cutoff) == '30777344'
            and self.shell('cat /sys/class/block/mmcblk0/device/type', cutoff) == 'MMC'
            and re.fullmatch('/sys/devices/sdhci-tegra\\.3/mmc_host/mmc0/mmc0:[0-9a-f]{4}',
              self.shell('/system/bin/toybox readlink -f /sys/class/block/mmcblk0/device', cutoff))
            and self.shell('/system/bin/toybox readlink -f /sys/devices/sdhci-tegra.3/of_node', cutoff)
              == '/sys/firmware/devicetree/base/sdhci@700b0600'
            and self.shell('/system/bin/toybox readlink -f /sys/devices/sdhci-tegra.3/driver', cutoff)
              == '/sys/bus/platform/drivers/sdhci-tegra',
            'Legacy eMMC controller ancestry/geometry differs')
    partitions = {}
    for name, index in PARTITIONS.items():
      expected = self.baseline.partitions[name]
      target = '/dev/block/mmcblk0p' + str(index)
      identity = self.block_identity('mmcblk0p' + str(index), cutoff)
      require(self.shell('/system/bin/toybox readlink -f /dev/block/by-name/' + name, cutoff) == target,
              'Recovery critical-partition alias differs')
      sectors = self.shell('cat /sys/class/block/mmcblk0p' + str(index) + '/size', cutoff)
      require(sectors.isdecimal() and int(sectors) * 512 == expected['bytes'],
              'Recovery critical-partition size differs')
      result = self.shell('sha256sum /dev/block/by-name/' + name, cutoff).split()
      require(result == [expected['sha256'], '/dev/block/by-name/' + name],
              'Recovery critical-partition readback differs')
      require(self.block_identity('mmcblk0p' + str(index), cutoff) == identity,
              'Recovery critical block identity changed during readback')
      partitions[name] = {**{key: expected[key] for key in ['index', 'bytes', 'sha256']},
                          'block_identity': identity}
    require(self.block_identity('mmcblk0', cutoff) == parent, 'Recovery parent block identity changed')
    require(self.call(['get-state'], cutoff) == 'recovery'
            and self.shell('cat /proc/sys/kernel/random/boot_id', cutoff) == boot,
            'Recovery boot changed during the complete read-only observation')
    return freeze({'format_version': 1, 'purpose': 'secure recovery identity observation',
      'baseline_sha256': self.baseline.expected_sha256, 'adb_sha256': self.adb_sha256,
      'boot_id': boot, 'kernel_release': LEGACY_KERNEL, 'device': 'darcy', 'route': route[0],
      'secure_adb_root_observed': True, 'critical_partitions': partitions,
      'started_monotonic_ns': started, 'observed_monotonic_ns': self.check(cutoff),
      'deadline_monotonic_ns': cutoff, 'device_writes': False, 'boot_ready': False})

  def inspect_initial(self):
    require(not self.initial_attempted, 'Initial recovery observation cannot replay')
    self.initial_attempted = True
    # The outer coordinator must first enter the previously qualified SOS
    # route. Observing the passive normal-LNX context is not a handoff grant.
    self.initial = self.snapshot(min(now() + 60 * SECOND, self.deadline), require_sos=True)
    return self.initial

  def observe_return(self, attempt):
    require(type(attempt) is Attempt and self.initial is not None and not self.return_attempted
            and attempt.finished and attempt.completion is not None
            and attempt.process.returncode == 0 and attempt.wait_status is not None
            and os.WIFEXITED(attempt.wait_status) and os.WEXITSTATUS(attempt.wait_status) == 0
            and attempt.pidfd is None and attempt.channel is None,
            'Actual successful transport/process completion required before recovery return')
    self.return_attempted = True
    epoch = attempt.completion['epoch']
    require(epoch == ('root' if attempt.spec.configuration['phase'] == 'systemd' else 'early'),
            'Recovery return terminal epoch differs from the phase')
    context = attempt.spec.contexts[epoch]
    cutoff = min(now() + 100 * SECOND, self.deadline)
    # One event-driven ADB wait, not repeated effect commands or probe replay.
    self.call(['wait-for-recovery'], cutoff, limit=100)
    observed = self.snapshot(cutoff, require_sos=True)
    require(observed['boot_id'] not in {self.initial['boot_id'], boot_uuid(attempt.completion['boot_id'])},
            'Recovery return is not a new boot after both prior epochs')
    self.returned = freeze({**plain(observed), 'purpose': 'secure SOS return observation',
      'initial_boot_id': self.initial['boot_id'], 'native_boot_id': attempt.completion['boot_id'],
      'native_epoch': epoch, 'native_configuration_sha256': context.config_sha256,
      'native_session_id': context.session_id,
      'evidence_sha256': attempt.completion['evidence_sha256']})
    return self.returned

  def preparation_content(self, attempt):
    """Exactly the shared 22-field predecessor; publisher still owns durability.

    The observer must belong to this same attempt. Neither a false phase result
    nor a standalone recovery snapshot can become a positive predecessor.
    This pure content result is NOT a published or next-phase release receipt.
    """
    require(type(attempt) is Attempt and self.returned is not None and attempt.completion is not None,
            'No actual secure SOS return observed')
    spec, completion = attempt.spec, attempt.completion
    require(type(spec) is Spec and completion['phase'] in {'packages', 'layer'}
            and completion['epoch'] == 'early' and completion['retained_fence'] is True
            and self.returned['native_epoch'] == 'early'
            and completion['authenticated_recovery_observed'] is False and completion['boot_ready'] is False
            and self.returned['native_boot_id'] == completion['boot_id']
            and self.returned['native_configuration_sha256'] == spec.contexts['early'].config_sha256
            and self.returned['native_session_id'] == spec.contexts['early'].session_id
            and self.returned['evidence_sha256'] == completion['evidence_sha256'],
            'SOS observation and native attempt differ')
    value = completion['observations']
    require(value['kind'] == 'maintenance-released' and value['phase'] == completion['phase']
            and all(value[key] is True for key in ['phase_passed', 'worker_started', 'worker_reaped',
              'reaper_reaped', 'worker_leaf_empty', 'filesystem_unmounted', 'partition_ro',
              'disk_ro', 'internal_user_ro', 'original_root_profile_preserved'])
            and value['candidate_id'] == spec.plan.manifest['candidate_id']
            and value['filesystem_uuid'] == spec.plan.manifest['filesystem_uuid']
            and value['original_default'] == spec.plan.original_default,
            'Incomplete preparation cannot advance after recovery')
    for name in ['worker_result_sha256', 'journal_sha256']: sha(value[name])
    row = {'format_version': 1, 'purpose': 'native preparation completion',
      'state': 'RELEASED_AND_RECOVERED', 'phase': completion['phase'],
      'filesystem_uuid': value['filesystem_uuid'], 'candidate_id': value['candidate_id'],
      'payload_manifest_sha256': spec.configuration['inputs']['payload']['sha256'],
      'plan_sha256': spec.configuration['inputs']['plan']['sha256'],
      'guardian_candidate': spec.contexts['early'].candidate,
      'boot_id': completion['boot_id'], 'configuration_sha256': spec.contexts['early'].config_sha256,
      'session_id': spec.contexts['early'].session_id, 'evidence_sha256': completion['evidence_sha256'],
      'journal_sha256': value['journal_sha256'], 'worker_result_sha256': value['worker_result_sha256'],
      'original_default': plain(spec.plan.original_default), 'clean_usb_release': True,
      'authenticated_recovery_observed': True,
      'recovery_observation_sha256': hashlib.sha256(canonical(plain(self.returned))).hexdigest(),
      'boot_ready': False, 'physical_powerloss_qualified': False}
    require(set(row) == RECEIPT_FIELDS, 'Producer/shared predecessor fields differ')
    self.check(self.deadline)
    return canonical(row)
