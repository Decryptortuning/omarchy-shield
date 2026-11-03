"""Local readiness policy and owned observation closure, without target effects."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import owner_runtime
spec = importlib.util.spec_from_file_location('owner_ready_target', TOOLS / 'owner-ready.py')
ready = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ready)


class OwnerReadyTests(unittest.TestCase):
  def test_cooling_requires_current_context_and_fresh_sample(self):
    record = dict(state='healthy', context_sha256='a'*64, boottime_ns=1_000_000_000)
    ready.cooling(record, 'a'*64, 4_000_000_000)
    for change, now in [({'context_sha256': 'b'*64}, 2_000_000_000),
                        ({'state': 'warming'}, 2_000_000_000),
                        ({'boottime_ns': True}, 2_000_000_000),
                        ({}, 4_000_000_001), ({}, 999_999_999)]:
      with self.subTest(change=change, now=now), self.assertRaises(ValueError):
        ready.cooling(record | change, 'a'*64, now)

  def mount_data(self):
    names = dict(root='@shield-' + 'a'*32, home='@shield-' + 'a'*32+'-home',
                 log='@shield-' + 'a'*32+'-log')
    # Btrfs subvolumes can have distinct anonymous device numbers.
    lines = []
    for index, mount, purpose, options in [(1, '/', 'root', 'rw,noatime'),
      (2, '/home', 'home', 'rw,nosuid,nodev,noatime'), (3, '/var/log', 'log', 'rw,noatime')]:
      subvol = '/' + names[purpose]
      lines.append(f'{index} 0 0:{index} {subvol} {mount} {options} - btrfs /dev/sda1 rw,subvol={subvol}')
    return '\n'.join(lines), {'filesystem': {'subvolumes': names}}

  def test_explicit_rw_subvolumes_accept_distinct_btrfs_device_numbers(self):
    raw, enrolled = self.mount_data()
    ready.mounts(raw, enrolled)

  def test_wrong_root_home_policy_or_backing_source_is_refused(self):
    raw, enrolled = self.mount_data()
    for value in [raw.replace('rw,nosuid,nodev,noatime', 'rw,nosuid,nodev,noexec'),
                  raw.replace('rw,nosuid,nodev,noatime', 'rw,noatime'),
                  raw.replace('/dev/sda1', '/dev/sdb1', 1),
                  raw.replace(' - btrfs ', ' - ext4 ', 1),
                  raw.replace(' / rw,noatime ', ' / ro,noatime '),
                  raw.replace('/dev/sda1 rw,subvol=', '/dev/sda1 ro,subvol=', 1),
                  raw + '\n' + raw.splitlines()[0], '\n'.join(raw.splitlines()[:2])]:
      with self.subTest(raw=value), self.assertRaises(ValueError): ready.mounts(value, enrolled)

  def test_expired_observation_does_not_spawn(self):
    with patch.object(ready.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
      ready.query(['/usr/bin/systemctl'], 0)
    spawn.assert_not_called()

  def test_query_waits_for_owned_child_and_absent_group(self):
    child = Mock(pid=100, returncode=0)
    child.communicate.return_value = (b'ActiveState=active\n', b'')
    with patch.object(ready.subprocess, 'Popen', return_value=child), \
      patch.object(ready.os, 'killpg', side_effect=ProcessLookupError):
      self.assertEqual(ready.query(['fixed'], ready.time.monotonic()+10), {'ActiveState': 'active'})
    child.communicate.assert_called_once()

  def test_timeout_reaps_then_fails_without_retry_authority(self):
    child = Mock(pid=100, returncode=-9)
    child.communicate.side_effect = [ready.subprocess.TimeoutExpired('fixed', 3), (b'', b'')]
    with patch.object(ready.subprocess, 'Popen', return_value=child), \
      patch.object(ready.os, 'killpg', side_effect=[None, ProcessLookupError]), \
      self.assertRaises(ready.ObservationClosureError):
      ready.query(['fixed'], ready.time.monotonic()+10)
    self.assertEqual(child.communicate.call_count, 2)

  def test_remaining_group_and_unknown_reap_are_fatal(self):
    child = Mock(pid=100, returncode=0)
    child.communicate.return_value = (b'ActiveState=active\n', b'')
    with patch.object(ready.subprocess, 'Popen', return_value=child), \
      patch.object(ready.os, 'killpg', return_value=None), \
      self.assertRaises(ready.ObservationClosureError):
      ready.query(['fixed'], ready.time.monotonic()+10)
    child.communicate.side_effect = ready.subprocess.TimeoutExpired('fixed', 3)
    with patch.object(ready.subprocess, 'Popen', return_value=child), \
      patch.object(ready.os, 'killpg', return_value=None), \
      self.assertRaises(ready.ObservationClosureError):
      ready.query(['fixed'], ready.time.monotonic()+10)

  def test_duplicate_service_fields_refused(self):
    child = Mock(pid=100, returncode=0)
    child.communicate.return_value = (b'ActiveState=active\nActiveState=failed\n', b'')
    with patch.object(ready.subprocess, 'Popen', return_value=child), \
      patch.object(ready.os, 'killpg', side_effect=ProcessLookupError), self.assertRaises(ValueError):
      ready.query(['fixed'], ready.time.monotonic()+10)

  def test_wrong_service_refuses_before_file_or_hardware_observation(self):
    with patch.object(owner_runtime, 'regular') as read, self.assertRaises(ValueError):
      owner_runtime.admit('unregistered.service')
    read.assert_not_called()

  def test_normal_pid1_entry_required_before_files_are_read(self):
    with patch.object(owner_runtime.os, 'getppid', return_value=999), \
      patch.object(owner_runtime, 'regular') as read, self.assertRaises(ValueError):
      owner_runtime.admit('shield-owner-ready.service')
    read.assert_not_called()
