"""Fresh bounded work admission without one guardian socket round trip per file.

Every call rechecks the actual BOOTTIME, pinned owner pidfd and all existing
work/health/reserve predicates. A status observation is cached for at most half
a second, below the existing one-second status freshness limit. This neither
feeds the watchdog nor renews a deadline. PID1 independently consumes recovery
notifications and owns immediate worker cancellation through its sole cgroup.
"""
import select

from guardian_client import GuardianClient, SECOND, STATUS, require_work_status
from native_serial_link import now
from usb_root_profile import require


class WorkGuard:
  def __init__(self, bundle, owner_pid, *, minimum_seconds=60):
    require(bundle.epoch == 'early' and bundle.phase in {'packages', 'layer'}
            and type(owner_pid) is int and owner_pid > 1
            and type(minimum_seconds) is int and 0 <= minimum_seconds <= 180,
            'Wrong fixed maintenance work owner/reserve')
    self.client = GuardianClient(bundle.profile['candidate'], bundle.boot_id, 1)
    self.owner = owner_pid
    self.minimum = minimum_seconds
    self.previous = now()
    self.status = None
    self.failed = False

  def __call__(self, seconds=None):
    try:
      require(not self.failed, 'Discarded work admission')
      reserve = self.minimum if seconds is None else seconds
      require(type(reserve) is int and 0 <= reserve <= 180, 'Wrong fixed stage reserve')
      timestamp = now()
      require(0 < self.previous <= timestamp, 'Work admission clock regressed')
      self.previous = timestamp
      if self.status is None or timestamp - self.status['now_ns'] >= SECOND // 2:
        self.status = self.client.request(STATUS)
        require(self.client.owner_pid == self.owner, 'Work guardian is not the PID1-owned child')
        timestamp = now()
        require(timestamp >= self.previous, 'Work status completed after clock regression')
        self.previous = timestamp
      require(self.client.owner_pidfd is not None
              and not select.select([self.client.owner_pidfd], [], [], 0)[0],
              'Work guardian exited')
      return require_work_status(self.status, reserve, timestamp)
    except BaseException:
      self.failed = True
      raise

  def close(self): self.client.close()
