"""Shared local OWNER service admission. No hardware or process effects.

The loader owns pre-execution source admission. These runtime checks bind the
service to that boot context and catch wrong-root or changed-file conditions;
they do not measure already executed Python or library code.
"""
from dataclasses import dataclass
from pathlib import Path
import ctypes
import hashlib
import json
import os
import re
import stat
import sys

from owner_profile import require, validate, validate_context

INSTALL = Path('/usr/lib/omarchy/shield/owner')
RUNTIME = Path('/run/shield-owner')
SYSFS_MAGIC, TMPFS_MAGIC = 0x62656572, 0x01021994
PROGRAMS = {'shield-owner-ethernet.service': 'owner-network.py',
            'shield-owner-thermal.service': 'owner-thermal.py',
            'shield-owner-ready.service': 'owner-ready.py'}


def decode(raw):
  def pairs(rows):
    result = {}
    for key, value in rows:
      require(key not in result, 'Duplicate JSON key')
      result[key] = value
    return result
  return json.loads(raw, object_pairs_hook=pairs)


def magic(fd):
  library = ctypes.CDLL(None, use_errno=True)
  library.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
  library.fstatfs.restype = ctypes.c_int
  data = (ctypes.c_long * 32)()
  require(library.fstatfs(fd, ctypes.byref(data)) == 0, 'Filesystem observation failed')
  return data[0]


def regular(path, limit, mode):
  fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
  try:
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1
            and info.st_size <= limit, 'Unowned OWNER file')
    chunks, total = [], 0
    while total <= limit:
      value = os.read(fd, min(65536, limit + 1 - total))
      if not value:
        break
      chunks.append(value)
      total += len(value)
    require(total == info.st_size and total <= limit, 'OWNER file size changed')
    return b''.join(chunks)
  finally:
    os.close(fd)


def sysfs(path, limit=4096, prefix=False):
  fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
  try:
    require(magic(fd) == SYSFS_MAGIC, 'Observation is outside sysfs')
    raw = os.read(fd, limit if prefix else limit + 1)
    require(len(raw) <= limit, 'Sysfs observation exceeds bound')
    return raw
  finally:
    os.close(fd)


@dataclass(frozen=True)
class Admitted:
  enrollment: dict
  context: dict
  digest: str
  runtime_fd: int  # The caller owns and closes this read-only directory fd.


def admit(unit):
  require(unit in PROGRAMS and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0
          and os.getppid() == 1 and sys.argv[1:] == ['--run'], 'OWNER system service required')
  require(Path('/proc/1/exe').resolve(strict=True) == Path('/usr/lib/systemd/systemd')
          and Path('/proc/self/cgroup').read_text().strip() == '0::/system.slice/' + unit
          and re.fullmatch('[0-9a-f]{32}', os.environ.get('INVOCATION_ID', '')),
          'Wrong OWNER service context')
  require(os.uname().release == '7.1.0-shield-bringup', 'Matched kernel ABI required')
  require(INSTALL.resolve(strict=True) == INSTALL and RUNTIME.resolve(strict=True) == RUNTIME,
          'OWNER directories redirected')
  info = RUNTIME.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == 0o700, 'Private OWNER runtime directory required')
  raw_context = regular(RUNTIME / 'context.json', 128 * 1024, 0o600)
  context = decode(raw_context)
  digest = hashlib.sha256(raw_context).hexdigest()
  tokens = Path('/proc/cmdline').read_text().split()
  for prefix, value in [('shield.omarchy-owner=', 'shield.omarchy-owner=1'),
      ('shield.owner-context=', 'shield.owner-context=' + digest),
      ('systemd.unit=', 'systemd.unit=graphical.target')]:
    require([x for x in tokens if x.startswith(prefix)] == [value], 'Wrong OWNER boot binding')
  raw = regular(INSTALL / 'enrollment.json', 128 * 1024, 0o600)
  enrolled = validate(decode(raw))
  validate_context(context, enrolled)
  require(context['enrollment_sha256'] == hashlib.sha256(raw).hexdigest(),
          'OWNER enrollment differs from boot context')
  for name in ('owner_profile.py', 'owner_runtime.py', PROGRAMS[unit]):
    source = regular(INSTALL / name, 1024 * 1024, 0o644)
    require(hashlib.sha256(source).hexdigest() == context['sources_sha256'][name],
            'OWNER runtime source differs')
  fd = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    require(magic(fd) == TMPFS_MAGIC, 'OWNER runtime is not RAM')
  except BaseException:
    os.close(fd)
    raise
  return Admitted(enrolled, context, digest, fd)
