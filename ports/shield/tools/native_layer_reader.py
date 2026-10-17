"""Read an exact pinned artifact from our host producer; never install it.

LayerPin must come from a separately admitted sealed controller/boot config,
never an archive, its sidecar, a network request, or caller-selected CLI fields.
This is not a general untrusted tar parser or physical preimage admission.
"""
from dataclasses import dataclass
from collections.abc import Mapping
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
from types import MappingProxyType
import zlib

from usb_root_profile import require, safe_relative

MAX_ARCHIVE_BYTES = 64 * 1024**2
MAX_TAR_BYTES = 96 * 1024**2
MAX_MANIFEST_BYTES = 4 * 1024**2
MAX_BLOB_BYTES = 16 * 1024**2
MAX_MEMBERS = 10000
PURPOSE = 'host-only exact native qualification layer'


def sha(value):
  require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value)
          and value != '0' * 64, 'Invalid pinned digest')


@dataclass(frozen=True)
class LayerPin:
  archive_sha256: str
  archive_bytes: int
  manifest_sha256: str
  profile_sha256: str
  payload_manifest_sha256: str
  sources: tuple

  def validate(self):
    for value in [self.archive_sha256, self.manifest_sha256, self.profile_sha256,
                  self.payload_manifest_sha256]: sha(value)
    require(type(self.archive_bytes) is int and 0 < self.archive_bytes <= MAX_ARCHIVE_BYTES,
            'Pinned archive exceeds the reviewed reader budget')
    require(type(self.sources) is tuple and 0 < len(self.sources) <= 64, 'Wrong pinned source cohort')
    names = set()
    for row in self.sources:
      require(type(row) is tuple and len(row) == 2, 'Malformed pinned source')
      name, digest = row; safe_relative(name); sha(digest)
      require(name not in names, 'Duplicate pinned source'); names.add(name)


@dataclass(frozen=True)
class LayerContent:
  manifest: Mapping
  blob_ranges: Mapping
  raw_tar: bytes
  physical_preimages_admitted: bool = False
  physical_write_authority: bool = False

  def blob(self, digest):
    offset, size = self.blob_ranges[digest]
    return memoryview(self.raw_tar)[offset:offset + size]  # Read-only bytes.


def freeze(value):
  if isinstance(value, dict): return MappingProxyType({key: freeze(item) for key, item in value.items()})
  if isinstance(value, list): return tuple(freeze(item) for item in value)
  return value


def unique_pairs(pairs):
  result = {}
  for key, value in pairs:
    require(key not in result, 'Duplicate JSON key'); result[key] = value
  return result


def manifest(raw, pin):
  require(hashlib.sha256(raw).hexdigest() == pin.manifest_sha256, 'Manifest pin differs')
  def nonfinite(_value): raise ValueError('Nonfinite JSON value')
  value = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=nonfinite)
  require(type(value) is dict and type(value.get('format_version')) is int
          and value['format_version'] == 1 and value.get('purpose') == PURPOSE
          and value.get('state') == 'HOST_LAYER_PREPARED', 'Wrong producer artifact state')
  require(all(value.get(key) is False for key in
    ['physical_preimages_admitted', 'physical_write_released', 'boot_ready']), 'Artifact claims physical authority')
  require(value.get('sources') == dict(pin.sources) and value.get('profile_sha256') == pin.profile_sha256
          and value.get('payload_manifest_sha256') == pin.payload_manifest_sha256, 'Pinned producer/profile cohort differs')
  require((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode() == raw,
          'Noncanonical own-producer manifest')
  entries = value.get('entries')
  require(type(entries) is dict and 0 < len(entries) <= 12000, 'Excessive destination inventory')
  blobs = {}
  for name, record in entries.items():
    safe_relative(name)
    require(len(name) <= 4096 and type(record) is dict and set(record) == {'identity', 'roles'},
            'Malformed destination descriptor')
    item = record['identity']
    require(type(item) is dict and item.get('type') in {'file', 'directory', 'symlink'}, 'Wrong object type')
    # The manifest hash authenticates all metadata. Applying its owners, modes,
    # links, xattrs, exclusions and target paths still requires the native broker.
    if item['type'] != 'file': continue
    sha(item.get('sha256'))
    size = item.get('bytes')
    require(type(size) is int and 0 <= size <= MAX_BLOB_BYTES, 'Blob exceeds the reviewed reader budget')
    key = 'blobs/' + item['sha256']
    require(key not in blobs or blobs[key] == size, 'Conflicting blob sizes')
    blobs[key] = size
  require(len(blobs) + 1 <= MAX_MEMBERS and sum(blobs.values()) <= MAX_TAR_BYTES,
          'Excessive declared blob inventory')
  return value, blobs


def read_layer(path, pin):
  require(type(pin) is LayerPin, 'Expected a sealed configuration pin')
  pin.validate()
  descriptor = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  with os.fdopen(descriptor, 'rb') as stream:
    info = os.fstat(stream.fileno())
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == pin.archive_bytes,
            'Expected one regular pinned archive')
    compressed = stream.read(pin.archive_bytes + 1)
  # No gzip, tar or JSON parsing precedes this gate. Parsing consumes this same
  # immutable bytes object, never a path reopened after a hash check.
  require(len(compressed) == pin.archive_bytes and hashlib.sha256(compressed).hexdigest() == pin.archive_sha256,
          'Full compressed artifact pin differs')
  decoder = zlib.decompressobj(31)
  try: raw = decoder.decompress(compressed, MAX_TAR_BYTES + 1)
  except zlib.error as error: raise ValueError('Pinned gzip is invalid') from error
  require(len(raw) <= MAX_TAR_BYTES and decoder.eof and not decoder.unused_data
          and not decoder.unconsumed_tail, 'Gzip budget, truncation or member boundary differs')
  del compressed
  seen, ranges = set(), {}
  declared = value = None
  with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
    for item in archive:
      require(len(seen) < MAX_MEMBERS and item.name not in seen and item.isfile()
              and not item.pax_headers and item.uid == item.gid == item.mtime == 0 and item.mode == 0o600,
              'Unexpected own-producer archive member')
      if not seen:
        require(item.name == 'manifest.json' and 0 < item.size <= MAX_MANIFEST_BYTES,
                'Expected first bounded manifest')
        value, declared = manifest(raw[item.offset_data:item.offset_data + item.size], pin)
      else:
        require(item.name in declared and item.size == declared[item.name], 'Undeclared or resized blob')
        data = memoryview(raw)[item.offset_data:item.offset_data + item.size]
        require(len(data) == item.size and hashlib.sha256(data).hexdigest() == item.name[6:], 'Blob hash differs')
        ranges[item.name[6:]] = (item.offset_data, item.size)
      seen.add(item.name)
  require(value is not None and seen == set(declared) | {'manifest.json'}, 'Missing own-producer archive members')
  return LayerContent(freeze(value), MappingProxyType(ranges), raw)
