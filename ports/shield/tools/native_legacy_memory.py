"""Pure review of actual legacy kexec segment output and pinned ARM64 Image.

The fixed outer actor must separately admit the live board/FDT/carveouts, actual
loader exit and kexec_loaded state. This parser grants no execution authority.
Source preparation only; no imports/tests before combined source admission.
"""
import re
import struct

from usb_root_profile import require

MINIMUM = 0x80020000
MAXIMUM_EXCLUSIVE = 0x92cc3000  # Before the qualified legacy framebuffer.


def review_segments(text, initramfs_bytes, image, *, reserved_ranges):
  require(type(text) is str and 0 < len(text) <= 1024**2
          and type(initramfs_bytes) is int and initramfs_bytes > 0
          and type(image) is bytes and len(image) >= 64 and image[56:60] == b'ARM\x64',
          'Actual bounded loader output and complete pinned ARM64 Image required')
  require(type(reserved_ranges) is list and len(reserved_ranges) <= 128
          and all(type(item) is tuple and len(item) == 2
            and all(type(value) is int for value in item) and 0 <= item[0] < item[1] <= 1 << 64
            for item in reserved_ranges), 'Actual persistent reserved ranges required')
  text_offset, image_memory = struct.unpack_from('<QQ', image, 8)
  require(image_memory >= len(image) and image_memory % 4096 == 0,
          'Unreviewed ARM64 Image memory extent')
  auxiliary = set()
  for line in text.splitlines():
    if line.startswith('nr_segments'):
      require(re.fullmatch(r'nr_segments = [0-9]+', line), 'Malformed segment-count report')
    elif line.startswith('kexec_load:'):
      require(re.fullmatch(r'kexec_load: entry = 0x[0-9a-fA-F]+ flags = 0x[0-9a-fA-F]+', line),
              'Malformed loader entry report')
    elif line.startswith('segment['):
      match = re.fullmatch(r'segment\[([0-9]+)\]\.(buf|bufsz|mem|memsz)\s*= 0x[0-9a-fA-F]+', line)
      require(match is not None and 0 <= int(match[1]) < 4, 'Malformed or extra loaded segment report')
      if match[2] == 'buf':
        require(int(match[1]) not in auxiliary, 'Duplicate auxiliary segment buffer report')
        auxiliary.add(int(match[1]))
  require(re.findall(r'^nr_segments = ([0-9]+)$', text, re.M) == ['4']
          and 'kexec_load failed' not in text and 'kexec: load failed' not in text,
          'Expected one successful four-segment loader report')
  parsed = {}
  for index, field, value in re.findall(
      r'^segment\[([0-9]+)\]\.(bufsz|mem|memsz)\s*= (0x[0-9a-fA-F]+)$', text, re.M):
    index = int(index)
    require(field not in parsed.setdefault(index, {}), 'Duplicate loaded segment field')
    parsed[index][field] = int(value, 16)
  require(sorted(parsed) == list(range(4)), 'Missing or unexpected loaded segment')
  segments = []
  for index in range(4):
    item = parsed[index]
    require(set(item) == {'bufsz', 'mem', 'memsz'} and 0 < item['bufsz'] <= item['memsz']
            and item['mem'] % 4096 == item['memsz'] % 4096 == 0
            and MINIMUM <= item['mem'] < item['mem'] + item['memsz'] <= MAXIMUM_EXCLUSIVE,
            'Incomplete, unaligned or framebuffer-overlapping loaded segment')
    require(all(item['mem'] + item['memsz'] <= start or item['mem'] >= end
                for start, end in reserved_ranges), 'Loaded segment overlaps an actual persistent reservation')
    segments.append({'index': index, **item})
  segments.sort(key=lambda item: item['mem'])
  for left, right in zip(segments, segments[1:]):
    require(left['mem'] + left['memsz'] <= right['mem'], 'Loaded segments overlap')
  kernel = [item for item in segments if item['bufsz'] == len(image) and item['memsz'] == image_memory]
  initrd = [item for item in segments if item['bufsz'] == initramfs_bytes]
  require(len(kernel) == len(initrd) == 1 and kernel[0] is not initrd[0]
          and (kernel[0]['mem'] - text_offset) % (2 * 1024 * 1024) == 0,
          'Loaded Image/initramfs extent or kernel alignment differs')
  entries = re.findall(r'^kexec_load: entry = (0x[0-9a-fA-F]+) flags = (0x[0-9a-fA-F]+)$', text, re.M)
  require(len(entries) == 1, 'Unique actual loader entry required')
  entry, flags = [int(value, 16) for value in entries[0]]
  require(flags == 0xB70000, 'Only ordinary AArch64 kexec load flags admitted')
  rest = [item for item in segments if item not in kernel + initrd]
  entry_segment = [item for item in rest if item['mem'] <= entry < item['mem'] + item['bufsz']]
  require(len(entry_segment) == 1 and entry % 4 == 0, 'Entry is not inside one loaded, aligned buffer')
  dt = [item for item in rest if item not in entry_segment]
  require(len(dt) == 1 and dt[0]['memsz'] <= 2 * 1024 * 1024,
          'Expected one bounded remaining DTB-candidate segment')
  return {'segments': segments, 'entry': entry, 'flags': flags, 'placement_review_passed': True,
          'segment_content_types_independently_verified': False,
          'persistent_reserved_ranges_checked': [list(item) for item in reserved_ranges],
          'device_execution_authorized_by_this_tool': False}
