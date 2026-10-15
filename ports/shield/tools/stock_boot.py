"""Bounded Android-v1/newc handling for a local stock-kernel inventory image."""
import hashlib
from pathlib import PurePosixPath
import stat
import struct


def aligned(value, size=4):
  return (value + size - 1) // size * size


def read_newc(data):
  entries, offset = {}, 0
  while offset + 110 <= len(data):
    header = data[offset:offset + 110]
    if header[:6] != b'070701':
      raise ValueError('Expected uncompressed newc archive')
    values = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
    mode, size, namesize = values[1], values[6], values[11]
    if not 1 <= namesize <= 4096 or offset + 110 + namesize > len(data):
      raise ValueError('Invalid newc name bounds')
    name_data = data[offset + 110:offset + 110 + namesize]
    if name_data[-1:] != b'\0':
      raise ValueError('Unterminated newc name')
    name = name_data[:-1].decode('utf-8')
    start = aligned(offset + 110 + namesize)
    end = start + size
    if end > len(data):
      raise ValueError('Invalid newc payload bounds')
    if name == 'TRAILER!!!':
      return entries
    if name.startswith('./'):
      name = name[2:]
    if name not in ('.', ''):
      path = PurePosixPath(name)
      if path.is_absolute() or '..' in path.parts or name in entries:
        raise ValueError('Unsafe or duplicate newc path')
      entries[name] = {'mode': mode, 'data': data[start:end], 'rdevmajor': values[9], 'rdevminor': values[10]}
    offset = aligned(end)
  raise ValueError('Missing newc trailer')


def write_newc(entries):
  output = bytearray()
  items = [*sorted(entries.items()), ('TRAILER!!!', {'mode': 0, 'data': b''})]
  for inode, (name, entry) in enumerate(items, 1):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:
      raise ValueError('Unsafe newc path')
    body = entry['data']
    encoded = name.encode() + b'\0'
    fields = [inode, entry['mode'], 0, 0, 1, 0, len(body), 0, 0,
              entry.get('rdevmajor', 0), entry.get('rdevminor', 0), len(encoded), 0]
    output.extend(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields))
    output.extend(encoded)
    output.extend(b'\0' * (aligned(len(output)) - len(output)))
    output.extend(body)
    output.extend(b'\0' * (aligned(len(output)) - len(output)))
  output.extend(b'\0' * (aligned(len(output), 512) - len(output)))
  return bytes(output)


def stock_parts(image):
  if len(image) < 2048 or image[:8] != b'ANDROID!':
    raise ValueError('Expected saved Android image')
  kernel_size, ramdisk_size, second_size = struct.unpack_from('<I', image, 8)[0], struct.unpack_from('<I', image, 16)[0], struct.unpack_from('<I', image, 24)[0]
  page, version = struct.unpack_from('<II', image, 36)
  if page != 2048 or version != 1 or second_size or struct.unpack_from('<I', image, 1632)[0]:
    raise ValueError('Only measured v1/2048 stock format with no second/DTBO is supported')
  start = page + aligned(kernel_size, page)
  if start + ramdisk_size > len(image):
    raise ValueError('Stock payload exceeds image')
  return image[:page], image[page:page + kernel_size], image[start:start + ramdisk_size]


def replace_ramdisk(image, ramdisk):
  header, kernel, _ = stock_parts(image)
  header = bytearray(header)
  command = header[64:576].split(b'\0', 1)[0] + header[608:1632].split(b'\0', 1)[0]
  command += b' rdinit=/init shield.stock-inventory=1'
  if len(command) >= 1536:
    raise ValueError('Stock command line exceeds the v1 limit')
  command = command.ljust(1536, b'\0')
  header[64:576], header[608:1632] = command[:512], command[512:]
  struct.pack_into('<I', header, 16, len(ramdisk))
  digest = hashlib.sha1()
  for payload in (kernel, ramdisk, b'', b''):
    digest.update(payload)
    digest.update(struct.pack('<I', len(payload)))
  header[576:608] = digest.digest().ljust(32, b'\0')
  output = bytes(header) + kernel
  output += b'\0' * (aligned(len(output), 2048) - len(output))
  output += ramdisk
  output += b'\0' * (aligned(len(output), 2048) - len(output))
  return output
