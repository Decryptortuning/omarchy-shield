"""One checked A04 ACM gadget, descriptors before UDC binding, never a shell.

Kernel modules and configfs mounting belong to the fixed PID1 producer. This
module configures only the newly owned, sole gadget; it never tears down or
replaces another gadget. The same gadget survives the standard switch_root.
"""
import os
from pathlib import Path
import select
import stat
import time

from native_boot_context import directory, filesystem_magic
from usb_root_profile import require

CONFIG = Path('/sys/kernel/config')
BASE = CONFIG / 'usb_gadget'
GADGET = BASE / 'shield-native'
UDC = '700d0000.usb'
NUMBERS = {'idVendor': 0x0525, 'idProduct': 0xa4a7, 'bcdUSB': 0x0200,
  'bcdDevice': 0x0100, 'bDeviceClass': 0xef, 'bDeviceSubClass': 0x02,
  'bDeviceProtocol': 0x01, 'configs/c.1/bmAttributes': 0x80,
  'configs/c.1/MaxPower': 2}


def strings(bundle):
  return {'strings/0x409/serialnumber': 'OMARCHY-A04-' + bundle.contexts['early'].session_id[:32],
    'strings/0x409/manufacturer': 'Omarchy Shield development',
    'strings/0x409/product': 'Bounded native control',
    'configs/c.1/strings/0x409/configuration': 'Authenticated observations'}


def admit(bundle):
  require(bundle.epoch in {'early', 'root'} and bundle.phase in {'packages', 'layer', 'systemd'},
          'Wrong gadget context')
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
          'Root gadget owner required')
  directory(CONFIG); directory(BASE)
  require(filesystem_magic(CONFIG) == 0x62656570
          and sorted(os.listdir('/sys/class/udc')) == [UDC], 'Wrong configfs or selected UDC')
  device = (Path('/sys/class/udc') / UDC / 'device').resolve(strict=True)
  require(device.is_relative_to(Path('/sys/devices')) and device.name == UDC
          and (device / 'driver').resolve(strict=True).name == 'tegra-xudc',
          'Wrong A04 gadget controller')


def read(name):
  descriptor = os.open(GADGET / name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
  try:
    require(filesystem_magic(descriptor) == 0x62656570, 'Gadget observation outside configfs')
    raw = os.read(descriptor, 4097)
    require(len(raw) <= 4096 and b'\0' not in raw, 'Oversized gadget observation')
    return raw.decode('ascii').strip()
  finally: os.close(descriptor)


def write(name, text):
  data = (text + '\n').encode('ascii')
  descriptor = os.open(GADGET / name, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
  try:
    require(filesystem_magic(descriptor) == 0x62656570, 'Gadget operation outside configfs')
    require(os.write(descriptor, data) == len(data), 'Uncertain gadget write; never replay')
  finally: os.close(descriptor)


def numeric(name):
  # Selected gadget configfs emits descriptor numbers as 0x-prefixed hex,
  # except MaxPower and the ACM port number, which are decimal.
  value = read(name)
  return int(value, 10 if name.endswith(('MaxPower', 'port_num')) else 16)


def validate(bundle, *, bound):
  admit(bundle)
  require(sorted(os.listdir(BASE)) == [GADGET.name], 'Another gadget exists')
  directory(GADGET, private=True)
  require(sorted(os.listdir(GADGET / 'functions')) == ['acm.usb0']
          and sorted(os.listdir(GADGET / 'configs')) == ['c.1']
          and sorted(os.listdir(GADGET / 'strings')) == ['0x409']
          and sorted(os.listdir(GADGET / 'configs/c.1/strings')) == ['0x409'],
          'Unexpected gadget function/configuration/string language')
  function = GADGET / 'configs/c.1/acm.usb0'
  require(function.is_symlink()
          and function.resolve(strict=True) == GADGET / 'functions/acm.usb0'
          and [p.name for p in (GADGET / 'configs/c.1').iterdir() if p.is_symlink()] == ['acm.usb0'],
          'Wrong gadget function link')
  for name, expected in NUMBERS.items():
    if name == 'bcdUSB' and bound:
      # Selected composite.c GET_DESCRIPTOR mutates this same configfs field:
      # initial 0200; SS-capable USB2 0210; SuperSpeed 0320. Identity stays exact.
      require(numeric(name) in {0x0200, 0x0210, 0x0320}, 'Gadget bound USB version differs')
    else:
      require(numeric(name) == expected, 'Gadget numeric descriptor differs')
  for name, expected in strings(bundle).items():
    require(read(name) == expected, 'Gadget string descriptor differs')
  require(numeric('functions/acm.usb0/port_num') == 0
          and read('UDC') == (UDC if bound else ''), 'Gadget ACM port/binding differs')


def prepare(bundle):
  require(os.getpid() == 1 and bundle.epoch == 'early', 'Only early PID1 prepares the gadget')
  admit(bundle)
  require(not os.listdir(BASE), 'Existing gadget never replaced')
  GADGET.mkdir(mode=0o700)
  # Selected configfs_create_dir uses its own 0755 default, independently of
  # mkdir's mode argument. Establish/read back our private mode explicitly.
  os.chmod(GADGET, 0o700, follow_symlinks=False)
  directory(GADGET, private=True)
  for relative in ['strings/0x409', 'configs/c.1', 'configs/c.1/strings/0x409',
                   'functions/acm.usb0']:
    (GADGET / relative).mkdir(mode=0o700)
  for name, value in NUMBERS.items():
    write(name, str(value) if name.endswith('MaxPower') else hex(value))
    require(numeric(name) == value, 'Gadget descriptor write/readback differs')
  for name, value in strings(bundle).items():
    write(name, value)
    require(read(name) == value, 'Gadget string write/readback differs')
  (GADGET / 'configs/c.1/acm.usb0').symlink_to(GADGET / 'functions/acm.usb0')
  validate(bundle, bound=False)
  # Function creation allocates the dynamically numbered ttyGS0. Do not open it
  # until after bind/configured admission: enumeration/reconfiguration can call
  # gserial_disconnect -> tty_hangup, permanently invalidating an existing fd.
  tty = Path('/dev/ttyGS0')
  info = tty.lstat()
  dev = (Path('/sys/class/tty/ttyGS0/dev')).read_text().strip().split(':')
  require(stat.S_ISCHR(info.st_mode) and info.st_uid == info.st_gid == 0
          and len(dev) == 2 and all(v.isdigit() for v in dev)
          and info.st_rdev == os.makedev(*map(int, dev))
          and filesystem_magic('/dev') == 0x01021994, 'Wrong allocated ACM node')
  os.chmod(tty, 0o600, follow_symlinks=False)


def bind(bundle):
  require(os.getpid() == 1 and bundle.epoch == 'early', 'Only early PID1 binds the gadget')
  validate(bundle, bound=False)
  write('UDC', UDC)  # One irreversible attempt; no unbind/rebind fallback.
  validate(bundle, bound=True)


def wait_configured(bundle, deadline_ns):
  """Actual sysfs change notification; no tty-open, hint or MAC authority.

  Selected udc/core schedules sysfs_notify(..., "state"). POLLPRI|POLLERR
  normally means a changed sysfs value, so seek/read acknowledges it; EPOLLERR
  here is not the tty transport's fatal EPOLLERR. Configured is preparatory:
  composite can set it before all function endpoints are active. Only the later
  SNCR1/PROBE/HELLO/ACK/PING/PONG exchange establishes the software round trip.
  """
  second = 1_000_000_000
  previous = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
  require(type(deadline_ns) is int and 0 < previous < deadline_ns <= 110 * second,
          'Configured discovery outside existing pre-open budget')
  validate(bundle, bound=True)
  descriptor = os.open(Path('/sys/class/udc') / UDC / 'state', os.O_RDONLY | os.O_CLOEXEC)
  try:
    require(filesystem_magic(descriptor) == 0x62656572, 'UDC state is outside sysfs')
    with select.epoll() as events:
      events.register(descriptor, select.EPOLLPRI | select.EPOLLERR | select.EPOLLHUP)
      while True:
        timestamp = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        require(previous <= timestamp < deadline_ns, 'UDC discovery clock/deadline')
        previous = timestamp
        os.lseek(descriptor, 0, os.SEEK_SET)
        state = os.read(descriptor, 65)
        require(0 < len(state) <= 64 and state.endswith(b'\n') and b'\0' not in state,
                'Wrong UDC state observation')
        if state == b'configured\n':
          validate(bundle, bound=True)
          require(time.clock_gettime_ns(time.CLOCK_BOOTTIME) < deadline_ns,
                  'Configured observation completed late')
          return
        remaining = deadline_ns - time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        require(remaining > 0, 'UDC configured deadline')
        changed = events.poll(remaining / second, 1)
        require(changed and not changed[0][1] & select.EPOLLHUP, 'UDC state lost or deadline')
  finally:
    os.close(descriptor)
