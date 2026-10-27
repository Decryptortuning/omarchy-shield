"""Durable internal startup acknowledgment, called by owner-ready.
Caller must admit new INTERNAL context, bootstore mount/block identity,
current-generation ready.json/cooling/PID1 ownership and exact cmdline tokens.
No lease, PC connection, DHCP/SSH proof or continued healthy expiry is created.
"""
import fcntl
import os
import re
import stat
import struct
import time
import uuid
from pathlib import Path

MAGIC = b'SHOWNR1\0'
SIZE = 48

def require(value, why):
    if not value:
        raise ValueError(why)

def record(generation, sequence):
    require(type(generation) is str and re.fullmatch('[0-9a-f]{64}', generation), 'generation')
    require(type(sequence) is int and 0 < sequence < 2**64, 'sequence')
    return MAGIC + bytes.fromhex(generation) + struct.pack('<Q', sequence)

def read_record(dirfd, name):
    try:
        fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK, dir_fd=dirfd)
    except FileNotFoundError:
        return None
    try:
        a = os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_uid == a.st_gid == 0 and
                stat.S_IMODE(a.st_mode) == 0o600 and a.st_nlink == 1 and a.st_size == SIZE,
                'record metadata')
        raw = bytearray()
        while len(raw) <= SIZE:
            chunk = os.read(fd, SIZE+1-len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        b = os.fstat(fd)
        require((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
                (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'record changed')
        require(len(raw) == SIZE and raw[:8] == MAGIC and struct.unpack_from('<Q', raw, 40)[0] > 0,
                'record format')
        return bytes(raw)
    finally:
        os.close(fd)

def acknowledge(admitted_boot_dirfd, generation, sequence):
    """Called once AFTER actual normal local readiness by a ROOT-admitted owner.
    fd is for exact APP ext4 /boot/shield-owner/state already bound to profile;
    checking a directory inode here alone is not filesystem/partition admission.
    """
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'root')
    want = record(generation, sequence)
    a = os.fstat(admitted_boot_dirfd)
    require(stat.S_ISDIR(a.st_mode) and a.st_uid == a.st_gid == 0 and
            stat.S_IMODE(a.st_mode) == 0o700, 'state directory')
    fcntl.flock(admitted_boot_dirfd, fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:
        require(read_record(admitted_boot_dirfd, 'pending') == want, 'current pending')
        previous = read_record(admitted_boot_dirfd, 'healthy')
        require(previous != want, 'ack already consumed')
        previous_sequence = 0 if previous is None else struct.unpack_from('<Q', previous, 40)[0]
        require(sequence == previous_sequence + 1, 'nonmonotonic pending sequence')
        fd = os.open('healthy.next', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|
                     os.O_CLOEXEC, 0o600, dir_fd=admitted_boot_dirfd)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(want)
            while view:
                n = os.write(fd, view)
                require(n > 0, 'short healthy write')
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename('healthy.next', 'healthy', src_dir_fd=admitted_boot_dirfd,
                  dst_dir_fd=admitted_boot_dirfd)
        os.fsync(admitted_boot_dirfd)
        require(read_record(admitted_boot_dirfd, 'healthy') == want, 'healthy readback')
        # Leave matching pending+healthy. Next legacy claim can retire only this
        # acknowledged pair and derive monotonic sequence from retained healthy.
        return {'durable_startup_ack_written': True, 'runtime_expiry_created': False}
    finally:
        fcntl.flock(admitted_boot_dirfd, fcntl.LOCK_UN)


def _bounded(path, maximum=131072):
    fd = os.open(path, os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        out = bytearray()
        while len(out) <= maximum:
            raw = os.read(fd, min(65536, maximum+1-len(out)))
            if not raw:
                break
            out.extend(raw)
        require(len(out) <= maximum, 'bounded observation')
        return bytes(out)
    finally:
        os.close(fd)

def _token(text, key):
    values = [value[len(key):] for value in text.split() if value.startswith(key)]
    require(len(values) == 1, 'unique internal attempt token')
    return values[0]

def _owned_dir(fd, mode=None):
    st = os.fstat(fd)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == st.st_gid == 0 and
            not st.st_mode & 0o022 and (mode is None or stat.S_IMODE(st.st_mode) == mode),
            'owned boot directory')
    return st

def acknowledge_ready(admitted, ready):
    """Internal owner-ready hook for the enrolled APP boot store.
    Called only for internal purpose after existing observe() and RAM ready
    fsync; no standalone main, no mount/format/PC/firmware operation.
    """
    boot = admitted.enrollment['boot_store']
    require(type(boot) is dict and set(boot) == {
        'filesystem_uuid', 'partition_uuid', 'filesystem_type', 'partition_index',
        'partition_label', 'partition_start_bytes', 'partition_bytes', 'generation_id'}, 'boot_store ABI')
    require(boot['filesystem_type'] == 'ext4' and boot['partition_index'] == 19 and
            boot['partition_label'] == 'APP', 'internal APP binding')
    for key in ['filesystem_uuid', 'partition_uuid']:
        require(type(boot[key]) is str and str(uuid.UUID(boot[key])) == boot[key], 'canonical boot UUID')
    generation = boot['generation_id']
    require(type(generation) is str and re.fullmatch('[0-9a-f]{64}', generation), 'generation_id')
    cmdline = _bounded('/proc/cmdline', 8192).decode('ascii')
    require(_token(cmdline, 'shield.owner-internal-generation=') == generation, 'current generation')
    sequence_hex = _token(cmdline, 'shield.owner-internal-sequence=')
    require(re.fullmatch('[0-9a-f]{16}', sequence_hex), 'sequence encoding')
    sequence = int(sequence_hex, 16)
    require(type(ready) is dict and ready['purpose'] == 'omarchy-shield-owner' and
            ready['owner_id'] == admitted.enrollment['owner_id'] and
            ready['context_sha256'] == admitted.digest and ready['local_startup_ready'] is True and
            ready['PID1_watchdog_fd_observed'] is True and type(ready['boottime_ns']) is int and
            0 < ready['boottime_ns'] <= time.clock_gettime_ns(time.CLOCK_BOOTTIME), 'current local readiness')
    # Whole-table and physical eMMC admission stays in NativeEmmcRoot.admit_table
    # and initial RAM. Here rebind exact mounted APP partition before ACK write.
    device = Path('/dev/mmcblk0p19')
    st = device.stat()
    require(stat.S_ISBLK(st.st_mode), 'APP block node')
    for base, key in [('/dev/disk/by-uuid', 'filesystem_uuid'),
                      ('/dev/disk/by-partuuid', 'partition_uuid')]:
        target = Path(base) / boot[key]
        require(target.is_symlink() and target.resolve(strict=True) == device.resolve(strict=True), 'APP UUID alias')
    start = int(_bounded('/sys/class/block/mmcblk0p19/start', 64).decode('ascii').strip())
    size = int(_bounded('/sys/class/block/mmcblk0p19/size', 64).decode('ascii').strip())
    require(start*512 == boot['partition_start_bytes'] and size*512 == boot['partition_bytes'], 'APP geometry')
    mount_rows = []
    for line in _bounded('/proc/self/mountinfo').decode('ascii').splitlines():
        left, right = line.split(' - ', 1)
        fields, suffix = left.split(), right.split()
        require(len(fields) >= 6 and len(suffix) >= 3, 'mountinfo fields')
        if fields[4] == '/boot':
            mount_rows.append((fields, suffix))
    require(len(mount_rows) == 1, 'unique boot mount')
    fields, suffix = mount_rows[0]
    expected_dev = str(os.major(st.st_rdev)) + ':' + str(os.minor(st.st_rdev))
    require(fields[2] == expected_dev and fields[3] == '/' and suffix[0] == 'ext4' and
            {'rw', 'nosuid', 'nodev', 'noexec', 'noatime'} <= set(fields[5].split(',')), 'admitted ext4 mount')
    opened = []
    try:
        fd = os.open('/boot', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        opened.append(fd)
        root = _owned_dir(fd)
        require(root.st_dev == st.st_rdev, 'APP mounted device')
        for component in ['shield-owner', 'state']:
            fd = os.open(component, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fd)
            opened.append(fd)
            require(_owned_dir(fd, 0o700).st_dev == st.st_rdev, 'state stays on APP')
        return acknowledge(fd, generation, sequence)
    finally:
        for fd in reversed(opened):
            os.close(fd)
