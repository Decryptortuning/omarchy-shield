#!/usr/bin/env python3
"""Pack a direct-boot image for LNX or SOS: Android v1 header, kernel = gzip(shim+Image+DTB),
ramdisk = loader initramfs, no recovery_dtbo (ignored on T210). Usage: pack-boot.py kernel.gz loader.cpio.gz out.img"""
import hashlib, struct, sys
k, r = open(sys.argv[1], 'rb').read(), open(sys.argv[2], 'rb').read()
PAGE, CAP = 2048, 26738688
pad = lambda b: b + b'\0' * (-len(b) % PAGE)
cmd = (b'console=tty0 loglevel=7 ignore_loglevel rdinit=/init nokaslr clk_ignore_unused regulator_ignore_unused '
       b'maxcpus=4 nr_cpus=4 tegra_smmu.reset_inherited=1 '
       b'tegra_smmu.quarantine_gpub_inherited=1 watchdog.open_timeout=240 watchdog.stop_on_reboot=0 '
       b'pstore.compress=none modprobe.blacklist=r8169,pci_tegra systemd.unit=graphical.target '
       b'systemd.log_target=kmsg systemd.log_level=info panic=10 shield.boot=direct')
assert len(cmd) < 512, len(cmd)
ident = hashlib.sha1(k + struct.pack('<I', len(k)) + r + struct.pack('<I', len(r)) + struct.pack('<I', 0)).digest().ljust(32, b'\0')
h = struct.pack('<8s10I16s512s32s1024sIQI', b'ANDROID!', len(k), 0x10008000, len(r), 0x11000000, 0, 0, 0x10000100,
                PAGE, 1, 0x1e0001a9, b'', cmd, ident, b'', 0, 0, 1648)
img = pad(h) + pad(k) + pad(r)
assert len(img) <= CAP
padded = img.ljust(CAP, b'\0'); open(sys.argv[3], 'wb').write(padded)
print(sys.argv[3], 'used', len(img), 'of', CAP, 'cmdline', len(cmd), 'sha256', hashlib.sha256(padded).hexdigest())
