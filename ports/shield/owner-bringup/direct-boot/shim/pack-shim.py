#!/usr/bin/env python3
"""Build the shim kernel: shim.bin + mainline Image + DTB, descriptor patched in.
Usage: pack-shim.py shim.bin Image board.dtb out.bin [flags]   (flags: 1 no-watchdog, 2 QEMU uart)"""
import struct, sys
shim, img, dtb = (open(p, 'rb').read() for p in sys.argv[1:4])
flags = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0
def al(n, a): return (n + a - 1) // a * a
img_off = 0x20000                                   # past the shim's bss + 64 KiB stack (checked in the Makefile)
assert len(shim) < img_off
dtb_off = al(img_off + len(img), 0x1000)
total = dtb_off + len(dtb)
buf = bytearray(shim.ljust(img_off, b'\0') + img + b'\0' * (dtb_off - img_off - len(img)) + dtb)
assert buf[0x38:0x3c] == b'ARMd' and buf[0x40:0x48] == b'SHIMPAY1'
struct.pack_into('<Q', buf, 16, total)                       # arm64 header image_size
struct.pack_into('<6Q', buf, 0x48, img_off, len(img), dtb_off, len(dtb), total, flags)
open(sys.argv[4], 'wb').write(buf)
print(sys.argv[4], 'total', total, 'img_off', hex(img_off), 'dtb_off', hex(dtb_off), 'flags', flags)
