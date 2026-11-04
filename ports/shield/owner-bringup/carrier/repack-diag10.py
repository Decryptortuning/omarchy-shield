"""Diagnostic-only carrier for `fastboot boot`: from a v8 image, stop the stage from
starting, add the USB-role script, start the diagnostic at boot, and append
androidboot.selinux=permissive to the boot image command line. Usage: in.img out.img"""
import importlib.util, lzma, stat, struct, sys, hashlib
from pathlib import Path
HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('pc', HERE / 'package-carrier.py'); pc = importlib.util.module_from_spec(spec); spec.loader.exec_module(pc)
raw = Path(sys.argv[1]).read_bytes(); h, k, r, dt = pc.parts(raw); items, tail = pc.members(pc.expand(r))
RC = 'shield-owner-internal.rc'; ADD = 'system/bin/shield-usbrole.sh'
m = {x['name']: x for x in items}; assert ADD not in m
old = m[RC]['body']
body = old + (HERE / 'diag/diag10.rc').read_bytes()
inode = max(x['values'][0] for x in items) + 1; pieces = []
for x in items:
    if x['name'] == RC:
        pre = bytearray(x['prefix']); pre[54:62] = ('%08x' % len(body)).encode(); rec = bytes(pre) + body
        pieces.append(rec + b'\0' * (pc.align(len(rec)) - len(rec)))
    elif x['name'] == 'TRAILER!!!':
        pieces.append(pc.added(ADD, stat.S_IFREG | 0o755, (HERE / 'diag/shield-usbrole.sh').read_bytes(), inode)); pieces.append(x['record'])
    else: pieces.append(x['record'])
newraw = b''.join(pieces) + tail; newraw += b'\0' * (pc.align(len(newraw), 512) - len(newraw))
newrd = lzma.compress(newraw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, preset=6)
nh = bytearray(h); struct.pack_into('<I', nh, 16, len(newrd))
doff = pc.PAGE + pc.align(len(k), pc.PAGE) + pc.align(len(newrd), pc.PAGE); struct.pack_into('<Q', nh, 1636, doff)
cmd = bytes(nh[64:576]).split(b'\0')[0]; print('old cmdline:', cmd)
new = (cmd + b' androidboot.selinux=permissive').strip(); assert len(new) < 512
nh[64:576] = new.ljust(512, b'\0'); nh[576:608] = pc.image_id(k, newrd, dt)
img = bytes(nh) + k; img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img)); img += newrd
img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img)); img += dt; img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img))
xh, xk, xr, xd = pc.parts(img); assert xk == k and xd == dt and pc.expand(xr) == newraw
Path(sys.argv[2]).write_bytes(img); print('new cmdline:', new, len(img), hashlib.sha256(img).hexdigest()[:16])
