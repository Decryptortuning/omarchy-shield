"""Add the diagnostic script + service to a carrier image. Only shield-owner-internal.rc
changes (text appended) and one new record (system/bin/shield-diag.sh) is added; kernel,
DTBO and every other ramdisk record stay byte-identical.
Usage: repack-diag.py <candidate.img> <outdir>"""
import hashlib, importlib.util, json, lzma, stat, struct, sys
from pathlib import Path
HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('pc', HERE / 'package-carrier.py'); pc = importlib.util.module_from_spec(spec); spec.loader.exec_module(pc)
sha = lambda b: hashlib.sha256(b).hexdigest()
cur, out = Path(sys.argv[1]), Path(sys.argv[2]); out.mkdir(exist_ok=True)
raw = cur.read_bytes(); h, k, r, dt = pc.parts(raw); items, tail = pc.members(pc.expand(r))
RC = 'shield-owner-internal.rc'; SCRIPTS = {'system/bin/shield-diag.sh': 'diag/shield-diag.sh', 'system/bin/shield-netadb.sh': 'diag/shield-netadb.sh'}
names = [x['name'] for x in items]; assert RC in names and not set(SCRIPTS) & set(names)
rcadd = (HERE / 'diag/diag.rc').read_bytes(); bodies = {n: (HERE / f).read_bytes() for n, f in SCRIPTS.items()}
inode = max(x['values'][0] for x in items) + 1
pieces = []
for x in items:
    if x['name'] == RC:
        body = x['body'] + rcadd; pre = bytearray(x['prefix']); pre[54:62] = ('%08x' % len(body)).encode()
        rec = bytes(pre) + body; pieces.append(rec + b'\0' * (pc.align(len(rec)) - len(rec)))
    elif x['name'] == 'TRAILER!!!':
        for j, (n, b) in enumerate(sorted(bodies.items())): pieces.append(pc.added(n, stat.S_IFREG | 0o755, b, inode + j))
        pieces.append(x['record'])
    else:
        pieces.append(x['record'])
newraw = b''.join(pieces) + tail; newraw += b'\0' * (pc.align(len(newraw), 512) - len(newraw))
after, _ = pc.members(newraw); m = {x['name']: x for x in after}
for x in items:
    if x['name'] != RC: assert m[x['name']]['record'] == x['record'], x['name']
assert m[RC]['body'].endswith(rcadd) and all(m[n]['body'] == b for n, b in bodies.items())
newrd = lzma.compress(newraw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, preset=6)
nh = bytearray(h); struct.pack_into('<I', nh, 16, len(newrd))
doff = pc.PAGE + pc.align(len(k), pc.PAGE) + pc.align(len(newrd), pc.PAGE)
struct.pack_into('<Q', nh, 1636, doff); nh[576:608] = pc.image_id(k, newrd, dt)
img = bytes(nh) + k; img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img)); img += newrd
img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img)); assert len(img) == doff
img += dt; img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img)); assert len(img) <= pc.CAPACITY
xh, xk, xr, xd = pc.parts(img); assert xk == k and xd == dt and pc.expand(xr) == newraw
(out / 'candidate.img').write_bytes(img); padded = img.ljust(pc.CAPACITY, b'\0'); (out / 'candidate-LNX-padded.bin').write_bytes(padded)
print(json.dumps({'base_sha256': sha(raw), 'padded_sha256': sha(padded), 'bytes': len(padded)}))
