#!/usr/bin/env python3
"""Swap one file (the stage binary) inside the current LNX carrier image.

Reuses the parsing/packing helpers of the reviewed 621 packager; everything
else in the image (kernel, recovery DTBO, every other ramdisk record) stays
byte-identical. Output: candidate.img + candidate-LNX-padded.bin in build/.
Usage: repack-stage.py <current-candidate.img> <new-stage-binary> <outdir>
"""
import hashlib, importlib.util, json, lzma, os, stat, struct, sys
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('pc', HERE / 'package-carrier.py')
pc = importlib.util.module_from_spec(spec); spec.loader.exec_module(pc)
STAGE_PATH = 'system/bin/shield-owner-internal-stage'

def sha(b): return hashlib.sha256(b).hexdigest()

def main():
    cur, new_stage, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    out.mkdir(exist_ok=True)
    raw = cur.read_bytes(); stage = new_stage.read_bytes(); pc.static_a64(stage)
    h, k, r, dt = pc.parts(raw)
    expanded = pc.expand(r); items, tail = pc.members(expanded)
    old = {e['name']: e for e in items}
    e = old[STAGE_PATH]; v = e['values']
    assert stat.S_ISREG(v[1]) and stat.S_IMODE(v[1]) == 0o755, 'stage record mode'
    old_stage_sha = sha(e['body'])
    # rebuild the record with the new body, same inode/mode/uid/gid/nlink/name
    inode, mode = v[0], v[1]
    prefix = bytearray(e['prefix']); prefix[54:62] = ('%08x' % len(stage)).encode('ascii')
    rec = bytes(prefix) + stage; rec += b'\0' * (pc.align(len(rec)) - len(rec))
    pieces = [rec if x['name'] == STAGE_PATH else x['record'] for x in items]
    newraw = b''.join(pieces) + tail
    newraw += b'\0' * (pc.align(len(newraw), 512) - len(newraw))
    after, _ = pc.members(newraw); cur_map = {x['name']: x for x in after}
    assert set(cur_map) == set(old), 'entry set changed'
    for name, x in old.items():
        if name == STAGE_PATH:
            nv = cur_map[name]['values']
            assert cur_map[name]['body'] == stage and nv[:6] == x['values'][:6] and nv[7:] == x['values'][7:]
        else:
            assert cur_map[name]['record'] == x['record'], 'unexpected record change: ' + name
    newrd = lzma.compress(newraw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, preset=6)
    assert pc.expand(newrd) == newraw
    nh = bytearray(h); struct.pack_into('<I', nh, 16, len(newrd))
    doff = pc.PAGE + pc.align(len(k), pc.PAGE) + pc.align(len(newrd), pc.PAGE)
    struct.pack_into('<Q', nh, 1636, doff); nh[576:608] = pc.image_id(k, newrd, dt)
    img = bytes(nh) + k; img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img))
    img += newrd; img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img))
    assert len(img) == doff
    img += dt; img += b'\0' * (pc.align(len(img), pc.PAGE) - len(img))
    assert len(img) <= pc.CAPACITY
    xh, xk, xr, xd = pc.parts(img)
    assert xk == k and xd == dt and pc.expand(xr) == newraw
    allowed = set(range(16, 20)) | set(range(576, 608)) | set(range(1636, 1644))
    assert all(a == b or n in allowed for n, (a, b) in enumerate(zip(h, xh)))
    padded = img.ljust(pc.CAPACITY, b'\0')
    (out / 'candidate.img').write_bytes(img); (out / 'candidate-LNX-padded.bin').write_bytes(padded)
    res = {'input_image_sha256': sha(raw), 'old_stage_sha256': old_stage_sha, 'new_stage_sha256': sha(stage),
           'candidate_sha256': sha(img), 'padded_LNX_sha256': sha(padded), 'padded_bytes': len(padded),
           'only_changed_record': STAGE_PATH, 'kernel_and_dtbo_unchanged': True}
    (out / 'repack-result.json').write_text(json.dumps(res, indent=2) + '\n')
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
