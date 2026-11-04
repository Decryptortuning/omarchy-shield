#!/usr/bin/env python3
"""Write an Android sparse image that contains RAW chunks only (no FILL, no DONT_CARE).

Why: the Shield (Darcy, T210) bootloader's `fastboot flash` sparse writer corrupts FILL
chunks. Host fastboot turns runs of a repeated 32-bit word in a raw image into FILL
chunks, so `fastboot flash system APP.img` silently damaged the kernel Image inside the
APP boot set on 2026-11-03 and the carrier refused every boot (whole-artifact-hash).
An image made of RAW chunks only is passed through unchanged and never hits that path.

Usage: make-rawsparse.py <raw.img> <out.sparse.img> [blocks-per-chunk]
Default 7680 blocks (30 MiB) keeps each chunk under the bootloader's 32 MiB
max-download-size. The output is verified by decoding it back to the input.
"""
import hashlib, struct, sys

def main():
    src, dst = sys.argv[1], sys.argv[2]
    per = int(sys.argv[3]) if len(sys.argv) > 3 else 7680
    block = 4096
    data = open(src, 'rb').read()
    if len(data) % block:
        sys.exit('input size is not a multiple of 4096')
    total = len(data) // block
    chunks = (total + per - 1) // per
    with open(dst, 'wb') as out:
        out.write(struct.pack('<IHHHHIIII', 0xED26FF3A, 1, 0, 28, 12, block, total, chunks, 0))
        for c in range(chunks):
            n = min(per, total - c * per)
            out.write(struct.pack('<HHII', 0xCAC1, 0, n, 12 + n * block))
            out.write(data[c * per * block:(c * per + n) * block])
    sparse = open(dst, 'rb').read()
    magic, _, _, _, _, bs, tb, tc, _ = struct.unpack_from('<IHHHHIIII', sparse, 0)
    pos, back = 28, bytearray()
    for _ in range(tc):
        kind, _, n, size = struct.unpack_from('<HHII', sparse, pos)
        if kind != 0xCAC1 or size != 12 + n * bs:
            sys.exit('verification failed: non-RAW chunk')
        back += sparse[pos + 12:pos + size]
        pos += size
    if magic != 0xED26FF3A or bytes(back) != data or pos != len(sparse):
        sys.exit('verification failed: decoded image differs')
    print(f'{dst}: {tc} RAW chunks, {total} blocks, sha256 {hashlib.sha256(sparse).hexdigest()}')

if __name__ == '__main__':
    main()
