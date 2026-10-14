#!/usr/bin/env python3
"""Fetch the pinned signed ARM base without running installation code."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


def main():
    port = Path(__file__).resolve().parent
    lock = json.loads((port / 'userspace.lock.json').read_text())['rootfs']
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-root', required=True, type=Path)
    root = parser.parse_args().build_root.resolve()
    files = [(lock['url'], lock['sha256'], root / 'downloads' / lock['filename']),
             (lock['signature_url'], lock['signature_sha256'], root / 'repository-metadata/rootfs-sig'),
             (lock['keyring_url'], lock['keyring_sha256'], root / 'repository-metadata/alarm-key')]
    for url, expected, path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            temporary = path.with_name(path.name + '.part')
            with urllib.request.urlopen(url, timeout=60) as response, temporary.open('wb') as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
            with temporary.open('rb') as source:
                actual = hashlib.file_digest(source, 'sha256').hexdigest()
            if actual != expected:
                raise SystemExit(f'Input changed upstream; review its signature before updating the lock: {url}')
            temporary.rename(path)
        with path.open('rb') as source:
            actual = hashlib.file_digest(source, 'sha256').hexdigest()
        if actual != expected:
            raise SystemExit(f'Checksum mismatch: {path}')
        print(f'OK {path.name}')


if __name__ == '__main__':
    main()
