#!/bin/bash
# Build only; no chroot, device access or target execution.
set -euo pipefail
port=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
archive=${1:?Pass the pinned BusyBox archive}
destination=${2:?Pass a new build directory}
[[ ! -e $destination ]] || { echo 'Use a new BusyBox build directory' >&2; exit 1; }
python3 - "$port/stock-bootstrap.lock.json" "$archive" "$destination" <<'PY'
import hashlib, json, pathlib, sys, tarfile
lock, archive, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
expected = json.loads(lock.read_text())['busybox']
assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected['sha256'], 'BusyBox archive mismatch'
output.mkdir(parents=True)
with tarfile.open(archive) as source:
    source.extractall(output, filter='data')
PY
destination=$(realpath -- "$destination")
version=$(python3 - "$port/stock-bootstrap.lock.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))['busybox']['version'])
PY
source_dir=$destination/busybox-$version
output_dir=$destination/out
mkdir "$output_dir"
export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
make -C "$source_dir" O="$output_dir" allnoconfig
python3 - "$output_dir/.config" <<'PY'
from pathlib import Path
import re, sys
path = Path(sys.argv[1])
enabled = '''STATIC ASH SH_IS_ASH ASH_JOB_CONTROL ASH_ECHO ASH_PRINTF ASH_TEST
FEATURE_PREFER_APPLETS FEATURE_SH_STANDALONE CAT CHMOD CP CUT DD DF DMESG
ECHO ENV FALSE FIND FREE GREP HEAD ID INSMOD KILL LN LS MKDIR MKNOD MOUNT MV
POWEROFF PRINTF PS PWD READLINK REBOOT RM RMDIR SED SETSID CTTYHACK SLEEP STAT
STTY SYNC TAIL TEE TEST TRUE TR TTY UMOUNT UNAME WC XARGS BASE64 SHA256SUM
TIMEOUT BLOCKDEV TAR FEATURE_TAR_CREATE'''.split()
names = {'CONFIG_' + name for name in enabled} | {'CONFIG_SH_IS_NONE'}
lines = [line for line in path.read_text().splitlines()
         if not any(line.startswith(name + '=') or line == '# ' + name + ' is not set' for name in names)]
lines.extend('CONFIG_' + name + '=y' for name in enabled)
lines.append('# CONFIG_SH_IS_NONE is not set')
path.write_text('\n'.join(lines) + '\n')
PY
make -C "$source_dir" O="$output_dir" oldconfig </dev/null
make -C "$source_dir" O="$output_dir" -j"${JOBS:-8}"
make -C "$source_dir" O="$output_dir" CONFIG_PREFIX="$destination/root" install
sha256sum "$output_dir/busybox" "$output_dir/.config" > "$destination/build-checksums.txt"
