#!/bin/bash
# Build a static ARM64 helper only; never invoke a kexec load/execute operation.
set -euo pipefail
port=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
repository=${1:?Pass the native kexec-tools checkout}
destination=${2:?Pass a new build directory}
[[ ! -e $destination ]] || { echo 'Use a new kexec build directory' >&2; exit 1; }
commit=$(python3 - "$port/diagnostic-boot.lock.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))['kexec']['commit'])
PY
)
git -C "$repository" cat-file -e "$commit^{commit}"
mkdir -p "$destination"
destination=$(realpath -- "$destination")
git -C "$repository" archive "$commit" | tar -xf - -C "$destination"
# Keep userspace --debug output without passing its newer kernel debug bit to
# the Shield recovery kernel's legacy kexec_load ABI. Integrity checks stay on.
python3 - "$destination/kexec/kexec.c" <<'PYDEBUG'
from pathlib import Path
import sys
path = Path(sys.argv[1])
source = path.read_text()
line = "\t\t\tkexec_flags |= KEXEC_DEBUG;\n"
assert source.count(line) == 1, 'Pinned kexec debug boundary changed'
path.write_text(source.replace(line, "", 1))
PYDEBUG
(
  cd "$destination"
  sh bootstrap
  CC=aarch64-linux-gnu-gcc LDFLAGS=-static ./configure \
    --host=aarch64-linux-gnu --target=aarch64-linux-gnu \
    --without-zlib --without-lzma --without-zstd --without-xen
  make -j"${JOBS:-8}" build/sbin/kexec
)
python3 - "$destination" "$commit" <<'PY'
import hashlib, json, pathlib, struct, sys
root, commit = pathlib.Path(sys.argv[1]), sys.argv[2]
binary = root / 'build/sbin/kexec'
data = binary.read_bytes()
assert data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 183
offset = struct.unpack_from('<Q', data, 32)[0]
size, count = struct.unpack_from('<HH', data, 54)
assert all(struct.unpack_from('<I', data, offset + i * size)[0] != 3 for i in range(count)), 'Unexpected dynamic interpreter'
report = {'source_commit': commit, 'path': 'build/sbin/kexec', 'bytes': len(data),
          'sha256': hashlib.sha256(data).hexdigest(), 'architecture': 'AArch64',
          'dynamic_interpreter': False, 'legacy_kernel_debug_flag_suppressed': True,
          'patched_kexec_source_sha256': hashlib.sha256((root / 'kexec/kexec.c').read_bytes()).hexdigest(),
          'load_or_execute_operation_tested': False,
          'physical_kexec_tested': False, 'device_actions_performed': []}
(root / 'shield-build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
PY
