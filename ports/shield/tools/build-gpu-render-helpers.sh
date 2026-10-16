#!/bin/bash
# Build the guarded ARM diagnostic helpers; never execute or deploy them.
set -euo pipefail
port=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
rootfs=$(realpath -- "${1:?Usage: build-gpu-render-helpers.sh ARM_ROOTFS NEW_OUTPUT_DIRECTORY}")
output=$(realpath -m -- "${2:?Usage: build-gpu-render-helpers.sh ARM_ROOTFS NEW_OUTPUT_DIRECTORY}")
[[ -f $rootfs/usr/include/EGL/egl.h && -f $rootfs/usr/include/gbm.h ]] || {
  echo 'The prepared ARM root must contain EGL, GLES, GBM and libdrm development headers.' >&2
  exit 1
}
umask 077
mkdir -m 700 -- "$output"
aarch64-linux-gnu-gcc -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-misleading-indentation \
  -static -Wl,--build-id=none "$port/diagnostic/gpu/native-egl.c" -o "$output/shield-native-egl"
aarch64-linux-gnu-gcc -std=gnu11 -O2 -Wall -Wextra -Werror \
  -idirafter "$rootfs/usr/include" -idirafter "$rootfs/usr/include/libdrm" \
  -Wl,--build-id=none "$port/diagnostic/gpu/egl-render.c" -ldl -o "$output/shield-egl-render"
chmod 0555 "$output/shield-native-egl" "$output/shield-egl-render"
(cd "$output" && sha256sum shield-native-egl shield-egl-render > SHA256SUMS)
printf 'Built GPU diagnostic helpers in %s; no device action performed.\n' "$output"
