#!/bin/bash
set -euo pipefail
port=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_root=$(realpath -- "${1:?Pass the native Linux build directory}")
image=$build_root/omarchy-userspace-test.ext4
[[ -f $image && ! -L $image ]] || exit 1
log=$build_root/qemu-userspace.log
timeout 300 qemu-system-aarch64 -machine virt -cpu cortex-a57 -smp 4 -m 3072M \
  -nographic -no-reboot -nic none -snapshot \
  -kernel "${SHIELD_DIST_DIR:-$port/build/kernel}/Image" \
  -drive "if=none,file=$image,format=raw,id=rootfs" -device virtio-blk-device,drive=rootfs \
  -append 'console=ttyAMA0 root=/dev/vda rootwait rw systemd.unit=shield-qemu-selftest.target shield.qemu-userspace-test=1 panic=-1' > "$log" 2>&1
grep -q '^SHIELD_OMARCHY_QEMU_USERSPACE_PASS' "$log"
if grep -q '^SHIELD_OMARCHY_QEMU_USERSPACE_FAIL' "$log"; then
  exit 1
fi
echo 'PASS: custom ARM kernel + installed Omarchy filesystem under QEMU; physical hardware remains untested.'
