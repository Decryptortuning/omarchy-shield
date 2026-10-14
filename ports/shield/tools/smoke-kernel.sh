#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
port_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
dist=${SHIELD_DIST_DIR:-"$port_dir/build/kernel"}
log=${SHIELD_QEMU_LOG:-"$port_dir/build/qemu-kernel.log"}
mkdir -p "$(dirname -- "$log")"
timeout 90s qemu-system-aarch64 -machine virt -cpu cortex-a57 -smp 2 -m 512M \
    -nographic -no-reboot -nic none \
    -kernel "$dist/Image" -initrd "$dist/initramfs.cpio.gz" \
    -append 'console=ttyAMA0 rdinit=/init panic=-1 shield.selftest=1' > "$log" 2>&1
rg -q '^SHIELD_LINUX_QEMU_SELFTEST_PASS' "$log"
printf 'PASS: kernel and ramdisk boot under QEMU virt. This does not validate Shield hardware.\n'
