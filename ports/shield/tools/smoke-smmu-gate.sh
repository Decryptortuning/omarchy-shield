#!/bin/bash
# The explicit reset request must stop on a virtual board with no Tegra MC.
set -euo pipefail
port=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
dist=${SHIELD_DIST_DIR:-$port/build/kernel}
log=${SHIELD_QEMU_LOG:-$port/build/qemu-smmu-gate.log}
mkdir -p "$(dirname -- "$log")"
timeout 20s qemu-system-aarch64 -machine virt -cpu cortex-a57 -smp 2 -m 512M \
  -nographic -no-reboot -nic none -kernel "$dist/Image" -initrd "$dist/initramfs.cpio.gz" \
  -append 'earlycon=pl011,0x9000000 console=ttyAMA0 rdinit=/init panic=1 shield.selftest=1 tegra_smmu.reset_inherited=1' > "$log" 2>&1
rg -qF 'Kernel panic - not syncing: tegra-smmu: requested handoff reset did not complete' "$log"
if rg -q 'SHIELD_LINUX_INIT_STARTED|SHIELD_LINUX_QEMU_SELFTEST_PASS' "$log"; then
  echo 'Requested SMMU reset was bypassed before userspace' >&2
  exit 1
fi
echo 'PASS: explicit reset request stops before userspace without the required Tegra MC. No physical handoff tested.'
