#!/bin/bash
# Build the patched tegra_cec.ko as an external module against the public-kernel-closure tree
# (7.1.0-shield-bringup; its .config differs from the running kernel only in CONFIG_PCI_TEGRA y/m,
# and MODVERSIONS/module signing are off). Usage: build-module.sh <dir with patched tegra_cec.[ch]>
set -euo pipefail
B=$SHIELD_BUILD/public-kernel-closure-2026-10-16
S=$B/sources/kernel-9336ceeebe1d75021d9fd98c94abaec522ba39b3
O=$B/kernel-out-9336ceeebe1d75021d9fd98c94abaec522ba39b3-omarchy-a04
M=$(realpath "$1")
echo 'obj-m := tegra_cec.o' > "$M/Makefile"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C ARCH=arm64 LLVM=1 CROSS_COMPILE=aarch64-linux-gnu-
make -C "$S" O="$O" M="$M" -j8 modules
modinfo -F vermagic "$M/tegra_cec.ko"
