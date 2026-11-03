#!/bin/bash
# Build shield_overlay.ko as an external module against the prepared kernel457 tree (same recipe as wave 628).
set -euo pipefail
W=$WORK/overlay
B=$SHIELD_BUILD
S=$B/btrfs-kernel-fix209-2026-10-17/sources/kernel-9336ceeebe1d75021d9fd98c94abaec522ba39b3
O=$B/btrfs-kernel-fix209-2026-10-17/kernel-out-9336ceeebe1d75021d9fd98c94abaec522ba39b3-omarchy-a04
LOWER=$B/ethernet-aspm628-build-2026-10-21/upper:$B/pcie-kernel338-2026-10-18/upper:$B/pcie-kbuild337-2026-10-18/upper:$O
mkdir -p $W/upper $W/work
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C ARCH=arm64 LLVM=1 CROSS_COMPILE=aarch64-linux-gnu- KBUILD_BUILD_USER=shield-linux KBUILD_BUILD_HOST=local-build KBUILD_BUILD_TIMESTAMP='2026-10-13 00:00:00 UTC'
mount -t overlay overlay -o lowerdir=$LOWER,upperdir=$W/upper,workdir=$W/work $O
cmp $O/.config $B/usb-maintenance-kernel457-2026-10-18/.config && echo config_identical
make -C $S O=$O modules_prepare >$W/make-prepare.log 2>&1
make -C $S O=$O M=$W/module -j4 modules >$W/make-module.log 2>&1
cmp $O/Module.symvers $B/usb-maintenance-kernel457-2026-10-18/Module.symvers && echo symvers_identical
cp $W/module/shield_overlay.ko $W/shield_overlay.ko
umount $O
modinfo -F vermagic $W/shield_overlay.ko; modinfo -F vermagic $B/usb-maintenance-kernel457-2026-10-18/pci-tegra.ko
