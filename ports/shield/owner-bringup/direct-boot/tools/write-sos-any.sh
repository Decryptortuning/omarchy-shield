#!/bin/bash
# Write the cold-boot carrier to LNX (mmcblk0p16) from the running Omarchy side over SSH.
# One write, with exact preimage check, fsync, full readback, and SOS/DTB unchanged checks.
set -euo pipefail
W=$WORK
IMG=${1:?usage: write-lnx.sh <padded-LNX> <expected-preimage-sha256>}
EXPECT_OLD=${2:?expected preimage}
NEW=$(sha256sum "$IMG" | cut -d' ' -f1)
SIZE=$(stat -c %s "$IMG"); [ "$SIZE" = 26738688 ]
S=(ssh -F /dev/null -T -i "$W/operator-ed25519" -o "UserKnownHostsFile=$W/known_hosts" -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=omarchy-shield -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR -l root 192.168.2.210)
echo "stage: upload image to RAM on device"
"${S[@]}" 'mkdir -p /run/sos-write && chmod 700 /run/sos-write && cat > /run/sos-write/sos.bin' < "$IMG"
echo "target: verify and write"
"${S[@]}" "set -e
cd /run/sos-write
[ \$(stat -c %s sos.bin) = $SIZE ]
[ \$(sha256sum sos.bin | cut -d' ' -f1) = $NEW ] || { echo UPLOAD_HASH_MISMATCH; exit 65; }
[ \$(cat /sys/class/block/mmcblk0p16/size) = 52224 ]
grep -q 'PARTNAME=SOS' /sys/class/block/mmcblk0p16/uevent
[ -z \"\$(ls /sys/class/block/mmcblk0p16/holders)\" ]
! grep -q mmcblk0p16 /proc/mounts
lnx_before=\$(sha256sum /dev/mmcblk0p18 | cut -d' ' -f1); dtb_before=\$(sha256sum /dev/mmcblk0p17 | cut -d' ' -f1)
old=\$(sha256sum /dev/mmcblk0p16 | cut -d' ' -f1)
echo SOS_PREIMAGE=\$old
[ \"\$old\" = $EXPECT_OLD ] || { echo PREIMAGE_MISMATCH_ABORT; exit 66; }
echo WRITE_INTENT old=\$old new=$NEW
dd if=sos.bin of=/dev/mmcblk0p16 bs=1M conv=fsync status=none
sync
echo 3 > /proc/sys/vm/drop_caches
rb=\$(sha256sum /dev/mmcblk0p16 | cut -d' ' -f1); echo SOS_READBACK=\$rb
[ \"\$rb\" = $NEW ] || { echo READBACK_MISMATCH; exit 67; }
[ \"\$(sha256sum /dev/mmcblk0p18 | cut -d' ' -f1)\" = \"\$lnx_before\" ] && echo LNX_UNCHANGED
[ \"\$(sha256sum /dev/mmcblk0p17 | cut -d' ' -f1)\" = \"\$dtb_before\" ] && echo DTB_UNCHANGED
rm -f sos.bin
echo SOS_WRITE_OK"
