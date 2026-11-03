#!/bin/bash
# Install carrier v2 on the running Shield: new board.dtb into the active boot set on APP (/boot),
# then the matching LNX image. Preimage, fsync and readback checks on both. SOS/DTB untouched.
set -euo pipefail
W=$WORK
DTB=$W/dtb/board.v2.dtb
IMG=$W/carrier/build/v2-lnx/candidate-LNX-padded.bin
GEN=3982163bd866565d843455b8a076124adfb58095cc8b11720a31835fa79dfbae
EXPECT_OLD_LNX=25da17573f25d48208871ac3b410b2c35c30de8eccc436347e9454fa2a871606
EXPECT_OLD_DTB=b5a2bb41ec40
NEW_LNX=$(sha256sum "$IMG" | cut -d' ' -f1); NEW_DTB=$(sha256sum "$DTB" | cut -d' ' -f1)
[ "$(stat -c %s "$IMG")" = 26738688 ]
S=(ssh -F /dev/null -T -i "$W/operator-ed25519" -o "UserKnownHostsFile=$W/known_hosts" -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=omarchy-shield -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR -l root 192.168.2.210)
echo "upload"
tar -C "$(dirname "$IMG")" -cf - candidate-LNX-padded.bin | "${S[@]}" 'mkdir -p /run/carrier-v2 && chmod 700 /run/carrier-v2 && tar -C /run/carrier-v2 -xf -'
"${S[@]}" 'cat > /run/carrier-v2/board.dtb' < "$DTB"
echo "install"
"${S[@]}" "set -e
cd /run/carrier-v2
[ \$(sha256sum candidate-LNX-padded.bin | cut -d' ' -f1) = $NEW_LNX ]
[ \$(sha256sum board.dtb | cut -d' ' -f1) = $NEW_DTB ]
SET=/boot/shield-owner/bootsets/$GEN
[ -d \$SET ]
old_dtb=\$(sha256sum \$SET/board.dtb | cut -c1-12); echo DTB_PREIMAGE=\$old_dtb
[ \"\$old_dtb\" = $EXPECT_OLD_DTB ] || { echo DTB_PREIMAGE_MISMATCH; exit 66; }
cp \$SET/board.dtb /boot/shield-owner/bootsets/board.dtb.v1.bak
install -m 600 -o root -g root board.dtb \$SET/board.dtb.new
sync; mv -f \$SET/board.dtb.new \$SET/board.dtb; sync
[ \$(sha256sum \$SET/board.dtb | cut -d' ' -f1) = $NEW_DTB ] && echo DTB_INSTALLED
[ \$(cat /sys/class/block/mmcblk0p18/size) = 52224 ]; grep -q PARTNAME=LNX /sys/class/block/mmcblk0p18/uevent; ! grep -q mmcblk0p18 /proc/mounts
sos=\$(sha256sum /dev/mmcblk0p16 | cut -d' ' -f1); dtbp=\$(sha256sum /dev/mmcblk0p17 | cut -d' ' -f1)
old=\$(sha256sum /dev/mmcblk0p18 | cut -d' ' -f1); echo LNX_PREIMAGE=\${old:0:16}
[ \"\$old\" = $EXPECT_OLD_LNX ] || { echo LNX_PREIMAGE_MISMATCH; exit 67; }
dd if=candidate-LNX-padded.bin of=/dev/mmcblk0p18 bs=1M conv=fsync status=none; sync; echo 3 > /proc/sys/vm/drop_caches
rb=\$(sha256sum /dev/mmcblk0p18 | cut -d' ' -f1); echo LNX_READBACK=\${rb:0:16}
[ \"\$rb\" = $NEW_LNX ] || { echo LNX_READBACK_MISMATCH; exit 68; }
[ \"\$(sha256sum /dev/mmcblk0p16 | cut -d' ' -f1)\" = \"\$sos\" ] && echo SOS_UNCHANGED
[ \"\$(sha256sum /dev/mmcblk0p17 | cut -d' ' -f1)\" = \"\$dtbp\" ] && echo DTBPART_UNCHANGED
systemctl disable shield-overlays.service >/dev/null 2>&1 && echo OVERLAY_UNIT_DISABLED
rm -f candidate-LNX-padded.bin
echo CARRIER_V2_INSTALLED"
