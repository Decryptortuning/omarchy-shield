#!/system/bin/sh
# Runs once after the carrier stage exits without handing off. Appends a short report
# to the recovery log (Advanced > View recovery logs) and, when a FAT32 stick is in the
# host USB port, copies the full report there. Read-only on eMMC.
sleep 15
O=/tmp/shield-diag.txt
{
echo "########## SHIELD CARRIER DIAGNOSTIC ##########"
echo "bootreason=$(getprop ro.boot.bootreason) uptime=$(cut -d' ' -f1 /proc/uptime)"
echo "--- stage"
cat /tmp/shield-internal/stage-failed 2>/dev/null && echo
dmesg | grep -a -i 'INTERNAL_STAGE\|shield-owner\|owner-local\|shield-boot-probe' | tail -8
echo "--- APP state"
mkdir -p /mnt/shield-diag
if mount -t ext4 -o ro,noload /dev/block/mmcblk0p19 /mnt/shield-diag; then
  S=/mnt/shield-diag/shield-owner
  echo "enabled=$(head -c 16 $S/enabled)"
  for f in $S/state/*; do echo "$(basename $f) seq=$(od -An -t u8 -j 40 -N 8 $f | tr -d ' ')"; done
  for f in $S/bootsets/*/*; do echo "$(sha256sum $f | cut -c1-16) $(stat -c %s $f) ${f#$S/bootsets/}" | cut -c1-60; done
  umount /mnt/shield-diag
else echo "APP mount failed"; fi
echo "--- pstore (last Linux)"
for f in /sys/fs/pstore/*; do [ -f "$f" ] || continue; echo "== $(basename $f) $(stat -c %s $f)"
  grep -a -i 'owner-init\|FAILED\|switch-root-fix\|ordering cycle\|Kernel panic\|Internal error\|SError\|reboot:\|Failed to start\|shield-owner' $f | tail -12 | cut -c1-110; done
echo "--- usb gadget"
echo "udc=$(ls /sys/class/udc 2>/dev/null) state=$(getprop sys.usb.state) cfg=$(getprop sys.usb.config) adbd=$(getprop init.svc.adbd)"
for e in /sys/class/extcon/*; do echo "$(basename $e) $(cat $e/name 2>/dev/null) $(cat $e/state 2>/dev/null | tr '\n' ' ')"; done
dmesg | grep -a -i 'xudc\|udc\|gadget\|extcon\|otg\|vbus' | tail -10 | cut -c1-110
echo "########## END DIAGNOSTIC ##########"
} > $O 2>&1
cat $O >> /tmp/recovery.log
for d in /dev/block/sd[a-z]1 /dev/block/sd[a-z]; do
  [ -b "$d" ] || continue
  mkdir -p /mnt/shield-stick
  if mount -t vfat $d /mnt/shield-stick 2>/dev/null; then
    cp $O /mnt/shield-stick/shield-diag.txt; dmesg > /mnt/shield-stick/shield-dmesg.txt
    for f in /sys/fs/pstore/*; do [ -f "$f" ] && cat $f > /mnt/shield-stick/pstore-$(basename $f).txt; done
    cp /tmp/recovery.log /mnt/shield-stick/recovery-log.txt 2>/dev/null; sync; umount /mnt/shield-stick
    echo "shield-diag: report copied to USB stick $d" >> /tmp/recovery.log; break
  fi
done
