#!/system/bin/sh
# shield-beacon.sh: classify the carrier outcome and print the evidence on the TV.
R=/tmp/shield-internal; O=/tmp/shield-beacon.txt; LED=/sys/class/leds/led_lightbar/brightness
k(){ echo "<3>shield-beacon: $*" > /dev/kmsg; }
class=0; why=running; t=0
while [ $t -lt 100 ]; do
  sleep 2; t=$((t+2))
  if [ -e $R/ABORT ]; then class=4; why="handoff abort"; break; fi
  if [ -e $R/stage-failed ]; then
    case "$(cat $R/stage-failed)" in owned-child-terminal-failure) [ -e $R/runtime-cmdline.txt ] && { class=2; why="post-claim child failure"; } || { class=3; why="claim refused"; } ;; *) class=2; why="stage refused (RAM)";; esac; break; fi
  if [ ! -d $R ] && dmesg | grep -q INTERNAL_STAGE_REFUSED; then class=1; why="stage refused (pre-RAM)"; break; fi
  if [ -e $R/WATCHDOG_ARMED ] && [ $t -ge 90 ]; then class=5; why="post-claim hang"; break; fi
done
{
echo "SHIELD CARRIER BEACON  class=$class  ($why)  t=${t}s"
echo "bootreason=$(getprop ro.boot.bootreason)  $(grep -o 'android.kerneltype=[a-z]*' /proc/cmdline)  svc=$(getprop init.svc.shield_owner_internal)"
echo "stage-failed: $(cat $R/stage-failed 2>/dev/null)"
echo "ABORT: $(cat $R/ABORT 2>/dev/null | head -c 300)"
echo "--- dmesg (stage)"; dmesg | grep -a 'INTERNAL_STAGE\|shield-owner\|shield-internal' | tail -4 | cut -c1-150
echo "--- RAM dir"; ls $R 2>&1 | tr '\n' ' ' | cut -c1-450; echo
echo "--- runner/handoff log tail"; for f in $R/runner.log $R/handoff.log $R/loader.log; do [ -f $f ] && { echo "[$(basename $f)]"; tail -8 $f | cut -c1-150; }; done
echo "--- temps"; for z in /sys/class/thermal/thermal_zone*; do printf '%s=%s ' "$(cat $z/type)" "$(cat $z/temp)"; done | cut -c1-300; echo
echo "--- APP state"
mkdir -p /mnt/shield-beacon
if mount -t ext4 -o ro,noload /dev/block/mmcblk0p19 /mnt/shield-beacon 2>/dev/null; then
  for f in /mnt/shield-beacon/shield-owner/state/*; do printf '%s seq=%s  ' "$(basename $f)" "$(od -An -t u8 -j 40 -N 8 $f | tr -d ' ')"; done; echo
  umount /mnt/shield-beacon
else echo "APP mount failed (may still be held)"; fi
echo "--- usb: udc=$(cat /sys/class/udc/*/state 2>/dev/null) devices=$(ls /sys/bus/usb/devices | tr '\n' ' ')"
} > $O 2>&1
k "$(head -1 $O)"
cat $O >> /tmp/recovery.log
[ $class = 0 ] && [ "$(getprop init.svc.shield_owner_internal)" = running ] && sleep 1
# Detail code from the refusal text: 1 framebuffer, 2 device tree, 3 RAM/VPR map, 4 artifact copy/hash,
# 5 GPT/CID/disk, 6 bootreason/identity, 7 APP store, 8 claim/child, 9 other.
sf=$(cat $R/stage-failed 2>/dev/null)
case "$sf" in *framebuffer*) code=1;; FDT-*|*FDT*) code=2;; *VPR*|*RAM-map*|*RAM-count*|*iomem*|*RAM-bank*|*reservation*) code=3;;
 *artifact*|*RAM-whole*|*copy*|*bootset*|*payload*) code=4;; *GPT*|*CID*|*disk*|*mmc*) code=5;; *bootreason*|*identity*|*tool*) code=6;;
 *APP*|*generation*|*owner-directory*|*state-directory*|*boot-directory*) code=7;; *child*|*claim*|*pending*) code=8;; '') code=0;; *) code=9;; esac
k "detail code=$code stage-failed=$sf"
# Boot reason code: 1 cold 2 warm 3 watchdog 4 unknown 5 kernel_panic 6 shutdown,* 7 other.
br=$(getprop ro.boot.bootreason); case "$br" in cold) rc=1;; warm) rc=2;; watchdog) rc=3;; unknown) rc=4;; kernel_panic) rc=5;; shutdown*) rc=6;; *) rc=7;; esac
k "bootreason=$br code=$rc"
# First: two long flashes then <rc> short blinks (boot reason), twice.
i=0; while [ $i -lt 2 ]; do echo 255 > $LED; sleep 2; echo 0 > $LED; sleep 0.7; echo 255 > $LED; sleep 2; echo 0 > $LED; sleep 1; j=0; while [ $j -lt $rc ]; do echo 255 > $LED; sleep 0.4; echo 0 > $LED; sleep 0.6; j=$((j+1)); done; sleep 2.5; i=$((i+1)); done
# Then: one long flash, pause, then <code> short blinks (failing check); repeated 4 times.
i=0; while [ $i -lt 4 ]; do echo 255 > $LED; sleep 2; echo 0 > $LED; sleep 1; j=0; while [ $j -lt $code ]; do echo 255 > $LED; sleep 0.4; echo 0 > $LED; sleep 0.6; j=$((j+1)); done; sleep 2; i=$((i+1)); done; echo 255 > $LED
setprop ctl.stop recovery; sleep 2
/system/bin/shield-fbstatus $O 600 2>>/tmp/recovery.log || { k "fbstatus failed rc=$?"; setprop ctl.start recovery; }
exit 0
i=0; while [ $i -lt 3 ]; do j=0; while [ $j -lt ${class:-0} ]; do echo 255 > $LED; sleep 0.3; echo 0 > $LED; sleep 0.3; j=$((j+1)); done; sleep 1; i=$((i+1)); done; echo 255 > $LED
