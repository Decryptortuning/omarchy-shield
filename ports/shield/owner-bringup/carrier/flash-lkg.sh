#!/bin/bash
# Restore the last configuration that booted Linux (2026-11-02 23:56Z): boot <- carrier v2 (6a5c527c),
# recovery <- original SOS readback (d8f68c06), system <- APP.lkg (original initramfs c443cb70, cmdline v2,
# board.dtb v2, healthy 9, no pending). Then reboot.
W=$WORK; FB=$WINHOME/AppData/Local/Android/Sdk/platform-tools/fastboot.exe; SER=${SHIELD_SERIAL:?set SHIELD_SERIAL to the fastboot serial of your Shield}
BOOT=$W/carrier/build/v2-lnx/candidate-LNX-padded.bin; REC=$BUILD/desktop-ready-2026-10-16/primary-recovery/SOS-readback.bin; APP=$W/fastboot/APP.lkg.img
LOG=$W/fastboot/flash-lkg.log; : > $LOG; log(){ echo "[$(date -u +%H:%M:%S)] $*" | tee -a $LOG; }
log "boot $(sha256sum $BOOT|cut -c1-16) recovery $(sha256sum $REC|cut -c1-16) app $(sha256sum $APP|cut -c1-16)"
start=$(date +%s); while :; do timeout 10s "$FB" devices 2>/dev/null | tr -d '\r' | grep -q "^$SER.*fastboot" && break
  [ $(( $(date +%s) - start )) -ge 7200 ] && { log NO_FASTBOOT; exit 3; }; sleep 2; done
log "fastboot present"; [ "$(timeout 10s "$FB" -s $SER getvar product 2>&1 | tr -d '\r' | grep -o t210ref)" = t210ref ] || { log PRODUCT_UNEXPECTED; exit 4; }
for pair in "boot $BOOT" "recovery $REC"; do set -- $pair; timeout 120s "$FB" -s $SER flash $1 "$2" 2>&1 | tr -d '\r' | tee -a $LOG; r=${PIPESTATUS[0]}; log "flash $1 rc=$r"; [ $r = 0 ] || exit 5; done
timeout 600s "$FB" -s $SER flash system "$APP" 2>&1 | tr -d '\r' | tail -2 | tee -a $LOG; r=${PIPESTATUS[0]}; log "flash system rc=$r"; [ $r = 0 ] || exit 6
echo "$(date -u +%FT%TZ) RESTORE last-known-good: boot<-carrier v2 6a5c527c, recovery<-SOS readback d8f68c06, system<-APP.lkg (initramfs c443cb70, cmdline v2, dtb v2, healthy 9, no pending)" >> $W/ledger.txt
timeout 20s "$FB" -s $SER reboot 2>&1 | tr -d '\r' | tee -a $LOG; log DONE
