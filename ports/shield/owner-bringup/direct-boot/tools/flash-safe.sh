#!/bin/bash
# boot (LNX) + recovery (SOS) <- direct-boot v2; system (APP) <- last-known-good RAW-only sparse (clears pending 15).
# Old carrier v13 kept at carrier/build/v13-lnx; original SOS at desktop-ready-2026-10-16/primary-recovery/SOS-readback.bin
W=$WORK; FB=$WINHOME/AppData/Local/Android/Sdk/platform-tools/fastboot.exe; SER=${SHIELD_SERIAL:?set SHIELD_SERIAL to the fastboot serial of your Shield}
BOOTIMG=$W/carrier/build/v13-lnx/candidate-LNX-padded.bin; IMG=$W/loader/direct-v3.img; APP=$W/fastboot/APP.lkg.rawsparse.img; LOG=$W/fastboot/flash-safe-v3.log; : > $LOG
log(){ echo "[$(date -u +%H:%M:%S)] $*" | tee -a $LOG; }
log "boot $(sha256sum $BOOTIMG | cut -c1-16) img $(sha256sum $IMG | cut -c1-16) app $(sha256sum $APP | cut -c1-16)"
start=$(date +%s); while :; do timeout 10s "$FB" devices 2>/dev/null | tr -d '\r' | grep -q "^$SER.*fastboot" && break
  [ $(( $(date +%s) - start )) -ge 7200 ] && { log NO_FASTBOOT; exit 3; }; sleep 2; done
log "fastboot present"; [ "$(timeout 10s "$FB" -s $SER getvar product 2>&1 | tr -d '\r' | grep -o t210ref)" = t210ref ] || { log PRODUCT_UNEXPECTED; exit 4; }
for pair in "recovery $IMG" "boot $BOOTIMG"; do set -- $pair; part=$1; timeout 120s "$FB" -s $SER flash $part "$2" 2>&1 | tr -d '\r' | tail -2 | tee -a $LOG; r=${PIPESTATUS[0]}; log "flash $part rc=$r"; [ $r = 0 ] || exit 5; done
timeout 600s "$FB" -s $SER flash system "$APP" 2>&1 | tr -d '\r' | tail -2 | tee -a $LOG; r=${PIPESTATUS[0]}; log "flash system rc=$r"; [ $r = 0 ] || exit 6
echo "$(date -u +%FT%TZ) fastboot: boot <- carrier v13 (912ceca6, back: direct-v2 in LNX powered off via PMIC watchdog on the normal path), recovery <- direct-v3 (shim word copy + progress; loader disables/kicks MAX77620 wdt), system <- APP.lkg raw-sparse" >> $W/ledger.txt
timeout 20s "$FB" -s $SER reboot 2>&1 | tr -d '\r' | tee -a $LOG; log DONE
