#!/bin/bash
# Rewrite APP with a RAW-only sparse image (no FILL chunks) to avoid suspected cboot FILL corruption.
W=$WORK; FB=$WINHOME/AppData/Local/Android/Sdk/platform-tools/fastboot.exe; SER=${SHIELD_SERIAL:?set SHIELD_SERIAL to the fastboot serial of your Shield}
APP=$W/fastboot/APP.lkg.rawsparse.img; LOG=$W/fastboot/flash-app-raw.log; : > $LOG; log(){ echo "[$(date -u +%H:%M:%S)] $*" | tee -a $LOG; }
log "app $(sha256sum $APP|cut -c1-16)"
start=$(date +%s); while :; do timeout 10s "$FB" devices 2>/dev/null | tr -d '\r' | grep -q "^$SER.*fastboot" && break
  [ $(( $(date +%s) - start )) -ge 7200 ] && { log NO_FASTBOOT; exit 3; }; sleep 2; done
log "fastboot present"; [ "$(timeout 10s "$FB" -s $SER getvar product 2>&1 | tr -d '\r' | grep -o t210ref)" = t210ref ] || { log PRODUCT_UNEXPECTED; exit 4; }
timeout 600s "$FB" -s $SER flash system "$APP" 2>&1 | tr -d '\r' | tee -a $LOG; r=${PIPESTATUS[0]}; log "flash system rc=$r"; [ $r = 0 ] || exit 6
echo "$(date -u +%FT%TZ) fastboot: system <- APP.lkg as RAW-only sparse (ddb55be8, 9 RAW chunks, no FILL) to avoid suspected cboot FILL-chunk corruption of Image; boot keeps v12" >> $W/ledger.txt
timeout 20s "$FB" -s $SER reboot 2>&1 | tr -d '\r' | tee -a $LOG; log DONE
