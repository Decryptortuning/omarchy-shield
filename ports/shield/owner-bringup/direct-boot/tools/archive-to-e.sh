#!/bin/bash
# Archive historical Shield build folders to E: as verified tar.zst, then remove the WSL copy.
# Keeps active dependencies on WSL. Log + manifest on E:.
B=$BUILD; A=/mnt/e/omarchy-shield-archive; M=$A/MANIFEST.tsv; LOG=$A/archive.log
KEEP=" bringup-2026-11-02 public-kernel-closure-2026-10-16 btrfs-kernel-fix209-2026-10-17 harvest-2026-10-14 a04-source-review-2026-10-15 desktop-ready-2026-10-16 boot-tools "
[ -f $M ] || printf "name\tsource_bytes\tentries\tarchive\tarchive_bytes\tarchive_sha256\tarchived_utc\n" > $M
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a $LOG; }
cd $B
for d in */; do
  d=${d%/}
  case "$KEEP" in *" $d "*) continue;; esac
  [ -e "$A/$d.tar.zst" ] && grep -q "^$d	" $M && { log "skip (already archived) $d"; continue; }
  if findmnt -rn -o TARGET | grep -q "^$B/$d"; then log "SKIP mounted $d"; continue; fi
  src=$(sudo du -xsb "$d" | cut -f1); n=$(sudo find "$d" -xdev | wc -l)
  log "archiving $d ($src bytes, $n entries)"
  if ! sudo tar --one-file-system --numeric-owner --xattrs -cpf - "$d" | zstd -q -T0 -6 -o "$A/$d.tar.zst.part"; then log "FAIL tar $d"; rm -f "$A/$d.tar.zst.part"; continue; fi
  zstd -q -t "$A/$d.tar.zst.part" || { log "FAIL zstd-test $d"; continue; }
  an=$(zstd -dc "$A/$d.tar.zst.part" | tar -tf - | wc -l)
  [ "$an" = "$n" ] || { log "FAIL count $d src=$n archive=$an"; continue; }
  mv "$A/$d.tar.zst.part" "$A/$d.tar.zst"; ab=$(stat -c %s "$A/$d.tar.zst"); h=$(sha256sum "$A/$d.tar.zst" | cut -d' ' -f1)
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$d" "$src" "$n" "$d.tar.zst" "$ab" "$h" "$(date -u +%FT%TZ)" >> $M
  sudo rm -rf --one-file-system "$B/$d" && log "removed WSL copy of $d (archive $ab bytes)"
done
log "DONE; WSL free: $(df -h / | tail -1 | awk '{print $4}')"
