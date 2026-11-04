#!/bin/bash
# Second pass for folders whose archive differed from the source only by sockets (tar skips sockets).
B=$BUILD; A=/mnt/e/omarchy-shield-archive; M=$A/MANIFEST.tsv; LOG=$A/archive.log
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a $LOG; }
for p in "$A"/*.tar.zst.part; do
  [ -e "$p" ] || continue
  d=$(basename "$p" .tar.zst.part); [ -n "$d" ] && [ -d "$B/$d" ] || { log "pass2 skip $d (no source)"; continue; }
  n=$(sudo find "$B/$d" -xdev ! -type s | wc -l); s=$(sudo find "$B/$d" -xdev -type s | wc -l)
  zstd -q -t "$p" || { log "pass2 FAIL zstd-test $d"; continue; }
  an=$(zstd -dc "$p" | tar -tf - | wc -l)
  if [ "$an" = "$n" ]; then
    mv "$p" "$A/$d.tar.zst"; ab=$(stat -c %s "$A/$d.tar.zst"); h=$(sha256sum "$A/$d.tar.zst" | cut -d' ' -f1); src=$(sudo du -xsb "$B/$d" | cut -f1)
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$d" "$src" "$n (+$s sockets omitted)" "$d.tar.zst" "$ab" "$h" "$(date -u +%FT%TZ)" >> $M
    sudo rm -rf --one-file-system "${B:?}/${d:?}" && log "pass2 accepted $d ($s sockets omitted); WSL copy removed"
  else log "pass2 FAIL count $d nonsocket=$n archive=$an"; fi
done
log "pass2 DONE; WSL free: $(df -h / | tail -1 | awk '{print $4}')"
