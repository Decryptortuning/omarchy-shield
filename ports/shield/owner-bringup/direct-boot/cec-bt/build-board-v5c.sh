#!/bin/bash
# board.v5a -> board.v5c: enable HDMI CEC bound to sor1 and give it its reset (CAR clock/reset 136),
# which the patched tegra_cec releases at probe. Usage: build-board-v5c.sh board.v5a.dtb board.v5c.dtb
set -euo pipefail
cp "$1" "$2"
sor1=$(fdtget "$2" /host1x@50000000/sor@54580000 phandle)
car=$(fdtget "$2" /clock@60006000 phandle)
fdtput -t s "$2" /cec@70015000 status okay
fdtput -t i "$2" /cec@70015000 hdmi-phandle "$sor1"
fdtput -t i "$2" /cec@70015000 resets "$car" 136
fdtput -t s "$2" /cec@70015000 reset-names cec
sha256sum "$2"
