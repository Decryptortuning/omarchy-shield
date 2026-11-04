#!/bin/bash
# board.v4a (pinmux default) -> board.v5a: enable the CPU DFLL and let the thermal zones drive the fan.
# Usage: build-board-v5a.sh board.v4a-pinmux-default.dtb board.v5a.dtb   (needs fdtput from dtc)
set -euo pipefail
cp "$1" "$2"; dtb=$2
fdtput -t s $dtb /clock@70110000 status okay
# pwm-fan states 0-4: off, 80 (~2800 rpm), 127 (~3900), 191 (~5000), 255 (~5800)
fdtput -t i $dtb /pwm-fan cooling-levels 0 80 127 191 255
for z in cpu-thermal gpu-thermal; do fdtput -t i $dtb /thermal-zones/$z polling-delay 2000; done
ph=128
add_trip() {
  local z=$1 n=$2 t=$3 s=$4
  fdtput -c $dtb /thermal-zones/$z/trips/$n
  fdtput -t i $dtb /thermal-zones/$z/trips/$n temperature $t
  fdtput -t i $dtb /thermal-zones/$z/trips/$n hysteresis 3000
  fdtput -t s $dtb /thermal-zones/$z/trips/$n type active
  fdtput -t i $dtb /thermal-zones/$z/trips/$n phandle $ph
  fdtput -c $dtb /thermal-zones/$z/cooling-maps/$n
  fdtput -t i $dtb /thermal-zones/$z/cooling-maps/$n trip $ph
  fdtput -t i $dtb /thermal-zones/$z/cooling-maps/$n cooling-device 99 $s $s   # 99 = 0x63, the pwm-fan phandle in board.v4a
  ph=$((ph + 1))
}
fdtput -c $dtb /thermal-zones/cpu-thermal/cooling-maps
for z in cpu-thermal gpu-thermal; do
  add_trip $z fan-quiet 30000 1; add_trip $z fan-low 50000 2; add_trip $z fan-mid 60000 3; add_trip $z fan-high 70000 4
done
sha256sum "$2"
