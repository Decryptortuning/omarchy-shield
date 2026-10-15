#!/bin/sh
# SPDX-License-Identifier: MIT
# One bounded stock-kernel inventory session; persistent filesystems stay unmounted.
[ "$$" = 1 ] || { echo 'This entrypoint requires ramdisk PID 1' >&2; exit 1; }
[ "$(uname -m)" = aarch64 ] && [ "$(id -u)" = 0 ] || exit 1
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
mkdir -p /proc /sys /run /tmp /dev/pts
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t devpts devpts /dev/pts
. /identity.sh
. /inventory.conf

stock_halt() {
  echo "STOCK_INVENTORY_STOP: $*"
  poweroff -f
  while true; do sleep 1; done
}

tokens=$(tr '\000' '\n' </proc/device-tree/compatible)
case " $(cat /proc/cmdline) " in
  *' shield.stock-selftest=1 '*)
    printf '%s\n' "$tokens" | grep -qx 'linux,dummy-virt' || stock_halt 'selftest requires QEMU virt'
    echo SHIELD_STOCK_INVENTORY_RAMDISK_SELFTEST_PASS
    poweroff -f
    while true; do sleep 1; done
    ;;
esac
case " $(cat /proc/cmdline) " in
  *' shield.stock-inventory=1 '*) ;;
  *) stock_halt 'inventory opt-in missing' ;;
esac
stock_inventory_supported "$tokens" \
  "$(cat /sys/module/tegra_fuse/parameters/tegra_chip_id)" \
  "$(cat /sys/module/tegra_fuse/parameters/tegra_chip_major_rev)" || stock_halt 'unsupported board/silicon'
[ "$(uname -r)" = '4.9.141-tegra' ] || stock_halt 'unexpected stock kernel'

# Same two cooling modules and order as the exact-release recovery recipe.
insmod /lib/modules/pwm_fan.ko || stock_halt 'stock fan module failed'
insmod /lib/modules/therm_fan_est.ko || stock_halt 'stock thermal estimator failed'

# Bounded idle inventory only. No stress, overclock or fan-control writes.
(
  elapsed=0
  while [ "$elapsed" -lt "$inventory_window_seconds" ]; do
    plausible=0
    for zone in /sys/class/thermal/thermal_zone*; do
      [ -r "$zone/type" ] && [ -r "$zone/temp" ] || continue
      case "$(cat "$zone/type")" in
        CPU-therm|GPU-therm|cpu-thermal|gpu-thermal)
          value=$(cat "$zone/temp")
          case "$value" in ''|*[!0-9]*) continue ;; esac
          [ "$value" -lt "$inventory_temperature_limit" ] || stock_halt 'thermal limit reached'
          if [ "$value" -ge 10000 ]; then plausible=1; fi
          ;;
      esac
    done
    if [ "$elapsed" -ge 10 ] && [ "$plausible" = 0 ]; then stock_halt 'no plausible CPU/GPU sensor'; fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  stock_halt 'inventory window ended'
) &

mkdir /run/shield-stock
for name in cmdline iomem meminfo partitions; do cp "/proc/$name" "/run/shield-stock/$name"; done
for name in compatible model nvidia,dtsfilename; do
  if [ -r "/proc/device-tree/$name" ]; then cp "/proc/device-tree/$name" "/run/shield-stock/$name"; fi
done
if [ -r /sys/firmware/fdt ]; then cp /sys/firmware/fdt /run/shield-stock/live.dtb; fi
dmesg >/run/shield-stock/dmesg.txt

# GPT labels independently select read-only backups into RAM, never disk output.
mkdir /run/shield-stock/partitions
for entry in /sys/class/block/mmcblk0p*/uevent; do
  [ -r "$entry" ] || continue
  label=$(sed -n 's/^PARTNAME=//p' "$entry")
  case "$label" in LNX|SOS) maximum=26738688 ;; DTB) maximum=2097152 ;; *) continue ;; esac
  block=$(sed -n 's/^DEVNAME=//p' "$entry")
  case "$block" in mmcblk0p[0-9]*) ;; *) continue ;; esac
  size=$(blockdev --getsize64 "/dev/$block") || continue
  case "$size" in ''|*[!0-9]*) continue ;; esac
  [ "$size" -gt 0 ] && [ "$size" -le "$maximum" ] || continue
  dd if="/dev/$block" of="/run/shield-stock/partitions/$label.img" bs=1048576 || stock_halt 'RAM backup read failed'
done
sha256sum /run/shield-stock/partitions/*.img >/run/shield-stock/partition-sha256.txt 2>/dev/null || true

# Stock 4.9 names this UDC xudc; its gadget functions are built in.
[ -d /sys/class/udc/700d0000.xudc ] || stock_halt 'stock UDC absent'
mount -t configfs configfs /sys/kernel/config || stock_halt 'configfs mount failed'
g=/sys/kernel/config/usb_gadget/shield-stock-inventory
mkdir "$g" || stock_halt 'gadget creation failed'
printf '0x1d6b\n' >"$g/idVendor"
printf '0x0104\n' >"$g/idProduct"
printf '0xef\n' >"$g/bDeviceClass"
printf '0x02\n' >"$g/bDeviceSubClass"
printf '0x01\n' >"$g/bDeviceProtocol"
mkdir "$g/strings/0x409"
printf 'shield-stock-inventory\n' >"$g/strings/0x409/serialnumber"
printf 'Omarchy Shield development\n' >"$g/strings/0x409/manufacturer"
printf 'Stock kernel inventory\n' >"$g/strings/0x409/product"
mkdir "$g/configs/c.1" "$g/functions/acm.usb0"
ln -s "$g/functions/acm.usb0" "$g/configs/c.1/acm.usb0"
printf '700d0000.xudc\n' >"$g/UDC" || stock_halt 'UDC bind failed'
while [ ! -c /dev/ttyGS0 ]; do sleep 1; done
stty -F /dev/ttyGS0 115200 sane -echo
while true; do
  echo 'Stock-kernel RAM-only inventory. Automatic power-off within 60 seconds.' >/dev/ttyGS0
  echo 'Evidence/backups: /run/shield-stock ; transfer before power-off. No kexec is run automatically.' >/dev/ttyGS0
  setsid cttyhack sh </dev/ttyGS0 >/dev/ttyGS0 2>&1
  sleep 1
done
