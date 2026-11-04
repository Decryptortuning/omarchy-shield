#!/system/bin/sh
# Recovery network ADB over a USB Ethernet adapter (ASIX/AX88179/CDC built into the
# recovery kernel). Static 192.168.2.211/24, adbd on TCP 5555. adbd keeps key auth
# (ro.adb.secure=1, /adb_keys), so only the operator PC's key is accepted.
IP=192.168.2.211
k(){ echo "<6>shield-netadb: $*" > /dev/kmsg; echo "shield-netadb: $*" >> /tmp/recovery.log; }
i=0; dev=
while [ $i -lt 300 ] && [ -z "$dev" ]; do
  for n in /sys/class/net/*; do
    case "$(readlink -f $n 2>/dev/null) $(readlink -f $n/device 2>/dev/null)" in */usb[0-9]*) dev=$(basename $n);; esac
  done
  [ -z "$dev" ] && { sleep 1; i=$((i+1)); }
done
[ -n "$dev" ] || { k "no USB Ethernet adapter found"; exit 0; }
ifconfig $dev $IP netmask 255.255.255.0 up && k "$dev up at $IP ($(cat /sys/class/net/$dev/address))" || k "ifconfig $dev failed"
setprop service.adb.tcp.port 5555
if [ "$(getprop init.svc.adbd)" = running ]; then setprop ctl.restart adbd; else setprop sys.usb.config adb; setprop ctl.start adbd; fi
sleep 3; k "adbd=$(getprop init.svc.adbd) tcp=5555"
