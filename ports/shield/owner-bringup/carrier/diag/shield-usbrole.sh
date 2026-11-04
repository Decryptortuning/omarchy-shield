#!/system/bin/sh
# Force OTG port (usb2-0) to device mode in recovery: ID=0, VBUS=1 on the xlate inputs.
k(){ echo "<6>shield-usbrole: $*" > /dev/kmsg; echo "shield-usbrole: $*" >> /tmp/recovery.log; }
set_role(){
  for e in /sys/class/extcon/extcon*; do
    n="$(cat $e/name 2>/dev/null) $(basename $(readlink -f $e/device 2>/dev/null))"
    case "$n" in
      *virtual_id*|"ID "*) echo 0x0 > $e/state 2>/dev/null ;;
      *vbus_gpio*|"VBUS "*) echo 0x1 > $e/state 2>/dev/null ;;
    esac
  done
  for e in /sys/class/extcon/extcon*; do
    n="$(cat $e/name 2>/dev/null) $(basename $(readlink -f $e/device 2>/dev/null))"
    case "$n" in *cable-xlate*|*usb_otg*) echo 0x1 > $e/state 2>/dev/null ;; esac
  done
}
U=/sys/class/udc/700d0000.xudc
i=0; while [ ! -e $U ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
for e in /sys/class/extcon/extcon*; do k "$(basename $e) $(cat $e/name) $(basename $(readlink -f $e/device)) $(cat $e/state | tr '\n' ' ')"; done
i=0
while [ $i -lt 120 ]; do
  s=$(cat $U/state 2>/dev/null)
  case "$s" in configured|addressed|default|powered) ;; *) set_role; k "udc=$s -> forced device" ;; esac
  sleep 3; i=$((i+1))
done
k "final udc=$(cat $U/state 2>/dev/null) usb=$(getprop sys.usb.state)"
