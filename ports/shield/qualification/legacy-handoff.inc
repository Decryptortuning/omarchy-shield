# Android shell input, invoked ONLY by explicit /system/bin/sh from the fixed
# coordinator/helper. Not a host script. Unqualified source: no execution before
# the current combined source gate and actual per-attempt release admission.
# No image load, partition write, broad unbind, IRQ teardown or forced reboot.

PATH=/system/bin:/system/xbin
export PATH
RAM=/tmp/shield-native
CG=/sys/fs/cgroup/shield-native
DC=/sys/bus/platform/devices/tegradc.0/enable
HOST=/sys/bus/platform/devices/50000000.host1x/force_idle
EMC=/sys/kernel/clk_emc/clk_rate
UDC=/config/usb_gadget/g1/UDC
TB=/system/bin/toybox
DISPLAY_TOUCHED=0
HOST_IDLED=0
STOPPED_SERVICES=
DEADLINE=0
WATCHDOG_HOLDING=0

now() {
  read _up _rest < /proc/uptime || return 1
  printf '%s\n' "${_up%%.*}"
}

log() {
  printf 'HANDOFF %s %s\n' "$(now)" "$*"
}

read_attr() {
  "$TB" timeout -k 1 4 "$TB" cat "$1"
}

write_attr() {
  "$TB" timeout -k 1 4 /system/bin/sh -c 'printf "%s\n" "$2" > "$1"' handoff-write "$1" "$2"
}

hold_watchdog() {
  # The fixed C helper acquired fd9 before exec. Retain that SAME open file
  # description on every post-open failure; unexpected last-close can ping the
  # stock driver. No feed/close/reopen or new hardware deadline is introduced.
  trap '' HUP INT TERM
  trap - 0
  if [ "$WATCHDOG_HOLDING" = 1 ]; then
    while :; do "$TB" sleep 2147483647; done
  fi
  WATCHDOG_HOLDING=1
  log 'WATCHDOG_FD9_HELD_NO_FEED; existing finite hardware policy remains owner'
  while :; do "$TB" sleep 2147483647; done
}

fatal() {
  log "ABORT $*"
  printf '%s\n' "$*" > "$RAM/ABORT"
  if [ "$DISPLAY_TOUCHED" = 1 ]; then
    # Only release the parent idle that this runner successfully acquired.
    # A timed-out/blocked writer is not evidence that acquisition succeeded.
    if [ "$HOST_IDLED" = 1 ]; then
      write_attr "$HOST" 0 || log 'HOST_UNIDLE_FAILED; physical fallback may be necessary'
      HOST_IDLED=0
    fi
    log 'REQUEST_RECOVERY_REBOOT; no promise of UI rollback or kernel-hang recovery'
    "$TB" timeout -k 1 3 /system/bin/reboot recovery || :
  else
    # Before display mutation the actual init service stops can be reversed.
    for _service in $STOPPED_SERVICES; do
      /system/bin/start "$_service" || :
    done
    log 'PRE_DISPLAY_ABORT; ADB configuration retained, inspect RAM log'
  fi
  hold_watchdog
}

guard() {
  "$@" || fatal "guard failed: $*"
}

time_guard() {
  _time=$(now) || fatal 'cannot read monotonic clock'
  [ "$_time" -lt "$DEADLINE" ] || fatal 'legacy handoff deadline reached'
}

wait_property() {
  _property=$1
  _value=$2
  _tries=0
  while [ "$_tries" -lt 4 ]; do
    [ "$(/system/bin/getprop "$_property")" = "$_value" ] && return 0
    sleep 1
    _tries=$((_tries + 1))
    time_guard
  done
  return 1
}

stop_service() {
  _service=$1
  STOPPED_SERVICES="$_service $STOPPED_SERVICES"
  /system/bin/stop "$_service" || fatal "init stop failed: $_service"
  wait_property "init.svc.$_service" stopped || fatal "service did not stop: $_service"
  log "SERVICE_STOPPED $_service"
}

check_clients() {
  for _device in 54100000.tsecb 54340000.vic 54480000.nvdec 544c0000.nvenc 54500000.tsec 54600000.isp 54680000.isp; do
    _state=$(read_attr "/sys/bus/platform/devices/$_device/power/runtime_status") || fatal "client status unreadable: $_device"
    [ "$_state" = suspended ] || fatal "client not suspended: $_device state=$_state"
  done
  [ ! -L /sys/bus/platform/devices/57000000.gpu/driver ] || fatal 'GPU driver unexpectedly bound'
  log 'CLIENTS_SUSPENDED_AND_GPU_UNBOUND'
}

check_temperature() {
  for _wanted in CPU-therm Tboard_tegra Tdiode_tegra; do
    _found=0
    for _zone in /sys/class/thermal/thermal_zone*; do
      [ "$(read_attr "$_zone/type")" = "$_wanted" ] || continue
      _temp=$(read_attr "$_zone/temp") || fatal "temperature read failed: $_wanted"
      case "$_temp" in ''|*[!0-9]*) fatal "invalid temperature: $_wanted" ;; esac
      [ "$_temp" -gt 0 ] && [ "$_temp" -lt 70000 ] || fatal "temperature outside probe start range: $_wanted=$_temp"
      log "TEMP $_wanted $_temp"
      _found=$((_found + 1))
    done
    [ "$_found" = 1 ] || fatal "missing or ambiguous temperature: $_wanted"
  done
}

storage_quiet() {
  "$TB" timeout -k 1 4 "$TB" sync || fatal 'sync failed or timed out'
  for _target in /cache /data; do
    _mounted=0
    while read _source _mount _type _options _rest; do
      [ "$_mount" = "$_target" ] && _mounted=1
    done < /proc/mounts
    if [ "$_mounted" = 1 ]; then
      "$TB" timeout -k 1 4 "$TB" umount "$_target" || fatal "cannot unmount $_target"
    fi
  done
  while read _source _mount _type _options _rest; do
    case "$_mount" in /cache|/data|/cache/*|/data/*) fatal "persistent mount remains: $_mount" ;; esac
    case "$_source:$_options" in /dev/block/*:rw|/dev/block/*:rw,*) fatal "unexpected writable block mount: $_mount" ;; esac
  done < /proc/mounts
  log 'CACHE_DATA_UNMOUNTED_NO_WRITABLE_BLOCK_MOUNTS'
}

# Private fixed-target legacy driver teardown, called only by reviewed handoff.
legacy_usb_host_check() {
  guard test "$(uname -r)" = 4.9.141-g9d1bd583388e
  guard test "$(readlink -f /sys/bus/platform/devices/70090000.xusb/driver)" = /sys/bus/platform/drivers/tegra-xusb
  guard test "$(readlink -f /sys/bus/platform/devices/700d0000.xudc/driver)" = /sys/bus/platform/drivers/tegra-xudc-new
  guard test "$(read_attr /sys/bus/platform/devices/70090000.xusb/power/runtime_status)" = active
  for USB_NODE in /sys/bus/usb/devices/*; do
    case "${USB_NODE##*/}" in
      usb1|usb2|1-0:1.0|2-0:1.0|2-2|2-2:1.0) ;;
      *) fatal 'unexpected USB host child; refuse teardown' ;;
    esac
  done
  guard test "$(read_attr /sys/bus/usb/devices/2-2/idVendor)" = 0781
  guard test "$(read_attr /sys/bus/usb/devices/2-2/idProduct)" = 5591
  USB_VBUS_FOUND=0
  USB_VBUS_PATH=
  for USB_REGULATOR in /sys/class/regulator/regulator.*; do
    [ "$(read_attr "$USB_REGULATOR/name")" = usb-vbus2 ] || continue
    USB_VBUS_FOUND=$((USB_VBUS_FOUND + 1))
    USB_VBUS_PATH=$USB_REGULATOR
  done
  guard test "$USB_VBUS_FOUND" = 1
  guard test "$(read_attr "$USB_VBUS_PATH/state")" = enabled
  guard test "$(read_attr "$USB_VBUS_PATH/num_users")" = 1
}

legacy_usb_host_remove() {
  legacy_usb_host_check
  time_guard
  guard test ! -e "$RAM/USB_HOST_REMOVE_STARTED"
  # Only after storage_quiet and display/host1x quiesce; no drive filesystem open.
  while read -r USB_SOURCE _USB_MOUNT _USB_TYPE _USB_OPTIONS _USB_REST; do
    case "$USB_SOURCE" in /dev/*) fatal 'block mount remains; refuse teardown' ;; esac
  done < /proc/mounts
  printf '%s\n' SINGLE_REVIEWED_HOST_REMOVE_V1 > "$RAM/USB_HOST_REMOVE_STARTED"
  log 'USB_HOST_REMOVE_BEGIN exact70090000.xusb normaldriverremove'
  write_attr /sys/bus/platform/drivers/tegra-xusb/unbind 70090000.xusb || fatal 'USB host remove failed or timed out; no replay'
  guard test ! -e /sys/bus/platform/devices/70090000.xusb/driver
  guard test ! -e /sys/bus/usb/devices/usb1
  guard test ! -e /sys/bus/usb/devices/usb2
  guard test ! -e /sys/bus/usb/devices/2-2
  guard test "$(read_attr "$USB_VBUS_PATH/state")" = disabled
  guard test "$(read_attr "$USB_VBUS_PATH/num_users")" = 0
  guard test "$(readlink -f /sys/bus/platform/devices/700d0000.xudc/driver)" = /sys/bus/platform/drivers/tegra-xudc-new
  guard test "$(read_attr "$UDC")" = 700d0000.xudc
  log 'USB_HOST_REMOVED normalregulatorVBUS2disabled users0 PCgadgetstillbound'
  sleep 2
  time_guard
  log 'USB_HOST_VBUS_OFF_SETTLED_2S beforeordinarykexec'
}

preflight() {
  guard test "$(id -u)" = 0
  guard test "$(id -Z)" = u:r:su:s0
  guard test "$(cat /proc/sys/kernel/random/boot_id)" = "$(cat "$RAM/legacy-boot-id")"
  guard test "$(read_attr /sys/kernel/kexec_loaded)" = 1
  guard test "$(read_attr /proc/sys/kernel/kexec_load_disabled)" = 0
  guard test "$(cat "$RAM/loaded-segments-reviewed")" = NATIVE_SEGMENTS_REVIEWED_V1
  guard test -x "$RAM/kexec"
  guard test "$(/system/bin/getprop sys.usb.configfs)" = 1
  guard test "$(/system/bin/getprop sys.usb.config)" = adb
  guard test "$(/system/bin/getprop sys.usb.state)" = adb
  guard test "$(/system/bin/getprop sys.usb.controller)" = 700d0000.xudc
  guard test "$(read_attr "$UDC")" = 700d0000.xudc
  guard test "$(read_attr "$DC")" = 1
  guard test "$(read_attr "$HOST")" = 0
  guard test -L /sys/bus/platform/devices/50000000.host1x/driver
  guard test "$(readlink -f /sys/bus/platform/devices/50000000.host1x/driver)" = /sys/bus/platform/drivers/host1x
  check_clients
  check_temperature
  legacy_usb_host_check
}

run_detached() {
  # No inherited terminal or ADB pipe is needed after this redirection.
  exec </dev/null >>"$RAM/runner.log" 2>&1
  [ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || fatal 'REFUSE runner identity'
  [ ! -e "$CG" ] || fatal 'REFUSE existing runner cgroup'
  mkdir "$CG" || fatal 'REFUSE cgroup create failed'
  printf '%s\n' "$$" > "$CG/cgroup.procs" || fatal 'REFUSE cgroup move failed'
  guard test "$(cat /proc/$$/cgroup)" = 0::/shield-native
  # A child created after migration must inherit the independent cgroup too.
  /system/bin/sh -c 'cat /proc/self/cgroup' > "$RAM/child-cgroup"
  guard test "$(cat "$RAM/child-cgroup")" = 0::/shield-native
  read _pid _comm _state _ppid _pgrp _sid _rest < /proc/$$/stat
  guard test "$_pgrp" = "$$"
  guard test "$_sid" = "$$"
  printf '%s\n' "$$" > "$RAM/runner.pid"
  guard test "$SHIELD_LEGACY_WDT_FD" = 9
  guard test "$(readlink /proc/$$/fd/9)" = /dev/watchdog0
  guard test -f "$RAM/WATCHDOG_ARMED"
  preflight
  DEADLINE=$(($(now) + 120))
  printf '%s\n' INDEPENDENT_RUNNER_READY_V1 > "$RAM/READY"
  log 'READY independent session/cgroup; loaded RAM image not executed'
  while [ ! -e "$RAM/RELEASE" ]; do
    time_guard
    [ ! -e "$RAM/CANCEL" ] || fatal 'cancelled before release'
    sleep 1
  done
  time_guard
  guard test "$(cat "$RAM/RELEASE")" = EXECUTE_NATIVE_QUALIFICATION_V1
  DEADLINE=$(($(now) + 25))
  preflight
  time_guard
  log 'RELEASED begin bounded legacy quiesce'
  stop_service recovery
  guard test -z "$(pidof recovery)"
  stop_service console
  stop_service vendor.health-default
  guard test "$(/system/bin/getprop init.svc.fastbootd)" = stopped
  storage_quiet
  check_clients
  time_guard
  # Mark before entering the driver: timeout alone cannot prove no mutation.
  DISPLAY_TOUCHED=1
  write_attr "$DC" 0 || fatal 'display disable failed or timed out'
  guard test "$(read_attr "$DC")" = 0
  log 'DISPLAY_DISABLED_READBACK_0'
  check_clients
  guard test "$(read_attr "$HOST")" = 0
  write_attr "$HOST" 1 || fatal 'host1x force-idle failed or timed out'
  guard test "$(read_attr "$HOST")" = 1
  HOST_IDLED=1
  log 'HOST1X_FORCE_IDLE_READBACK_1'
  _emc=$(read_attr "$EMC") || fatal 'post-idle EMC read failed'
  case "$_emc" in ''|*[!0-9]*) fatal 'invalid post-idle EMC rate' ;; esac
  [ "$_emc" -gt 0 ] || fatal 'zero post-idle EMC rate'
  log "POST_IDLE_EMC_HZ $_emc (observed now; no assumed1600000000)"
  legacy_usb_host_remove
  guard test "$(read_attr /sys/kernel/kexec_loaded)" = 1
  guard test "$(/system/bin/getprop init.svc.recovery)" = stopped
  guard test -z "$(pidof recovery)"
  check_temperature
  guard test "$(cat /proc/$$/cgroup)" = 0::/shield-native
  time_guard
  log 'PRE_DISCONNECT all gates passed; next action configfs none; host tail may now disconnect'
  sleep 1
  # These are the captured recovery init.rc195..201 rules, not generic policy.
  # Recovery has already stopped, so it cannot request a new gadget mode.
  /system/bin/setprop sys.usb.config none || fatal 'cannot request gadget none'
  wait_property sys.usb.state none || fatal 'init did not finish gadget none'
  guard test "$(/system/bin/getprop sys.usb.config)" = none
  guard test "$(/system/bin/getprop sys.usb.ffs.ready)" = 0
  guard test "$(/system/bin/getprop init.svc.adbd)" = stopped
  guard test "$(/system/bin/getprop init.svc.fastbootd)" = stopped
  guard test -z "$(read_attr "$UDC")"
  guard test ! -e /config/usb_gadget/g1/configs/b.1/f1
  guard test "$(cat /proc/$$/cgroup)" = 0::/shield-native
  time_guard
  log 'USB_UNBOUND_ADBD_STOPPED_RUNNER_SURVIVED; invoking ordinary kexec-e'
  "$RAM/kexec" -e
  fatal 'kexec-e returned; legacy kernel may already be partly shut down'
}

case "$1" in
  --arm)
    [ "$(id -u)" = 0 ] && [ "$(id -Z)" = u:r:su:s0 ] || exit 1
    [ -d "$RAM" ] && [ -f "$RAM/legacy-handoff.sh" ] || exit 1
    [ ! -e "$RAM/READY" ] && [ ! -e "$RAM/RELEASE" ] && [ ! -e "$CG" ] || exit 1
    "$TB" nohup "$TB" setsid "$RAM/legacy-watchdog-exec" /system/bin/sh "$RAM/legacy-handoff.sh" --runner </dev/null >>"$RAM/runner.log" 2>&1 &
    printf '%s\n' 'Runner spawned; inspect READY, runner.pid, cgroup and runner.log before separate RELEASE.'
    ;;
  --runner)
    # C deliberately passes ignored HUP/INT/TERM through this entire handoff.
    # POSIX noninteractive shells cannot make those catchable on entry. They
    # are NOT an abort protocol. Cancellation is the fixed CANCEL marker only
    # before RELEASE; after RELEASE, the runner's own checks/deadlines apply.
    # Protect ordinary script failure before its first fallible redirection.
    trap 'hold_watchdog' 0
    run_detached
    ;;
  *) printf '%s\n' 'Source draft: --arm only after reviewed RAM load/segment receipt; no automatic release.'; exit 2 ;;
esac
