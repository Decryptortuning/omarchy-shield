# Sourced by the optional BusyBox diagnostic init only, never the desktop.
if grep -q 'shield.usb-console=1' /proc/cmdline; then
  # The USB diagnostic builder installs this library into the ramdisk root.
  # shellcheck disable=SC1091
  . /usb-gadget.sh
  if modprobe tegra_xudc && shield_usb_gadget_create shield 700d0000.usb; then
    # Opening ttyGS0 waits for the PC, so keep PID 1's diagnostic path running.
    (
      while true; do
        setsid sh -c '
          exec </dev/ttyGS0 >/dev/ttyGS0 2>&1
          echo "Omarchy Shield diagnostic USB console; volatile root filesystem."
          exec cttyhack sh -i
        '
        sleep 1
      done
    ) &
    echo 'Diagnostic USB serial prepared; physical enumeration is unqualified.'
  else
    echo 'Diagnostic USB serial unavailable; no persistent storage was changed.'
  fi
fi
