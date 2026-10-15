# POSIX library shared by the BusyBox diagnostic init and the Bash VM test.
# This configures USB serial only; it never starts a shell or changes storage.
shield_usb_supported_board() {
  shield_usb_tokens=$1
  if printf '%s\n' "$shield_usb_tokens" | grep -Eq '^(apple,|qcom,)'; then return 1; fi
  if printf '%s\n' "$shield_usb_tokens" | grep -qx 'nvidia,p2894-0050-a04' &&
     printf '%s\n' "$shield_usb_tokens" | grep -qx 'nvidia,p2894-0050-a08'; then return 1; fi
  if printf '%s\n' "$shield_usb_tokens" | grep -Eq '^nvidia,p2894-0050-a0[48]$'; then
    printf '%s\n' "$shield_usb_tokens" | grep -qx 'nvidia,tegra210' || return 1
    if printf '%s\n' "$shield_usb_tokens" | grep -Eq '^nvidia,(tegra210b01|p2894-2551-b00)$'; then return 1; fi
  elif printf '%s\n' "$shield_usb_tokens" | grep -qx 'nvidia,p2894-2551-b00'; then
    printf '%s\n' "$shield_usb_tokens" | grep -qx 'nvidia,tegra210b01' || return 1
  else
    return 1
  fi
}

shield_usb_gadget_create() {
  shield_usb_mode=$1
  shield_usb_udc=$2
  [ "$(id -u)" = 0 ] || return 1
  case "$shield_usb_mode" in
    dummy)
      grep -q 'shield.qemu-userspace-test=1' /proc/cmdline || return 1
      tr '\000' '\n' < /proc/device-tree/compatible | grep -qx 'linux,dummy-virt' || return 1
      case "$shield_usb_udc" in dummy_udc.*) ;; *) return 1 ;; esac
      ;;
    shield)
      shield_usb_supported_board "$(tr '\000' '\n' < /proc/device-tree/compatible)" || return 1
      [ "$shield_usb_udc" = '700d0000.usb' ] || return 1
      ;;
    *) return 1 ;;
  esac
  [ -d "/sys/class/udc/$shield_usb_udc" ] || return 1
  modprobe libcomposite || return 1
  modprobe usb_f_acm || return 1
  mkdir -p /sys/kernel/config
  if ! grep -q ' /sys/kernel/config configfs ' /proc/mounts; then
    mount -t configfs configfs /sys/kernel/config || return 1
  fi
  shield_usb_gadget=/sys/kernel/config/usb_gadget/omarchy-shield-diagnostic
  [ ! -e "$shield_usb_gadget" ] || return 1
  mkdir "$shield_usb_gadget" || return 1
  # Upstream serial.c's donated CDC-ACM gadget IDs, for this serial-only probe.
  printf '0x0525\n' > "$shield_usb_gadget/idVendor"
  printf '0xa4a7\n' > "$shield_usb_gadget/idProduct"
  printf '0x0200\n' > "$shield_usb_gadget/bcdUSB"
  printf '0xef\n' > "$shield_usb_gadget/bDeviceClass"
  printf '0x02\n' > "$shield_usb_gadget/bDeviceSubClass"
  printf '0x01\n' > "$shield_usb_gadget/bDeviceProtocol"
  mkdir "$shield_usb_gadget/strings/0x409"
  printf 'shield-diagnostic\n' > "$shield_usb_gadget/strings/0x409/serialnumber"
  printf 'Omarchy Shield development\n' > "$shield_usb_gadget/strings/0x409/manufacturer"
  printf 'Diagnostic USB serial\n' > "$shield_usb_gadget/strings/0x409/product"
  mkdir "$shield_usb_gadget/configs/c.1"
  mkdir "$shield_usb_gadget/configs/c.1/strings/0x409"
  printf 'USB serial diagnostics\n' > "$shield_usb_gadget/configs/c.1/strings/0x409/configuration"
  mkdir "$shield_usb_gadget/functions/acm.usb0"
  ln -s "$shield_usb_gadget/functions/acm.usb0" "$shield_usb_gadget/configs/c.1/acm.usb0"
  printf '%s\n' "$shield_usb_udc" > "$shield_usb_gadget/UDC"
}

shield_usb_gadget_remove() {
  [ -n "${shield_usb_gadget:-}" ] || return 0
  printf '\n' > "$shield_usb_gadget/UDC"
  rm -f "$shield_usb_gadget/configs/c.1/acm.usb0"
  rmdir "$shield_usb_gadget/functions/acm.usb0" "$shield_usb_gadget/configs/c.1/strings/0x409" \
    "$shield_usb_gadget/configs/c.1" "$shield_usb_gadget/strings/0x409" "$shield_usb_gadget"
}
