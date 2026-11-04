#!/bin/bash
# After `reboot recovery` into the direct-boot slot: find the Shield on .210 (Wi-Fi), .146 (Ethernet) or .211 (rescue) and report.
W=$WORK
o=(-F /dev/null -T -i $W/operator-ed25519 -o UserKnownHostsFile=$W/known_hosts -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=omarchy-shield -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=3 -o LogLevel=ERROR)
start=$(date +%s)
while :; do
  t=$(( $(date +%s) - start ))
  for ip in 192.168.2.210 192.168.2.146 192.168.2.211; do
    if timeout 6 ssh "${o[@]}" root@$ip true 2>/dev/null; then
      echo "[$t s] UP at $ip"
      timeout 30 ssh "${o[@]}" root@$ip 'uptime; tr " " "\n" < /proc/cmdline | grep -E "shield\.|kerneltype"; echo "--- loader"; cat /run/shield-loader.log 2>/dev/null; echo "--- counter"; cat /boot/shield-boot/counter /boot/shield-boot/history 2>/dev/null | tail -4; echo "--- units"; for u in sshd shield-direct-boot-ok shield-direct-wifi shield-direct-fan shield-ethernet NetworkManager bluetooth shield-owner-ready shield-owner-thermal; do printf "%s=%s " $u $(systemctl is-active $u); done; echo; systemctl --failed --no-legend | head; echo "--- net"; ip -br addr | grep -v "^lo"; echo "--- usb"; lsusb; echo "--- display"; pgrep -a Hyprland | head -1; cat /sys/class/drm/card*-HDMI-A-1/status 2>/dev/null; echo "--- dmesg warnings"; dmesg | grep -i -E "error|fail|warn" | grep -v -i "firmware.*-2\|regdom" | head -15 | cut -c1-150' 2>&1
      exit 0
    fi
  done
  [ $t -ge 600 ] && { echo "[$t s] TIMEOUT"; exit 3; }
  sleep 3
done
