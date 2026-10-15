#!/bin/bash
# Runs only in the disposable, network-disconnected QEMU image.
set -euo pipefail
finish() {
  result=$?
  if (( result != 0 )); then
    echo "SHIELD_OMARCHY_QEMU_USERSPACE_FAIL status=$result"
    journalctl -b -u "user@${test_uid:-1002}.service" --no-pager || true
    systemctl --failed --no-pager || true
    coredumpctl --no-pager info Hyprland || true
    if [[ -n ${test_uid:-} ]]; then
      find "/run/user/$test_uid/hypr" /home/qemutest/.cache/hyprland -name '*.log' -type f -exec tail -n 50 {} \; 2>/dev/null || true
    fi
  fi
}
trap finish EXIT
grep -q 'shield.qemu-userspace-test=1' /proc/cmdline
[[ $(uname -m) == aarch64 ]]
[[ $(cat /proc/1/comm) == systemd ]]
[[ $(uname -r) == $(cat /var/lib/shield-linux/kernel-release.txt) ]]
[[ $(getconf PAGESIZE) == 4096 ]]
echo 'CHECK: custom ARM kernel and systemd PID 1'
[[ -r /proc/pressure/memory ]]
systemctl start systemd-oomd
systemctl is-active systemd-oomd
echo 'CHECK: pressure stall reporting and Omarchy memory-pressure service'
systemctl is-active systemd-zram-setup@zram0.service dev-zram0.swap
grep -q '\[zstd\]' /sys/block/zram0/comp_algorithm
swapon --show
echo 'CHECK: Omarchy zstd compressed swap is active'
pacman -Dk
mapfile -t packages < /var/lib/shield-linux/repository-packages.txt
pacman -T "${packages[@]}" omarchy-shield
pacman -Q linux-shield omarchy omarchy-settings omarchy-shield hyprland quickshell mesa vulkan-nouveau
echo 'CHECK: installed package database and complete requested package set'
[[ $(/usr/bin/omarchy-hw-platform) == aarch64 ]]
echo 'CHECK: QEMU hardware remains plain aarch64, never a physical Shield pass'
for module in nouveau brcmfmac r8152 r8169 hci_uart tegra_cec snd_hda_tegra tegra_xudc; do
  version=$(modinfo -k "$(uname -r)" -F vermagic "$module")
  [[ $version == "$(uname -r) "* ]]
  modprobe --dry-run "$module"
done
echo 'CHECK: matching driver metadata and dependency resolution'
/bin/bash /var/lib/shield-linux/qemu-usb-test.sh
systemctl start systemd-user-sessions
test_uid=$(id -u qemutest)
test_gid=$(id -g qemutest)
install -d -m 0700 -o "$test_uid" -g "$test_gid" "/run/user/$test_uid"
loginctl enable-linger qemutest
systemctl start "user@$test_uid.service"
systemctl is-active "user@$test_uid.service"
runuser -u qemutest -- env XDG_RUNTIME_DIR="/run/user/$test_uid" timeout 30 Hyprland --version
runuser -u qemutest -- env XDG_RUNTIME_DIR="/run/user/$test_uid" timeout 30 qs --version
timeout 30 pipewire --version
timeout 30 wireplumber --version
timeout 30 NetworkManager --version
timeout 30 /usr/lib/bluetooth/bluetoothd --version
timeout 30 cec-ctl --version
timeout 30 v4l2-ctl --version
systemctl is-active systemd-udevd
systemctl start dbus
systemctl is-active dbus
echo 'CHECK: desktop, audio, network and peripheral userspace binaries'
# shellcheck disable=SC2016 # Expand these paths in the guest user's shell.
runuser -u qemutest -- env HOME=/home/qemutest OMARCHY_PATH=/usr/share/omarchy /bin/bash -c '
  set -e
  test -f "$HOME/.config/hypr/hyprland.lua"
  test -f /usr/share/omarchy/shell/shell.qml
  test -f /usr/local/share/wayland-sessions/omarchy.desktop
  /usr/bin/omarchy-hw-aarch64
  /usr/bin/omarchy-shell --help >/dev/null
'
echo 'CHECK: user defaults and installed Omarchy session assets'
test_image=/var/tmp/shield-encrypted-filesystem-test.img
test_mount=/run/shield-filesystem-test
test_key=/run/shield-filesystem-test.key
printf 'disposable-qemu-test-key\n' > "$test_key"
chmod 0600 "$test_key"
truncate -s 512M "$test_image"
loop=$(losetup --find --show "$test_image")
cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --iter-time 100 --key-file "$test_key" "$loop"
cryptsetup open --key-file "$test_key" "$loop" shield-filesystem-test
mkfs.btrfs -q -f /dev/mapper/shield-filesystem-test
mkdir "$test_mount"
mount /dev/mapper/shield-filesystem-test "$test_mount"
btrfs subvolume create "$test_mount/active"
printf 'original data\n' > "$test_mount/active/payload"
btrfs subvolume snapshot -r "$test_mount/active" "$test_mount/checkpoint"
snapper --no-dbus -c shield-selftest create-config "$test_mount/active"
snapshot=$(snapper --no-dbus -c shield-selftest create --print-number --description 'Disposable QEMU test')
[[ $snapshot =~ ^[0-9]+$ ]]
printf 'changed data\n' > "$test_mount/active/payload"
grep -qx 'original data' "$test_mount/checkpoint/payload"
grep -qx 'original data' "$test_mount/active/.snapshots/$snapshot/snapshot/payload"
grep -qx 'changed data' "$test_mount/active/payload"
snapper --no-dbus -c shield-selftest delete "$snapshot"
snapper --no-dbus -c shield-selftest delete-config
umount "$test_mount"
cryptsetup close shield-filesystem-test
losetup --detach "$loop"
rm -f "$test_image" "$test_key"
echo 'CHECK: encrypted loop storage, Btrfs and Snapper snapshot data'
runuser -u qemutest -- env XDG_RUNTIME_DIR="/run/user/$test_uid" OMARCHY_PATH=/usr/share/omarchy \
  timeout 45 Hyprland --verify-config --config /home/qemutest/.config/hypr/hyprland.lua
echo 'CHECK: installed Omarchy Hyprland configuration'
echo SHIELD_OMARCHY_QEMU_USERSPACE_PASS
