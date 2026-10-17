#!/bin/bash
# Create a disposable VM filesystem; never accept a physical block device.
set -euo pipefail
port=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=ports/shield/tools/qemu-guest-profile.sh
source "$port/tools/qemu-guest-profile.sh"
build_root=$(realpath -- "${1:?Pass the native Linux build directory}")
rootfs=$build_root/rootfs
guest=$build_root/qemu-rootfs
image=$build_root/omarchy-userspace-test.ext4
kernel=${SHIELD_DIST_DIR:-$port/build/kernel}
(( EUID == 0 )) || { echo 'Run as WSL root' >&2; exit 1; }
[[ $build_root != / && ! -L $build_root ]]
[[ -f $rootfs/var/lib/shield-linux/sources.lock.json ]]
shield_qemu_validate_source "$rootfs"
cmp -s "$kernel/Image" "$rootfs/usr/lib/omarchy/shield/kernel/Image" || { echo 'VM kernel differs from the installed linux-shield package' >&2; exit 1; }
cmp -s "$kernel/kernel-release.txt" "$rootfs/usr/lib/omarchy/shield/kernel/kernel-release.txt" || exit 1
[[ ! -e $guest && ! -e $image ]] || { echo 'Preserve or remove the previous owned QEMU build first' >&2; exit 1; }
mkdir "$guest"
rsync -aHAX --numeric-ids --exclude=/build --exclude=/var/cache/pacman/pkg \
  --exclude=/etc/pacman.d/gnupg --exclude=/root/.gnupg --exclude=/home/portbuild \
  "$rootfs/" "$guest/"
# Preserve the package-owned modules already installed in this filesystem.
cp "$kernel/kernel-release.txt" "$guest/var/lib/shield-linux/kernel-release.txt"
install -m 0755 "$port/tools/qemu-userspace-selftest.sh" "$guest/var/lib/shield-linux/qemu-userspace-selftest.sh"
install -m 0755 "$port/tools/qemu-usb-test.sh" "$guest/var/lib/shield-linux/qemu-usb-test.sh"
install -m 0644 "$port/diagnostic/usb-gadget.sh" "$guest/var/lib/shield-linux/usb-gadget.sh"
# Lock inherited development accounts; the test user has no password.
mknod -m 0666 "$guest/dev/null" c 1 3
shield_qemu_lock_accounts "$guest"
shield_qemu_write_mounts "$rootfs" "$guest"
useradd --root "$guest" --create-home --shell /bin/bash qemutest
rm -f "$guest/etc/machine-id" "$guest/var/lib/dbus/machine-id"
touch "$guest/etc/machine-id"
rm -f "$guest/etc/ssh/ssh_host_"*
cat > "$guest/etc/systemd/system/shield-qemu-selftest.service" <<'UNIT'
[Unit]
Description=Shield port userspace test on QEMU virtual hardware
Requires=basic.target systemd-user-sessions.service
After=basic.target systemd-user-sessions.service
SuccessAction=poweroff
FailureAction=poweroff
[Service]
Type=oneshot
ExecStart=/bin/bash /var/lib/shield-linux/qemu-userspace-selftest.sh
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=180
UNIT
cat > "$guest/etc/systemd/system/shield-qemu-selftest.target" <<'UNIT'
[Unit]
Description=Disposable Omarchy ARM userspace qualification
Requires=shield-qemu-selftest.service
After=shield-qemu-selftest.service
AllowIsolate=yes
UNIT
truncate --size 16G "$image"
mkfs.ext4 -q -F -L omarchy-qemu -d "$guest" "$image"
printf 'Disposable QEMU image: %s\n' "$image"
