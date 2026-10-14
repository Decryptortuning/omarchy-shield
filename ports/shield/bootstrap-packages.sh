#!/bin/bash
# Run only inside the newly prepared ARM build filesystem.
set -euo pipefail
[[ $(uname -m) == aarch64 && -f /var/lib/shield-linux/sources.lock.json ]] || { echo 'Not the prepared ARM target' >&2; exit 1; }
export OMARCHY_ALLOW_DIRECT_PACMAN=1
pacman-key --init
pacman-key --populate archlinuxarm omarchy
mapfile -t packages < /var/lib/shield-linux/repository-packages.txt
# The temporary cross-emulation executable was not package-owned. The native
# target's qemu-user-static package may own that name when defaults are installed.
if ! pacman -Qo /usr/bin/qemu-aarch64-static >/dev/null 2>&1; then
  rm -f /usr/bin/qemu-aarch64-static
fi
# QEMU user emulation does not expose the host's Landlock sandbox API. This
# command-line exception is confined to the isolated build, never pacman.conf;
# normal package signature validation remains enabled.
# These three bootstrap trust files are the pinned upstream keyring payload;
# hand them to their signed package without permitting other file takeovers.
# configure-build.py supplied the checksum-pinned sync databases; do not refresh
# them here and silently change the candidate being built.
pacman -Su --disable-sandbox --needed --noconfirm \
  --overwrite usr/share/pacman/keyrings/omarchy.gpg \
  --overwrite usr/share/pacman/keyrings/omarchy-trusted \
  --overwrite usr/share/pacman/keyrings/omarchy-revoked "${packages[@]}"
pacman -Q > /var/lib/shield-linux/installed-packages.txt
echo SHIELD_OMARCHY_PACKAGES_INSTALLED
