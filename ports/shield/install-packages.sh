#!/bin/bash
set -euo pipefail
[[ $(uname -m) == aarch64 && -f /var/lib/shield-linux/sources.lock.json ]] || exit 1
export OMARCHY_ALLOW_DIRECT_PACMAN=1
mapfile -t packages < <(find /build/linux-shield /build/omarchy /build/omarchy-settings /build/omarchy-shield -maxdepth 1 -name '*.pkg.tar.*' ! -name '*.sig' ! -name '*-debug-*' | sort)
(( ${#packages[@]} == 4 )) || { echo 'Expected exactly the kernel, paired runtime/settings and Shield platform packages' >&2; exit 1; }
# Answer only the declared package-conflict question (ALPM bit 1 << 2), which
# replaces the generic ALARM kernel in this isolated build filesystem.
pacman -U --disable-sandbox --noconfirm --ask=4 "${packages[@]}"
pacman -Q > /var/lib/shield-linux/installed-packages.txt
pacman -Q linux-shield omarchy omarchy-settings omarchy-shield hyprland quickshell
echo SHIELD_OMARCHY_LOCAL_PACKAGES_INSTALLED
