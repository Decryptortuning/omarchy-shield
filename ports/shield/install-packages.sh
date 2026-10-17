#!/bin/bash
set -euo pipefail
shield_install_packages() {
  local build=$1 state=$2 selected
  local -a packages
  [[ $(uname -m) == aarch64 && -f $state/sources.lock.json ]] || return 1
  export OMARCHY_ALLOW_DIRECT_PACMAN=1
  selected=$(python "$build/omarchy-src/ports/shield/tools/package_set.py" \
    --build "$build" --intent "$state/package-artifacts-intent.json") || return 1
  mapfile -t packages <<< "$selected"
  (( ${#packages[@]} == 5 )) || return 1
  # Answer only the declared package-conflict question (ALPM bit 1 << 2), which
  # replaces the generic ALARM kernel in this isolated build filesystem.
  pacman -U --disable-sandbox --noconfirm --ask=4 "${packages[@]}"
  pacman -Q > "$state/installed-packages.txt"
  pacman -Q mesa linux-shield omarchy omarchy-settings omarchy-shield hyprland quickshell
  echo SHIELD_OMARCHY_LOCAL_PACKAGES_INSTALLED
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  shield_install_packages /build /var/lib/shield-linux
fi
