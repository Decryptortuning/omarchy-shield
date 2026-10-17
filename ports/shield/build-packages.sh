#!/bin/bash
set -euo pipefail
[[ $(uname -m) == aarch64 && -f /var/lib/shield-linux/sources.lock.json ]] || exit 1
export OMARCHY_ALLOW_DIRECT_PACMAN=1
id portbuild >/dev/null 2>&1 || useradd --create-home --shell /bin/bash portbuild
chown -R portbuild:portbuild /build
for package in mesa-shield linux-shield omarchy omarchy-settings omarchy-shield; do
  # shellcheck disable=SC2016 # $1 is the child shell's positional argument.
  runuser -u portbuild -- env OMARCHY_SRC=/build/omarchy-src SHIELD_KERNEL_DIR=/build/kernel-inputs SHIELD_MESA_DIR=/build/mesa-inputs \
    bash -c 'cd "/build/$1" && exec makepkg --noconfirm --nodeps --cleanbuild --force' bash "$package"
done
exec /bin/bash /var/lib/shield-linux/install-target-packages.sh
