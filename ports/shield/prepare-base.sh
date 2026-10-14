#!/bin/bash
# Prepare a signed ARM userspace directory; never partition or flash a drive.
set -euo pipefail
port=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_root=$(realpath -- "${1:?Pass the absolute native Linux build directory}")
lock=$port/userspace.lock.json
rootfs=$build_root/rootfs
[[ $build_root != / && -d $build_root && ! -L $build_root ]] || { echo 'Use an owned native WSL build directory' >&2; exit 1; }
(( EUID == 0 )) || { echo 'Run this preparation helper as WSL root' >&2; exit 1; }
readarray -t source < <(python3 - "$lock" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))['rootfs']
for field in ('filename','url','sha256','signature_sha256','signer_fingerprint','keyring_sha256'):
 print(d[field])
PY
)
archive=$build_root/downloads/${source[0]}
[[ -f $archive ]] || { echo "Fetch the pinned archive first: $archive" >&2; exit 1; }
printf '%s  %s\n' "${source[2]}" "$archive" | sha256sum --check --status
metadata=$build_root/repository-metadata
printf '%s  %s\n' "${source[3]}" "$metadata/rootfs-sig" "${source[5]}" "$metadata/alarm-key" | sha256sum --check --status
gpg_dir=$(mktemp -d "$build_root/verify.XXXXXX")
trap 'rm -rf "$gpg_dir"' EXIT
gpg --homedir "$gpg_dir" --batch --dearmor --output "$gpg_dir/alarm.gpg" "$metadata/alarm-key"
gpgv --homedir "$gpg_dir" --keyring "$gpg_dir/alarm.gpg" --status-fd 1 "$metadata/rootfs-sig" "$archive" >"$gpg_dir/status"
grep -qF "[GNUPG:] VALIDSIG ${source[4]} " "$gpg_dir/status"
[[ ! -e $rootfs ]] || { echo "Refusing to replace existing rootfs: $rootfs" >&2; exit 1; }
mkdir -m 0755 "$rootfs"
bsdtar --numeric-owner -xpf "$archive" -C "$rootfs"
install -m 0755 /usr/bin/qemu-aarch64-static "$rootfs/usr/bin/qemu-aarch64-static"
chroot "$rootfs" /usr/bin/qemu-aarch64-static /usr/bin/uname -m | grep -qx aarch64
install -D -m 0644 "$lock" "$rootfs/var/lib/shield-linux/sources.lock.json"
install -m 0644 "$gpg_dir/status" "$build_root/rootfs-signature.status"
printf 'Signed ARM64 userspace prepared: %s\n' "$rootfs"
