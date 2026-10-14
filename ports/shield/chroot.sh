#!/bin/bash
# Isolated build mounts/PID namespace for our newly prepared ARM filesystem.
set -euo pipefail
rootfs=${1:?Usage: omarchy-chroot.sh ROOTFS COMMAND [ARGUMENTS...]}
shift
rootfs=$(realpath -- "$rootfs")
[[ $rootfs != / && $rootfs != /usr && $rootfs != /var && $rootfs != /home ]] || { echo 'Refusing a root outside the port build directory' >&2; exit 1; }
[[ -f $rootfs/var/lib/shield-linux/sources.lock.json ]] || { echo 'Missing prepared Shield rootfs marker' >&2; exit 1; }
(( EUID == 0 )) || { echo 'Run this build helper as WSL root' >&2; exit 1; }
install -d -m 0755 /run/omarchy-shield
exec 9>/run/omarchy-shield/binfmt.lock
flock 9
registered=0
if [[ ! -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]]; then
  cat /usr/lib/binfmt.d/qemu-aarch64.conf > /proc/sys/fs/binfmt_misc/register
  registered=1
fi
cleanup() {
  if (( registered )); then
    echo -1 > /proc/sys/fs/binfmt_misc/qemu-aarch64
  fi
}
trap cleanup EXIT
unshare --mount --pid --fork /bin/bash -s -- "$rootfs" "$@" <<'SH'
set -euo pipefail
rootfs=$1
shift
mount --make-rprivate /
mount --bind "$rootfs" "$rootfs"
mount -t proc proc "$rootfs/proc"
mount -t tmpfs -o mode=0755 tmpfs "$rootfs/dev"
for spec in 'null 1 3' 'zero 1 5' 'full 1 7' 'random 1 8' 'urandom 1 9' 'tty 5 0'; do
  read -r name major minor <<<"$spec"
  mknod -m 0666 "$rootfs/dev/$name" c "$major" "$minor"
done
mkdir -p "$rootfs/dev/pts" "$rootfs/dev/shm"
mount -t devpts -o newinstance,ptmxmode=0666 devpts "$rootfs/dev/pts"
ln -s pts/ptmx "$rootfs/dev/ptmx"
ln -s /proc/self/fd "$rootfs/dev/fd"
ln -s /proc/self/fd/0 "$rootfs/dev/stdin"
ln -s /proc/self/fd/1 "$rootfs/dev/stdout"
ln -s /proc/self/fd/2 "$rootfs/dev/stderr"
mount -t tmpfs -o mode=0755 tmpfs "$rootfs/run"
mount -t tmpfs -o mode=1777 tmpfs "$rootfs/tmp"
chroot "$rootfs" /usr/bin/env -i HOME=/root USER=root PATH=/usr/local/sbin:/usr/local/bin:/usr/bin TERM=dumb LC_ALL=C QEMU_CPU=cortex-a57 "$@"
SH
