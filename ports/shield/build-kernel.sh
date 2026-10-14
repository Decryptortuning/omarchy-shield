#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail

port_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$port_dir/../.." && pwd)
clone_root=$(dirname -- "$project_root")
lock_file=${1:-"$port_dir/kernel.lock.json"}
build_root=${SHIELD_BUILD_ROOT:-"$HOME/build/omarchy-shield"}
cross=${CROSS_COMPILE:-aarch64-linux-gnu-}
jobs=${JOBS:-16}
dist=${SHIELD_DIST_DIR:-"$port_dir/build/kernel"}
export ARCH=arm64 CROSS_COMPILE="$cross"
export LLVM=${LLVM:-1}
export SHIELD_BUILD_MODULES=${SHIELD_BUILD_MODULES:-1}
export KBUILD_BUILD_USER=shield-linux KBUILD_BUILD_HOST=local-build
export KBUILD_BUILD_TIMESTAMP='2026-10-13 00:00:00 UTC'
# This large ARM configuration can change kallsyms size during final linking.
export KALLSYMS_EXTRA_PASS=1

for program in git make gcc bison flex bc curl python3 gzip "${cross}gcc"; do
  command -v "$program" >/dev/null || { echo "Missing dependency: $program" >&2; exit 1; }
done
if [[ $LLVM == 1 ]]; then
  for program in clang ld.lld llvm-strip llvm-objcopy; do
    command -v "$program" >/dev/null || { echo "Missing dependency: $program" >&2; exit 1; }
  done
fi
readarray -t locked < <(python3 - "$lock_file" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for value in (d['kernel']['repository'], d['kernel']['commit'], d['kernel']['device_tree'],
              d['busybox']['version'], d['busybox']['url'], d['busybox']['sha256'],
              d['kernel'].get('source_archive', {}).get('url', ''),
              d['kernel'].get('source_archive', {}).get('sha256', ''),
              d['kernel'].get('config_fragment', ''), d['kernel'].get('variant', '')):
    print(value)
PY
)
[[ ${#locked[@]} == 10 ]] || { echo 'Invalid source lock' >&2; exit 1; }
kernel_repo="$clone_root/${locked[0]}"
kernel_commit=${locked[1]}
dtb=${locked[2]}
busybox_version=${locked[3]}
kernel_src="$build_root/sources/kernel-$kernel_commit"
kernel_out="$build_root/kernel-out-$kernel_commit"
variant=${locked[9]}
if [[ -n $variant ]]; then
  [[ $variant =~ ^[a-z0-9-]+$ ]] || { echo 'Invalid kernel variant' >&2; exit 1; }
  kernel_out="$kernel_out-$variant"
fi
busybox_src="$build_root/sources/busybox-$busybox_version"
busybox_out="$build_root/busybox-out"
ramdisk_root="$build_root/ramdisk"
if [[ ${SHIELD_USB_CONSOLE:-0} == 1 ]]; then
  [[ $SHIELD_BUILD_MODULES == 1 ]] || { echo 'USB diagnostics require matching modules' >&2; exit 1; }
  ramdisk_root=$(mktemp -d "$build_root/ramdisk-usb-console.XXXXXX")
fi
mkdir -p "$build_root/sources" "$build_root/downloads" "$kernel_out" "$busybox_out" "$dist"

# Archive the locked commit, independent of checkout state or local modifications.
git -C "$kernel_repo" cat-file -e "$kernel_commit^{commit}"
if [[ ! -f "$kernel_src/.shield-source-commit" ]]; then
  [[ ! -e "$kernel_src" ]] || { echo "Incomplete extraction: $kernel_src" >&2; exit 1; }
  if [[ -n ${locked[6]} ]]; then
    snapshot="$build_root/downloads/kernel-$kernel_commit.tar.gz"
    if [[ ! -f "$snapshot" ]]; then
      curl --fail --location --retry 2 --connect-timeout 15 --max-time 300 \
        --output "$snapshot.part" "${locked[6]}"
      mv "$snapshot.part" "$snapshot"
    fi
    printf '%s  %s\n' "${locked[7]}" "$snapshot" | sha256sum --check --status
    python3 "$port_dir/tools/extract-kernel-snapshot.py" \
      "$kernel_repo" "$kernel_commit" "$snapshot" "$kernel_src"
  else
    temp_source=$(mktemp -d "$build_root/sources/kernel-extract.XXXXXX")
    git -C "$kernel_repo" archive "$kernel_commit" | tar -xf - -C "$temp_source"
    printf '%s\n' "$kernel_commit" > "$temp_source/.shield-source-commit"
    mv "$temp_source" "$kernel_src"
  fi
fi
[[ $(cat "$kernel_src/.shield-source-commit") == "$kernel_commit" ]]
python3 "$port_dir/tools/apply-kernel-patches.py" "$project_root" "$lock_file" "$kernel_src"

archive="$build_root/downloads/busybox-$busybox_version.tar.bz2"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --retry 2 --connect-timeout 15 --max-time 300 \
    --output "$archive.part" "${locked[4]}"
  mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "${locked[5]}" "$archive" | sha256sum --check --status
if [[ ! -d "$busybox_src" ]]; then
  tar -xjf "$archive" -C "$build_root/sources"
fi

fragments=("$port_dir/config/bringup.fragment")
if [[ -n ${locked[8]} ]]; then
  fragment=$(realpath -- "$project_root/${locked[8]}")
  [[ $fragment == "$project_root/"* && -f $fragment ]] || { echo 'Invalid variant fragment' >&2; exit 1; }
  fragments+=("$fragment")
fi
make -C "$kernel_src" O="$kernel_out" defconfig
"$kernel_src/scripts/kconfig/merge_config.sh" -m -O "$kernel_out" \
  "$kernel_out/.config" "${fragments[@]}"
make -C "$kernel_src" O="$kernel_out" olddefconfig
targets=(Image Image.gz "$dtb")
if [[ ${SHIELD_BUILD_MODULES:-0} == 1 ]]; then
  targets+=(modules)
fi
make -C "$kernel_src" O="$kernel_out" -j"$jobs" "${targets[@]}"
if [[ ${SHIELD_BUILD_MODULES:-0} == 1 ]]; then
  module_root="$build_root/kernel-modules-$kernel_commit${variant:+-$variant}"
  make -C "$kernel_src" O="$kernel_out" INSTALL_MOD_PATH="$module_root" INSTALL_MOD_STRIP=1 modules_install
  release=$(make -s -C "$kernel_src" O="$kernel_out" kernelrelease)
  printf '%s\n' "$release" > "$dist/kernel-release.txt"
  tar --zstd --exclude="lib/modules/$release/build" --exclude="lib/modules/$release/source" \
    -cf "$dist/kernel-modules.tar.zst" -C "$module_root" lib/modules
fi

make -C "$busybox_src" O="$busybox_out" allnoconfig
"$kernel_src/scripts/config" --file "$busybox_out/.config" --disable SH_IS_NONE
for symbol in STATIC ASH SH_IS_ASH ASH_JOB_CONTROL ASH_ECHO ASH_PRINTF ASH_TEST \
  FEATURE_PREFER_APPLETS FEATURE_SH_STANDALONE CAT CHMOD CLEAR CP CUT DF DMESG \
  ECHO ENV FALSE FIND FREE GREP HEAD ID KILL LN LS MKDIR MKNOD MOUNT MV \
  POWEROFF PRINTF PS PWD READLINK REBOOT RM RMDIR SED SETSID CTTYHACK SLEEP \
  STAT SYNC TAIL TEE TEST TRUE TR TTY UMOUNT UNAME WC XARGS \
  INSMOD LSMOD MODPROBE RMMOD; do
  "$kernel_src/scripts/config" --file "$busybox_out/.config" --enable "$symbol"
done
"$kernel_src/scripts/config" --file "$busybox_out/.config" --set-str DEFAULT_MODULES_DIR '/lib/modules'
"$kernel_src/scripts/config" --file "$busybox_out/.config" --set-str DEFAULT_DEPMOD_FILE 'modules.dep'
make -C "$busybox_src" O="$busybox_out" oldconfig </dev/null
make -C "$busybox_src" O="$busybox_out" -j"$jobs"
make -C "$busybox_src" O="$busybox_out" CONFIG_PREFIX="$ramdisk_root" install
mkdir -p "$ramdisk_root"/{dev,proc,sys,run,tmp,etc}
install -m 0755 "$port_dir/ramdisk/init" "$ramdisk_root/init"
if [[ ${SHIELD_USB_CONSOLE:-0} == 1 ]]; then
  install -m 0644 "$port_dir/diagnostic/usb-gadget.sh" "$ramdisk_root/usb-gadget.sh"
  install -m 0644 "$port_dir/diagnostic/usb-console-start.sh" "$ramdisk_root/usb-console-start.sh"
  mkdir -p "$ramdisk_root/lib/modules/$release"
  for module in tegra_xudc usb_f_acm; do
    dependencies=$(modprobe -C /dev/null -d "$module_root" -S "$release" --show-depends "$module")
    while IFS= read -r dependency; do
      [[ $dependency == 'insmod '* ]] || continue
      file=${dependency#insmod }
      file=${file%"${file##*[![:space:]]}"}
      [[ $file == "$module_root/"* && -f $file ]] || { echo 'Invalid module dependency path' >&2; exit 1; }
      install -Dm644 "$file" "$ramdisk_root/${file#"$module_root/"}"
    done <<< "$dependencies"
  done
  for metadata in modules.dep modules.alias modules.softdep modules.builtin; do
    cp "$module_root/lib/modules/$release/$metadata" "$ramdisk_root/lib/modules/$release/"
  done
fi
python3 - "$dist/ramdisk-profile.json" "${SHIELD_USB_CONSOLE:-0}" <<'PY'
import json, sys
usb = sys.argv[2] == '1'
with open(sys.argv[1], 'w') as output:
    json.dump({'kind': 'diagnostic', 'usb_console_included': usb,
               'usb_console_requires_cmdline': 'shield.usb-console=1' if usb else None,
               'physical_enumeration_tested': False, 'flashable_image': False}, output, indent=2)
    output.write('\n')
PY
(
  cd "$kernel_out"
  "$kernel_src/usr/gen_initramfs.sh" -o "$dist/initramfs.cpio" -u squash -g squash \
    -d "$KBUILD_BUILD_TIMESTAMP" "$ramdisk_root" "$port_dir/config/ramdisk-devices.list"
)
gzip -n -f "$dist/initramfs.cpio"
cp "$kernel_out/arch/arm64/boot/Image" "$dist/Image"
cp "$kernel_out/arch/arm64/boot/Image.gz" "$dist/Image.gz"
cp "$kernel_out/arch/arm64/boot/dts/$dtb" "$dist/"
python3 "$port_dir/tools/apply-device-tree-overlays.py" "$project_root" "$lock_file" "$dist/$(basename -- "$dtb")"
cp "$kernel_out/.config" "$dist/kernel.config"
cp "$busybox_out/.config" "$dist/busybox.config"
cp "$lock_file" "$dist/sources.lock.json"
if [[ -f "$kernel_src/.shield-source-verification.json" ]]; then
  cp "$kernel_src/.shield-source-verification.json" "$dist/source-verification.json"
fi
if [[ -f "$kernel_src/.shield-applied-patches.json" ]]; then
  cp "$kernel_src/.shield-applied-patches.json" "$dist/applied-patches.json"
fi
if [[ ${LLVM:-0} == 1 ]]; then
  clang --version > "$dist/compiler.txt"
else
  "${cross}gcc" --version > "$dist/compiler.txt"
fi
(
  cd "$dist"
  sha256sum Image Image.gz initramfs.cpio.gz "$(basename -- "$dtb")" \
    kernel.config busybox.config sources.lock.json compiler.txt > SHA256SUMS
  sha256sum ramdisk-profile.json >> SHA256SUMS
  if [[ -f source-verification.json ]]; then
    sha256sum source-verification.json >> SHA256SUMS
  fi
  if [[ -f applied-patches.json ]]; then
    sha256sum applied-patches.json >> SHA256SUMS
  fi
  if [[ -f device-tree-overlays.json ]]; then
    sha256sum device-tree-overlays.json >> SHA256SUMS
  fi
  if [[ ${SHIELD_BUILD_MODULES:-0} == 1 ]]; then
    sha256sum kernel-release.txt kernel-modules.tar.zst >> SHA256SUMS
  fi
)
printf 'Build artifacts: %s\n' "$dist"
