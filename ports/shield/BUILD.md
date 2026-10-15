# Offline build workflow

These tools build Linux components and an ARM development filesystem on an x86-64 Linux/WSL host. They do not create a Shield installer, unlock a device, partition a disk or flash anything. Keep the native build directory on Linux storage rather than NTFS. The prepared filesystem contains development accounts and a build signing keyring; do not deploy or distribute it without owner/account, machine-key and boot finalization.

## Host and source inputs

On Ubuntu 24.04 the tools used here are `git make gcc gcc-aarch64-linux-gnu libc6-dev-arm64-cross clang lld llvm libelf-dev bison flex bc libssl-dev python3 curl gzip cpio zstd libarchive-tools gnupg qemu-user-static qemu-system-arm rsync util-linux e2fsprogs device-tree-compiler kmod`. Source staging needs Python 3.12 or later. Keep Linux repositories under `/home/jresp/Active_GH` and use WSL Git/native tools. No Docker daemon or host ARM package configuration is used.

Clone the `ack-tegra` repository beside this checkout using the URL/branch in [kernel.lock.json](kernel.lock.json), and `omacom/omarchy-pkgs` beside it using [userspace.lock.json](userspace.lock.json). The build verifies the exact commits. Kernel source archives are checked against the pinned SHA256 and the Git object identities before the recorded regulator patch is applied. A source cache can be reused only with the same base commit and ordered patch hashes, with a reverse-application check on every patch.

## Kernel and diagnostic boot

Run from the fork's repository root:

```sh
build_root="$HOME/build/omarchy-shield"
mkdir -p "$build_root"
SHIELD_BUILD_ROOT="$build_root/kernel-cache" SHIELD_DIST_DIR="$build_root/kernel" \
  bash ports/shield/build-kernel.sh
SHIELD_DIST_DIR="$build_root/kernel" bash ports/shield/tools/smoke-kernel.sh
(cd "$build_root/kernel" && sha256sum --check SHA256SUMS)
```

The default lock now selects original Tegra210 Darcy with the A08 evaluation DTB and its CEC overlay. To build the separate B01 B00 candidate, pass `ports/shield/kernel-mdarcy.lock.json` to `build-kernel.sh` and select a different output directory. Never mix their DTBs, matrices or firmware. The actual connected device's board SKU is not yet verified.

Both profiles include the full module set, LLVM and an extra kallsyms link pass. QEMU uses its own virtual DTB; its pass does not exercise a Shield overlay or peripheral. Output contains raw `Image`, diagnostic initramfs, DTB, matching modules, checksum-locked hardware matrix and provenance. No Android boot header or flashing command is supplied. The kernel package validates the lock's board/DTB pair and ships only that selected DTB.

## Signed ARM filesystem and packages

The base tarball, signature and keyring are checksum-pinned. Signature verification additionally requires the exact Arch Linux ARM build-system fingerprint in the lock. The download URL points at a moving upstream archive: if it changes, the fetch fails instead of accepting a new base. Retain the verified cache or review a new signed input deliberately.

```sh
python3 ports/shield/fetch-base.py --build-root "$build_root"
sudo bash ports/shield/prepare-base.sh "$build_root"
python3 ports/shield/audit-packages.py \
  --metadata-dir "$build_root/repository-metadata" --output "$build_root/package-audit.json"
sudo python3 ports/shield/configure-build.py --rootfs "$build_root/rootfs" \
  --recipes ../omarchy-pkgs --metadata-dir "$build_root/repository-metadata" \
  --audit "$build_root/package-audit.json"
sudo bash ports/shield/chroot.sh "$build_root/rootfs" \
  /bin/bash /var/lib/shield-linux/bootstrap-packages.sh
sudo python3 ports/shield/stage-packages.py --rootfs "$build_root/rootfs" \
  --recipes ../omarchy-pkgs --kernel-dir "$build_root/kernel"
sudo bash ports/shield/chroot.sh "$build_root/rootfs" \
  /bin/bash /var/lib/shield-linux/build-target-packages.sh
```

The bootstrap installs the complete repository package set from pinned sync databases. The four local packages are `linux-shield`, `omarchy`, `omarchy-settings` and `omarchy-shield`. Current paired runtime/settings recipes use release `99.3`. Local installation validates dependencies together and replaces the generic ALARM kernel through its declared conflict. `linux-shield` owns modules and selected kernel/DTB/matrix inputs under `/usr/lib/omarchy/shield/kernel`; it has no boot-partition install hook. The platform package includes both acceptance matrices and the guarded collector.

The chroot uses private mount/PID namespaces, temporary device nodes and Cortex-A57 user emulation. It serializes its temporary binfmt registration, exposes no host block devices or sysfs tree, and starts no host daemons. Pacman signature validation stays enabled. Its sandbox exception applies to this emulated build command because Landlock is unavailable through QEMU user emulation; the installed configuration keeps normal sandbox settings. Fork packages are ignored by repository upgrades until a tested Shield release/update path exists.

## Whole-filesystem VM test

```sh
sudo env SHIELD_DIST_DIR="$build_root/kernel" \
  bash ports/shield/tools/prepare-qemu.sh "$build_root"
SHIELD_DIST_DIR="$build_root/kernel" \
  bash ports/shield/tools/smoke-userspace.sh "$build_root"
python3 ports/shield/audit-hardware.py --kernel-dir "$build_root/kernel" \
  --rootfs "$build_root/rootfs" --output "$build_root/hardware-audit.json"
```

The VM boots the custom kernel with the installed filesystem, disconnected from networking and with a disposable disk snapshot. It checks systemd, package dependencies, matching modules, zstd compressed swap, desktop binary startup, user/session assets and an encrypted loop filesystem with independent Btrfs snapshot data. The emulated board must remain plain `aarch64`; no virtual test changes the physical acceptance matrix. This is development coverage, separate from native Hyprland rendering, physical firmware matching, USB SSD boot and cooling qualification.

The current test also starts the systemd user manager and memory-pressure service, verifies the installed Hyprland configuration, exercises Snapper, and checks USB CDC ACM enumeration/data through a virtual `dummy_hcd` controller. That USB check deliberately binds a virtual UDC, never a physical controller. `audit-userspace.py --rootfs "$build_root/rootfs" --output "$build_root/userspace-abi-audit.json"` separately checks native ELF payloads under `usr` and `opt`; it does not prove application behavior or CPU instruction compatibility.

## Firmware candidates and USB-only diagnostics

```sh
python3 ports/shield/fetch-firmware-candidates.py --build-root "$build_root"
SHIELD_BUILD_ROOT="$build_root/kernel-cache" SHIELD_DIST_DIR="$build_root/usb-diagnostic" \
  SHIELD_USB_CONSOLE=1 bash ports/shield/build-kernel.sh
```

The firmware tool extracts checksum-pinned files from NVIDIA's original L4T 32.2.1 archive and retains its license. It validates the B01 XUSB header, Falcon v1 video containers and HCD command framing. These are inactive candidates for comparison with the actual stock device; it does not rename files into the runtime firmware path or execute any BSP install/flash utility. Container checks do not establish firmware command ABI, chip identity or physical behavior.

The optional diagnostic ramdisk includes only USB serial module dependencies in addition to BusyBox. Its root USB shell requires `shield.usb-console=1`, an exact supported board/SoC pair and the Tegra UDC. It stays off otherwise and is never enabled by the desktop. This is an unauthenticated physical debugging console for bring-up, not a production login configuration. Physical Linux gadget enumeration on Windows remains untested. The bundle is still raw components; stock boot headers and recovery must be established before booting it.

On Windows, `ports/shield/inspect-usb.ps1` performs bounded read-only ADB/fastboot inventory. Reports default to ignored `ports/shield/build`. It never reboots, unlocks or flashes. ADB classification requires NVIDIA Shield identity and Tegra chip ID/major revision; `darcy` alone does not select a silicon generation. Unsupported fastboot variables remain explicitly unavailable even when the bootloader returns a successful command status.

## Inspecting an existing stock boot image

Clone AOSP's `platform/system/tools/mkbootimg` beside this checkout using [boot-tools.lock.json](boot-tools.lock.json). The wrapper exports only the pinned commit into a temporary directory, regardless of checkout changes. With an owner-supplied saved boot or recovery image:

```sh
python3 ports/shield/inspect-boot-image.py --tools ../mkbootimg \
  --image "$build_root/stock-boot.img" --output "$build_root/stock-boot-inspection"
```

This preserves the input and extracts the header and payloads into a new directory. Generated command arguments are recorded as a JSON array, never executed. Four upstream Android v0/v1/v2 image tests and a synthetic wrapper fixture have passed; no actual Shield image, load address, device-tree handoff or temporary-boot route has been validated. This tool neither repacks nor flashes an image.
