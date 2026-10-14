# Offline build workflow

These tools build Linux components and an ARM development filesystem on an x86-64 Linux/WSL host. They do not create a Shield installer, unlock a device, partition a disk or flash anything. Keep the native build directory on Linux storage rather than NTFS. The prepared filesystem contains development accounts and a build signing keyring; do not deploy or distribute it without owner/account, machine-key and boot finalization.

## Host and source inputs

On Ubuntu 24.04 the tools used here are `git make gcc gcc-aarch64-linux-gnu libc6-dev-arm64-cross clang lld llvm libelf-dev bison flex bc libssl-dev python3 curl gzip cpio zstd libarchive-tools gnupg qemu-user-static qemu-system-arm rsync util-linux e2fsprogs`. Source staging needs Python 3.12 or later. No Docker daemon or host ARM package configuration is used.

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

The default build includes the full module set, uses LLVM and an extra kallsyms link pass, and enables the evaluation B00 CEC overlay. QEMU uses its own virtual DTB; its pass does not exercise that overlay or any Shield peripheral. The output contains raw `Image`, a diagnostic initramfs, DTB, modules, configuration and provenance. No Android boot header or flashing command is supplied.

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

The bootstrap installs the complete repository package set from the pinned sync databases. The four fork packages are built locally: `linux-shield`, `omarchy`, `omarchy-settings` and `omarchy-shield`. Paired runtime/settings packages use the exported source version and numeric package release `99.2`. Local package installation validates dependencies together and replaces the generic ALARM kernel through its declared package conflict. `linux-shield` owns its modules and stores kernel/DTB inputs under `/usr/lib/omarchy/shield/kernel`; it has no boot-partition install hook. The platform package includes the hardware matrix and evidence collector.

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
SHIELD_BUILD_ROOT="$build_root/kernel-cache" SHIELD_DIST_DIR="$build_root/usb-diagnostic" \\
  SHIELD_USB_CONSOLE=1 bash ports/shield/build-kernel.sh
```

The firmware tool extracts checksum-pinned files from NVIDIA's original L4T 32.2.1 archive and retains its license. It validates the B01 XUSB header, Falcon v1 video containers and HCD command framing. These are inactive candidates for comparison with the actual stock device; it does not rename files into the runtime firmware path or execute any BSP install/flash utility. Container checks do not establish firmware command ABI, chip identity or physical behavior.

The optional diagnostic ramdisk includes only the USB serial module dependencies in addition to BusyBox. Its root USB shell requires the explicit kernel parameter `shield.usb-console=1`, a supported Tegra210B01 board, and its Tegra UDC. It stays off without that parameter and is never enabled by the desktop. This is an unauthenticated physical debugging console for bring-up, not a production login configuration. Physical enumeration on Windows remains untested. The bundle is still raw components; the actual Shield boot header and recovery route must be established before booting it.

On Windows, `ports/shield/inspect-usb.ps1` performs bounded read-only ADB/fastboot inventory. Its default report lives under the ignored `ports/shield/build` directory. It never reboots, unlocks or flashes, and it refuses Android property inspection after a device identifies as something other than `mdarcy`.
