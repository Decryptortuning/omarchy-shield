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

The default lock selects original Tegra210 Darcy A04, matching the connected device's bootloader-selected and independently captured stock DTB. `ports/shield/kernel-darcy-a08.lock.json` retains the distinct A08 evaluation profile; `ports/shield/kernel-mdarcy.lock.json` selects B01 B00. Pass the chosen lock to `build-kernel.sh` and use a separate output directory. Never mix their DTBs, matrices or firmware.

All three profiles include the full module set, LLVM and an extra kallsyms link pass. QEMU uses its own virtual DTB; its pass does not exercise a Shield overlay or peripheral. Output contains raw `Image`, diagnostic initramfs, DTB, matching modules, checksum-locked hardware matrix and provenance. No Android boot header or flashing command is supplied. The kernel package validates the lock's board/DTB pair and ships only that selected DTB.

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

The bootstrap installs the complete repository package set from pinned sync databases. The four local packages are `linux-shield`, `omarchy`, `omarchy-settings` and `omarchy-shield`. Current paired runtime/settings recipes use release `99.6`; the previous integration build used `99.4`. Local installation validates dependencies together and replaces the generic ALARM kernel through its declared conflict. `linux-shield` owns modules and selected kernel/DTB/matrix inputs under `/usr/lib/omarchy/shield/kernel`; it has no boot-partition install hook. The platform package includes all three acceptance matrices and the guarded collector.

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

This preserves the input and extracts the header and payloads into a new directory. Generated command arguments are recorded as a JSON array, never executed. Four upstream Android v0/v1/v2 image tests and a synthetic wrapper fixture have passed. Exact installed-build stock boot and reconstructed recovery have also been inspected; load-address interpretation, device-tree handoff and temporary-boot behavior remain unqualified. This tool neither repacks nor flashes an image.


## Integration candidate: firmware, fan and diagnostic handoff

The current Darcy candidate adds the Thunderstrike controller driver/force feedback and an explicit inverted fan PWM contract. The Tegra provider complements duty only for `usage_power` consumers. The A08 candidate uses three-cell specifiers: fan channel 3 is inverted, GPU regulator channel 1 remains normal. `pwm-fan` holds an enabled inactive signal at logical zero and restores that state on resume. Source regression does not qualify electrical levels, fan startup or RPM; verify those before load.

Use a new kernel cache because the pinned patch set changed. Preserve the previous validated cache and components. After the combined source/interface review:

```sh
SHIELD_BUILD_ROOT="$HOME/build/shield-linux-integration-v2" \
  SHIELD_DIST_DIR="$build_root/integration-2026-10-14/kernel" \
  SHIELD_USB_CONSOLE=1 bash ports/shield/build-kernel.sh
python3 ports/shield/tools/check-fan-behavior.py \
  --kernel-source "$HOME/build/shield-linux-integration-v2/sources/kernel-9336ceeebe1d75021d9fd98c94abaec522ba39b3" \
  --output "$build_root/integration-2026-10-14/fan-regression.json"
python3 ports/shield/stage-board-firmware.py \
  --input-root "$build_root/harvest-2026-10-14/firmware" \
  --output "$build_root/integration-2026-10-14/firmware"
python3 ports/shield/audit-hardware.py \
  --kernel-dir "$build_root/integration-2026-10-14/kernel" \
  --rootfs "$build_root/rootfs" \
  --firmware-stage "$build_root/integration-2026-10-14/firmware" \
  --output "$build_root/integration-2026-10-14/hardware-audit.json"
```

[firmware-darcy.lock.json](firmware-darcy.lock.json) pins selected original-T210 upstream firmware, exact-release radio inputs, codec interface references and notices. The stager verifies hashes and publishes a complete new inactive directory only after all inputs pass. `--download-upstream` optionally fetches missing upstream files; stock inputs must be supplied locally from the harvest. It never modifies runtime search paths or calibration/MAC data. The audit reports staged availability separately from exact installed byte identity, including compressed firmware. Codec references are not install candidates.

[diagnostic-boot.lock.json](diagnostic-boot.lock.json) pins the exact stock boot/recovery digests, measured v1/2048-byte header format, observed size limits and a legacy-kexec source candidate. Prepare the component bundle and build the static ARM64 helper separately:

```sh
python3 ports/shield/prepare-diagnostic-boot.py \
  --kernel-dir "$build_root/integration-2026-10-14/kernel" \
  --stock-root "$build_root/harvest-2026-10-14/boot/current-build" \
  --output "$build_root/integration-2026-10-14/diagnostic-review"
bash ports/shield/tools/build-kexec.sh ../kexec-tools \
  "$build_root/integration-2026-10-14/kexec-tools"
```

The diagnostic tool checks kernel compression identity, stock input hashes/header format, the compiled fan/GPU specifiers, the USB ramdisk and aligned size budget. It creates raw components plus a review manifest, with unresolved native gates recorded. It creates no Android boot image or device command. The helper build executes no kexec operation; a static ELF or a passing `--help` invocation is not proof of stock-kernel entry or mainline handoff. A04 identity, unlocking, recovery entry and privileged collection are established in [validation-native-entry.json](validation-native-entry.json). Modern RAM/EMC reservations, CBoot address interpretation, CPU/device shutdown and native modern boot remain open.

## A04 inherited SMMU state

The A04 kernel includes a default-off experimental `tegra_smmu.reset_inherited=1` parameter. It is for a reviewed recovery-to-Linux handoff after old DMA masters have been quiesced. It clears and verifies only the enable bit of the 39 SWGROUP registers already described by the T210 SoC table, before the existing cache flush, global enable and IOMMU registration. The register set is documented by [upstream commit 4a91b11c](https://github.com/torvalds/linux/commit/4a91b11c0a100532c466e07a1372d134ab0e753d), citing the Tegra X1 TRM with NVIDIA maintainer acknowledgement. Client registers, PTB slots and the default identity policy stay unchanged.

A requested unsupported, repeated or rejected reset panics. A completion gate runs at subsystem phase 4, after the MC driver's architecture registration and OF platform population at phase 3s, and before the selected DMA drivers at phase 6; this also stops boot if MC probing never reaches the helper or fails before successful SMMU registration. The normal kernel behavior is unchanged while the parameter is off. This does not stop old DMA, establish RAM/EMC stability or qualify native userspace.

The additional default-off `tegra_smmu.preserve_disabled_gpu=1` option is confined to the stamped first RAM probe, with the exact A04/T210 identity and an explicitly disabled GM20B node. It requires the inherited-reset request, retains only GPUB at `0xaac`, and marks all 128 paging ASIDs unavailable before IOMMU registration. This prevents paging attachments from replacing PTB slots, including all four GPUB selectors, while preserving strict checks for the other 38 groups. It does not preserve old page-table RAM or support an enabled GPU. The old GPU must already be quiescent. No conclusion about register security or writability follows from the observed failed clear.

After the frozen source review and build, test the actual driver functions with fake MMIO and the missing-provider boot guard:

```sh
python3 ports/shield/tools/check-smmu-handoff.py --kernel-source "$kernel_source" --output "$build_root/smmu-regression.json"
SHIELD_DIST_DIR="$build_root/kernel" bash ports/shield/tools/smoke-smmu-gate.sh
```

The host harness checks all 39 registers and 128 ASID values, crossed-profile rejection, protected-write failure, an absent MC, the completion latch, invalid retention contracts, untouched GPUB state and refusal of all paging allocations in retention mode. The second command intentionally requests the reset on QEMU `virt`, where no Tegra MC can complete it, and requires a kernel panic before userspace. Neither is a physical SMMU or DMA qualification.

### Early persistent diagnostic console

The diagnostic configuration builds ramoops, its console and pmsg support into the kernel. For the attended RAM probe, a private command line supplies the measured reserved-memory address/size and the legacy record/console/pmsg split, with explicit zero ftrace and ECC. This creates one backend at postcore phase 2 and can capture failures before OF platform population. Retain the memory reservation without adding a second ramoops-compatible DT node. Do not substitute another board's layout or assume the modern ftrace default matches recovery.

The probe's one-way background logger mirrors bounded lines into kernel messages; the independent reset worker performs no console writes. A warm recovery boot is intended to expose the console through its existing pstore reader. USB capture and physical retrieval are separate measurements; the [handoff receipt](validation-ram-handoff.json) records their current result. These components are not an installer or a full hardware pass.

### Authenticated recovery and serial identity

The owner-specific recovery now returns authenticated root ADB without menu input. Its only ramdisk change is the workstation's public key at `/adb_keys`; its key-bearing image and raw backups are private. Preserve authentication and do not publish or reuse another workstation's recovery image. [The physical receipt](validation-headless-usb.json) records two reboot proofs, subsequent automated probe returns and the recovery-only readback scope.

The serial-only diagnostic and inventory sources use upstream `serial.c`'s donated CDC-ACM identity `0525:a4a7`. The Windows inventory consumer requires that pair and the exact `shield-stock-inventory` parent serial. The private RAM collector similarly requires `shield-diagnostic`. Keep producers and consumers paired. Reusing the old multifunction ID `1d6b:0104` caused Windows to bind an existing RNDIS driver on this workstation, despite successful SuperSpeed enumeration. The corrected physical diagnostic transferred 67,611 bytes; an inventory boot with the updated identity has not been retried.

The initial successful physical USB probe used temporary DT supply dependencies to avoid destructive padctl probe deferral. The maintained A04 driver now resolves child VBUS suppliers before entering the hardware probe and balances temporary handles while preserving the port devices' normal regulator ownership. It adds no voltage/enable calls or PHY settings. A fresh complete build, both QEMU checks and a physical RAM test with the original probe DT pass in [validation-xusb-supplies.json](validation-xusb-supplies.json); Windows received 71,639 bytes at SuperSpeed. The temporary supplier properties are no longer needed. The separate measured RAM layout and disabled-GPU handoff remain prerequisites; this is not independent installed boot or a desktop image.

The A04 build runs the actual-source provider/refcount harness before compilation. It checks ready, missing/disabled/optional nodes, first/later deferral, permanent supplier errors and the SoC port-count limit, with balanced OF and regulator references. It also checks that failures return before hardware probe, MMIO mapping or reset:

```sh
python3 ports/shield/tools/check-xusb-supplies.py --kernel-source "$kernel_source" --output "$build_root/xusb-supplies-regression.json"
```
