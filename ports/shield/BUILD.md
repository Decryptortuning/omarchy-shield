# Offline build workflow

These tools build Linux components and an ARM development filesystem on an x86-64 Linux/WSL host. They do not create a Shield installer, unlock a device, partition a disk or flash anything. Keep the native build directory on Linux storage rather than NTFS. The prepared filesystem contains development accounts and a build signing keyring; do not deploy or distribute it without owner/account, machine-key and boot finalization.

## Host and source inputs

On Ubuntu 24.04 the tools used here are `git make gcc gcc-aarch64-linux-gnu libc6-dev-arm64-cross clang lld llvm libelf-dev bison flex bc libssl-dev python3 curl gzip cpio zstd libarchive-tools gnupg qemu-user-static qemu-system-arm rsync util-linux e2fsprogs device-tree-compiler kmod`. Source staging needs Python 3.12 or later. Keep Linux repositories under `/home/jresp/Active_GH` and use WSL Git/native tools. No Docker daemon or host ARM package configuration is used.

Clone the `ack-tegra` repository beside this checkout using the URL/branch in [kernel.lock.json](kernel.lock.json), and `omacom/omarchy-pkgs` beside it using [userspace.lock.json](userspace.lock.json). The build verifies the exact commits. Kernel source archives are checked against the pinned SHA256 and the Git object identities before the recorded regulator patch is applied. A source cache can be reused only with the same base commit and ordered patch hashes, with a reverse-application check on every patch.

## Kernel and diagnostic boot

The next A04 candidate carries the tested display/MC-reset, inherited-watchdog and fixed 1.8V SDHCI code as 15 ordered patches. Its full-board DT remains distinct from the restricted native probe DT: it does not opt into fixed-rate display PTSA, and inherited fast eMMC, radios, cooling and DVFS still require qualification. The A04-only watchdog fragment enables early timer7/WDT0 adoption with a 600-second core open timeout; bounded native probes use a 240-second command-line override. This does not establish normal PID1 ownership or a guaranteed 240-second boot-to-reset interval. A08/B01 do not inherit that A04-specific fragment.

Use a fresh source/build cache when changing the ordered patch set. The builder records exact configuration-fragment hashes and the resolved kernel configuration in `config-fragments.json`, includes it in `SHA256SUMS`, and runs 19 actual-source SDHCI voltage/timing boundary cases alongside the USB regressions. These are candidate checks, not a claim that the new complete package or full-board DT has already passed.

Kernel admission now compares the compiled bundle against the exact source commit selected for package staging: complete lock, ordered applied patches, source input hashes, configuration-fragment provenance, actual config and overlay/result identity. The package recipe repeats this check with `OMARCHY_SRC` set to that source export. A checksum-consistent older bundle is refused before staging a build into the root filesystem or copying package inputs. Commit the reviewed candidate before using `stage-packages.py --commit`; uncommitted working-tree recipes are not the selected export.

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

The A04 build also runs actual-source USB supplier and OTG VBUS ownership regressions before compilation, and includes their reports in `SHA256SUMS`. The OTG change follows the [upstream Tegra210 regulator ownership finding](https://lists.infradead.org/pipermail/linux-phy/2026-January/028641.html), with successful-operation tracking to handle duplicate HOST requests and regulator failures. It leaves fixed-host init/exit unchanged. The fresh kernel, 1,561 matching ARM64 modules and QEMU boot passed; [validation-usb-vbus-ownership.json](validation-usb-vbus-ownership.json) pins the inputs and results. This candidate has not booted on the Shield. These offline checks do not qualify physical role switching. The later [USB-root follow-up](validation-usb-root-userspace.json) separately resolves enumeration in the bounded recovery-handoff test.

The A04 build also verifies the final compiled VBUS GPIO specifiers and the XUSBC reset array (`MC_XUSB_HOST` before `CAR_XUSB_HOST`), and hashes both contract reports in `SHA256SUMS`. These DT checks reject the prior definitions. The fresh full bundle passes checksum, source, configuration, module-vermagic and QEMU checks; [validation-usb-root-userspace.json](validation-usb-root-userspace.json) pins its artifacts separately from the physical five-patch diagnostic. Recovery must release the old host through its matched normal driver path before this measured handoff; the DT fix alone does not qualify arbitrary warm-state entry or independent boot.

## Signed ARM filesystem and packages

Before local package staging, build the complete patched Mesa output with `--with-x11 --with-va` into `"$build_root/mesa-desktop"` using the source/sysroot procedure below. A minimal Wayland-only probe bundle is not a desktop package input. This adds the matched Mesa payload to the kernel/runtime/settings/platform cutover; source staging still does not install or contact the Shield.

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
  --recipes ../omarchy-pkgs --kernel-dir "$build_root/kernel" \
  --mesa-dir "$build_root/mesa-desktop"
sudo bash ports/shield/chroot.sh "$build_root/rootfs" \
  /bin/bash /var/lib/shield-linux/build-target-packages.sh
```

The bootstrap installs the complete repository package set from pinned sync databases. The five local packages are `mesa`, `linux-shield`, `omarchy`, `omarchy-settings` and `omarchy-shield`; the installer submits them in one ALPM transaction. The ARM kernel recipe declares `python` and `dtc` (which provides `fdtget`) as build dependencies. The pinned package audit includes `dtc` as a build input so bootstrap supplies it before the `--nodeps` package build; host intent tests also require the documented device-tree-compiler tools.

Staging records `package-artifacts-intent.json` from the five exact recipes. Before invoking ALPM, the installer requires one archive per component and matches its `.PKGINFO` name, full version and AArch64 architecture, plus `.BUILDINFO` recipe hash. Same-name older packages and archives built from another recipe are refused before the transaction. This coordinated dependency transaction is not a power-loss rollback guarantee.

The candidate staging recipes use paired runtime/settings release `99.7`; the installed USB root remains on `99.6`, and the earlier integration build used `99.4`. Local installation validates dependencies together and replaces the generic ALARM kernel through its declared conflict. `linux-shield` owns modules and selected kernel/DTB/matrix inputs under `/usr/lib/omarchy/shield/kernel`; it has no boot-partition install hook. The platform package includes all three acceptance matrices and the guarded collector.

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

The A04 kernel includes a default-off experimental `tegra_smmu.reset_inherited=1` parameter. It is for a reviewed recovery-to-Linux handoff after old DMA masters have been quiesced. It clears and verifies only the enable bit of the 39 SWGROUP registers already described by the T210 SoC table, before the existing cache flush, global enable and IOMMU registration. The register set is documented by [upstream commit 4a91b11c](https://github.com/torvalds/linux/commit/4a91b11c0a100532c466e07a1372d134ab0e753d), citing the Tegra X1 TRM with NVIDIA maintainer acknowledgement. With this reset mode alone, client registers, PTB slots and the default identity policy stay unchanged; the separately gated GPU quarantine below additionally denies PTB zero.

A requested unsupported, repeated or rejected reset panics. A completion gate runs at subsystem phase 4, after the MC driver's architecture registration and OF platform population at phase 3s, and before the selected DMA drivers at phase 6; this also stops boot if MC probing never reaches the helper or fails before successful SMMU registration. The normal kernel behavior is unchanged while the parameter is off. This does not stop old DMA, establish RAM/EMC stability or qualify native userspace.

The additional default-off `tegra_smmu.preserve_disabled_gpu=1` option is confined to the stamped first RAM probe, with the exact A04/T210 identity and an explicitly disabled GM20B node. It requires the inherited-reset request, retains only GPUB at `0xaac`, and marks all 128 paging ASIDs unavailable before IOMMU registration. This prevents paging attachments from replacing PTB slots, including all four GPUB selectors, while preserving strict checks for the other 38 groups. It does not preserve old page-table RAM or support an enabled GPU. The old GPU must already be quiescent. No conclusion about register security or writability follows from the observed failed clear.

After the frozen source review and build, test the actual driver functions with fake MMIO and the missing-provider boot guard:

```sh
python3 ports/shield/tools/check-smmu-handoff.py --kernel-source "$kernel_source" --output "$build_root/smmu-regression.json"
SHIELD_DIST_DIR="$build_root/kernel" bash ports/shield/tools/smoke-smmu-gate.sh
```

The host harness checks all 39 registers and 128 ASID values, crossed-profile rejection, protected-write failure, an absent MC, the completion latch, invalid retention contracts, untouched GPUB state and refusal of all paging allocations in retention mode. The second command intentionally requests the reset on QEMU `virt`, where no Tegra MC can complete it, and requires a kernel panic before userspace. Neither is a physical SMMU or DMA qualification.

### GPU quarantine and offscreen rendering

The maintained A04 lock now contains nine applied patches, including [the GPUB/Nouveau handoff correction](kernel-patches/0010-a04-gpub-quarantine.patch). The separately gated `tegra_smmu.quarantine_gpub_inherited=1` mode requires the inherited reset, the exact A04 first-probe stamp and no retention request. It reserves ASID zero, verifies denied PTB data and clears all four GPU selectors to zero. The enable bit may remain set, as measured on this board. Normal paging can then use ASIDs 1–127; GPU attach/detach enforce selector readbacks. Nouveau clamps instance allocations to the forced domain aperture and propagates IOMMU setup errors before power-up.

`check-smmu-handoff.py` now compiles the actual reset, allocator/free, GPU attach/detach, Nouveau aperture and IOMMU setup functions against explicit MMIO/API models. It retains the old disabled-GPU retention cases and covers banked PTB state, reserved ASID zero, all available paging IDs, rejected writes, cleanup and returned failures. These source tests complement the measured hardware result in [validation-gpu-rendering.json](validation-gpu-rendering.json).

The guarded rendering helpers can be built independently:

```sh
bash ports/shield/tools/build-gpu-render-helpers.sh "$rootfs" "$build_root/new-gpu-helpers"
```

This creates two ARM ELF payloads and checksums; it executes or deploys neither. The static launcher only admits the exact reviewed diagnostic environment, an already verified read-only owner root and the fixed Nouveau render device. It mounts isolated RAM device/runtime directories, reopens the namespace root FD, verifies mount types, drops privileges and bounds the child to nine seconds. The dynamic helper uses the ARM root's GBM/EGL/GLES libraries, requires the hardware renderer and checks a GPU clear and shader triangle through an offscreen FBO. The caller's independent thermal/fan/reset supervision remains necessary; these helpers are not an installer or general desktop launcher.

The namespace regression needs root on a Linux build host and uses a new output directory:

```sh
python3 ports/shield/tools/check-gpu-render-namespace.py --output "$build_root/new-namespace-test"
```

It creates only private RAM/sysfs/proc mounts, reproduces the stale-FD failure and checks the corrected UID-65534 view. It creates a character-node entry for metadata checks but never opens a physical device or accesses an owner filesystem. The namespace disappears when the test exits. The physical GPU result remains distinct from this host regression.

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

The next seven physical diagnostics reused that exact kernel and matching modules, enabled USB host firmware and retained automatic authenticated recovery. [The storage investigation receipt](validation-usb-storage-probes.json) records the power-management, startup-order, register, firmware and canonical-PHY comparisons. None reached external-drive enumeration or a filesystem mount, so these results do not qualify USB-root boot. The [attended reconnect follow-up](validation-usb-hotplug-probe.json) retained the 30-second kernel-uptime budget and strict owner-identity/read-only checks, with the same unresolved drive detection and an inconclusive reconnect-timing control. The owner cannot determine the reconnect time; timed manual reconnects are retired and no timing answer is pending. The [automatic observation tests](validation-usb-vbus-gpio.json) kept the drive connected and verified drive-port tuning plus raw VBUS GPIO mode/level. Explicit active-high open-drain GPIO flags correct the board definition; patch 7 carries that intent into the maintained A04 source. The builder checks the compiled, overlaid A04 DT and hashes its VBUS contract report. All four tests returned automatically within the reset budget, but none enumerated the drive. The tests retained the earlier five-patch Image/modules; the updated maintained DT was compiled separately, and no complete seven-patch bundle is claimed. Do not rewrite the prepared drive merely to update a RAM-loaded diagnostic.


## Paired Mesa desktop libraries

The native compositor receipt uses Mesa 26.2.4 at the commit in [mesa.lock.json](mesa.lock.json), with [the combined Tegra API patch](mesa-patches/0001-tegra-current-gallium-api.patch). Apply that patch once to a checkout of the locked commit. `tools/build-mesa.py` rejects other tracked changes and writes only to a new output directory. It reads the prepared ARM root as its sysroot; it does not install libraries, enter that root, contact the Shield or change boot partitions.

The host needs AArch64 GCC/G++, pkg-config, Ninja, Bison, Flex, QEMU user emulation and Meson 1.4 or newer with Mako, PyYAML and packaging. The tested build uses GCC 13.3 and Meson 1.12.1. The builder runs the ARM root's matching Wayland scanner through QEMU, avoiding a protocol-version mismatch with the host scanner.

```bash
python3 ports/shield/tools/build-mesa.py \
  --source "$source_root/mesa" --rootfs "$build_root/rootfs" \
  --output "$build_root/mesa-desktop" --meson "$tools_venv/bin/meson" \
  --with-x11 --with-va
```

`--with-x11` adds the paired X11/GLX components needed for installed-desktop preparation. `--with-va` adds the Nouveau VA-API frontend and Mesa's codec parsers. Omitting both reproduces the smaller Wayland/EGL/GBM/Gallium diagnostic configuration. These configurations build only the Nouveau and Tegra Gallium drivers, without Vulkan or LLVM. Building the VA frontend does not establish Tegra video-engine support or hardware decoding. The output manifest records every installed file and explicitly leaves native qualification false; installation and hardware tests are separate steps. Keep EGL, GBM, its backend, Gallium and any GLX/DRI/VA components from the same build because Mesa checks their internal interface identity.

`mesa-shield/PKGBUILD` packages a build made with both switches as `mesa` 1:26.2.4-99.1. Set `SHIELD_MESA_DIR` to the completed builder output and `OMARCHY_SRC` to the exact source export, and use an AArch64 makepkg configuration. The package and staging tool use the same validator against that export’s Mesa lock; incomplete X11/VA outputs, stale source/patch/CPU identity, changed files or escaping symlinks are refused. `stage-packages.py --mesa-dir` stages only the checked manifest/install tree, and the five-package build/install includes Mesa atomically. The recipe verifies the source/patch identity, complete file manifest, required ARM libraries and symlink boundaries before packaging. It replaces the distribution Mesa package as one unit and retains the VA/OpenGL package provides; it is specific to this board and does not include other GPUs' drivers. It does not install anything or update the owner's USB drive. The separate `vulkan-nouveau` package remains outside this build and outside native qualification.

The [software package receipt](validation-desktop-package.json) records the completed build, ARM loader checks and isolated installation with kernel release 7. The 26-file/link Mesa payload, embedded build manifest and all 1,561 modules were verified after installation; ALPM reported no database errors or missing files. This is a disposable-filesystem installation test, not a native full-desktop or video-decoding pass. The Shield pacman template includes `mesa` in its local-package hold so a later distribution upgrade cannot silently discard the required Tegra fixes.

The actual-source checks run on Linux without opening a GPU:

```bash
python3 ports/shield/tools/check-mesa-reset.py \
  --source "$source_root/mesa" --output "$build_root/mesa-reset-check"
python3 ports/shield/tools/check-mesa-surfaces.py \
  --source "$source_root/mesa" --build "$build_root/mesa-desktop/build" \
  --output "$build_root/mesa-surface-check"
```

The first check reproduces the baseline null-callback crash in a child and verifies optional callback forwarding. The second compiles the real current Mesa API headers and Tegra callback bodies to check framebuffer textures, clear surfaces, scissor rectangles, null attachments and preservation of caller data. These checks supplement the physical compositor result; they do not qualify every hardware clear path, application or sustained session.

## Host preparation of the matched USB maintenance payload

`tools/prepare-usb-payload.py` creates an offline maintenance input from the verified ARM build root and the pinned original USB-root reference. Pass `--rootfs`, `--base-rootfs`, `--audit`, `--filesystem-uuid` and a new `--output` directory. Use WSL root when the installed package files include protected directories. The tool never mounts storage, installs packages or contacts the Shield.

It admits the exact five locally built archives and the audited `dtc` archive with its detached signature, then copies and rechecks them before publishing the output. `tools/usb_root_profile.py` provides the paired archive admission and installed-root verifier: complete installed package versions and ALPM semantics (installation timestamps deliberately excluded), selected payload metadata/hashes/xattrs, matching module and dynamic-loader state, and explicit obsolete paths derived from the original/new package lists. Shared paths owned by another package are retained. Signature integrity here is a pinned-byte check; upstream PGP authentication belongs to the later package transaction.

This is input preparation only. The physical USB remains unchanged, and no updater or hardware boot is released by creating a payload. The next maintenance candidate needs a separately reviewed device-identity check, exclusive mount ownership, new root/home/log subvolumes, interrupted-update interlock, verified clean relinquishment and recovery route. The existing root/default subvolume must remain available. The systemd desktop candidate also needs its actual initramfs handoff, finite watchdog/fan guard, user/session configuration and phased hardware/performance acceptance runner.

`tools/prepare-maintenance-plan.py` additionally pins the original root's ALPM semantics and bootstrap hashes to the exact payload manifest. It creates only a host JSON plan. `tools/usb_candidate_transaction.py` is the paired transaction core, without a device or mount entrypoint: its caller must already own an admitted Btrfs top-level mount, RAM payload, finite independent guard and attempt journal. It creates fresh root/home/log snapshots, installs the six archives in one offline ALPM transaction, checks the reference profile and original/default state, and unwinds its nested mounts. Existing candidates are refused. Its `VERIFIED` result deliberately leaves boot readiness false; a separate clean-unmount/host receipt is mandatory. A phase budget callback cannot by itself bound blocked commands or kernel I/O.

`tools/prepare-maintenance-toolroot.py --inventory PATH --inventory-sha256 SHA256 --output NEW_DIRECTORY` archives an independently reviewed ARM runtime inventory plus those Python runtime modules. It admits selected bytes, ownership, modes, symlink targets and ancestors before writing a deterministic archive. It neither extracts nor executes the archive. The [maintenance preparation receipt](validation-maintenance-preparation.json) records the actual compressed size and separate ARM chroot smoke result. This proves neither complete initramfs placement nor a real Btrfs/package transaction. The root-only transaction fixtures fence every mount, package and Btrfs command; run them separately as Linux root to exercise journal fsync and failure cleanup without touching block devices.

## Actual Btrfs maintenance integration on QEMU

`tools/prepare-maintenance-vm.py` builds a separate VM-only CPIO and a new qcow2 overlay over the hash-pinned original Btrfs image. Pass `--toolroot`, `--payload`, `--plan`, `--base-image`, `--base-image-sha256`, `--kernel`, `--base-components` and a new `--output` directory. The runtime inventory must include the matching ARM `chroot`, `mount` and `umount` executable closures. Source ownership/modes are admitted before the toolroot producer explicitly strips set-ID bits from regular files in this root-only RAM environment; the source filesystem is unchanged. The assembler rejects collisions, uses one canonical `/lib` → `/usr/lib` layout, and retains only the pinned static BusyBox/applets from the earlier diagnostic CPIO. It does not inherit that diagnostic's init, board DT, drivers, graphics or guard programs.

`tools/run-maintenance-vm.py --candidate DIRECTORY --output NEW_DIRECTORY` admits the prepared artifacts and exact two-file qcow2/raw backing chain, exclusively latches one attempt, and starts QEMU virt with no network or physical-device passthrough. Its guest rejects Shield hardware and requires its own VM command-line marker. Do not use these tools as the physical installer. A timeout or failure retains its overlay and attempt; prepare a new derivative after resolving the cause rather than rerunning that filesystem. The original image is hashed before and after execution.

The actual [integration receipt](validation-maintenance-integration.json) records successful snapshots, signed-dependency authentication, one six-package transaction with normal disk-space checks, exact installed-profile verification, clean unmount, read-only remount/readback and final unmount. The original root's pinned metadata/bootstrap state and default selection are checked separately. Btrfs generation changes are transaction bookkeeping; selection checks preserve object ID, parent and path. The candidate root is self-bound before its child mounts so ALPM can enumerate `/` inside the chroot, and that binding is removed last. Candidate-only keyring initialization uses the pinned distribution trust files; its GPG agents are stopped before mount cleanup. Canonical `/dev/fd` aliases and an actual Bash process-substitution roundtrip are required before that bootstrap.

This is software integration on an owned virtual disk. Physical USB identity, internal-storage protection, finite independent watchdog/cooling control, the recovery controller and complete native memory placement still need their combined implementation and qualification. The full systemd desktop also needs its actual root handoff, user/session configuration and hardware/performance acceptance; this result does not select a boot root or change the Shield.

## Finite guardian source and qualification configuration

`guardian/` contains the finite watchdog owner, prelaunched sensor worker and pure lifecycle state. Its checked-in profile deliberately disables device access. The [host receipt](validation-guardian-host.json) records actual-source assertions, C/Python wire parity and an ARM-emulated disabled-profile refusal; an enabled native guardian is not qualified by those checks. `tools/guardian_client.py` consumes the root-only, candidate/boot-bound status protocol, pins peer process identity and compares requested work reserve against existing absolute cutoffs. It cannot extend a deadline or control watchdog registers.

Run the source checks in a new directory with `python3 ports/shield/tools/check-guardian.py --output NEW_DIRECTORY`. The enabled host harness renames and never calls the hardware entrypoint. The separately cross-compiled ARM binary keeps the disabled public profile and must return64 without watchdog/MMIO/sysfs access. Compilers, ARM user emulation and the matched source cohort are prerequisites; this command neither contacts the Shield nor approves physical use.

`tools/prepare-qualification-overlay.py --rootfs MATCHED_REFERENCE --payload-manifest PRIVATE_MANIFEST --output NEW_DIRECTORY` verifies the matched reference and renders candidate-specific Btrfs mounts, systemd settings and temporary nonadministrative user configuration. It preserves normal Omarchy/UWSM config and bindings while replacing startup orchestration for a bounded run; online enrollment, power initialization, automounting and owner hooks remain visibly deferred, without writing a first-run completion marker. The overlay also carries the normal source-provided session desktop entry. Keep its filesystem UUID, candidate identifiers and full manifest private. It does not create the account, seed a theme, install the guardian, apply files or select a boot root. Account/home preparation and the actual guardian/recovery service graph remain separate required work before native execution.

## Clean qualification root and bound guardian artifacts

`tools/prepare-qualification-root.py` takes the matched reference, pinned payload manifest, current rendered overlay and its pinned manifest, plus a new output directory. It runs only as Ubuntu24.04 WSL root on the native host filesystem. It verifies the source, copies it without build/private state, creates the locked nonadministrative qualification account, seeds the installed headless Tokyo Night theme inside a network-isolated ARM chroot, applies the admitted service masks and verifies the complete matched payload again. It preserves both the reference and any failed derivative. No root is selected or booted.

Sudo policy admission checks the actual root query for the exact negative-only Omarchy rule, then requires a command-specific authorization denial. A successful `sudo -l` can describe a negative-only rule; it is not itself an allowed command. QEMU-user's setuid failure is not accepted as native authorization evidence. Native setuid behavior stays unverified until a full-system test.

`tools/prepare-guardian.py` additionally takes the selected kernel directory, restricted DTB, role and a new artifact output. It re-admits the reference and overlay, checks the exact kernel/config/DT pins, seals the shared14-source closure and builds static ARM guardian/recovery artifacts. It neither installs nor executes those enabled artifacts. Generated profiles, overlays and full receipts contain private filesystem/candidate identities and stay local.

The [qualification contract and next-run order](qualification/README.md) describe readiness, the finite cleanup window and the remaining native release gates. Host account/theme preparation and compiled artifacts are prerequisites; installation on physical USB, the complete memory/root handoff, authenticated control and full systemd/hardware acceptance still need their combined implementation and qualification.

`tools/install-qualification-artifacts.py` now performs host installation into a further new derivative. Supply `--prepared`, `--prepared-receipt-sha256`, `--payload-manifest`, `--payload-manifest-sha256`, `--artifacts`, `--artifact-manifest-sha256`, `--profile-sha256` and an unused `--output`. The current renderer, root preparation receipt and all fourteen bound artifact sources must agree. It verifies the copied root, nine installed files, unchanged account databases and default selection, then writes a private receipt. It never runs the enabled binaries, activates the qualification target or accepts a physical output device. The [installation receipt](validation-systemd-installation.json) does not release a native boot.

The current overlay also binds the installed power-action catalogs/manuals and emits qualification-user power denials, logind ignore settings and Ctrl-Alt-Delete controls. Recovery verifies these files and the effective manager settings before readiness. A later full-system test must observe actual polkit/logind decisions and native setuid behavior; neither emitted rules nor QEMU-user policy queries prove those runtime results.
