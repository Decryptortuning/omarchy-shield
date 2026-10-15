# NVIDIA Shield TV port

This experimental Omarchy port targets the owner's connected `darcy` / original Tegra210 A02 Shield. The earlier `mdarcy` / Tegra210B01 candidate is retained as a separate board profile. Full hardware support remains the acceptance goal in [hardware-darcy.json](hardware-darcy.json) and [hardware.json](hardware.json), respectively. No native Linux Shield boot or peripheral test has passed yet. There is no flashable installer.

The [latest integration build](INTEGRATION.md) adds the Shield controller driver, the reviewed fan/PWM candidate, verified inactive firmware staging and diagnostic component validation. Four matching ARM packages and the complete filesystem VM test pass; [validation-darcy-integration.json](validation-darcy-integration.json) records exact hashes and scope. The [earlier Darcy report](DARCY.md#verified-build-2026-10-14) and [pre-USB B01 report](VALIDATION.md) remain separate historical builds.

USB inspection identifies original Tegra210 silicon, Android 11 and the bootloader-selected **Darcy A04** DTB. On October 15, owner-approved unlocking completed and fastboot verified `unlocked: Yes`. Temporary boots of both the [stock-kernel inventory candidate](STOCK_BOOTSTRAP.md) and the untouched matching NVIDIA recovery returned to Android welcome/setup. Installed stock recovery worked through the fastboot menu. A subsequently approved recovery-only diagnostic flash completed, but its menu boot also returned to Android; no diagnostic USB session was obtained. [validation-native-entry.json](validation-native-entry.json) records the measured results and unresolved recovery contents. The current modern lock remains an A08 evaluation profile and needs an A04 definition before mainline testing. See [DARCY.md](DARCY.md) for the current scope.

The [reusable board-source map](BOARD_SOURCES.md) identifies the original Darcy definitions inside LineageOS's T210 Foster hardware project, its compressed-kernel boot recipe and specific Linux radio firmware mappings. [board-sources.lock.json](board-sources.lock.json) pins these research inputs independently of the built kernel/component lock.

The [integration plan](INTEGRATION_PLAN.md) orders the remaining board/firmware work, recovery and boot handoff, reproducible builds, native diagnostics, full hardware qualification and owner installation/update support. It includes the first implementation batch and acceptance checks for all 19 subsystems.

The [completed source and firmware harvest](HARVEST.md) records 728 verified local files, including exact installed-build boot/recovery inputs, four stock DT variants and specifically mapped radio firmware. It also identifies fan startup semantics, a disabled Shield controller driver, NVK's default Tegra rejection and the vendor/modern media interface gap. These are staged research inputs; the built runtime and physical acceptance remain unchanged.

## Current implementation

- The `aarch64-shield` detector recognizes A08 with original Tegra210, and B00 with Tegra210B01. Cross-generation pairs, conflicting proc/sysfs identities, 2015 Shields, Switches and Jetsons are rejected. Compatible strings identify supported evaluation DTs; they do not qualify the physical unit.
- Package composition retains Omarchy's base and ARM defaults and adds the Shield platform, firmware candidates, Nouveau/Mesa/NVK and hardware diagnostics. The existing ARM edge repository supplies the desktop packages.
- Image manifests and pacman templates understand the Shield platform. Boot, provisioning, reset and update operations dispatch to the local `omarchy-shield` package, whose unfinished boot-changing operations refuse to run rather than use a PC boot path.
- The pinned ACK Tegra 7.1 kernel and diagnostic initramfs have compiled and booted under QEMU `virt`. The hardware configuration enables PCIe Wi-Fi, USB host/device mode, UAS storage, Bluetooth HID, HDMI audio, CEC, Nouveau and the host1x userspace interface. The matching kernel modules have been built. QEMU's virtual board does not exercise the Shield DTB or physical peripherals.
- Each board profile selects its own DTB, acceptance matrix and CEC overlay. The original Darcy profile includes PCIe Ethernet and PWM regulator requirements; B01 retains its own USB firmware and radio requirements. Firmware matching and all physical behavior remain untested.
- The kernel profile includes Omarchy's zstd compressed swap and encrypted-root driver requirements. `linux-shield` owns the custom kernel modules without installing a boot image. Btrfs and Snapper are included; native snapshot boot integration remains unfinished.

The firmware audit finds GM20B ACR, VIC and original Tegra210 XUSB files in the signed Linux firmware packages. Tegra210B01 XUSB, matching Bluetooth HCD files, and NVDEC/NVENC blobs remain absent from the development runtime. Tegra210 XUSB is not a B01 replacement. Exact current-OTA Darcy calibration/HCD/media payloads and pinned upstream firmware are now staged locally with hashes and mappings; activation, license review and physical qualification remain open. Older L4T candidates stay separate and inactive. Stock Android denied direct firmware and raw boot-partition reads; no physical partition backup was obtained through ADB.

## Boot design

NVIDIA early boot firmware → a matched custom Linux Android-format boot image → an ARM Linux filesystem on external USB storage → Omarchy/Hyprland. Boot-image headers, DT handoff, actual board revision, required firmware and a stock recovery route must be established before installation. A Switch Hekate payload, Jetson flash configuration or desktop NVIDIA DKMS package is not a Shield boot configuration.

The initial target keeps native kernel/boot-image installation outside desktop updates. Encrypted owner setup, factory reset and boot-update verification are unfinished: their lifecycle entrypoints currently report that requirement and fail. This is a visible capability gap, not a production update path.

## Inputs

- [kernel.lock.json](kernel.lock.json): default original Tegra210 Darcy candidate, with pinned kernel, matrix and CEC overlay.
- [kernel-mdarcy.lock.json](kernel-mdarcy.lock.json): separate Tegra210B01 B00 candidate; never substitute it for the connected original-X1 device.
- [kernel.fragment](kernel.fragment): additional Shield hardware configuration, merged after a normal ARM64 diagnostic configuration.
- [tegra210b01-shield-cec.dtso](tegra210b01-shield-cec.dtso): B00 evaluation board overlay; it is not confirmation of the owner's actual board revision.
- [userspace.lock.json](userspace.lock.json): upstream source, packaging, ARM repository metadata and signed rootfs provenance. It records the upstream base rather than claiming that the public binary packages include this fork's changes.
- [omarchy-shield](omarchy-shield/PKGBUILD): local ARM platform package. Build on Arch Linux ARM with `makepkg` after building/installing this fork's paired `omarchy` and `omarchy-settings` packages from the same source checkout through `OMARCHY_SRC` in the pinned upstream packaging recipes.
- [BUILD.md](BUILD.md): checked build tools for the kernel/modules, signed ARM filesystem, four local packages, and isolated whole-filesystem QEMU tests.
- [collect-shield-linux.py](collect-shield-linux.py): bounded evidence collection on either supported Shield board/SoC pair. Run `sudo python3 collect-shield-linux.py --output hardware-report.json` after a native boot and basic cooling verification. `--graphics` additionally initializes EGL/Vulkan. Generated device reports must be reviewed before publishing.

The source branch reports `4.0.0.alpha`. Current paired-package recipes use release `99.4`; the earlier Darcy packages use `99.3` and pre-USB packages use `99.2`. Do not mix runtime/settings source commits or board kernel inputs. The upstream MIT license applies to Omarchy; copied kernel and device-tree inputs retain their stated GPL licenses.

## Qualification

The acceptance matrix covers CPU/RAM, eMMC, both USB ports and role switching, SSD, Ethernet, Wi-Fi, Bluetooth/remote/microphone, HDMI/audio/CEC, GPU rendering/Vulkan, video decode/encode/VIC, cooling, clocks/power, suspend/wake and independent boot/recovery. Hardware-rendered Hyprland is required; a software renderer is not a GPU pass. HDR, Dolby, protected playback and NVIDIA AI upscaling need separate vendor/userspace/licensing feasibility work.

The source currently has focused automated coverage for platform detection, package composition, manifests, repository templates and lifecycle boundaries. Desktop and hardware qualification requires the real Shield; the matrix stays untested until evidence is available.
