# Shield TV Pro 2019 port

This is an experimental Omarchy platform port for `mdarcy` / Tegra210B01. Full hardware support is the acceptance goal, and outstanding capabilities stay visible in [hardware.json](hardware.json). No physical Shield boot or peripheral test has passed yet. There is no flashable installer.

## Current implementation

- The `aarch64-shield` detector recognizes the verified A08 and B00 mainline board compatibles together with Tegra210B01. Older Shields, Switches and Jetsons do not select this platform. The physical unit's board revision remains unconfirmed.
- Package composition retains Omarchy's base and ARM defaults and adds the Shield platform, firmware candidates, Nouveau/Mesa/NVK and hardware diagnostics. The existing ARM edge repository supplies the desktop packages.
- Image manifests and pacman templates understand the Shield platform. Boot, provisioning, reset and update operations dispatch to the local `omarchy-shield` package, whose unfinished boot-changing operations refuse to run rather than use a PC boot path.
- The pinned ACK Tegra 7.1 kernel and diagnostic initramfs have compiled and booted under QEMU `virt`. The hardware configuration enables PCIe Wi-Fi, USB host/device mode, UAS storage, Bluetooth HID, HDMI audio, CEC, Nouveau and the host1x userspace interface. The matching kernel modules have been built. QEMU's virtual board does not exercise the Shield DTB or physical peripherals.
- The B00 device-tree overlay enables the CEC controller on the inherited P2894 CEC pinmux. Firmware matching and all physical behavior remain untested.
- The kernel profile includes Omarchy's zstd compressed swap and encrypted-root driver requirements. `linux-shield` owns the custom kernel modules without installing a boot image. Btrfs and Snapper are included; native snapshot boot integration remains unfinished.

The current firmware audit finds GM20B ACR firmware and VIC firmware in the signed Linux firmware packages. The Tegra210B01 XUSB blob, Bluetooth HCD files, and NVDEC/NVENC blobs are absent. Generic Tegra210 firmware is not a replacement for the B01 XUSB blob. Board-specific Wi-Fi calibration also needs stock-device evidence. These are unresolved input/qualification gaps, not supported hardware claims.

## Boot design

NVIDIA early boot firmware → a matched custom Linux Android-format boot image → an ARM Linux filesystem on external USB storage → Omarchy/Hyprland. Boot-image headers, DT handoff, actual board revision, required firmware and a stock recovery route must be established before installation. A Switch Hekate payload, Jetson flash configuration or desktop NVIDIA DKMS package is not a Shield boot configuration.

The initial target keeps native kernel/boot-image installation outside desktop updates. Encrypted owner setup, factory reset and boot-update verification are unfinished: their lifecycle entrypoints currently report that requirement and fail. This is a visible capability gap, not a production update path.

## Inputs

- [kernel.lock.json](kernel.lock.json): pinned ACK kernel, regulator build fix and board overlay.
- [kernel.fragment](kernel.fragment): additional Shield hardware configuration, merged after a normal ARM64 diagnostic configuration.
- [tegra210b01-shield-cec.dtso](tegra210b01-shield-cec.dtso): B00 evaluation board overlay; it is not confirmation of the owner's actual board revision.
- [userspace.lock.json](userspace.lock.json): upstream source, packaging, ARM repository metadata and signed rootfs provenance. It records the upstream base rather than claiming that the public binary packages include this fork's changes.
- [omarchy-shield](omarchy-shield/PKGBUILD): local ARM platform package. Build on Arch Linux ARM with `makepkg` after building/installing this fork's paired `omarchy` and `omarchy-settings` packages from the same source checkout through `OMARCHY_SRC` in the pinned upstream packaging recipes.
- [BUILD.md](BUILD.md): checked build tools for the kernel/modules, signed ARM filesystem, four local packages, and isolated whole-filesystem QEMU tests.
- [collect-shield-linux.py](collect-shield-linux.py): bounded evidence collection on the actual Tegra210B01 system. Run `sudo python3 collect-shield-linux.py --output hardware-report.json` after a native boot and basic cooling verification. `--graphics` additionally initializes EGL/Vulkan. Generated device reports must be reviewed before publishing.

The source branch reports `4.0.0.alpha`. Local paired packages use that source version with release `99.1`; do not mix the fork's runtime with settings built from another source commit. The upstream MIT license applies to Omarchy; the copied kernel patch and device-tree inputs retain their stated GPL licenses.

## Qualification

The acceptance matrix covers CPU/RAM, eMMC, both USB ports and role switching, SSD, Ethernet, Wi-Fi, Bluetooth/remote/microphone, HDMI/audio/CEC, GPU rendering/Vulkan, video decode/encode/VIC, cooling, clocks/power, suspend/wake and independent boot/recovery. Hardware-rendered Hyprland is required; a software renderer is not a GPU pass. HDR, Dolby, protected playback and NVIDIA AI upscaling need separate vendor/userspace/licensing feasibility work.

The source currently has focused automated coverage for platform detection, package composition, manifests, repository templates and lifecycle boundaries. Desktop and hardware qualification requires the real Shield; the matrix stays untested until evidence is available.
