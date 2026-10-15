# Connected Darcy target

The owner confirmed that the connected Shield is the device to convert. Read-only USB ADB inspection reports `darcy`, NVIDIA Shield Android TV, original Tegra210 A02, chip ID `0x21`, silicon major revision `1`, and revision enum `3`. Android is version 11, build `13961458_4387.0822`, on kernel `4.9.141-tegra`. This supersedes the initial assumption that the owner's box was a 2019 Pro. NVIDIA's [revision table](https://github.com/LineageOS/android_kernel_nvidia_linux-4.9_kernel_kernel-4.9/blob/929f123da07cc9f73af2861eccf5a01591794e52/drivers/soc/tegra/fuse/tegra-apbmisc.c#L170) distinguishes original Tegra210 from B01 using the hardware major revision.

The owner tentatively reads `P2897` on the enclosure. NVIDIA documents that model code in both its [2017 Shield declaration](https://images.nvidia.com/shieldwebsite/visuals/public/DoC/EN/SHIELD_TV_P2897_DoC_EN.pdf) and its [later Shield Pro declaration](https://www.nvidia.com/content/dam/en-zz/Solutions/SHIELD/support/shield-tv/shield-tv-pro-p2897-ce-doc.pdf). The enclosure model alone therefore does not establish the generation, internal board SKU or A08 PCB revision. This label is consistent with the connected device; the measured Darcy/original-Tegra210 identity remains the basis for the current kernel profile and 2017 recovery-family investigation. A part number has not been supplied.

The official NVIDIA Windows USB driver was downloaded from NVIDIA, its WHQL catalog signature verified, and installed with the owner's Windows administrator approval. Read-only fastboot inspection succeeded: `product=t210ref`, `secure=Yes`, `unlocked=No`, boot and recovery each `0x1980000` bytes (25.5 MiB), and a `0x02000000` maximum download size. `t210ref` does not identify a specific board SKU. Unknown SKU/revision variables were not treated as evidence. The Shield was returned to stock Android and ADB reconnected. No unlock, erase or partition flash occurred.

The stock partition links identify Android boot as `LNX`/`mmcblk0p18`, recovery as `SOS`/`mmcblk0p16` and the device-tree partition as `DTB`/`mmcblk0p17`. Fastboot uses the names `boot` and `recovery`; it rejects the raw NVIDIA partition names queried here. These are observations, not flashing instructions. Direct ADB reads of boot/recovery, device-tree values and vendor firmware are blocked. Only the stock kernel configuration and accessible metadata have been captured; there is no raw stock boot backup yet.

The default [kernel.lock.json](kernel.lock.json) selects the pinned ACK kernel and `tegra210-p2894-0050-a08.dtb`, with [hardware-darcy.json](hardware-darcy.json) as its 19-subsystem acceptance matrix. This is an evaluation DT for the correct SoC generation, not proof that A08 is the owner's exact SKU. Its SDIO radio and PCIe Ethernet topology need comparison with the stock board. The separate [kernel-mdarcy.lock.json](kernel-mdarcy.lock.json) retains the B01 B00 candidate. Platform detection, Linux evidence collection, USB diagnostics and package staging reject crossed board/SoC combinations.

The original Tegra210 XUSB firmware and generic BCM4354 SDIO firmware are present in the development filesystem. Board-specific radio calibration, matching Bluetooth firmware, NVDEC/NVENC firmware, native graphics, cooling and all physical acceptance remain open. A 2019-only AI upscaling feature is not an acceptance requirement for this original-X1 hardware; capabilities actually present on the owner’s Shield remain in scope.

## Verified build: 2026-10-14

The Darcy diagnostic kernel, modules and USB ramdisk have built successfully. Four AArch64 packages from fork commit `05dbb78eb68d63dc3c95969f5e0ff33a5411602b` have been built and installed together in the 890-package development filesystem. [validation-darcy.json](validation-darcy.json) records package hashes, built-recipe hashes, source pins, component checksums and test scope. [VALIDATION.md](VALIDATION.md) and [validation.json](validation.json) remain historical B01 results.

| Package | Version |
| --- | --- |
| linux-shield | 7.1.0-3 |
| omarchy | 4.0.0.alpha-99.3 |
| omarchy-settings | 4.0.0.alpha-99.3 |
| omarchy-shield | 0.1.0-4 |

The installed filesystem boots under the matching packaged kernel on QEMU `virt`, four Cortex-A57 CPUs and 3 GB RAM, without a network adapter and with a disposable disk snapshot. The test passes systemd PID 1, the requested package/dependency set, matching module metadata including `r8169`, pressure reporting, `systemd-oomd`, zstd compressed swap, virtual USB CDC ACM enumeration and bidirectional transfers, the user manager, desktop/peripheral version commands, session assets, LUKS2/Btrfs/Snapper snapshot data and actual ARM `Hyprland --verify-config`. This does not render or qualify the native desktop. The separate diagnostic ramdisk boots in QEMU, and ARM BusyBox resolves its included Tegra USB gadget module dependencies.

The ELF header audit finds 7,822 AArch64 payloads, 350 Guile bytecode containers and nine BPF objects, with no foreign CPU executables/shared libraries or unreadable paths under `usr` and `opt`. Instruction compatibility and application behavior remain outside this audit. The 19-subsystem build audit finds no missing requested configuration, packaged modules or disabled reference-DT nodes; firmware matching and all 19 physical acceptance entries remain unresolved. Eleven variant/profile Python tests and eight focused Bash suites pass in [CI for the built source](https://github.com/Decryptortuning/omarchy-shield/actions/runs/38674519735).

The local review bundle is `ports/shield/build/darcy-2026-10-14/` in the native Linux checkout. It contains the four packages, the coherent raw diagnostic component set, source/provenance and sanitized test receipts. It excludes the development filesystem, device identifiers, keys and stock firmware binaries. It is not an installable or flashable image.

## Native boot prerequisites

The raw `Image` is 45,746,688 bytes, exceeding both the observed 25.5 MiB boot partition and 32 MiB download limit. `Image.gz` is 17,246,875 bytes; together with the 732,023-byte diagnostic ramdisk and 72,330-byte evaluation DTB, its raw payload fits that partition before header/alignment overhead. This is a size check only: the stock bootloader's compressed-kernel support, load addresses, Android header and DT handoff still require compatible stock-image evidence.

NVIDIA's [recovery download catalog](https://developer.nvidia.com/tools-downloads.json) lists a 2017 recovery 9.2.1 image, but the official download redirects to developer login when checked. No recovery image has been obtained. Its compatibility with the installed newer stock build has not been established; an older catalog entry is not a verified downgrade or restoration route.

Before any device write, the remaining work is to confirm the actual board SKU, obtain compatible stock recovery/boot inputs, verify the Android boot header and device-tree handoff, and prepare a recoverable diagnostic boot. The locked bootloader prevents a native test at this stage; unlocking would erase Android user data and requires a separate owner decision after the boot/recovery preparation is reviewable. The ARM development filesystem still contains build accounts and signing state and is not an installable SSD image.
