# Darcy integration build: October 14, 2026

Later read-only bootloader inspection selects A04 on the owner device. The A08 candidate documented here remains a historical evaluation build. The [stock-kernel inventory candidate](STOCK_BOOTSTRAP.md) preserves that actual board handoff for the proposed first hardware inventory; the modern kernel needs an A04 definition before native testing.

The first integration candidate has built and passed its offline checks. It adds the Shield controller driver, a source-tested fan/PWM correction, reproducible inactive firmware staging and diagnostic boot-component validation. [validation-darcy-integration.json](validation-darcy-integration.json) records exact hashes, source commit `fb3d99c4dd3476a4134327e506a04f58bf8ec436` and test scope. The earlier [Darcy receipt](validation-darcy.json) and [harvest](HARVEST.md) remain separate historical evidence.

| Package built and installed | Version |
| --- | --- |
| linux-shield | 7.1.0-4 |
| omarchy | 4.0.0.alpha-99.4 |
| omarchy-settings | 4.0.0.alpha-99.4 |
| omarchy-shield | 0.1.0-5 |

## Changes and checks

- The Thunderstrike controller module and force feedback are enabled. The actual packaged module has USB and Bluetooth match aliases and resolves its `ff-memless` dependency. Other remotes, microphone and IR still require separate native evidence.
- The Tegra PWM provider supports inverted power-only consumers; phase-sensitive inverted requests remain rejected. The selected A08 candidate explicitly inverts fan channel 3 while keeping GPU regulator channel 1 normal. Compiled-DTB checks verify both consumers and ascending cooling levels together.
- The fan holds a defined inactive output at logical zero and restores idle after resume. Eight actual driver functions, compiled with fake hardware callbacks, pass cold start, all 256 duties, cooling states, idle/resume/disable and power-error regressions. Electrical levels, actual RPM and thermal performance remain untested.
- The firmware stager verifies 41 selected payload/reference/notice inputs in a new inactive directory. The hardware audit independently confirms 32 upstream request-path payloads are already byte-identical in the development runtime. Exact Wi-Fi calibration and Bluetooth HCD remain staged; board/MAC/license review and physical testing are required before activation. Codec vendor-interface references remain inactive and are not replacements for a modern userspace implementation.
- Both saved exact-release stock images pass the pinned inspector. The diagnostic bundle verifies stock hashes/header format, raw/compressed kernel identity, the USB ramdisk and an aligned compressed budget of 17,983,488 bytes against the observed 26,738,688-byte limit. It creates raw components and a review manifest, not an Android boot image or boot command.
- A static 1,520,200-byte ARM64 kexec helper has built from its pinned source. ELF inspection and informational `--help`/`--version` calls under ARM emulation pass. No load or execute operation has been attempted.

The matching kernel and diagnostic ramdisk boot on QEMU `virt`. The complete 890-package filesystem also passes with the packaged kernel, four Cortex-A57 CPUs and 3 GB RAM: systemd, dependencies/modules, PSI/oomd/zram, user manager, desktop commands/session assets, Hyprland configuration, encrypted Btrfs/Snapper data and virtual USB CDC ACM transfers. This does not demonstrate a rendered native desktop. The ARM ELF audit finds 7,823 AArch64 payloads, 350 Guile containers and nine BPF objects, with no foreign executable/shared-library payloads or unreadable paths.

Twenty-three Python tests, eight focused Bash suites, ShellCheck, input/provenance checks and diagnostic ARM BusyBox module resolution pass. The 19-subsystem build audit reports no missing configured drivers, packaged modules or disabled reference-DT nodes. It still reports the uninstalled radio calibration/HCD and modern codec firmware requirements; these gaps remain visible.

The [source/interface review](INTEGRATION_REVIEW.md) explains the coupled changes and test boundaries. [BUILD.md](BUILD.md#integration-candidate-firmware-fan-and-diagnostic-handoff) documents the tools and new-cache build procedure. The local review bundle is `ports/shield/build/darcy-integration-2026-10-14/`; it excludes stock binaries, calibration data, the development filesystem and signing state.

## Next native milestone

Prepare and qualify controlled privileged stock-kernel entry, capture the actual loaded board DT/SKU and RAM/EMC reservations, then review explicit-DTB handoff into the diagnostic kernel. Stock enables legacy kexec and built-in USB gadget functions, but the saved recovery has production security properties and does not establish an available privileged shell. Temporary boot support, CBoot load-address interpretation, Tegra shutdown state, physical backups and restoration remain unresolved.

After a reviewed entry route and the owner's separate unlocking/data-wipe decision, establish a native USB console and verify fan supply, polarity, tach and conservative stop conditions before load. Native Nouveau/Wayland, Vulkan, codecs, suspend and all peripheral acceptance follow. NVK's Tegra gate and vendor/modern media interface work remain open.

No Shield access, reboot, unlock, flash or firmware activation occurred in this batch. Physical acceptance remains **0 of 19**. The development filesystem contains build accounts/signing state and is not an owner installation image.
