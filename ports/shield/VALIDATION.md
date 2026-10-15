# Pre-USB validation: 2026-10-14

This historical report covers the original B01 candidate and paired package release `99.2`. USB inspection subsequently identified the owner's connected original-Tegra210 Darcy; [DARCY.md](DARCY.md) records the updated target. Current build defaults and package releases differ from the artifacts listed here.

The custom ARM kernel and installed Omarchy development filesystem pass the whole-filesystem QEMU test. Four ARM packages have been built and installed together. No physical Shield boot, GPU or peripheral has passed qualification, and these artifacts are not a flashable installer. Full hardware support remains the acceptance goal in [hardware.json](hardware.json).

## Built artifacts

| Package | Version | Architecture |
| --- | --- | --- |
| linux-shield | 7.1.0-2 | aarch64 |
| omarchy | 4.0.0.alpha-99.2 | aarch64 |
| omarchy-settings | 4.0.0.alpha-99.2 | aarch64 |
| omarchy-shield | 0.1.0-3 | aarch64 |

The runtime/settings pair uses fork source commit `5ece262609cd4eacdbc1c99f005a455986a6fc1e` and upstream packaging commit `c505828452be1e9d95c28183889ee4c922b4d7da`. The platform recipe's collector checksum was corrected before its successful build; [validation.json](validation.json) records each built recipe and package hash. The kernel is ACK Tegra commit `9336ceeebe1d75021d9fd98c94abaec522ba39b3` with the pinned regulator fix, B00 CEC overlay and Shield configuration. The signed Arch Linux ARM base and repository database hashes are recorded in [userspace.lock.json](userspace.lock.json).

The installed build filesystem contains 890 packages. Pacman validates its package dependency database, the requested platform package set is present, and the generic Arch kernel has been replaced by `linux-shield`. The custom kernel package owns its modules and raw kernel/DTB/configuration files without a boot-partition installation hook. The diagnostic ramdisk is a separate component build; its kernel and modules must stay with its own checksum set.

## Tests that passed

- The packaged kernel boots the installed filesystem as systemd PID 1 on QEMU `virt`, Cortex-A57, four CPUs and 3 GB RAM. The VM has no network adapter and uses a disposable disk snapshot.
- Pressure-stall information, `systemd-oomd`, zstd compressed swap, the systemd user manager, D-Bus and udev operate in the guest.
- Driver metadata matches the running kernel, and the required Shield module dependencies resolve. USB CDC ACM enumerates and transfers data in both directions through a virtual `dummy_hcd` controller.
- Hyprland, Quickshell, PipeWire, WirePlumber, NetworkManager, BlueZ and the CEC/video diagnostic tools start their version commands. The installed Omarchy session assets and user defaults exist. These checks do not exercise their physical devices or every application.
- A LUKS2 encrypted loop device supports Btrfs, a read-only subvolume snapshot and Snapper. Data in both snapshots remains unchanged after the active payload is modified. Physical encrypted boot and snapshot boot integration remain unfinished.
- The installed Omarchy configuration passes the actual ARM `Hyprland --verify-config` command. Testing exposed a startup-cursor timer crash in config-only execution; the fork now skips those timers without a compositor instance, and the focused Lua regression passes.
- The ELF header audit finds 7,822 native AArch64 payloads under `usr` and `opt`, 350 Guile bytecode containers and nine BPF objects, with no foreign CPU ELF payloads or unreadable paths. CPU instruction compatibility, .NET/PE payloads and application behavior require separate checks.
- The opt-in USB diagnostic initramfs boots in QEMU. Its ARM BusyBox module loader resolves the included Tegra UDC/CDC ACM dependencies with the correct `/lib/modules` path. The shared gadget implementation passes the virtual USB data test; Tegra UDC enumeration on Windows remains untested.
- ShellCheck, Python/JSON parsing, repository input checksums and eight focused platform/cursor suites pass. Pinned AOSP boot-image tools pass four upstream synthetic tests and the read-only wrapper's synthetic fixture.

## Remaining hardware work

An additional graphical VM attempt uses `virtio-gpu-pci` with software rendering requested. Hyprland starts and answers a monitor query at 1280×800, but Aquamarine cannot match an EGL rendering device and fails renderer-state updates. Two inspected screenshots remain black, with a cursor visible in the first. The complete Omarchy desktop has not rendered successfully in this VM; this is recorded as incomplete, independently of the passing configuration/userspace test above. The experiment and screenshots are retained locally.

All 19 physical acceptance entries remain untested. The configuration/module/device-tree audit finds the requested build inputs enabled or packaged, which does not establish driver compatibility or physical behavior. The DTB currently targets the evaluation B00 board; the owner's actual board revision is still unconfirmed.

The installed firmware tree lacks the Tegra210B01 XUSB blob, matching Bluetooth HCD files and NVDEC/NVENC firmware. Board-specific Wi-Fi calibration is also unmatched. Checksum-pinned XUSB, Bluetooth and video candidates from NVIDIA's original L4T 32.2.1 archive pass container checks and remain inactive outside the runtime firmware tree. They have not been qualified on this Shield.

Native Nouveau/GM20B rendering, Hyprland/Quickshell, Vulkan, accelerated video, HDMI/audio/CEC, both USB roles, Ethernet, Wi-Fi/Bluetooth, remote/microphone, cooling, clock scaling, suspend/wake and stock recovery all require the device. HDR, Dolby, protected playback and NVIDIA AI upscaling remain separate vendor/userspace/licensing feasibility gaps. Software rendering cannot satisfy the GPU acceptance entry.

USB inspection must first establish `mdarcy`, board revision, installed firmware, bootloader state and the matching recovery source. A saved stock boot/recovery image can then be examined with [inspect-boot-image.py](inspect-boot-image.py). No Android load addresses, DT handoff, temporary-boot support or stock restoration route have been proven. Provisioning, encrypted owner setup, reset, native boot updates and snapshot boot integration remain unfinished and fail explicitly.

The local review bundle contains only the four packages, raw diagnostic components, source/provenance and test receipts. The development filesystem is retained locally because it contains build accounts and signing state. No NVIDIA firmware binaries, device identifiers, keys or credentials are published in this repository.
