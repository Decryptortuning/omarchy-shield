# Omarchy on the NVIDIA Shield TV (2017)

This port runs [Omarchy](https://omarchy.org) — Arch Linux ARM with Hyprland — on the 2017 NVIDIA Shield TV, booted from the internal eMMC by the stock NVIDIA bootloader. Android is replaced; there is no dual boot.

It is experimental. It has run on exactly one device, the author's, and **there is no ready-made installer yet**. Read [Status](#status) before you plan anything around it.

## Supported hardware

| Model | Board | SoC | State |
| --- | --- | --- | --- |
| Shield TV 2017, 16 GB | Darcy, P2894 revision A04 | Tegra X1 (T210) | Runs. Everything below was measured on this board. |
| Shield TV 2017, other board revisions | Darcy, P2894 A08 | Tegra X1 (T210) | A kernel profile exists. It has never been booted. |
| Shield TV Pro 2019 | mdarcy, P2894 B00 | Tegra X1+ (T210B01) | A kernel profile exists. It has never been booted, and the boot method here does not apply as written. |
| Shield TV 2015, Shield TV 2019 "tube", Jetson, Switch | — | — | Not supported. |

The bootloader must be unlocked (`fastboot oem unlock`), which erases Android's data.

## Status

Measured on the Darcy A04 on 2026-11-09, after five days of continuous uptime.

| Area | State | Notes |
| --- | --- | --- |
| Boot from eMMC | Working | The stock bootloader starts a mainline kernel directly. No Android, no LineageOS, no kexec. |
| Boot safety | Working | Hardware watchdog, a boot counter, automatic rollback to the last good root, and a network rescue mode. |
| CPU | Working | Four Cortex-A57 cores, frequency scaling from 204 MHz to 2.2 GHz, and the power-down idle state. |
| Memory | Working | 3 GB fitted, about 2.4 GB usable by Linux. This is tight for a desktop with a browser. |
| Storage | Working | Root is Btrfs on the internal eMMC, with snapshots. |
| HDMI video | Working | The desktop runs at 1280×720 by default. 1080p has been driven; 4K modes are offered but not qualified. |
| GPU | Working | Hardware-rendered Hyprland through Mesa's nouveau driver (GM20B). Vulkan (NVK) is installed but not qualified. |
| HDMI audio | Working | PipeWire's default sink. |
| Wi-Fi | Working | BCM4354, 5 GHz, 866 Mbit/s link rate. |
| Ethernet | Working | 1 Gbit/s. |
| Bluetooth | Partly verified | The controller starts with its factory address. Pairing a device has not been tested. |
| USB host port | Partly verified | Keyboards and receivers work. USB storage has not been retested on the current boot path. |
| USB OTG port | Bootloader only | Used for fastboot. Not qualified from Linux. |
| Fan and thermals | Working | The kernel sets the fan from CPU and GPU temperature. Idle is about 47 °C; four cores at full load peak at 61 °C. |
| HDMI CEC | Untested end to end | The adapter registers and reads its address from the TV. The test TV has no CEC. |
| Shield controller and remote | Untested | |
| Hardware video decode and encode | Not available | Video plays through software decoding only. |
| Suspend and resume | Untested | |
| Installer for other owners | Not available yet | See [Roadmap](#roadmap). |

## How it boots

```
stock NVIDIA bootloader (cboot)
        │  loads the "boot" or "recovery" partition as if it were an Android kernel
        ▼
shim  (30 KB, this repo)
        │  swaps in the mainline device tree, arms the watchdog, hands over memory and command line
        ▼
mainline Linux 7.1 kernel
        ▼
loader initramfs (busybox, this repo)
        │  counts boots, rolls back or enters rescue after repeated failures
        ▼
Omarchy root filesystem (Btrfs on eMMC)
```

The shim exists because this bootloader always passes Android's own device tree to whatever it boots. The mainline kernel needs a different one, so the bootloader starts the shim instead, and the shim starts Linux. Both the `boot` and `recovery` partitions hold a complete copy, which gives two independent boot slots: a test image goes into `recovery`, and if it hangs the watchdog returns the board to `boot`.

The design, the reasons behind it and the build steps are in [owner-bringup/direct-boot/README.md](owner-bringup/direct-boot/README.md).

## Where things are

| Path | Contents |
| --- | --- |
| [owner-bringup/direct-boot/](owner-bringup/direct-boot/README.md) | The current boot chain: shim, loader, system units, device-tree changes and the tools that write the boot partitions. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | What to do when the Shield does not come up, and the rules that keep it bootable. |
| [kernel-patches/](kernel-patches) | Patches on top of the pinned Tegra kernel tree. |
| [kernel.lock.json](kernel.lock.json), [kernel.fragment](kernel.fragment) | The pinned kernel source and the Shield configuration. |
| [linux-shield/](linux-shield), [mesa-shield/](mesa-shield), [omarchy-shield/](omarchy-shield) | Package recipes for the kernel modules, the patched Mesa and the platform package. |
| [owner-bringup/AAR-2026-11-03.md](owner-bringup/AAR-2026-11-03.md) | After-action report for the outage that led to the current boot design. |
| [owner-bringup/team-2026-11-03/](owner-bringup/team-2026-11-03) | Investigation reports: the bootloader's fastboot behaviour, the GPU fault, and the boot redesign. |
| [DARCY.md](DARCY.md), [BUILD.md](BUILD.md), `INTEGRATION*.md`, `validation*.json`, [qualification/](qualification) | Records from the earlier bring-up, which booted through LineageOS recovery and kexec. That path is retired. These files are history, not instructions. |

## Roadmap

1. A kernel, device tree and boot image that anyone can rebuild from public sources with one script.
2. An install guide and a first-install procedure for another Darcy owner, tested by wiping and reinstalling the reference device.
3. Hardware still to qualify: Bluetooth pairing, USB storage, the Shield controller, suspend, 4K output.
4. Hardware video decode.

## Risks

Flashing replaces Android. The stock bootloader stays in place and fastboot remains reachable (hold A and B on the controller at power-on, with a PC attached to the USB port farther from HDMI), so a bad flash is recoverable, but returning to stock Android needs NVIDIA's recovery image for your exact model. Nothing here touches the bootloader itself.

## Licence

The Omarchy parts are MIT, as upstream. The shim and the device-tree sources derive from the Linux kernel and libfdt and carry their licences in the file headers.
