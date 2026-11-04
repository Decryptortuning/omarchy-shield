# Owner bring-up, 2026-11-02 and 2026-11-03

This folder records work on the connected Darcy A04 Shield. It reuses the kernel457, policy555 and carrier 619-622 artifacts that were already built; nothing here is a new kernel. Private inputs (board DTB lineage, stage profile descriptor, LNX images, keys, APP images) stay under `$SHIELD_BUILD/bringup-2026-11-02/`, and the `$WORK` placeholder in the scripts refers to that folder.

**Status 2026-11-04 18:18Z.** The Shield boots Omarchy directly from the NVIDIA bootloader through our shim and loader, with no Lineage, no 4.9 kernel and no kexec, from both the boot and recovery partitions. Wi-Fi, 1 Gb/s Ethernet, Bluetooth, HDMI, the GM20B GPU (nouveau), the fan, sshd and the boot counter, rollback and rescue all work. Details are in [direct-boot/README.md](direct-boot/README.md); the 11-03 outage is described in [AAR-2026-11-03.md](AAR-2026-11-03.md).

## Rules that keep the device bootable

1. **Never `fastboot flash system` a raw image.** The Shield bootloader corrupts the FILL chunks that host fastboot generates, and the kernel Image on APP then fails the carrier's hash check. Convert the image with `carrier/make-rawsparse.py` first, or write APP with `dd` from Linux. `fastboot flash boot` and `fastboot flash recovery` with padded raw images are fine.
2. **Keep the Shield's USB host port empty while it boots.** The carrier handoff refuses kexec when any USB device besides the root hubs is present.
3. **Check every systemd unit before enabling it.** Run `systemd-analyze verify <unit> default.target`, and never order an optional unit `Before=` anything in the acknowledgement chain (sshd, network.target, NetworkManager, `shield-owner-*`).
4. **Know the ports.** The port farther from HDMI is the OTG/device port (PC cable, fastboot). The port beside HDMI is host-only (controller, adapters). To reach the bootloader menu, hold A+B on the controller at power-on with the PC cable attached.
5. **If the Shield lands in recovery, read the beacon first.** About three minutes in, the carrier replaces the menu with `SHIELD CARRIER BEACON` and the exact refusal text, and blinks the light bar. Photograph the screen.

## What changed on the device

| Item | Before | After |
| --- | --- | --- |
| Boot after power loss | Carrier refused `androidboot.bootreason=shutdown,battery_low` and sat in Lineage recovery | Since 11-03 the stage accepts any well-formed boot reason except `watchdog`, which keeps its retry semantics (`carrier/stage-v11-bootreason.patch`) |
| Stale attempt record | Second failed sequence-7 `pending` blocked every boot | Archived as `pending.failed-632` with the wave 641 helper; healthy 6 → 7 → … → 11 |
| Board DTB | `pcie336.dtb` (b5a2bb41) | `board.v2.dtb` (c0fef725): see `dtb/board.v1-to-v2.diff` |
| HDMI audio | `hda@70030000` disabled | Enabled: `tegra-hda` card, ELD valid, PipeWire default sink |
| Bluetooth | `serial@70006300` disabled | Enabled with `max-speed 3000000`: BCM4354 over `hci_uart`, stock HCD staged as `brcm/BCM4354.nvidia,p2894-0050-a04.hcd` |
| Ethernet | PCIe config-read SError on every attempt (Oct 18-21) | `pci@1,0` enabled with 4 lanes and `nvidia,disable-aspm-states = <0xf>` on both ports (stock parity); r8169 enumerates at 1 Gb/s; `units/shield-ethernet.service` is ordered after NetworkManager |
| LNX carrier | caa4c805 (wave 621/622) | 2be92fdd (v12): the v2 stage with the boot-reason patch, plus the beacon service |
| SOS (recovery partition) | Original Lineage recovery | Unchanged; briefly overwritten on 11-03 and restored from the 2026-10-16 readback (d8f68c06) |

The Ethernet SError had one cause: the mainline P2894 DT enabled only root port 1 (`pci@2,0`). Stock enables both ports, and the vendor driver programs root port 0 even with no device attached. The earlier config-window and aperture candidates (patch 0018, 616) targeted the wrong thing and should be dropped from the series.

## Layout

- `AAR-2026-11-03.md`: after-action report for the 11-03 outage.
- `direct-boot/`: the carrier replacement: `shim/` (cboot → mainline), `loader/` (boot counter, rollback, rescue), `root/` (direct-path units) and `tools/` (unit guardrail, partition writers, fastboot recovery).
- `team-2026-11-03/`: the read-only investigation reports. They cover the boot refusal, USB/ADB in recovery, fastboot capabilities, a deep refusal analysis with the beacon design, and a proposed rescue architecture.
- `overlay-module/`: source for `shield_overlay.ko`, a generic runtime DT overlay loader (a list of `.dtbo` files plus a guard node). Build it with `build-module.sh` against the prepared kernel457 tree; the script checks for identical `.config` and `Module.symvers`.
- `overlays/`: the HDMI audio and Bluetooth overlays used for the runtime test. The PCIe root-port-0 overlay could not be applied at runtime because the deployed DTB gives the lane nodes no phandles, so that change went into the DTB instead.
- `dtb/board.v1-to-v2.diff`: the complete DTB change, decompiled.
- `units/`: `shield-ethernet.service` and the now-disabled `shield-overlays.service`. The Ethernet unit loads the in-tree `pci-tegra.ko` and `r8169` after `shield-owner-ready` and NetworkManager.
- `carrier/`:
  - `build-stage.sh` reproduces the 620 stage byte for byte, then builds a new profile.
  - `repack-stage.py` swaps the stage record in an LNX image.
  - `write-lnx.sh` and `install-v2.sh` install on the device with preimage and readback checks.
  - `stage-v11-bootreason.patch` is the boot-reason relaxation.
  - `repack-beacon.py`, `diag/shield-beacon.sh`, `diag/fbstatus.c` and `diag/make-font.py` build the refusal beacon.
  - `make-rawsparse.py` writes RAW-only sparse images for `fastboot flash system`.
  - `flash-lkg.sh` and `flash-app-raw.sh` are the PC-side fastboot flashers.
  - `repack-diag*.py`, `diag/*.rc`, `diag/shield-{diag,netadb,usbrole}.sh` and `switch_root_fix2.c.unused` are the 11-03 diagnostic experiments, kept for reference. Most never worked; the report explains why.
- `LEDGER-2026-11-02.txt` and `LEDGER-2026-11-03.txt`: timestamped records of every host and device step.

## Still open

- **Rescue path.** An unacknowledged boot should land in a networked rescue initramfs instead of the silent Lineage menu (`team-2026-11-03/rescue-architecture.md`, step 1). This needs an owner decision.
- **Unit guardrail.** Add a `shield-unit-apply` helper that verifies a unit and refuses ordering into the acknowledgement chain, plus a Btrfs snapshot before each change.
- **Recovery ADB.** Recovery ADB over the PC cable has not worked since 11-03 03:27Z, although fastboot on the same cable works. The leading theory is VBUS sensing in the recovery kernel.
- **Bluetooth address.** Bluetooth uses the firmware default BD address; read the real one from the stock NCT/nvram partition.
- **Module blacklist.** The kernel cmdline still carries `modprobe.blacklist=r8169,pci_tegra`, and the unit loads both modules explicitly. On the next boot-set update, drop the blacklist, ship `pci-tegra.ko` in `/lib/modules`, then retire `shield-ethernet.service`.
- **Ethernet default route.** Ethernet DHCP gave an address but no IPv4 default route on the first attempt; check the router option.
- **APP space.** About 18 MB of the APP partition is free. Move the unused `e8f146cd…` generation and the `*.bak` files off the device.
- **DTB overlays.** Fold `hda`, `bt` and `pcie-rp0` into the kernel-built DTB overlays (`*.dtso`) and `kernel.lock.json`, then remove patch 0018 and the `darcy-pcie` overlay.
