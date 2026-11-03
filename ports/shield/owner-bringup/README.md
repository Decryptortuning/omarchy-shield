# Owner bring-up, 2026-11-02

Work done on the connected Darcy A04 Shield in one session, reusing the kernel457 /
policy555 / carrier 619-622 artifacts already built. Nothing here is a new kernel.
Private inputs (board DTB lineage, stage profile descriptor, LNX images, keys, APP
images) stay under `$SHIELD_BUILD/bringup-2026-11-02/`; the
`$WORK` placeholder in the scripts refers to that folder.

## What changed on the device

| Item | Before | After |
| --- | --- | --- |
| Boot after power loss | Carrier refused `androidboot.bootreason=shutdown,battery_low` and sat in Lineage recovery | Stage profile accepts `cold`, `warm`, `watchdog`, `shutdown,battery_low` |
| Stale attempt record | Second failed sequence-7 `pending` blocked every boot | Archived as `pending.failed-632` with the wave 641 helper; healthy 6 → 7 → 8 → 9 |
| Board DTB | `pcie336.dtb` (b5a2bb41) | `board.v2.dtb` (c0fef725): see `dtb/board.v1-to-v2.diff` |
| HDMI audio | `hda@70030000` disabled | enabled; `tegra-hda` card, ELD valid, PipeWire default sink |
| Bluetooth | `serial@70006300` disabled | enabled with `max-speed 3000000`; BCM4354 over `hci_uart`, stock HCD staged as `brcm/BCM4354.nvidia,p2894-0050-a04.hcd` |
| Ethernet | PCIe config read SError on every attempt (Oct 18-21) | `pci@1,0` enabled with 4 lanes + `nvidia,disable-aspm-states = <0xf>` on both ports (stock parity); r8169 enumerates, 1 Gb/s, DHCP |
| LNX carrier | caa4c805 (wave 621/622) | 6a5c527c: same image with only `system/bin/shield-owner-internal-stage` replaced |

Root cause of the Ethernet SError: the mainline P2894 DT only enabled root port 1
(`pci@2,0`); stock enables both ports and the vendor driver programs root port 0 even
with no device. Every earlier config-window / aperture candidate (patch 0018, 616) was
targeting the wrong thing and should be dropped from the series.

## Layout

- `overlay-module/`: `shield_overlay.ko` source, a generic runtime DT overlay loader
  (list of `.dtbo` + guard node). Build with `build-module.sh` against the prepared
  kernel457 tree (identical `.config` and `Module.symvers` are checked).
- `overlays/`: HDMI audio and Bluetooth overlays used for the runtime test. The PCIe
  root-port-0 overlay could not be applied at runtime because the deployed DTB gives
  the lane nodes no phandles; it went into the DTB instead.
- `dtb/board.v1-to-v2.diff`: the complete DTB change (decompiled).
- `units/`: `shield-ethernet.service` (loads the in-tree `pci-tegra.ko` and `r8169`
  after `shield-owner-ready`) and the now-disabled `shield-overlays.service`.
- `carrier/`: `build-stage.sh` (reproduces the 620 stage byte-for-byte, then builds
  the new profile), `repack-stage.py` (swaps one ramdisk record in the LNX image),
  `write-lnx.sh` / `install-v2.sh` (device-side install with preimage/readback).
- `LEDGER-2026-11-02.txt`: timestamped record of every host and device step.

## Still open

- Cold-boot (power-cut) test of the new carrier: needs a physical power cycle.
- Bluetooth uses the firmware default BD address; read the real one from the stock
  NCT/nvram partition.
- The kernel cmdline still carries `modprobe.blacklist=r8169,pci_tegra`; the unit
  loads them explicitly. Drop the blacklist and ship `pci-tegra.ko` in `/lib/modules`
  on the next bootset/cmdline update, then retire `shield-ethernet.service`.
- Ethernet DHCP gave an address but no IPv4 default route on the first attempt; check
  the router option on the next boot.
- USB host port: the receiver only enumerates through an extension cable; the
  carrier's pre-kexec "root hubs only" guard still refuses to boot with a peripheral
  attached and needs an owner policy change.
- Fold `hda`/`bt`/`pcie-rp0` into the kernel-built DTB overlays (`*.dtso`) and
  `kernel.lock.json`, remove patch 0018 and the `darcy-pcie` overlay.
