# Darcy cboot fastboot capabilities (2026-11-03)

Evidence base: the stock cboot (`EBT`, 551,840 B, sha256 a0b42f27...) carved from the locally harvested OTA blob
`$BUILD/harvest-2026-10-14/boot/current-build/ota-metadata/blob` (entry table in
`.../ota-blob-entries.json`; OTA `productionBL-droid-signed-darcy-full_ota-13961458_4387.0822`). It is plain AArch64 and loads at
0x92c00000 (file offset == VA - 0x92c00000). I disassembled it with `aarch64-linux-gnu-objdump` and resolved the adrp/add
string references. Version strings "1.0/2.0/0.4/t210ref" match the owner's `getvar all`
(`bringup-2026-11-02/fastboot-watch.log`), so this is very likely the same build that is on the device. No device commands were run.
Confidence: **H** = read in the code, **M** = strings or partial code plus sources, **L** = inference.

## 1. `fastboot boot <img>`: supported, unlocked only (H)

The fastboot init code at VA 0x92c4aa40 registers exactly these commands: `reboot`, `reboot-bootloader`, `oem `, `flashing `,
`getvar:`, `erase:`, `download:`, `flash:`, `boot`, `continue`. ("boot" and "continue" are tail-merged strings, which is why
`strings` misses them.)

- The `boot` handler (0x92c4c390) returns "Bootloader is locked." if the device is locked. When unlocked it stops the fastboot
  thread and calls the Android boot routine (0x92c039b8) with **mode 2 and the download buffer**. Mode 0 is LNX and mode 1 is SOS.
- Mode 2 checks the `ANDROID!` magic in RAM, prints "load kernel from memory", and enforces a ramdisk size cap ("Ramdisk size is
  more than expected(%dMB)"). Use a normal mkbootimg v0 image with the same layout as our LNX image. Gzip kernels are
  decompressed ("decompressing kernel...").
- **DTB source:** modes 0 (normal) and 2 (fastboot boot) print "Using dtb image from DTB partition". Only mode 1 (recovery) uses
  "dtb image appended to SOS". cboot then picks the entry that matches BoardId/SKU/Rev from the DTB-partition image and patches
  it (bootargs, /memory, MAC, `/chosen`). **A DTB inside a RAM-booted image is ignored.** Our carrier's own Linux DTB comes from
  APP and is hash-pinned by the stage, so it is not affected.
- Max download size: there is a `max-download-size` getvar, but `getvar all` did not print it. Run
  `fastboot getvar max-download-size` before a large boot. LNX (0x1980000 = 26.5 MB) has already transferred via `flash boot`.
- Caveat: andreiw's 2018 shieldTV_loader README (local copy at `harvest-2026-10-14/boot/sources/shieldTV_loader/README.md`)
  says "`fastboot boot` is kinda broken on newer firmware". The code path exists, but treat the first try as an experiment (M).
- **Use:** test new carrier LNX candidates with `fastboot boot` **without overwriting LNX p18**. If one fails, power-cycle and the
  flashed LNX boots unchanged.

## 2. oem/getvar surface; no readback (H)

- `oem` handler (0x92c4b0fc): `lock`, `unlock`, `audio-uart`, `audio-no-uart` (both **write odmdata in the BCT**, so do not
  use them), `dtbname` (prints board id/sku/rev and the `nvidia,dtsfilename` of the selected kernel DTB; useful and read-only),
  `ecid` (chip ECID; read-only), `off-mode-charge 1|0` (sets a flag and reboots). Anything else returns "unknown command..".
- `flashing lock|unlock`: the same lock/unlock flow, which requires on-screen confirmation and does a factory reset.
- Getvars: `version-bootloader`, `version-baseband`, `version-mts`, `version`, `max-download-size`, `serialno`, `mid`, `product`,
  `secure`, `unlocked`, `partition-size:<p>`, `partition-type:<p>`, `partition-crc32` ("NO SUPPORT YET!"), `off-mode-charge`,
  `all`.
- **No `upload`, `fetch`, `oem log`, or crc/readback.** You cannot read partitions or logs through this fastboot. cboot logs go
  only to the debug UART (an "sqa-automation-port" is also referenced).
- `erase:` and `flash:` resolve partition names through the partition table. The flash code also recognises special names such
  as `staging`, `mts_preboot`, `nvtboot`, `cbootbackup`, `tbcbackup` and `vendor`. NVIDIA's official reflash uses
  `fastboot flash staging blob`, and cboot applies the staged blob on the next boot
  ([NVIDIA HowTO](https://developer.download.nvidia.com/assets/gameworks/downloads/regular/howtoflash/HowTO-Flash-Recovery-Image.txt)).

## 3. Entering fastboot without a working controller

Decision code is at 0x92c044e8-0x92c04958 (H):

1. **Gate:** unless `/chosen/nvidia,fastboot_without_usb` is set, cboot reads a VBUS GPIO (0x6000d6xx). Without VBUS it prints
   "fastboot: usb cable is not connected" and **ignores every fastboot trigger**. The PC must already be on the OTG port (the
   port farther from HDMI, per the ledger) with a powered link.
2. **PMC fastboot flag** (flag id 0x1e = PMC_SCRATCH0 bit 30). If set, cboot clears it and enters fastboot. Both the NVIDIA 4.9
   kernel and mainline `drivers/soc/tegra/pmc.c` set this bit for `reboot("bootloader")`. That covers `adb reboot bootloader`,
   recovery's `reboot bootloader`, and in Omarchy `systemctl reboot --reboot-argument=bootloader`. The bit survives a warm
   reset but not a power cut. (H for cboot; M for the bit mapping.)
3. **USB gamepad or keyboard A+B:** cboot polls "abxy key state" 6 times at 100 ms each and needs bits 0 and 1 both set. This is
   NVIDIA's documented 2017 method: controller or keyboard on the port **nearest HDMI**, hold A+B, then apply power
   ([NVIDIA](https://developer.download.nvidia.com/assets/gameworks/downloads/regular/howtoflash/HowTO-Flash-Recovery-Image.txt),
   [LineageOS foster](https://wiki.lineageos.org/devices/foster/install/variant1)). (H)
4. **Power-key long press** from `/gpio-keys/power`: 10 reads 300 ms apart. This is the 2015 touch-button route; Darcy has no
   power button. (H code, M applicability)
5. **misc/BCB (`MSC`) cannot reach fastboot.** cboot reads 0x440 bytes and acts only on `boot-recovery` (plus stage `2/3`).
   There is **no `bootonce-bootloader`**. Writing MSC can only force SOS (recovery). (H)

**Robust refusal scheme (M):** when the carrier refuses, it calls `reboot(RB_AUTOBOOT2, "bootloader")` (busybox
`reboot bootloader` in the 4.9 recovery kernel) instead of dropping straight to Lineage recovery. With the PC on OTG, cboot
enters fastboot, and the host's `fastboot-watch.sh` sees it and can `boot`/`flash`. If no cable is detected, cboot skips
fastboot and boots LNX normally, which would loop. Guard against that:

- keep a persistent refusal counter (carrier-owned, e.g. on APP or cache);
- on attempt 1, reboot to bootloader;
- on attempt 2 or later, fall through to Lineage recovery (or write BCB `boot-recovery`), so ADB is still the backstop;
- clear the counter when ACK reaches healthy.

**Does it stay in fastboot?** The command loop reads USB with an infinite timeout, and I found no menu timer constant. The
owner, however, observed an automatic Continue after about 60 s. I could not locate its source; a PMIC/watchdog-related path is
possible (L). Plan for a ~60 s window: the host watcher should act immediately. If the window closes, the counter scheme brings
the device back to recovery and then to the bootloader on the next refusal.

**Software RCM:** mainline/NVIDIA `reboot("forced-recovery")` sets PMC_SCRATCH0 bit 1, which the T210 BootROM honours to enter
RCM/APX on warm reset (H for the BootROM; the same mechanism Switch homebrew uses). The menu item "Forced Recovery" does the
same.

## 4. Flash risks and last resort

- **`boot` (LNX):** already in routine use. A bad LNX still reaches cboot fastboot via A+B, or via the PMC flag if recovery runs.
  Risk is low.
- **`recovery` (SOS):** SOS boots with its **appended** DTB. A broken SOS removes our only Android/ADB fallback. Boot and
  fastboot remain usable, so it is recoverable, but do not flash SOS while LNX is also unproven. Risk is medium.
- **`dtb`:** both LNX and `fastboot boot` take their kernel DTB from it, and cboot patches nodes into it. If the image header is
  unreadable, cboot prints "Error loading kernel DTB. Will enter fastboot" (H), which is a soft landing. A DTB that parses but
  is wrong (no matching BoardId entry or bad nodes) can boot-loop the carrier kernel. Recovery would still boot with its
  appended DTB, so SOS is the fallback (M). Flash only a full multi-entry DTB image (the stock blob `DTB-11..14` from the OTA)
  and back it up first. Risk is medium.
- **`bootloader`, `staging`, `rp4`, `nvtboot`/`cbootbackup`/`tbcbackup`, and `oem audio-uart`:** these touch the BCT, boot
  chain, or odmdata. A bad write can leave cboot unreachable. Only the RCM path below can recover that. Do not touch them. The
  official `flash staging blob` is the only sanctioned bootloader repair. Risk is high.

**RCM/APX last resort (M/L):** Darcy is an original T210 (A02/A04, not T210B01). It is therefore subject to the BootROM RCM
overflow CVE-2018-6242 (Fusée Gelée/ShofEL2), which runs unsigned code over USB on fused production parts
([CVE](https://cvefeed.io/vuln/detail/CVE-2018-6242), [shofel2](https://github.com/fail0verflow/shofel2)). NVIDIA's
nvflash/tegraflash is useless on a consumer Shield, because RCM messages must be signed with the device SBK/PKC key, which we do
not have, and NVIDIA ships no Shield nvflash. Recovery therefore means:

1. enter APX (menu item, `reboot forced-recovery`, or a dead boot chain);
2. load a payload via fusee-launcher;
3. use a custom payload that brings up the SDMMC4 eMMC and exposes it (USB mass storage, or a write-back loader) to restore the
   boot0/boot1 chain and GPT from the stock blob.

No turnkey Darcy payload is known to me (L), and building one is a project. Treat RCM as "possible in principle" and avoid
needing it.

## Local artefacts

The scratch EBT and disassembly were deleted after analysis. Reproduce them from the blob with
`dd if=blob of=EBT.bin bs=1 skip=1024 count=551840` and `aarch64-linux-gnu-objdump -D -b binary -m aarch64 --adjust-vma=0x92c00000`.
Key VAs: command table 0x92c4aa40, oem 0x92c4b0fc, boot 0x92c4c390, getvar 0x92c4b86c, boot routine 0x92c039b8, fastboot
triggers 0x92c044e8-0x92c048a4, MSC/BCB 0x92c045d0-0x92c04958.
