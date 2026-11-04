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

## DTBO selection (recovery_dtbo, magic 0xd7b7ab1e) — added 2026-11-03

**Bottom line (H): on this unit cboot never reads the recovery_dtbo table.** Recovery (SOS) boots with the kernel DTB from the
DTB partition. The A04 DTB you saw in recovery came from that gate, not from a no-match fallback.

**Gate: "Platform supports dtb image" (0x92c022bc).** It returns true only when all of these hold:
1. PMC_SCRATCH20 (odmdata, 0x7000e4a0) bit 0 is clear.
2. HIDREV (0x70000804) has chipid 0x21 and majorrev > 1. That is T210B01 only (0x92c020d8-0x92c020f8).
3. The EEPROM board ID (board-info query 0x26/0x37) is 0xb4e (P2894, 0x92c02130) or 0xd61 (P3425 sif, 0x92c021b0).

This unit is an original T210 (majorrev 1), so the gate is false (H code; M on the majorrev value for B01). The DTB-image step
(0x92c03c44 -> 0x92c03da4) is skipped, and the kernel DTB loaded earlier from the DTB partition is used. Independent check (H):
`oem dtbname` prints "DTB image: compatible id/custom0/rev" only when the gate is true (0x92c4b284). On your device it printed
only the dtsfilename. The 7 Lineage entries are for tegra210b01 boards anyway.

**Matching rule, for reference** (applies on B01 only; `extract_dtb` 0x92c292e8):
- It requires magic 0xd7b7ab1e and dt_entry_count <= 10 (0x92c29358). Otherwise it fails with "Invalid dtb image" (-7).
- Board info comes from query 0x14, 18 bytes: board id at +4, SKU at +6, fab/rev at +8, all u16 (0x92c2939c).
- For each entry it tests `id == board_id` (0x92c29438), `custom[0] == sku` (0x92c29450) and `rev == fab` (0x92c29468).
  These are **exact equality tests, and the first match wins**. There is no mask and no closest match; custom[1..3] are ignored.
  The entry fields are u32 and the board fields are u16, so values >= 0x10000 never match.
- No match prints "No compatible DTB for BoardId..." and returns -2. Then "Failed to extract dtb from dtb image."
  (0x92c036dc), then "Failed while extracting DTB" (0x92c03e20), then "Failed to boot Android", then the **fastboot menu**
  (0x92c03b8c). It does **not** fall back to the DTB partition or to entry 0.
- SOS needs a boot header version > 0 (0x92c035fc, "Header version not > 0"). It reads recovery_dtbo_size at hdr+0x660 and
  recovery_dtbo_offset (u64) at hdr+0x664 (0x92c03630).
- Several entries with different revs may point to the same dt_offset (each entry is just size + offset).

**Consequences for a mainline SOS with our own DTB:**
- A recovery_dtbo table has no effect on this T210. Our values would be id 0xb4e, custom0 = EEPROM SKU, rev = fab code (A04
  probably 0xa4, by analogy with a08 = 0xa8, M), but they are irrelevant here.
- Options:
  - Write our DTB into the DTB partition. This also changes the DTB for the LNX carrier's 4.9 kernel and for any
    `fastboot boot`, so do not do it unless the carrier tolerates it.
  - Keep the stock DTB and have the SOS ramdisk kexec mainline with our DTB, as the carrier already does. **Recommended.**
- arm64 has no appended-DTB support.

**Nodes cboot patches in the kernel DTB it hands over** (from strings, M): `/chosen` (bootargs and `/chosen/bootloader`;
"Failed to find node /chosen in DTB" is an error), `/memory` (reg update), the MAC address nodes (via NCT), verified-boot and
safe-mode nodes, and `system_root_blkdev` (warns if missing). `nvidia,dtsfilename` is only read: by `oem dtbname` and by the
blob updater ("Device DTB file name %s matches with blob DTB"), which uses it to decide which blob DTB to write into the DTB
partition during a `staging` update. `nvidia,boardids` is not compared by the selection code above.

## Shim boot contract (cboot -> "kernel"), added 2026-11-03

Source: the same EBT disassembly. LNX (mode 0) and SOS (mode 1) share one load path in `0x92c039b8`. The mode only selects the
partition, plus the DTB-image step, which is skipped on this T210 (see above). Everything below therefore applies to both
unless noted.

**1. Kernel load and decompression**
- The destination is fixed at `base + 0x80000`, where `base` comes from nvtboot boot-args query 4 (0x92c03c64-0x92c03c78) (H).
- The header's `kernel_addr`, `ramdisk_addr` and `tags_addr` are never read. Only kernel_size (+8), ramdisk_size (+16) and
  page_size (+36) are used (H).
- base is almost certainly DRAM 0x80000000, giving a kernel at 0x80080000. That is not 2 MiB aligned (M). The log line
  "kernel load address" prints the exact value on UART.
- There is no arm64 Image header parsing: no 0x644d5241 constant, no text_offset or image_size use (H). The payload is jumped to
  at its first byte.
- Compression is detected by magic (table at 0x92c7f648): `1f8b` = zlib/gzip, `0221` = lz4-legacy, `0422` = lz4 (H).
  - Compressed: decompressed straight to the destination with a **max output of 0x2f80000 (47.5 MiB)** (0x92c04004-0x92c04024)
    (H).
  - Raw: copied as-is (0x92c03f74). There is no explicit cap, but the ramdisk sits at `base+0x4100000`, so raw must be
    < 0x4080000 (64.5 MiB) (M).
- **Shim rule:** make the shim position-independent, then copy the mainline Image to a 2 MiB-aligned address (text_offset 0)
  that does not overlap the shim, the ramdisk or the DTB. Use the cboot /memory ranges to choose it.

**2. Ramdisk**
- It is loaded at `base + 0x4100000` (≈0x84100000) (H code, M absolute).
- The cap is 200 MiB: `0xc800000` page-rounded at 0x92c03d2c-0x92c03d48, plus a 0xc7fffff check in RAM mode (H).
- The range is passed as `/chosen/linux,initrd-start` and `linux,initrd-end`, **each a 1-cell (32-bit) property**
  (0x92c075a8-0x92c0761c, len 4) (H). Mainline accepts 1-cell values. Copy them as they are or widen to 2 cells.

**3. The DTB it hands over**
- **x0 = DTB pointer.** It is the kernel DTB loaded early from the DTB partition ("Kernel DTB loaded at %p", 0x92c0d7c4) and
  then patched (H).
- The address is printed on UART but not known statically (L: TX1 L4T cboot commonly uses 0x83000000). Slack after the blob is
  unknown, so **the shim should copy cboot's values into its own embedded DTB, not edit in place**.
- `/memory` (0x92c07fe0-0x92c081e0) (M):
  - rebuilt as a multi-range `reg` of 2 MiB-aligned non-secure DRAM ranges with the carve-outs (TOS/TLK, BPMP, etc.) cut out as
    holes;
  - the same ranges go to the TOS by SMC ("NS DRAM ranges recorded by TOS").
  - **Copy every reg tuple**, not just the first.
- `/reserved-memory` is not generated. The stock DTB already has iram-carveout, ramoops (0xb0000000), a VPR alloc-range and
  fb0/fb1 entries.
- Other carve-outs are passed **in bootargs**: `lp0_vec=`, `nvdumper_reserved=`, `vpr_resize`, `tegra_fbmem=`, plus tegraid,
  ddr_die, `androidboot.*` and so on (string table around 0x92c5feeb).
- Mainline should reserve with /memreserve/ or no-map nodes (M):
  - the lp0_vec and nvdumper ranges;
  - the still-scanning boot framebuffer (`tegra_fbmem=`), or display must be quiesced;
  - the existing fdt memreserve entries (`fdt_num_mem_rsv`).
- `/chosen` gets (M, strings around 0x92c614xx):
  - `bootargs`: the cboot-built string + the boot.img cmdline + the DTB cmdline;
  - linux,initrd-start/end;
  - board/pmu/display info;
  - major_revision and minor_revision;
  - pmc_reset_status and pmic_reset_status;
  - eks_info and hdcp14enabled;
  - verified-boot and bootloader nodes.

**4. The jump (0x92c04270-0x92c04298, H)**
- Sequence: `msr daifset,#3` (IRQ/FIQ masked), timer/irq teardown (0x92c0ca6c), `arch_disable_cache(3)` (0x92c024cc), then MMU
  off (0x92c030d4), then `blr x23`.
  - arch_disable_cache clears SCTLR_EL2.C, cleans and invalidates the D-cache by set/way, clears SCTLR_EL2.I and runs `ic iallu`.
  - The MMU step clears SCTLR_EL2.M.
- **The CPU is at EL2 (cboot runs at EL2: sctlr_el2/hcr_el2/vbar_el2), with MMU, D-cache and I-cache all off.**
- Registers: x0 = DTB, x1 = x2 = x3 = 0.
- EL3 is ATF with TLK as the TOS (`androidboot.secureos=tlk` in the stock /chosen/bootargs). Secondary CPUs are held by firmware
  and started through PSCI (the stock DTB has `arm,psci-1.0` and enable-method psci) (M).
- Do not touch the TOS carve-outs, which are absent from /memory.

**5. Watchdog**
- cboot does not program the Tegra TKE WDT. There are no 0x600051xx accesses, only TIMERUS 0x60005010 reads (H).
- It **does run a thread that clears the MAX77620 PMIC system watchdog every 30 s** (0x92c2ea70 waits 30000 ms, then
  `max77620_clear_syswdt` 0x92c2e770) (H).
- I found no evidence that it disables the PMIC watchdog before the jump (M).
- The current chain keeps Linux up for more than 326 s because the 4.9 kernel and mainline drivers handle it.
- **With a direct mainline boot, have the MFD_MAX77620 + MAX77620_WATCHDOG + I2C_TEGRA drivers built in**, or a PMIC reset may
  occur after up to ~128 s (M/L).
- Stock DT: the `watchdog@60005100` node is "disabled", and the odm-data bit 0x10000 overrides it. timeout-sec = 120.
- To arm a ~120 s TKE WDT from the shim (mainline `tegra_wdt.c` layout, WDT0 paired with TMR5, which mainline clocksource
  leaves free):
  - `0x60005060` (TMR5 PTV) = `0xC003D090`: EN | PERIODIC | 250000 µs, so that 4 expiries = 1 s.
  - `0x60005100` (WDT_CFG) = `5 | (120 << 4) | (1 << 15)` = `0x8785` (timer 5, period 120, PMC2CAR_RST_EN).
  - `0x60005108` (WDT_CMD) = `1` (START_COUNTER). Writing 1 again pings it.
  - To stop it: `0x6000510c` = `0xC45A` (unlock), then WDT_CMD = `2`.
  - Mainline `tegra_wdt` reprograms it on open. Userspace (systemd `RuntimeWatchdogSec`) must open and ping it, or the board
    resets at 120 s, which is the intended safety net (M).

**6. shieldTV_loader lessons** (harvest `sources/shieldTV_loader/{start.S,main.c,README.md}`)
- It uses an arm64 Image-style header (`ARMd` at +0x38) but **self-relocates (PIE, R_AARCH64_RELATIVE loop)**. The README
  says "your image will be loaded at the first opportune place, so it better be position-independent".
- It takes x0 = FDT and reads `/chosen/bootargs` and every `/memory` reg.
- It reserves `tsec=`, `vpr=`, `lp0_vec=`, `nvdumper_reserved=`, the cboot framebuffer (`tegra_fbmem=`, else
  0x92ca6000/0x92ca8000 depending on firmware), the FDT itself and all fdt memreserve entries.
- It checks CurrentEL and SCTLR (EL2/EL1 aware) and runs with MMU and caches off as received.
- It reuses the live cboot framebuffer for output, so cboot leaves the display scanning out at handoff.
- Its partial source copy has no cache maintenance before jumping onward.
