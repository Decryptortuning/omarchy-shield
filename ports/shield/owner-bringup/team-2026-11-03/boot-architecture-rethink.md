# Shield (Darcy A04) boot architecture rethink — 2026-11-03

Design only. No device access, no writes outside this folder. Confidence marks: **H** = read in local code/data or well-documented upstream behaviour, **M** = strong inference from evidence, **L** = guess. "local" = evidence in this build tree; "web" = cited source.

## 0. Why the current chain hurts, in one paragraph

Every pain point in the AAR traces to one design decision: the production kernel is reached *through* a vendor 4.9 kernel and the Lineage recovery userspace. That forces a two-kernel handoff (SMMU/GPUB/host1x/xusb quiesce, the "root hubs only" USB rule, the pinned RAM map, the pinned `tegra_fbmem`), it leaves the only fallback in a userspace we do not control (recovery ADB with flaky VBUS sensing, no usb-storage, no network), and it made every integrity check a *refusal* with nowhere to land. The claim/ack protocol then turned a one-line unit mistake into a 20-hour outage. The fix is not a better carrier; it is removing the carrier.

## 1. Hard facts that constrain every design

| Fact | Source | Mark |
|---|---|---|
| cboot `boot` (LNX, mode 0) and `fastboot boot` (mode 2) take the kernel DTB from the **DTB partition**; recovery (SOS, mode 1) takes it from the **DTB appended to SOS** | `fastboot.md` §1 (disassembly) | H local |
| "Appended to SOS" = the Android v1 header's `recovery_dtbo` blob. Lineage's SOS carries a 1.16 MB blob of six FDTs; the live recovery FDT has `nvidia,dtbbuildtime = "Jan 30 2026"` while the DTB-partition entry for A04 says `"Dec 15 2024"`, so cboot really did use the SOS blob | SOS readback header parse; `stock-a04.dts` vs `ota-blob-dtbs/DTB-12.dts` | H local |
| Stock NVIDIA SOS has `recovery_dtbo` size 0, so cboot must fall back to the DTB partition when the blob is absent | `stock-bootstrap-2026-10-14/image/stock-inventory.img` header | H local (fallback: M) |
| The DTB-partition image is a plain concatenation of FDTs; all four Darcy entries carry identical `nvidia,boardids = "2530:0032:E0"` and differ only by `nvidia,dtsfilename`; cboot selected the `-a04-` entry | `ota-dtb-summary.json`, `oem dtbname` in `fastboot.md` | H local; selection key: M |
| cboot patches `/chosen/bootargs`, `/memory`, MAC addresses into whichever DTB it chose | `fastboot.md` §1 | H local |
| Partition sizes: LNX = SOS = 25.5 MiB, DTB = 4 MiB, APP = 256 MiB ext4, UDA (p33) = 14.1 GiB Btrfs, MSC = 2 MiB | `carrier/build/descriptor.json` | H local |
| cboot gzip-decompresses the kernel; kernel457 `Image.gz` is 17.3 MB, leaving ~8 MB for an initramfs inside LNX | `public-kernel-closure-2026-10-16/dist/`, `fastboot.md` | H local |
| kernel457 has `BTRFS_FS=y EXT4_FS=y DRM_TEGRA=y FRAMEBUFFER_CONSOLE=y MMC_SDHCI_TEGRA=y USB_XHCI_TEGRA=y KEXEC=y KEXEC_FILE=y RELOCATABLE=y RANDOMIZE_BASE=y`; `BRCMFMAC R8169 USB_TEGRA_XUDC LIBCOMPOSITE F_NCM F_MASS_STORAGE` are modules; `DEBUG_INFO_NONE` | the 10-16 `.config` (same lineage as 457) | H local |
| The recovery kernel starts "All CPU(s) started at EL2" with PSCI 1.1 from the TOS; the kexec'd mainline kernel inherits that, so mainline already runs at the EL cboot provides | recovery dmesg; pstore of the kexec jump | H local |
| cboot forces device mode on the OTG pad by register override and does not need real VBUS; recovery's xudc does. Mainline xudc + NCM already works on this port (`shield.owner-maintenance=usb-ncm`) | `usb-adb.md` §4; owner-init cmdline | H local |
| `fastboot boot` works on this unit (Oct 15 RAM entry of the stock-kernel diagnostic) but stalls on the unlocked-warning screen when no controller answers | `README.md` (port), AAR | M-H local |
| MSC/BCB: cboot acts only on `boot-recovery` → SOS; PMC flag 0x1f (`reboot recovery`) → SOS; PMC 0x1e (`reboot bootloader`) → fastboot; no `bootonce-bootloader` | `fastboot.md` §3, `deep-refusal.md` §1.1 | H local |
| cboot never arms a hardware watchdog; a hung kernel needs a power cycle | inference from `fastboot.md` §3 ("no menu timer constant") | M |
| arm64 boot protocol: Image goes `text_offset` bytes above a 2 MiB-aligned base; since 5.8 `text_offset` is 0. With `CONFIG_RELOCATABLE` a misaligned load works in practice (any 64 KiB multiple) with a kernel warning, but only the EFI stub officially does it | [booting.rst](https://git.radix-linux.su/kernel/linux.git/tree/Documentation/arch/arm64/booting.rst), [Ard Biesheuvel, Oct 2025](https://lists.infradead.org/pipermail/linux-arm-kernel/2025-October/1068713.html), [OpenWrt note](https://github.com/haotiangood/openwrt/commit/82ce460ab106c1d3626607c4d867853cf385ad33) | H web |
| u-boot's `arch/arm/mach-tegra/cboot.c` saves x0 from cboot and reads `/memory` from the cboot-supplied DTB; TX1 and Nano boot cboot → u-boot → extlinux | [cboot.c](https://coral.googlesource.com/u-boot-mtk/+/3342717cb1c906144525d3fc88addb12e5fc67a5/arch/arm/mach-tegra/cboot.c), [L4T u-boot guide](https://docs.nvidia.com/jetson/archives/l4t-archived/l4t-321/Tegra%20Linux%20Driver%20Package%20Development%20Guide/uboot_guide.html) | H web |
| u-boot on Nano has XHCI host (`usb start`) over the same `xusb@70090000`; no T210 XUDC gadget driver was found, so no `ums` | [NVIDIA forum log](https://forums.developer.nvidia.com/t/jetpack-4-5-production-release-with-l4t-32-5/166475?page=2) | M web |
| andreiw's 2018 `shieldTV_loader` replaced LNX on a 2015 Shield (same T210) with a custom fastboot shim that boots arbitrary position-independent payloads; it notes `fastboot boot` "kinda broken on newer firmware" | local README (`harvest-2026-10-14/boot/sources/shieldTV_loader`) | H local |
| Switch (same T210): hekate → coreboot → u-boot → extlinux/boot.scr; hekate's bare-metal BDK provides USB mass storage of eMMC/SD | [fluxcoil](https://fluxcoil.net/wiki/hardware/nintendo_switch), [shofel2](https://github.com/chrepl/shofel2), [hekate](https://github.com/CTCaer/hekate), [UMS Loader](https://www.gamebrew.org/wiki/UMS_Loader_Switch) | H web |
| Mainline has the Darcy DT since v5.1 (`tegra210-p2894-0050-a08.dts`, compatible `nvidia,p2894-0050-a08`); our `board.v2.dtb` is the A04 derivative | [tegra.yaml](https://git.zx2c4.com/linux-dev/tree/Documentation/devicetree/bindings/arm/tegra.yaml), local DTB | H |
| Darcy is original T210 and therefore subject to the BootROM RCM bug (CVE-2018-6242); payloads need RCM entry (menu "Forced Recovery", `reboot forced-recovery`, or a dead BCT/bootloader) and a signed-key-free launcher | [fusee-launcher](https://github.com/rebelmx4/fusee-launcher), `fastboot.md` §4 | H (applicability to Darcy: M) |
| VPR: MC `VIDEO_PROTECT_BOM/SIZE_MB/REG_CTRL` at 0x70019648/64c/650; the 4.9 kernel creates a *resizable* VPR heap at 0xd7000000+0x19000000 and shrinks it through the TOS (`vpr_resize`, `secureos=tlk`); the kexec'd mainline kernel already uses that range without faults | [u-boot mc.h](https://grok.openbmc.org/xref/openbmc/u-boot/arch/arm/include/asm/arch-tegra210/mc.h?r=85187b80), recovery dmesg, `stage-memory.inc` | H / M (direct-boot state unknown) |

## 2. The option space

### A. Mainline 7.1 directly from LNX, no loader (the pure form of (a))
cboot decompresses `Image.gz`, jumps at EL2 with x0 = the DTB it chose and patched. The DTB must be ours, so either (A1) flash a DTB-partition image whose single entry is the mainline DTB carrying the stock root properties (`nvidia,boardids`, `nvidia,dtsfilename`), or (A2) boot from SOS with the mainline DTB in `recovery_dtbo` and make SOS the default route via a sticky `boot-recovery` BCB. Unknowns: whether cboot honours `text_offset`/alignment (mitigated by `RELOCATABLE=y`, H web), whether cboot's node patching tolerates a mainline tree (M: it adds `/chosen` and `/memory`, both present), the display state cboot leaves (logo scanning out of `tegra_fbmem`; mainline tegra-drm resets DC; Nano does this routinely, M), and whether cboot/TOS leaves the VPR armed (M, see E3). Fixes: no kexec, no quiesce, no USB rule, no RAM-map pinning, no two kernels. Does not fix by itself: fallback, rescue, A/B. Brick risk: a wrong DTB-partition entry hangs LNX *and* RAM boot, but SOS with its own blob and A+B → fastboot survive; `fastboot flash dtb <stock backup>` (4 MiB, backed up) undoes it. Reuses kernel457 Image, board.v2.dtb, modules, Btrfs root. Effort: days, mostly experiments.

### B. u-boot chainloaded from LNX (switchroot/Nano style)
Feasible in principle: cboot→u-boot is the supported L4T chain on TX1/Nano and `cboot.c` consumes exactly the DTB cboot passes (H web); the 2015 Shield took foreign payloads from LNX (andreiw, H local). u-boot would read extlinux from APP, load our DTB itself (so the DTB partition stays stock), and give `bootcount`-based A/B and PXE/TFTP via the PCIe RTL8168 (u-boot drives the same chip on Nano, M). What it does **not** give on T210: USB device mode/UMS (no XUDC driver found, M), Wi-Fi, Btrfs snapshots, SSH. HDMI console on T210 u-boot is unproven (L). Needs a Darcy board port (pinmux, PMIC, eMMC, PCIe lanes) — a real porting job, and a second code base to maintain next to Linux. Brick risk low (LNX only). Verdict: good engineering, wrong tool for *this* pain list.

### C. LinuxBoot-style: mainline 7.1 as the boot manager, kexec into the production kernel
LNX holds kernel457 + a small initramfs (busybox or u-root; a bare u-root arm64 `boot`-only initramfs xz-compresses to ~3.5 MB, [Fujitsu](https://pt.slideshare.net/naohirot/getting-started-with-linuxboot-firmware-on-aarch64-server)). It brings up fbcon, Ethernet, Wi-Fi, NCM, UMS and sshd with drivers already proven on this board, selects a boot set from APP/Btrfs, and kexecs. Mainline→mainline kexec is routine; none of the 4.9 inherited-state quirks (GPUB, SMMU, host1x) apply. Cost: two kernels on the normal path (+10–15 s), kexec display re-init, and the same DTB question as A for the first kernel. Fixes everything on the pain list except "two-kernel complexity", which it merely tames. Strong runner-up; it is also the natural *fallback* if LNX cannot hold the production kernel.

### D. Keep cboot→4.9 LNX, replace Lineage userspace with a tiny initramfs
Removes recovery UI, SELinux and the init.rc dance, but keeps the vendor kernel and therefore every kexec quirk, the quiesce script, the pinned memory map and the no-usb-storage/VBUS problems. Rejected: it is the current design minus one layer.

### E. A/B boot sets with boot counting (Android A/B, RAUC/mender style)
cboot has no slot logic, but it has one free binary switch: `boot-recovery` in MSC (and PMC 0x1f for warm reboots) selects SOS. Treat **LNX = slot A, SOS = slot B** at the kernel level, and let *our* loader do counted retries at the root/boot-set level on APP. Boot counting replaces the pending/healthy claim: increment before boot, clear on success, escalate (retry → other root snapshot → other kernel slot → rescue). This is a component, not an architecture; it is adopted in the recommendation.

### F. Root on Btrfs snapshots with automatic rollback
`@root` vs `@root.lkg`, chosen by the loader; a timer promotes a proven-healthy boot to `.lkg`. Already sketched in `rescue-architecture.md` §3. Independent of the kernel question; adopted.

### G. SOS as an independent second loader
Already true in cboot's model: SOS has its own DTB blob and its own entry conditions. Use it as slot B carrying the previous known-good kernel+initramfs, not as "Lineage recovery". Adopted.

### H. RCM / Fusée Gelée as a development unbrick tool
Possible in principle (original T210, H), but there is no Darcy payload; hekate's BDK (SDMMC4 eMMC + USB mass storage, no display) is the obvious base, and the Switch and Darcy share the SoC, PMIC family and eMMC controller. A payload that exposes eMMC over USB would make *every* partition recoverable with no running bootloader. It only matters if cboot/BCT/TOS ever get damaged, which nothing below writes. Keep as an optional research track, not a dependency.

### I. Status quo plus `rescue-architecture.md` (retry, LKG slot, rescue initramfs)
Would have saved 11-03, but keeps Lineage, 4.9, the quiesce, the profile compiler and the pinning. Every future change still means a new profile, a new carrier and a new APP image. Rejected as the *target*; its rescue initramfs design and guardrails are reused.

### J. Radical variants considered and parked
UEFI (Tianocore) via an LNX shim and systemd-boot (andreiw explored this path on the 2015 Shield; nothing current, L); PXE netboot only (needs u-boot or a Linux loader anyway); repurposing the 128 MiB `BMP` partition as a boot store (unnecessary, APP suffices).

## 3. Recommendation: "one kernel, lands somewhere useful"

Fuse A + C-rescue + E + F + G:

```
cboot ──LNX (slot A)──► mainline Image.gz + micro-initramfs (≤ 3 MB)
      └─SOS (slot B)──► previous Image.gz + same initramfs + mainline DTB blob
                              │
                              ▼  mount APP ro, exec /loader/boot (shell/C, on APP)
                 ┌────────────┴─────────────┐
            counter < N                 counter ≥ N  (or APP unmountable)
                 │                              │
   pick @root / @root.lkg, write pending,   RESCUE in the same initramfs:
   mount Btrfs p33, switch_root → systemd   fbcon status + QR, Ethernet/Wi-Fi/NCM,
   shield-ready clears counter + MSC        key-only sshd, UMS of eMMC over the OTG port,
                                            `shield-rescue status|rollback|resume|slot-b`
```

- **One kernel, no kexec on the normal path.** The LNX kernel *is* the production kernel. Modules stay in the Btrfs root; a rescue subset (brcmfmac, r8169, pci-tegra, xudc, libcomposite, f_mass_storage, f_ncm, firmware) lives on APP next to `/loader`.
- **The DTB rides with the kernel, not with cboot's partition, wherever possible.** Slot B always carries its own blob (`recovery_dtbo`). Slot A needs the DTB partition (A1) — flashed only after A2 has proven the kernel boots directly from cboot. Keep the stock DTB-partition image on the PC; restoring Android later is `flash dtb` + `flash boot/recovery` from backups.
- **Every failure lands in rescue, never in a refusal.** Integrity checks still exist (sha256 of the loader and the chosen boot set, fsck state), but their failure mode is "go to rescue with the reason on screen", not "sit in a menu". The watchdog is taken only by systemd (as today).
- **Boot counting replaces pending/healthy.** `state/counter` on APP: incremented by the loader, cleared by `shield-owner-ready`. Escalation: 2 × retry same root → 2 × `@root.lkg` → rescue. Slot B is chosen explicitly (`shield-rescue slot-b` writes `boot-recovery`; the healthy ack clears MSC) or by the owner from fastboot.
- **No pinned RAM map, framebuffer or GPT hashes.** They existed to make kexec placement safe under a vendor kernel. cboot now does the placement.
- **Kernel updates are rare and fenced:** build → `fastboot boot` (RAM, after A1) → flash to SOS and `systemctl reboot --reboot-argument=recovery` for a full boot from slot B → `dd` the same image to LNX from Linux. SOS always keeps the previous kernel.
- **Writing APP never goes through fastboot sparse mode again:** from Linux (`dd`), from rescue over SSH, or over UMS from the PC. `fastboot flash boot/recovery` with padded raw images stays the only fastboot write.
- **The USB rule disappears** (no xusb teardown), and the controller can stay plugged in.
- **Physical presence** is needed only when both kernel slots fail *and* the loader on APP is broken — then A+B → fastboot, which never changed.

What is retained from today: kernel457 Image, board.v2.dtb (plus the stock root properties for cboot matching), all modules, the Btrfs root and its systemd units, `shield-owner-ready` (as the counter clearer), the ledger/preimage/readback discipline, the make-rawsparse and flash scripts, the beacon idea (now a real fbcon screen), the rescue closure measurements (19 MB glibc / ~10 MB static) and the §3 guardrails of `rescue-architecture.md`.

What is retired: Lineage recovery and its ramdisk, `owner-internal-stage.c` and the profile compiler, `owner-local-claim.c`, `internal-handoff.sh`, `stage-memory.inc`, the 33 MB Python initramfs and its exact-cmdline/boot.json admission, the `watchdog-retry` permit, the `tegra_smmu.*inherited` and `initcall_blacklist` kexec-inheritance hacks (remove one at a time; they are harmless on a clean boot but unneeded).

### Honest trade-offs
- The loader on APP is a single shared component for both slots. It is tiny (a shell script or ~300 lines of C), and the micro-initramfs's UMS fallback covers a broken APP. If that still worries the owner, slot B can carry a frozen copy of the loader inside its initramfs.
- Rescue exposes a key-only root SSH on the LAN and the eMMC as a USB disk on the OTG port. Both are opt-in by failure. The owner must accept this explicitly (the same decision `rescue-architecture.md` asked for).
- Direct boot from cboot is unproven on *this* cboot build. The whole plan is sequenced so that the proof costs one SOS flash and nothing else.

## 4. Experiments that settle the unknowns cheaply (ordered)

| # | Question | Method | Cost / blast radius |
|---|---|---|---|
| E1 | Does cboot jump into a mainline `Image.gz` and does mainline accept the load address? | Build SOS = `Image.gz` + 1 MB busybox initramfs (`init` prints to fbcon and to kmsg, blinks the light bar, sleeps) + `recovery_dtbo` = board.v2.dtb with the stock a04 root properties added. `fastboot flash recovery`, then `systemctl reboot --reboot-argument=recovery` from the running system. Watch HDMI. Look for the 2 MiB alignment warning in dmesg afterwards. | One SOS write; LNX untouched; SOS restore image exists (d8f68c06) |
| E2 | Which blob entry does cboot pick, and does it tolerate a mainline tree? | Variant of E1 with two entries (stock a04 first, mainline second) and the inverse; `fastboot oem dtbname` reports the chosen `dtsfilename`. | Same as E1 |
| E3 | Is the VPR armed after a direct cboot boot? | E1's init reads `0x70019648/64c/650` with `busybox devmem` (needs `CONFIG_DEVMEM`; else a 20-line module). Until answered, the mainline DTB reserves `0xd7000000+0x19000000` `no-map`. | None beyond E1 |
| E4 | Does the display hand over cleanly? | E1 shows fbcon; then load the full root (E5) and confirm Hyprland. If DC fights the logo scan-out, add a `simple-framebuffer`/`tegra_fbmem` reservation rather than touching cboot. | None beyond E1 |
| E5 | Full system boot without kexec | E1 initramfs mounts APP, runs a 30-line `/loader/boot` that mounts `@root` and `switch_root`s. Expect the systemd root to come up unchanged except `/proc/cmdline`; relax `shield-owner-ready`'s exact-cmdline check first or run it in report-only mode. | SOS + APP file adds (`dd` from Linux) |
| E6 | Does `fastboot boot` of the same image work once the DTB partition carries the mainline entry? | After E1–E5 pass: `fastboot flash dtb mainline-single-entry.img`, then `fastboot boot candidate.img` with a controller attached. | DTB partition (backup held); undo = `flash dtb` stock |
| E7 | cboot and MSC persistence | Write `boot-recovery` from Linux, boot twice without clearing: does SOS boot both times? Decides whether slot-B selection is sticky. | MSC only; our SOS clears it on request |
| E8 | Rescue closure fit | Measure static busybox + dropbear/sshd + wpa_supplicant + kmod closure; target ≤ 10 MB on APP, ≤ 3 MB in LNX. | Host only |
| E9 (optional) | RCM research | Confirm RCM entry via `reboot forced-recovery` → `lsusb` shows the NVIDIA APX device; do **not** send a payload until a Darcy UMS payload exists. | Reboot only |

## 5. Migration path (each step reversible, smallest payoff first)

1. **Hygiene now (hours, no architecture change):** adopt `shield-unit-apply` with `systemd-analyze verify` and the ACK-chain lint; snapshot `@root` before unit changes; document the RAW-only APP rule. Reversible: userspace only.
2. **E1–E4 on SOS** (one evening): proves direct boot. Reversible: reflash SOS from the readback.
3. **E5: full root from slot B.** Switch to slot B for daily use for a week via `reboot recovery`; LNX carrier still boots on cold power. Reversible: stop writing the PMC flag.
4. **Micro-initramfs + `/loader` + counter + rescue** (E8): implement escalation and the fbcon status page; test by deliberately installing the 11-03 cycle unit and repairing from rescue over SSH and over UMS. Still slot B only.
5. **E6/E7: DTB partition + `fastboot boot` qualification**, then flash the same image to LNX. Now slot A = mainline, slot B = mainline, Lineage gone from the device. Reversible: `flash boot` carrier v12, `flash dtb` stock.
6. **Retire** the carrier sources, profile compiler, Python admission and inherited-state cmdline hacks one per boot, with the counter watching each change.
7. **Later:** `@root.lkg` promotion timer; kexec-based "try a new kernel from Btrfs without flashing" as a developer convenience; RCM payload research only if cboot repair ever becomes a real need.

If E1 fails for alignment reasons and a header patch does not cure it, insert a 100-line position-independent shim (andreiw's loader pattern) that copies Image to a 2 MiB boundary and jumps; if cboot's DTB patching cannot tolerate a mainline tree, fall back to architecture C (mainline loader kernel from LNX with the stock 4.9-era DTB *for the loader only* is not viable, so C would also need E1 to pass — in that case the shim or u-boot (B) becomes the first stage). Either way, nothing below cboot is ever written.

## 6. Sources
- Local: `fastboot.md`, `usb-adb.md`, `deep-refusal.md`, `boot-refusal.md`, `rescue-architecture.md`, `carrier/src/*`, `carrier/build/descriptor.json`, the SOS readback and stock boot images, `ota-dtb-summary.json`, `lineage-recovery-control-2026-10-15-2/metadata-1/dmesg.txt`, `public-kernel-closure-2026-10-16`, `shieldTV_loader/README.md`, `AAR-2026-11-03.md`.
- Web: [arm64 booting.rst](https://git.radix-linux.su/kernel/linux.git/tree/Documentation/arch/arm64/booting.rst); [u-boot booti placement patch](https://src.whiteboxsystems.nl/Whitebox/u-boot/commit/2808576491ae36b6ea96743005058f370d936beb); [Ard Biesheuvel on TEXT_OFFSET](https://lists.infradead.org/pipermail/linux-arm-kernel/2025-October/1068713.html); [u-boot mach-tegra/cboot.c](https://coral.googlesource.com/u-boot-mtk/+/3342717cb1c906144525d3fc88addb12e5fc67a5/arch/arm/mach-tegra/cboot.c); [L4T u-boot guide](https://docs.nvidia.com/jetson/archives/l4t-archived/l4t-321/Tegra%20Linux%20Driver%20Package%20Development%20Guide/uboot_guide.html); [Nano u-boot USB log](https://forums.developer.nvidia.com/t/jetpack-4-5-production-release-with-l4t-32-5/166475?page=2); [T210 cboot is binary-only](https://github-redirect.dependabot.com/OE4T/meta-tegra/wiki/Using-cboot-as-bootloader); [Tegra DT bindings](https://git.zx2c4.com/linux-dev/tree/Documentation/devicetree/bindings/arm/tegra.yaml); [Switch boot chain](https://fluxcoil.net/wiki/hardware/nintendo_switch); [shofel2](https://github.com/chrepl/shofel2); [hekate](https://github.com/CTCaer/hekate); [UMS Loader](https://www.gamebrew.org/wiki/UMS_Loader_Switch); [fusee-launcher](https://github.com/rebelmx4/fusee-launcher); [T210 MC register map](https://grok.openbmc.org/xref/openbmc/u-boot/arch/arm/include/asm/arch-tegra210/mc.h?r=85187b80); [coreboot T210 VPR](https://review.coreboot.org/plugins/gitiles/coreboot/+/50967870a9b0a55a5c973785803d7fe8921c1107); [LinuxBoot AArch64 sizes](https://pt.slideshare.net/naohirot/getting-started-with-linuxboot-firmware-on-aarch64-server).
