# Direct boot: cboot → shim → mainline Linux

This replaces the Lineage-recovery carrier (Lineage 22.2, the 4.9 kernel and kexec) with a single mainline kernel booted directly by the NVIDIA bootloader (cboot). It is under test as of 2026-11-03 23:40Z: the full Omarchy root runs from the recovery partition (slot B), and the boot partition (slot A) still holds the old carrier v13 until the open items below are done. Background and evidence: `../AAR-2026-11-03.md`, `../team-2026-11-03/boot-architecture-rethink.md` and `../team-2026-11-03/fastboot.md` (the "DTBO selection" and "Shim boot contract" sections).

## Why a shim

On this original-T210 Shield, cboot always hands the kernel the downstream DTB from the DTB partition. It reads a recovery image's own DTB table only on T210B01 boards. Mainline needs our board DTB, so cboot boots a small shim as if it were the kernel:

1. cboot loads the shim at base+0x80000 (gzip, at most 47.5 MiB unpacked) and jumps at EL2 with the MMU and caches off and x0 = its DTB.
2. The shim (`shim/`) relocates itself. It reads `/memory`, `bootargs` and the initrd range from cboot's DTB and writes them into our embedded mainline DTB. It reserves the live splash framebuffer and, if armed, VPR.
3. It clears the one-shot PMC boot-mode flags (through the secure monitor when the PMC is TrustZone-only) and arms the Tegra watchdog: TMR7 PTV 0xc3938700, WDT0 cfg 0x8017, 240 s. Mainline's tegra-wdt adopts it, and systemd pings it.
4. It copies the Image to a free 2 MiB-aligned address and jumps. Progress is drawn on the splash framebuffer, so a photo of the TV shows how far it got.

## Loader (`loader/init`)

A busybox initramfs replaces both the carrier stage and the Python owner-init:

- It disables and kicks the MAX77620 PMIC watchdog. cboot armed it on the normal path and nothing in mainline kicks it.
- It keeps a boot counter in `/shield-boot/counter` on APP: +1 per boot, reset to 0 by `shield-direct-boot-ok` after 3 minutes up.
  - At 3 and 4 it rolls back by renaming `@root` to `@root.bad-<n>` and `@root.lkg` to `@root`.
  - At 5, or when `/shield-boot/next` contains `rescue`, it starts rescue: Ethernet at 192.168.2.211, the root's sshd in a chroot and a console shell on tty1.
- It carries the USB host firmware and the Ethernet modules, so USB and rescue networking do not depend on the root.
- It mounts `@root` read-write and `switch_root`s into systemd. The kernel command line carries `shield.boot=direct`.

## Root side (`root/`)

- **Old owner units:** `shield-owner-*` and `shield-wifi` get a `ConditionKernelCommandLine=shield.omarchy-owner=1` drop-in. On the direct path they are skipped, and a skipped unit never triggers the reboot-on-failure unit.
- **Direct-path units:** `shield-direct-{wifi,fan,pmic,boot-ok,lkg}` run only with `shield.boot=direct`. `@root.lkg` is refreshed 13 minutes after a good boot.
- **Old path:** unaffected. The owner-init enforced file list and forbidden paths were checked, and these files are not on either.

## Build

All inputs are existing artifacts; there is no kernel rebuild.

1. **Font:** `../carrier/diag/make-font.py <linux>/lib/fonts/font_8x16.c shim/font8x16.h`.
2. **Shim:** `make -C shim` (aarch64-linux-gnu-gcc-13). `make -C shim check` confirms the BSS and stack end below the 0x20000 payload offset.
3. **Shim kernel:** `shim/pack-shim.py shim/shim.bin <Image> <board.dtb> shim-kernel.bin`, then `gzip -9 -n`. Use the deployed Image (sha256 `a317e05d…`) and `../dtb` board.v2 (`c0fef725…`).
4. **Busybox:** busybox 1.37.0 `defconfig` with `CONFIG_STATIC=y`, and without `CONFIG_TC`, `CONFIG_SHA1_HWACCEL` and `CONFIG_SHA256_HWACCEL` (they fail on aarch64).
5. **Loader initramfs:** busybox plus `loader/init`, `lib/firmware/nvidia/tegra210/xusb.bin` and `lib/modules/{pci-tegra,r8169}.ko` from the root, packed as newc owned by 0:0 and gzipped.
6. **Boot image:** `loader/pack-boot.py shim-kernel.bin.gz loader.cpio.gz direct.img`. This is an Android v1 image padded to the 25.5 MiB partition, with the direct cmdline.

## Test workflow (remote, reversible)

1. **Write slot B from Linux:** `tools/write-sos-any.sh direct.img <current SOS sha256>`. It checks the preimage, reads back after the write, and confirms LNX and DTB are unchanged.
2. **Boot it:** `systemctl reboot --reboot-argument=recovery`, then watch with `tools/watch-direct.sh`.
3. **Return:** a clean reboot from Linux clears the flag and boots slot A. A hang resets through the shim's watchdog.
4. **Never write an image to LNX that has not run from SOS first.** The bootloader's normal mode differs: it leaves the PMIC watchdog armed. On 11-03 a v2 image in LNX powered the board off after about 2 minutes.
5. **Hands-on recovery, if both slots are bad:** hold A+B at power-on to reach the bootloader, then `tools/flash-safe.sh` restores carrier v13 to LNX, a direct image to SOS and a clean APP image.

## Open before slot A switches

- **GPU on the direct path.** nouveau faults (gpusrd read of address 0, then an SError panic) because the GPU and SMMU arrive straight from cboot. It is blacklisted on the direct path for now; the analysis will go in `../team-2026-11-03/gpu-smmu-direct.md`.
- **PMIC watchdog in normal mode.** The loader and `shield-direct-pmic.service` cover it, but it needs one guarded test from LNX.
