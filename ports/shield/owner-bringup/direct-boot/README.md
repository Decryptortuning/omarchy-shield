# Direct boot: cboot → shim → mainline Linux

This replaces the Lineage-recovery carrier (Lineage 22.2, the 4.9 kernel and kexec) with a single mainline kernel booted directly by the NVIDIA bootloader (cboot). Status 2026-11-04 01:00Z: direct-v4 runs the full Omarchy root from the recovery partition, stable with nouveau blacklisted, and is staged to go into both slots, replacing the carrier (see "Carrier retirement" below). Background and evidence: `../AAR-2026-11-03.md`, `../team-2026-11-03/boot-architecture-rethink.md`, `../team-2026-11-03/fastboot.md` (the "DTBO selection" and "Shim boot contract" sections) and `../team-2026-11-03/gpu-smmu-direct.md`.

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

## Carrier retirement

Two warm reboots from the direct path into the old carrier path (2026-11-03 22:21Z and 2026-11-04 00:37Z) both hung the old path's mainline kernel. The watchdog reset the board and the carrier then refused the leftover claim. A cold power-on into the old path worked both times. Hardware state left by the direct boot, most likely the GPU rail and MC client state, survives a warm reset and breaks the kexec path. Alternating between the paths is therefore unsafe, so the carrier is being retired: `tools/flash-direct-v4.sh` writes direct-v4 to both slots and resets APP. Carrier v13 stays in the build folder and can return through fastboot.

## GPU and fan: root cause and fix (2026-11-04)

The board DT names its pin table `pinctrl-names = "boot"` (the same as upstream `tegra210-p2894.dtsi`). Mainline only applies hog states named `default`/`init`. The old kexec path inherited the stock 4.9 pinmux, but cboot leaves two pins at function 0:
- `lcd_gpio2_pv4`, the GPU voltage PWM1. With it unrouted, the GPU buck never saw a VID signal and sat at about 710 mV, whatever nouveau asked for. At high clocks the GPU then corrupted its work: a gpusrd read of address 0, MEMACK timeouts, CTXSW timeouts and an SError.
- `pe7`, the fan PWM3. The fan stayed off on every direct boot, and the board idled at 83-86 C.

The fix is `gpu-fix/board.v2-to-v4a-pinmux-default.diff`: one property, `pinctrl-names = "default"`. With it, the kernel routes both pins at boot, the fan runs at about 5900 rpm (34-42 C), VDD_GPU tracks nouveau's DVFS across its hardware 710-1320 mV range, and nouveau with Hyprland ran with zero GPU errors. direct-v9 loads nouveau at boot (no blacklist). Diagnosis: `../team-2026-11-03/gpu-smmu-direct.md`. The VDD_GPU-pinning DTs (v3a-v3e) only masked the missing PWM routing; do not use them.

## Open items

- **GPU on the direct path: fixed by the pinmux (see above).** Earlier analysis notes, kept for reference: The analysis is in `../team-2026-11-03/gpu-smmu-direct.md`. The SMMU handoff patches are not the cause: they reach the same end state on both paths, and the cmdline flags must stay. The fault starts on the GPU side, with an untranslated `gpusrd` read of address 0, then PBDMA errors, an LTC flush timeout and an SError. Ranked candidates:
  - VDD_GPU left at 710 mV. Stock sets 1.0 V; the fix is `gpu-fix/board.v2-to-v3a-vddgpu-1v0.diff`, DT only.
  - The GPU MC client flush/hot-reset state, which nouveau never resets. The fix is `gpu-fix/board.v2-to-v3c-mcreset-only.diff` plus `gpu-fix/0019-nouveau-tegra-gm20b-mc-client-reset.patch`.

  Test order: capture nouveau's init log on direct-v4 (`modprobe nouveau` by hand), then v3a, then v3b with the patched `nouveau.ko`. Each test runs in slot B through `reboot --reboot-argument=recovery`.
- **PMIC watchdog in normal mode.** This is verified by the first boot from LNX after the carrier retirement. The loader and `shield-direct-pmic.service` disable it and keep kicking it.
- **Rescue sshd** runs the root's sshd in a chroot with PAM on. A static dropbear would make rescue independent of the root.
