# nouveau on the direct boot path: SMMU handoff analysis and fix plan

Date 2026-11-03. Scope: why nouveau (GM20B) faults when the shim boots the 7.1.0-shield-bringup kernel straight from cboot, while the same kernel/DTB/cmdline works after the Lineage 4.9 kexec. Confidence marks: [H] measured on hardware or read in the exact source, [M] inferred from code with one unverified assumption, [L] hypothesis.

Kernel tree used for all file:line references: `$BUILD/public-kernel-closure-2026-10-16/sources/kernel-9336ceeebe1d75021d9fd98c94abaec522ba39b3` (patch series 0001-0018 applied). Live reads were taken on the running direct path (nouveau blacklisted) with busybox devmem copied to `/tmp/busybox` on the device.

## 1. What the 0004/0010 patches do, and why they are not the differentiator

`tegra_smmu.reset_inherited=1` (0004) runs `tegra_smmu_reset_handoff()` from `tegra_smmu_probe()` before PTC/TLB setup (`drivers/iommu/tegra-smmu.c:1190-1310`, call at `:1352`). It requires the A04 machine compatible and T210 MC (`:1207-1210`), then for each of the 39 SWGROUP registers clears `ASID_ENABLE`, reads back and panics if the bit stays set (`:1292-1303`). `quarantine_gpub_inherited=1` (0010) additionally reserves ASID 0, selects PTB 0 and writes `PTB_DATA=0` (no permission, no page directory) (`:1255-1268`), then writes 0 to GPUB (0xaac) and accepts a readback of `0x80000000` because bit 31 cannot be cleared on this board (`:1274-1289`). Later, GPU attach writes `ENABLE | asid` into selector byte 0 only, leaving the three upper selectors (GPU address bits 33:32 != 0) on denied ASID 0, and nouveau's instance allocator is clamped to the 4 GiB SMMU aperture (`drivers/gpu/drm/nouveau/nvkm/engine/device/tegra.c:139-205`, log line "IOMMU address limit 0x100000000 bytes").

Measured state after the handoff on both paths [H]:

| | old path (4.9 kexec) | direct path (cboot -> shim) |
|---|---|---|
| GPUB before -> after | `0x8c0b0a09 -> 0x80000000` (`first-ram-probe-2026-10-15/hyprland-v45/v45-console.bin`) | `0x80000000 -> 0x80000000` (journal, boot of 2026-11-03) |
| inherited SWGROUPs disabled | 21 | 0 |
| PTB 0 | denied (`PTB_DATA=0`) | denied; live `MC+0x1c=2`, `MC+0x20=0xE008043F` (last selected ASID 2 = dc) |
| GPU default domain | identity (`tegra_smmu_def_domain_type`, `:1067-1075`) | identity (`/sys/kernel/iommu_groups/1/type`) |
| debugfs `smmu/swgroups` gpu | n/a | `yes 0x00` (enable bit stuck, selectors 0) |
| TRANSLATION_ENABLE_0..3, 0xb98 | n/a | all `0xFFFFFFFF` (all GPU clients translate) |

Conclusion [H]: the inherited-state code reaches the identical end state on a fresh cboot (nothing to clear, quarantine verified, PTB 0 denied). It neither does the wrong thing nor nothing harmful. Dropping the flags would not help: with `reset_inherited=1` alone the sticky GPUB bit 31 panics the kernel (`:1301`), and with both dropped ASID 0 stays allocatable while GPUB's upper selectors still point at it. Keep the cmdline as is.

Why the GPU still "reads address 0": the first latched MC error in the crash log is a plain `gpusrd` read of physical 0 with type 2 "EMEM decode error" (`loader/pstore-direct-crash.txt:84`; decoder `drivers/memory/tegra/mc.c:640-760`), i.e. a GPU-originated, untranslated (bit 34 clear) fetch of address 0, followed by a page-fault interrupt on the same client (`:85`) and PBDMA `SIGNATURE` errors with data `0xffffffff` (`:86`, bus-error fill). That pattern means the GPU consumed zero/garbage pointers from its own instance memory, then wedged: `gf100_ltc_flush` timeout at 41 s (`:304-311`) and an asynchronous SError on a GPU register read at 84 s (`:460-470`). It is a GPU power/bring-up symptom, not an SMMU programming symptom [M].

## 2. Hardware state that actually differs between the paths

Both runs use the same kernel, DTB, modules, root and cmdline, so only bootloader-inherited hardware state can differ. Verified facts on the direct path:

1. GPU rail: `VDD_GPU` is a pwm-regulator on PWM1 (`dtb/v2.dts:4329-4340`). Live: regulator `disabled`, 710 mV reported, `PWM_CSR_1 (0x7000a010) = 0x00000000`, MAX77620 gpio-6 (`enable`) `out lo`. Stock 4.9 sets `regulator-init-microvolt = <1000000>` (`a04-source-review-2026-10-15/stock-a04.dts:10278-10293`, dmesg `v45-preflight-dmesg.txt:396-397` "vdd-gpu ... at 1002 mV"). Mainline code analysis says the two paths should still end up equal: `pwm_regulator_probe` drives the enable GPIO low (`drivers/regulator/pwm-regulator.c:396-397`), and nouveau's `regulator_enable` -> `pwm_enable` rewrites duty 0 (`pwm-regulator.c:115-121`, `drivers/pwm/pwm-tegra.c:240-269`, `:94-200`), so both paths would run the GPU at 710 mV, below the GM20B DVFS floor (~814 mV at 76.8 MHz, `nvkm/subdev/volt/gm20b.c:44-48`). This is marginal in both cases; whether the old path really sits at duty 0 is checkable (read list below) [M].
2. MC client hot-reset: `MC_CLIENT_HOTRESET_CTRL_1 (0x970) = 0`, `STATUS_1 (0x974) = 0x164` -> GPU (bit 2), NVDEC, APE, NVJPG flushed with no software request; `0x204 = 0x002E0908` similarly for DCB/ISP2/NVENC/VI/VIC/XUSB_HOST/A9AVP. Mainline only requests VI and XUSB_HOST (`0x200 = 0x000A0000`); the rest is cboot/TOS power-gating state. Stock nvgpu pulses the GPU MC flush (client 34) after every unrailgate; nouveau never touches the MC reset (`nvgpu-analysis-2026-10-16/GPU-PARITY-FINDINGS.md`, GPU-D01; `tegra.c:31-66`). Whether STATUS=1 here means "blocked" or merely "partition off" is open [L-M].
3. Clocks/memory: `gpu` CAR gate on, GPU not in CAR reset (`CLK_OUT_ENB_X=0x23800780`, `RST_DEVICES_X=0x20004434`), `emc 800 MHz`, `mc 200 MHz`, GPU LA `0x3ac = 0x00FF0032`. Old-path values unknown (4.9 EMC DVFS with `emc_max_dvfs=1`) [M].
4. PMC (clamps `GPU_RG_CNTRL 0x2d4`, `PWRGATE_STATUS`) is TZ-only: EL1 reads return 0 (`0x7000e438/0x7000e6d4 -> 0`). Nouveau removes clamps via SMC (`drivers/soc/tegra/pmc.c:760-775`); display power gating via the same SMC path works, so the call itself is unlikely to be refused [M].
5. Unchanged between paths [H]: memory map (3 GiB incl. the bank above 4 GiB), security carveouts (`0xc08..0xd54` locked by cboot), VPR (`0x648/0x64c = 0`, legacy reservation only), MAX77620 pinmux (gpio5/6/7 push-pull GPIO, `v2.dts:2416-2420`), nouveau firmware (`/usr/lib/firmware/nvidia/gm20b/{acr,gr,pmu}`).

The `WARNING: iommu.c:654` at ~7 s is `sdhci-tegra 700b0600.mmc: late IOMMU probe at driver bind` (journal), identical on both paths and unrelated.

## 3. Root cause statement

[H] The SMMU inherited-state handling is not what breaks nouveau on the direct path; its end state is identical to the working path and the live registers confirm it.
[M] The failure is in GPU power/bring-up state inherited from cboot that the 4.9 kernel normally normalises before kexec. The two concrete candidates, in order: (a) GPU memory-client hot-reset/flush state left by cboot/TOS power-gating, which nouveau never releases (stock does); (b) GPU rail voltage/PWM duty (710 mV vs stock 1.0 V). (c) EMC/MC rate and latency allowance is a weaker third candidate. The direct-path nouveau init log was lost (ramoops console window starts at 32 s), so the first test below must capture it.

## 4. Fix candidates (prepared, not deployed)

All files in `team-2026-11-03/gpu-direct-fix/`. DTBs are byte-minimal `fdtput` edits of `dtb/board.v2.dtb` (sha `c0fef725...`); `dtc -I dtb -O dts` diffs show only the listed properties.

- `board.v3a-vddgpu-1v0.dtb` (`d83a2144...`): `regulator-vdd-gpu` becomes a one-entry voltage table, `min=max=1000000`, `voltage-table = <1000000 48>` (48 % of 8000 ns -> 123/256 ticks -> ~1.003 V, matching stock's 1002 mV). The regulator core applies it at probe (`drivers/regulator/core.c:1225-1240`, table ops `pwm-regulator.c:56-110`), so nouveau's `regulator_enable` turns the rail on at 1.0 V. DVFS above 1.0 V is refused (`regulator_set_voltage` -EINVAL) until a real table is added; nouveau never changes pstate on its own (`nvkm/subdev/clk/base.c:590-630`, Tegra returns from `func->init`). No kernel rebuild.
- `board.v3c-mcreset-only.dtb` (`695e4478...`): gpu node `resets = <&tegra_car 184>, <&mc TEGRA210_MC_RESET_GPU(22)>; reset-names = "gpu", "mc"` (`include/dt-bindings/memory/tegra210-mc.h:69`, `drivers/memory/tegra/tegra210.c:1271`). Harmless without the module patch (the name lookup is optional).
- `0019-nouveau-tegra-gm20b-mc-client-reset.patch`: nouveau acquires the optional `mc` reset and mirrors stock: assert (block + wait idle, `mc.c:234-292`) then deassert after CAR reset release in `nvkm_device_tegra_power_up`, assert before clocks drop in `power_down`. Applies cleanly to the tree (`patch -p1 --dry-run`). Only `nouveau.ko` changes: rebuild incrementally in `kernel-out-9336ceee...-omarchy-a04` (`ports/shield/build-kernel.sh`, cached tree, `SHIELD_BUILD_MODULES=1`), install the single module (vermagic `7.1.0-shield-bringup` matches, as the overlay module did).
- `board.v3b-vddgpu-mcreset.dtb` (`17ccbc3e...`): both DT changes.
- Shim-side register poking is not recommended: PMC is TZ-only and the regulator GPIO lives on the PMIC, so the shim cannot set the rail; the MC flush pulse is better owned by the driver.

Repack for a test: `python3 shim/pack-shim.py shim/shim.bin <Image> <dtb> shim-kernel.bin && gzip -9` then `loader/pack-boot-v2.py` and write SOS from Linux (`carrier/write-sos-any.sh` pattern), exactly as direct-v4 was produced.

## 5. Safe test plan for the main session

Every step is on SOS (`reboot recovery`); a panic (`panic=10`) or the shim-armed WDT returns the board to LNX = old path. Nouveau stays blacklisted on the cmdline; load it by hand so the log can be captured first.

T0, old path (no risk, read-only): run the register list in section 6 and save it next to this file. Decisive items: `0x7000a010` (duty with the GPU running), `MC+0x974 bit 2`, `MC+0x970`, EMC/MC rates.

T1, direct path, baseline with full log: boot current direct-v4. On the host: `ssh ... 'dmesg -w' > direct-nouveau-T1.log &` plus `journalctl -k -f` in a second session; then on the board `modprobe nouveau`. Expected crash within ~60 s and auto-reboot to the old path. This recovers the lost init log (ACR/WPR, `IOMMU address limit`, first MC error). Abort criteria: none needed; the watchdog covers a hang.

T2, direct path with `board.v3a` (voltage only): repack, write SOS, `reboot recovery`, repeat T1's capture and `modprobe nouveau`. Before loading, verify `fdtget /sys/firmware/devicetree/base/regulator-vdd-gpu regulator-min-microvolt` = 1000000 and `cat /sys/class/regulator/*/microvolts` for VDD_GPU = 1000000. Pass: `drm: VRAM/GART`, no `tegra-mc` errors in 10 min, `glxinfo`/Hyprland render. Fail: same crash signature -> voltage excluded.

T3, direct path with `board.v3c` + patched `nouveau.ko` (MC reset only; or `v3b` if T2 passed and you want both): same procedure. Check `dmesg | grep -i "MC client flush"` is absent (no warning) and `MC+0x970/0x974 bit 2` read 0 with the GPU active.

T4 (only if T1-T3 all fail): compare the T1 log and the T0 snapshot for EMC rate / LA differences and decide on an EMC rate test; do not change MC timing registers blind.

Rollback for each: SOS <- `loader/direct-v4.img` (sha in ledger), or simply let the WDT fall back to LNX.

## 6. Old-path read list (read-only; run with the busybox already at `/tmp/busybox` or copy it)

```
B="/tmp/busybox devmem"
for off in 0x10 0x14 0x18 0x1c 0x20 0x228 0x22c 0x230 0x234 0x238 0xb98 0x9e0 0x9e4 0x9e8 0x9ec 0x9f0 0x9f4 0x9f8 0x9fc 0xa00 0xaa8 0xaac 0x200 0x204 0x970 0x974 0x3ac 0x3b4 0x50 0x54 0x90 0x94 0x98 0x9c 0x648 0x64c 0x650 0xc58 0xc5c 0xc64; do printf "MC+%s=%s\n" $off "$($B $((0x70019000+off)) 32)"; done
for a in 0x7000a000 0x7000a010 0x7000a030 0x60006010 0x60006028 0x60006110 0x6000619c 0x60006280; do printf "%s=%s\n" $a "$($B $a 32)"; done
cat /sys/kernel/debug/smmu/swgroups; cat /sys/kernel/debug/pwm; grep -E "VDD_GPU" -A1 /sys/kernel/debug/regulator/regulator_summary
grep -E "gpio-6 |max77620" /sys/kernel/debug/gpio; grep -E "^ *(gpu|emc|mc|pwm|pllg_ref) " /sys/kernel/debug/clk/clk_summary
cat /sys/kernel/iommu_groups/1/type; dmesg | grep -E "nouveau|GPUB|SHIELD_PTB|SHIELD_MC_CONFIG|tegra-mc" | head -40
```
Expected if the voltage hypothesis holds: `0x7000a010` shows duty 0x7b (`0x807B....`) on the old path; if it shows `0x8000....`, voltage is excluded and the MC/power sequencing candidates remain.

Not done here: no kernel build, no deployment, no device writes other than `/tmp/busybox`.
