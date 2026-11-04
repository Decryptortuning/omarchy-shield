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

## Follow-up (2026-11-04, after tests T2/T3 and the MC hot-reset probe)

Inputs: `loader/gpu-t2-dmesg.log` (v3a, VDD_GPU table pinned 1.0 V: nouveau up, 3 min idle, no MC error; `clk: failed to raise voltage: -1 / error setting pstate 12` every few seconds), `loader/gpu-t3-dmesg.log` (v3d: `regulator-min-microvolt=1000000`, max 1320000, continuous, no `voltage-table`/`pwm-dutycycle-range`; Hyprland submitted work, `HCE_ILLEGAL_MTHD` 40.78 s, `MEMACK_TIMEOUT` 42.45 s, `gf100_ltc_flush` timeout 44 s, reboot; no MC decode error), and the live MC pulse (0x970 bit 2 assert/release leaves 0x974 at 0x164).

### Re-ranking

1. GPU rail voltage is the lever, and T3 was defeated by the DT mapping, not by new hardware [H for the mapping, M for the overall cause]. pwm-regulator continuous mode maps duty 0 % to `regulator-min-microvolt` and 100 % to `regulator-max-microvolt` (`drivers/regulator/pwm-regulator.c:145-262`); the board's hardware mapping is 0 % = 710 mV, 100 % = 1320 mV (stock `regulator-n-voltages=62`, 10 mV steps, `stock-a04.dts:10278-10293`). With v3d the kernel believed 1.0 V while the PWM sat at duty 0 = 710 mV on enable, and every devfreq-driven `regulator_set_voltage(X)` produced actual = 710 + (X-1.0)/0.32*610 mV, i.e. ~0.71-0.9 V while the GPC clock was raised to pstate 12 (998.4 MHz). nouveau's CVB table for this board (speedo 2048, vmin 840 mV, `nvkm/subdev/volt/gm20b.c:44-66`) needs 1.095 V at pstate 12 (computed per `gk20a_volt_calc_voltage`, `volt/gk20a.c:46-90`: pstates 0-5 840 mV, 7 886, 9 970, 11 1053, 12 1095). An under-volted GPU at 1 GHz corrupting its own pushbuffer fetch explains `HCE_ILLEGAL_MTHD` -> `MEMACK_TIMEOUT` -> L2 flush timeout with no MC error. T2 differs only in holding the rail at a true 1.0 V (and being stuck at 76.8 MHz because the 1.0 V constraint refuses pstate 12's 1.095 V). T1 (v2, correct mapping, but 710 mV during nouveau init: ACR/PMU/GR bring-up) is consistent with the same lever.
2. Devfreq policy: `gk20a_devfreq.c` polls every 50 ms with upthreshold 45 and asked for pstate 12 even on an idle desktop (T2 log), so any voltage path error is hit within seconds [H].
3. Demoted: MC GPU client hot-reset (status bit is an idle/flush-done indicator, unaffected by the pulse; the GPU initialised and ran in T2/T3) [H]; PMC clamps (GPU registers and DMA worked for minutes in T2, so `tegra_powergate_remove_clamping` via SMC took effect) [M]; EMC 800 MHz / MC 200 MHz / LA (no MC error or starvation signature in T3; revisit only if v3e fails under load) [M]; GPCPLL state (nouveau reprograms it in `gm20b_clk_init`) [H]; missing nvgpu-style init (same code renders on the old path) [H].

### Next single test: v3e, VDD_GPU pinned at the pstate-12 voltage

`gpu-direct-fix/board.v3e-vddgpu-1v095.dtb` (sha `c7922618...`): `regulator-vdd-gpu` with `regulator-min-microvolt = regulator-max-microvolt = 1095000`, `voltage-table = <1095000 63>` (63 % -> 161/256 ticks -> ~1.094 V actual, within stock nominal 1110 mV). Only those three properties differ from board.v2.dtb. Why this value: the regulator core applies it at probe (`core.c:1225-1240`), `gk20a_volt_vid_get` resolves 1.095 V to vid 12 (`volt/gk20a.c:93-106`; a value above 1.095 V returns -EINVAL and corrupts `gm20b_clk_init`'s DVFS seed), and every `nvkm_volt_set_id` request `[vid.uv, 1.2 V]` overlaps the constraint, so devfreq can run the full 76.8-998.4 MHz range at a fixed, sufficient voltage with no `failed to raise voltage` spam. Procedure as T2/T3 with log capture; before `modprobe nouveau` confirm `cat /sys/class/regulator/*/microvolts` shows 1095000 for VDD_GPU and `/sys/kernel/debug/pwm` shows pwm-1 duty 5040/8000 after the rail enables. Pass: Hyprland renders and `dmesg` stays clean for 10 min under window moves/glmark-style load; `cat /sys/kernel/debug/dri/*/pstate` may show the active pstate. Fail: the voltage lever is exhausted and the EMC/LA candidate moves up (then collect `MC+0x970/0x974/0x200/0x204`, `MC_INTSTATUS 0x00`, `MC_ERR_STATUS 0x08`, `MC_ERR_ADR 0x0c` immediately after the first error, plus `clk_summary` emc/mc).

Optional read-only add-on for the same run: `/tmp/busybox devmem 0x7000a010` before and after `modprobe nouveau` (expect `0x8000_00xx` -> `0x80A1_00xx`-style with duty 161 in bits 30:16).

### Should v3d stay as the base?

No. v3d is wrong on its own terms: it rewrites the hardware duty/voltage mapping, so every voltage the kernel sets is ~300 mV low, and it still enables the rail at 710 mV. Use v3e as the interim base (fixed 1.095 V, full clocks). v3a (1.0 V) is the fallback if v3e fails. The durable fix is kernel-side, not DT: keep the hardware-true `710000..1320000` continuous regulator (as board.v2) and make nouveau raise the rail to the lowest-pstate voltage before it touches the GPU (`nvkm_device_tegra_power_up` before/after `regulator_enable`, or in `gm20b_clk_init` from `volt->vid[0].uv`), which restores real DVFS and a 840 mV idle. That patch is a few lines in `nvkm/engine/device/tegra.c` and only changes `nouveau.ko`; write it after v3e proves the GPU is stable at the correct voltage. The 0019 MC-reset patch stays optional and is no longer motivated by evidence.

Old-path comparison reads are not needed for this decision; do not warm-reboot into the old path for them.

## Follow-up 2 (2026-11-04, after T4: v3e, 1.095 V, CTXSW_TIMEOUT)

Inputs: `loader/gpu-t4-dmesg.log`; live reads on the running T4 board (nouveau loaded, uptime 13 min): `/sys/kernel/debug/dri/1/pstate` shows pstates 01-0d (76-998 MHz) with the GPU sitting at 01 (76 MHz, `AC DC *`), DRM clients Hyprland x3 + Xwayland, `pll_p_out5` 204 MHz, `pllg_ref` on, `emc` 800 MHz, `mc` 200 MHz, GPU thermal 68 C; user journal: `owed ... renderer start failed` / `shell handoff failed` every ~30 s, matching the ~7 s `SCHED_ERROR 0a [CTXSW_TIMEOUT]` cadence.

### What the evidence excludes

- Secure boot / WPR / FECS+GPCCS load [H]: every failure in that path logs at error level and none appear: `WPR image too big` (`nvkm/subdev/acr/gm20b.c:40`), `WPR not configured as expected` (`acr/base.c:108`, compares `0x100cd4` WPR info with the located region), `ACR WPR init failure` (`pmu/gm20b.c:133`), `falcon cannot be bootstrapped` (`acr/base.c:277`), FECS start timeout (`gr/gf100.c:1793-1797`, returns -EBUSY -> gr init fails loudly), and `failed to construct context` (`gr/gf100.c:445`) when the golden context cannot be generated on the first channel. The golden-context generation runs FECS methods, boots GPCCS and DMAs a full context image through the SMMU, so FECS, GPCCS, GPC clock, instmem and the MC path all worked at init. Carveout 2 (`0xFF300000`, 256 KiB) is identical to the earlier no-nouveau read and is bootloader-locked; cboot programs carveouts before choosing normal/recovery flow (same values both boots) [M].
- GPCPLL / NA DVFS [M-H]: lock/calibration failures log (`clk/gm20b.c:961,1032,1135,1290,1336`); the pinned 1.095 V cannot overclock the NA PLL because `dfs_det_max = 0` clamps positive voltage deltas (`clk/gm20b.c:200-220`); the GPU idles at 76 MHz where the CVB floor is 840 mV.
- GR clock/power gating (SLCG/BLCG/ELCG) [H]: nouveau never enables gating on GM20B (`NvPmEnableGating` default false, `therm/base.c:440`), and the CAR reset in `nvkm_device_tegra_power_up` resets all GPU-internal state, so no bootloader GPU state survives on either path.
- Voltage [H]: fixed by v3e (`PWM1 = 0x80A10000`, 1095000 uV); T4 ran 10 min without MC/PBDMA/SError.

### Re-ranked

1. GR work hangs at execution time (shader/raster work from Mesa), not at bring-up [H for the symptom]. Each hang produces `CTXSW_TIMEOUT`; the recovery (`fifo/gf100.c:618-642`) triggers an MMU fault on the engine and nothing is logged afterwards (no `fault`, no `channel killed`), i.e. GR does not even answer the forced fault. The 7 s cadence is owed/Hyprland retrying the renderer.
2. External memory path under GR load [M]: the only state that is not reset by nouveau and differs from the 4.9 path is EMC/MC: direct = cboot BCT (EMC 800 MHz, MC 200 MHz, LA `0x3ac=0x00FF0032`, arbitration `0x90..0x9c`), old = 4.9 EMC DVFS at `emc_max_dvfs=1` with its LA/PTSA programming. FECS/golden-ctx traffic is light; SM/ROP traffic is not. T3's `MEMACK_TIMEOUT` (a host write never acknowledged by the MC) fits a memory-path stall better than a voltage glitch in hindsight.
3. GPU bypass (bit 34 clear) accesses to physical RAM above 4 GiB [L-M]: Mesa BOs are mapped by physical address (identity default domain, 40-bit DMA mask, `mmu/gm20b.c:31`), instmem goes through the SMMU (< 4 GiB). Same on the old path, so only placement luck would differ; cheap to exclude with `mem=2G`.
4. PMC clamps / TZ [L]: GPU registers, DMA and FECS all work; `tegra_powergate_remove_clamping` evidently took effect.
5. ACR/WPR, FECS/GPCCS, SLCG/BLCG/ELCG, GPCPLL: excluded above.

### Next single remote test (slot B, reversible, watchdog-covered)

Reload nouveau with debug output and take a read-only GR snapshot while the hang is present:

1. `rmmod nouveau` is unsafe with clients attached; instead reboot slot B as is, then before anything opens the render node: `modprobe nouveau debug="fifo=trace,gr=debug,acr=debug,pmu=debug,clk=debug,volt=debug,mmu=debug"` with `dmesg -w` captured on the host. `fifo=trace` prints the ENGN status at each timeout (`busy/faulted/chsw/save/load prev->next ids`, `fifo/gk104.c:206-240`), `gr=debug` prints FECS method results, `acr=debug` prints `WPR region is from ...` and LSF bootstrap, `clk=debug` prints PLL/DVFS values.
2. Let owed/Hyprland trigger the hang (or run `glmark2-es2-wayland`/`kmscube` on renderD129), then read, with the GPU powered (nouveau loaded; no runtime PM on this platform), BAR0 = `0x57000000` + offset:
   `0x002640` (GR engine status), `0x002648` (CE), `0x00254c` (sched error), `0x002100` (fifo intr), `0x002a30`, `0x400700/0x400704/0x400708/0x40070c` (FE status/method), `0x400500`, `0x400100`, `0x400108`, `0x400118`, `0x409800/0x409804/0x409814/0x409c18` (FECS mailbox/err/intr), `0x409100/0x40910c` (FECS CPUCTL), `0x41a800/0x41a100/0x41a10c` (GPCCS), `0x137000/0x137004/0x137008/0x13700c/0x137010/0x137014/0x137250/0x137340` (GPCPLL CFG/COEFF/CFG2/CFG3/DVFS0/DVFS1/GPC2CLK_OUT/BYPASSCTRL), `0x020160` (idle slowdown), and MC `0x70019000+{0x00,0x08,0x0c,0x970,0x974}`. Reads only; PRI reads of a halted unit at worst log a privring error.
3. Pass/fail: if GR status shows `busy` with `chsw` stuck and FECS mailbox/CPUCTL frozen while the GPCPLL is locked at the expected N/M/P, the hang is downstream of FECS (memory path) and the EMC comparison becomes the next step. If `0x409c18`/`0x409814` carry a FECS error code, that is a firmware/context problem instead.

Cheap add-on for the same boot (no reflash): `mem=2G` in the direct cmdline excludes candidate 3 in one run. Do not combine it with other changes.

### Old-path reads (decisive only for candidate 2; need the owner's cold power cycle)

Minimal set, with nouveau working: `grep -E "^ *(emc|mc|gpu|pll_p_out5) " /sys/kernel/debug/clk/clk_summary`; `devmem` MC `0x70019000+{0x50,0x54,0x90,0x94,0x98,0x9c,0xa0..0xdc step 4,0x3ac,0x3b4,0x648,0x64c,0x970,0x974,0xaa8}`; EMC `0x7001b000+{0x00,0x08,0x0c,0x10}`; `cat /sys/kernel/debug/dri/*/pstate`. The GR register snapshot from step 2 taken on the old path at idle is a useful baseline but not decisive; skip it unless the board is already up.

## Follow-up 3 (2026-11-04, after T5 debug run): root cause found - bootloader pinmux

### What T5 shows

`loader/gpu-t5-dmesg.log`: ACR/PMU/FECS/GPCCS all load and run (WPR = carveout 2 at `0xFF300000`, `ACR WPR init complete`, FECS/GPCCS acquired, golden context generated on channel 2 at 31.2 s, channels 2-6 created, GR working at 76.8 MHz for 15 s). At 45.82 s devfreq raises the GPC clock to pstate 12 (998.4 MHz) for the first time; at 46.46 s a **genuine** hardware MMU fault follows (`gf100_engn_mmu_fault_triggered` read `0x002a30 = 0`, so it was not the software-forced fault; `fifo/gf100.c:202-215`): `fault 01 [WRITE] at 0 engine gr client HUB/FE reason PTE` on Hyprland's channel 4, i.e. the GR front end executed garbage. Then the context switch sticks (`8005e004 ... save 1 load 1 chid 4 -> 5`), FECS stops answering (`gf100_gr_fecs_ctrl_ctxsw` timeout), GR reset fails, LTC flush times out, SError. T4's steady `CTXSW_TIMEOUT` is the same wedge seen without debug. Conclusion [H]: the GPU is fine at 76.8 MHz and dies within a second at 998.4 MHz. Not a memory-path stall, not >4 GiB placement, not secure boot.

### Why: the GPU rail and the fan are not wired on the direct path

Live reads on the running direct-path board (nouveau not loaded, 8 min uptime), `/tmp/busybox devmem`:

| pad (register) | live value | meaning | needed |
|---|---|---|---|
| `LCD_GPIO2_PV4` = GPU VID PWM1 (`0x7000320c`) | `0x00000000` | function 0 = DISPLAYB, not PWM1 | `0x1` (PWM1) |
| `PE7` = fan PWM3 (`0x7000324c`) | `0x00000000` | function 0 = RSVD0, not PWM3 | `0x2` (PWM3) |
| `PWM_CSR_1` (`0x7000a010`) | `0` | GPU PWM idle (regulator off) | |
| fan tach `/sys/class/hwmon/hwmon1/fan1_input` | 0 rpm | fan stopped, pwm1=255 requested | |
| thermal zones | CPU 85.5 C, GPU 83 C, diode 86 C at idle | old path idle ~41 C (ledger/uptime-watch) | |

Function indices from `drivers/pinctrl/tegra/pinctrl-tegra210.c:1593,1609` (`lcd_gpio2_pv4: DISPLAYB, PWM1, RSVD2, SOR1`; `pe7: RSVD0, I2S5A, PWM3, RSVD3`; mux bits [1:0], tristate bit 4, e_input bit 6, `:1388-1396`).

The board DTB has a complete pinmux table (`/pinmux@700008d4`, `v2.dts:641-709`, including `pe7 -> pwm3` and `lcd_gpio2_pv4 -> pwm1` at `v2.dts:1027-1034,1670`), but it is named `pinctrl-names = "boot"`, as in upstream `tegra210-p2894.dtsi:63-64`. The pinctrl core only applies hog states named `default`/`init` (`drivers/pinctrl/core.c:2179-2221`, `include/linux/pinctrl/pinctrl-state.h:33-34`), and `pinctrl-tegra.c` never selects "boot". Upstream therefore relies on the bootloader's pinmux. On the old path the 4.9 kernel programmed the full stock pinmux (169 groups, `stock-a04.dts:1948-1954,2026-2032`) and kexec preserved it; cboot's own pinmux leaves PV4 and PE7 at function 0.

Consequences, all consistent with every test so far [H]:
- The GPU buck never saw a PWM VID signal; the rail sat at the buck's no-signal level (~710 mV class) in T1-T5 regardless of the regulator DT. The VDD_GPU variants only changed what nouveau *believed* and therefore which pstates it allowed: v2/v3d/v3e let devfreq reach 998 MHz -> immediate corruption (T1 read @0, T3 MEMACK, T4/T5 fault); v3a pinned 1.0 V refused pstate 12 -> stuck at 76.8 MHz -> idle-stable (T2).
- The fan never ran on the direct path, hence the 40 C hotter board.
- The SMMU handoff flags, MC hot-reset, WPR/ACR, EMC rate, >4 GiB placement are all exonerated.

### Fix (no kernel rebuild)

`gpu-direct-fix/board.v4a-pinmux-default.dtb` (sha `3eb5a52d...`): board.v2.dtb with the single change `/pinmux@700008d4/pinctrl-names = "default"` (verified: the hog state still maps `lcd_gpio2_pv4 -> pwm1`, `pe7 -> pwm3`). The pinctrl core then applies the full table at pinmux probe, before pwm-fan and pwm-regulator bind. The regulator stays hardware-true (`710000..1320000`, continuous) exactly as on the old path, so nouveau's DVFS raises the real voltage with the clock. This is the closest equivalent of the old path and is the recommended base. `board.v4b-pinmux-default-vddgpu-1v095.dtb` (sha `da963673...`) is the same plus the 1.095 V pin, as a conservative fallback if real DVFS misbehaves. Do not keep v3d/v3e alone: without the pinmux they are inert.

Repack as before (`shim/pack-shim.py shim.bin Image board.v4a-pinmux-default.dtb` -> gzip -> `loader/pack-boot-v2.py` -> SOS), reboot recovery.

### Immediate live confirmation before reflashing (owner-side writes, 1 minute, reversible by reboot)

```
/tmp/busybox devmem 0x7000324c 32 0x2      # PE7 -> PWM3 (fan), output, no tristate
sleep 5; cat /sys/class/hwmon/hwmon1/fan1_input; for z in /sys/class/thermal/thermal_zone*; do cat $z/temp; done   # expect rpm > 0 and temps falling
/tmp/busybox devmem 0x7000320c 32 0x1      # PV4 -> PWM1 (GPU VID); harmless now: regulator disabled, PWM1 idle
```
The fan read-back alone proves the pinmux theory. Then the GPU test on this same boot (board.v2.dtb, hardware-true regulator): wait for temps < 55 C, `modprobe nouveau` with `dmesg -w` captured, let Hyprland run 10 min; expect `/sys/kernel/debug/dri/1/pstate` to reach 0d and `/sys/class/regulator/*/microvolts` for VDD_GPU to follow (840000..1095000). Watchdog/panic still cover a failure.

### Test plan after the DT fix

T6: boot v4a. Before nouveau: `devmem 0x7000320c` = `0x1`, `devmem 0x7000324c` = `0x2`, fan rpm > 0, idle temps ~40-50 C. Then nouveau as above. Pass = Hyprland renders, DVFS cycles, no fault 10 min. Fail -> use v4b and compare.

### Old-path reads
None needed; the live pinmux registers are decisive. (If the owner is on the old path anyway: `devmem 0x7000320c` and `0x7000324c`, expected `0x1` and `0x2`.)
