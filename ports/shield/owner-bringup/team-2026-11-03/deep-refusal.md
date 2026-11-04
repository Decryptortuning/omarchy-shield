# Deep refusal analysis: carrier v8 lands in recovery (2026-11-03, read-only)

Evidence: `carrier/src/*`, `build/v8/owner-internal-profile.c`, the v8/v10 ramdisks (via
`package-carrier.py`), `fastboot/APP.v8.img` (debugfs), the recovery kernel IKCONFIG, the ramdisk
`sepolicy` (setools), stock cboot `EBT` (objdump), and the 10-15/10-16 captures.
H = read in code/data, M = inference, L = guess.

## 1. Refusal points, in order, and whether each can fire now

### 1.1 Which kernel route is running at all (H, new)

cboot (`EBT` 0x92c048a8-0x92c04954) reads 0x440 bytes of `MSC`, sets w19 = (command ==
"boot-recovery"), and at 0x92c045fc-0x92c04624 boots **SOS** (mode 1) when PMC flag 0x1f is set
**or** w19 == 1; otherwise LNX. Since 19:28Z SOS **is also carrier v8**. In SOS cboot appends
`android.kerneltype=recovery post_recovery` (string 0x60a5b; seen in both 10-15 and 10-16 SOS
captures), so the stage refuses at `owner-internal-stage.c:33` (`normal-LNX-only`). This
refusal is *pre-RAM*: `die()` only writes kmsg (`stage-primitives.inc:44-54,73`), no
`stage-failed` file, then exits. The screen is identical to an LNX refusal.

Can it fire now? Only if MSC holds `boot-recovery` or the PMC recovery flag is set. The Lineage
recovery binary does **not** leave `boot-recovery` behind (10-16 `msc-info.txt` shows MSC all
zero while recovery ran; the owner's `recovery-return.py` had to write it explicitly), and
Linux never ran today, so `RebootArgument=recovery` (`owner_profile.py:221`) is not the source.
Verdict: possible but not expected (M). It is cheap to exclude: cboot `fastboot getvar` cannot
read MSC, but the recovery log block (`bootreason=` line plus dmesg `INTERNAL_STAGE_REFUSED
stage=normal-LNX-only`) distinguishes it.

### 1.2 Identity (`owner-internal-stage.c:24-61`)

| Check | Line | Now? |
|---|---|---|
| uid 0, kernel release, ppid 1, `u:r:recovery:s0`, compatible | 19-28 | no, same kernel/ramdisk base |
| exactly one `android.kerneltype=normal` | 33,39 | **yes in SOS route** (1.1) |
| profile constants, fds 0-2, pgrp/sid/tty, exclusive `/tmp/shield-internal`, pinned tools | 40-57 | no, passed 11-02 with identical records |
| **bootreason policy** | 60 | see below |

**Bootreason mapping (H, from cboot 0x92c06f3c-0x92c0715c).** cboot reads `/chosen/reset/
pmc_reset_status` and `pmic_reset_status`. PMC: 0 → `cold`, 1 → `watchdog`, 2 (sensor) →
`shutdown`, 3 (SW_MAIN) → `warm`, other → `unknown`. PMIC byte then overrides/composes:
2 → `watchdog`, 8 → `warm`, 4 → `shutdown,temperature`, 6 → `shutdown,overvoltage`,
7 → `shutdown,undervoltage` (only when PMC != 0), 5 → `shutdown,battery_low`; a panic flag
(bit 24 of PMC scratch 0x130) with PMC != 0 → `kernel_panic`.
- `fastboot reboot` is a software reset → PMC 3 → `warm` (allowed). Confirmed by the 10-16
  capture: fastboot flash then reboot gave `bootreason=warm`, `TEGRA_RESET_LEVEL_WARM`
  (`desktop-ready-2026-10-16/primary-recovery/dmesg.txt:36,190`). 89 of 100 logged reasons are `warm`.
- Cold power-on → `cold`, or `shutdown,battery_low` when the PMIC latched LBT (ledger 00:47Z).
  Both allowed. `shutdown,undervoltage` or `unknown` would refuse; not expected from a clean
  power cycle (M).
- After a hardware watchdog reset → `watchdog`, allowed here but refused later by the claim
  (1.6) unless `watchdog-retry` exists.
Verdict: bootreason does not refuse a fastboot reboot or a normal cold boot (M-H).

### 1.3 Disk admission (`:62-81`)

`fastboot flash boot/recovery/system` writes partition contents only; cboot's `flash:` resolves
names through the existing table and never rewrites the GPT. CID, capacity and rows are
hardware. Verdict: cannot fire (H).

### 1.4 Store and artifacts (`:83-109`)

debugfs on `APP.v8.img`: `/shield-owner` 40700 0:0, `enabled` 65 B 0600 = generation 3982163b,
`state` 40700, bootset dir 40700 with Image 45746688 / board.dtb 73816 / initramfs 33038386 /
cmdline 653, all 100600 nlink 1, matching `build/v8/owner-internal-profile.c:37-40`. Extra
entries (`enabled.*-disabled`, `*.bak`, `pending.failed-*`) are never opened. `APP-mountpoint-
unused` (`:87`) would fire if APP were already mounted; only `shield-diag.sh:15` mounts it and
only after the stage stopped. Verdict: cannot fire (H).

### 1.5 Memory admission (`stage-memory.inc`)

Live FDT, fbmem token, `dmesg` lines and `/proc/iomem`; DTB partition unchanged since 11-02 and
the v8 services write nothing to kmsg before the stage. Verdict: unchanged from the booting v2
(H). In the SOS route the FDT is the appended DTBO, but 1.1 fires first.

### 1.6 Claim (`owner-local-claim.c`)

With APP.v8 (healthy 9, no pending) the first claim succeeds and writes pending 10. Every later
boot refuses at `:87` (`unacknowledged-or-malformed-prior-attempt`) if that attempt was not
ACKed, and a `watchdog` boot refuses at `:98`. Both exit before the watchdog is taken, so the
stage exits and `shield_diag` runs. Verdict: fires on **every boot after the first** unless the
first boot kexec'd and Linux ACKed (H).

### 1.7 Post-claim: watchdog, hdcp-off, kexec load, segment check (`:118-127`)

After `owner_legacy_watchdog_take()` (`:118`) `wdt_taken=1`. From here any `need()` failure
ends in `for(;;)pause()` (`stage-primitives.inc:86`); `child()` with an unreaped child does
the same even earlier (`:139-141`). The stage never exits, `init.svc.shield_owner_internal`
stays `running`, **no diag service ever starts**, and the Tegra watchdog (SETTIMEOUT 240,
`internal-watchdog-owner.c:191,222`) resets the board within 240 s. hdcp-off output is
ignored (`:119`); kexec load must print 4 segments inside 0x80020000-0x91ffffff; the
segment check (`internal-segment-check.c`) is deterministic on the same Image/initrd. The only
delta from v2 is +195 KB of initrd. Verdict: unlikely, but if it fires it is invisible (M).

### 1.8 `internal-handoff.sh` guards (same hang semantics: `fatal` → `hold_watchdog`, `:60-78`)

| Guard | Lines | With PC cable on OTG, nothing in host port |
|---|---|---|
| runner identity, cgroup, fd9, `preflight` (kexec_loaded, DC, host1x, clients, GPU) | 231-271 | same as 11-02 |
| temperatures < 70 C | 145-157 | only if hot (L) |
| **USB root hubs only** | 188-193 | PC in device mode adds no `/sys/bus/usb/devices` entry: passes (H); a controller or stick refuses |
| usb-vbus2 `enabled:1`/`disabled:0` | 194-207 | host-only port, unchanged (H) |
| 25 s `DEADLINE`, service stops, `gadget_quiesce` | 276, 280-285, 109-134 | depend on init's `sys.usb.config=none` actions (init.rc:195-201); worked 11-02 |
| `storage_quiet` | 160-176 | nothing mounts rw before the stage |
| display off, host1x idle, xusb unbind, `kexec -e` | 290-315 | TV goes black here, which was **not** observed |

Observation constraint (H): the Lineage UI (`service recovery`) runs concurrently with the stage
and is killed only at `:280`, so a persistent menu means the stage stopped or hung **before**
line 280; hdcp-off (`:119`) cannot keep the menu up.

### 1.9 Ranking for "fastboot reboot → menu; cold cycle → menu"

1. First boot after 19:28Z claimed pending 10 and hung or refused post-claim (1.7/1.8 before
   `:280`), watchdog reset ~4 min later (NVIDIA logo again), then every boot refuses at the
   claim (1.6). The owner's description fits if the 4-minute reboot went unnoticed (M).
2. SOS route via a stale `boot-recovery` in MSC or PMC recovery flag (1.1) (M-L).
3. First boot kexec'd but Linux never showed text: contradicts `console=tty0` (L).

The recovery log ("Advanced → View logs" shows `/tmp/recovery.log`) decides: a `SHIELD CARRIER
DIAGNOSTIC` block with `pending seq=10` → case 1; `bootreason=` and `stage=normal-LNX-only`
in the dmesg lines → case 2; no block at all → the stage is hanging post-claim in *this* boot,
or (less likely) the rc was not parsed.

## 2. Why the added services never showed anything

- **Parsing (H).** `init.rc:1` → `init.recovery.darcy.rc:20-23` → `/shield-owner-internal.rc`;
  appended sections are valid and the stage started through this chain on 11-02.
- **`on property:init.svc.shield_owner_internal=stopped` (H).** A `oneshot` service that exits
  is marked stopped and the trigger fires. It never fires when the stage parks in `pause()`
  (1.7/1.8): the property stays `running` until the hardware watchdog resets the board. The
  trigger also fires in the SOS route (the stage exits in milliseconds), so `shield_diag` would
  then have written the block after 15 s.
- **SELinux (H).** The recovery kernel boots enforcing (`audit ... enforcing=1`, 10-15 dmesg:762),
  `CONFIG_SECURITY_SELINUX_DEVELOP=y`, no `BOOTPARAM` (so `androidboot.selinux=permissive` in
  v9/v10 does nothing; only `ro.boot.selinux` for init, which honours it). But `seinfo
  --permissive` lists **recovery, su, backuptool**: everything labelled `u:r:recovery:s0` is
  permissive, so mount vfat, ifconfig, kmsg, fb0, LEDs and `setprop sys.powerctl`
  (`powerctl_prop` is also explicitly allowed) all work. Note init itself is enforcing:
  `write /sys/class/extcon/extcon3/state` from `init.recovery.darcy.rc:18` is denied
  (`sysfs_usb_convertible`, 10-15 dmesg:790), so Lineage's own USB-role write never lands.
- **Stick path cannot work (H).** `CONFIG_USB_STORAGE=m` and `lib/modules/` holds only exfat,
  hid-*, pwm_fan, therm_fan_est. No `sd*` node ever appears, so `shield-diag.sh:32-41` is a no-op.
- **Ethernet path (M).** Built-in drivers are AX8817X, AX88179_178A, CDC Ether, SMSC95XX;
  `CONFIG_USB_RTL8152` is not set. A Realtek adapter never enumerates a net device.
- **Watchdog (H).** Once taken, nobody feeds fd9 (`internal-handoff.sh:46-58`), so every
  post-claim stall ends in a reset ≤240 s later with `bootreason=watchdog`, whose claim is
  refused without a `watchdog-retry` record (`owner-local-claim.c:98`).

## 3. Beacon build

Goal: report the refusal class without logs, under the current sepolicy, without touching the
stage, profile or APP. All beacon code runs as `u:r:recovery:s0` (permissive) from a service
started `on boot`, polling `/tmp/shield-internal` (mode 0700, root-readable) and kmsg.

Channels, all verified available:
1. **Light bar LED**: `pwm-leds/lightbar`, label `led_lightbar` (live DTS 10917-10926),
   `CONFIG_LEDS_PWM=y` → `/sys/class/leds/led_lightbar/brightness`. Blink the class number.
2. **cboot outcome**: `setprop sys.powerctl reboot,bootloader` sets PMC flag 0x1e and cboot
   enters fastboot (USB gate bypassed by `/chosen/nvidia,fastboot_without_usb`); `shutdown`
   powers off; staying in recovery is the third outcome.
3. **Framebuffer** `/dev/graphics/fb0` (ueventd.rc:66, `CONFIG_FB_TEGRA=y`) after `stop
   recovery`, e.g. the `fbstatus` of `rescue-architecture.md` section 4. Optional.

Classes (poll every 2 s from boot+5 s, decide by boot+100 s, i.e. before the 240 s watchdog):

| Class | Evidence | LED | Outcome |
|---|---|---|---|
| 1 identity/pre-RAM | kmsg `INTERNAL_STAGE_REFUSED` and no `/tmp/shield-internal` | 1 blink | stay in recovery |
| 2 disk/APP/memory | `stage-failed` present, not a claim text | 2 blinks | stay |
| 3 claim refused | `stage-failed` contains `owned-child-terminal-failure` and `runtime-cmdline.txt` absent | 3 blinks | reboot to bootloader |
| 4 handoff abort | `WATCHDOG_ARMED` and `ABORT` present (`internal-handoff.sh:62`) | 4 blinks | reboot to bootloader after 20 s |
| 5 post-claim hang | `WATCHDOG_ARMED` present, no `ABORT`, no kexec by boot+100 s | 5 blinks | reboot to bootloader |
| 0 success | kexec happens; the beacon is killed with the kernel | - | Linux |

Files (new `carrier/diag/beacon.rc`, `carrier/diag/shield-beacon.sh`, and `repack-beacon.py` =
`repack-diag.py` with `SCRIPTS = {'system/bin/shield-beacon.sh': 'diag/shield-beacon.sh'}` and
`rcadd` read from `diag/beacon.rc`; everything else identical, so kernel, DTBO and all other
records stay byte-identical and the stage artifacts keep their pinned hashes):

```
# beacon.rc (appended to shield-owner-internal.rc)
service shield_beacon /system/bin/sh /system/bin/shield-beacon.sh
    disabled
    oneshot
    user root
    group root
    seclabel u:r:recovery:s0

on boot
    start shield_beacon
```

```sh
#!/system/bin/sh
# shield-beacon.sh: classify the carrier outcome, blink it, pick a cboot-visible outcome.
R=/tmp/shield-internal; L=/sys/class/leds/led_lightbar/brightness
k(){ echo "<3>shield-beacon: $*" > /dev/kmsg; echo "shield-beacon: $*" >> /tmp/recovery.log; }
blink(){ n=$1; i=0; while [ $i -lt 3 ]; do j=0; while [ $j -lt $n ]; do echo 255 > $L; sleep 0.3; echo 0 > $L; sleep 0.3; j=$((j+1)); done; sleep 1.5; i=$((i+1)); done; echo 255 > $L; }
class=0; t=0
while [ $t -lt 100 ]; do
  sleep 2; t=$((t+2))
  if [ -e $R/ABORT ]; then class=4; break; fi
  if [ -e $R/stage-failed ]; then
    case "$(cat $R/stage-failed)" in owned-child-terminal-failure) [ -e $R/runtime-cmdline.txt ] && class=2 || class=3 ;; *) class=2 ;; esac; break; fi
  if [ ! -d $R ] && dmesg | grep -q INTERNAL_STAGE_REFUSED; then class=1; break; fi
  if [ -e $R/WATCHDOG_ARMED ] && [ $t -ge 90 ]; then class=5; break; fi
done
k "class=$class bootreason=$(getprop ro.boot.bootreason) kerneltype=$(grep -o 'android.kerneltype=[a-z]*' /proc/cmdline) stage=$(cat $R/stage-failed 2>/dev/null) abort=$(cat $R/ABORT 2>/dev/null) t=$t"
[ $class = 0 ] && exit 0
blink $class
case $class in 3|4|5) sleep 20; k "rebooting to bootloader"; setprop sys.powerctl reboot,bootloader ;; esac
```

Notes: classes 1-2 keep the recovery UI (ADB/menu backstop); classes 3-5 show up in `fastboot
devices` within ~2 min after ~15 s of LED code. The kmsg line records `kerneltype=recovery` in
the SOS route. No stage artifact, profile or APP changes, so no pinned hash moves; flash it to
**both** LNX and SOS as v8 was.

## 4. Confidence summary

H: SOS/LNX both v8 and the SOS route refuses silently; cboot picks SOS on MSC `boot-recovery`
or PMC flag 0x1f; flashing leaves every hashed input intact; the PC cable passes the USB guards;
post-watchdog refusals never exit; recovery domain permissive, init enforcing; stick path
impossible. M-H: `fastboot reboot` → `warm`, cold → `cold`/`shutdown,battery_low`.
M: primary cause = post-claim stall then claim refusals; alternative = SOS route.

## Follow-up 19:xx — beacon codes 6 then 4 on identical inputs

**Strings behind the codes** (beacon case order applied to every `need()` string):
- Code 6 (`*bootreason*|*identity*|*tool*`): `legacy-init-identity` (:25), `unique-nonempty-bootreason-token`
  (:35), `unique-bootreason-token` (:39), `compiled-profile-identity` (:40), `bootreason-NUL`,
  `bootreason-property-cmdline-identity`, `bootreason-policy` (:60), `required-pinned-system-tool` (:57),
  `system-tool-hash` (stage-primitives.inc:146), `APP-mounted-identity` (:89, also matches `identity`).
- Code 4 (`*artifact*|*RAM-whole*|*copy*|*bootset*|*payload*`): `bootset-owner/bootsets-directory/
  generation-bootset/bootset-total/bootset-close` (:102-106), `artifact-executable-policy`,
  `individual-payload-budgets` (:105), `artifact-budget-hash`, `literal-*-file`, `artifact-metadata`
  (safe_file: regular, 0:0, nlink 1, 0600, exact size), `whole-artifact-hash` (:97), `copy-before`,
  `copy-exclusive`, `artifact-copy-close` (same_stat), `RAM-whole-hash`, `RAM-executable-mode` (:99),
  `duplicate/missing-artifact`.
- Not in 4 or 6: `stage-deadline`, `exact-read`, `hash-pread`, `short-write`, `read-*`, `AF_ALG-*`,
  `hash-source-changed` all fall to code 9; `owned-child-*` to 8. So EIO, the 180 s budget, child
  timeouts and tmpfs ENOSPC (`/tmp` is tmpfs, default half of RAM) are excluded by the codes seen.

**Reading the two runs.** Identity runs before artifacts (`main`, :115). v11 differs from v2 only in
the bootreason policy, so the natural reading is: the v2 run stopped at a code-6 check (most likely
`bootreason-policy` on a reason outside the four, or `system-tool-hash`), v11 removed that gate and
the stage advanced to the first artifact check that fails, code 4. Two different codes do not
require non-determinism. Within code 4 the only data-dependent check is `whole-artifact-hash`
(the on-APP file content) or `RAM-whole-hash` (its tmpfs copy); everything else is metadata that
debugfs confirms correct in the image.

**What differs from 11-02 (H):** on 11-02 APP was written by `dd` from Linux/ADB. Every boot since
17:25Z used `fastboot flash system`, which cboot processes through its sparse writer
(`device_write_sparse_image_recovery`, `write_fill_data`, "Unexpected Non-zero write offset,
Clearing sparse variables"). The host splits a 256 MiB image at `max-download-size` 32 MiB and
emits FILL chunks for 4 KiB blocks of one repeated word. In the bootset only `Image` has such
blocks: 215 of 11169 (198 all-zero), initramfs and dtb none. A FILL chunk written wrongly or
skipped by cboot corrupts `Image` on APP while the ext4 metadata (sizes, modes, UUID, dirs) stays
exact, which is precisely a `whole-artifact-hash` failure and nothing else. APP.lkg.img itself is
correct (dumped Image/initramfs/dtb/cmdline hash to the pins).

**Single most likely culprit (M):** cboot's sparse FILL handling corrupts `Image` on APP;
`whole-artifact-hash` (owner-internal-stage.c:97) fires. RAM/eMMC/thermal corruption would scatter
across code-9 strings and did not occur in the many 11-02 boots; the alternative is the
unknown reason of the v2 run (`bootreason-policy`), already removed by v11.

**Test in minutes (beacon only, no stage change):** after class 2 mount APP ro (the beacon already
does) and compare software hashes with the pins, blinking the first mismatching file index:
```sh
G=/mnt/shield-beacon/shield-owner/bootsets/3982163bd866565d843455b8a076124adfb58095cc8b11720a31835fa79dfbae
i=1; bad=0; for p in Image:a317e05d7f14a10b board.dtb:c0fef725b51a97c5 initramfs.cpio.gz:c443cb70e4d99201 cmdline.txt:5c4a357874fe7bf5; do
  f=${p%%:*}; h=$(sha256sum $G/$f | cut -c1-16); k "hash $f $h want ${p##*:}"; [ "$h" = "${p##*:}" ] || { bad=$i; break; }; i=$((i+1)); done
k "bootset-hash-mismatch=$bad"   # blink $bad: 1 Image, 2 dtb, 3 initramfs, 4 cmdline, 0 all match
```
Also `sha256sum /tmp/shield-internal/Image` if the copy exists: a mismatch there with a matching APP
file would instead indict RAM/AF_ALG (`CONFIG_CRYPTO_SHA2_ARM64_CE=y` serves AF_ALG sha256).

**Fix if confirmed:** feed fastboot a sparse file that contains only RAW chunks (zero blocks as
RAW zeros, no FILL, no DONT_CARE): header magic 0xed26ff3a, v1.0, 28/12-byte headers, blk 4096,
65536 blocks, N RAW chunks of 7680 blocks (30 MiB, under max-download-size). Host fastboot passes
chunks through unchanged, so cboot never sees a FILL chunk. Then `fastboot flash system` that
file, reboot, and confirm with the beacon hash lines above. Also carry `stage-failed` text (not
only the code) into the beacon's kmsg line, which it already does.
