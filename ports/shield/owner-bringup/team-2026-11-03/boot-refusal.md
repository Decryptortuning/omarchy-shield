# Boot refusal after APP.v4b flash: static analysis (2026-11-03)

Scope: read-only. APP.v4b.img (sha e90efb80) was read with `debugfs -R` and `e2fsck -fn`. Nothing was mounted and the device was not touched. Paths are relative to `bringup-2026-11-02/`.

## Bottom line

APP.v4b.img passes every stage check that can be checked offline. The memory and kexec checks are not sensitive to the larger initramfs. The patched initramfs changes nothing that owner-init checks. So the stage would have accepted the first boot after the flash. It would claim **pending seq 10** and kexec into Linux.

Once that boot fails to ACK for any reason, every later boot (the cold cycle and the v5diag/v6net/v7net carriers) refuses at the claim helper. The cold-cycle result therefore tells us nothing about why the first boot failed. The main suspect is the wrapper silently failing to replace the unit (see 3.4). Linux would then repeat the seq-10 boot: no sshd and no ACK.

## 1. Stage checks against APP.v4b.img and descriptor.v4.json

| Check (source) | Result |
|---|---|
| ext4 magic and UUID (`owner-internal-stage.c:86`) | `ccedac46-6a04-48f9-950f-71de93163bbf` matches the descriptor. fsck is clean. No needs_recovery or metadata_csum feature, which is fine for kernel 4.9. 24892 free blocks |
| `boot_directory` = `owned_dir(0700)` root:root (`owner-internal-stage.c:9`, `stage-primitives.inc:96`) | `/`, `/shield-owner`, `state`, `bootsets` and `bootsets/3982163b…` are all 40700 0:0 |
| `enabled` via `safe_file(65,0600)` and generation (`:91`) | Regular file, 0:0, 0600, nlink 1, 65 bytes. Content is `3982163b…fbae\n`, matching the descriptor and boot.json |
| `state` dir (`:92`) | 0700 0:0 |
| 4 boot artifacts via `safe_file` (`stage-primitives.inc:97`), whole hash (`owner-internal-stage.c:96-99`) | Image a317e05d / 45746688. board.dtb c0fef725 / 73816. initramfs 6de13979 / 33029931. cmdline 5c4a3578 / 653. All are regular files, 0:0, 0600, nlink 1, and match descriptor.v4 and `build/v4/owner-internal-profile.c:39` |
| Canonical cmdline (`:107-108`) | cmdline.txt minus its final `\n` equals `normal_command_line` |
| Budgets (`:104-105`, `internal-segment-check.c:43,51`) | Bootset total is 82,426,982 bytes against a 104,857,600 limit. Initramfs is 33.0 MB against 40 MiB. Image is under 48 MiB |
| descriptor v2 to v4 diff | Only the initramfs bytes and sha changed. The v2 carrier booted seq 9 with identical GPT, CID, system tools, FDT, reasons and generation |

**Claim helper (`owner-local-claim.c`).** It opens only three fixed names: `pending`, `healthy` and `watchdog-retry` (`:86`, `:96`). It never scans the directory, so names matching `pending.failed-*` have no effect. Each of these archived files is still 0600, nlink 1. The helper refuses in these cases:
- The state dir is not a 0700 root ext4 directory, or the `flock` fails (`:83-85`).
- A record exists but is not regular, 0:0, nlink 1, 0600 and 48 bytes with the right magic (`:36-53`).
- `pending` exists without `healthy`, or differs from it in any byte (`:87`).
- `healthy` seq is 0 or UINT64_MAX (`:91`).
- `watchdog-retry` is malformed, or missing on a `watchdog` boot (`:98`).
- The retry binding fails (`:101-107`).
- It cannot create `pending` exclusively (`:121`).

In v4b, `state` holds `healthy` (seq 9) and five `pending.failed-*` files, and there is no `pending`. So p=0, h=1, next=10, and the claim **succeeds**. The ACK side also uses only exact names (`owner_internal_ack.py:64-69`). It would fail only on a stale `healthy.next`, and there is none.

The debugfs `ln` + `unlink` pair adjusts no link counts. Inode 30 ends with nlink 1, which matches what fsck reports.

## 2. Memory admission and kexec placement

`stage-memory.inc` never looks at the initramfs. It uses the live FDT, `tegra_fbmem` (≥ 0x92000000, `:199`), dmesg VPR, `/proc/iomem` (`:211`) and the fixed RAM map (`:214-216`).

The load window is `--mem-min=0x80020000 --mem-max=0x91ffffff` (`owner-internal-stage.c:121`), which is 287.9 MiB. The profile has no reservations inside that window:
- memreserve is 0x80000000+128K, below LOW.
- iram is at 0x40001000 and ramoops at 0xb0000000.
- the fb0 and fb1 carveouts have zero size.
- VPR is at 0xd7000000.

Payload: Image image_size is 46,596,096, the initrd is 33.0 MB (46 pages bigger than before), and the dtb is 74 KB. That is about 80 MB of 288 MiB. `segment-check` limits (`internal-segment-check.c:102-105,118`) cannot be newly triggered by an extra 182 KiB. **Memory and kexec are ruled out.**

## 3. Linux side

**3.1 cpio.** I parsed the new and original archives directly. The only changes:
- `usr/bin/switch_root` is replaced by the static wrapper: 0100755, 0:0, nlink 1.
- `usr/bin/switch_root.real` is added. It is byte-identical to the old switch_root (ead4bf9f).
- `etc/shield-owner/shield-ethernet.service` is added: 0100644, 0:0, 556 bytes, the fixed version (ffaa3567).

Parent directories went from nlink 1 to nlink 2, which is harmless. No uid or gid is non-zero. `boot.json` is unchanged (0600, de467383, the same value as `shield.owner-boot=` in cmdline.v2). `/init` (a static C bootstrap) does no inventory check. It only mounts and execs Python.

**3.2 Owner-init admission.** It checks `boot.json` with `regular(...,0600)`, the exact cmdline (`owner_command_line.py:49-64`, generation and sequence are added by the stage), the Python source hashes (`owner-init.py:229-231`) and the root postimages. None of these involve `switch_root` or the new unit file. `boot.json` does not bind the initramfs or bootset hash; it contains only generation 3982163b. cmdline.v2 is exactly `normal_command_line`, so admission passes. This is the same path that booted seq 9.

**3.3 Wrapper and loader.** The wrapper is a static aarch64 EXEC. `switch_root.real` is a PIE that needs `libc.so.6` and `ld-linux-aarch64.so.1`, both present under `usr/lib` with `/lib -> usr/lib`. Every wrapper error path logs and still execs `.real` (`switch_root_fix.c:18-33`), so the wrapper cannot stop the boot unless the exec itself fails.

The wrapper's write does land before systemd builds its transaction: owner-init execs it at `owner-init.py:351`, and systemd loads units only after `switch_root.real` execs it.

**3.4 The flaw.** The wrapper opens the destination with `O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW` (`switch_root_fix.c:24`). If `/etc/systemd/system/shield-ethernet.service` is a **symlink**, `open` fails with ELOOP. The wrapper logs "cannot open unit on root" and boots the old unit unchanged.

Evidence that it is a symlink:
- `ledger.txt:22` records the persisted ethernet unit inside `/usr/lib/omarchy/shield/ethernet/{pci-tegra.ko, shield-ethernet.service} enabled`.
- By contrast, `ledger.txt:15` places the overlays unit explicitly in `/etc/systemd/system/`.
- `ethernet/manifest.sha256` pins the bad unit (32031bdc) next to `pci-tegra.ko`.
- `systemctl enable /usr/lib/.../shield-ethernet.service` creates exactly such a link in `/etc/systemd/system`.

This cannot be confirmed without reading the root.

**3.5 With the bad unit still in place.** Seq 10 (`ledger.txt:23-24`) showed Linux stayed up without sshd and without an ACK, and needed a manual power cut. When systemd breaks an ordering cycle by deleting the sshd job, it also drops `shield-owner-ready`, which has `Requires=sshd.service` (`owner_profile.py:205-211`). So ready never runs, `OnFailure` and `FailureAction=reboot` (`:218-222`) never fire, and PID1 keeps feeding the watchdog (`RuntimeWatchdogSec=240s`, `:183`).

**FailureAction does not cause the refusals.** The **pending record** does: once seq 10 is claimed and not ACKed, every boot fails `owner-local-claim.c:87`. The stage then records `stage-failed: owned-child-terminal-failure` with `reserved-ranges` present and no `runtime-cmdline.txt`. That is the same signature as in `diag-after-v3.log`.

If the wrapper did work, the fixed unit has no `Before=` and is ordered `After=shield-owner-ready`. That satisfies ready's PCIe check (`owner-ready.py:230-233`), so I see no remaining cycle.

## 4. Ranked failure points

1. **(Most likely) The first boot after the flash passed the stage and claimed seq 10, and Linux did not ACK. All later boots refuse on pending 10 ≠ healthy 9.** The most likely reason for the missing ACK is that the wrapper hit ELOOP on a symlinked unit (3.4), which reproduces the seq-10 cycle. In that case the TV would have shown Linux and the desktop, not recovery, until power was cut.
2. **The fastboot-initiated reboot reported a bootreason outside {cold, warm, watchdog, shutdown,battery_low}** (`owner-internal-stage.c:60`). The bootloader table also contains temperature, overvoltage, undervoltage, kernel_panic and composite `%s,%s` reasons (`fastboot-scratch/strings.txt:1425-1436`). This refuses before the claim, so no pending is written. A following `cold` boot would pass this check (`diag-after-v3.log`: bootreason=cold), so this alone cannot explain both failures. It can explain only the first one, with the cold cycle then failing for reason 1 or 3.
3. **The wrapper worked, but ready failed for another reason, so FailureAction rebooted into SOS** (stock Lineage recovery, which looks the same as the carrier). Possible causes are sshd, USB NCM or the 60 s deadline (`owner-ready.py:256-262`). Static analysis found nothing new that would cause this.
4. **owner-init failed, hung (`owner-init.py:363-368`), and the watchdog reset after about 240 s.** That boot reports `watchdog`, and the claim refuses without `watchdog-retry`. The statics argue against this: only `switch_root` changed.
5. **A problem in APP, a hash, a mode, memory or kexec.** None found.

## 5. Telling them apart without ADB

- **Recovery log on carriers v5 and later** (Advanced > View recovery logs, "SHIELD CARRIER DIAGNOSTIC"). The `--- APP state` list is decisive:
  - **`pending seq=10` present**: the first boot after the flash passed the stage and kexec'd, so the cause is 1, 3 or 4.
  - **Only `healthy seq=9`**: every boot was refused before the claim. Read `stage-failed` and `bootreason=`.

  If the block is missing entirely, that boot is SOS (Linux's `RebootArgument=recovery`), not the carrier.
- **TV timing.** Use this on the next attempt.

  | What the TV shows after the logo | Meaning |
  |---|---|
  | The recovery UI with no kernel text | Stage refusal |
  | Dense scrolling Linux 7.1 text (`console=tty0 loglevel=7 ignore_loglevel`), then Hyprland, staying up | Bad unit (case 1) |
  | Linux text, then recovery about 70–90 s later | FailureAction (case 3) |
  | Text that freezes for about 4 min, then a reset | owner-init hang (case 4) |

- **While Linux is up without sshd:**
  - `ping 192.168.2.210` (Wi-Fi via NetworkManager) and the router's DHCP lease table show Linux is alive.
  - A USB keyboard on the autologin Hyprland session (getty only `Requires=` thermal) gives a local terminal. `journalctl -b | grep -i "ordering cycle\|switch-root-fix"` and `ls -l /etc/systemd/system/shield-ethernet.service` settle 3.4 directly.
  - A warm reboot from there keeps ramoops, and the carrier diag greps pstore for `switch-root-fix` and `ordering cycle`.
- **fastboot `getvar`** cannot show APP contents or state, only partition sizes. Those already match LNX = 0x1980000 and APP = 0x10000000.

## 6. Suggested fix (not executed)

1. Reflash `APP.v4b.img` again. This restores healthy 9 with no pending.
2. Before that, rebuild the wrapper so it handles a symlinked unit:
   - `lstat` the destination; if it is a symlink, `unlinkat` it, then create a regular file.
   - Also rewrite or neutralise `/usr/lib/omarchy/shield/ethernet/shield-ethernet.service`. Alternatively, remove `multi-user.target.wants/shield-ethernet.service`, which is the most robust option.
   - Write a breadcrumb file on the root as well as to kmsg.
3. A new wrapper means a new initramfs hash. The carrier profile, LNX image and APP image must then be rebuilt together. APP.v4b has about 97 MB free.
