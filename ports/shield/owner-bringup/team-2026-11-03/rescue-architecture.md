# Shield (Darcy) rescue and maintenance architecture — 2026-11-03

Design only; the device was not touched. Uses kernel457 `Image` (a317e05d),
`board.dtb` v2 (c0fef725), the LNX carrier tooling and binaries/modules from
the local rootfs copy (`$BUILD/rootfs`). No kernel build.

## 0. What the sources actually enforce (compatibility constraints)

- `owner-internal-stage.c` compiles one profile: one `generation_id`, exactly 9
  artifacts in `bootsets/<gen>/`, and an exact `normal_command_line`. Every
  failure path calls `need()`→`die()`, which writes `stage-failed`, exits and leaves recovery running.
- `owner-local-claim.c` refuses when `pending != healthy`
  (`unacknowledged-or-malformed-prior-attempt`). A `watchdog` boot needs a
  `watchdog-retry` permit. The next sequence is `healthy.seq + 1`.
- Linux ACK (`owner_internal_ack.acknowledge`) needs `pending == (gen, seq)`
  and `seq == healthy.seq + 1`. It does **not** check the generation stored in
  `healthy`. Two consequences: a retry that reuses `healthy.seq+1` is
  ACK-compatible with no Linux change, and `healthy.gen` already names the
  last-known-good (LKG) generation.
- Owner-init (`owner_command_line.admit_normal`) admits an exact token list.
  `boot.json` pins the source closure, and its hash is on the cmdline. Any
  initramfs or cmdline edit therefore means a new profile and a new carrier.
  The fix is to move repair out of that admission, not to loosen it.
- Root subvolumes are mounted **by name** (`subvol=@root`). Renaming
  subvolumes is a valid root rollback that owner-init accepts unchanged.
- Space: APP is 256 MiB. `APP.v4b.img` has ~97 MiB free. LNX holds 25.5 MiB
  and has ~3.4 MiB free, so rescue artifacts must live on APP, not in the carrier.
- Display: tegra-drm, host1x and drm are built into kernel457, and the cmdline
  already contains `console=tty0`, so fbcon on tty1 works in any 7.1 initramfs.
  brcmfmac, cfg80211, brcmutil and r8169 are modules. `pci-tegra.ko`
  (566db4f9) is out-of-tree.

## 1. Rescue path

### 1.1 Artifacts (APP `shield-owner/`)

| Object | Notes |
|---|---|
| `Image`, `board.dtb` | **Shared** with the active generation (same hash pins). |
| `rescue/initramfs.cpio.gz` | ≤ 24 MiB budget. Measured: the glibc closure of sshd, sshd-session, wpa_supplicant, dhcpcd, ip, btrfs, kmod, setfont, qrencode, bash, coreutils, journalctl, plus 5 modules and BCM4354 firmware, is **19.3 MiB gzip**. Dropping journalctl and btrfs (use the root's copies through chroot) or switching to static busybox brings it to about 10 MiB. |
| `rescue/cmdline.txt` | `HARDWARE` tokens minus `modprobe.blacklist`, plus `rdinit=/init shield.rescue=1`. The stage appends `shield.rescue-reason=<tok> shield.rescue-seq=<16hex> shield.rescue-gen=<64hex>`. |

Initramfs contents: `/init` (shell, or a small static C program built with the
existing `aarch64-linux-gnu-gcc-13 -static`), a watchdog feeder, sshd with
**`AuthorizedKeysFile` holding only the operator ed25519 public key**, a
dedicated rescue host key (published to `known_hosts` as alias
`shield-rescue`), `wpa_supplicant.conf` (PSK), modules
`pci-tegra r8169 cfg80211 brcmutil brcmfmac` with firmware
`brcmfmac4354-sdio.{bin,clm_blob,nvidia,p2371-2180.txt}`, `Lat2-Terminus16`,
and the `shield-rescue` tool.

The stage profile pins every rescue artifact by size and sha256, the same way
it pins the normal set. The rescue cmdline is a second compiled constant.

### 1.2 Rescue /init sequence (budget: sshd up < 60 s)

1. Mount proc, sys, dev and pstore. Open `/dev/watchdog0` and feed it every
   10 s for the whole session. The current cmdline uses
   `watchdog.open_timeout=240`, so an unfed rescue would reset into a loop.
2. Start the HDMI status screen (section 4).
3. Bring up networking, all three paths in parallel:
   - **Ethernet**: `insmod pci-tegra.ko`, then `r8169`. The same sequence is
     proven with `board.v2.dtb`. Use DHCP plus a static alias 192.168.2.211/24.
   - **Wi-Fi**: brcmfmac, `wpa_supplicant`, `dhcpcd`.
   - **USB NCM gadget** on 700d0000: reuse the `libcomposite` and `usb_f_ncm`
     modules already shipped in the owner initramfs, with 10.55.0.1/30.
4. Start sshd: key-only, root login by key only, no passwords, no agent or TCP
   forwarding, `ListenAddress` limited to the addresses obtained, and a
   `Match` rule that denies anything outside 192.168.0.0/16, 10.0.0.0/8 and
   the NCM /30. If the root's `nft` is not reachable, carry an nft ruleset.
5. Once sshd is listening, mount APP read-write for under 1 s and write the
   `rescue-alive` record (48 B, magic `SHRSC1`, gen and seq). This plays the
   role of the ACK for rescue (see section 2).
6. Copy pstore, dmesg and the stage reason into `@log/shield-rescue/<seq>/`
   on the Btrfs root (keep 5 sets). Do not write logs to APP.

### 1.3 What `shield-rescue` may do (over SSH only)

- `status`: state records, archived failures, pstore excerpt, counters.
- `root ro|rw`: mounts `subvol=@root` (and `@log`) at `/mnt/root`. The default
  is read-only; `rw` is explicit. `chroot /mnt/root systemd-analyze verify …`
  and `journalctl -D /mnt/root/var/log/journal -b -1` use the root's own tools.
- `root-rollback`: `@root → @root.bad-<seq>`, then snapshot `@root.lkg → @root`.
  The bad root is never deleted.
- `archive`: rename `pending` to `failed/pending.<seq>-<n>-<reason>`. It
  renames and never deletes.
- `resume [gen]`, `lkg`, `rescue-again`: write the one-shot `next-boot`
  record, then reboot.
- Rescue never writes LNX, SOS or the GPT; those stay fastboot-only.

### 1.4 Security posture

Rescue is reachable only by stage policy (section 2) or by an operator
`next-boot` written from root. It exposes no password, no ADB and no remote
"enter rescue" endpoint. Exposure is key-only SSH on LAN-scoped addresses.
The PSK and host key sit in 0600 files on APP (same trust level as the boot
chain). sshd is the only service, and every login is shown on HDMI and logged.

## 2. Stage selection and last-known-good policy

### 2.1 State records in `state/`

All records are 48 B, 0600, nlink 1, and use the existing atomic
`renameat2(RENAME_NOREPLACE)` pattern.

| Record | Meaning |
|---|---|
| `pending`, `healthy` | Unchanged format. `healthy.gen` = LKG generation. |
| `attempts` *(new)* | `SHATT1`, gen, u16 count, u8 slot, u8 last-reason. |
| `next-boot` *(new, one-shot)* | `SHNXT1`, target gen or zero, mode `normal|lkg|rescue`. Consumed by rename to `next-boot.used-<seq>`. |
| `rescue-active` / `rescue-alive` *(new)* | Rescue was selected / rescue reached sshd. |
| `failed/` | Archived pendings. This replaces today's manual `pending.failed-*` handling. |

### 2.2 Decision (claim helper v2, under the existing `flock`)

```
if next-boot valid        -> consume; mode = requested
elif rescue-active        -> if rescue-alive missing twice: RECOVERY (today's behavior)
                             else mode = rescue (sticky until operator `resume`)
elif pending absent or pending == healthy -> mode = normal(active); attempts = 0
else  # unacknowledged (includes bootreason=watchdog; the permit file is retired)
      archive pending -> failed/; attempts.count++
      count <= 2                                   -> normal(active)  retry, seq = healthy.seq+1
      count <= 4 and healthy.gen != active, pinned -> normal(healthy.gen) = LKG
      else                                         -> rescue(reason)
unknown bootreason  -> rescue("bootreason-<x>") instead of refusal
```

Retries reuse `healthy.seq+1`, so the ACK needs no change. A successful ACK
sets `healthy = pending` and the next claim resets `attempts`.

### 2.3 Stage restructuring

Split `main()` into two phases.

- **Phase A** is the existing identity, disk and APP admission. A failure
  there means APP is untrustworthy: keep today's exit into recovery and diag.
  Repair is fastboot `flash system APP.img`.
- **Phase B** loops `plan → stage_artifacts(slot) → claim` up to 3 times.
  `stage_artifacts` returns an error instead of dying. A hash or metadata
  failure demotes the slot (active → LKG → rescue) with reason
  `artifact-<slot>-<name>`.

The watchdog fd, hdcp-off, kexec and the handoff script stay exactly as they
are after the claim. The profile becomes v2:
`slots[] = {role, generation, artifacts[4], base_cmdline}`, with up to 2
normal slots and 1 rescue slot, plus the 5 shared carrier tools.

Space after step 3: Image 46 + initramfs 33 ×2 + rescue ≤ 24 + small items ≈
140 MiB, inside 256 MiB. `bootsets/e8f146cd…` and `*.bak` must be archived
off-device first.

## 3. Guardrails inside Linux

1. **`shield-unit-apply`** is the only supported way to add or enable units:
   - Stage the unit and take a read-only snapshot of `@root` as `@root.pre-<ts>`.
   - Run `systemd-analyze verify <unit> graphical.target`. Fail on any
     "ordering cycle", "Requires dependency … masked" or "not found" message.
   - **Lint**: reject any unit that is `Before=`, `RequiredBy=` or
     `Conflicts=` a member of the ACK chain (`sshd`, `systemd-networkd`,
     `shield-owner-{thermal,usb,ready}`, `local-fs.target`, `sysinit.target`).
     Optional units must be `After=shield-owner-ready.service`.
     `shield-ethernet.service` with `Before=NetworkManager` is exactly the
     shape that dropped sshd today.
   - Only after these checks: `daemon-reload` and `enable`.
2. **LKG root snapshot**: `shield-lkg.timer` fires 10 minutes after a boot
   whose ACK was written, and only if `systemctl is-system-running` is
   `running` or `degraded`, with sshd up and no failed ACK-chain unit. It then
   replaces `@root.lkg` with a read-only snapshot of `@root`. Only roots that
   proved healthy become rollback targets.
3. **ACK stays minimal**: it already requires only thermal, owner-usb,
   networkd and sshd. Do not add Wi-Fi, Ethernet, Hyprland or Bluetooth. A
   lint check in `shield-unit-apply` keeps it that way, because owner-ready
   sources are hash-bound and cannot be relaxed casually.
4. **Pre-reboot canary**: `shield-reboot-check` runs
   `systemd-analyze verify default.target` and warns if any ACK-chain unit
   has a drop-in newer than `@root.lkg`.

## 4. On-screen status (a photo of the TV is enough)

- **Rescue (7.1)**: `/init` runs `setfont -d Lat2-Terminus16` on tty1
  (32 px glyphs) and redraws every 10 s. The screen shows:
  - Header: `SHIELD RESCUE  reason=<tok>  seq=<n>  gen=<8hex>  count=<n>`.
  - One line per interface: `eth 192.168.2.146 UP`, `wlan …`, `usb 10.55.0.1`.
  - `ssh root@<ip>  hostkey SHA256:<first 16>`.
  - The last pstore panic or `Failed to start` line.
  - Rows for `APP state ok/err` and `root mount ro/rw`.
  - A QR code (`qrencode -t UTF8`) of the status line. Check that the font has
    block glyphs. If it does not, show text only.
- **Carrier (4.9), Phase A failures only**: `shield-diag` already composes the
  report. Add a static `fbstatus` program (≈ 300 lines, embedded 8×16 font
  scaled ×4) that runs `stop recovery`, draws the stage reason, the APP
  state, the pending and healthy sequences and "use fastboot: flash system
  APP.img" on `/dev/graphics/fb0` for 90 s, and then runs `start recovery`
  so the bootloader menu path stays usable. With rescue in place this screen
  appears only when APP itself fails admission.

## 5. Rollout (incremental; each step leaves the device no worse than today)

**Step 1 — the smallest change that would have saved us today:**
"unacknowledged pending → archive and kexec rescue" in place of refusal.
- Build the rescue initramfs from the rootfs closure: sshd, operator key,
  Ethernet, Wi-Fi and the watchdog feeder. Skip status QR and NCM for now.
- In `owner-local-claim`, replace the refusal with archive, write
  `rescue-active`, and print `SHIELD_INTERNAL_RESCUE_V1`.
- In the stage, add one rescue artifact pair and the rescue cmdline constant.
- Loop guard: if `rescue-active` is present and `rescue-alive` is absent
  twice, fall back to today's recovery.
- Deliver as LNX (`repack-stage.py`, extended to swap the claim record too)
  plus `APP.img` through `fastboot flash boot/system`, the path proven at
  17:25Z.
- Qualify from a healthy boot: an operator `next-boot=rescue`, then SSH in,
  then `resume`, then ACK. Then repeat today's incident on purpose (a unit
  with a cycle) and repair it from rescue.
- Today, that rescue would have mounted `@root` read-write, replaced
  `shield-ethernet.service`, archived pending10 and resumed. It would not have
  needed the `systemd.mask` attempt, the switch_root wrapper or the
  empty-initramfs incident.
- Risks:
  - Untested rescue userspace: the loop guard bounds this.
  - Rescue watchdog misfeed: tested by the voluntary entry.
  - APP space: 97 MiB free vs ≤ 24 MiB needed.
  - SSH-on-LAN exposure: key-only and address-scoped.
  - The stage loses its "refuse" invariant: an unacked attempt now leads to a
    networked shell. Accept this explicitly in the owner policy.

**Step 2 — guardrails in Linux:** `shield-unit-apply`, `shield-lkg.timer`
and the reboot canary. These are userspace-only, need no carrier change, and
add a `root-rollback` target for rescue.

**Step 3 — retry and LKG:** add the `attempts` record, retry ≤ 2, profile v2
with an LKG slot equal to `healthy.gen`, and Phase-B demotion on artifact
failure. The unknown-bootreason refusal also becomes rescue. Risk: retrying
a power-cut boot repeats a hardware fault twice before rescue. The watchdog
and thermal limits in the handoff still apply.

**Step 4 — visibility:** the rescue HDMI QR, the NCM gadget, and carrier
`fbstatus` for Phase A failures.

Recovery tiers after rollout:
1. Retry.
2. LKG boot set.
3. Network rescue with root repair or rollback.
4. Lineage recovery with HDMI reason, then fastboot `flash system` with a
   known APP image.
