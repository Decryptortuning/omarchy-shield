# Stock-kernel inventory entry candidate

This is a separate first-stage diagnostic candidate. It uses the exact installed-release stock recovery kernel and preserves its header load-address fields and existing bootloader/DTB handoff. It replaces the ramdisk and command line, updates the Android image digest and omits the original signature footer. It requires an unlocked bootloader. Preserving measured fields does not qualify their effective addresses or prove that temporary boot works.

The independently inspected `stock-bootstrap.lock.json` pins the stock recovery, matching fan/thermal modules, XUSB firmware, BusyBox archive and kexec source. `prepare-stock-bootstrap.py` keeps every header byte outside the ramdisk size, command line and digest ranges unchanged. The kernel payload remains byte-identical. No DTB, partition table or early boot firmware is included for replacement.

The inventory init requires explicit opt-in, original Darcy compatible strings, chip ID 33/major revision 1 and stock kernel release `4.9.141-tegra`. It uses the same two cooling modules and load order as the matching recovery. It runs no Android installer/service and mounts no persistent filesystem. A short idle session records DT identity, available live FDT, memory maps and logs under `/run/shield-stock`. GPT labels independently select bounded read-only boot/recovery/DTB backups into RAM. Missing labels or unavailable FDT remain visible gaps; nothing is inferred from the evaluation A08 DTB.

USB serial uses stock's `700d0000.xudc` controller and built-in ACM function. The root console is intended only for this physical diagnostic session. The session powers off after 60 seconds, sooner for a detected 70°C CPU/GPU reading or absent plausible sensor data. It runs no kexec operation automatically. Evidence disappears at power-off unless transferred to the PC; any real device dumps must stay private until reviewed.

Build from verified local inputs into new directories:

```sh
work="$HOME/build/omarchy-shield/stock-bootstrap-2026-10-14"
bash ports/shield/tools/build-stock-busybox.sh \
  "$HOME/build/shield-linux/downloads/busybox-1.37.0.tar.bz2" "$work/busybox"
python3 ports/shield/prepare-stock-bootstrap.py \
  --recovery "$HOME/build/omarchy-shield/harvest-2026-10-14/boot/current-build/recovery-inputs/recovery.img" \
  --busybox-root "$work/busybox/root" \
  --kexec-root "$HOME/build/omarchy-shield/integration-2026-10-14/kexec-static" \
  --output "$work/image"
```

The output is a local unsigned inventory image and review receipt. Stock payloads remain outside public Git. Before a native attempt, inspect it using the pinned AOSP tools and check the source/ramdisk tests. Testing the ramdisk with a modern kernel on QEMU validates userspace startup only; it does not boot the original stock kernel on a Shield or qualify the stock USB/cooling interfaces.

Any owner-approved first device attempt must be temporary RAM boot only. Temporary boot is unverified; rejection or failure must stop the attempt. This candidate supplies no persistent flash fallback. Bootloader unlocking erases Android user data and requires the owner's separate explicit decision after reviewing the candidate and backup requirements. No native boot, partition write or restoration pass is claimed by these build tools.
