# Stock-kernel inventory entry candidate

## Native entry results

On October 15, owner-approved unlocking completed in 394.918 seconds and subsequent fastboot queries verified `unlocked: Yes` on the same A04-selected Darcy. Temporary boot commands for both this candidate and the untouched matching NVIDIA recovery returned `OKAY`, but both attempts reached Android welcome/setup. The diagnostic USB serial interface never appeared and no inventory archive was saved. [validation-native-entry.json](validation-native-entry.json) records the inputs and outcomes. No partition image was flashed. Command acceptance does not qualify kernel or ramdisk execution; the cause of the return to Android remains unresolved.

The next comparison uses the installed stock recovery through **Boot recovery kernel** in the fastboot menu. **Forced Recovery** is the separate low-level Tegra USB recovery mode. Any later recovery-partition diagnostic test needs its own reviewed image/restoration plan and owner decision.

## Built candidate

The locally built image is **12,384,256 bytes**, SHA-256 `2f37d27e9b7c1a17cd777adf35c622314bce5dc98927f8a7593b4788f9d29a1e`. Its independent pinned-AOSP repack is byte-identical. The ramdisk starts under the modern kernel on QEMU `virt`; 30 Python tests, ShellCheck and the Windows CI binary-stream parser tests pass. [validation-stock-bootstrap.json](validation-stock-bootstrap.json) records the exact scope. Neither the stock kernel on real hardware nor physical USB/cooling has been qualified by those virtual tests.

An October 14 documented read-only `fastboot oem dtbname` query returned `tegra210-darcy-p2894-0050-a04-00.dtb` while the owner device remained locked. It was returned to Android with authorized ADB connected. This independently establishes the bootloader's **A04 selection**; no PCB EEPROM or part number was read. The existing modern A08 evaluation profile needs an A04 definition before a mainline hardware test. This stock-kernel inventory candidate preserves the current bootloader/DTB handoff.

This is a separate first-stage diagnostic candidate. It uses the exact installed-release stock recovery kernel and preserves its header load-address fields and existing bootloader/DTB handoff. It replaces the ramdisk and command line, updates the Android image digest and omits the original signature footer. It requires an unlocked bootloader. Preserving measured fields does not qualify their effective addresses or prove that temporary boot works.

The independently inspected `stock-bootstrap.lock.json` pins the stock recovery, matching fan/thermal modules, XUSB firmware, BusyBox archive and kexec source. `prepare-stock-bootstrap.py` keeps every header byte outside the ramdisk size, command line and digest ranges unchanged. The kernel payload remains byte-identical. No DTB, partition table or early boot firmware is included for replacement.

The inventory init requires explicit opt-in, original Darcy compatible strings, chip ID 33/major revision 1 and stock kernel release `4.9.141-tegra`. It uses the same two cooling modules and load order as the matching recovery. It runs no Android installer/service and mounts no persistent filesystem. A short idle session records DT identity, available live FDT, memory maps and logs under `/run/shield-stock`. GPT labels independently select bounded read-only boot/recovery/DTB backups into RAM. Missing labels or unavailable FDT remain visible gaps; nothing is inferred from the evaluation A08 DTB.

USB serial uses stock's `700d0000.xudc` controller and built-in ACM function. The root console is intended only for this physical diagnostic session. The session powers off after 60 seconds, sooner for a detected 70°C CPU/GPU reading or absent plausible sensor data. It runs no kexec operation automatically. Evidence disappears at power-off unless transferred to the PC; any real device dumps must stay private until reviewed.

The Windows [collector](tools/collect-stock-inventory.ps1) waits for a unique USB serial interface whose parent has the inventory gadget's VID/PID and explicit serial string. It opens no arbitrary COM port. Its fixed command creates a tar in device RAM and transfers a nonce/length-framed binary stream into a new private PC directory. It bounds the transfer and saves a SHA-256 receipt; it never extracts or publishes the archive, writes a device partition or invokes kexec. Start it before a separately authorized temporary boot so collection fits the bounded session. Synthetic binary-stream tests do not qualify physical USB enumeration or transfer.

Build from verified local inputs into new directories:

```sh
work="$HOME/build/omarchy-shield/stock-bootstrap-2026-10-14"
bash ports/shield/tools/build-stock-busybox.sh \
  "$HOME/build/shield-linux/downloads/busybox-1.37.0.tar.bz2" "$work/busybox-v2"
python3 ports/shield/prepare-stock-bootstrap.py \
  --recovery "$HOME/build/omarchy-shield/harvest-2026-10-14/boot/current-build/recovery-inputs/recovery.img" \
  --busybox-root "$work/busybox-v2/root" \
  --kexec-root "$HOME/build/omarchy-shield/integration-2026-10-14/kexec-static" \
  --output "$work/image"
```

The output is a local unsigned inventory image and review receipt. Stock payloads remain outside public Git. Before a native attempt, inspect it using the pinned AOSP tools and check the source/ramdisk tests. Testing the ramdisk with a modern kernel on QEMU validates userspace startup only; it does not boot the original stock kernel on a Shield or qualify the stock USB/cooling interfaces.

The first device attempt and unmodified-recovery comparison used temporary RAM boot only. Their return to Android stopped those attempts; this candidate supplies no automatic persistent flash fallback. The owner separately approved bootloader unlocking and Android data erasure. A controlled diagnostic kernel entry and physical restoration remain unqualified.

The Windows review folder is `C:\Users\JResp\Documents\ChatGPT\Vizio\shield-stock-inventory-20261014`. It contains the image, matching release boot/recovery inputs, collector, review receipt and checksums. The October 14 default Windows policy blocked local PS1 execution. On October 15 the existing CurrentUser policy was observed as RemoteSigned; the collector started under that policy without changing it. Native Windows file hashes were verified directly, and collector readiness was checked in Windows because WSL's view did not expose its newly created private output directory. The collector then timed out without the diagnostic USB interface. Its synthetic tests passed in [Windows CI](https://github.com/Decryptortuning/omarchy-shield/actions/runs/38686684307).

NVIDIA's [open-source README](https://gitlab.com/nvidia/nv-tegra/manifest/android/binary/-/blob/rel-24-uda-r1-partner/README_SHIELD) documents the DTB-name query and bootloader unlocking confirmation. Its old touch-button navigation is not assumed for this unit; NVIDIA's [current fastboot guidance](https://nvidia.custhelp.com/app/answers/detail/a_id/4359) describes USB keyboard/controller navigation for the 2017 model. A display and supported controls must be available for the on-device warning before requesting unlock.
