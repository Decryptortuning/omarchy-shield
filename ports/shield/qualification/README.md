# Full-systemd qualification preparation

The current qualification sources prepare a separate matched ARM root and bind a finite guardian/recovery pair. The [full-system ARM VM receipt](../validation-systemd-vm.json) now qualifies its systemd/session core. The existing secure recovery control and physical USB remain separate until the native broker, materializer and root handoff complete qualification.

`prepare-qualification-overlay.py` renders the normal Omarchy UWSM session, temporary account policy, candidate-only root/home/log mounts and systemd units. `prepare-qualification-root.py` requires a pinned payload/overlay, verifies the reference, copies it to a new private host directory, excludes build/private state, creates the locked nonadministrative `shieldqual` account, runs the installed headless Tokyo Night theme leaf in a network-isolated ARM chroot, applies service masks and rechecks the full matched package payload. A partial output is retained and cannot be reused. Online onboarding and normal first-run completion remain pending.

`prepare-guardian.py` builds static AArch64 guardian/recovery artifacts without installing or executing them. Its shared exact source closure, kernel/config/DT inputs, root identity, overlay, helper and role form one sealed candidate. The generated C profile embeds that identity; the public default profile remains disabled. The runtime receiver checks the profile, artifact sidecar and installed helper/Python identities together.

`install-qualification-artifacts.py` admits pinned preparation, payload, artifact and profile receipts and rechecks the current producer/consumer closure. It creates another private host root, installs nine exact runtime/profile files, verifies their readback and repeats payload, account, home, policy and default-selection checks. It does not execute enabled entrypoints, activate units, select a boot root or write a physical device. The [host installation receipt](../validation-systemd-installation.json) records the executed scope.

The bounded qualification account has an explicit deny rule for twenty installed login1 power/boot actions, four systemd global-management actions and portable-image attachment, which can imply systemd daemon reload authorization. The complete 32-file action catalog is pinned and its incoming implication closure must be exactly these 25 actions. Recovery verifies the actual catalog, five primary XML/manual inputs and all root overlay files before readiness. Root recovery and unrelated subjects/actions fall through. The overlay ignores the installed logind key/lid/long-press and idle actions, disables forced Ctrl-Alt-Delete bursts and masks its target. An actual active local session produced 25 explicit NO results and denied direct power methods in the ARM VM; native effective policy remains unqualified. This temporary policy is not a claim of root/global-shutdown immunity or the permanent owner policy.

Sudo authentication policy remains unchanged. The VM separately proves the root policy's negative-only listing and denied command query, actual setuid elevation/drop, and the user's noninteractive authentication barrier. The user's password-required response is recorded as an authentication barrier, never as an observed command-authorization denial.

## Executed software and layer preparation

`prepare-systemd-vm.py` constructs a fresh isolated 24 GiB Btrfs fixture with the matched root/home/log layout, a small PID1 handoff and fixed root/user probes. `run-systemd-vm.py` permits one bounded run on its owned COW disk, retains a permanent attempt record and verifies the immutable baseline afterward. Real systemd, mount compression, actual modern VirtIO GPU/card linkage, native-entrypoint refusal, PAM/logind seat activation, user bus, setuid and bounded power controls passed. The virtual graphics fixture has no demonstrated software UWSM/compositor renderer; that scope remains blocked. Native guardian readiness is deliberately refused on the virtual board.

`prepare-native-qualification-layer.py` packages the admitted account files, complete themed home, policy/masks, runtime files and ancestor metadata as a private manifest plus content-addressed regular blobs. The [layer receipt](../validation-native-layer.json) records 10,388 entries and 6,536 unique blobs. `native_layer_reader.py` first authenticates an immutable copy against independently sealed compressed-length, archive, manifest, profile, payload and source pins, then applies bounded own-producer parsing. It returns immutable metadata and read-only blob views. The archive and account/profile data stay outside this repository. Physical preimage admission and a native writer are still required.

## Planned native preparation phases

The native controller and broker remain implementation work. Separate bounded boots keep package data and the complete home/runtime layer within the reviewed memory window:

1. Maintenance A creates new candidate snapshots and applies the signed matched packages. A successful package receipt still requires clean USB release and observed authenticated recovery before advancing.
2. Maintenance B uses a fresh guardian and exclusive phase journal, admits the actual A postimages and account preimages, applies the exact qualification layer, verifies it and returns through clean release and authenticated recovery.
3. The systemd boot selects that verified candidate for the bounded desktop qualification. Both prior completion receipts and fresh boot/recovery/memory admission are required. Original default/rescue roots remain preserved.

Each boot has its own watchdog owner; no descriptor is transferred or reopened to join phases. Unknown or incomplete outcomes remain ineligible and are never automatically replayed. The native initramfs must stage the matching XUSB firmware before USB-root discovery and the four matching ACM gadget modules for early control. The VM handoff helper admits only its virtual board and cannot serve as the native loader.

Recovery must admit the actual USB Btrfs root/home/log after local mounts, verify startup masks and PID1 watchdog ownership, then announce readiness. Only then may the guardian acquire its sole watchdog descriptor and announce its first validated keepalive. The desktop follows that readiness through PAM/logind/UWSM. The guardian opens before boottime120 seconds, permits work only before540 seconds and never feeds beyond its cleanup cutoff or600 seconds. These are feeding deadlines; they are not a claim that hardware reset occurs at600 seconds.

The receiver never opens or feeds the watchdog. Its one cleanup attempt stops the temporary user, synchronizes the filesystem, unmounts home/log, verifies remaining Btrfs mounts read-only, verifies USB partition/whole-device read-only state, then requests guarded recovery within the existing deadline. It does not claim to unmount the root or guarantee power-loss durability. Blocking kernel I/O and recovery failures remain visible; no plain/global reboot fallback or automatic effect replay is provided.

## Next native run acceptance order

The next controller and collection bundle must implement and review this order before release. These are planned checks, not implemented collector results:

1. Admit current LNX/SOS recovery hashes, exact kernel/config/restricted DT, matching installed modules, USB identity and candidate root. Preserve the original default root and rescue snapshots. Keep eMMC writes and unrelated storage outside this run.
2. Prove systemd PID1, required root/home/log mounts, manager watchdog settings, guardian readiness and sensor/fan health before starting a desktop or workload. Establish authenticated host collection before effects; insufficient reserve or missing control ends work.
3. Prove the normal user session, shell/bar IPC, terminal, hardware Nouveau renderer and physical display mode. Capture screenshots, compositor logs, all underflow counters, kernel faults and actual application results. A device node or screenshot alone is insufficient.
4. Qualify a small designated USB scratch file with write/fsync/readback/hash/removal; inventory eMMC read-only. Capture USB device/gadget state, CPU topology/online state, memory/zram and thermal readings. Admit each bounded workload against the guardian's remaining reserve.
5. For enabled and wired hardware, test available Ethernet link/traffic and audio routing/playback. Inventory Wi-Fi/Bluetooth/video/Vulkan firmware, drivers and userspace separately. Disabled DT nodes, unavailable peers or absent firmware remain blocked tests, not passes. Pairing, network credentials or physical observations require the actual setup.
6. Stop workloads before the finite work cutoff. Prove owned cleanup/read-only state, observed secure recovery return and host receipt collection. Compare recovery hashes and distinguish a requested reboot from an observed reboot. Preserve failed or uncertain outcomes without replay.

Broader modes/hotplug, all-core load, DVFS, automatic cooling, radio coexistence, codec acceleration, suspend/wake and unattended permanent launch remain separate acceptance work. A bounded systemd desktop run is a prerequisite to that matrix, not full parity.

The current restricted DT keeps PCIe Ethernet, SDIO Wi-Fi, UART Bluetooth and HDA/board sound nodes disabled. Those functional tests remain blocked in the next unchanged-DT run. Native graphics, USB/root/control, read-only eMMC, fixed maximum fan/sensors and single-CPU observations are the initial supported qualification scope.

The current matched skeleton also contains an x86-64 Mason `shfmt` cache. Its ELF architecture was checked in the retained host copy. That editor-tooling gap needs a package-level ARM correction; it is not silently removed or counted as working by root preparation.
