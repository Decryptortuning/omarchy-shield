# Shield Omarchy integration plan

Integrate the available Shield and Tegra work into a portable Arch Linux ARM desktop with the full Omarchy environment, using an external USB SSD. The primary target is the connected original-Tegra210 Darcy. The bootloader-selected and independently backed-up stock DTB identify its A04 configuration. The retained B01 profile has its own board and firmware inputs.

Use the existing modern kernel, Nouveau/Mesa and Omarchy packages as the main implementation. Adapt board definitions, firmware mappings and relevant fixes from the other projects after checking their hardware and software interfaces. Every capability actually present on this Shield stays in the acceptance scope. Full hardware support can be claimed only after its applicable physical tests pass.

Plan date: October 14, 2026. The [current validation receipt](validation-darcy.json) records four built ARM packages and passing virtual tests; physical acceptance is currently zero of 19. The work below is planned, and does not change those tested artifacts.

The [completed harvest](HARVEST.md) now supplies verified local board/source snapshots, exact-build boot/recovery inputs and radio firmware. It also identifies concrete fan/controller changes, NVK's default Tegra rejection and incompatible vendor/modern media interfaces. This closes acquisition work within the selected scope; the implementation, boot qualification and hardware acceptance phases below remain open.

On October 15, later owner-authorized unlock and recovery-only work verified matching stock recovery restoration, official Lineage recovery entry and a root ADB shell on the A04-selected device. A read-only session captured live FDT/memory/EMC data, thermal/module state and physical LNX/SOS/DTB backups with independent device/host hash agreement. SOS contains the current Lineage control. [validation-native-entry.json](validation-native-entry.json) records this progress through the recovery and inventory work below. The custom stock-inventory image failed, modern A04 entry is untested, and full hardware acceptance remains open; the distinct modern A04 profile is now implemented and component-tested in [validation-a04.json](validation-a04.json). The next native work is the reviewed memory/EMC, CPU and USB/DMA handoff.

The [first integration build](INTEGRATION.md) now adds the controller/fan candidate, reproducible inactive staging and diagnostic component checks, with four rebuilt packages and a passing whole-filesystem VM test. Native entry, radio activation, graphics/media work and all physical qualification remain open.

## What each project contributes

| Source | Integration work | Compatibility check |
| --- | --- | --- |
| Omarchy and Arch Linux ARM | Retain desktop, settings, native ARM applications, PipeWire, NetworkManager, BlueZ, zram, Btrfs and Snapper; extend the existing Shield lifecycle package. | Keep runtime/settings built from the same fork commit and preserve package signature checks. Final images need owner setup and machine-specific keys. |
| Upstream Linux and ACK Tegra | Tegra210 drivers, mainline device-tree bindings, USB roles, PCIe, display, audio, fan, power domains and Nouveau integration. | Start from the [pinned kernel](kernel.lock.json). Add small, attributable patches with board-specific tests; distinguish compiled support from physical operation. |
| Mesa | Nouveau OpenGL/EGL and evaluation of NVK Vulkan on GM20B. | Test the actual Tegra display/render-device combination and DMA-BUF sharing. Mesa 26.2.4 source rejects Tegra by default as unsupported/nonconformant; the broken-driver developer override remains disabled. This needs explicit implementation work. Meeting the [documented kernel-version prerequisite](https://docs.mesa3d.org/drivers/nvk.html) does not resolve that gate. |
| LineageOS and NVIDIA-derived Darcy definitions | Board variants, GPIO/pinmux, regulators, fan and thermal policy, radio firmware mappings, compressed-kernel boot format and DT packaging. | Use the original T210 Darcy files inside the Foster hardware repository. Compare vendor bindings with current Linux bindings before translating them. [Pinned references](board-sources.lock.json) cover the inspected files. |
| NVIDIA Shield releases and linux-firmware | Compatible recovery inputs and the required XUSB, GM20B, radio and video firmware. | Record source, hash, license, chip revision, driver request name and firmware interface for each payload. Prefer the already present original-T210 firmware where it matches. |
| Switchroot L4T kernel and image projects | Tegra power/media fixes, firmware handling and reproducible build recipes. | The [pinned build-script references](kernel.lock.json) use a downstream kernel stack. Port applicable changes to our build tools and Arch packages; verify driver/library interfaces before importing binaries or patches. |
| Switchroot FFmpeg and media packages | Investigate its [Tegra FFmpeg work](https://github.com/theofficialgman/FFmpeg/tree/6.1.1-nvv4l2) for decode, encode and video processing. | Trace the required device nodes, ioctls, firmware and libraries against our kernel. Pin actual source commits before integration. FFmpeg success does not establish GStreamer or browser acceleration. |
| AOSP boot-image tools | Inspect stock images and construct reproducible candidate boot images. | Use [the pinned tools](boot-tools.lock.json), verified metadata, round-trip extraction and observed device size limits. The builder must operate on regular output files. |
| postmarketOS and older Shield Linux projects | Boot-chain lessons, partition handling, recovery experience and historical L4T behavior. | [postmarketOS Foster work](https://wiki.postmarketos.org/wiki/Nvidia_SHIELD_TV_2015_/_2015_Pro_/_2017_Pro_%28nvidia-foster%29) targets P2571. [Older Shield L4T notes](https://github.com/na6an/ShieldTV) are historical references. Use only findings that survive comparison with Darcy; their flashing procedures do not establish a safe procedure for this unit. |

Preserve upstream licenses and patch attribution. Keep device identifiers and unique calibration private. Where a firmware payload cannot be redistributed, package its verified acquisition procedure and require local acquisition through the permitted source.

## Phase 1 Map board wiring and software interfaces

Build a comparison of the pinned vendor Darcy DTS, the current mainline/ACK DT and accessible stock evidence. Cover regulators and supply dependencies, GPIO polarity, pinmux, clocks, OPPs, interrupts, PCIe lanes, USB roles, SDIO, UART Bluetooth, fan and thermal sensors. Normalize units and phandle references so electrical differences are visible.

Record each subsystem's kernel driver, firmware request, userspace interface, source project, proposed change and test. Obtain independently readable board identifiers or compatible stock DT data to resolve A00/A04/A08 selection. A DTB we deliberately load is not independent proof of the physical board SKU. Preserve original memory/voltage information while comparing; Switch overclock tables are outside the initial integration.

Deliver a board comparison and patch ledger beside [BOARD_SOURCES.md](BOARD_SOURCES.md). Pass this phase when each planned change has a matching SoC/board reference and a concrete verification method. Unknown wiring stays explicit and cannot be treated as a verified setting.

## Phase 2 Stage firmware and reconcile kernel support

Extend [firmware.lock.json](firmware.lock.json) and [fetch-firmware-candidates.py](fetch-firmware-candidates.py) to describe per-board firmware inputs and their requested runtime paths. Acquisition initially produces inactive candidates with hashes, source licenses and format/interface reports.

Start with these known Darcy mappings:

- Wi-Fi: obtain the vendor `nvram_darcy_a00.txt` mapped by the A04 lock to `brcm/brcmfmac4354-sdio.nvidia,p2894-0050-a04.txt` (A08 retains its separate compatible-specific filename); the live A04 DT independently names the same vendor input. Verify its board/chip assumptions and the matching SDIO binary and regulatory data.
- Bluetooth: investigate LineageOS's specific mapping from vendor `bcm4354/BCM4350C0.hcd` to `brcm/BCM4354.hcd`. Validate the source payload and radio revision before activation.
- USB and graphics: verify the installed original-T210 XUSB and GM20B ACR files against driver requests. Keep the B01 XUSB candidate with the B01 profile.
- Video: compare the existing inactive NVIDIA NVDEC/NVENC/VIC candidates with the exact kernel firmware parsers and runtime command interfaces. Container validity alone does not qualify them.

Translate necessary board differences into small kernel/DT patches. Reconcile the downstream quiet/cool fan profiles with mainline PWM polarity, cooling states and sensor bindings. Both inspected fan sources use channel 3 and a 65,536 ns period, but their control values have different meanings. Determine safe defaults and stop conditions from matching board evidence before any sustained load.

Update [hardware-darcy.json](hardware-darcy.json) to require specific calibration and firmware inputs, then update its locked hash and affected package source checksums together. Extend the audit to distinguish source mapping, available payload, successful firmware load and functional hardware results. Pass when baseline boot/storage/radio candidates and board patches are reproducible, with remaining media or vendor gaps identified by subsystem.

## Phase 3 Establish recovery and the boot handoff

Acquire compatible official recovery/boot inputs for the installed firmware family and inspect them with [inspect-boot-image.py](inspect-boot-image.py). Compare their device identity, versions, partition expectations, compressed-kernel handling, header, addresses, command line and DT selection with the unit's observations. Older recovery releases need explicit compatibility evidence before use.

Use LineageOS's `Image.gz` and header-version-1 recipe as candidate-format evidence. Resolve the original Darcy DT handoff: the inspected recipe says older platforms ignore the later Mdarcy/Sif recovery-DTBO payload. Investigate temporary boot support and an appropriate chainloaded loader where needed. The existing P2571 U-Boot configuration does not establish P2894 support; any loader work needs its own board review and validation while retaining NVIDIA early firmware.

Prepare a boot profile containing verified metadata, payload hashes, DT mechanism, partition/download bounds and the return-to-stock procedure. Prefer a temporary diagnostic boot where supported. If native testing requires persistent boot or DT changes, present the exact images, affected partitions, backups and restoration steps before the device-write decision. No guessed addresses or unverified DT attachment can satisfy this phase.

Pass when there is a reviewable diagnostic image and a compatible recovery route. Obtain the owner's explicit decision before the data-wiping unlock. This planning request does not initiate an unlock or flash. Firmware staging and virtual filesystem builds can continue while recovery inputs are being obtained.

## Phase 4 Build one coherent candidate and test it offline

Freeze the selected source/patch/firmware/DT set after reviewing the actual producers and consumers. Build the matching kernel, modules, initramfs and four existing ARM packages through [BUILD.md](BUILD.md). Introduce a dedicated firmware package only when it improves provenance and its payloads can be packaged under their licenses. Keep experimental vendor media libraries in an isolated development filesystem until their interfaces are understood.

Extend source verification, profile validation and CI to reject wrong SoC/board pairs, altered inputs, missing board calibration and incompatible module releases. Test any new boot packer with synthetic v1 fixtures, round-trip extraction, size/alignment checks and refusal cases. Create a real candidate boot image only after Phase 3 supplies its verified metadata and DT mechanism.

Run the existing focused suites, configuration/module/DT audits, ELF header audit, kernel/ramdisk boot and complete filesystem VM test. Add tests where new integration behavior creates a meaningful failure case. Rebuild and repeat affected checks after a candidate changes; retain the previous passing bundle. QEMU qualifies virtual behavior and cannot pass a Shield peripheral or its electrical configuration.

Deliver versioned package/component bundles, source and license records, checksums and validation receipts. This phase can validate raw components and userspace before Phase 3 completes; the first native boot requires both phases.

## Phase 5 Boot a small native diagnostic environment

After the boot/recovery preparation and required owner decision, boot the minimal USB-console diagnostic candidate. Confirm effective DT identity against independent board evidence, actual RAM/CPU information, interrupt behavior, firmware loads and basic regulators. Establish USB console access, bounded logging, shutdown/reboot and a return to the known-good environment.

Check thermal sensor plausibility, fan polarity, controllable cooling and RPM feedback where exposed. Use conservative clock limits while comparing board data. Do not begin stress or graphics workloads until the cooling path and stop conditions are verified. Inventory internal storage read-only; back up accessible original boot/recovery/DT inputs before any later overwrite.

Pass with a repeatable native diagnostic boot, working console, verified cooling response and retained evidence. A boot failure or incorrect fan behavior returns work to the relevant earlier phase rather than widening the test load.

## Phase 6 Deliver the portable desktop

Prepare a clean ARM filesystem from verified inputs and the matching package set. Create an owner account and machine-specific keys; the development rootfs contains build accounts and signing state and must not be deployed. Use an image file for preparation and select the dedicated external SSD explicitly before any physical formatting.

Qualify both USB host ports, SSD reads/writes on a designated test area, UAS where supported, disconnect/reconnect behavior and Ethernet. Boot the clean SSD filesystem with the known-good kernel. Retain compressed swap and memory-pressure handling for the 3 GB system while keeping the complete applicable Omarchy package set.

Bring up HDMI at 1080p first, then test the actual supported higher modes. Verify Tegra display output, Nouveau rendering, EGL/OpenGL and DMA-BUF sharing between the render and display devices. Start Hyprland and Quickshell, then test terminal, browser, file manager, audio and user-session recovery. Software rendering can aid diagnosis but cannot pass native GPU acceptance. Display testing needs an attached display; earlier diagnostic work can use USB console access.

Pass with a usable hardware-rendered Omarchy desktop, stable storage/network/input and a monitored 30-minute desktop workload. This is the first usable-desktop milestone; the full hardware matrix continues through Phase 7.

## Phase 7 Qualify all hardware and advanced features

Use the following checks to complete [the 19-subsystem matrix](hardware-darcy.json). Record exact versions, setup, results and failures. Driver enumeration or an advertised API is not a functional pass.

| Matrix entry | Required physical evidence |
| --- | --- |
| CPU and memory | Match topology/RAM, exercise supported CPU frequencies, observe zram and memory pressure, and confirm thermal limits under bounded load. |
| Internal eMMC | Match device and partition identity, verify reads and preserve backups; qualify writes only within the specifically authorized scope. |
| USB host and SSD | Test both ports, USB 2/3 devices, hubs, hotplug and sustained data-verified SSD I/O. |
| USB device role | Test role switching, Windows enumeration, CDC ACM data and NCM networking. Replace the diagnostic root shell with authenticated access for normal use. |
| Ethernet | Match the PCI adapter/driver, verify link negotiation, DHCP, sustained LAN transfers and reconnect. |
| Wi-Fi | Match SDIO identity/calibration, verify both supported bands, regulatory settings, traffic and reconnect. |
| Bluetooth | Match chip/HCD, pair peripherals and audio, then verify reconnect and coexistence with Wi-Fi. |
| Remote and controller | Test buttons, pairing, microphone, available IR behavior and wake independently. |
| HDMI display | Verify EDID, supported resolutions/refresh rates, cursor, VT switching and hotplug. |
| Audio | Test HDMI PCM/routing, USB/Bluetooth audio and supported channel/rate combinations; assess passthrough separately. |
| CEC | Verify adapter discovery, key events, display control and supported wake behavior. |
| GPU and desktop | Demonstrate native GM20B EGL/OpenGL rendering, buffer sharing, Hyprland/Quickshell and monitored clock scaling. |
| Vulkan | Verify NVK on this actual SoC with rendering, synchronization and correctness tests. Keep any Tegra-specific gap visible. |
| Video engines | Prove NVDEC decode, NVENC encode and VIC processing using known samples and output comparisons. Establish the userspace/kernel interface before porting Switchroot FFmpeg patches. Test player, browser and GStreamer paths separately. |
| Cooling | Verify sensor readings, fan response/polarity, cooling transitions and sustained thermally controlled operation. |
| Power and clocks | Check board-matched rails, CPU/GPU/EMC scaling, idle behavior and power measurements where available; preserve any unmeasured requirement as open. |
| Suspend and wake | Repeat suspend/resume and stock-supported remote, USB and network wake tests; confirm display, radio and storage recovery. |
| Boot and recovery | Repeat standalone cold boot/reboot, known-good recovery and restoration tests at the authorized scope. Qualify recovery from failed updates. |
| Licensed media and vendor features | Evaluate capabilities present in the stock device, including relevant HDR, Dolby and protected playback paths. Identify required vendor components and availability; 2019-only AI upscaling is outside original-T210 capability. |

Assess GPU compute with the GPU entry: test relevant Vulkan/OpenCL paths and investigate CUDA's actual driver/userspace dependencies. A successful desktop renderer does not establish CUDA compatibility. Keep vendor-stack experiments in an isolated filesystem until a viable integration is demonstrated.

If a mainline gap requires downstream Tegra work, first identify a patch or interface adaptation that preserves the modern desktop. Where that is infeasible, build an isolated matching L4T comparison environment to establish what the donor stack actually provides. Any proposed product-stack change needs explicit comparison of Omarchy compatibility, security maintenance, recoverability and measured feature coverage. Do not count an unavailable capability as passed or remove it to improve the support total.

## Phase 8 Finish installation updates and recovery

Implement the guarded operations in [the Shield lifecycle package](omarchy-shield/lifecycle) only after their native boot prerequisites are verified. Cover owner provisioning, encrypted SSD root/unlock, reset/re-keying, boot setup, update verification and snapshot recovery. Preserve authenticated access during headless operation and remove the unauthenticated diagnostic console from normal images.

Stage kernel, modules, DT, firmware and rootfs changes as a compatible set. Couple Btrfs/Snapper recovery with the matching boot components; a filesystem snapshot alone does not roll back a kernel stored elsewhere. Retain a known-good boot set and test interrupted or incompatible updates in the disposable VM before bounded device tests. Desktop package updates must not silently rewrite NVIDIA early firmware or boot partitions.

Produce a reproducible owner image, install/recovery instructions, package provenance and the hardware support table. Release experimental milestones with their actual gaps. Full-support status requires every applicable physical entry to pass, along with usable native graphics, clean provisioning and tested recovery/update behavior.

## First implementation batch

The harvest completes the selected source comparison and inactive staging portions of items 1 and 2 below. Continue with the [concrete integration findings](HARVEST.md#integration-findings); reproducible fetch/package integration and the remaining items still need implementation:

1. Add a source verifier and board-comparison report for the pinned Darcy inputs; record relevant Switchroot kernel/FFmpeg dependencies before importing code.
2. Add per-board inactive firmware staging with the exact radio mappings, payload hashes, requested filenames and driver-interface evidence.
3. Tighten the hardware audit to require Darcy calibration and distinguish configuration coverage, payload availability and physical results.
4. Design the boot-profile/packer validation around the LineageOS recipe, observed size limits and the unresolved original-Darcy DT handoff. Continue obtaining compatible recovery evidence.
5. After the source/interface review, update the affected locks and package recipes together, then rebuild one coherent candidate and run the focused offline checks.

The first deliverable is an auditable candidate bundle with explicit native-test prerequisites. Subsequent milestones are a cooled native USB-console boot, a usable SSD-based Omarchy desktop, completion of the hardware matrix, and a clean install/update/recovery release.
