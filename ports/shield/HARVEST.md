# Shield integration harvest: October 14, 2026

The subsequent [integration build](INTEGRATION.md) implements and tests the first offline batch. This report preserves the acquisition scope and findings.

Three agents harvested board, boot/recovery and firmware inputs; the coordinating agent harvested graphics/media sources and checked the combined results. The target remains the connected original Tegra210 A02 `darcy`. Its exact PCB/SKU is unresolved. This acquisition changes no tested runtime inputs and passes no physical hardware acceptance entries.

The combined check verified **728 recorded local files, 1,234,676,427 bytes**, against their recorded sizes and SHA-256 hashes. Counts include duplicate source content staged by different groups. There are 668 top-level artifact records plus 60 additional boot-source snapshots. The [index and verification receipt](harvest/index.json) pins all four reports; original source notices, acquisition scripts and binaries remain under `/home/jresp/build/omarchy-shield/harvest-2026-10-14/`. Public Git contains research metadata and documentation only.

| Workstream | Recorded files verified | Acquired inputs and evidence |
| --- | ---: | --- |
| [Board](harvest/board.json) | 207 | 206 source files across 11 Git repositories, the existing build configuration, 162 DTS/header include edges with zero unresolved lexical includes, and comparison of four matching-release stock DTBs. This is not whole-driver compilation closure. |
| [Boot and recovery](harvest/boot.json) | 86 | Exact installed-build official boot image, four stock DT variants, reconstructed matching recovery, boot recipes, AOSP format references, U-Boot/loader references and ARM64 kexec sources. |
| [Firmware](harvest/firmware.json) | 116 | 88 firmware payload records: 49 from the current official OTA, 32 upstream, two mirror cross-checks and five older L4T references; also driver mappings and notices. All remain inactive. |
| [Graphics and media](harvest/media.json) | 319 | Full pinned Switchroot FFmpeg and official Mesa source archives, selected driver/API/build sources and notices, and six inactive L4T libraries with static ELF dependency inventories. |

## Exact-build boot and recovery

The public [NVIDIA OTA](https://ota-downloads.nvidia.com/ota/productionBL-droid-signed-darcy-full_ota-13961458_4387.0822_76B4A5.zip) identifies Shield Experience 9.2.4 and exactly matches installed build `13961458_4387.0822`. Selected ZIP members were acquired using byte ranges and checked against ZIP CRCs. The embedded kernel configuration has SHA-256 `325d2cf28000ddda0ad6c65f4083648b5bb4348d793e7a4406a423574ca7c4d4`, identical to the earlier authorized stock capture.

The vendor recovery patch applied locally to the matching stock boot input produces a **20,575,528-byte recovery image** whose SHA-1 matches NVIDIA's vendor installer metadata. The installer was read as data; it was not run. Independent OpenSSL RSA/SHA-256 checks pass for both boot and recovery footers using their embedded certificate. This verifies internal signature consistency; the certificate has not been independently matched to the device trust anchor, and the whole OTA signature and provider archive MD5 remain unverified.

| Release input | SHA-256 |
| --- | --- |
| Stock boot | `a1111a6924a5bdffa8e88c960219b299a7b80d4690bffe92e415c6afb29ddd75` |
| Reconstructed stock recovery | `ebe2fc16c2b82114712f18bd78781b63c8d4b9a52de2294239b08a817098341d` |

Both images use Android header version 1, 2,048-byte pages and the same gzip-compressed kernel. Stock boot has no external ramdisk; recovery does. The raw kernel/tags address fields lie outside Tegra DRAM and need CBoot-specific interpretation; they must not be copied as validated load addresses. The original Darcy recovery-DTBO slot is ignored, so appending our DTB there does not establish a handoff.

Stock enables `CONFIG_KEXEC=y`. A controlled privileged stock-kernel environment could potentially load the mainline Image, diagnostic ramdisk and an explicit DTB through legacy `kexec_load`. The relevant sources are staged. Temporary stock-kernel entry, privileges, memory reservations, CPU/cache shutdown and Tegra firmware state remain untested. No P2894 U-Boot configuration is qualified. Acquired release inputs are not physical partition backups or a tested restoration procedure.

## Integration findings

| Area | Evidence | Required work |
| --- | --- | --- |
| PCB, RAM and resume | Four stock A00/A04/A08 variants are available; regulator/sensor behavior differs. Static EMC tables do not capture the owner's trained memory state. LP0 requires bootloader vector handoff. | Identify the actual loaded DT/SKU, RAM code, reservations and bootloader fixups before selecting the final board profile. |
| Fan and thermal policy | Mainline's inverted cooling levels end at zero. Generic `pwm-fan` can select that zero at probe without enabling the fan supply; the Tegra PWM driver rejects inverted polarity. Current stock A08 defaults to quiet while pinned vendor DTS defaults to cool. | Review rail startup, zero-duty and polarity semantics together; verify physical fan response before load. Adding an inverted-polarity flag alone is insufficient. |
| Shield controller | The upstream `hid-nvidia-shield` Thunderstrike driver covers USB/Bluetooth battery, LEDs and force feedback; `CONFIG_HID_NVIDIA_SHIELD` is disabled in the built configuration. | Enable it in the next coherent kernel candidate and extend diagnostics. Other remotes, microphone, IR and wake still need their own evidence. |
| Wi-Fi and Bluetooth | Exact OTA NVRAM and HCD bytes match pinned mirror cross-checks. Lineage maps these to Darcy BCM4354 SDIO calibration and `brcm/BCM4354.hcd`. Upstream binary/CLM candidates are staged separately from stock DHD inputs. | Review board mapping, unique platform MAC handling and payload licenses before packaging; qualify chip revision, regulatory behavior and radio operation. |
| XUSB, GPU and codecs | Upstream original-T210 XUSB, GM20B and VIC files are available. Stock XUSB and media firmware differ from upstream/older L4T versions. | Select firmware by actual driver contract. File presence and container parsing do not qualify execution or codec ABI. |
| Vulkan | Mesa 26.2.4 maps Tegra to the SoC device type and NVK rejects it by default as unsupported/nonconformant. An explicit broken-driver developer override exists and remains disabled. | Track and implement the required NVK Tegra work; retain Vulkan as an open acceptance requirement. Nouveau OpenGL/EGL remains the desktop bring-up path. |
| Video and compute | Switchroot FFmpeg opens `/dev/nvhost-nvdec` and `/dev/nvhost-msenc`, loads `libnvbuf_utils` and expects vendor V4L2/NvBuffer interfaces. The modern ACK stack exposes a different DRM/host1x interface. Vendor CUDA libraries also need their matching kernel services. | Build a modern media userspace implementation/bridge or qualify an isolated matched vendor stack. Copying libraries or renaming firmware is insufficient. |

All 19 [hardware acceptance entries](hardware-darcy.json) are mapped to these workstreams in the index. HDMI/audio/CEC, USB/SSD, Ethernet, clocks/power and suspend have pinned wiring and driver references, but still need native tests. HDR, Dolby, protected playback and other licensed features remain feasibility and qualification work; no implementation or redistribution rights are inferred from finding a vendor file.

## Next implementation batch

1. Add a reproducible per-board fetch/staging lock with license boundaries and explicit firmware-to-driver mappings; tighten the audit to distinguish available payloads, installed payloads and physical results.
2. Resolve the fan producer/consumer semantics and add the Shield controller configuration as one reviewed kernel/DT candidate. Preserve attribution and modern bindings.
3. Prepare a reviewable diagnostic boot/handoff profile using the measured image format and size limits. Investigate temporary stock-kernel entry and legacy kexec without assuming either works.
4. Once the source/interface changes settle, update matching locks and recipes, rebuild the coherent candidate and run focused offline checks. Keep the existing [built validation receipt](validation-darcy.json) unchanged.
5. Obtain physical board and memory evidence in a later authorized privileged diagnostic session, then qualify cooling and a USB console before desktop or sustained workloads.

The Shield was not accessed, rebooted, unlocked, flashed or reconfigured during this harvest. No donor installer/build script or proprietary library was executed. Native physical acceptance remains **0 of 19**.
