# NVIDIA Shield TV bring-up

`aarch64-shield` is an experimental platform for the connected original-Tegra210 Darcy Shield, with a separate Tegra210B01 2019 Pro candidate. It uses NVIDIA early boot firmware and a separately packaged Linux boot image with an external Linux root filesystem. There is no hardware-validated installer yet.

The detector accepts `nvidia,p2894-0050-a08` with original `nvidia,tegra210`, and `nvidia,p2894-2551-b00` with `nvidia,tegra210b01`. Crossed silicon generations, conflicting proc/sysfs identities and mixed hardware families fail. Other Shields, generic Tegra devices, Switches and Jetsons remain plain `aarch64`. These are supported evaluation DTs, not proof of the connected unit's exact board SKU or native hardware qualification.

The default package set composes the existing base and aarch64 lists with `install/omarchy-aarch64-shield.packages`. The platform uses the existing ARM edge repository and Arch Linux ARM mirror; it adds no x86 multilib, Apple packages, proprietary desktop NVIDIA DKMS drivers or PC bootloader dependency. Mesa/nouveau is the graphics target. Firmware package availability does not establish that the required Tegra210B01 XUSB and GM20B firmware files are present or working.

All lifecycle operations register through `/usr/lib/omarchy/shield` from `omarchy-shield`. The port's build project supplies that package. Its unsupported owner provisioning, encryption re-keying and factory reset operations fail explicitly rather than falling into Limine/UKI paths. Initial boot image preparation and installation remain in the Shield bring-up project until the hardware handoff is verified.

The [Shield port directory](../ports/shield/README.md) contains the hardware acceptance matrix, kernel configuration, board overlay, source pins, platform package and evidence collector. A successful ARM userspace or QEMU test does not qualify physical Shield HDMI, GPU rendering, Wi-Fi, USB SSD boot or cooling.
