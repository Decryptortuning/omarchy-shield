# Troubleshooting and ground rules

This covers the 2017 Shield TV (Darcy A04) on the current boot path, described in [owner-bringup/direct-boot/README.md](owner-bringup/direct-boot/README.md). Every rule here was learned from a real failure on the reference device.

## Know the hardware

- **USB ports.** The port farther from HDMI is the OTG port: it is the one a PC talks to for fastboot. The port beside HDMI is host-only: keyboards, receivers and drives go there.
- **Reaching the bootloader.** Connect a PC to the OTG port, then hold **A and B** on the Shield controller while applying power. The bootloader menu appears on HDMI and `fastboot devices` lists the Shield.
- **Two boot slots.** The `boot` partition (LNX) is the normal slot. The `recovery` partition (SOS) is a second, complete slot. Both normally hold the same image.

## What the Shield does when a boot fails

1. **The shim prints progress on the TV.** It draws status text over the NVIDIA splash: memory banks, the kernel copy, the jump. If the screen stops there, photograph it; the last line shows how far it got.
2. **A hardware watchdog resets a hang.** The shim arms a 240-second watchdog before starting Linux, and systemd keeps feeding it. A kernel that hangs is reset without anyone touching the device.
3. **A boot counter tracks bad boots.** The loader adds one on every boot. A service resets the counter after the system has been up for three minutes.
4. **At three and four failed boots, the root rolls back.** The loader renames the root subvolume `@root` to `@root.bad-…` and puts the last known good copy, `@root.lkg`, in its place. The good copy is refreshed 13 minutes after each healthy boot.
5. **At five, the loader stops in rescue mode.** See below.

## Rescue mode

Rescue runs entirely from the boot image, so it works when the root filesystem does not.

- **How to tell:** the TV shows a shell prompt on the console instead of the desktop.
- **Network:** Ethernet comes up with the fixed address `192.168.2.211/24`. This address is currently hard-coded in `loader/init`; change it there for another network.
- **SSH:** the loader starts the root filesystem's own `sshd` from a read-only mount, so your existing root key works. If the root cannot be mounted at all, only the console shell is available.
- **Leaving rescue:** run `shield-rescue-resume`. It resets the boot counter and reboots.
- **Entering rescue on purpose:** from the running system, `echo rescue > /boot/shield-boot/next` and reboot. The request applies to one boot.

## Rules that keep it bootable

1. **Test every new boot image in the recovery slot first.** Write it to SOS, then `systemctl reboot --reboot-argument=recovery`. A clean reboot returns to the normal slot. Build test images with shim flags `0`, so that a hang falls back to the normal slot instead of looping. The bootloader's normal mode leaves the power-management chip's own watchdog armed; an early image that had only run in recovery mode powered the board off two minutes after a normal boot.
2. **Never `fastboot flash` a normal sparse image to `system` or `userdata`.** This bootloader corrupts the "fill" chunks that host fastboot generates for large images. Convert the image with `owner-bringup/carrier/make-rawsparse.py`, which emits raw chunks only. Small padded images for `boot` and `recovery` are unaffected.
3. **Install system units through the guard script.** `shield-unit-apply <unit>` refuses a unit that orders itself before SSH or networking, runs `systemd-analyze verify`, and takes a read-only snapshot of the root first. An ordering cycle introduced by one hand-written unit once removed `sshd` from the boot and took the device offline.
4. **Do not enable a Tegra peripheral in the device tree without checking its reset.** The bootloader leaves some blocks held in reset, and the mainline clock driver no longer releases them. Enabling HDMI CEC without a reset line froze the whole system on the first register write.
5. **Name the pin table `default`.** Upstream's device tree for this board names its pin configuration `boot`, which mainline never applies. With it unapplied the GPU's voltage control and the fan are both disconnected: the GPU corrupts its work at speed and the board idles above 80 °C.

## Symptoms

| Symptom | Cause and fix |
| --- | --- |
| Green tint over the whole desktop | Seen once after a boot; the cause is not established. Force a mode change and change back: switch the monitor to `1920x1080@60` with `hyprctl`, then to your normal mode. |
| Fan silent, board hot | The running device tree lacks the pin fix (rule 5). Check `pwm1` under `/sys/class/hwmon/*/` and the temperatures in `/sys/class/thermal/`. |
| Bluetooth controller missing after boot | `shield-bt-address.service` failed. Run `journalctl -u shield-bt-address -b`. Restarting the unit is safe. |
| `fastboot flash system` succeeds but the files are corrupt | Rule 2. |
| Boots the recovery slot every time | The image in that slot was built with shim flag `4`, which keeps the recovery request set. Rebuild it with flags `0`, or run `systemctl reboot` from a working boot. |
| Nothing on screen, no network | Wait five minutes for the watchdog and the fallback slot. If it still does not return, use A and B to reach the bootloader and reflash both slots with a known good image. |

## Checking health

`owner-bringup/direct-boot/cpu-fan/check.sh` prints the boot slot, CPU clock source and frequency range, fan state, every temperature, failed units and GPU errors in one pass:

```bash
ssh root@<shield> 'bash -s' < owner-bringup/direct-boot/cpu-fan/check.sh
```
