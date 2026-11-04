# Recovery USB / ADB analysis (Darcy P2894 A04, carrier v4..v7net) — 2026-11-03

Read-only analysis; no device commands. Evidence: carrier images v2/v4/v7net (parsed with package-carrier.py), stock-a04.dts, the live Lineage recovery capture `lineage-recovery-control-2026-10-15-2/metadata-1/dmesg.txt` (same 4.9.141-g9d1bd583388e kernel), the kernel's embedded config (IKCONFIG) and strings.

## 0. What the image change history rules out (high confidence)
- v2 -> v4: kernel (sha dc88871a), DTBO (e7a34911) and every ramdisk file are byte-identical except `system/bin/shield-owner-internal-stage`. v4 -> v7net adds only shield-diag/netadb. **The USB stack, rc files and props did not change at ~03:27.**
- The stage binary contains no USB/UDC/extcon/setprop strings. The only USB teardown is in `system/bin/shield-owner/internal-handoff.sh` (`gadget_quiesce` at line 123, `internal_usb_host_remove` at line 210). That runs only after admission (`run_internal`, lines 250-316). A refusal at the profile or hash stage never reaches it. If the runner had aborted after quiesce, recovery would have been stopped (line 280), but you were still navigating the menu.
- So the 03:27 regression is a change in runtime or physical state, not a change in the image.

## 1. Port roles and the extcon write

**Physical mapping (high confidence)**
- Stock DTS padctl ports: `usb2-0` has `mode = "otg"`, `vbus-supply = <0x49>` (usb-vbus1, GPIO CC5) and `usb-role-switch` (stock-a04.dts:3487-3500). `usb2-2` has `mode = "host"` and `vbus-supply = <0x50>` (usb-vbus2, GPIO CC4) (3506-3510). The regulators are at 10111-10133.
- `xudc@700d0000` uses only `phys = usb2-0, usb3-1` (7574-7593). xhci uses usb2-0 and usb2-2 (3638).
- The bootloader text (`chosen/fastboot-instructions`, 8198) says: *"Use USB port near HDMI port for the controller and USB port away for PC connection"*.
- Live recovery dmesg: the controller enumerated as `usb 1-3` (lines 582-630). That is root-hub port 3, i.e. usb2-2.
- **Result: the far port is usb2-0 (OTG, xudc + xhci). The port beside HDMI is usb2-2 (host-only, VBUS from usb-vbus2).**

**How the OTG role is decided (high confidence)**
- Extcon chain in the DTS (7869-7917):
  - `vbus_gpio`: extcon-gpio-states on GPIO Z0, mapped low -> VBUS attached.
  - `virtual_id`: ID with no GPIO.
  - Both feed `usb_otg` (`extcon-cable-xlate`, `extcon-name = "cable-xlate"`).
  - xudc listens to output cable 0 "vbus" (EXTCON_USB) and xhci/xotg to output cable 1 "id" (EXTCON_USB_HOST).
  - Xlate table: input VBUS -> output 0x1 (device); input ID -> 0x2 (host); both -> host.
- Working capture (dmesg 298-304, 510-519):
  - `virtual_id: No Cable connected on boot`
  - `vbus_gpio: Cable state:1` -> `usb_otg: New cable state 0x0001 ... Cable0 vbus is attach`
  - xudc `vbus state: 1`, then `device mode on`
  - Gadget endpoints were enabled at 11.2 s.
  - At 6.526 s `usb-vbus1: disabling` (line 681): the far port supplies no VBUS when it is not in host mode.
- **The xudc only pulls up D+ (becomes visible to the PC) when the extcon "vbus" input is attached.** If Z0 does not report VBUS, Windows sees *nothing*: no failed enumeration, no device. "Enable ADB" and sideload do not help, because both only bind the UDC (init.rc:203-215) and never assert VBUS. This matches the symptom exactly.

**What `write /sys/class/extcon/extcon3/state 0x1` does (medium/low confidence)**
- The same write is in upstream Lineage `init.recovery.darcy.rc:17-18`, so it is not a carrier addition. The kernel names devices `extcon%lu` in registration order (string in Image).
- Probe order in dmesg is virtual_id, vbus_gpio, extcon@2 (ACADPTR), usb_otg. Whether disp-state (and usb_cd) registered before them decides the target:
  - If none registered earlier, **extcon3 = cable-xlate**, and 0x1 forces EXTCON_USB, i.e. device mode on the far port. This is the plausible Lineage intent.
  - If disp-state registered first, extcon3 = ACADPTR, and the write is a no-op for USB.
- It is **not** an ID-ground/host force:
  - 0x1 is bit 0 = USB/VBUS on xlate. On virtual_id it would be the USB_HOST cable, but the controller would then also work in the far port. It does not.
  - The far port has no VBUS (usb-vbus1 disabled), so the controller only works beside HDMI. That is explained by usb2-2 being the only host-only port, not by the extcon write.
- Even when the write lands on xlate, any later Z0 interrupt recomputes the output from the real inputs, so the force is fragile.
- To resolve the numbering, read `shield-diag` output in Advanced > View recovery logs (v5diag+). It prints every `/sys/class/extcon/*` name and state plus the xudc/extcon/vbus dmesg lines.

**Why ADB worked before and not now (medium confidence, inference)**
- Device mode follows the Z0 VBUS-sense level and its edges. Before 03:27 a *reseat at the Shield end* was often needed. That is the signature of an intermittent VBUS contact: the edge re-fires the vbus_gpio IRQ and xlate goes 0 -> 1.
- Since then it never works, yet the image is unchanged and fastboot works. This points to the VBUS path (A-to-A cable VBUS conductor or contact, or the Z0 sense) no longer reaching "attached".
- Bootloader fastboot evidently does not gate on that Linux extcon. It runs with `nvidia,bootloader-xusb-enable` / `bootloader-vbus-enable`, and works on D+/D- alone.
- A race with the stage is unlikely: the stage does not touch USB (section 0).
- Cheap discriminators:
  - Try a different A-to-A cable.
  - Unplug and replug at the PC end while in recovery.
  - Check the diag output for `vbus_gpio ... state` and `USB=0`.

## 2. USB2 Ethernet adapter gets no power or light (medium confidence)
- **Far port:** in recovery it is not in host mode, so usb-vbus1 is off (dmesg 681). Nothing plugged there is ever powered. (A-to-A designs avoid driving VBUS against a PC.)
- **Near port:** VBUS is on (the controller works). The driver is present:
  - `CONFIG_USB_USBNET=y`, `CONFIG_USB_NET_AX8817X=y`, `CONFIG_USB_NET_AX88179_178A=y` (embedded config lines 2022-2024).
  - The Image contains usb_device_id entries for 0b95:7720/772a/772b/1780/1790 and Apple 05ac:1402.
- AX88772 LEDs are link/activity LEDs of the internal PHY. They light only after the driver releases PHY power-down and autoneg reaches a *live link partner*. "No light" therefore does not prove "no VBUS".
- Likely causes, in order: no live Ethernet link on the cable; an adapter VID:PID outside the table (check the hardware ID on Windows); a faulty adapter.
- In the bootloader there is no driver, so no LED is expected there.
- Ledger 23:20 shows mainline Linux had root hubs only, so Linux 7.1 is not evidence either.
- Caveat: `internal_usb_host_check` (handoff.sh:188-207) **fatals if any USB device besides root hubs is present**. Unplug the controller and adapter before a real handoff.

## 3. Proposed carrier ramdisk changes (ranked)

### R1 (high value, medium-high confidence, low risk): force the far port to device mode by name and re-assert it
Add `system/bin/shield-usbrole.sh` (mode 0755):
```sh
#!/system/bin/sh
# Force OTG port (usb2-0) to device mode in recovery: ID=0, VBUS=1 on the xlate inputs.
k(){ echo "<6>shield-usbrole: $*" > /dev/kmsg; echo "shield-usbrole: $*" >> /tmp/recovery.log; }
set_role(){
  for e in /sys/class/extcon/extcon*; do
    n="$(cat $e/name 2>/dev/null) $(basename $(readlink -f $e/device 2>/dev/null))"
    case "$n" in
      *virtual_id*|"ID "*) echo 0x0 > $e/state 2>/dev/null ;;
      *vbus_gpio*|"VBUS "*) echo 0x1 > $e/state 2>/dev/null ;;
    esac
  done
  for e in /sys/class/extcon/extcon*; do
    n="$(cat $e/name 2>/dev/null) $(basename $(readlink -f $e/device 2>/dev/null))"
    case "$n" in *cable-xlate*|*usb_otg*) echo 0x1 > $e/state 2>/dev/null ;; esac
  done
}
U=/sys/class/udc/700d0000.xudc
i=0; while [ ! -e $U ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
for e in /sys/class/extcon/extcon*; do k "$(basename $e) $(cat $e/name) $(basename $(readlink -f $e/device)) $(cat $e/state | tr '\n' ' ')"; done
i=0
while [ $i -lt 120 ]; do
  s=$(cat $U/state 2>/dev/null)
  case "$s" in configured|addressed|default|powered) ;; *) set_role; k "udc=$s -> forced device" ;; esac
  sleep 3; i=$((i+1))
done
k "final udc=$(cat $U/state 2>/dev/null) usb=$(getprop sys.usb.state)"
```
rc diff (append to `shield-owner-internal.rc`):
```diff
+service shield_usbrole /system/bin/sh /system/bin/shield-usbrole.sh
+    disabled
+    oneshot
+    user root
+    group root
+    seclabel u:r:recovery:s0
+
+on property:sys.usb.ffs.ready=1
+    start shield_usbrole
```
- Rationale: it addresses the identified gate (the xudc vbus extcon) without depending on extcon numbering.
- Writing inputs first lets the xlate notifier drive xudc through the normal chain; the direct xlate write is a backstop.
- It never asserts ID, so it never turns on usb-vbus1. There is no 5 V back-feed into the PC.
- The near port is host-only and unaffected, so the controller keeps working.
- Uncertainty: whether `state` is writable on this NVIDIA 4.9 extcon. Lineage's own write and the `0x%4x` format string next to extcon core strings suggest it is. The kmsg log will show the result.
- If xudc stays `not attached` after the write, add `setprop sys.usb.config none` then `setprop sys.usb.config adb` after `set_role` once.

### R2 (medium confidence): keep Lineage's extcon3 write, add a late re-assert
Keep `init.recovery.darcy.rc:18` unchanged; R1 supersedes it. Do not delete it: it is upstream behaviour and may be the xlate write.

### R3 (high confidence, zero software risk): host for both controller and Ethernet
Put a *powered* USB 2.0 hub in the **near-HDMI** port, with the controller and ASIX adapter behind it. v7net's `shield-netadb.sh` already matches `*/usb[0-9]*` net devices and brings up 192.168.2.211:5555 with key auth. Ensure the Ethernet cable reaches a live switch or DHCP-less PC link (static IP).

### R4 (medium confidence, higher risk): true host on the far port
Writing `0x1` to `virtual_id` (ID attached) makes xlate output 0x2. xhci then takes usb2-0 and enables usb-vbus1.
```diff
+on property:shield.usb.farport=host
+    exec - root -- /system/bin/sh -c "for e in /sys/class/extcon/extcon*; do case \"$(readlink -f $e/device)\" in *virtual_id) echo 0x1 > $e/state;; esac; done"
```
- **Never automate this:** if the A-to-A PC cable is attached, the Shield drives 5 V into the PC's VBUS.
- It is useful only for a build where the far port carries the Ethernet adapter and ADB is network-only. It also kills USB ADB on that port.

### Not recommended
`persist.vendor.convertible.usb.mode=host` (prop.default:264) has no consumer in the recovery rc set; it is an Android vendor-HAL property. Changing it does nothing in recovery. `sys.usb.controller` (263) is correct.

## Confidence summary
| Claim | Confidence |
|---|---|
| Far = usb2-0 OTG/xudc; near-HDMI = usb2-2 host-only | High |
| xudc pull-up gated on extcon VBUS (Z0 via cable-xlate) | High |
| Image/rc unchanged across the regression | High |
| extcon3 = cable-xlate (device force) vs ACADPTR (no-op) | Medium/Low; diag log resolves it |
| Regression = VBUS sense or cable path, not software | Medium |
| Ethernet adapter: far port unpowered; near port powered with driver present | Medium-High |

## 4. cboot vs recovery (EBT a0b42f27, VA 0x92c00000, objdump)
**cboot device mode is a register force; it does not detect anything (high confidence, read in code).**
- **Lane and port setup** (0x92c4e3a0..0x92c4e460):
  - `USB2_PAD_MUX` 0x7009f004[1:0]=1 routes OTG pad 0 to XUSB.
  - `USB2_PORT_CAP` 0x7009f008[1:0]=2 sets port 0 to **DEVICE** (not OTG).
  - `SS_PORT_MAP` 0x7009f014[3:0]=0.
  - Pad 0 is calibrated from FUSE_USB_CALIB 0x7000f9f0/+0x160 into `OTG_PAD0_CTL0/1` 0x7009f088/08c, then powered up (clears PD/PD_ZI/PD_DR and BIAS PD 0x7009f284 bit11).
  - Then it enables the XUDC (0x700d9180 bit0, then the 0x700d0000 registers).
  - The host routine (0x92c474e8) does the same for **pad 2** (`[5:4]`=1, 0x7009f104..10c).
  - **UTMI pad 0 = usb2-0 = far port (device); pad 2 = usb2-2 = HDMI-side host.** This is identical to the kernel DT.
- **VBUS/ID** (0x92c4f668..0x92c4f70c):
  - Clears `ELPG_PROGRAM_0/1` (0x7009f020/024).
  - In `USB2_VBUS_ID` 0x7009fc60 it sets VBUS_SOURCE_SELECT=1 and ID_SOURCE_SELECT=1 (both software override), **VBUS_OVERRIDE (bit14)=1**, and ID_OVERRIDE[21:18]=0x8 (floating, so not host).
  - **cboot never needs real VBUS.** It writes no PMIC or regulator for the device port.
- **Z0 VBUS GPIO:** cboot reads Z0 (GPIO_CNF 0x6000d604 bit0, then GPIO_IN 0x6000d634 bit0; low = cable present) only as the fastboot-entry gate (0x92c044e8). The gate is **bypassed** when `/chosen/nvidia,fastboot_without_usb` exists (0x92c046c8). It does exist (stock-a04.dts chosen, ~8203).
  - So **fastboot working proves nothing about Z0 or the cable's VBUS line.** This strengthens the section 1 hypothesis.
- **HDMI-side VBUS:** I found no cboot GPIO write for CC4/CC5. Both pins are pinmuxed to SFIO `usb` (stock-a04.dts:2224-2240), so in cboot the host VBUS likely comes from XUSB itself (medium confidence).
  - In recovery, usb-vbus2 (CC4, GPIO mode via regulator-fixed) is **on**: it is not in the late-cleanup list, and the controller enumerates at `1-3`.
  - Only usb-vbus1 is switched off (dmesg 681).

**Recovery path (high confidence):**
- The NVIDIA 4.9 kernel sets the same `USB2_VBUS_ID` override only through `tegra_xusb_padctl_set_vbus_override` (Image strings).
- xudc calls it when its extcon "vbus" (xlate cable 0 <- vbus_gpio/Z0) becomes attached.
- No other path exists: `CONFIG_DEVMEM` is not set (config 2345), so a register poke from userspace is impossible.
- **The only ramdisk-level equivalent of cboot's VBUS_OVERRIDE=1 + ID floating is the extcon write in R1:**
  - virtual_id=0x0 (ID floating);
  - vbus_gpio=0x1 (VBUS attached);
  - xlate=0x1 as a backstop.
- Then xudc sets the padctl override and pulls D+ up even if Z0 never sees the PC's VBUS. Lineage's `extcon3 0x1` is an index-dependent attempt at the same thing.
- **Gadget-bind timing:** cboot forces the override before it enables the controller. R1 matches this by forcing on `sys.usb.ffs.ready=1` (UDC is written in the same action group, init.rc:210-215) and re-asserting whenever the UDC state is not attached. If xudc ignores a late vbus change, the fallback is one `sys.usb.config none` -> `adb` cycle.
- Residual difference: cboot sets PORT_CAP=device. The kernel keeps `mode="otg"` and lets the extcon choose the role. With ID kept at 0 the outcome is the same; a DT change is not needed.
