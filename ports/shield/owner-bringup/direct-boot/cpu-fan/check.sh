#!/bin/bash
# Report CPU scaling, fan and thermal state on the Shield (run over SSH: ssh ... 'bash -s' < check.sh)
uptime
grep -o "android.kerneltype=[a-z]*\|cpuidle.off=1\|initcall_blacklist=[a-z_]*" /proc/cmdline | tr "\n" " "; echo
cat /shield-boot/counter 2>/dev/null || true
mount | grep -q debugfs || mount -t debugfs none /sys/kernel/debug
echo "cclk_g parent: $(cat /sys/kernel/debug/clk/cclk_g/clk_parent 2>/dev/null) rate: $(cat /sys/kernel/debug/clk/cclk_g/clk_rate 2>/dev/null)"
p=/sys/devices/system/cpu/cpufreq/policy0
if [[ -d $p ]]; then
  echo "cpufreq: driver=$(cat $p/scaling_driver) gov=$(cat $p/scaling_governor) cur=$(cat $p/scaling_cur_freq) min=$(cat $p/cpuinfo_min_freq) max=$(cat $p/cpuinfo_max_freq)"
  echo "avail: $(cat $p/scaling_available_frequencies 2>/dev/null)"
else
  echo "cpufreq: none"
fi
for c in /sys/class/thermal/cooling_device*; do echo "cdev $(cat $c/type) cur=$(cat $c/cur_state) max=$(cat $c/max_state)"; done
for z in /sys/class/thermal/thermal_zone*; do printf "%s=%s " "$(cat $z/type)" "$(cat $z/temp)"; done; echo
for h in /sys/class/hwmon/hwmon*; do [[ $(cat $h/name) == pwmfan ]] && echo "fan pwm=$(cat $h/pwm1) rpm=$(cat $h/fan1_input) enable=$(cat $h/pwm1_enable)"; done
systemctl show -p ConditionResult -p ActiveState shield-direct-fan.service | tr "\n" " "; echo
systemctl --failed --no-legend | head
dmesg | grep -i -E "dfll|cpufreq|speedo|thermal|pwm-fan|soctherm" | head -20
dmesg | grep -c -i -E "nouveau.*(error|fault|timeout)"
