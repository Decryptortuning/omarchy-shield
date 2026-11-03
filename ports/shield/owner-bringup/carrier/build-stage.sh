#!/bin/bash
# Rebuild the carrier stage binary. Step 1 reproduces the 620 build from the unchanged
# descriptor (must match byte-for-byte). Step 2 adds the power-restore boot reason.
set -euo pipefail
W=$WORK/carrier; cd "$W/build"
CC=/usr/bin/aarch64-linux-gnu-gcc-13; ARGS=(-static -Os -fno-stack-protector -fno-builtin -Wl,--build-id=none -I "$W/src")
export LC_ALL=C
# step 1: reproduce
rm -f repro-profile.c repro-stage
python3 -B "$W/src/generate-profile.py" descriptor.json live.dtb repro-profile.c
cmp repro-profile.c owner-internal-profile.620.c && echo "profile_reproduced=yes"
$CC "${ARGS[@]}" "$W/src/owner-internal-stage.c" "$W/src/internal-watchdog-owner.c" repro-profile.c -o repro-stage 2>repro-stage.stderr
cmp repro-stage owner-internal-stage.620 && echo "stage_reproduced=yes"
# step 2: new descriptor with the extra boot reason
python3 - <<'PY'
import json
d=json.load(open('descriptor.json'))
assert d['boot_reasons']==['cold','warm','watchdog']
d['boot_reasons']=['cold','warm','watchdog','shutdown,battery_low']
json.dump(d,open('descriptor.coldboot.json','w'),sort_keys=True,indent=2)
PY
rm -f owner-internal-profile.coldboot.c owner-internal-stage.coldboot
python3 -B "$W/src/generate-profile.py" descriptor.coldboot.json live.dtb owner-internal-profile.coldboot.c
diff owner-internal-profile.620.c owner-internal-profile.coldboot.c || true
$CC "${ARGS[@]}" "$W/src/owner-internal-stage.c" "$W/src/internal-watchdog-owner.c" owner-internal-profile.coldboot.c -o owner-internal-stage.coldboot 2>coldboot-stage.stderr
ls -l owner-internal-stage.620 owner-internal-stage.coldboot
sha256sum owner-internal-stage.620 owner-internal-stage.coldboot | cut -c1-16
strings owner-internal-stage.coldboot | grep -c "shutdown,battery_low"
file owner-internal-stage.coldboot | cut -c1-100
