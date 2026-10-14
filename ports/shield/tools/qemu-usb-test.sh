#!/bin/bash
set -euo pipefail
# Installed into the disposable guest by prepare-qemu.sh; linted separately.
# shellcheck disable=SC1091
source /var/lib/shield-linux/usb-gadget.sh
modprobe dummy_hcd
modprobe cdc_acm
shield_usb_gadget_create dummy dummy_udc.0
trap shield_usb_gadget_remove EXIT
udevadm settle --timeout=20
for (( attempt = 0; attempt < 100; attempt++ )); do
  [[ -c /dev/ttyACM0 && -c /dev/ttyGS0 ]] && break
  sleep 0.1
done
python3 - <<'PY'
import os, select, time, tty
host = os.open('/dev/ttyACM0', os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
gadget = os.open('/dev/ttyGS0', os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
try:
    for descriptor in (host, gadget):
        tty.setraw(descriptor)
    for sender, receiver, payload in ((host, gadget, b'shield-host-to-gadget\n'),
                                      (gadget, host, b'shield-gadget-to-host\n')):
        os.write(sender, payload)
        received = b''
        deadline = time.monotonic() + 10
        while len(received) < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([receiver], [], [], remaining)[0]:
                raise SystemExit('USB serial transfer timed out')
            received += os.read(receiver, len(payload) - len(received))
        if received != payload:
            raise SystemExit('USB serial payload mismatch')
finally:
    os.close(gadget)
    os.close(host)
PY
echo 'CHECK: virtual USB CDC ACM enumeration and bidirectional serial data'
