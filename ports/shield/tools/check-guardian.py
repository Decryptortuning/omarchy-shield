#!/usr/bin/env python3
"""Check actual guardian pure state/wire code and disabled ARM entrypoint.

No enabled hardware entrypoint runs. The host harness calls pure functions and
serializes status; the ARM binary retains the disabled public profile.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from guardian_client import (ABORT, CLIENT_ABORT, MAGIC, QUIESCE, REQUEST, RESPONSE,
                             VERSION, decode_packet, require_work_status)
from usb_root_profile import digest, require


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--output', type=Path, required=True)
  args = parser.parse_args()
  port = Path(__file__).resolve().parent.parent
  sources = port / 'guardian'
  harness = port / 'tests/guardian-state-harness.c'
  output = args.output
  require(not output.exists() and not output.is_symlink(), 'Output must be new')
  output.mkdir(mode=0o700)
  copied = output / 'enabled-pure-harness'
  copied.mkdir()
  names = ['main.c', 'sampler.c', 'state.c', 'guardian.h', 'profile.h']
  hashes = {name: digest(sources / name) for name in names}
  for name in names:
    shutil.copyfile(sources / name, copied / name)
  profile = (copied / 'profile.h').read_text()
  require(profile.count('#define SG_PROFILE_ENABLED 0') == 1
          and profile.count('"' + '0' * 64 + '"') == 1, 'Expected disabled source profile')
  profile = profile.replace('#define SG_PROFILE_ENABLED 0', '#define SG_PROFILE_ENABLED 1')
  profile = profile.replace('"' + '0' * 64 + '"', '"' + 'a' * 64 + '"')
  (copied / 'profile.h').write_text(profile)
  shutil.copyfile(harness, copied / 'fixture.c')
  flags = ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror']
  subprocess.run(['cc', *flags, str(copied / 'fixture.c'), str(copied / 'state.c'),
                  str(copied / 'sampler.c'), '-o', str(copied / 'fixture')], check=True)
  packet = subprocess.run([str(copied / 'fixture')], check=True, capture_output=True).stdout
  candidate, boot_id = 'a' * 64, '11111111-1111-4111-8111-111111111111'
  require(len(packet) == RESPONSE.size + 2 * REQUEST.size, 'Actual C wire payload size differs')
  status = decode_packet(packet[:RESPONSE.size], candidate, boot_id, 1)
  for index, (operation, reason) in enumerate([(ABORT, CLIENT_ABORT), (QUIESCE, 0)]):
    offset = RESPONSE.size + index * REQUEST.size
    expected = REQUEST.pack(MAGIC, VERSION, operation, reason, candidate.encode(), boot_id.encode())
    require(packet[offset:offset + REQUEST.size] == expected, 'Actual C/Python control mapping differs')
  require_work_status(status, 120, 30_000_000_000)
  require(status['cpu'] == 40000 and status['local'] == 30000 and status['remote'] == 41000
          and status['rpm'] == 5000 and status['pcr'] == 17, 'Actual C/Python field mapping differs')
  disabled = output / 'disabled-arm'
  disabled.mkdir()
  for name in names:
    shutil.copyfile(sources / name, disabled / name)
  binary = disabled / 'shield-guardian'
  subprocess.run(['aarch64-linux-gnu-gcc', *flags, '-static', '-Wl,--build-id=none',
    str(disabled / 'main.c'), str(disabled / 'sampler.c'), str(disabled / 'state.c'), '-o', str(binary)], check=True)
  result = subprocess.run(['qemu-aarch64-static', '-strace', str(binary), '--run'],
    capture_output=True, text=True, timeout=10)
  (output / 'disabled-arm-syscalls.log').write_text(result.stderr)
  require(result.returncode == 64 and not result.stdout, 'Disabled ARM profile did not refuse')
  require('/dev/watchdog' not in result.stderr and '/dev/mem' not in result.stderr
          and '/sys/class/' not in result.stderr and 'ioctl(' not in result.stderr,
          'Disabled profile reached a hardware interface')
  require(all(digest(sources / name) == value for name, value in hashes.items()), 'Source moved during checks')
  receipt = {'format_version': 1, 'source_hashes': hashes, 'harness_sha256': digest(harness),
    'client_sha256': digest(Path(__file__).with_name('guardian_client.py')),
    'pure_state_assertions': 'passed', 'actual_C_to_Python_status_bytes': RESPONSE.size,
    'actual_C_to_Python_control_packets': 2,
    'disabled_ARM_exit': result.returncode, 'disabled_ARM_hardware_access': False,
    'native_qualification': False, 'boot_ready': False}
  with (output / 'receipt.json').open('x') as stream:
    json.dump(receipt, stream, indent=2)
    stream.write('\n')
  print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
  main()
