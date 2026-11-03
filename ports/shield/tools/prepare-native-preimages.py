"""Read-only expected-A witness, then bind it to actual phase-A publication.

Collection runs inside a fresh read-only qualification VM, never by replaying
the package transaction. Witnesses predict content only. The native writer
still checks every physical preimage before its first write. Finalization
requires the coordinator's actual Published object, not a receipt filename.
"""
import ctypes
import fcntl
import hashlib
import os
import stat
import struct

from native_layer_reader import LayerContent, LayerPin
from maintenance_accounts import ACCOUNT_NAMES, validate_accounts
from native_layer_writer import (FIVE, MAX_PROFILE, PURPOSE, Roots,
  WriterPin, admit, canonical, identity_schema, observe, plain, require_existing_ancestor)
from usb_root_profile import require

WITNESS_PURPOSE = 'read-only VM expected-A content witness'
FS_INFO = 0x8400941f
SUBVOL_INFO = 0x81f8943c


def digest(raw): return hashlib.sha256(raw).hexdigest()


def readonly_btrfs(fd, filesystem_uuid, name, original=False):
  """Check the supplied descriptor itself, not a caller's mount receipt."""
  import uuid
  require(os.fstat(fd).st_ino == 256, 'Witness descriptor must be the subvolume root')
  require(os.fstatvfs(fd).f_flag & os.ST_RDONLY, 'Witness source must be mounted read-only')
  buffer = ctypes.create_string_buffer(256)
  libc = ctypes.CDLL(None, use_errno=True)
  require(libc.fstatfs(ctypes.c_int(fd), ctypes.byref(buffer)) == 0
          and ctypes.c_long.from_buffer(buffer).value == 0x9123683e,
          'Witness source must be Btrfs')
  info = bytearray(1024)
  require(fcntl.ioctl(fd, FS_INFO, info, True) == 0,
          'Btrfs FS_INFO did not report complete success')
  require(str(uuid.UUID(bytes=bytes(info[16:32]))) == filesystem_uuid,
          'Witness filesystem UUID differs')
  subvolume = bytearray(504)
  require(fcntl.ioctl(fd, SUBVOL_INFO, subvolume, True) == 0,
          'Btrfs GET_SUBVOL_INFO did not report complete success')
  tree = struct.unpack_from('<Q', subvolume)[0]
  parent = struct.unpack_from('<Q', subvolume, 264)[0]
  require(subvolume[8:264].split(b'\0', 1)[0].decode('ascii') == name
          and parent == 5 and (tree == 256 if original else tree > 258),
          'Witness source subvolume differs')


def collect(content, layer_pin, root_fd, home_fd, original_fd, *, guard_check):
  """No process, mount, media write, transaction replay or publication occurs."""
  require(type(content) is LayerContent and type(layer_pin) is LayerPin
          and callable(guard_check), 'Admitted layer and actual deadline guard required')
  layer_pin.validate()
  manifest = plain(content.manifest)
  require(digest(canonical(manifest)) == layer_pin.manifest_sha256
          and manifest['sources'] == dict(layer_pin.sources), 'Layer witness binding differs')
  filesystem = manifest['filesystem']
  selected = [(root_fd, filesystem['subvolumes']['root'], False),
              (home_fd, filesystem['subvolumes']['home'], False),
              (original_fd, '@', True)]
  identities = []
  for fd, name, original_root in selected:
    guard_check()
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0,
            'Root-owned witness directory required')
    identities.append((info.st_dev, info.st_ino))
    readonly_btrfs(fd, filesystem['uuid'], name, original_root)
  require(len(set(identities)) == 3, 'Original root, candidate root and home must be distinct')
  candidate = Roots(root_fd, home_fd, guard_check)
  original = None
  try:
    original = Roots(original_fd, home_fd, guard_check)
    roots = {name: observe(fd, None, guard_check)
             for name, fd in [('root', root_fd), ('home', home_fd)]}
    entries = {name: candidate.observe(name) for name in sorted(manifest['entries'])}
    # Reject an impossible writer contract while this is still a read-only witness.
    for name, row in manifest['entries'].items():
      guard_check()
      require_existing_ancestor(row, entries[name])
    before, originals = {}, {}
    for name in sorted(ACCOUNT_NAMES):
      expected, data = original.observe(name, data=True)
      actual, candidate_data = candidate.observe(name, data=True)
      require(expected == actual and data == candidate_data and expected['xattrs'] == {},
              'Phase-A candidate accounts must equal original accounts')
      identity_schema(expected)
      originals[name] = {key: expected[key] for key in FIVE}
      before[name] = data
    after = {name: bytes(content.blob(manifest['entries'][name]['identity']['sha256']))
             for name in ACCOUNT_NAMES}
    validate_accounts(before, after)
    # A second complete observation rejects movement during the witness pass.
    require(entries == {name: candidate.observe(name) for name in sorted(manifest['entries'])}
            and roots == {name: observe(fd, None, guard_check)
              for name, fd in [('root', root_fd), ('home', home_fd)]},
            'Witness changed during observation')
    for name in ACCOUNT_NAMES:
      expected, data = original.observe(name, data=True)
      require(data == before[name] and {key: expected[key] for key in FIVE} == originals[name],
              'Original accounts changed during observation')
    for fd, name, original_root in selected:
      guard_check(); readonly_btrfs(fd, filesystem['uuid'], name, original_root)
    value = {'format_version': 1, 'purpose': WITNESS_PURPOSE,
      'candidate_id': filesystem['candidate_id'], 'filesystem_uuid': filesystem['uuid'],
      'layer': {key: getattr(layer_pin, key) for key in ['archive_sha256',
        'manifest_sha256', 'profile_sha256', 'payload_manifest_sha256']},
      'original_accounts': originals, 'original_accounts_sha256': digest(canonical(originals)),
      'roots': roots, 'entries': entries, 'source_mounted_readonly': True,
      'physical_preimages_admitted': False, 'boot_ready': False}
    raw = canonical(value)
    require(len(raw) <= MAX_PROFILE, 'Witness exceeds expected-A profile budget')
    guard_check()
    return raw
  finally:
    candidate.close()
    if original is not None: original.close()


def finalize(witness_raw, expected_witness_sha256, content, layer_pin, publication,
             phase_a_plan_sha256, original_accounts_sha256):
  """Bind predicted bytes only after actual A release and secure recovery."""
  from native_attempt_journal import Published
  from native_phase_plan import RECEIPT_FIELDS, decode
  require(type(publication) is Published, 'Actual coordinator publication required')
  require(type(witness_raw) is bytes and digest(witness_raw) == expected_witness_sha256,
          'Witness pin differs')
  value = decode(witness_raw)
  require(canonical(value) == witness_raw and set(value) == {'format_version', 'purpose',
    'candidate_id', 'filesystem_uuid', 'layer', 'original_accounts', 'original_accounts_sha256',
    'roots', 'entries', 'source_mounted_readonly', 'physical_preimages_admitted', 'boot_ready'}
    and type(value['format_version']) is int and value['format_version'] == 1
    and value['purpose'] == WITNESS_PURPOSE and value['source_mounted_readonly'] is True
    and value['physical_preimages_admitted'] is False and value['boot_ready'] is False,
    'Wrong read-only witness')
  raw = publication.predecessor_raw
  receipt = decode(raw)
  require(digest(raw) == publication.predecessor_sha256 and set(receipt) == RECEIPT_FIELDS
          and receipt['purpose'] == 'native preparation completion'
          and receipt['state'] == 'RELEASED_AND_RECOVERED' and receipt['phase'] == 'packages'
          and receipt['candidate_id'] == value['candidate_id']
          and receipt['filesystem_uuid'] == value['filesystem_uuid']
          and receipt['payload_manifest_sha256'] == layer_pin.payload_manifest_sha256
          and receipt['plan_sha256'] == phase_a_plan_sha256
          and receipt['clean_usb_release'] is True
          and receipt['authenticated_recovery_observed'] is True
          and receipt['recovery_observation_sha256'] == publication.recovery_observation_sha256
          and receipt['boot_ready'] is False and receipt['physical_powerloss_qualified'] is False,
          'Actual phase-A completion does not match witness')
  require(value['original_accounts_sha256'] == original_accounts_sha256,
          'Witness original accounts differ from maintenance plan')
  profile = {key: value[key] for key in ['candidate_id', 'filesystem_uuid', 'layer',
    'original_accounts', 'original_accounts_sha256', 'roots', 'entries']}
  profile.update(format_version=1, purpose=PURPOSE,
    phase_a_plan_sha256=phase_a_plan_sha256, phase_a_receipt_sha256=publication.predecessor_sha256)
  result = canonical(profile)
  pin = WriterPin(layer_pin, digest(result), len(result), value['candidate_id'],
    value['filesystem_uuid'], phase_a_plan_sha256, publication.predecessor_sha256, original_accounts_sha256)
  admit(content, pin, result)
  return result, pin


def finalize_audited_completed(witness_raw, expected_witness_sha256, content, layer_pin, completion,
             phase_a_plan_sha256, original_accounts_sha256):
  """Finalize after separately granted closed-A admission and fresh secure recovery."""
  from native_attempt_journal import AuditedCompletedPreparation
  from native_phase_plan import RECEIPT_FIELDS, decode
  require(type(completion) is AuditedCompletedPreparation, 'Distinct audited completed-A authority required')
  try:
    completion.begin_finalization(expected_witness_sha256, layer_pin)
    require(type(witness_raw) is bytes and digest(witness_raw) == expected_witness_sha256,
            'Witness pin differs')
    value = decode(witness_raw)
    require(canonical(value) == witness_raw and set(value) == {'format_version', 'purpose',
      'candidate_id', 'filesystem_uuid', 'layer', 'original_accounts', 'original_accounts_sha256',
      'roots', 'entries', 'source_mounted_readonly', 'physical_preimages_admitted', 'boot_ready'}
      and type(value['format_version']) is int and value['format_version'] == 1
      and value['purpose'] == WITNESS_PURPOSE and value['source_mounted_readonly'] is True
      and value['physical_preimages_admitted'] is False and value['boot_ready'] is False,
      'Wrong read-only witness')
    raw = completion.predecessor_raw
    receipt = decode(raw)
    require(digest(raw) == completion.predecessor_sha256 and set(receipt) == RECEIPT_FIELDS
            and receipt['purpose'] == 'native preparation completion'
            and receipt['state'] == 'RELEASED_AND_RECOVERED' and receipt['phase'] == 'packages'
            and receipt['candidate_id'] == value['candidate_id']
            and receipt['filesystem_uuid'] == value['filesystem_uuid']
            and receipt['payload_manifest_sha256'] == layer_pin.payload_manifest_sha256
            and receipt['plan_sha256'] == phase_a_plan_sha256
            and receipt['clean_usb_release'] is True
            and receipt['authenticated_recovery_observed'] is True
            and receipt['recovery_observation_sha256'] == completion.recovery_observation_sha256
            and receipt['boot_ready'] is False and receipt['physical_powerloss_qualified'] is False,
            'Actual phase-A completion does not match witness')
    require(value['original_accounts_sha256'] == original_accounts_sha256,
            'Witness original accounts differ from maintenance plan')
    profile = {key: value[key] for key in ['candidate_id', 'filesystem_uuid', 'layer',
      'original_accounts', 'original_accounts_sha256', 'roots', 'entries']}
    profile.update(format_version=1, purpose=PURPOSE,
      phase_a_plan_sha256=phase_a_plan_sha256, phase_a_receipt_sha256=completion.predecessor_sha256)
    result = canonical(profile)
    pin = WriterPin(layer_pin, digest(result), len(result), value['candidate_id'],
      value['filesystem_uuid'], phase_a_plan_sha256, completion.predecessor_sha256, original_accounts_sha256)
    admit(content, pin, result)
    completion.note_finalized(result)
    return result, pin
  finally:
    completion.close()
