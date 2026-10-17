"""One sealed native plan and observed-predecessor contract for each phase.

The systemd phase consumes the exact completed phase-B plan as a reference; it
does not execute that plan's writer. Predecessor files are pinned host-produced
observations after actual authenticated recovery, not native self-attestation.
Their actual host producer and physical journal consumers must match this
schema before a capsule is eligible for release.
"""
from dataclasses import dataclass
import hashlib
import json

from native_boot_context import freeze, owned_bytes, plain, sha, unique
from native_layer_reader import LayerPin
from native_layer_writer import WriterPin
from usb_candidate_transaction import validate_plan
from usb_root_profile import require, validate_manifest

MAINTENANCE_FIELDS = {'format_version', 'candidate_id', 'filesystem_uuid',
  'original_subvolumes', 'minimum_free_bytes', 'base_database', 'base_files',
  'payload_manifest_sha256', 'base_image_sha256', 'base_account_preimages',
  'original_image_account_receipt_sha256', 'payload_canonical_sha256',
  'physical_write_released', 'boot_ready'}
LAYER_FIELDS = {'archive_sha256', 'archive_bytes', 'manifest_sha256', 'profile_sha256',
                'payload_manifest_sha256', 'sources'}
WRITER_FIELDS = {'layer', 'preimages_sha256', 'preimages_bytes', 'candidate_id',
  'filesystem_uuid', 'phase_a_plan_sha256', 'phase_a_receipt_sha256', 'original_accounts_sha256'}
RECEIPT_FIELDS = {'format_version', 'purpose', 'state', 'phase', 'filesystem_uuid',
  'candidate_id', 'payload_manifest_sha256', 'plan_sha256', 'guardian_candidate',
  'boot_id', 'configuration_sha256', 'session_id', 'evidence_sha256', 'journal_sha256',
  'worker_result_sha256', 'original_default', 'clean_usb_release',
  'authenticated_recovery_observed', 'recovery_observation_sha256', 'boot_ready',
  'physical_powerloss_qualified'}


def canonical(value):
  return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False) + '\n').encode('ascii')


def decode(raw):
  def forbidden(_value): raise ValueError('Noninteger native plan number')
  value = json.loads(raw.decode('ascii'), object_pairs_hook=unique,
                     parse_float=forbidden, parse_constant=forbidden)
  require(type(value) is dict, 'Native input must be a JSON object')
  return value


def read_raw_input(bundle, name):
  path, item = bundle.input(name)
  raw = owned_bytes(path, item['bytes'], 0o600)
  require(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'],
          'Phase input differs from sealed capsule')
  return raw


def read_input(bundle, name): return decode(read_raw_input(bundle, name))


def writer_pin(value):
  require(type(value) is dict and set(value) == WRITER_FIELDS, 'Wrong phase-B writer pin fields')
  layer = value['layer']
  require(type(layer) is dict and set(layer) == LAYER_FIELDS
          and type(layer['sources']) is dict, 'Wrong exact layer pin fields')
  lp = LayerPin(layer['archive_sha256'], layer['archive_bytes'], layer['manifest_sha256'],
    layer['profile_sha256'], layer['payload_manifest_sha256'], tuple(sorted(layer['sources'].items())))
  result = WriterPin(lp, *[value[key] for key in ['preimages_sha256', 'preimages_bytes',
    'candidate_id', 'filesystem_uuid', 'phase_a_plan_sha256', 'phase_a_receipt_sha256',
    'original_accounts_sha256']])
  result.validate()
  return result


def default_identity(value, original_name):
  require(type(value) is dict and set(value) == {'id', 'top_level', 'path'}
          and type(value['id']) is int and value['id'] >= 256
          and type(value['top_level']) is int and value['top_level'] == 5
          and value['path'] == original_name, 'Wrong original default root identity')


@dataclass(frozen=True)
class PhasePlan:
  manifest: object
  maintenance: object
  original_default: object
  writer: WriterPin | None

  def manifest_data(self): return plain(self.manifest)

  def maintenance_data(self): return plain(self.maintenance)


def load_plan(bundle):
  return admit_plan(bundle, read_input(bundle, 'payload'), read_input(bundle, 'plan'))


def admit_plan(bundle, manifest, value):
  """Shared content admission; callers must first authenticate their bytes."""
  manifest = validate_manifest(manifest)
  filesystem = bundle.profile['filesystem']
  require(manifest['candidate_id'] == filesystem['candidate_id']
          and manifest['filesystem_uuid'] == filesystem['uuid']
          and manifest['subvolumes'] == plain(filesystem['subvolumes']),
          'Phase payload and guardian filesystem differ')
  purpose = 'native packages plan' if bundle.phase == 'packages' else 'native layer plan'
  require(set(value) == {'format_version', 'purpose', 'maintenance', 'original_default', 'writer_pin'}
          and type(value['format_version']) is int and value['format_version'] == 1
          and value['purpose'] == purpose, 'Wrong current native plan purpose/fields')
  maintenance = value['maintenance']
  require(type(maintenance) is dict and set(maintenance) == MAINTENANCE_FIELDS
          and maintenance['boot_ready'] is False and maintenance['physical_write_released'] is False,
          'Wrong original package plan scope')
  validate_plan(maintenance, manifest)
  require(maintenance['payload_manifest_sha256'] == bundle.configuration['inputs']['payload']['sha256'],
          'Plan does not bind the exact payload file')
  for key in ['base_image_sha256', 'original_image_account_receipt_sha256']:
    sha(maintenance[key])
  require(set(maintenance['base_account_preimages']) == {'etc/' + name for name in
    ['passwd', 'group', 'shadow', 'gshadow']}, 'Four original account pins required')
  default_identity(value['original_default'], maintenance['original_subvolumes']['root'])
  writer = None
  if bundle.phase == 'packages':
    require(value['writer_pin'] is None, 'Package phase cannot carry a layer writer')
  else:
    writer = writer_pin(value['writer_pin'])
    require(writer.candidate_id == filesystem['candidate_id']
            and writer.filesystem_uuid == filesystem['uuid']
            and writer.layer.payload_manifest_sha256 == bundle.configuration['inputs']['payload']['sha256']
            and writer.layer.archive_sha256 == bundle.configuration['inputs']['layer']['sha256']
            and writer.layer.archive_bytes == bundle.configuration['inputs']['layer']['bytes']
            and hashlib.sha256(canonical(maintenance['base_account_preimages'])).hexdigest()
                == writer.original_accounts_sha256, 'Writer/source/account/capsule pins differ')
    if bundle.phase == 'layer':
      require(writer.preimages_sha256 == bundle.configuration['inputs']['preimages']['sha256']
              and writer.preimages_bytes == bundle.configuration['inputs']['preimages']['bytes'],
              'Expected-A preimages are not independently sealed')
    else:
      require(writer.layer.profile_sha256 == bundle.configuration['guardian_profile_sha256'],
              'Completed layer does not contain this systemd guardian profile')
  return PhasePlan(freeze(manifest), freeze(maintenance), freeze(value['original_default']), writer)


def predecessor(bundle, plan, name, phase):
  value = admit_predecessor(bundle, plan, name, phase, read_input(bundle, name))
  require(value['boot_id'] != bundle.boot_id, 'Predecessor must belong to a distinct prior actual boot')
  return value


def admit_predecessor(bundle, plan, name, phase, value):
  """Content/provenance only; actual running-boot exclusion stays native."""
  require((bundle.phase, name, phase) in {('layer', 'predecessor', 'packages'),
    ('systemd', 'predecessorA', 'packages'), ('systemd', 'predecessorB', 'layer')},
    'Wrong predecessor purpose')
  require(set(value) == RECEIPT_FIELDS and type(value['format_version']) is int
          and value['format_version'] == 1 and value['purpose'] == 'native preparation completion'
          and value['state'] == 'RELEASED_AND_RECOVERED' and value['phase'] == phase,
          'Incomplete native predecessor receipt')
  require(value['candidate_id'] == bundle.profile['filesystem']['candidate_id']
          and value['filesystem_uuid'] == bundle.profile['filesystem']['uuid']
          and value['payload_manifest_sha256'] == bundle.configuration['inputs']['payload']['sha256']
          and value['original_default'] == plan.original_default
          and value['clean_usb_release'] is True and value['authenticated_recovery_observed'] is True
          and value['boot_ready'] is False and value['physical_powerloss_qualified'] is False,
          'Predecessor filesystem/release/recovery scope differs')
  for key in ['payload_manifest_sha256', 'plan_sha256', 'guardian_candidate',
              'configuration_sha256', 'session_id', 'evidence_sha256', 'journal_sha256',
              'worker_result_sha256', 'recovery_observation_sha256']:
    sha(value[key])
  from native_boot_context import UUID
  require(type(value['boot_id']) is str and UUID.fullmatch(value['boot_id'])
          and value['boot_id'] != '00000000-0000-0000-0000-000000000000',
          'Predecessor must belong to a prior distinct actual boot')
  if phase == 'packages':
    require(value['plan_sha256'] == plan.writer.phase_a_plan_sha256
            and bundle.configuration['inputs'][name]['sha256'] == plan.writer.phase_a_receipt_sha256,
            'Phase-A plan/observed completion differs')
  else:
    require(value['plan_sha256'] == bundle.configuration['inputs']['plan']['sha256'],
            'Systemd must consume the exact completed phase-B plan')
  return value
