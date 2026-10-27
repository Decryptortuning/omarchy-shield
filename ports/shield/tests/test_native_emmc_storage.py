"""Exact enrolled active GPT admission; no block, mount or target operations."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_emmc_storage import admit_table, canonical


def fixture():
  rows = [{'index': index, 'start_bytes': index * 1024**2,
           'bytes': 1024**2, 'label': 'P' + str(index)}
          for index in range(1, 34) if index not in (20, 21)]
  rows[-1].update(label='UDA', bytes=100 * 1024**2)
  expected = {'disk_bytes': 30777344 * 512, 'partition_index': 33,
    'partition_label': 'UDA', 'partition_start_bytes': rows[-1]['start_bytes'],
    'partition_bytes': rows[-1]['bytes'],
    'partition_table_sha256': hashlib.sha256(canonical(rows)).hexdigest()}
  boot = rows[18]
  store = {'partition_index': 19, 'partition_label': 'APP',
    'partition_start_bytes': boot['start_bytes'], 'partition_bytes': boot['bytes']}
  rows[18]['label'] = 'APP'
  expected['partition_table_sha256'] = hashlib.sha256(canonical(rows)).hexdigest()
  return rows, expected, store


class InternalTableTests(unittest.TestCase):
  def test_deleted_android_slots_do_not_require_dummy_partitions(self):
    rows, expected, store = fixture()
    self.assertEqual(len(rows), 31)
    admit_table(rows, expected, store)

  def test_any_changed_boot_partition_requires_new_enrollment(self):
    rows, expected, store = fixture()
    rows[0]['start_bytes'] -= 512
    with self.assertRaisesRegex(ValueError, 'complete partition geometry'):
      admit_table(rows, expected, store)

  def test_selected_root_identity_is_separately_required(self):
    for field, value in [('partition_index', 32), ('partition_label', 'APP'),
                         ('partition_start_bytes', 34 * 1024**2),
                         ('partition_bytes', 99 * 1024**2)]:
      with self.subTest(field=field):
        rows, expected, store = fixture()
        expected[field] = value
        with self.assertRaisesRegex(ValueError, 'selected UDA'):
          admit_table(rows, expected, store)

  def test_malformed_tables_refuse_even_if_digest_matches(self):
    def duplicate_index(rows): rows[1]['index'] = rows[0]['index']
    def duplicate_label(rows): rows[1]['label'] = rows[0]['label']
    def overlap(rows): rows[1]['start_bytes'] = rows[0]['start_bytes'] + 512
    def zero_size(rows): rows[1]['bytes'] = 0
    def non_sector(rows): rows[1]['bytes'] += 1
    def outside_disk(rows): rows[-1]['bytes'] = 30777344 * 512
    def bool_index(rows): rows[0]['index'] = True
    def wrong_order(rows): rows.reverse()
    def missing_root(rows): rows.pop()
    def extra_field(rows): rows[0]['unused'] = True
    for mutate in [duplicate_index, duplicate_label, overlap, zero_size, non_sector,
                   outside_disk, bool_index, wrong_order, missing_root, extra_field]:
      with self.subTest(case=mutate.__name__):
        rows, expected, store = fixture()
        mutate(rows)
        expected['partition_table_sha256'] = hashlib.sha256(canonical(rows)).hexdigest()
        with self.assertRaises(ValueError):
          admit_table(rows, expected, store)

  def test_boot_store_must_match_exact_app_record(self):
    rows, expected, store = fixture()
    store['partition_start_bytes'] += 512
    with self.assertRaisesRegex(ValueError, 'selected APP'):
      admit_table(rows, expected, store)

  def test_input_records_are_not_rewritten(self):
    rows, expected, store = fixture()
    before = copy.deepcopy((rows, expected, store))
    admit_table(rows, expected, store)
    self.assertEqual((rows, expected, store), before)


if __name__ == '__main__':
  unittest.main()
