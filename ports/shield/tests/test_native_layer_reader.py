"""Hash-first own-producer content tests; no native writer or device fixture."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent.parent / 'tools'
sys.path.insert(0, str(TOOLS))
import native_layer_reader as READER
from usb_root_profile import file_identity
SPEC = importlib.util.spec_from_file_location('reader_fixture_host_producer', TOOLS / 'prepare-native-qualification-layer.py')
PRODUCER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCER)


class NativeLayerReaderTests(unittest.TestCase):
  def fixture(self):
    temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
    root = Path(temporary.name); data = b'explicit synthetic own-producer bytes'
    (root / 'file').write_bytes(data)
    entries = {'file': {'identity': file_identity(root, 'file'), 'roles': ['synthetic, not native eligible']}}
    value = {'format_version': 1, 'purpose': READER.PURPOSE, 'state': 'HOST_LAYER_PREPARED',
      'sources': {'tools/explicit-synthetic.py': '1' * 64}, 'profile_sha256': '2' * 64,
      'payload_manifest_sha256': '3' * 64, 'entries': entries,
      'physical_preimages_admitted': False, 'physical_write_released': False, 'boot_ready': False}
    archive = root / 'layer.tar.gz'
    manifest_sha, _count = PRODUCER.pack(root, entries, value, archive)
    pin = READER.LayerPin(hashlib.sha256(archive.read_bytes()).hexdigest(), archive.stat().st_size,
      manifest_sha, '2' * 64, '3' * 64, (('tools/explicit-synthetic.py', '1' * 64),))
    return archive, pin, data

  def test_valid_pinned_content_has_readonly_blobs_and_no_write_authority(self):
    archive, pin, data = self.fixture()
    result = READER.read_layer(archive, pin)
    blob = result.blob(hashlib.sha256(data).hexdigest())
    self.assertEqual(bytes(blob), data); self.assertTrue(blob.readonly)
    self.assertFalse(result.physical_preimages_admitted)
    self.assertFalse(result.physical_write_authority)
    with self.assertRaises(TypeError): result.blob_ranges['new'] = (0, 0)
    with self.assertRaises(TypeError): result.manifest['state'] = 'BOOTABLE'
    with self.assertRaises(TypeError): result.manifest['entries']['file']['identity']['bytes'] = 0
    with self.assertRaises(FrozenInstanceError): pin.archive_sha256 = '4' * 64

  def test_modified_archive_never_reaches_any_decompressor(self):
    archive, pin, _data = self.fixture()
    value = bytearray(archive.read_bytes()); value[len(value) // 2] ^= 1; archive.write_bytes(value)
    with patch.object(READER.zlib, 'decompressobj') as decoder:
      with self.assertRaises(ValueError): READER.read_layer(archive, pin)
      decoder.assert_not_called()

  def test_wrong_sealed_digest_or_length_cannot_be_replaced_by_archive_data(self):
    archive, pin, _data = self.fixture()
    for bad in [replace(pin, archive_sha256='4' * 64), replace(pin, archive_bytes=pin.archive_bytes - 1)]:
      with self.subTest(pin=bad), patch.object(READER.zlib, 'decompressobj') as decoder:
        with self.assertRaises(ValueError): READER.read_layer(archive, bad)
        decoder.assert_not_called()

  def test_original_path_mutation_after_hash_does_not_change_parsed_bytes(self):
    archive, pin, data = self.fixture()
    factory = READER.zlib.decompressobj
    class Decoder:
      def __init__(self): self.inner = factory(31)
      def decompress(self, value, limit):
        self.verified_bytes = isinstance(value, bytes)
        archive.write_bytes(b'x' * pin.archive_bytes)
        return self.inner.decompress(value, limit)
      def __getattr__(self, name): return getattr(self.inner, name)
    decoder = Decoder()
    with patch.object(READER.zlib, 'decompressobj', return_value=decoder):
      result = READER.read_layer(archive, pin)
    self.assertTrue(decoder.verified_bytes)
    self.assertEqual(bytes(result.blob(hashlib.sha256(data).hexdigest())), data)

  def test_wrong_profile_or_source_cohort_is_refused(self):
    archive, pin, _data = self.fixture()
    for bad in [replace(pin, profile_sha256='4' * 64),
                replace(pin, sources=(('tools/other.py', '1' * 64),))]:
      with self.subTest(pin=bad), self.assertRaises(ValueError): READER.read_layer(archive, bad)

  def test_expansion_and_declared_blob_budgets_are_enforced(self):
    archive, pin, _data = self.fixture()
    with patch.object(READER, 'MAX_TAR_BYTES', 512), patch.object(READER.tarfile, 'open') as parser:
      with self.assertRaises(ValueError): READER.read_layer(archive, pin)
      parser.assert_not_called()
    with patch.object(READER, 'MAX_BLOB_BYTES', 1):
      with self.assertRaises(ValueError): READER.read_layer(archive, pin)

  def test_bad_crc_truncation_and_concatenated_gzip_are_refused(self):
    archive, pin, _data = self.fixture(); original = archive.read_bytes()
    crc = bytearray(original); crc[-8] ^= 1
    for bad in [bytes(crc), original[:-1], original + original]:
      archive.write_bytes(bad)
      admitted_bad_producer = replace(pin, archive_bytes=len(bad), archive_sha256=hashlib.sha256(bad).hexdigest())
      with self.subTest(size=len(bad)), self.assertRaises(ValueError): READER.read_layer(archive, admitted_bad_producer)

  def test_manifest_duplicate_keys_or_nonfinite_constants_are_refused(self):
    archive, pin, _data = self.fixture()
    for raw in [b'{"format_version":1,"format_version":1}', b'{"value":NaN}']:
      malformed = replace(pin, manifest_sha256=hashlib.sha256(raw).hexdigest())
      with self.subTest(raw=raw), self.assertRaises(ValueError): READER.manifest(raw, malformed)


if __name__ == '__main__':
  unittest.main()
