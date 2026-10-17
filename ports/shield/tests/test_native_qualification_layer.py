"""Private blob packs cannot turn destination paths into tar extraction paths."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent.parent / 'tools'
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location('native_layer_builder', TOOLS / 'prepare-native-qualification-layer.py')
LAYER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAYER)
from usb_root_profile import file_identity


class NativeLayerPackTests(unittest.TestCase):
  def fixture(self):
    temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
    root = Path(temporary.name); (root / 'file').write_bytes(b'explicit synthetic layer bytes')
    (root / 'same').write_bytes((root / 'file').read_bytes())
    (root / 'link').symlink_to('/usr/share/omarchy/config')
    entries = {name: {'identity': file_identity(root, name), 'roles': ['synthetic']}
               for name in ['file', 'same', 'link']}
    return root, entries, {'format_version': 1, 'entries': entries}

  def test_roundtrip_deduplicates_bytes_and_never_archives_destination_symlinks(self):
    root, entries, manifest = self.fixture(); output = root / 'pack.tar.gz'
    _sha, count = LAYER.pack(root, entries, manifest, output)
    self.assertEqual(count, 1)
    LAYER.verify_pack(output, manifest)
    with tarfile.open(output, 'r:gz') as archive:
      self.assertEqual({p.name for p in archive}, {'manifest.json', 'blobs/' + entries['file']['identity']['sha256']})

  def test_changed_source_is_preserved_as_failed_output(self):
    root, entries, manifest = self.fixture(); output = root / 'pack.tar.gz'
    (root / 'file').write_bytes(b'changed')
    with self.assertRaises(ValueError): LAYER.pack(root, entries, manifest, output)
    self.assertTrue(output.exists())
    with self.assertRaises(FileExistsError): LAYER.pack(root, entries, manifest, output)

  def test_symlink_ancestor_cannot_supply_blob_bytes(self):
    root, _entries, _manifest = self.fixture()
    (root / 'outside-parent').symlink_to(root, target_is_directory=True)
    with self.assertRaises(ValueError): file_identity(root, 'outside-parent/file')

  def test_archive_extra_missing_duplicate_or_link_members_are_rejected(self):
    root, entries, manifest = self.fixture()
    canonical = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
    blob = 'blobs/' + entries['file']['identity']['sha256']
    data = (root / 'file').read_bytes()
    for kind in ['extra', 'missing', 'duplicate', 'symlink', 'wrong-bytes']:
      output = root / (kind + '.tar.gz')
      with tarfile.open(output, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        def add(name, content, link=False):
          item = tarfile.TarInfo(name); item.mode = 0o600
          if link: item.type = tarfile.SYMTYPE; item.linkname = '/etc/shadow'
          else: item.size = len(content)
          archive.addfile(item, None if link else io.BytesIO(content))
        add('manifest.json', canonical)
        if kind != 'missing': add(blob, b'x' * len(data) if kind == 'wrong-bytes' else data, kind == 'symlink')
        if kind == 'extra': add('../../outside', b'no')
        if kind == 'duplicate': add(blob, data)
      with self.subTest(kind=kind), self.assertRaises(ValueError): LAYER.verify_pack(output, manifest)


if __name__ == '__main__':
  unittest.main()
