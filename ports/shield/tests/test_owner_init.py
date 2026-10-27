"""OWNER early-boot source boundaries; no PID1, USB, mount or handoff effects."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).parent))
from test_owner_profile import enrollment, context
spec = importlib.util.spec_from_file_location('owner_init_target', TOOLS / 'owner-init.py')
init = importlib.util.module_from_spec(spec)
spec.loader.exec_module(init)


class OwnerInitTests(unittest.TestCase):
  def config(self):
    enrolled = enrollment()
    ctx = context(enrolled)
    ctx['sources_sha256'] = {name: 'a'*64 for name in init.BOOT_SOURCES}
    ctx['enrollment_sha256'] = hashlib.sha256(init.canonical(enrolled)).hexdigest()
    result = dict(purpose='omarchy-shield-owner', enrollment=enrolled, context=ctx,
      root_postimages={name: dict(bytes=1, sha256='b'*64, mode=0o755) for name in init.CORE_FILES})
    result['root_postimages'].update({name:dict(bytes=1,sha256='c'*64,mode=0o644) for name in init.DESKTOP_FILES})
    from owner_layer import preparation
    result['preparation'] = preparation(enrolled, ctx, 'd'*64)
    return result

  def test_current_boot_contract_is_pure(self):
    value = self.config()
    before = copy.deepcopy(value)
    enrolled, ctx = init.validate_boot(value)
    self.assertEqual(value, before)
    self.assertEqual(enrolled['purpose'], 'omarchy-shield-owner')
    self.assertEqual(set(ctx['sources_sha256']), init.BOOT_SOURCES)

  def test_boot_enrollment_bytes_and_source_closure_are_bound(self):
    for kind in ['digest', 'missing', 'extra', 'purpose']:
      value = self.config()
      if kind == 'digest': value['context']['enrollment_sha256'] = 'd'*64
      elif kind == 'missing': del value['context']['sources_sha256']['native_mounts.py']
      elif kind == 'extra': value['context']['sources_sha256']['decoy.py'] = 'e'*64
      else: value['purpose'] = 'qualification'
      with self.subTest(kind=kind), self.assertRaises(ValueError): init.validate_boot(value)

  def test_missing_core_unexecutable_or_unknown_fields_refused(self):
    for kind in ['core', 'permission', 'extra', 'unknown']:
      value = self.config()
      name = sorted(init.CORE_FILES)[0]
      if kind == 'core': del value['root_postimages'][name]
      elif kind == 'permission': value['root_postimages'][name]['mode'] = 0o600
      elif kind == 'extra': value['root_postimages'][name]['extra'] = True
      else: value['unknown'] = True
      with self.subTest(kind=kind), self.assertRaises(ValueError): init.validate_boot(value)

  def test_unsafe_root_paths_refused(self):
    for name in ['', '/', '/etc/passwd', '../etc/passwd', 'etc/../passwd', './etc/passwd',
                 'etc//passwd', 'etc/./passwd', 'etc/passwd\n', 'etc/white space']:
      with self.subTest(name=name), self.assertRaises(ValueError): init.relative(name)
    self.assertEqual(init.relative('usr/lib/systemd/systemd'), 'usr/lib/systemd/systemd')

  def test_parent_symlink_or_writable_directory_refused(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      (root/'real').mkdir(mode=0o755)
      (root/'redirect').symlink_to(root/'real', target_is_directory=True)
      with self.assertRaises(ValueError): init.safe_path(root, 'redirect/file')
      (root/'real').chmod(0o777)
      with self.assertRaises(ValueError): init.safe_path(root, 'real/file')

  def test_absent_removal_parent_is_accepted_only_when_explicit(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      self.assertEqual(init.safe_path(root, 'absent/file', missing_parents=True), root/'absent/file')
      with self.assertRaises(ValueError): init.safe_path(root, 'absent/file')

  def test_observe_file_checks_hash_size_and_existing_deadline(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      (root/'sample').write_bytes(b'actual')
      (root/'sample').chmod(0o644)
      item = dict(bytes=6, mode=0o644, sha256=hashlib.sha256(b'actual').hexdigest())
      deadline = init.time.clock_gettime_ns(init.time.CLOCK_BOOTTIME)+init.SECOND
      init.observe_file(root, 'sample', item, deadline)
      with self.assertRaises(ValueError): init.observe_file(root, 'sample', item|{'sha256':'0'*64}, deadline)
      with patch.object(init, 'regular') as read, self.assertRaises(ValueError):
        init.observe_file(root, 'sample', item, 0)
      read.assert_not_called()

  def test_non_pid1_refuses_before_config_or_hardware_access(self):
    with patch.object(init.os, 'getpid', return_value=100), patch.object(init, 'regular') as read, \
      self.assertRaises(ValueError): init.load()
    read.assert_not_called()

  def test_missing_or_changed_preparation_is_refused(self):
    for kind in ['missing','hash','path','layer']:
      value=self.config()
      if kind=='missing':del value['preparation']
      elif kind=='hash':value['preparation']['sha256']='0'*64
      elif kind=='path':value['preparation']['path']='../PREPARED.json'
      else:value['preparation']['layer_sha256']='e'*64
      with self.subTest(kind=kind),self.assertRaises(ValueError):init.validate_boot(value)

  def test_marker_readback_precedes_candidate_root_access(self):
    value=self.config()
    with patch.object(init,'observe_file',side_effect=ValueError('marker absent')) as observe, \
      patch.object(init,'safe_path') as paths,self.assertRaises(ValueError):
      init.root_admission(Path('/admitted-top'),value,123)
    self.assertEqual(observe.call_args.args[1],value['preparation']['path'])
    paths.assert_not_called()

  def test_matched_desktop_sources_are_required(self):
    for kind in ['missing','mode']:
      value=self.config();name=sorted(init.DESKTOP_FILES)[0]
      if kind=='missing':del value['root_postimages'][name]
      else:value['root_postimages'][name]['mode']=0o755
      with self.assertRaises(ValueError):init.validate_boot(value)
