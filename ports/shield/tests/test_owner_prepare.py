"""Preparation command/config/mount-purpose boundaries, no target commands."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch,call

TOOLS=Path(__file__).resolve().parents[1]/'tools'
sys.path.insert(0,str(TOOLS));sys.path.insert(0,str(Path(__file__).parent))
from test_owner_init import init,OwnerInitTests
import native_mounts
from owner_layer import canonical
import owner_command_line as command_line
spec=importlib.util.spec_from_file_location('owner_prepare_target',TOOLS/'owner-prepare.py')
prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)


class OwnerPreparationTests(unittest.TestCase):
  def config(self):
    normal=OwnerInitTests().config()
    payloads={name:dict(bytes=1,sha256='f'*64) for name in
      ['Image','probe.dtb','initramfs.cpio.gz','BOOTSET.json','boot.json','context.json','enrollment.json']}
    for name,data in [('boot.json',normal),('context.json',normal['context']),('enrollment.json',normal['enrollment'])]:
      raw=canonical(data);payloads[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    parent=copy.deepcopy(normal['root_postimages'])
    parent.update({name:dict(bytes=1,mode=0o600,sha256='a'*64) for name in ['etc/passwd','etc/group','etc/shadow','etc/gshadow']})
    return dict(purpose='omarchy-shield-owner-preparation',boot=normal,layer=dict(bytes=1234,sha256='d'*64),
      parent_default=dict(id=5,top_level=None,path=None),parent_postimages=parent,
      sources_sha256=normal['context']['sources_sha256']|{'owner-prepare.py':'e'*64},boot_payloads=payloads)

  def test_distinct_preparation_contract_is_validated_without_effect(self):
    value=self.config();before=copy.deepcopy(value)
    prepare.validate_config(value,init);self.assertEqual(value,before)

  def test_normal_purpose_or_missing_parent_source_cannot_be_adopted(self):
    for kind in ['purpose','parent','source','layer','extra']:
      value=self.config()
      if kind=='purpose':value['purpose']='omarchy-shield-owner'
      elif kind=='parent':del value['parent_postimages']['etc/shadow']
      elif kind=='source':del value['sources_sha256']['owner-prepare.py']
      elif kind=='layer':value['layer']['sha256']='0'*64
      else:value['unknown']=True
      with self.subTest(kind=kind),self.assertRaises(ValueError):prepare.validate_config(value,init)

  def test_persistent_payload_is_complete_bounded_and_binds_normal_config(self):
    for kind in ['missing','wrong','oversize','unknown']:
      value=self.config()
      if kind=='missing':del value['boot_payloads']['Image']
      elif kind=='wrong':value['boot_payloads']['boot.json']['sha256']='0'*64
      elif kind=='oversize':value['boot_payloads']['Image']['bytes']=129*1024**2
      else:value['boot_payloads']['../other']=dict(bytes=1,sha256='a'*64)
      with self.subTest(kind=kind),self.assertRaises(ValueError):prepare.validate_config(value,init)

  def test_default_selection_parser_ignores_generation_only(self):
    self.assertEqual(prepare.default_subvolume(b'ID 256 gen 5 top level 5 path @original\n'),
                     prepare.default_subvolume(b'ID 256 gen 999 top level 5 path @original\n'))
    for raw in [b'',b'ID 5 (FS_TREE)',b'ID 256 unexpected\n']:
      with self.assertRaises(ValueError):prepare.default_subvolume(raw)

  def test_only_fixed_snapshot_and_default_commands_allowed(self):
    prepare.command_allowed(['/usr/bin/btrfs','subvolume','get-default','/run/shield-usb'])
    prepare.command_allowed(['/usr/bin/btrfs','subvolume','snapshot','/run/shield-usb/@shield-'+'a'*32,
      '/run/shield-usb/@shield-'+'b'*32])
    for argv in [['/bin/sh','-c','anything'],['/usr/bin/btrfs','subvolume','delete','/run/shield-usb'],
      ['/usr/bin/btrfs','subvolume','snapshot','/tmp/base','/tmp/new'],
      ['/usr/bin/btrfs','subvolume','snapshot','/run/shield-usb/../other','/run/shield-usb/@shield-'+'b'*32]]:
      with self.assertRaises(ValueError):prepare.command_allowed(argv)

  def test_expired_budget_does_not_spawn(self):
    with patch.object(prepare.subprocess,'Popen') as spawn,self.assertRaises(ValueError):
      prepare.run(['/usr/bin/btrfs','subvolume','get-default','/run/shield-usb'],0,lambda:None,[])
    spawn.assert_not_called()

  def test_owned_child_is_waited_and_group_absence_observed(self):
    child=Mock(pid=100,returncode=0);child.communicate.return_value=(b'ID 5 (FS_TREE)\n',b'')
    clients=[]
    with patch.object(prepare.subprocess,'Popen',return_value=child),patch.object(prepare.os,'killpg',side_effect=ProcessLookupError):
      raw=prepare.run(['/usr/bin/btrfs','subvolume','get-default','/run/shield-usb'],
        prepare.time.clock_gettime_ns(prepare.time.CLOCK_BOOTTIME)+10*prepare.SECOND,lambda:None,clients)
    self.assertEqual(prepare.default_subvolume(raw)['id'],5)
    self.assertEqual(clients,[dict(actual_wait_exit=0,positive_wait=True,group_absent=True,timed_out=False)])

  def test_timeout_reap_is_fatal_and_not_a_retry(self):
    child=Mock(pid=100,returncode=-9)
    child.communicate.side_effect=[prepare.subprocess.TimeoutExpired('fixed',1),(b'',b'')]
    clients=[]
    with patch.object(prepare.subprocess,'Popen',return_value=child), \
      patch.object(prepare.os,'killpg',side_effect=[None,ProcessLookupError]),self.assertRaises(prepare.ChildClosureError):
      prepare.run(['/usr/bin/btrfs','subvolume','get-default','/run/shield-usb'],
        prepare.time.clock_gettime_ns(prepare.time.CLOCK_BOOTTIME)+10*prepare.SECOND,lambda:None,clients)
    self.assertEqual(child.communicate.call_count,2);self.assertTrue(clients[0]['positive_wait'])

  def test_non_pid1_entry_refuses_before_import_or_config(self):
    with patch.object(prepare.os,'getpid',return_value=999),patch.object(prepare,'local_module') as module, \
      self.assertRaises(ValueError):prepare.main()
    module.assert_not_called()

  def domain(self,phase='owner-prepare',purpose='omarchy-shield-owner-preparation',readonly=True):
    value=object.__new__(native_mounts.MountDomain)
    value.bundle=SimpleNamespace(phase=phase,configuration=dict(purpose=purpose),profile=dict(purpose='omarchy-shield-owner'))
    value.mounted={native_mounts.TOP:(1,readonly)}
    value._unmount=Mock();value._mount=Mock();value.device=SimpleNamespace(verify_superblock=Mock())
    return value

  def test_preparation_mount_gate_is_distinct_and_requires_readonly_first(self):
    for phase,purpose,readonly in [('layer','omarchy-shield-owner-preparation',True),
      ('owner','omarchy-shield-owner-preparation',True),('owner-prepare','qualification',True),
      ('owner-prepare','omarchy-shield-owner-preparation',False)]:
      value=self.domain(phase,purpose,readonly)
      with self.assertRaises(ValueError):value.owner_preparation_rw(123)
      value._mount.assert_not_called();value._unmount.assert_not_called()
    value=self.domain();value.owner_preparation_rw(123)
    value._unmount.assert_called_once_with(native_mounts.TOP,123)
    value.device.verify_superblock.assert_called_once_with()
    value._mount.assert_called_once_with(native_mounts.TOP,None,False,123)

  def test_command_line_purposes_are_disjoint_and_data_bound(self):
    a=command_line.normal(b'boot',b'context').decode().split()
    b=command_line.preparation(b'preparation').decode().split()
    self.assertIn('systemd.unit=graphical.target',a)
    self.assertFalse(any(x.startswith('systemd.unit=') for x in b))
    self.assertFalse(any(x.startswith(('shield.guardian=','shield.native-bundle=')) for x in a+b))
    self.assertNotEqual(command_line.normal(b'boot',b'context'),command_line.normal(b'changed',b'context'))
    self.assertNotEqual(command_line.preparation(b'prepare'),command_line.preparation(b'changed'))
