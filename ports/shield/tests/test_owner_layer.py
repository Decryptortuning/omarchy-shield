"""OWNER archive/marker boundaries and real isolated filesystem application."""
import copy
import gzip
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).parent))
import owner_layer as layer
import owner_profile as profile
from test_owner_profile import enrollment, context


def fixture():
  enrolled = enrollment()
  private = b'fixture private bytes; no cryptographic capability claim\n'
  enrolled['ssh']['host_private_identity'] = {'bytes':len(private), 'sha256':hashlib.sha256(private).hexdigest()}
  ctx = context(enrolled)
  source = b'# fixture source payload, never executed\n'
  ctx['sources_sha256'] = {name:hashlib.sha256(source).hexdigest() for name in ctx['sources_sha256']}
  policy = profile.render(enrolled)
  files = copy.deepcopy(policy['files'])
  for name in ctx['sources_sha256']:
    files[profile.INSTALL.lstrip('/')+'/'+name] = dict(data=source, mode=0o644, uid=0, gid=0)
  files['etc/ssh/ssh_host_ed25519_key'] = dict(data=private, mode=0o600, uid=0, gid=0)
  module = b'fixture module, not executable'
  firmware = b'fixture firmware'
  enrolled['ethernet']['module'] = {'bytes':len(module), 'sha256':hashlib.sha256(module).hexdigest()}
  enrolled['ethernet']['firmware'] = {name:{'bytes':len(firmware), 'sha256':hashlib.sha256(firmware).hexdigest()}
                                    for name in enrolled['ethernet']['firmware']}
  # Enrollment file reflects the final fixture identities.
  policy = profile.render(enrolled)
  files.update(policy['files'])
  files[profile.MODULE] = dict(data=module,mode=0o644,uid=0,gid=0)
  for name in enrolled['ethernet']['firmware']:
    files[name] = dict(data=firmware,mode=0o644,uid=0,gid=0)
  seed = b'require("default.hypr.omarchy")\n'
  seed_info = {'bytes':len(seed),'sha256':hashlib.sha256(seed).hexdigest(),'mode':0o644}
  item = policy['home_seed']
  files[item['target']] = dict(data=seed,mode=item['mode'],uid=item['uid'],gid=item['gid'])
  old = '@shield-'+'b'*32
  manifest = dict(purpose='omarchy-shield-owner', owner_id=enrolled['owner_id'], filesystem=enrolled['filesystem'],
    base_subvolumes=dict(root=old,home=old+'-home',log=old+'-log'),
    files={name:dict(bytes=len(v['data']),sha256=hashlib.sha256(v['data']).hexdigest(),mode=v['mode'],uid=v['uid'],gid=v['gid'],volume='home' if name.startswith('home/') else 'root') for name,v in files.items()},
    directories=policy['directories'],links=policy['links'],removals=policy['removals'],home_removals=policy['home_removals'],
    normal_home_seed_in_layer=True,normal_first_run_complete=False,base_full_filesystem_reverified=False,physical_root_prepared=False,boot_ready=False)
  ctx['enrollment_sha256']=hashlib.sha256(layer.canonical(enrolled)).hexdigest()
  return manifest,{name:v['data'] for name,v in files.items()},enrolled,ctx,{item['source']:seed_info}


def archive(rows):
  data=io.BytesIO()
  with tarfile.open(fileobj=data,mode='w',format=tarfile.USTAR_FORMAT) as tf:
    for name,raw,kind in rows:
      item=tarfile.TarInfo(name);item.mode=0o600;item.uid=item.gid=0
      item.type=kind;item.size=len(raw) if kind==tarfile.REGTYPE else 0
      tf.addfile(item,io.BytesIO(raw) if kind==tarfile.REGTYPE else None)
  return gzip.compress(data.getvalue(),mtime=0)


class OwnerLayerTests(unittest.TestCase):
  def test_complete_payload_contract_is_validated_without_writes(self):
    args=fixture()
    self.assertIs(layer.validate_layer(*args),args[0])

  def test_unknown_or_missing_payload_is_refused(self):
    for extra in [True,False]:
      args=list(fixture());args[1]=dict(args[1])
      if extra:args[1]['etc/unreviewed']=b'extra'
      else:args[1].pop(next(iter(args[1])))
      with self.assertRaises(ValueError):layer.validate_layer(*args)

  def test_changed_privileged_payload_hash_or_uid_is_refused(self):
    for kind in ['payload','hash','uid','routing','mode']:
      args=list(fixture());name='etc/ssh/sshd_config'
      if kind=='payload':args[1][name]+=b'PasswordAuthentication yes\n'
      elif kind=='hash':args[0]['files'][name]['sha256']='0'*64
      elif kind=='uid':args[0]['files'][name]['uid']=1001
      elif kind=='mode':args[0]['files'][name]['mode']=0o666
      else:args[0]['files'][name]['volume']='home'
      with self.subTest(kind=kind),self.assertRaises(ValueError):layer.validate_layer(*args)

  def test_wrong_snapshot_parent_or_overclaimed_state_is_refused(self):
    for kind in ['same','escape','ready','first_run','unknown']:
      args=list(fixture())
      if kind=='same':args[0]['base_subvolumes']=copy.deepcopy(args[2]['filesystem']['subvolumes'])
      elif kind=='escape':args[0]['base_subvolumes']['home']='../other'
      elif kind=='ready':args[0]['boot_ready']=True
      elif kind=='first_run':args[0]['normal_first_run_complete']=True
      else:args[0]['unknown']=True
      with self.subTest(kind=kind),self.assertRaises(ValueError):layer.validate_layer(*args)

  def test_marker_binds_enrollment_context_layer_without_cleanup_claim(self):
    _,_,enrolled,ctx,_=fixture()
    item=layer.preparation(enrolled,ctx,'a'*64)
    layer.validate_marker(item,enrolled,ctx)
    self.assertEqual(item,layer.preparation(enrolled,ctx,'a'*64))
    self.assertFalse(layer.marker(enrolled,ctx,'a'*64)['cleanup_qualified'])
    self.assertNotEqual(item,layer.preparation(enrolled,ctx,'b'*64))
    for change in [{'bytes':float(item['bytes'])},{'path':'../PREPARED.json'}, {'sha256':'b'*64}]:
      with self.assertRaises(ValueError):layer.validate_marker(item|change,enrolled,ctx)

  def test_archive_roundtrip_is_data_only(self):
    m,p,_,_,_=fixture()
    rows=[('manifest.json',layer.canonical(m),tarfile.REGTYPE)]+[('files/'+n,b,tarfile.REGTYPE) for n,b in p.items()]
    parsed,data=layer.read_archive(archive(rows))
    self.assertEqual(parsed,m);self.assertEqual(data,p)

  def test_archive_symlinks_hardlinks_escape_duplicate_and_unknown_are_refused(self):
    manifest=('manifest.json',b'{}',tarfile.REGTYPE)
    for row in [('files/x',b'',tarfile.SYMTYPE),('files/x',b'',tarfile.LNKTYPE),
                ('files/../escape',b'x',tarfile.REGTYPE),('unknown',b'x',tarfile.REGTYPE),manifest]:
      with self.subTest(row=row[0]),self.assertRaises(ValueError):layer.read_archive(archive([manifest,row]))

  def roots(self,base):
    roots={name:Path(base)/name for name in ['root','home','log']}
    for path in roots.values():path.mkdir(mode=0o755)
    return roots

  def test_real_filesystem_apply_routes_home_and_preserves_base(self):
    m,p,enrolled,ctx,images=fixture();layer.validate_layer(m,p,enrolled,ctx,images)
    with tempfile.TemporaryDirectory() as base:
      roots=self.roots(base);(roots['root']/'untouched').write_bytes(b'base unchanged')
      guard=Mock();tree=layer.Tree(roots,guard)
      fds=list(tree.fds.values())
      try:tree.apply(m,p)
      finally:tree.close()
      self.assertEqual((roots['root']/'untouched').read_bytes(),b'base unchanged')
      self.assertFalse((roots['root']/'home/shieldqual/.bash_profile').exists())
      home=roots['home']/'shieldqual/.config/hypr/hyprland.lua'
      self.assertEqual(home.read_bytes(),p['home/shieldqual/.config/hypr/hyprland.lua'])
      self.assertEqual((home.stat().st_uid,home.stat().st_gid),(1001,1001))
      self.assertEqual((roots['root']/'etc/ssh/authorized_keys').stat().st_mode&0o777,0o755)
      self.assertTrue((roots['root']/'etc/systemd/system/default.target').is_symlink())
      self.assertGreater(guard.call_count,1)
      for fd in fds:
        with self.assertRaises(OSError):os.fstat(fd)

  def test_stock_polkit_group_parent_allows_full_apply_without_changing_parent(self):
    m,p,enrolled,ctx,images=fixture();layer.validate_layer(m,p,enrolled,ctx,images)
    retired=next(name for name in m['removals'] if name.startswith('etc/polkit-1/rules.d/'))
    with tempfile.TemporaryDirectory() as base:
      roots=self.roots(base);target=roots['root']/retired
      target.parent.mkdir(parents=True,mode=0o750)
      os.chown(target.parent,0,102);os.chmod(target.parent,0o750)
      target.write_bytes(b'old bounded qualification policy')
      tree=layer.Tree(roots,lambda:None)
      try:tree.apply(m,p)
      finally:tree.close()
      self.assertFalse(target.exists())
      parent=target.parent.stat()
      self.assertEqual((parent.st_uid,parent.st_gid,parent.st_mode&0o777),(0,102,0o750))
      self.assertEqual((roots['root']/'etc/ssh/sshd_config').read_bytes(),p['etc/ssh/sshd_config'])

  def test_writable_or_nonroot_system_group_parent_refuses_mutation(self):
    for uid,gid,mode in [(0,102,0o770),(1001,102,0o750)]:
      with self.subTest(uid=uid,mode=mode),tempfile.TemporaryDirectory() as base:
        roots=self.roots(base);parent=roots['root']/'rules';parent.mkdir()
        old=parent/'retired';old.write_bytes(b'preserve')
        os.chown(parent,uid,gid);os.chmod(parent,mode)
        tree=layer.Tree(roots,lambda:None)
        try:
          with self.assertRaises(ValueError):tree.remove('rules/retired')
          with self.assertRaises(ValueError):tree.write('rules/new',dict(mode=0o644,uid=0,gid=0),b'blocked')
        finally:tree.close()
        self.assertEqual(old.read_bytes(),b'preserve')
        self.assertFalse((parent/'new').exists())

  def test_parent_symlink_never_writes_outside_selected_root(self):
    with tempfile.TemporaryDirectory() as base:
      roots=self.roots(base);outside=Path(base)/'outside';outside.mkdir();(roots['root']/'etc').symlink_to(outside,target_is_directory=True)
      tree=layer.Tree(roots,lambda:None)
      try:
        with self.assertRaises(OSError):tree.write('etc/escaped',dict(mode=0o644,uid=0,gid=0),b'blocked')
      finally:tree.close()
      self.assertEqual(list(outside.iterdir()),[])

  def test_existing_directory_or_hardlink_cannot_be_replaced_as_file(self):
    for kind in ['directory','hardlink']:
      with tempfile.TemporaryDirectory() as base:
        roots=self.roots(base);target=roots['root']/'object'
        if kind=='directory':target.mkdir()
        else:
          target.write_bytes(b'original');os.link(target,roots['root']/'second')
        tree=layer.Tree(roots,lambda:None)
        try:
          with self.assertRaises(ValueError):tree.write('object',dict(mode=0o644,uid=0,gid=0),b'changed')
        finally:tree.close()
        self.assertTrue(target.is_dir() if kind=='directory' else target.read_bytes()==b'original')

  def test_expired_guard_refuses_before_write_and_does_not_leak_fds(self):
    with tempfile.TemporaryDirectory() as base:
      roots=self.roots(base);tree=layer.Tree(roots,lambda:None)
      tree.guard=Mock(side_effect=ValueError('expired'))
      try:
        with self.assertRaises(ValueError):tree.write('blocked',dict(mode=0o644,uid=0,gid=0),b'data')
      finally:tree.close()
      self.assertFalse((roots['root']/'blocked').exists())

  def test_absent_policy_removal_is_safe_and_log_writes_are_refused(self):
    with tempfile.TemporaryDirectory() as base:
      roots=self.roots(base);tree=layer.Tree(roots,lambda:None)
      try:
        tree.remove('etc/missing/old-policy');tree.remove('home/shieldqual/.local/absent')
        for name in ['var/log','var/log/file','home/../root/file']:
          with self.assertRaises(ValueError):tree.route(name)
      finally:tree.close()
