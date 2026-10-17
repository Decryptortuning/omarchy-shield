#!/usr/bin/env python3
"""Prepare a NEW host-only qualification root; never select or boot it.

WSL Ubuntu24.04 root only. A failed output is retained and cannot be reused.
All ARM account/theme commands use the reviewed chroot helper inside a fresh
network namespace. No enabled guardian, target activation or physical IO here.
"""
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys

from qualification_profile import GID, HOME, UID, USER, account_plan, render
from maintenance_accounts import (ACCOUNT_NAMES, account_preimages, original_account_baseline,
  original_baseline_from_record, validate_accounts)
from usb_root_profile import digest, require, rooted, safe_relative, verify_root

CHROOT_SHA256 = '1aeb2fd5343bb3ce6b72448913ca3dc1a1e417d5b6b28a8bc5ee4fa6419d9b24'
GROUPS = ('video', 'render', 'audio', 'input')
# No build user data, runtime mounts, copied private trust or SSH host keys.
EXCLUDES = ('/build', '/home/portbuild', '/root', '/etc/pacman.d/gnupg',
            '/etc/ssh/ssh_host_*', '/dev/***', '/proc/***', '/sys/***',
            '/run/***', '/tmp/***', '/mnt/***', '/media/***')
THEME_SCRIPT = r'''set -euo pipefail
/usr/bin/install -d -o 1001 -g 1001 -m 0700 /run/user/1001
exec /usr/bin/runuser -u shieldqual -- /usr/bin/env -i \
 HOME=/home/shieldqual USER=shieldqual LOGNAME=shieldqual SHELL=/bin/bash \
 PATH=/usr/share/omarchy/bin:/usr/local/bin:/usr/bin TERM=dumb LC_ALL=C \
 XDG_CONFIG_HOME=/home/shieldqual/.config XDG_STATE_HOME=/home/shieldqual/.local/state \
 XDG_CACHE_HOME=/home/shieldqual/.cache XDG_RUNTIME_DIR=/run/user/1001 \
 OMARCHY_PATH=/usr/share/omarchy OMARCHY_THEME_HEADLESS=1 OMARCHY_THEME_WAIT=1 \
 QEMU_CPU=cortex-a57 /usr/share/omarchy/bin/omarchy-theme-set 'Tokyo Night'
'''


def real_directory(path):
  require(not path.is_symlink() and path.is_dir(), 'Expected real directory')
  return path.resolve(strict=True)


def regular(path):
  info = path.lstat()
  require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Expected unshared regular input')
  return info


def locked_directory(path):
  info = path.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
          and stat.S_IMODE(info.st_mode) == 0o700, 'Expected private root-owned directory')


def wsl_root():
  require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
          'Run as WSL Ubuntu24.04 root')
  require('microsoft' in Path('/proc/sys/kernel/osrelease').read_text().lower(),
          'Only WSL hosts are admitted')
  release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                 if '=' in line and not line.startswith('#'))
  require(release.get('ID', '').strip('"') == 'ubuntu' and
          release.get('VERSION_ID', '').strip('"') == '24.04', 'Expected Ubuntu24.04 host')


def matched_json(path, expected):
  regular(path)
  require(re.fullmatch('[0-9a-f]{64}', expected) is not None and digest(path) == expected,
          'Pinned manifest bytes differ')
  return json.loads(path.read_text())


def tables(root):
  result = {}
  for name, width in [('passwd', 7), ('group', 4), ('shadow', 9), ('gshadow', 4)]:
    path = rooted(root, 'etc/' + name)
    regular(path)
    rows = {}
    for line in path.read_text().splitlines():
      values = line.split(':')
      require(len(values) == width and values[0] and values[0] not in rows,
              'Malformed or duplicate account database entry')
      rows[values[0]] = values
    result[name] = rows
  return result


def account_preflight(root):
  t = tables(root)
  passwd, groups = t['passwd'], t['group']
  require('root' in passwd and passwd['root'][2:4] == ['0', '0'] and
          'portbuild' in passwd and passwd['portbuild'][2] == '1000', 'Unexpected reference accounts')
  require([name for name, row in passwd.items() if row[2] == '0'] == ['root'],
          'Multiple root identities')
  require(USER not in passwd and USER not in groups and USER not in t['shadow'] and USER not in t['gshadow'],
          'Qualification identity already exists')
  require(all(int(row[2]) != UID for row in passwd.values()) and
          all(int(row[3]) != GID for row in passwd.values()) and
          all(int(row[2]) != GID for row in groups.values()), 'Qualification UID/GID is occupied')
  require(all(name in groups for name in GROUPS), 'Required desktop groups are missing')
  require({name for name, row in passwd.items() if 1000 <= int(row[2]) < 60000} == {'portbuild'},
          'Unexpected reference login user')
  require(not (root / HOME.lstrip('/')).exists() and not (root / HOME.lstrip('/')).is_symlink(),
          'Qualification home already exists')
  skel = rooted(root, 'etc/skel')
  real_directory(skel)
  for forbidden in ['.ssh', '.gnupg', '.local/state/omarchy/done']:
    path = skel / forbidden
    require(not path.exists() and not path.is_symlink(), 'Skeleton contains private/completion state')
  return {name: digest(rooted(root, 'etc/' + name)) for name in t}


def admit_overlay(source, manifest, overlay, manifest_digest, payload_digest):
  locked_directory(overlay)
  record = matched_json(overlay / 'manifest.json', manifest_digest)
  expected = render(source, manifest)
  tools = Path(__file__).resolve().parent
  require(record['format_version'] == 1 and record['policy'] == expected['policy'] and
          expected['policy']['account'] == account_plan(), 'Unreviewed qualification policy')
  require(record['payload_manifest_sha256'] == payload_digest and
          record['producer_sha256'] == digest(tools / 'prepare-qualification-overlay.py') and
          record['renderer_sha256'] == digest(tools / 'qualification_profile.py'),
          'Overlay producer/reference identity differs')
  require(all(record[key] is False for key in ['guardian_installed', 'account_created',
          'theme_seeded', 'root_modified', 'boot_ready']), 'Overlay is already applied or ready')
  files = {}
  for purpose in ('root', 'home'):
    for name, content in expected[purpose].items():
      safe_relative(name)
      key = purpose + '/' + name
      files[key] = content.encode()
      path = rooted(overlay, key)
      info = regular(path)
      owner = UID if purpose == 'home' else 0
      require(record['files'][key] == {'sha256': hashlib.sha256(files[key]).hexdigest(),
              'mode': 0o644, 'uid': owner, 'gid': owner} and
              path.read_bytes() == files[key] and stat.S_IMODE(info.st_mode) == 0o644 and
              info.st_uid == info.st_gid == 0, 'Overlay file identity differs')
  require(set(record['files']) == set(files), 'Extra/missing overlay manifest entry')
  actual = set()
  for base, dirs, names in os.walk(overlay, followlinks=False):
    for name in dirs:
      require(not (Path(base) / name).is_symlink(), 'Symlink overlay parent')
    for name in names:
      actual.add(str((Path(base) / name).relative_to(overlay)))
  require(actual == set(files) | {'manifest.json'}, 'Extra/missing overlay file')
  return files, expected['policy']['masked_services']


def parents(root, relative, uid=0, gid=0):
  safe_relative(relative)
  at = root
  for part in PurePosixPath(relative).parts[:-1]:
    at /= part
    if not at.exists() and not at.is_symlink():
      at.mkdir(mode=0o755)
      os.chown(at, uid, gid)
    require(not at.is_symlink() and at.is_dir(), 'Unsafe destination parent')
  target = at / PurePosixPath(relative).name
  if target.exists() or target.is_symlink():
    require(not target.is_symlink() and target.is_file() and target.stat().st_nlink == 1,
            'Refusing special/shared destination')
  return target


def atomic_file(root, relative, content, uid, gid, mode):
  require(type(mode) is int and 0 <= mode <= 0o777 and not mode & 0o022,
          'Unsafe prepared file mode')
  target = parents(root, relative, uid, gid)
  temporary = target.with_name('.' + target.name + '.shield-preparing')
  fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(fd, 'wb') as stream:
    stream.write(content)
    stream.flush()
    os.fchown(stream.fileno(), uid, gid)
    os.fchmod(stream.fileno(), mode)
    os.fsync(stream.fileno())
  os.replace(temporary, target)
  directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
  try:
    os.fsync(directory)
  finally:
    os.close(directory)



def seed_original_accounts(root, provenance, contents):
  """Seed only the new, unbooted host copy from actual original-image bytes."""
  require(type(contents) is dict and set(contents) == ACCOUNT_NAMES,
          'Four original account byte objects required')
  for name, data in sorted(contents.items()):
    identity = provenance['account_preimages'][name]
    require(type(data) is bytes and len(data) == identity['bytes']
            and hashlib.sha256(data).hexdigest() == identity['sha256'], 'Original account seed differs')
    atomic_file(root, name, data, identity['uid'], identity['gid'], identity['mode'])
  observed = account_preimages(root, provenance['account_preimages'])
  require(all(observed[name]['xattrs'] == {} and rooted(root, name).read_bytes() == data
              for name, data in contents.items()), 'Seeded account readback differs')
  current = tables(root)
  require(all('portbuild' not in rows and USER not in rows for rows in current.values()),
          'Original runtime baseline contains a build/qualification account')
  require([name for name, row in current['passwd'].items() if row[2] == '0'] == ['root']
          and all(int(row[2]) != UID and int(row[3]) != GID for row in current['passwd'].values())
          and all(int(row[2]) != GID for row in current['group'].values())
          and all(name in current['group'] for name in GROUPS), 'Original runtime identities differ')


def guest_path(root, absolute):
  """Resolve guest absolute links inside this root, never against host /."""
  require(absolute.startswith('/'), 'Expected guest absolute path')
  todo, done, links = deque(PurePosixPath(absolute).parts[1:]), [], 0
  while todo:
    part = todo.popleft()
    if part in ('', '.'): continue
    if part == '..':
      require(bool(done), 'Guest link escapes root')
      done.pop()
      continue
    path = root.joinpath(*done, part)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
      links += 1
      require(links <= 40, 'Guest link cycle')
      target = os.readlink(path)
      if target.startswith('/'): done = []
      todo.extendleft(reversed(PurePosixPath(target).parts[1:] if target.startswith('/') else PurePosixPath(target).parts))
    else:
      if todo: require(stat.S_ISDIR(info.st_mode), 'Non-directory guest parent')
      done.append(part)
  return root.joinpath(*done)


def apply_service_masks(root, masks):
  """Mask admitted units in the new copy, without following destination links."""
  require(isinstance(masks, dict) and bool(masks), 'Missing admitted service masks')
  unit_pattern = r'[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(?:service|target)'
  require(all(isinstance(unit, str) and len(unit) <= 200 and
              re.fullmatch(unit_pattern, unit) is not None and
              isinstance(reason, str) and bool(reason)
              for unit, reason in masks.items()), 'Unsafe service mask policy')
  directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
  try:
    for part in ('etc', 'systemd', 'system'):
      owner = os.fstat(directory)
      require(owner.st_uid == owner.st_gid == 0 and not owner.st_mode & 0o022,
              'Unsafe service mask ancestor')
      try:
        os.mkdir(part, 0o755, dir_fd=directory)
        os.chown(part, 0, 0, dir_fd=directory, follow_symlinks=False)
      except FileExistsError:
        pass
      next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=directory)
      os.close(directory)
      directory = next_directory
    owner = os.fstat(directory)
    require(owner.st_uid == owner.st_gid == 0 and not owner.st_mode & 0o022,
            'Unsafe service mask parent')
    proof = {}
    for unit in sorted(masks):
      try:
        existing = os.stat(unit, dir_fd=directory, follow_symlinks=False)
      except FileNotFoundError:
        existing = None
      correct = False
      if existing is not None:
        require(existing.st_uid == existing.st_gid == 0, 'Unowned mask destination')
        if stat.S_ISLNK(existing.st_mode):
          old_target = os.readlink(unit, dir_fd=directory)
          correct = old_target == '/dev/null'
          if not correct:
            # A known installed unit alias may be replaced; arbitrary dangling
            # or outside-root links cannot be used as authority for a mask.
            resolved = guest_path(root, '/etc/systemd/system/' + unit)
            require((resolved.is_relative_to(root / 'usr/lib/systemd/system') or
                     resolved.is_relative_to(root / 'etc/systemd/system')) and
                    re.fullmatch(unit_pattern, resolved.name) is not None,
                    'Unknown unit alias at mask destination')
            item = resolved.lstat()
            require(stat.S_ISREG(item.st_mode) and item.st_uid == item.st_gid == 0,
                    'Unowned unit alias target')
        else:
          require(stat.S_ISREG(existing.st_mode) and existing.st_nlink == 1,
                  'Special/shared mask destination')
      if not correct:
        temporary = '.' + unit + '.shield-mask-preparing'
        os.symlink('/dev/null', temporary, dir_fd=directory)
        os.chown(temporary, 0, 0, dir_fd=directory, follow_symlinks=False)
        os.replace(temporary, unit, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
      item = os.stat(unit, dir_fd=directory, follow_symlinks=False)
      require(stat.S_ISLNK(item.st_mode) and item.st_uid == item.st_gid == 0 and
              os.readlink(unit, dir_fd=directory) == '/dev/null', 'Service mask verification failed')
      proof[unit] = {'type': 'symlink', 'target': '/dev/null', 'uid': 0, 'gid': 0,
                     'reason': masks[unit]}
    return proof
  finally:
    os.close(directory)


def home_proof(root):
  home = rooted(root, HOME.lstrip('/'))
  real_directory(home)
  require(home.stat().st_uid == UID and home.stat().st_gid == GID, 'Home ownership differs')
  for forbidden in ['.ssh', '.gnupg', '.local/state/omarchy/done']:
    p = home / forbidden
    require(not p.exists() and not p.is_symlink(), 'Unexpected private/completion state in home')
  proof = {}
  for base, dirs, files in os.walk(home, followlinks=False):
    for name in dirs + files:
      p = Path(base) / name
      info = p.lstat()
      require(info.st_uid == UID and info.st_gid == GID and not info.st_mode & 0o6000,
              'Unexpected user-file owner or privileged mode')
      entry = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
      if stat.S_ISLNK(info.st_mode):
        target = os.readlink(p)
        guest = '/' + str(p.relative_to(root))
        resolved = guest_path(root, guest)
        require(resolved.is_relative_to(home) or resolved.is_relative_to(root / 'usr/share/omarchy'),
                'Home link outside admitted config/theme roots')
        entry.update(type='symlink', target=target)
      elif stat.S_ISREG(info.st_mode):
        require(info.st_nlink == 1, 'Shared user file')
        entry.update(type='file', sha256=digest(p), bytes=info.st_size)
      else:
        require(stat.S_ISDIR(info.st_mode), 'Special file in home')
        entry['type'] = 'directory'
      proof[str(p.relative_to(home))] = entry
  for name in ['.bashrc', '.config/hypr/hyprland.lua', '.config/hypr/input.lua',
               '.config/hypr/bindings.lua', '.config/hypr/looknfeel.lua', '.config/hypr/autostart.lua']:
    require(guest_path(root, HOME + '/' + name).is_file(), 'Missing normal skeleton configuration')
  current = rooted(root, HOME.lstrip('/') + '/.local/state/omarchy/current/theme.name').parent
  regular(current / 'theme.name')
  require((current / 'theme.name').read_text() == 'tokyo-night\n', 'Theme selection differs')
  theme = real_directory(current / 'theme')
  for name in ['colors.toml', 'hyprland.lua', 'foot.ini', 'shell.toml', 'btop.theme', 'pi.json']:
    p = theme / name
    require(p.is_file() and not p.is_symlink() and p.stat().st_size > 0,
            'Required generated theme configuration is absent')
  official = root / 'usr/share/omarchy/themes/tokyo-night/colors.toml'
  require(digest(theme / 'colors.toml') == digest(official), 'Theme palette differs')
  background = current / 'background'
  require(background.is_symlink(), 'Missing theme background link')
  resolved = guest_path(root, HOME + '/.local/state/omarchy/current/background')
  require(resolved.is_relative_to(theme / 'backgrounds') and resolved.is_file() and
          resolved.stat().st_size > 0, 'Background does not resolve inside selected theme')
  return proof


def account_proof(root, original_accounts):
  actual = {name: rooted(root, name).read_bytes() for name in ACCOUNT_NAMES}
  validate_accounts(original_accounts, actual)
  t = tables(root)
  p, g = t['passwd'], t['group']
  require(p[USER][2:] == [str(UID), str(GID), '', HOME, '/bin/bash'], 'Target account differs')
  require(g[USER][2] == str(GID), 'Target primary group differs')
  require({name for name, row in g.items() if USER in row[3].split(',')} == set(GROUPS),
          'Target supplementary membership differs')
  return {'name': USER, 'uid': UID, 'gid': GID, 'supplementary_groups': list(GROUPS),
          'root_password_locked': True, 'build_account_absent': True,
          'runtime_account_baseline_admitted': True, 'target_password_locked': True,
          'administrative': False, 'ssh_keys_created': False}


def admit_sudo_diagnostic(kind, returncode, output):
  """Pure admission of the reviewed C-locale sudo policy/denial dialect.

  A negative command specification makes sudo -l succeed without granting any
  command. A password/PAM/plugin error is never evidence of authorization denial.
  """
  require(type(returncode) is int and isinstance(output, bytes) and len(output) <= 32768 and
          all(byte in (9, 10) or 32 <= byte <= 126 for byte in output),
          'Malformed sudo diagnostic')
  if kind == 'true-policy':
    require(returncode == 1 and output == b'', 'Root true policy query was not denied')
    return
  text = output.decode('ascii')
  host = r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}'
  if kind == 'listing':
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    require(returncode == 0 and len(lines) == 6, 'Unexpected sudo listing result')
    header = re.fullmatch(r'Matching Defaults entries for shieldqual on (' + host + r'):', lines[0])
    require(header is not None and
            lines[1] == r'secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/bin, passwd_tries=10' and
            lines[2] == 'Runas and Command-specific defaults for shieldqual:' and
            lines[3] == 'Defaults!/usr/bin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"' and
            lines[4] == 'User shieldqual may run the following commands on ' + header[1] + ':' and
            lines[5] == '(ALL) !/usr/bin/asdcontrol',
            'Sudo listing is not the admitted negative-only policy')
    return
  raise ValueError('Unknown sudo diagnostic operation')


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  for name in ['rootfs', 'payload-manifest', 'overlay', 'output',
               'original-account-rootfs', 'original-account-receipt']:
    parser.add_argument('--' + name, type=Path, required=True)
  parser.add_argument('--payload-manifest-sha256', required=True)
  parser.add_argument('--overlay-manifest-sha256', required=True)
  parser.add_argument('--original-account-receipt-sha256', required=True)
  parser.add_argument('--original-root-image-sha256', required=True)
  args = parser.parse_args()
  wsl_root()
  source, overlay = real_directory(args.rootfs), real_directory(args.overlay)
  original_root = real_directory(args.original_account_rootfs)
  original_receipt = args.original_account_receipt.absolute()
  original_provenance, original_contents = original_account_baseline(original_root, original_receipt,
    args.original_account_receipt_sha256, args.original_root_image_sha256)
  forbidden = {Path(p) for p in ['/', '/etc', '/usr', '/var', '/home', '/root', '/boot', '/mnt', '/media', '/run', '/proc', '/sys', '/dev', '/tmp']}
  require(source not in forbidden and original_root not in forbidden, 'Refusing host root or system directory')
  require(args.output.name not in ('', '.', '..') and not args.output.exists() and not args.output.is_symlink(),
          'Output must be new; failed attempts cannot be reused')
  output = args.output.parent.resolve(strict=True) / args.output.name
  payload_path = args.payload_manifest.resolve(strict=True)
  for path in [source, overlay, payload_path.parent, original_root, original_receipt.parent]:
    require(not output.is_relative_to(path) and not path.is_relative_to(output), 'Output overlaps an input')
  require(all(path.stat().st_dev == Path('/').stat().st_dev
              for path in [source, overlay, payload_path, original_root, original_receipt, output.parent]),
          'Use the native WSL host filesystem for all inputs and output')
  manifest = matched_json(payload_path, args.payload_manifest_sha256)
  verify_root(manifest, source)
  regular(rooted(source, 'var/lib/shield-linux/sources.lock.json'))
  account_identity = account_preflight(source)
  files, masks = admit_overlay(source, manifest, overlay, args.overlay_manifest_sha256,
                        args.payload_manifest_sha256)
  helper = Path(__file__).resolve().parent.parent / 'chroot.sh'
  regular(helper)
  require(digest(helper) == CHROOT_SHA256, 'Chroot consumer changed; review before use')
  source_files = [Path(__file__).resolve(), helper, *[Path(__file__).resolve().parent / name
                  for name in ['qualification_profile.py', 'usb_root_profile.py', 'prepare-qualification-overlay.py',
                               'maintenance_accounts.py']]]
  source_hashes = {str(path): digest(path) for path in source_files}
  output.mkdir(mode=0o700)  # Exclusive claim. Never delete or retry this output.
  locked_directory(output)
  (output / 'ATTEMPTED').write_text('Partial output is never boot ready. No retry.\n')
  def stopped(_signum, _frame):
    raise InterruptedError('Owned preparation interrupted')

  signal.signal(signal.SIGTERM, stopped)
  target = output / 'rootfs'
  target.mkdir(mode=0o755)
  log = output / 'preparation.log'
  host_env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}

  def run(argv, seconds=600, sudo_check=None):
    with log.open('ab') as stream:
      process = subprocess.Popen(argv, env=host_env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if sudo_check is not None else stream,
        stderr=subprocess.STDOUT, start_new_session=True)
      try:
        stdout, _ = process.communicate(timeout=seconds)
      except BaseException:
        # Only this owned process session, never a global process-name kill.
        try:
          os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
          pass
        try:
          process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
          try:
            os.killpg(process.pid, signal.SIGKILL)
          except ProcessLookupError:
            pass
          process.communicate()
        raise
      result = subprocess.CompletedProcess(argv, process.returncode, stdout)
    if sudo_check is not None:
      # Keep the actual policy diagnostic before admission, including failures.
      # This private log never receives passwd/shadow database contents.
      with log.open('ab') as stream:
        stream.write(('\nSUDO_ADMISSION ' + sudo_check + ' exit=' + str(result.returncode) + '\n').encode())
        stream.write(result.stdout[:32768])
        if len(result.stdout) > 32768:
          stream.write(b'\nDIAGNOSTIC_TRUNCATED\n')
      admit_sudo_diagnostic(sudo_check, result.returncode, result.stdout)
    else:
      require(result.returncode == 0, 'Preparation command failed; retain partial output')
    return result

  def chroot(*argv, sudo_check=None):
    return run(['/usr/bin/unshare', '--net', '--', '/bin/bash', str(helper), str(target), *argv],
               sudo_check=sudo_check)

  run(['/usr/bin/rsync', '-aHAXx', '--numeric-ids', *['--exclude=' + n for n in EXCLUDES],
       str(source) + '/', str(target) + '/'], seconds=3600)
  for name, mode in [('proc', 0o755), ('dev', 0o755), ('run', 0o755), ('tmp', 0o1777),
                     ('sys', 0o755), ('root', 0o700), ('mnt', 0o755), ('media', 0o755)]:
    p = target / name
    p.mkdir(mode=mode, exist_ok=True)
    require(not p.is_symlink() and p.is_dir(), 'Unsafe cloned runtime directory')
    os.chown(p, 0, 0); p.chmod(mode)
  verify_root(manifest, target)  # Prove exclusions did not drop package payload.
  account_preflight(target)  # Build reference admission, before replacing only its account tables.
  seed_original_accounts(target, original_provenance, original_contents)
  chroot('/usr/bin/usermod', '--password', '!', 'root')
  chroot('/usr/bin/groupadd', '--gid', str(GID), USER)
  chroot('/usr/bin/useradd', '--uid', str(UID), '--gid', str(GID), '--groups', ','.join(GROUPS),
         '--create-home', '--skel', '/etc/skel', '--shell', '/bin/bash', '--no-log-init', '--password', '!', USER)
  account = account_proof(target, original_contents)
  chroot('/usr/bin/sudo', '-n', '-l', '-U', USER, sudo_check='listing')
  chroot('/usr/bin/sudo', '-n', '-l', '-U', USER, '--', '/usr/bin/true', sudo_check='true-policy')
  # QEMU-user cannot establish native setuid sudo execution semantics. These
  # two real root policy queries prove authorization only, never a native run.
  account.update(sudo_policy_denied=True, sudo_negative_only_listing=True,
                 sudo_true_policy_query_denied=True, native_sudo_execution_verified=False)
  for key, content in files.items():
    purpose, name = key.split('/', 1)
    relative = name if purpose == 'root' else 'home/' + name
    owner = 0 if purpose == 'root' else UID
    atomic_file(target, relative, content, owner, owner, 0o644)
  # No full provision-user, install/user/all, hooks, mise or online first-run.
  chroot('/bin/bash', '-euc', THEME_SCRIPT)
  home = home_proof(target)
  account_proof(target, original_contents)
  service_masks = apply_service_masks(target, masks)
  applied = {}
  for key, content in files.items():
    purpose, name = key.split('/', 1)
    relative = name if purpose == 'root' else 'home/' + name
    p = rooted(target, relative)
    info = p.lstat(); owner = 0 if purpose == 'root' else UID
    require(p.read_bytes() == content and info.st_uid == info.st_gid == owner and
            stat.S_IMODE(info.st_mode) == 0o644, 'Applied overlay changed')
    applied[relative] = {'sha256': digest(p), 'uid': owner, 'gid': owner, 'mode': 0o644}
  for excluded in ['build', 'home/portbuild', 'root/.ssh', 'root/.gnupg', 'etc/pacman.d/gnupg']:
    p = target / excluded
    require(not p.exists() and not p.is_symlink(), 'Excluded private/build state appeared')
  require(not list((target / 'etc/ssh').glob('ssh_host_*')), 'SSH host keys appeared')
  verify_root(manifest, target)  # Re-admit the complete matched payload after all configuration.
  verify_root(manifest, source)
  require(all(digest(rooted(source, 'etc/' + name)) == value for name, value in account_identity.items()),
          'Source account databases changed')
  require(original_baseline_from_record(original_provenance) == original_contents,
          'Original account source changed during preparation')
  require(all(digest(path) == value for path, value in source_hashes.items()), 'Preparation source moved')
  require(digest(payload_path) == args.payload_manifest_sha256 and
          digest(overlay / 'manifest.json') == args.overlay_manifest_sha256 and
          digest(helper) == CHROOT_SHA256, 'Preparation input changed')
  receipt = {'format_version': 1, 'purpose': 'new host-only qualification root preparation',
    'producer_sha256': digest(__file__), 'chroot_helper_sha256': CHROOT_SHA256,
    'source_hashes': source_hashes,
    'payload_manifest_sha256': args.payload_manifest_sha256,
    'overlay_manifest_sha256': args.overlay_manifest_sha256,
    'source_reference_verified_before_and_after': True, 'source_accounts_unchanged': True,
    'original_account_baseline': original_provenance, 'runtime_accounts_seeded_from_original': True,
    'original_account_source_verified_before_and_after': True,
    'reference_root_modified': False, 'prepared_root_modified': True,
    'copy_exclusions': list(EXCLUDES), 'network_isolated_chroot_commands': True,
    'account': account, 'account_created': True, 'theme': 'tokyo-night', 'theme_seeded': True,
    'sudo_policy_denied': True, 'native_sudo_execution_verified': False,
    'normal_first_run_complete': False, 'applied_files': applied, 'home_files': home,
    'preparation_log_sha256': digest(log), 'guardian_installed': False,
    'root_selected': False, 'boot_ready': False, 'native_qualified': False,
    'service_masks_applied': True, 'service_masks': service_masks,
    'matched_package_payload_verified_after_configuration': True,
    'remaining': ['bound enabled guardian/profile', 'recovery broker and systemd unit graph',
                  'separate candidate identity/root handoff', 'native setuid sudo execution verification',
                  'physical/native qualification']}
  with (output / 'receipt.json').open('x') as stream:
    json.dump(receipt, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
  print('Prepared a new private host root only; boot readiness remains false.')


if __name__ == '__main__':
  try:
    main()
  except (ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt) as error:
    # Do not print account database contents, command output or password hashes.
    print('Qualification root preparation failed; preserve any partial output. ' + type(error).__name__, file=sys.stderr)
    raise SystemExit(1)
