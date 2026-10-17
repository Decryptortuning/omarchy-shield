"""Bind the final five-package transaction to its exact staged recipes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

PACKAGES = {'mesa': 'mesa-shield', 'linux-shield': 'linux-shield', 'omarchy': 'omarchy',
            'omarchy-settings': 'omarchy-settings', 'omarchy-shield': 'omarchy-shield'}


def recipe_identity(path, expected):
  text = path.read_text()
  def scalar(key, default=None):
    values = re.findall(r'^' + key + r'=(.*)$', text, re.MULTILINE)
    if not values and default is not None:
      return default
    if len(values) != 1:
      raise ValueError('Expected one static recipe field: ' + key)
    tokens = shlex.split(values[0], comments=True)
    if len(tokens) != 1 or not re.fullmatch(r'[A-Za-z0-9._+:-]+', tokens[0]):
      raise ValueError('Expected a static recipe value: ' + key)
    return tokens[0]
  if scalar('pkgname') != expected:
    raise ValueError('Wrong staged package recipe: ' + expected)
  architectures = re.findall(r'^arch=\((.*)\)$', text, re.MULTILINE)
  if len(architectures) != 1 or 'aarch64' not in shlex.split(architectures[0]):
    raise ValueError('Recipe does not declare the AArch64 target: ' + expected)
  epoch = scalar('epoch', '0')
  if not epoch.isdecimal():
    raise ValueError('Invalid recipe epoch')
  version = (epoch + ':' if int(epoch) else '') + scalar('pkgver') + '-' + scalar('pkgrel')
  return {'name': expected, 'version': version, 'architecture': 'aarch64',
          'recipe_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def package_intent(build):
  return {'format_version': 1, 'packages': {
    name: recipe_identity(Path(build) / directory / 'PKGBUILD', name)
    for name, directory in PACKAGES.items()}}


def metadata_value(text, key):
  values = [line.split(' = ', 1)[1] for line in text.splitlines() if line.startswith(key + ' = ')]
  if len(values) != 1:
    raise ValueError('Expected one archive metadata field: ' + key)
  return values[0]


def admitted_archives(build, intent_path):
  build = Path(build)
  intent = json.loads(Path(intent_path).read_text())
  if intent != package_intent(build):
    raise ValueError('Package intent differs from the exact staged recipes')
  selected = []
  for name, directory in PACKAGES.items():
    archives = sorted(path for path in (build / directory).glob('*.pkg.tar.*')
                      if not path.name.endswith('.sig') and '-debug-' not in path.name)
    if len(archives) != 1 or not archives[0].is_file() or archives[0].is_symlink():
      raise ValueError('Expected exactly one regular package archive: ' + name)
    archive = archives[0]
    info = subprocess.run(['bsdtar', '-xOf', str(archive), '.PKGINFO'],
                          capture_output=True, text=True, check=True).stdout
    build_info = subprocess.run(['bsdtar', '-xOf', str(archive), '.BUILDINFO'],
                                capture_output=True, text=True, check=True).stdout
    expected = intent['packages'][name]
    for key, value in [('pkgname', name), ('pkgver', expected['version']), ('arch', 'aarch64')]:
      if metadata_value(info, key) != value:
        raise ValueError('Package archive identity differs from staged intent: ' + name + '/' + key)
    for key, value in [('pkgname', name), ('pkgver', expected['version']), ('pkgarch', 'aarch64'),
                       ('pkgbuild_sha256sum', expected['recipe_sha256'])]:
      if metadata_value(build_info, key) != value:
        raise ValueError('Package build identity differs from staged intent: ' + name + '/' + key)
    selected.append(archive)
  return selected


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--build', required=True, type=Path)
  parser.add_argument('--intent', required=True, type=Path)
  args = parser.parse_args()
  try:
    paths = admitted_archives(args.build, args.intent)
  except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
    raise SystemExit(str(error)) from error
  print('\n'.join(map(str, paths)))
