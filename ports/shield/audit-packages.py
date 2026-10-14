#!/usr/bin/env python3
"""Resolve the port's package names against pinned ARM repository metadata.

This checks names and providers, not libalpm's version/conflict solver. It never
installs packages, changes host repositories, or executes an upstream installer.
"""
import argparse
import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.request


def fields(text):
    result = {}
    current = None
    for line in text.splitlines():
        if line.startswith('%') and line.endswith('%'):
            current = line[1:-1]
            result[current] = []
        elif line and current:
            result[current].append(line)
    return result


def read_repository(path):
    data = path.read_bytes()
    if data.startswith(b'\x28\xb5\x2f\xfd'):
        data = subprocess.check_output(['zstd', '-dc', str(path)])
    records = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for entry in archive:
            if entry.isfile() and entry.name.rsplit('/', 1)[-1] in ('desc', 'depends'):
                records.setdefault(entry.name.rsplit('/', 1)[0], {}).update(
                    fields(archive.extractfile(entry).read().decode()))
    return records


def main():
    port = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--metadata-dir', type=Path, default=Path.home() / 'build/omarchy-shield/repository-metadata')
    parser.add_argument('--output', type=Path, default=port / 'build/package-audit.json')
    args = parser.parse_args()
    lock = json.loads((port / 'userspace.lock.json').read_text())
    repositories = lock['repositories']
    args.metadata_dir.mkdir(parents=True, exist_ok=True)

    def acquire(repository):
        path = args.metadata_dir / repository['file']
        if args.refresh or not path.exists():
            request = urllib.request.Request(repository['url'], headers={'User-Agent': 'pacman/7.0.0 (Linux aarch64)'})
            with urllib.request.urlopen(request, timeout=45) as response:
                data = response.read(40 * 1024 * 1024)
            if hashlib.sha256(data).hexdigest() != repository['sha256']:
                raise RuntimeError(f"{repository['name']}: metadata changed; review and update the lock")
            path.write_bytes(data)
        if hashlib.sha256(path.read_bytes()).hexdigest() != repository['sha256']:
            raise RuntimeError(f"{repository['name']}: cached metadata does not match its lock")
        return repository, read_repository(path)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        acquired = list(pool.map(acquire, repositories))
    packages, providers, anomalies = {}, {}, []
    for repository, records in acquired:
        for directory, record in records.items():
            if not record.get('NAME'):
                anomalies.append({'repository': repository['name'], 'entry_without_name': directory})
                continue
            name = record['NAME'][0]
            item = {key.lower(): value for key, value in record.items()}
            item['repository'] = repository['name']
            packages.setdefault(name, item)
            for provide in record.get('PROVIDES', []):
                providers.setdefault(re.split('[<>=]', provide)[0], name)
    source = port.parent.parent
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    subprocess.run(['git', '-C', str(source), 'diff', '--quiet', 'HEAD', '--', 'bin/omarchy-pkg-defaults', 'install'], check=True)
    environment = dict(os.environ, OMARCHY_PATH=str(source))
    defaults = subprocess.check_output(['/bin/bash', str(source / 'bin/omarchy-pkg-defaults'), 'aarch64-shield'], env=environment, text=True).splitlines()
    wanted = list(dict.fromkeys(['base', 'omarchy', 'omarchy-settings', 'pipewire', 'pipewire-alsa', 'pipewire-pulse', *defaults]))
    resolved, missing, local = {}, [], []
    for requested in wanted:
        if requested in lock['local_packages']:
            local.append(requested)
            continue
        name = requested if requested in packages else providers.get(requested)
        if name is None:
            missing.append(requested)
            continue
        package = packages[name]
        resolved[requested] = {key: package.get(key, []) for key in ('name', 'version', 'arch', 'filename', 'sha256sum', 'depends', 'provides')}
        resolved[requested]['repository'] = package['repository']
    report = {
        'target': lock['target'], 'omarchy_commit': head,
        'check': 'Package-name/provider availability; version/conflict resolution still requires pacman',
        'repositories': repositories, 'repository_package_count': len(packages),
        'requested_count': len(wanted), 'resolved_count': len(resolved),
        'local_packages': local, 'missing': missing, 'metadata_anomalies': anomalies,
        'resolved': resolved, 'all_package_names_available': not missing,
        'physical_shield_tested': False, 'flashable_image': False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('target', 'requested_count', 'resolved_count', 'local_packages', 'missing', 'metadata_anomalies', 'all_package_names_available')}, indent=2))
    raise SystemExit(bool(missing))


if __name__ == '__main__':
    main()
