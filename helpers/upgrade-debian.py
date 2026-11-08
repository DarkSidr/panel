#!/usr/bin/env python3
"""Detached Debian 12 → 13 upgrade and one-time post-reboot installation."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
from urllib.parse import urlparse

ROOT = Path('/var/lib/proxy-stack-upgrade')
APT = Path('/etc/apt')
OS_RELEASE = Path('/etc/os-release')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
UNITS = Path('/etc/systemd/system')


def command(*args, capture=False):
    return subprocess.run(args, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          env=dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='a'))


def store(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.next')
    temporary.write_text(json.dumps(data, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def source_files():
    files = [APT / 'sources.list'] + sorted((APT / 'sources.list.d').glob('*.list')) + sorted((APT / 'sources.list.d').glob('*.sources'))
    return [p for p in files if p.is_file()]


def validate_sources():
    """Reject mixed/third-party/backports repositories rather than silently disabling them."""
    active = 0
    for path in source_files():
        text = path.read_text()
        entries = []
        if path.suffix == '.sources':
            for stanza in re.split(r'\n\s*\n', text):
                fields = {}
                key = None
                for line in stanza.splitlines():
                    if not line.strip() or line.lstrip().startswith('#'):
                        continue
                    if line[0].isspace() and key:
                        fields[key] += ' ' + line.strip()
                    elif ':' in line:
                        key, value = line.split(':', 1)
                        key = key.lower()
                        fields[key] = value.strip()
                    else:
                        raise ValueError('Unrecognized APT source in ' + str(path))
                if not fields or fields.get('enabled', 'yes').lower() == 'no':
                    continue
                entries.append((fields.get('uris', '').split(), fields.get('suites', '').split()))
        else:
            for line in text.splitlines():
                line = line.split('#', 1)[0].strip()
                if not line:
                    continue
                match = re.fullmatch(r'deb(?:-src)?\s+(?:\[[^\]]+\]\s+)?(\S+)\s+(\S+)\s+.+', line)
                if not match:
                    raise ValueError('Unrecognized APT source in ' + str(path))
                entries.append(([match[1]], [match[2]]))
        for urls, suites in entries:
            if not urls or not suites:
                raise ValueError('Empty APT URIs/Suites in ' + str(path))
            for url in urls:
                parsed = urlparse(url)
                if parsed.scheme not in ('http', 'https') or parsed.hostname not in ('deb.debian.org', 'security.debian.org', 'ftp.debian.org'):
                    raise ValueError('Automatic upgrade requires official Debian mirrors only; review ' + str(path))
            if not set(suites).issubset({'bookworm', 'bookworm-updates', 'bookworm-security'}):
                raise ValueError('Mixed, backports or non-bookworm APT suites; review ' + str(path))
            active += 1
    if not active:
        raise ValueError('No enabled Debian APT sources found')


def validate_upgrade():
    if not re.search(r'^ID="?debian"?$', OS_RELEASE.read_text(), re.M) or not re.search(r'^VERSION_ID="?12"?$', OS_RELEASE.read_text(), re.M):
        raise ValueError('The upgrade worker supports Debian 12 only')
    if ROOT.exists():
        raise ValueError('An upgrade workspace already exists. Inspect /var/lib/proxy-stack-upgrade/state.json and journalctl -u proxy-stack-upgrade before retrying.')
    validate_sources()
    if command('dpkg', '--audit', capture=True).stdout.strip():
        raise ValueError('Repair unfinished dpkg operations before upgrading Debian')
    if command('apt-mark', 'showhold', capture=True).stdout.strip():
        raise ValueError('Review held packages before upgrading Debian')
    for path in ('/', '/var'):
        if shutil.disk_usage(path).free < 3 * 1024**3:
            raise ValueError('Automatic upgrade needs at least 3 GiB free on ' + path)
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('Automatic upgrade requires systemd')


def trixie_sources(text, deb822=False):
    def replace(match):
        return re.sub(r'\bbookworm\b', 'trixie', match[0])
    if deb822:
        return re.sub(r'^Suites:[^\n]*(?:\n[ \t]+[^\n]*)*', replace, text, flags=re.M | re.I)
    # Match the suite only, not URLs, Signed-By paths or comments.
    return re.sub(r'^(deb(?:-src)?\s+(?:\[[^\]]+\]\s+)?\S+\s+)(bookworm(?:-updates|-security)?)(?=\s)',
                  lambda m: m[1] + m[2].replace('bookworm', 'trixie'), text, flags=re.M)


def schedule(options, source):
    ROOT.mkdir(mode=0o700)
    shutil.copytree(source, ROOT / 'source', ignore=shutil.ignore_patterns('.git', '.agents', '.codex', '.aws', 'dist', '__pycache__'))
    store(ROOT / 'options.json', options)
    store(ROOT / 'state.json', {'stage': 'scheduled', 'boot_id': BOOT_ID.read_text().strip()})
    helper = ROOT / 'source/helpers/upgrade-debian.py'
    for mode, name in [('worker', 'upgrade'), ('resume', 'resume')]:
        condition = 'ConditionPathExists=' + str(ROOT / 'ready') + '\n' if mode == 'resume' else ''
        unit = UNITS / ('proxy-stack-' + name + '.service')
        unit.write_text('[Unit]\nDescription=Proxy stack Debian ' + name + '\n'
                        'Wants=network-online.target\nAfter=network-online.target\n' + condition +
                        '[Service]\nType=oneshot\nTimeoutStartSec=infinity\nUMask=0077\n'
                        'ExecStart=/usr/bin/python3 ' + str(helper) + ' ' + mode + '\n'
                        '[Install]\nWantedBy=multi-user.target\n')
        unit.chmod(0o644)
    command('systemctl', 'daemon-reload')
    command('systemctl', 'start', '--no-block', 'proxy-stack-upgrade.service')
    print('Обновление Debian запущено отдельной службой. После обновления VPS перезагрузится, установка продолжится автоматически.\n'
          'Ход выполнения: journalctl -fu proxy-stack-upgrade.service\n'
          'После перезагрузки: journalctl -fu proxy-stack-resume.service\n'
          'Состояние и резервная копия: /var/lib/proxy-stack-upgrade/')


def worker():
    state = json.loads((ROOT / 'state.json').read_text())
    if state['stage'] != 'scheduled':
        raise ValueError('Upgrade already started; inspect its state and logs before manual recovery')
    validate_sources()
    state.update(stage='backing-up', started_at=int(time.time()))
    store(ROOT / 'state.json', state)
    with tarfile.open(ROOT / 'system-backup.tar.gz', 'w:gz') as archive:
        for path in ('/etc', '/var/lib/dpkg', '/var/lib/apt/extended_states'):
            if Path(path).exists():
                archive.add(path, arcname=path.lstrip('/'))
    (ROOT / 'system-backup.tar.gz').chmod(0o600)
    (ROOT / 'package-selections').write_text(command('dpkg', '--get-selections', capture=True).stdout)
    apt = ('apt-get', '-y', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold')
    state['stage'] = 'upgrading-bookworm'
    store(ROOT / 'state.json', state)
    command('apt-get', 'update')
    command(*apt, 'full-upgrade')
    # Preserve signing-key paths, components, architecture filters and comments.
    for path in source_files():
        path.write_text(trixie_sources(path.read_text(), deb822=path.suffix == '.sources'))
    state['stage'] = 'upgrading-trixie'
    store(ROOT / 'state.json', state)
    command('apt-get', 'update')
    command(*apt, 'upgrade', '--without-new-pkgs')
    command(*apt, 'full-upgrade')
    command(*apt, 'install', 'linux-image-' + {'x86_64': 'amd64', 'aarch64': 'arm64'}[os.uname().machine])
    if not re.search(r'^VERSION_ID="?13"?$', OS_RELEASE.read_text(), re.M):
        raise ValueError('APT finished without Debian 13; inspect the upgrade logs')
    if command('dpkg', '--audit', capture=True).stdout.strip():
        raise ValueError('dpkg requires attention after upgrade; automatic reboot cancelled')
    state['stage'] = 'awaiting-reboot'
    store(ROOT / 'state.json', state)
    (ROOT / 'ready').touch(mode=0o600)
    command('systemctl', 'enable', 'proxy-stack-resume.service')
    command('systemctl', 'reboot', '--no-block')


def resume():
    state = json.loads((ROOT / 'state.json').read_text())
    if BOOT_ID.read_text().strip() == state['boot_id']:
        raise ValueError('Reboot into the Debian 13 kernel before resuming installation')
    if not re.search(r'^VERSION_ID="?13"?$', OS_RELEASE.read_text(), re.M):
        raise ValueError('Debian 13 is required to resume')
    if state['stage'] not in ('awaiting-reboot', 'installing'):
        raise ValueError('Unexpected upgrade stage; inspect state.json')
    options = json.loads((ROOT / 'options.json').read_text())
    args = ['/usr/bin/python3', str(ROOT / 'source/proxyctl.py'), 'install',
            '--site', options['site'], '--panel', options['panel']]
    if options.get('email'):
        args += ['--email', options['email']]
    if options.get('theme'):
        args += ['--theme', options['theme']]
    for name in options.get('reality_name', []):
        args += ['--reality-name', name]
    for name in ('manual_inbounds', 'no_default_inbounds'):
        if options.get(name):
            args.append('--' + name.replace('_', '-'))
    state['stage'] = 'installing'
    store(ROOT / 'state.json', state)
    command(*args)
    state['stage'] = 'installed'
    store(ROOT / 'state.json', state)
    (ROOT / 'ready').unlink()
    command('systemctl', 'disable', 'proxy-stack-resume.service')


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['worker', 'resume'])
    args = parser.parse_args()
    try:
        {'worker': worker, 'resume': resume}[args.mode]()
    except Exception as error:
        print('Debian upgrade/installation stopped:', error, file=sys.stderr)
        print('Inspect /var/lib/proxy-stack-upgrade/state.json and the systemd journal. No automatic rollback or retry was attempted.', file=sys.stderr)
        sys.exit(1)
