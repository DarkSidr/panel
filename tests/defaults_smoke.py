"""Exercise default provisioning against an isolated real 3x-ui release.

Run locally: python3 tests/defaults_smoke.py /path/to/extracted/x-ui/x-ui
Creates only temporary files and loopback listeners; never uses a live panel DB.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    binary = Path(sys.argv[1]).resolve()
    spec = importlib.util.spec_from_file_location('proxyctl', Path(__file__).parents[1] / 'proxyctl.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='proxy-defaults-smoke-') as directory:
        root = Path(directory)
        shutil.copytree(binary.parent / 'bin', root / 'bin', ignore=shutil.ignore_patterns('config.json'))
        env = dict(os.environ, XUI_DB_FOLDER=str(root / 'db'), XUI_BIN_FOLDER=str(root / 'bin'),
                   XUI_LOG_FOLDER=str(root / 'log'), XUI_ENABLE_FAIL2BAN='false')
        panel_port, sub_port = free_port(), free_port()
        def cli(*args):
            result = subprocess.run([str(binary), *args], env=env, cwd=root, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError('3x-ui CLI failed')
            return result.stdout
        cli('setting', '-username', 'smoke-admin', '-password', os.urandom(24).hex(),
            '-listenIP', '127.0.0.1', '-port', str(panel_port), '-webBasePath', '/smoke/')
        token = re.search(r'^apiToken:\s*(\S+)', cli('setting', '-getApiToken', '-tokenName', 'smoke', '-tokenScope', 'node-sync'), re.M)[1]
        config = {'site': 'site.example.test', 'panel': 'panel.example.test', 'panel_path': '/smoke/',
                  'sub_paths': {'base': '/smokesub/', 'json': '/smokejson/', 'clash': '/smokeclash/'},
                  'ssh_ports': [22], 'public_ips': ['127.0.0.1']}
        template = json.loads((Path(__file__).parents[1] / 'templates/xray.json').read_text())
        template['inbounds'][0]['port'] = free_port()
        template['metrics']['listen'] = '127.0.0.1:' + str(free_port())
        with sqlite3.connect(root / 'db/x-ui.db') as db:
            settings = {'webDomain': config['panel'], 'subListen': '127.0.0.1', 'subPort': str(sub_port),
                        'subEnable': 'true', 'subPath': config['sub_paths']['base'],
                        'xrayTemplateConfig': json.dumps(template)}
            for key, value in settings.items():
                db.execute('DELETE FROM settings WHERE key=?', (key,))
                db.execute('INSERT INTO settings(key,value) VALUES (?,?)', (key, value))
        (root / 'api-token').write_text(token)
        urlopen = urllib.request.urlopen
        def local_request(request, **kwargs):
            if isinstance(request, urllib.request.Request):
                request.full_url = request.full_url.replace('127.0.0.1:2053/', f'127.0.0.1:{panel_port}/')
            return urlopen(request, **kwargs)
        run = m.run
        def local_run(*args, **kwargs):
            if str(args[0]) == m.BIN:
                result = subprocess.run([str(binary), *map(str, args[1:])], env=env, cwd=root,
                                        capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError('Provisioning CLI failed')
                return result
            if str(args[0]).startswith('/usr/local/x-ui/bin/xray-'):
                args = (str(root / 'bin' / Path(args[0]).name), *args[1:])
            return run(*args, **kwargs)
        with open(root / 'panel.log', 'w') as log:
            process = subprocess.Popen([str(binary), 'run'], cwd=root, env=env, stdout=log, stderr=log)
            try:
                with patch.object(m, 'BASE', root / 'state'), patch.object(m, 'CONF', root), \
                     patch.object(m.urllib.request, 'urlopen', side_effect=local_request), \
                     patch.object(m, 'run', side_effect=local_run):
                    for attempt in range(50):
                        try:
                            m.panel_api(config, 'inbounds/list')
                            break
                        except Exception:
                            if attempt == 49:
                                raise RuntimeError('Isolated panel did not start') from None
                            time.sleep(0.2)
                    # UDP 443 is only advertised in this test, never bound.
                    probe = m.udp_port_free
                    with patch.object(m, 'udp_port_free', side_effect=lambda p: True if p == 443 else probe(p)):
                        m.seed_default_inbounds(config)
                    first = m.panel_api(config, 'inbounds/list')
                    m.seed_default_inbounds(config)
                    second = m.panel_api(config, 'inbounds/list')
                    assert len(first) == len(second) == 7
                    for i, j in zip(first, second):
                        assert i['id'] == j['id'] and i['settings'] == j['settings']
                    rs = m.routes(m.attach_awg_hosts(second, m.panel_api(config, 'hosts/list')), config)
                    assert len(rs) == 7
                    assert 'udp dport { 443 }' in m.firewall(config, rs)
                    with sqlite3.connect(root / 'db/x-ui.db') as db:
                        assert db.execute("SELECT count(*) FROM api_tokens WHERE name='proxy-stack-provision'").fetchone()[0] == 0
                    # Consume the real panel's exported subscriptions and verify
                    # each advertises the public endpoint and required transport.
                    for i in second:
                        client = m.json_object(i['settings'])['clients'][0]
                        request = urllib.request.Request(f'http://127.0.0.1:{sub_port}/smokesub/' + client['subId'],
                                                         headers={'Host': config['panel']})
                        with urlopen(request, timeout=10) as response:
                            body = response.read().decode()
                        assert body.strip(), 'Empty subscription for ' + i['tag']
                        if '://' not in body:
                            body = base64.b64decode(body + '=' * (-len(body) % 4)).decode()
                        link = body.strip().splitlines()[0]
                        if i['protocol'] == 'amneziawg':
                            assert link.startswith('vpn://')
                            encoded = link.removeprefix('vpn://')
                            text = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode()
                            assert 'Endpoint = ' + config['panel'] + ':443' in text
                            for field in ('HeaderProtectionKey', 'ContentPaddingAddition', 'RandomTrailers', 'DisableCookies', 'RekeyAfterTime'):
                                assert field + ' = ' in text
                            assert '127.0.0.1' not in text
                        else:
                            parsed = urlparse(link)
                            s = m.json_object(i['streamSettings'])
                            ep = s['externalProxy'][0]
                            assert parsed.scheme == i['protocol']
                            assert (parsed.hostname, parsed.port) == (ep['dest'], ep['port'])
                            query = parse_qs(parsed.query)
                            assert query['security'] == ['reality' if s['security'] == 'reality' else 'tls']
                            assert query['type'] == [s['network']]
                    # Ask the bundled core to validate its generated server config.
                    for attempt in range(50):
                        status = m.panel_api(config, 'server/status')
                        if status.get('xray', {}).get('state') == 'running' and status.get('amneziawg', {}).get('running'):
                            break
                        if attempt == 49:
                            raise RuntimeError('Xray or AWG failed to start in the isolated panel')
                        time.sleep(0.2)
                    candidate = root / 'bin/config.json'
                    core = root / 'bin/xray-linux-amd64'
                    result = subprocess.run([str(core), 'run', '-test', '-config', str(candidate)],
                                            cwd=root, env=dict(env, XRAY_LOCATION_ASSET=str(root / 'bin')),
                                            capture_output=True, text=True)
                    if result.returncode:
                        raise RuntimeError('Bundled Xray rejected the generated server configuration: ' + result.stderr[-2000:])
                    print('PASS: 7 real inbounds, enabled clients, AWG 3.1, Hosts, subscriptions, idempotence and Xray config')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
