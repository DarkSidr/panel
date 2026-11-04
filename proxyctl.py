#!/usr/bin/env python3
"""Debian 13 proxy appliance. No third-party Python dependencies."""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

BASE = Path('/var/lib/proxy-stack')
CONF = Path('/etc/proxy-stack')
APP = Path('/opt/proxy-stack')
NGINX = Path('/etc/nginx/nginx.conf')
REPO = 'https://api.github.com/repos/MHSanaei/3x-ui'
BIN = '/usr/local/x-ui/x-ui'
RESERVED = {80, 443, 7443, 9443, 2053, 2096}


def run(*args, check=True, **kw):
    result = subprocess.run(list(map(str, args)), check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    if check and result.returncode:
        raise RuntimeError(str(args[0])+': '+result.stderr[-4000:])
    return result


def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save(path, obj):
    write(path, json.dumps(obj, indent=2) + '\n')


def domain(value):
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
        raise ValueError('Expected lowercase ASCII domain (IDN: use punycode)')
    return value


def port(value):
    n = int(value)
    if not 1 <= n <= 65535:
        raise ValueError('Invalid port')
    return n


def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'proxy-stack/1'})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()


def release():
    r = json.loads(fetch(REPO + '/releases/latest'))
    if r.get('draft') or r.get('prerelease') or not re.fullmatch(r'v\d+\.\d+\.\d+', r['tag_name']):
        raise ValueError('Latest release is not a stable semantic version')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
    asset = next(a for a in r['assets'] if a['name'] == f'x-ui-linux-{arch}.tar.gz')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest', '')):
        raise ValueError('GitHub release lacks SHA256 digest; refusing unverifiable download')
    return r, asset


def payload(r, asset, dest):
    data = fetch(asset['browser_download_url'])
    if 'sha256:' + hashlib.sha256(data).hexdigest() != asset['digest']:
        raise ValueError('Release digest mismatch')
    archive = dest / 'release.tar.gz'
    archive.write_bytes(data)
    with tarfile.open(archive) as t:
        t.extractall(dest, filter='data')
    root = dest / 'x-ui'
    if not (root / 'x-ui').is_file():
        raise ValueError('Unexpected release archive layout')
    # The unit is pinned to the same release, never downloaded from main.
    unit = fetch(f"https://raw.githubusercontent.com/MHSanaei/3x-ui/{r['tag_name']}/x-ui.service.debian").decode()
    return root, unit


def routes(inbounds, c):
    """Strict allowlist compiler; never turns a URL into a localhost port."""
    result, paths, udp, reality = [], [], set(), set()
    tcp_backend_ports = {port(i['port']) for i in inbounds if i.get('enable') and not i.get('nodeId',0) and i.get('protocol') != 'amneziawg'}
    allowed_names = {c['site'], *c.get('reality_names', [])}
    for name in allowed_names:
        domain(name)
    if c['panel'] in allowed_names:
        raise ValueError('REALITY SNI must not replace the panel domain')
    for i in inbounds:
        if not i.get('enable') or i.get('nodeId', 0):
            continue
        s = i.get('streamSettings', '{}')
        s = json.loads(s or '{}') if isinstance(s, str) else (s or {})
        p = port(i['port'])
        if i.get('listen') != '127.0.0.1' or p in RESERVED:
            raise ValueError(f"Inbound {i['id']}: listen must be 127.0.0.1, port must not be reserved")
        kind = s.get('network', 'tcp')
        security = s.get('security', 'none')
        route = {'port': p, 'id': i['id']}
        if i['protocol'] == 'amneziawg':
            cfg = i.get('settings', '{}')
            cfg = json.loads(cfg or '{}') if isinstance(cfg, str) else cfg
            if cfg.get('server', {}).get('kernelMode', False):
                raise ValueError('AWG kernel mode cannot use this loopback nginx relay; use userspace')
            entries = s.get('externalProxy', [])
            public_port = port(entries[0].get('port', p)) if entries else p
            if public_port in udp or (public_port < 1024 and public_port != 443):
                raise ValueError('Duplicate or unsupported public UDP port')
            udp.add(public_port)
            route.update(kind='udp', public_port=public_port)
        elif security == 'reality' and kind in ('tcp', 'raw', 'xhttp', 'grpc'):
            rs = s.get('realitySettings', {})
            names = rs.get('serverNames', [])
            if len(names) != 1 or names[0] not in allowed_names:
                raise ValueError('REALITY requires one configured site SNI; add extra names at installation')
            advertised = s.get('externalProxy', [])
            public_port = port(advertised[0].get('port', 443)) if advertised else 443
            if public_port != 443 and (public_port < 1024 or public_port in RESERVED or public_port in c['ssh_ports'] or public_port in tcp_backend_ports):
                raise ValueError('REALITY public TCP port conflicts with reserved/SSH ports')
            endpoint = (public_port, names[0])
            if endpoint in reality:
                raise ValueError('Duplicate REALITY public port/SNI; choose a different SNI or public port')
            tcp = s.get('rawSettings', s.get('tcpSettings', {}))
            accept_proxy = s.get('sockopt', {}).get('acceptProxyProtocol') or (kind in ('tcp','raw') and tcp.get('acceptProxyProtocol'))
            if rs.get('target', rs.get('dest')) != '127.0.0.1:9443' or rs.get('xver') != 1 or not accept_proxy:
                raise ValueError('REALITY requires target 127.0.0.1:9443, xver=1 and PROXY protocol (sockopt for XHTTP/gRPC)')
            if kind == 'xhttp' and s.get('xhttpSettings', {}).get('mode', 'auto') not in ('auto','stream-one','stream-up','packet-up'):
                raise ValueError('Unknown XHTTP REALITY mode')
            reality.add(endpoint)
            route.update(kind='reality', transport=kind, sni=names[0], public_port=public_port)
        elif kind in ('ws', 'grpc', 'xhttp', 'httpupgrade') and security == 'none':
            settings = s.get({'ws': 'wsSettings', 'grpc': 'grpcSettings', 'xhttp': 'xhttpSettings', 'httpupgrade': 'httpupgradeSettings'}[kind], {})
            path = settings.get('serviceName', '') if kind == 'grpc' else settings.get('path', '')
            path = '/' + path.lstrip('/')
            if not re.fullmatch(r'/[A-Za-z0-9_-]{8,}(?:/[A-Za-z0-9_-]+)*', path):
                raise ValueError('Transport path/serviceName must use 8+ safe characters')
            if any(path.startswith(x) or x.startswith(path) for x in paths + list(c['sub_paths'].values()) + [c['panel_path']]):
                raise ValueError('Overlapping panel, subscription or transport paths')
            paths.append(path)
            if kind == 'xhttp' and settings.get('mode', 'auto') != 'stream-one':
                raise ValueError('XHTTP adapter currently requires stream-one')
            route.update(kind=kind, path=path)
        else:
            raise ValueError(f"Inbound {i['id']}: unsupported transport; no route published")
        advertised = s.get('externalProxy', [])
        expected_host = route['sni'] if route['kind'] == 'reality' else c['panel']
        expected_port = route['public_port'] if route['kind'] in ('udp','reality') else 443
        expected_tls = 'same' if route['kind'] in ('udp', 'reality') else 'tls'
        if not advertised or any(e.get('dest') != expected_host or e.get('port') != expected_port or e.get('forceTls') != expected_tls for e in advertised):
            raise ValueError(f"Inbound {i['id']}: set External Proxy to {expected_host}:{expected_port}, forceTls={expected_tls} for public subscriptions")
        result.append(route)
    return result


def headers():
    return '''proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;'''


def render(c, rs, tls=True):
    site, panel = domain(c['site']), domain(c['panel'])
    site_names = sorted({site, *c.get('reality_names', [])})
    for name in site_names:
        domain(name)
    http_names = ' '.join([panel]+site_names)
    challenge = f'''server {{ listen 80; listen [::]:80; server_name {http_names};
location ^~ /.well-known/acme-challenge/ {{ root /var/www/proxy-acme; }}
location / {{ return 301 https://$host$request_uri; }} }}
server {{ listen 80 default_server; listen [::]:80 default_server; server_name _; return 444; }}'''
    prefix = '''include /etc/nginx/modules-enabled/*.conf;
user www-data;
worker_processes auto;
worker_rlimit_nofile 8192;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
events { worker_connections 4096; }
'''
    if not tls:
        return prefix + 'http { include /etc/nginx/mime.types; ' + challenge + ' }\n'
    # Every passthrough backend accepts a PROXY header only over loopback.
    reality_routes = [r for r in rs if r['kind'] == 'reality']
    public_ports = sorted({443, *(r.get('public_port',443) for r in reality_routes)})
    stream = 'stream {\n'
    for public in public_ports:
        entries = {r.get('sni',site):r['port'] for r in reality_routes if r.get('public_port',443)==public}
        defaults = {name:9443 for name in site_names} if public==443 else {}
        defaults.update(entries)
        if public==443:
            defaults[panel]=7443
        stream += f'map $ssl_preread_server_name $backend_{public} {{\n'
        stream += ''.join(f'{name} 127.0.0.1:{upstream};\n' for name,upstream in sorted(defaults.items()))
        stream += 'default 127.0.0.1:10443;\n}\n'
        stream += f'server {{ listen {public}; listen [::]:{public}; ssl_preread on; proxy_protocol on; proxy_pass $backend_{public}; proxy_timeout 1h; }}\n'
    for r in rs:
        if r['kind'] == 'udp':
            # Public IP binds avoid collision with loopback inbound at the same port.
            listens = ''.join(f"listen {'['+ip+']' if ':' in ip else ip}:{r.get('public_port', r['port'])} udp reuseport;\n" for ip in c['public_ips'])
            stream += f"server {{ {listens} proxy_pass 127.0.0.1:{r['port']}; proxy_timeout 120s; }}\n"
    stream += '}\n'
    cert = f'''ssl_certificate /etc/letsencrypt/live/proxy-stack/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/proxy-stack/privkey.pem;
ssl_protocols TLSv1.2 TLSv1.3;
http2 on;
'''
    cover = '''root /var/www/proxy-site;
index index.html;
location / { try_files $uri $uri/ =404; add_header Cache-Control "no-store" always; }
'''
    web = '''http {
include /etc/nginx/mime.types;
default_type application/octet-stream;
server_tokens off;
access_log off;
map $http_upgrade $connection_upgrade { default upgrade; '' close; }
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
set_real_ip_from 127.0.0.1;
real_ip_header proxy_protocol;
'''+challenge
    web += 'server { listen 127.0.0.1:10443 ssl proxy_protocol; ssl_reject_handshake on; }\n'
    # Two listeners: PROXY from stream; no PROXY from REALITY target (xver=0).
    web += f'''server {{ listen 127.0.0.1:9443 ssl proxy_protocol;

server_name {' '.join(site_names)}; {cert}
if ($host != $ssl_server_name) {{ return 421; }}
{cover} }}
'''
    web += f'''server {{ listen 127.0.0.1:7443 ssl proxy_protocol; server_name {panel}; {cert}
if ($host != $ssl_server_name) {{ return 421; }}
location ^~ {c['panel_path']} {{
proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
{headers()} proxy_pass http://127.0.0.1:2053; }}
'''
    web += f"location = {c['panel_path']}login {{ limit_req zone=login burst=5 nodelay; {headers()} proxy_pass http://127.0.0.1:2053; }}\n"
    # Subscription tokens are bearer secrets: no access logging or shared caching.
    for path in c['sub_paths'].values():
        web += f'''location ^~ {path} {{ {headers()}
proxy_buffering off; proxy_cache off; proxy_read_timeout 60s;
add_header Cache-Control "private, no-store" always;
proxy_pass http://127.0.0.1:2096; }}\n'''
    for r in rs:
        if 'path' not in r:
            continue
        web += f"location ^~ {r['path']} {{ client_max_body_size 0; client_body_timeout 1h;\n"
        if r['kind'] in ('grpc', 'xhttp'):
            web += f'''grpc_set_header Host $host;
grpc_set_header X-Forwarded-For $remote_addr;
grpc_set_header X-Forwarded-Proto https;
grpc_read_timeout 1h; grpc_send_timeout 1h;
grpc_pass grpc://127.0.0.1:{r['port']};\n'''
        else:
            web += f'''{headers()} proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade;
proxy_buffering off; proxy_request_buffering off; proxy_read_timeout 1h;
proxy_pass http://127.0.0.1:{r['port']};\n'''
        web += '}\n'
    return prefix + stream + web + cover + '}\n}\n'


def firewall(c, rs):
    ports = ', '.join(map(str, sorted(set(c['ssh_ports'] + [80, 443] + [r.get('public_port',443) for r in rs if r['kind']=='reality']))))
    udp = sorted(r.get('public_port', r['port']) for r in rs if r['kind'] == 'udp')
    return '''table inet proxy_stack {
chain input { type filter hook input priority 0; policy drop;
iifname "lo" accept
ct state established,related accept
ct state invalid drop
meta l4proto { icmp, ipv6-icmp } accept
''' + f'tcp dport {{ {ports} }} accept\n' + (f"udp dport {{ {', '.join(map(str,udp))} }} accept\n" if udp else '') + '}\n}\n'


def apply(c, rs):
    old = NGINX.read_text()
    old_fw = Path('/etc/proxy-stack/firewall.nft').read_text() if Path('/etc/proxy-stack/firewall.nft').exists() else None
    new_fw = firewall(c, rs)
    candidate = render(c, rs)
    if old == candidate and old_fw == new_fw:
        return
    write(NGINX, candidate, 0o644)
    try:
        run('nginx', '-t')
        write(CONF / 'firewall.next', new_fw)
        exists = run('nft', 'list', 'table', 'inet', 'proxy_stack', check=False).returncode == 0
        # Delete+create in ONE nft transaction; no window without filtering.
        batch = ('delete table inet proxy_stack\n' if exists else '') + new_fw
        write(CONF / 'firewall.batch', batch)
        run('nft', '-c', '-f', CONF / 'firewall.batch')
        run('systemctl', 'reload', 'nginx')
        run('nft', '-f', CONF / 'firewall.batch')
        write(CONF / 'firewall.nft', new_fw)
    except Exception:
        write(NGINX, old, 0o644)
        run('systemctl', 'reload', 'nginx', check=False)
        raise
    save(BASE / 'routes.json', rs)


def attach_awg_hosts(inbounds, hosts):
    """AWG has no streamSettings; panel Hosts provide its public endpoint."""
    import copy
    result = copy.deepcopy(inbounds)
    for i in result:
        if i.get('protocol') != 'amneziawg' or not i.get('enable'):
            continue
        entries=[]
        for group in hosts:
            if group.get('isDisabled') or i['id'] not in group.get('inboundIds',[]):
                continue
            for address in group.get('hosts',[]):
                host, sep, number=address.rpartition(':')
                if not sep:
                    host=address;number=group.get('port') or i['port']
                entries.append({'dest':host,'port':port(number),'forceTls':group.get('security') or 'same'})
        i['streamSettings']={'externalProxy':entries}
    return result


def json_object(value):
    return json.loads(value or '{}') if isinstance(value, str) else (value or {})


def panel_api(c, path, body=None):
    token = (CONF / 'api-token').read_text().strip()
    headers = {'Host': c['panel'], 'Authorization': 'Bearer ' + token}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request('http://127.0.0.1:2053' + c['panel_path'] + 'panel/api/' + path,
                                 headers=headers, data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req, timeout=20) as response:
        result = json.load(response)
    if result.get('success') is not True:
        # API validation messages can echo supplied settings; do not log secrets.
        raise ValueError('Panel API rejected operation: ' + path.split('/')[0])
    return result.get('obj')


def x25519_pair(private=None):
    binary = '/usr/local/x-ui/bin/xray-linux-' + {'x86_64':'amd64', 'aarch64':'arm64'}[platform.machine()]
    args = [binary, 'x25519'] + (['-i', private] if private else [])
    try:
        output = run(*args).stdout
    except RuntimeError:
        raise ValueError('Cannot derive REALITY keys; no inbound changed') from None
    values = dict(re.findall(r'^(PrivateKey|PublicKey|Password(?: \(PublicKey\))?):\s*([A-Za-z0-9_-]+)\s*$', output, re.M))
    result = (values.get('PrivateKey', private), values.get('Password (PublicKey)', values.get('Password', values.get('PublicKey'))))
    if not all(v and len(v) == 43 for v in result):
        raise ValueError('Cannot generate supported REALITY keypair; no inbound changed')
    return result


def tcp_port_free(number):
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(('::', number))
        return True
    except OSError:
        return False


def prepare_inbound(inbound, all_inbounds, c, security=None, keypair=None, is_free=None):
    """Pure planner except optional key generation and free-port probes; creates no clients."""
    import copy
    i = copy.deepcopy(inbound)
    s = json_object(i.get('streamSettings'))
    kind = s.get('network', 'tcp')
    s.setdefault('network', kind)
    supported = ('tcp', 'raw', 'xhttp', 'grpc', 'ws', 'httpupgrade')
    if i.get('nodeId') or i['protocol'] not in ('vless', 'vmess', 'trojan') or kind not in supported:
        raise ValueError('Auto setup supports local VLESS, or VMess/Trojan over HTTP transports only')
    if security is None:
        security = 'tls' if kind in ('ws', 'httpupgrade') or '[TLS]' in i.get('remark', '').upper() else 'reality'
    if security == 'reality' and (i['protocol'] != 'vless' or kind not in ('tcp', 'raw', 'xhttp', 'grpc')):
        raise ValueError('Default REALITY requires VLESS RAW/XHTTP/gRPC; use TLS for other transports')
    if security == 'tls' and kind in ('tcp', 'raw'):
        raise ValueError('RAW TLS is not supported by this HTTP adapter; use REALITY or an HTTP transport')
    keypair = keypair or x25519_pair
    is_free = is_free or tcp_port_free
    others = [x for x in all_inbounds if x['id'] != i['id'] and not x.get('nodeId')]
    backend_ports = {port(x['port']) for x in others}
    protected = RESERVED | {10443, 9444, 11111, 62789} | set(c['ssh_ports'])
    # Include other public ports to avoid binding a backend over a nginx listener.
    public_ports = set()
    occupied = set()
    for other in others:
        stream = json_object(other.get('streamSettings'))
        for ep in stream.get('externalProxy', []):
            if ep.get('port'):
                public_ports.add(port(ep['port']))
                if other.get('enable') and stream.get('security') == 'reality':
                    occupied.add((ep.get('dest'), port(ep['port'])))
    p = port(i['port'])
    if p <= 1024 or p in protected | backend_ports | public_ports:
        p = next((n for n in range(12000, 13000) if n not in protected | backend_ports | public_ports and is_free(n)), None)
        if p is None:
            raise ValueError('No free local TCP port in 12000-12999')
    i.update(listen='127.0.0.1', port=p)
    s.setdefault('sockopt', {})['acceptProxyProtocol'] = security == 'reality'
    if kind in ('tcp', 'raw'):
        for key in ('tcpSettings', 'rawSettings'):
            if key in s:
                s[key]['acceptProxyProtocol'] = False  # Do not parse PROXY twice.
    settings = json_object(i['settings'])
    if security == 'reality':
        allowed = [c['site']] + c.get('reality_names', [])
        current = s.get('externalProxy', [])
        desired = None
        if current:
            ep = current[0]
            number = port(ep.get('port', 443))
            if ep.get('dest') in allowed and (ep['dest'], number) not in occupied and number not in backend_ports | {p} and (number == 443 or (number >= 1024 and number not in protected and (is_free(number) or any(r.get('id')==i['id'] and r.get('sni')==ep['dest'] and r.get('public_port')==number for r in c.get('_published_routes',[]))))):
                desired = (ep['dest'], number)
        if desired is None:
            desired = next(((name,443) for name in allowed if (name,443) not in occupied), None)
        if desired is None:
            number = next((n for n in range(8443, 8543) if n not in protected | backend_ports | public_ports | {p} and is_free(n)), None)
            if number is None:
                raise ValueError('No free public REALITY TCP port in 8443-8542')
            desired = (c['site'], number)
        name, public = desired
        rs = s.setdefault('realitySettings', {})
        private, public_key = keypair(rs.get('privateKey'))
        rs.update(privateKey=private, target='127.0.0.1:9443', serverNames=[name], xver=1)
        rs.pop('dest', None)
        short_ids = rs.get('shortIds', [])
        if not short_ids or any(not isinstance(x,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', x) for x in short_ids):
            rs['shortIds'] = [secrets.token_hex(8)]
        rs.setdefault('settings', {}).update(publicKey=public_key, serverName=name)
        rs['settings'].setdefault('fingerprint', 'chrome')
        s['security'] = 'reality'
        s['externalProxy'] = [{'dest':name,'port':public,'forceTls':'same','sni':name,'remark':''}]
    else:
        name, public = c['panel'], 443
        s['security'] = 'none'  # TLS terminates at nginx, never a public plaintext listener.
        s['externalProxy'] = [{'dest':name,'port':443,'forceTls':'tls','sni':name,'remark':''}]
        s.setdefault('sockopt', {})['trustedXForwardedFor'] = ['127.0.0.1/32']
    if kind in ('xhttp', 'grpc', 'ws', 'httpupgrade'):
        key = {'xhttp':'xhttpSettings','grpc':'grpcSettings','ws':'wsSettings','httpupgrade':'httpupgradeSettings'}[kind]
        transport = s.setdefault(key, {})
        field = 'serviceName' if kind == 'grpc' else 'path'
        path = '/' + transport.get(field, '').lstrip('/')
        occupied_paths = []
        for other in others:
            os_ = json_object(other.get('streamSettings'))
            for k in ('xhttpSettings','grpcSettings','wsSettings','httpupgradeSettings'):
                ts = os_.get(k, {})
                if ts.get('serviceName') or ts.get('path'):
                    occupied_paths.append('/' + ts.get('serviceName',ts.get('path','')).lstrip('/'))
        protected_paths = list(c['sub_paths'].values()) + [c['panel_path']] + occupied_paths
        if not re.fullmatch(r'/[A-Za-z0-9_-]{8,}(?:/[A-Za-z0-9_-]+)*', path) or any(path.startswith(x) or x.startswith(path) for x in protected_paths):
            path = '/proxy_' + secrets.token_hex(12)
        transport[field] = path.lstrip('/') if kind == 'grpc' else path
        if kind != 'grpc':
            transport['host'] = name
        if kind == 'xhttp':
            transport['mode'] = 'stream-one'
        for client in settings.get('clients', []):
            if client.get('flow'):
                client['flow'] = ''  # Vision is a RAW/TCP flow, not XHTTP/gRPC.
    i['settings'], i['streamSettings'] = settings, s
    routes([i], c)
    return i


def inbound_signature(i):
    """Exclude traffic counters; include all settings that a concurrent editor can change."""
    fields = ('enable','listen','port','protocol','remark','nodeId','expiryTime','total','sniffing','settings','streamSettings','shareAddrStrategy','shareAddr')
    data = {k:i.get(k) for k in fields}
    for key in ('settings','streamSettings','sniffing'):
        data[key] = json_object(data.get(key))
    return json.dumps(data, sort_keys=True)


def configure_inbound(c, i, inbounds, security=None):
    planning = dict(c)
    published = BASE/'routes.json'
    planning['_published_routes'] = json.loads(published.read_text()) if published.exists() else []
    prepared = prepare_inbound(i, inbounds, planning, security)
    fresh = next((x for x in panel_api(c,'inbounds/list') if x['id']==i['id']),None)
    if fresh is None:
        raise ValueError('Inbound was deleted during setup')
    if inbound_signature(fresh) != inbound_signature(i):
        raise ValueError('Inbound changed during setup; retry after closing its editor')
    # Root-only rollback snapshot; no database edits and no credentials in journal.
    save(BASE / 'auto-backups' / f"inbound-{i['id']}-{time.time_ns()}.json", i)
    panel_api(c, 'inbounds/update/' + str(i['id']), prepared)
    result = next((x for x in panel_api(c,'inbounds/list') if x['id']==i['id']),None)
    if result is None:
        raise ValueError('Inbound was deleted during setup')
    routes([result], c)
    return result


def auto_configure(c, inbounds):
    if not c.get('auto_setup', False):
        return inbounds
    state_file = BASE / 'auto-setup.json'
    state = json.loads(state_file.read_text()) if state_file.exists() else {'seen':{}}
    import copy
    result = copy.deepcopy(inbounds)
    for index, i in enumerate(result):
        ident = str(i['id'])
        if ident in state['seen'] or not i.get('enable'):
            continue
        stream = json_object(i.get('streamSettings'))
        eligible = not i.get('nodeId') and i['protocol']=='vless' and stream.get('network','tcp') in ('tcp','raw','xhttp','grpc','ws','httpupgrade')
        if not eligible or '[MANUAL]' in i.get('remark','').upper():
            state['seen'][ident] = 'manual'
            save(state_file,state)
            continue
        try:
            result[index] = configure_inbound(c, i, result)
        except Exception as error:
            raise ValueError(f'Auto setup failed for inbound {ident}: {error}') from None
        state['seen'][ident] = 'configured'
        save(state_file,state)
    return result


def set_auto_setup(c, enabled):
    if enabled:
        # Adopting an existing installation must not rewrite existing customer profiles.
        existing = panel_api(c,'inbounds/list')
        save(BASE / 'auto-setup.json', {'seen':{str(i['id']):'existing' for i in existing}})
    c['auto_setup'] = enabled
    save(CONF / 'config.json',c)
    print('Automatic setup of new VLESS inbounds:', 'enabled' if enabled else 'disabled')



def sync(c):
    token = (CONF / 'api-token').read_text().strip()
    req = urllib.request.Request('http://127.0.0.1:2053' + c['panel_path'] + 'panel/api/inbounds/list',
                                 headers={'Authorization': 'Bearer ' + token, 'Host': c['panel']})
    with urllib.request.urlopen(req, timeout=10) as r:
        response = json.load(r)
    if response.get('success') is not True or not isinstance(response.get('obj'), list):
        raise ValueError('Unexpected inbounds API response')
    inbounds = auto_configure(c, response['obj'])
    if any(i.get('protocol') == 'amneziawg' and i.get('enable') for i in inbounds):
        req = urllib.request.Request('http://127.0.0.1:2053' + c['panel_path'] + 'panel/api/hosts/list',
                                     headers={'Authorization': 'Bearer ' + token, 'Host': c['panel']})
        with urllib.request.urlopen(req, timeout=10) as r:
            hosts_response = json.load(r)
        if hosts_response.get('success') is not True or not isinstance(hosts_response.get('obj'), list):
            raise ValueError('Unexpected Hosts API response')
        inbounds = attach_awg_hosts(inbounds, hosts_response['obj'])
    rs = routes(inbounds, c)
    if c.get('reality_names'):
        cert = run('openssl','x509','-in','/etc/letsencrypt/live/proxy-stack/fullchain.pem','-noout','-ext','subjectAltName').stdout
        covered = set(re.findall(r'DNS:([^,\s]+)',cert))
        if not set(c['reality_names']).issubset(covered):
            raise ValueError('Extra REALITY names are missing from the certificate; use add-reality-name')
    apply(c, rs)
    save(BASE / 'sync-status.json', {'ok': True, 'at': timestamp(), 'routes': len(rs)})


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def healthcheck(c):
    """Check the running core and public HTTPS before declaring installation ready."""
    run('nginx', '-t')
    run('systemctl', 'is-active', 'nginx', 'x-ui', 'proxy-stack-sync.timer',
        'proxy-stack-firewall.service', 'certbot.timer')
    run('nft', 'list', 'table', 'inet', 'proxy_stack')
    status = panel_api(c, 'server/status')
    if not isinstance(status, dict) or status.get('xray', {}).get('state') != 'running':
        raise ValueError('Xray is not running; check journalctl -u x-ui')
    binary = '/usr/local/x-ui/bin/xray-linux-' + {'x86_64':'amd64', 'aarch64':'arm64'}[platform.machine()]
    run(binary, 'run', '-test', '-config', '/usr/local/x-ui/bin/config.json',
        env=dict(os.environ, XRAY_LOCATION_ASSET='/usr/local/x-ui/bin'))
    cover_body = None
    for label, url in [('site', 'https://' + c['site'] + '/'),
                       ('panel cover', 'https://' + c['panel'] + '/'),
                       ('panel', 'https://' + c['panel'] + c['panel_path'])]:
        try:
            # urlopen verifies the certificate chain and hostname. Never log the secret path.
            with urllib.request.urlopen(url, timeout=15) as response:
                body = response.read(65536)
                if response.status != 200 or b'<html' not in body.lower():
                    raise ValueError('Unexpected HTML response')
                if label == 'site':
                    cover_body = body
                elif label == 'panel cover' and body != cover_body:
                    raise ValueError('Panel root does not serve the cover site')
        except Exception:
            raise ValueError('HTTPS health check failed for ' + label + '; check DNS, certificate and nginx') from None
    # Shared certificates let HTTP/2 clients reuse one TLS connection for both hosts.
    # The stream router picked its backend using the original SNI: reject a different
    # authority with 421 so the client reconnects with that authority's own SNI.
    for sni, host, path in [(c['panel'], c['site'], '/'),
                            (c['site'], c['panel'], c['panel_path'])]:
        connection = http.client.HTTPSConnection(sni, timeout=15)
        try:
            connection.request('GET', path, headers={'Host': host})
            response = connection.getresponse()
            if response.status != 421:
                raise ValueError('Missing misdirected-request response')
            response.read()
        except Exception:
            raise ValueError('HTTPS routing check failed; regenerate nginx with proxyctl.py sync') from None
        finally:
            connection.close()
    print('Health checks passed: services, firewall, Xray, HTTPS and cross-domain routing.')


def unit(name, text):
    write(Path('/etc/systemd/system') / name, text, 0o644)


def bootstrap_db(c, username, password):
    run(BIN, 'setting', '-username', username, '-password', password, '-port', '2053',
        '-listenIP', '127.0.0.1', '-webBasePath', c['panel_path'])
    # Only once, offline, before the service starts. Later changes belong to the panel.
    with sqlite3.connect('/etc/x-ui/x-ui.db') as db:
        settings = {'subListen':'127.0.0.1', 'subPort':'2096', 'subEnable':'true',
                    'subJsonEnable':'true', 'subClashEnable':'true', 'webCertFile':'', 'webKeyFile':'',
                    'subCertFile':'', 'subKeyFile':'', 'devChannelEnable':'false',
                    'webDomain': c['panel'], 'subDomain': c['panel']}
        for name, path in c['sub_paths'].items():
            key = {'base':'sub', 'json':'subJson', 'clash':'subClash'}[name]
            settings[key+'Path'] = path
            settings[key+'URI'] = 'https://' + c['panel'] + path
        template = json.loads((APP / 'templates' / 'xray.json').read_text())
        template['routing']['rules'].extend([
            {'type':'field','domain':['domain:ru','domain:su','domain:xn--p1ai','geosite:category-ru'],'outboundTag':'direct'},
            {'type':'field','ip':['geoip:ru'],'outboundTag':'direct'}])
        template['routing']['domainStrategy'] = 'IPIfNonMatch'
        with tempfile.TemporaryDirectory() as testdir:
            candidate = Path(testdir)/'xray.json'
            candidate.write_text(json.dumps(template))
            env = dict(os.environ, XRAY_LOCATION_ASSET='/usr/local/x-ui/bin')
            run('/usr/local/x-ui/bin/xray-linux-'+{'x86_64':'amd64','aarch64':'arm64'}[platform.machine()],
                'run','-test','-config',candidate,env=env)
        settings['xrayTemplateConfig'] = json.dumps(template)
        for k, v in settings.items():
            db.execute('DELETE FROM settings WHERE key=?', (k,))
            db.execute('INSERT INTO settings (key,value) VALUES (?,?)', (k,v))
    output = run(BIN, 'setting', '-tokenName', 'proxy-stack-sync', '-tokenScope', 'node-sync', '-getApiToken').stdout
    match = re.search(r'^apiToken:\s*(\S+)\s*$', output, re.M)
    if not match:
        raise ValueError('Installed panel lacks supported scoped API token CLI')
    write(CONF / 'api-token', match[1]+'\n')


def preflight(args):
    osinfo = Path('/etc/os-release').read_text()
    if not re.search(r'^ID=debian$', osinfo, re.M) or not re.search(r'^VERSION_ID="?13"?$', osinfo, re.M):
        raise ValueError('Only Debian 13 is supported')
    if BASE.exists() or CONF.exists() or APP.exists() or Path('/usr/local/x-ui').exists() or Path('/etc/x-ui').exists() or Path('/etc/nginx').exists():
        raise ValueError('Existing installation/configuration found; refusing overwrite')
    if args.panel in args.reality_name or args.site in args.reality_name or len(set(args.reality_name)) != len(args.reality_name):
        raise ValueError('Extra REALITY names must be distinct from site/panel and each other')
    if args.site == args.panel:
        raise ValueError('Two different domains required')
    for service in ('ufw', 'firewalld', 'docker'):
        if run('systemctl', 'is-active', '--quiet', service, check=False).returncode == 0:
            raise ValueError('Existing firewall/container service: ' + service)
    if shutil.which('nft') and run('nft', 'list', 'ruleset').stdout.strip():
        raise ValueError('Existing nft ruleset; integration requires manual review')
    ssh = run('/usr/sbin/sshd', '-T').stdout
    ssh_ports = sorted({port(x.split()[1]) for x in ssh.splitlines() if x.startswith('port ')})
    if not ssh_ports:
        raise ValueError('Cannot determine SSH ports')
    if os.environ.get('SSH_CONNECTION'):
        ssh_ports = sorted(set(ssh_ports + [port(os.environ['SSH_CONNECTION'].split()[3])]))
    ips = json.loads(run('ip', '-j', 'address', 'show', 'scope', 'global').stdout)
    local = {a['local'] for i in ips for a in i['addr_info'] if 'local' in a}
    public = sorted(ip for ip in local if ipaddress.ip_address(ip).is_global)
    for name in [args.site, args.panel]+args.reality_name:
        addresses = {x[4][0] for x in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)}
        if not addresses or not addresses.issubset(set(public)):
            raise ValueError(f'{name}: every A/AAAA must point directly to an address on this VPS; no CDN/NAT')
    for p in RESERVED | {10443,9444}:
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET6, kind) as sock:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                sock.bind(('::',p))
    return ssh_ports, public


def install(args):
    ssh_ports, ips = preflight(args)
    r, asset = release()
    for path in (BASE, CONF):
        path.mkdir(mode=0o700)
    c = {'site': args.site, 'panel': args.panel, 'email': args.email, 'reality_names':args.reality_name, 'auto_setup':not args.manual_inbounds,
         'panel_path': '/'+secrets.token_hex(16)+'/',
         'sub_paths': {k:'/'+secrets.token_hex(16)+'/' for k in ('base','json','clash')},
         'ssh_ports':ssh_ports, 'public_ips':ips, 'tag':r['tag_name'], 'stage':'preparing',
         'theme':args.theme or secrets.choice(['astronomy','plants','photography','travel','cooking'])}
    save(CONF / 'config.json', c)
    try:
        run('apt-get', 'update')
        run('apt-get', 'install', '-y', 'nginx', 'libnginx-mod-stream', 'certbot', 'nftables', 'ca-certificates', 'curl', 'logrotate')
        shutil.copytree(Path(__file__).parent, APP, ignore=shutil.ignore_patterns('__pycache__','.git'))
        shutil.copy2(NGINX, BASE / 'nginx.original')
        Path('/var/www/proxy-site').mkdir(mode=0o755)
        Path('/var/www/proxy-site').chmod(0o755)
        shutil.copy2(APP / 'sites' / (c['theme']+'.html'), '/var/www/proxy-site/index.html')
        Path('/var/www/proxy-acme').mkdir(mode=0o755)
        Path('/var/www/proxy-acme').chmod(0o755)
        write(NGINX, render(c, [], tls=False), 0o644)
        run('nginx', '-t')
        run('systemctl', 'enable', '--now', 'nginx')
        run('systemctl', 'reload', 'nginx')
        run('certbot', 'certonly', '--webroot', '-w', '/var/www/proxy-acme', '--non-interactive',
            '--agree-tos', *(['--email', args.email] if args.email else ['--register-unsafely-without-email']), '--cert-name', 'proxy-stack', '-d', c['site'], '-d', c['panel'], *[v for name in c['reality_names'] for v in ('-d',name)])
        write('/etc/logrotate.d/proxy-stack', '/var/log/x-ui/*.log {\n daily\n rotate 7\n maxsize 10M\n missingok\n notifempty\n compress\n copytruncate\n}\n', 0o644)
        write('/etc/letsencrypt/renewal-hooks/deploy/proxy-stack', '#!/bin/sh\nset -eu\nnginx -t\nsystemctl reload nginx\n', 0o755)
        with tempfile.TemporaryDirectory() as tmp:
            root, service = payload(r, asset, Path(tmp))
            shutil.copytree(root, '/usr/local/x-ui')
            unit('x-ui.service', service)
        username, password = 'admin_'+secrets.token_hex(4), secrets.token_urlsafe(24)
        bootstrap_db(c, username, password)
        write(CONF / 'credentials', f'URL=https://{c["panel"]}{c["panel_path"]}\nUSERNAME={username}\nPASSWORD={password}\n')
        unit('proxy-stack-firewall.service', '''[Unit]
Description=Proxy stack owned firewall table
Before=nginx.service x-ui.service
After=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/proxy-stack/load-firewall
ExecStop=/usr/sbin/nft delete table inet proxy_stack
[Install]
WantedBy=multi-user.target
''')
        unit('proxy-stack-sync.service', '''[Unit]
Description=Compile 3x-ui inbounds to nginx allowlist
After=nginx.service x-ui.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/proxy-stack/proxyctl.py sync
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
''')
        unit('proxy-stack-sync.timer', '''[Unit]
Description=Refresh proxy routes every 15 seconds
[Timer]
OnBootSec=30s
OnUnitInactiveSec=15s
AccuracySec=1s
Unit=proxy-stack-sync.service
[Install]
WantedBy=timers.target
''')
        apply(c, [])
        # Start the unit without duplicating the already installed table.
        # Its loader atomically replaces only our own table.
        shutil.copy2(APP / 'templates' / 'load-firewall.sh', CONF / 'load-firewall')
        (CONF / 'load-firewall').chmod(0o700)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', 'proxy-stack-firewall.service', 'x-ui.service', 'proxy-stack-sync.timer', 'certbot.timer')
        for attempt in range(15):
            try:
                sync(c)
                healthcheck(c)
                break
            except Exception:
                if attempt == 14:
                    raise
                time.sleep(1)
        c['stage'] = 'installed'
        save(CONF / 'config.json', c)
        print('Installed. Read root-only /etc/proxy-stack/credentials. Enable 2FA in panel.')
    except Exception:
        c['stage'] = 'failed'
        save(CONF / 'config.json', c)
        print('Installation interrupted. State retained. Run uninstall to roll back before retrying.', file=sys.stderr)
        raise


def add_reality_name(c, name):
    domain(name)
    if name == c['panel']:
        raise ValueError('Panel domain cannot be used by a REALITY passthrough')
    if name in {c['site'], *c.get('reality_names',[])}:
        print('Name already configured:',name)
        return
    addresses={x[4][0] for x in socket.getaddrinfo(name,443,type=socket.SOCK_STREAM)}
    if not addresses or not addresses.issubset(set(c['public_ips'])):
        raise ValueError('Every A/AAAA of the new name must point directly to this VPS; add DNS first')
    sync(c)
    rs=json.loads((BASE/'routes.json').read_text()) if (BASE/'routes.json').exists() else []
    import copy
    proposed=copy.deepcopy(c)
    proposed['reality_names']=sorted(set(c.get('reality_names',[])+[name]))
    old_nginx=NGINX.read_text()
    # Publish HTTP-01 for the new name while retaining all existing routes.
    write(NGINX,render(proposed,rs),0o644)
    try:
        run('nginx','-t')
        run('systemctl','reload','nginx')
        names=[c['site'],c['panel']]+proposed['reality_names']
        run('certbot','certonly','--expand','--webroot','-w','/var/www/proxy-acme',
            '--non-interactive','--agree-tos',
            *(['--email',c['email']] if c.get('email') else ['--register-unsafely-without-email']),
            '--cert-name','proxy-stack',*[v for n in names for v in ('-d',n)])
        run('nginx','-t')
        run('systemctl','reload','nginx')
        save(CONF/'config.json',proposed)
    except Exception:
        write(NGINX,old_nginx,0o644)
        run('systemctl','reload','nginx',check=False)
        raise
    print('REALITY name and certificate configured:',name)


def backup():
    dest = BASE / ('backup-'+str(time.time_ns()))
    dest.mkdir(mode=0o700)
    # SQLite online backup avoids copying an inconsistent WAL database.
    with sqlite3.connect('/etc/x-ui/x-ui.db') as source, sqlite3.connect(dest / 'x-ui.db') as target:
        source.backup(target)
    shutil.copytree(CONF, dest / 'config')
    if (BASE/'auto-setup.json').exists():
        shutil.copy2(BASE/'auto-setup.json',dest/'auto-setup.json')
    shutil.copytree('/usr/local/x-ui', dest / 'x-ui')
    shutil.copy2(NGINX, dest / 'nginx.conf')
    shutil.copy2('/etc/systemd/system/x-ui.service', dest / 'x-ui.service')
    print('Backup:', dest)
    return dest


def restore(dest):
    dest = Path(dest).resolve()
    if dest.parent != BASE or not dest.name.startswith('backup-'):
        raise ValueError('Restore accepts only this installation\'s local backup directory')
    for name in ('x-ui.db','config/config.json','x-ui/x-ui','nginx.conf','x-ui.service'):
        if not (dest/name).is_file():
            raise ValueError('Incomplete backup')
    run('systemctl', 'stop', 'proxy-stack-sync.timer', 'proxy-stack-sync.service', 'x-ui')
    shutil.rmtree('/usr/local/x-ui')
    shutil.copytree(dest / 'x-ui', '/usr/local/x-ui')
    for name in ('x-ui.db-wal','x-ui.db-shm'):
        Path('/etc/x-ui',name).unlink(missing_ok=True)
    shutil.copy2(dest / 'x-ui.db', '/etc/x-ui/x-ui.db')
    shutil.copytree(dest / 'config', CONF, dirs_exist_ok=True)
    if (dest/'auto-setup.json').exists():
        shutil.copy2(dest/'auto-setup.json',BASE/'auto-setup.json')
    else:
        (BASE/'auto-setup.json').unlink(missing_ok=True)
    shutil.copy2(dest / 'nginx.conf', NGINX)
    shutil.copy2(dest / 'x-ui.service', '/etc/systemd/system/x-ui.service')
    run('nginx','-t')
    run('systemctl','daemon-reload')
    c = json.loads((CONF / 'config.json').read_text())
    # Restore firewall in an atomic transaction.
    batch = 'delete table inet proxy_stack\n' + (CONF/'firewall.nft').read_text()
    write(CONF/'firewall.batch', batch)
    run('nft','-f',CONF/'firewall.batch')
    run('systemctl','reload','nginx')
    run('systemctl','start','x-ui','proxy-stack-sync.timer')
    return c


def update(c):
    r, asset = release()
    if r['tag_name'] == c['tag']:
        print('Already latest stable:', c['tag'])
        return
    with tempfile.TemporaryDirectory() as tmp:
        root, service = payload(r, asset, Path(tmp))
        previous = backup()
        try:
            run('systemctl','stop','proxy-stack-sync.timer','proxy-stack-sync.service','x-ui')
            shutil.rmtree('/usr/local/x-ui')
            shutil.copytree(root,'/usr/local/x-ui')
            unit('x-ui.service',service)
            run('systemctl','daemon-reload')
            run('systemctl','start','x-ui')
            for attempt in range(15):
                try:
                    sync(c)
                    break
                except Exception:
                    if attempt == 14:
                        raise
                    time.sleep(1)
            c['tag'] = r['tag_name']
            save(CONF/'config.json',c)
            run('systemctl','start','proxy-stack-sync.timer')
        except Exception:
            restore(previous)
            raise


def uninstall(c, purge=False):
    if c['stage'] == 'installed' and not purge:
        backup()
    for name in ('proxy-stack-sync.timer','proxy-stack-sync.service','proxy-stack-firewall.service','x-ui.service'):
        run('systemctl','disable','--now',name,check=False)
        Path('/etc/systemd/system',name).unlink(missing_ok=True)
    run('nft','delete','table','inet','proxy_stack',check=False)
    if (BASE/'nginx.original').exists():
        shutil.copy2(BASE/'nginx.original',NGINX)
        run('nginx','-t')
        run('systemctl','reload','nginx',check=False)
    Path('/etc/letsencrypt/renewal-hooks/deploy/proxy-stack').unlink(missing_ok=True)
    Path('/etc/logrotate.d/proxy-stack').unlink(missing_ok=True)
    if shutil.which('certbot') and Path('/etc/letsencrypt/renewal/proxy-stack.conf').exists():
        run('certbot','delete','--non-interactive','--cert-name','proxy-stack')
    for path in ('/usr/local/x-ui','/etc/x-ui','/var/log/x-ui','/var/www/proxy-site','/var/www/proxy-acme'):
        if Path(path).exists():
            shutil.rmtree(path)
    # preflight disallows existing nginx: these packages belong to this installation.
    run('apt-get','purge','-y','nginx','nginx-common','libnginx-mod-stream')
    run('systemctl','daemon-reload')
    if purge or (c['stage'] != 'installed' and not list(BASE.glob('backup-*'))):
        shutil.rmtree(BASE)
    for path in (CONF, APP):
        if path.exists():
            shutil.rmtree(path)
    print('Removed. Backups retained in /var/lib/proxy-stack unless purge was used.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command',required=True)
    ins = sub.add_parser('install')
    ins.add_argument('--site',required=True,type=domain)
    ins.add_argument('--panel',required=True,type=domain)
    ins.add_argument('--email',default='')
    ins.add_argument('--reality-name',action='append',default=[],type=domain,help='Additional DNS name for independent REALITY on TCP 443; repeatable')
    ins.add_argument('--manual-inbounds',action='store_true',help='Disable automatic first-time setup of newly created VLESS inbounds')
    ins.add_argument('--theme',choices=['astronomy','plants','photography','travel','cooking'])
    for name in ('sync','status','doctor','backup','update','uninstall','purge'):
        sub.add_parser(name)
    auto = sub.add_parser('auto-setup',help='Configure newly created VLESS inbounds once; existing profiles are preserved')
    auto.add_argument('mode',choices=['on','off'])
    configure = sub.add_parser('configure-inbound',help='Explicitly configure an existing inbound for REALITY or nginx TLS')
    configure.add_argument('id',type=int)
    configure.add_argument('--security',choices=['reality','tls'],default='reality')
    addname = sub.add_parser('add-reality-name',help='After adding DNS, extend nginx and certificate for another REALITY SNI on TCP 443')
    addname.add_argument('name',type=domain)
    res = sub.add_parser('restore')
    res.add_argument('directory')
    ren = sub.add_parser('render',help='Offline render for review/tests; no root required')
    ren.add_argument('config')
    ren.add_argument('inbounds')
    args = p.parse_args()
    if args.command == 'render':
        c = json.loads(Path(args.config).read_text())
        print(render(c,routes(json.loads(Path(args.inbounds).read_text()),c)))
        return
    if os.geteuid() != 0:
        p.error('Run as root on the target Debian 13 VPS')
    os.umask(0o077)
    with open('/run/lock/proxy-stack.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.command == 'install':
            if (CONF/'config.json').exists():
                c = json.loads((CONF/'config.json').read_text())
                if c['stage'] == 'installed' and (c['site'],c['panel']) == (args.site,args.panel) and sorted(c.get('reality_names',[])) == sorted(args.reality_name):
                    print('Already installed; use doctor/update.')
                    return
            install(args)
            return
        if args.command == 'purge' and not (CONF/'config.json').exists() and BASE.exists():
            shutil.rmtree(BASE)
            print('Retained local backups removed.')
            return
        c = json.loads((CONF/'config.json').read_text())
        if args.command == 'sync':
            try:
                sync(c)
            except Exception as e:
                save(BASE/'sync-status.json',{'ok':False,'at':timestamp(),'error':str(e)})
                raise
        elif args.command in ('status','doctor'):
            print(json.dumps({k:v for k,v in c.items() if k not in ('panel_path','sub_paths')},indent=2))
            if (BASE/'sync-status.json').exists():
                print((BASE/'sync-status.json').read_text())
            if args.command == 'doctor':
                sync(c)
                healthcheck(c)
        elif args.command == 'auto-setup':
            set_auto_setup(c,args.mode=='on')
        elif args.command == 'configure-inbound':
            items = panel_api(c,'inbounds/list')
            i = next((i for i in items if i['id']==args.id),None)
            if i is None:
                raise ValueError('Inbound ID not found')
            configure_inbound(c,i,items,args.security)
            if c.get('auto_setup'):
                path=BASE/'auto-setup.json'
                state=json.loads(path.read_text()) if path.exists() else {'seen':{}}
                state['seen'][str(args.id)]='configured'
                save(path,state)
            sync(c)
        elif args.command == 'add-reality-name':
            add_reality_name(c,args.name)
        elif args.command == 'backup':
            backup()
        elif args.command == 'restore':
            backup()
            restore(args.directory)
        elif args.command == 'update':
            update(c)
        elif args.command in ('uninstall','purge'):
            uninstall(c,args.command=='purge')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as e:
        print('ERROR:',e,file=sys.stderr)
        sys.exit(1)
