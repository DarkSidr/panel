"""Run on Debian with nginx/certificates installed. No clients or live config changes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from test_proxyctl import C, inbound, m
c=json.loads(Path('/etc/proxy-stack/config.json').read_text())
for kind in ['ws','grpc','xhttp','httpupgrade','reality','udp']:
    i=inbound(kind if kind not in ('reality','udp') else 'tcp')
    s=i['streamSettings']
    host=c['panel'];p=443;tls='tls'
    if kind=='reality':
        host=c['site'];tls='same'
        s.update(security='reality',tcpSettings={'acceptProxyProtocol':True},realitySettings={'serverNames':[host],'target':'127.0.0.1:9443','xver':1})
    if kind=='udp':
        i['protocol']='amneziawg';p=i['port'];tls='same'
    s['externalProxy']=[{'dest':host,'port':p,'forceTls':tls}]
    with tempfile.NamedTemporaryFile(mode='w',suffix='.conf') as f:
        f.write(m.render(c,m.routes([i],c)));f.flush()
        subprocess.run(['nginx','-t','-c',f.name],check=True,capture_output=True)
    print(kind, 'nginx -t OK')

# Check parallel REALITY layouts without changing DNS, panel objects or live nginx.
from test_proxyctl import Tests
helper=Tests()
for layout in ('ports','names'):
    extra=dict(c)
    if layout=='ports':
        items=[helper.real('tcp',12010,443,sni=c['site']),helper.real('xhttp',12011,8443,sni=c['site']),helper.real('grpc',12012,8444,sni=c['site'])]
    else:
        extra['reality_names']=['xh.example.org','grpc.example.org']
        items=[helper.real('tcp',12010,443,sni=c['site']),helper.real('xhttp',12011,443,sni='xh.example.org'),helper.real('grpc',12012,443,sni='grpc.example.org')]
    with tempfile.NamedTemporaryFile(mode='w',suffix='.conf') as f:
        f.write(m.render(extra,m.routes(items,extra)));f.flush()
        subprocess.run(['nginx','-t','-c',f.name],check=True,capture_output=True)
    print('parallel REALITY '+layout+' nginx -t OK')
