"""Check an existing REALITY profile from its actual JSON subscription.
No users/inbounds are created. Run on the VPS as root with --inbound ID.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


def obj(v):
    return json.loads(v or '{}') if isinstance(v,str) else v or {}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inbound',type=int,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    c=json.loads(Path('/etc/proxy-stack/config.json').read_text())
    token=Path('/etc/proxy-stack/api-token').read_text().strip()
    req=urllib.request.Request('http://127.0.0.1:2053'+c['panel_path']+'panel/api/inbounds/list',headers={'Host':c['panel'],'Authorization':'Bearer '+token})
    with urllib.request.urlopen(req,timeout=10) as r:
        i=next(i for i in json.load(r)['obj'] if i['id']==args.inbound)
    s=obj(i['streamSettings']);client=obj(i['settings'])['clients'][0]
    assert s.get('security')=='reality','This checker expects an existing REALITY inbound'
    expected=s['externalProxy'][0]
    with urllib.request.urlopen('https://'+c['panel']+c['sub_paths']['json']+client['subId'],timeout=15) as r:
        configs=json.load(r)
    configs=configs if isinstance(configs,list) else [configs]
    candidates=[]
    for cfg in configs:
        for o in cfg.get('outbounds',[]):
            stream=o.get('streamSettings',{})
            settings=o.get('settings',{})
            server=settings['vnext'][0] if 'vnext' in settings else settings
            if stream.get('security')=='reality' and stream.get('network')==s['network'] and server.get('address')==expected['dest'] and server.get('port')==expected['port']:
                candidates.append(o)
    assert candidates,'Public endpoint/transport missing from JSON subscription'
    out=candidates[0]
    assert out['streamSettings']['realitySettings']['serverName'] in s['realitySettings']['serverNames']
    print('Subscription:',s['network'],'REALITY',expected['dest'],expected['port'],flush=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));socks=sock.getsockname()[1]
    config={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{}}],'outbounds':[out]}
    binary='/usr/local/x-ui/bin/xray-linux-'+{'x86_64':'amd64','aarch64':'arm64'}[os.uname().machine]
    with tempfile.TemporaryDirectory(prefix='proxy-profile-',dir='/run') as d:
        path=Path(d)/'client.json';path.write_text(json.dumps(config))
        with open(Path(d)/'client.log','w') as log:
            proc=subprocess.Popen([binary,'run','-config',str(path)],stdout=log,stderr=log)
            try:
                time.sleep(1)
                r=subprocess.run(['curl','--socks5-hostname',f'127.0.0.1:{socks}','--max-time','20','-sS','-o','/dev/null','-w','%{http_code}','https://example.com/'],capture_output=True,text=True)
                assert r.returncode==0 and r.stdout=='200',f'Tunnel failed: curl exit {r.returncode}, HTTP {r.stdout}'
                print('Existing client via public nginx endpoint: HTTPS 200',flush=True)
            finally:
                proc.terminate()
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()


if __name__=='__main__':
    main()
