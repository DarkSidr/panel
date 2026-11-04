"""Opt-in: isolated loopback servers reuse an existing client; no panel objects created.
Run as root on the installed VPS: python3 tests/reality_smoke.py --inbound 3
Tests REALITY RAW, XHTTP and gRPC through a separate nginx process and real HTTPS.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


def obj(value):
    return json.loads(value or '{}') if isinstance(value,str) else value or {}


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inbound',type=int,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    c=json.loads(Path('/etc/proxy-stack/config.json').read_text())
    token=Path('/etc/proxy-stack/api-token').read_text().strip()
    req=urllib.request.Request('http://127.0.0.1:2053'+c['panel_path']+'panel/api/inbounds/list',headers={'Host':c['panel'],'Authorization':'Bearer '+token})
    with urllib.request.urlopen(req,timeout=10) as r:
        inbound=next(i for i in json.load(r)['obj'] if i['id']==args.inbound)
    stream=obj(inbound['streamSettings']);settings=obj(inbound['settings'])
    assert stream['security']=='reality' and inbound['protocol']=='vless'
    client=settings['clients'][0]
    with urllib.request.urlopen('https://'+c['panel']+c['sub_paths']['json']+client['subId'],timeout=10) as r:
        configs=json.load(r)
    configs=configs if isinstance(configs,list) else [configs]
    source=next(o for cfg in configs for o in cfg.get('outbounds',[]) if o.get('streamSettings',{}).get('security')=='reality')
    binary='/usr/local/x-ui/bin/xray-linux-'+{'x86_64':'amd64','aarch64':'arm64'}[os.uname().machine]
    for transport in ('tcp','xhttp','grpc'):
        backend,frontend,socks=free_port(),free_port(),free_port()
        rs=stream['realitySettings']
        serverstream={'network':transport,'security':'reality', 'sockopt':{'acceptProxyProtocol':True},
                      'realitySettings':{'target':'127.0.0.1:9443','serverNames':[c['site']],'xver':1,
                                         'privateKey':rs['privateKey'],'shortIds':rs['shortIds']}}
        clientout=copy.deepcopy(source)
        cs=clientout['streamSettings'];cs['network']=transport
        for key in ('tcpSettings','rawSettings','xhttpSettings','grpcSettings','sockopt'):
            cs.pop(key,None)
        if transport=='xhttp':
            serverstream['xhttpSettings']={'path':'/isolated_smoke_test','mode':'stream-one'}
            cs['xhttpSettings']={'path':'/isolated_smoke_test','mode':'stream-one'}
        if transport=='grpc':
            serverstream['grpcSettings']={'serviceName':'isolated_smoke_test'}
            cs['grpcSettings']={'serviceName':'isolated_smoke_test'}
        if 'vnext' in clientout['settings']:
            server=clientout['settings']['vnext'][0];server.update(address='127.0.0.1',port=frontend)
            for user in server['users']:user['flow']=''
        else:
            clientout['settings'].update(address='127.0.0.1',port=frontend,flow='')
        cs['realitySettings']['serverName']=c['site']
        servercfg={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':backend,'protocol':'vless','settings':{'clients':[{'id':client['id']}],'decryption':'none'},'streamSettings':serverstream}], 'outbounds':[{'protocol':'freedom','settings':{}}]}
        clientcfg={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{}}],'outbounds':[clientout]}
        with tempfile.TemporaryDirectory(prefix='proxy-reality-smoke-',dir='/run') as d:
            root=Path(d);procs=[]
            try:
                for name,cfg in [('server',servercfg),('client',clientcfg)]:
                    path=root/(name+'.json');path.write_text(json.dumps(cfg))
                    subprocess.run([binary,'run','-test','-config',str(path)],check=True,capture_output=True)
                    with open(root/(name+'.log'),'w') as log:
                        procs.append(subprocess.Popen([binary,'run','-config',str(path)],stdout=log,stderr=log))
                path=root/'nginx.conf'
                path.write_text(f'''include /etc/nginx/modules-enabled/*.conf;
pid {root}/nginx.pid;
error_log {root}/nginx.log;
events {{ worker_connections 128; }}
stream {{ server {{ listen 127.0.0.1:{frontend}; proxy_protocol on; proxy_pass 127.0.0.1:{backend}; }} }}
''')
                subprocess.run(['nginx','-t','-c',str(path)],check=True,capture_output=True)
                with open(root/'nginx-stdout.log','w') as log:
                    procs.append(subprocess.Popen(['nginx','-c',str(path),'-g','daemon off;'],stdout=log,stderr=log))
                time.sleep(1)
                result=subprocess.run(['curl','--socks5-hostname',f'127.0.0.1:{socks}','--max-time','20','-sS','-o','/dev/null','-w','%{http_code}','https://example.com/'],capture_output=True,text=True)
                assert result.returncode==0 and result.stdout=='200',f'{transport}: tunnel failed (exit {result.returncode}, HTTP {result.stdout})'
                print(f'{transport} + REALITY via nginx PROXY protocol: HTTPS 200',flush=True)
            finally:
                for proc in reversed(procs):
                    proc.terminate()
                for proc in reversed(procs):
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()


if __name__=='__main__':
    main()
