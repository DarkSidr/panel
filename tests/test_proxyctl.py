import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('proxyctl',Path(__file__).parents[1]/'proxyctl.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
C={'site':'example.org','panel':'lk.example.org','panel_path':'/adminsecret/', 'sub_paths':{'base':'/subscription/','json':'/jsonsecret/','clash':'/clashsecret/'},'public_ips':['192.0.2.1'],'ssh_ports':[2222]}
def inbound(kind='ws',p=12000,path='/transportsecret'):
    return {'id':1,'enable':True,'nodeId':None,'listen':'127.0.0.1','port':p,'protocol':'vless','streamSettings':{'network':kind,'security':'none',kind+'Settings':{'path':path,'serviceName':path[1:],'mode':'stream-one'},'externalProxy':[{'dest':C['panel'],'port':443,'forceTls':'tls'}]}}
class Tests(unittest.TestCase):
    def test_transports_and_subscription(self):
        for kind in ['ws','grpc','xhttp','httpupgrade']:
            rs=m.routes([inbound(kind)],C);out=m.render(C,rs)
            self.assertIn('127.0.0.1:12000',out)
            for path in C['sub_paths'].values():self.assertIn('location ^~ '+path,out)
            self.assertIn('proxy_cache off',out)
            self.assertNotIn('$fwdport',out)
    def test_admin_assets_and_api_are_not_login_throttled(self):
        out=m.render(C,[])
        self.assertNotIn('zone=panel',out)
        self.assertIn('location = /adminsecret/login { limit_req zone=login',out)
        self.assertNotIn('location ^~ /adminsecret/ { limit_req',out)

    def test_public_and_reserved_ports(self):
        for key,value in [('listen','0.0.0.0'),('port',2053),('port',65536)]:
            i=inbound();i[key]=value
            with self.assertRaises(ValueError):m.routes([i],C)
    def test_path_injection_and_overlap(self):
        for path in ['/bad;thing','/subscription/anything','/adminsecret/','/transportsecret{']:
            with self.assertRaises(ValueError):m.routes([inbound(path=path)],C)
        with self.assertRaises(ValueError):m.routes([inbound(),inbound(p=13000)],C)
    def test_subscription_endpoint_required(self):
        i=inbound();i['streamSettings']['externalProxy']=[]
        with self.assertRaisesRegex(ValueError,'External Proxy'):m.routes([i],C)
    def test_reality(self):
        i=inbound('tcp');s=i['streamSettings'];s.update(security='reality',tcpSettings={'acceptProxyProtocol':True},realitySettings={'serverNames':[C['site']],'target':'127.0.0.1:9443','xver':1},externalProxy=[{'dest':C['site'],'port':443,'forceTls':'same'}])
        self.assertEqual(m.routes([i],C)[0]['kind'],'reality')
        with self.assertRaises(ValueError):m.routes([i,copy.deepcopy(i)],C)
        s['realitySettings']['xver']=0
        with self.assertRaises(ValueError):m.routes([i],C)
    def real(self,kind='tcp',backend=12000,public=443,sni=None):
        i=inbound(kind,p=backend);s=i['streamSettings']
        sni=sni or C['site']
        s.update(security='reality',sockopt={'acceptProxyProtocol':True},realitySettings={'serverNames':[sni],'target':'127.0.0.1:9443','xver':1},externalProxy=[{'dest':sni,'port':public,'forceTls':'same'}])
        return i

    def test_all_supported_reality_transports(self):
        for kind in ('tcp','raw','xhttp','grpc'):
            rs=m.routes([self.real(kind)],C)
            self.assertEqual(rs[0]['kind'],'reality')
            self.assertEqual(rs[0]['transport'],kind)
        with self.assertRaisesRegex(ValueError,'unsupported transport'):
            m.routes([self.real('ws')],C)

    def test_parallel_reality_with_public_ports(self):
        rows=[self.real('tcp',12000,443),self.real('xhttp',12001,8443),self.real('grpc',12002,8444)]
        rs=m.routes(rows,C);out=m.render(C,rs)
        for public,backend in [(443,12000),(8443,12001),(8444,12002)]:
            self.assertIn(f'listen {public};',out)
            self.assertIn(f"{C['site']} 127.0.0.1:{backend};",out)
        self.assertIn('8443, 8444',m.firewall(C,rs))
        self.assertIn('location ^~ /subscription/',out)
        with self.assertRaisesRegex(ValueError,'Duplicate REALITY'):
            m.routes([self.real('tcp',12000),self.real('xhttp',12001)],C)

    def test_parallel_reality_with_sni(self):
        c=copy.deepcopy(C);c['reality_names']=['xh.example.org','grpc.example.org']
        rs=m.routes([self.real('tcp',12000),self.real('xhttp',12001,sni='xh.example.org'),self.real('grpc',12002,sni='grpc.example.org')],c)
        out=m.render(c,rs)
        self.assertEqual(out.count('listen 443;'),1)
        self.assertIn('xh.example.org 127.0.0.1:12001;',out)
        self.assertIn('grpc.example.org 127.0.0.1:12002;',out)
        with self.assertRaisesRegex(ValueError,'configured site SNI'):
            m.routes([self.real('xhttp',sni='unconfigured.example.org')],C)
        c['reality_names']=[C['panel']]
        with self.assertRaisesRegex(ValueError,'panel domain'):
            m.routes([],c)

    def test_reality_requires_proxy_and_reserved_ports_are_rejected(self):
        for kind in ('xhttp','grpc'):
            i=self.real(kind);i['streamSettings'].pop('sockopt')
            with self.assertRaisesRegex(ValueError,'PROXY protocol'):m.routes([i],C)
        for public in [22,2222,7443,9443,12000]:
            with self.assertRaises(ValueError):m.routes([self.real(public=public)],C)

    def test_add_name_rolls_back_on_acme_failure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);nginx=root/'nginx.conf';nginx.write_text('previous nginx')
            c=copy.deepcopy(C);c['email']=''
            m.save(root/'config.json',c)
            def command(*args,**kwargs):
                if args[0]=='certbot':raise RuntimeError('ACME failed')
                return None
            with patch.object(m,'NGINX',nginx),patch.object(m,'CONF',root),patch.object(m,'BASE',root),patch.object(m,'sync'),patch.object(m,'run',side_effect=command),patch.object(m.socket,'getaddrinfo',return_value=[(None,None,None,None,('192.0.2.1',443))]):
                with self.assertRaisesRegex(RuntimeError,'ACME failed'):m.add_reality_name(c,'xh.example.org')
            self.assertEqual(nginx.read_text(),'previous nginx')
            self.assertEqual(__import__('json').loads((root/'config.json').read_text()),c)

    def test_udp(self):
        i=inbound();i['protocol']='amneziawg';i['streamSettings']['externalProxy']=[{'dest':C['panel'],'port':12000,'forceTls':'same'}]
        rs=m.routes([i],C)
        self.assertIn('192.0.2.1:12000 udp',m.render(C,rs))
        self.assertIn('udp dport { 12000 }',m.firewall(C,rs))
        self.assertIn('2222, 80, 443' if False else '80, 443, 2222',m.firewall(C,rs))
    def test_awg_public_443_and_userspace(self):
        i=inbound(); i['protocol']='amneziawg'; i['port']=51820
        i['streamSettings']={'externalProxy':[{'dest':C['panel'],'port':443,'forceTls':'same'}]}
        i['settings']={'server':{'kernelMode':False}}
        rs=m.routes([i],C)
        self.assertIn('192.0.2.1:443 udp',m.render(C,rs))
        self.assertIn('proxy_pass 127.0.0.1:51820',m.render(C,rs))
        self.assertIn('udp dport { 443 }',m.firewall(C,rs))
        i['settings']['server']['kernelMode']=True
        with self.assertRaisesRegex(ValueError,'kernel mode'):m.routes([i],C)

    def test_awg_hosts_from_actual_api_shape(self):
        i={'id':2,'enable':True,'protocol':'amneziawg','listen':'127.0.0.1','port':51820,'streamSettings':None,'settings':{'server':{'kernelMode':False}}}
        groups=[{'inboundIds':[2],'hosts':[C['panel']+':443'],'security':'same','isDisabled':False}]
        augmented=m.attach_awg_hosts([i],groups)
        self.assertIsNone(i['streamSettings'])
        rs=m.routes(augmented,C)
        self.assertEqual(rs[0]['public_port'],443)
        self.assertEqual(rs[0]['port'],51820)
        groups[0]['isDisabled']=True
        with self.assertRaisesRegex(ValueError,'External Proxy'):
            m.routes(m.attach_awg_hosts([i],groups),C)

    def test_null_stream_is_diagnostic_not_crash(self):
        i=inbound();i['streamSettings']=None
        with self.assertRaises(ValueError):m.routes([i],C)

    def test_unknown(self):
        with self.assertRaises(ValueError):m.routes([inbound('mkcp')],C)
    def test_domain(self):
        for v in ['a;bad.org','https://example.org','*.example.org','a.org\nfoo']:
            with self.assertRaises(ValueError):m.domain(v)
    def test_empty(self):
        self.assertEqual(m.routes([],C),[])
        self.assertNotIn('udp dport',m.firewall(C,[]))
    def test_apply_restores_on_validation_failure(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            conf=Path(d)/'nginx.conf';conf.write_text('previous')
            with patch.object(m,'NGINX',conf),patch.object(m,'run',side_effect=RuntimeError('invalid')):
                with self.assertRaises(RuntimeError):m.apply(C,[])
            self.assertEqual(conf.read_text(),'previous')
    def test_api_host_and_failure_do_not_apply(self):
        import tempfile, io
        with tempfile.TemporaryDirectory() as d:
            Path(d,'api-token').write_text('test-only-token')
            with patch.object(m,'CONF',Path(d)), patch.object(m,'BASE',Path(d)), patch.object(m,'apply') as apply:
                with patch.object(m.urllib.request,'urlopen',return_value=io.BytesIO(b'{"success":true,"obj":[]}')) as request:
                    m.sync(C)
                    self.assertEqual(request.call_args.args[0].get_header('Host'),C['panel'])
                    apply.assert_called_once_with(C,[])
                apply.reset_mock()
                with patch.object(m.urllib.request,'urlopen',side_effect=OSError('offline')):
                    with self.assertRaises(OSError):m.sync(C)
                apply.assert_not_called()
if __name__=='__main__':unittest.main()
