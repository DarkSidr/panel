import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_proxyctl import m,C,inbound


def new(kind='xhttp',ident=4,backend=443):
    i=inbound(kind,p=backend)
    i.update(id=ident,listen='',remark='New connection',sniffing={},expiryTime=900,total=12345)
    i['streamSettings'].pop('externalProxy')
    i['settings']={'clients':[{'id':'preserved-uuid','email':'original','subId':'preserved-sub','totalGB':123,'flow':'xtls-rprx-vision'}]}
    return i


def pair(private=None):
    return private or 'new-private', 'derived-public'


class AutomaticSetup(unittest.TestCase):
    def test_x25519_output_current_and_legacy_formats(self):
        from types import SimpleNamespace
        for label in ('Password (PublicKey)','Password','PublicKey'):
            output=f"PrivateKey: {'a'*43}\n{label}: {'b'*43}\nHash32: ignored\n"
            with patch.object(m,'run',return_value=SimpleNamespace(stdout=output)):
                self.assertEqual(m.x25519_pair(),('a'*43,'b'*43))

    def test_new_xhttp_real_endpoint_without_changing_client_identity(self):
        i=new()
        raw=inbound('tcp',p=28211)
        raw['streamSettings'].update(security='reality',externalProxy=[{'dest':C['site'],'port':443,'forceTls':'same'}])
        original=copy.deepcopy(i)
        p=m.prepare_inbound(i,[raw,i],C,keypair=pair,is_free=lambda p:True)
        self.assertEqual(i,original)
        self.assertEqual(p['listen'],'127.0.0.1')
        self.assertEqual(p['port'],12000)
        s=p['streamSettings']
        self.assertEqual(s['security'],'reality')
        self.assertEqual(s['externalProxy'][0]['port'],8443)
        self.assertEqual(s['externalProxy'][0]['forceTls'],'same')
        self.assertTrue(s['sockopt']['acceptProxyProtocol'])
        self.assertEqual(s['realitySettings']['xver'],1)
        for key in ('id','email','subId','totalGB'):
            self.assertEqual(p['settings']['clients'][0][key],original['settings']['clients'][0][key])
        self.assertEqual(p['settings']['clients'][0]['flow'],'')
        self.assertEqual((p['total'],p['expiryTime']),(12345,900))

    def test_keys_and_short_ids_preserved(self):
        i=new('tcp',backend=12011)
        i['streamSettings']['realitySettings']={'privateKey':'original-private','shortIds':['abcdef12'],'settings':{'publicKey':'stale-public'}}
        p=m.prepare_inbound(i,[i],C,keypair=pair,is_free=lambda p:True)
        rs=p['streamSettings']['realitySettings']
        self.assertEqual(rs['privateKey'],'original-private')
        self.assertEqual(rs['shortIds'],['abcdef12'])
        self.assertEqual(rs['settings']['publicKey'],'derived-public')
        self.assertEqual(p['settings'],i['settings'])

    def test_ws_httpupgrade_and_tls_override(self):
        for kind in ('ws','httpupgrade','xhttp','grpc'):
            i=new(kind);i['remark']='Backup [TLS]'
            p=m.prepare_inbound(i,[i],C,keypair=pair,is_free=lambda p:True)
            self.assertEqual(p['streamSettings']['security'],'none')
            self.assertEqual(p['streamSettings']['externalProxy'][0]['forceTls'],'tls')
            self.assertEqual(p['streamSettings']['externalProxy'][0]['dest'],C['panel'])
            self.assertEqual(p['streamSettings']['sockopt']['trustedXForwardedFor'],['127.0.0.1/32'])
        for kind in ('ws','httpupgrade'):
            i=new(kind)
            self.assertEqual(m.prepare_inbound(i,[i],C,keypair=pair,is_free=lambda p:True)['streamSettings']['security'],'none')
        with self.assertRaises(ValueError):m.prepare_inbound(new('tcp'),[],C,security='tls')

    def test_extra_name_preferred_over_extra_port(self):
        c=copy.deepcopy(C);c['reality_names']=['xh.example.org']
        i=new()
        other=inbound('tcp',p=28211);other['streamSettings'].update(security='reality',externalProxy=[{'dest':C['site'],'port':443}])
        p=m.prepare_inbound(i,[other,i],c,keypair=pair,is_free=lambda p:True)
        self.assertEqual(p['streamSettings']['externalProxy'][0]['dest'],'xh.example.org')
        self.assertEqual(p['streamSettings']['externalProxy'][0]['port'],443)

    def test_owned_listener_does_not_change_public_port_on_explicit_reconfigure(self):
        c=copy.deepcopy(C);i=new(backend=12001)
        i['streamSettings'].update(security='reality',externalProxy=[{'dest':C['site'],'port':8443,'forceTls':'same'}])
        c['_published_routes']=[{'id':4,'sni':C['site'],'public_port':8443}]
        p=m.prepare_inbound(i,[i],c,keypair=pair,is_free=lambda n:False)
        self.assertEqual(p['streamSettings']['externalProxy'][0]['port'],8443)

    def test_seen_existing_and_manual_inbounds_are_not_rewritten(self):
        c=dict(C,auto_setup=True)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m.save(root/'auto-setup.json',{'seen':{'4':'existing'}})
            i=new();manual=new(ident=5);manual['remark']='Custom [MANUAL]'
            with patch.object(m,'BASE',root),patch.object(m,'configure_inbound') as configure:
                result=m.auto_configure(c,[i,manual])
            configure.assert_not_called()
            self.assertEqual(result,[i,manual])
            self.assertEqual(json.loads((root/'auto-setup.json').read_text())['seen']['5'],'manual')

    def test_new_inbound_processed_once_and_disabled_deferred(self):
        c=dict(C,auto_setup=True);i=new();disabled=new(ident=5);disabled['enable']=False
        with tempfile.TemporaryDirectory() as d,patch.object(m,'BASE',Path(d)),patch.object(m,'configure_inbound',return_value=i) as configure:
            m.auto_configure(c,[i,disabled]);m.auto_configure(c,[i,disabled])
            self.assertEqual(configure.call_count,1)

    def test_failure_is_not_marked_configured(self):
        c=dict(C,auto_setup=True)
        with tempfile.TemporaryDirectory() as d,patch.object(m,'BASE',Path(d)),patch.object(m,'configure_inbound',side_effect=ValueError('API failed')):
            with self.assertRaises(ValueError):m.auto_configure(c,[new()])
            self.assertFalse((Path(d)/'auto-setup.json').exists())

    def test_new_inbound_roundtrip_snapshot_and_second_poll(self):
        c=dict(C,auto_setup=True)
        existing=inbound('tcp',p=28211)
        existing['streamSettings'].update(security='reality',externalProxy=[{'dest':C['site'],'port':443,'forceTls':'same'}])
        database=[existing,new()]
        posts=[]
        def api(config,path,body=None):
            if path=='inbounds/list':return copy.deepcopy(database)
            if path=='inbounds/update/4':
                posts.append(copy.deepcopy(body))
                database[1]=copy.deepcopy(body)
                return body
            raise AssertionError('Unexpected API endpoint '+path)
        with tempfile.TemporaryDirectory() as d,patch.object(m,'BASE',Path(d)),patch.object(m,'panel_api',side_effect=api),patch.object(m,'x25519_pair',side_effect=pair),patch.object(m,'tcp_port_free',return_value=True):
            m.save(Path(d)/'auto-setup.json',{'seen':{'1':'existing'}})
            result=m.auto_configure(c,database)
            self.assertEqual(result[1]['streamSettings']['externalProxy'][0]['port'],8443)
            snapshots=list((Path(d)/'auto-backups').glob('*.json'))
            self.assertEqual(len(snapshots),1)
            self.assertEqual(snapshots[0].stat().st_mode & 0o777,0o600)
            saved=json.loads(snapshots[0].read_text())
            self.assertEqual(saved['settings']['clients'][0]['id'],'preserved-uuid')
            m.auto_configure(c,database)
            self.assertEqual(len(posts),1)
            self.assertEqual(database[1]['settings']['clients'][0]['totalGB'],123)

    def test_concurrent_edit_prevents_update(self):
        i=new();changed=copy.deepcopy(i);changed['remark']='Edited'
        with tempfile.TemporaryDirectory() as d,patch.object(m,'BASE',Path(d)),patch.object(m,'prepare_inbound',return_value=i),patch.object(m,'panel_api',return_value=[changed]) as api:
            with self.assertRaisesRegex(ValueError,'changed during setup'):m.configure_inbound(C,i,[i])
            self.assertEqual(api.call_count,1)
            self.assertFalse((Path(d)/'auto-backups').exists())

    def test_enabling_auto_setup_seeds_existing_ids(self):
        c=copy.deepcopy(C)
        with tempfile.TemporaryDirectory() as d,patch.object(m,'BASE',Path(d)),patch.object(m,'CONF',Path(d)),patch.object(m,'panel_api',return_value=[new()]) as api:
            m.set_auto_setup(c,True)
            self.assertTrue(c['auto_setup'])
            self.assertEqual(json.loads((Path(d)/'auto-setup.json').read_text())['seen'],{'4':'existing'})
            self.assertEqual(api.call_count,1)

    def test_allocated_local_and_public_ports_do_not_overlap(self):
        i=new();other=inbound('tcp',p=8443)
        other['streamSettings'].update(security='reality',externalProxy=[{'dest':C['site'],'port':443}])
        p=m.prepare_inbound(i,[other,i],C,keypair=pair,is_free=lambda p:True)
        self.assertEqual(p['streamSettings']['externalProxy'][0]['port'],8444)


if __name__=='__main__':unittest.main()
