import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_proxyctl import C, m


class DefaultConnections(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(m, 'BASE', self.root / 'state'))
        self.enterContext(patch.object(m, 'CONF', self.root / 'conf'))
        self.enterContext(patch.object(m, 'tcp_port_free', return_value=True))
        self.enterContext(patch.object(m, 'udp_port_free', return_value=True))
        self.enterContext(patch.object(m, 'x25519_pair', return_value=('a' * 43, 'b' * 43)))
        self.enterContext(patch.object(m, 'run', return_value=type('Result', (), {'stdout': 'apiToken: test-admin\n'})()))
        self.database, self.hosts, self.posts = [], [], []
        self.fail_after_commit = False
        self.enterContext(patch.object(m, 'panel_api', side_effect=self.api))

    def api(self, config, path, body=None, **kwargs):
        if path == 'inbounds/list':
            return copy.deepcopy(self.database)
        if path == 'hosts/list':
            return copy.deepcopy(self.hosts)
        if path == 'setting/apiTokens':
            self.assertEqual(kwargs['token'], 'test-admin')
            return [{'id': 99, 'name': 'proxy-stack-provision', 'scope': 'admin'}]
        if path == 'setting/apiTokens/delete/99':
            self.assertEqual(kwargs['token'], 'test-admin')
            return None
        self.posts.append((path, copy.deepcopy(body)))
        if path == 'inbounds/add':
            created = copy.deepcopy(body)
            created['id'] = len(self.database) + 1
            if created['protocol'] == 'amneziawg':
                created['settings']['server'].update(privateKey='generated-private', publicKey='generated-public')
                created['streamSettings'] = None
            self.database.append(created)
            if self.fail_after_commit:
                self.fail_after_commit = False
                raise TimeoutError('Response lost after commit')
            return copy.deepcopy(created)
        if path == 'hosts/bulk/add':
            self.hosts.append(copy.deepcopy(body))
            return body
        raise AssertionError('Unexpected API operation: ' + path)

    def test_seven_profiles_public_endpoints_and_clients(self):
        m.seed_default_inbounds(C)
        compiled = m.routes(m.attach_awg_hosts(self.database, self.hosts), C)
        self.assertEqual(len(compiled), 7)
        self.assertEqual([r['public_port'] for r in compiled if r['kind'] == 'reality'], [443, 8443, 8444])
        self.assertEqual(compiled[-1]['public_port'], 443)
        self.assertEqual(compiled[-1]['kind'], 'udp')
        self.assertEqual(len({i['port'] for i in self.database}), 7)
        clients = [i['settings']['clients'][0] for i in self.database]
        self.assertEqual(len({c['email'] for c in clients}), 7)
        self.assertEqual(len({c['subId'] for c in clients}), 7)
        self.assertTrue(all(c['enable'] and c['subId'] for c in clients))
        self.assertEqual([c.get('flow', '') for c in clients], ['', 'xtls-rprx-vision', '', '', '', '', ''])
        server = self.database[-1]['settings']['server']
        self.assertEqual(server['mtu'], 1380)
        self.assertFalse(server['kernelMode'])
        self.assertEqual([server[f'h{i}'] for i in range(1, 5)], ['1', '2', '3', '4'])
        self.assertTrue(all(server[f's{i}'] >= 12 for i in range(1, 5)))
        self.assertEqual(len(base64.b64decode(server['headerProtectionKey'])), 32)
        self.assertEqual(len(base64.b64decode(clients[-1]['privateKey'])), 32)
        self.assertIn('udp dport { 443 }', m.firewall(C, compiled))
        for path in (m.CONF / 'default-subscriptions', m.BASE / 'default-inbounds.json'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((m.CONF / 'default-subscriptions').read_text().count('https://'), 7)

    def test_retry_after_committed_timeout_has_no_duplicates_or_key_rotation(self):
        self.fail_after_commit = True
        with self.assertRaises(TimeoutError):
            m.seed_default_inbounds(C)
        first = copy.deepcopy(self.database[0])
        m.seed_default_inbounds(C)
        original = copy.deepcopy(self.database)
        m.seed_default_inbounds(C)
        self.assertEqual(len(self.database), 7)
        self.assertEqual(self.database[0], first)
        self.assertEqual(self.database, original)
        self.assertEqual(len(self.posts), 8)  # Seven creates and one AWG Host.

    def test_saved_defaults_are_not_reconfigured_by_automatic_setup(self):
        m.seed_default_inbounds(C)
        with patch.object(m, 'configure_inbound') as configure:
            m.auto_configure(dict(C, auto_setup=True), self.database)
        configure.assert_not_called()

    def test_deleted_default_is_not_silently_recreated(self):
        m.seed_default_inbounds(C)
        self.database.pop(0)
        with self.assertRaisesRegex(ValueError, 'refusing to recreate'):
            m.seed_default_inbounds(C)
        self.assertEqual(len(self.database), 6)

    def test_incomplete_awg_response_prevents_success(self):
        original = self.api
        def api(c, path, body=None, **kwargs):
            result = original(c, path, body, **kwargs)
            if path == 'inbounds/add' and body['protocol'] == 'amneziawg':
                self.database[-1]['settings']['server'].pop('headerProtectionKey')
            return result
        with patch.object(m, 'panel_api', side_effect=api):
            with self.assertRaisesRegex(ValueError, 'AWG 3.1'):
                m.seed_default_inbounds(C)
        self.assertFalse(json.loads((m.BASE / 'default-inbounds.json').read_text())['complete'])

    def test_awg_occupied_udp443_fails_before_any_writes(self):
        with patch.object(m, 'udp_port_free', side_effect=lambda p: p != 443):
            with self.assertRaisesRegex(ValueError, 'public UDP 443'):
                m.seed_default_inbounds(C)
        self.assertEqual(self.posts, [])
        self.assertFalse((m.BASE / 'default-inbounds.json').exists())

    def test_existing_custom_inbound_is_preserved(self):
        from test_proxyctl import inbound
        custom = inbound(p=12101)
        custom.update(tag='custom-user-inbound', settings={'clients': [{'enable': True, 'id': 'existing-identity'}]})
        self.database.append(copy.deepcopy(custom))
        m.seed_default_inbounds(C)
        self.assertEqual(self.database[0], custom)
        self.assertEqual(len(self.database), 8)

    def test_admin_token_cleanup_is_attempted_if_host_creation_fails(self):
        original = self.api
        calls = []
        def api(c, path, body=None, **kwargs):
            calls.append(path)
            if path == 'hosts/bulk/add':
                raise ValueError('Host write failed')
            return original(c, path, body, **kwargs)
        with patch.object(m, 'panel_api', side_effect=api):
            with self.assertRaisesRegex(ValueError, 'Host write failed'):
                m.seed_default_inbounds(C)
        self.assertIn('setting/apiTokens/delete/99', calls)
        self.assertFalse(json.loads((m.BASE / 'default-inbounds.json').read_text())['complete'])


if __name__ == '__main__':
    unittest.main()
