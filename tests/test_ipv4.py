import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_proxyctl import C, m


class IPv4PolicyTests(unittest.TestCase):
    def test_disabled_ipv6_has_no_http_tcp_or_awg_ipv6_listeners(self):
        c = dict(C, ipv6_disabled=True, public_ips=['192.0.2.1', '2001:db8::1'])
        routes = [{'id': 7, 'kind': 'udp', 'port': 51820, 'public_port': 24443}]
        for tls in (False, True):
            config = m.render(c, routes, tls=tls)
            self.assertNotIn('[::]', config)
            self.assertNotIn('2001:db8::1', config)
            self.assertIn('listen 80;', config)
        self.assertIn('listen 192.0.2.1:24443 udp', m.render(c, routes))

    def test_legacy_installations_keep_ipv6_until_explicitly_migrated(self):
        self.assertIn('listen [::]:443;', m.render(C, []))

    def test_policy_reapplies_to_every_interface_after_network_startup(self):
        with patch.object(m, 'write') as write, patch.object(m, 'unit') as unit, \
                patch.object(m, 'run') as run:
            m.configure_ipv4()
        self.assertIn('net.ipv6.conf.*.disable_ipv6 = 1', write.call_args.args[1])
        self.assertIn('net.ipv6.conf.default.disable_ipv6 = 1', write.call_args.args[1])
        service = unit.call_args.args[1]
        self.assertIn('After=network-online.target', service)
        self.assertIn('Before=nginx.service x-ui.service', service)
        self.assertIn(('systemctl', 'enable', 'proxy-stack-ipv4.service'),
                      [call.args for call in run.call_args_list])

    def preflight(self, addresses):
        args = SimpleNamespace(site='example.org', panel='lk.example.org', reality_name=[])

        def run(*command, **kwargs):
            if command[0] == '/usr/sbin/sshd':
                return SimpleNamespace(stdout='port 22\n', returncode=0)
            if command[0] == 'ip':
                return SimpleNamespace(stdout=json.dumps([{'addr_info': [
                    {'local': '8.8.8.8'}, {'local': '2001:4860:4860::8888'}]}]))
            return SimpleNamespace(stdout='', returncode=1)

        with patch.object(m.platform, 'freedesktop_os_release',
                          return_value={'ID': 'debian', 'VERSION_ID': '13'}), \
                patch.object(m.Path, 'exists', return_value=False), \
                patch.object(m.shutil, 'which', return_value=None), \
                patch.object(m, 'run', side_effect=run), \
                patch.object(m.socket, 'getaddrinfo', return_value=[
                    (None, None, None, None, (ip, 443)) for ip in addresses]), \
                patch.object(m.socket, 'socket') as sock:
            result = m.preflight(args)
        return result, sock

    def test_preflight_works_with_ipv6_unavailable_and_keeps_only_ipv4(self):
        (_, ips), sock = self.preflight(['8.8.8.8'])
        self.assertEqual(ips, ['8.8.8.8'])
        self.assertTrue(all(call.args[0] == m.socket.AF_INET for call in sock.call_args_list))

    def test_preflight_rejects_aaaa_before_disabling_ipv6(self):
        with self.assertRaisesRegex(ValueError, 'remove AAAA'):
            self.preflight(['8.8.8.8', '2001:4860:4860::8888'])


if __name__ == '__main__':
    unittest.main()
