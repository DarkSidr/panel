import io
import unittest
from unittest.mock import patch

from test_proxyctl import C, m


def html_response(body=b'<!doctype html><html><body>Ready</body></html>'):
    response = io.BytesIO(body)
    response.status = 200
    return response


class HealthCheckTests(unittest.TestCase):
    def setUp(self):
        self.run = self.enterContext(patch.object(m, 'run'))
        self.api = self.enterContext(patch.object(m, 'panel_api',
                                                return_value={'xray': {'state': 'running'}}))
        self.request = self.enterContext(patch.object(m.urllib.request, 'urlopen',
                                                    side_effect=lambda *a, **k: html_response()))
        self.output = self.enterContext(patch('builtins.print'))
        self.connection = self.enterContext(patch.object(m.http.client, 'HTTPSConnection'))
        self.connection.return_value.getresponse.return_value.status = 421

    def test_healthy_server_checks_both_https_hosts(self):
        m.healthcheck(C)
        self.assertEqual([call.args[0] for call in self.request.call_args_list],
                         ['https://' + C['site'] + '/', 'https://' + C['panel'] + '/',
                          'https://' + C['panel'] + C['panel_path']])
        self.output.assert_called_once()

    def test_running_panel_with_stopped_xray_is_not_healthy(self):
        self.api.return_value = {'xray': {'state': 'error', 'errorMsg': 'internal details'}}
        with self.assertRaisesRegex(ValueError, 'Xray is not running'):
            m.healthcheck(C)
        self.request.assert_not_called()
        self.output.assert_not_called()

    def test_configured_but_stopped_awg_is_not_healthy(self):
        self.api.return_value = {'xray': {'state': 'running'},
                                 'amneziawg': {'configured': True, 'running': False}}
        with self.assertRaisesRegex(ValueError, 'AmneziaWG is configured but not running'):
            m.healthcheck(C)
        self.request.assert_not_called()
        self.output.assert_not_called()

    def test_inactive_service_fails_readiness(self):
        self.run.side_effect = RuntimeError('inactive service')
        with self.assertRaisesRegex(RuntimeError, 'inactive service'):
            m.healthcheck(C)
        self.output.assert_not_called()

    def test_invalid_xray_config_fails_readiness(self):
        def command(*args, **kwargs):
            if '-test' in args:
                raise RuntimeError('invalid Xray configuration')
        self.run.side_effect = command
        with self.assertRaisesRegex(RuntimeError, 'invalid Xray configuration'):
            m.healthcheck(C)
        self.request.assert_not_called()
        self.output.assert_not_called()

    def test_html_is_required_instead_of_a_successful_empty_response(self):
        self.request.side_effect = lambda *a, **k: html_response(b'')
        with self.assertRaisesRegex(ValueError, 'HTTPS health check failed for site'):
            m.healthcheck(C)
        self.output.assert_not_called()

    def test_certificate_or_http_failure_does_not_expose_panel_path(self):
        self.request.side_effect = [html_response(), html_response(),
                                    OSError('failed URL ' + C['panel_path'])]
        with self.assertRaisesRegex(ValueError, 'HTTPS health check failed for panel') as error:
            m.healthcheck(C)
        self.assertNotIn(C['panel_path'], str(error.exception))
        self.output.assert_not_called()

    def test_panel_root_must_serve_the_same_cover_site(self):
        self.request.side_effect = [html_response(), html_response(b'<html>Wrong page</html>')]
        with self.assertRaisesRegex(ValueError, 'HTTPS health check failed for panel cover'):
            m.healthcheck(C)
        self.output.assert_not_called()

    def test_reused_connection_must_be_rejected_to_avoid_cross_domain_404(self):
        self.connection.return_value.getresponse.return_value.status = 404
        with self.assertRaisesRegex(ValueError, 'HTTPS routing check failed') as error:
            m.healthcheck(C)
        self.assertNotIn(C['panel_path'], str(error.exception))
        self.output.assert_not_called()


if __name__ == '__main__':
    unittest.main()
