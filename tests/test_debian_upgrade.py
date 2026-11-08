import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_proxyctl import m

spec = importlib.util.spec_from_file_location('debian_upgrade', Path(__file__).parents[1] / 'helpers/upgrade-debian.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class DebianUpgrade(unittest.TestCase):
    def setUp(self):
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for name, value in [('ROOT', self.temp / 'upgrade'), ('APT', self.temp / 'apt'),
                            ('OS_RELEASE', self.temp / 'os-release'), ('BOOT_ID', self.temp / 'boot-id'),
                            ('UNITS', self.temp / 'units')]:
            self.enterContext(patch.object(u, name, value))
        u.APT.mkdir()
        (u.APT / 'sources.list.d').mkdir()
        u.UNITS.mkdir()
        u.OS_RELEASE.write_text('ID=debian\nVERSION_ID="12"\n')
        u.BOOT_ID.write_text('old-boot')
        self.sources = u.APT / 'sources.list.d/debian.sources'
        self.sources.write_text('Types: deb\nURIs: https://deb.debian.org/debian\nSuites: bookworm bookworm-updates\nComponents: main non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: https://security.debian.org/debian-security\nSuites: bookworm-security\nComponents: main\n')

    def test_deb822_and_legacy_sources_allow_official_bookworm(self):
        (u.APT / 'sources.list').write_text('deb [arch=amd64] http://deb.debian.org/debian bookworm main\n')
        u.validate_sources()

    def test_third_party_mixed_and_backports_are_rejected_without_writes(self):
        for text in ('deb https://packages.example.org/debian bookworm main',
                     'deb https://deb.debian.org/debian bookworm-backports main',
                     'deb https://deb.debian.org/debian stable main',
                     'deb https://deb.debian.org/debian bullseye main'):
            with self.subTest(text=text):
                path = u.APT / 'sources.list'
                path.write_text(text)
                with self.assertRaises(ValueError):
                    u.validate_sources()
                self.assertEqual(path.read_text(), text)

    def test_suite_migration_preserves_signing_keys_and_comments(self):
        text = ('# bookworm repositories\nTypes: deb\nSuites: bookworm\n bookworm-updates bookworm-security\n'
                'Signed-By: /usr/share/keyrings/debian-archive-bookworm-stable.gpg\n')
        migrated = u.trixie_sources(text, deb822=True)
        self.assertIn('Suites: trixie\n trixie-updates trixie-security', migrated)
        self.assertIn('debian-archive-bookworm-stable.gpg', migrated)
        self.assertIn('# bookworm repositories', migrated)
        legacy = 'deb [signed-by=/keys/bookworm.gpg] https://deb.debian.org/debian bookworm main # bookworm\n'
        self.assertEqual(u.trixie_sources(legacy), legacy.replace(' bookworm main', ' trixie main'))

    def test_schedule_detaches_and_retains_installation_arguments(self):
        source = self.temp / 'source'
        source.mkdir()
        (source / 'proxyctl.py').write_text('# test')
        (source / 'dist').mkdir()
        options = {'site': 'example.org', 'panel': 'panel.example.org', 'email': '',
                   'reality_name': [], 'no_default_inbounds': False}
        with patch.object(u, 'command') as command:
            u.schedule(options, source)
        self.assertEqual(json.loads((u.ROOT / 'options.json').read_text()), options)
        self.assertFalse((u.ROOT / 'source/dist').exists())
        self.assertIn('start', command.call_args_list[-1].args)
        self.assertIn('--no-block', command.call_args_list[-1].args)
        resume_unit = (u.UNITS / 'proxy-stack-resume.service').read_text()
        self.assertIn('ConditionPathExists=', resume_unit)
        self.assertFalse((u.ROOT / 'ready').exists())

    def test_worker_stages_upgrade_before_reboot_and_installs_kernel(self):
        u.ROOT.mkdir()
        u.store(u.ROOT / 'state.json', {'stage': 'scheduled', 'boot_id': 'old-boot'})
        calls = []
        def command(*args, **kwargs):
            calls.append(args)
            if 'full-upgrade' in args and 'trixie' in self.sources.read_text():
                u.OS_RELEASE.write_text('ID=debian\nVERSION_ID="13"\n')
            return SimpleNamespace(stdout='')
        with patch.object(u, 'command', side_effect=command), patch.object(u.tarfile, 'open') as archive:
            archive.return_value.__enter__.return_value.add.side_effect = lambda *a, **k: (u.ROOT / 'system-backup.tar.gz').touch()
            u.worker()
        self.assertEqual(json.loads((u.ROOT / 'state.json').read_text())['stage'], 'awaiting-reboot')
        self.assertNotIn('bookworm', self.sources.read_text())
        self.assertIn('Signed-By:', self.sources.read_text())
        self.assertTrue(any('linux-image-' in ' '.join(c) for c in calls))
        self.assertEqual(calls[-1], ('systemctl', 'reboot', '--no-block'))
        self.assertTrue((u.ROOT / 'ready').exists())

    def test_failed_apt_never_reboots_or_marks_ready(self):
        u.ROOT.mkdir()
        u.store(u.ROOT / 'state.json', {'stage': 'scheduled', 'boot_id': 'old-boot'})
        def command(*args, **kwargs):
            if args[0] == 'apt-get':
                raise RuntimeError('APT failed')
            return SimpleNamespace(stdout='')
        with patch.object(u, 'command', side_effect=command) as run, patch.object(u.tarfile, 'open') as archive:
            archive.return_value.__enter__.return_value.add.side_effect = lambda *a, **k: (u.ROOT / 'system-backup.tar.gz').touch()
            with self.assertRaisesRegex(RuntimeError, 'APT failed'):
                u.worker()
        self.assertFalse(any('reboot' in c.args for c in run.call_args_list))
        self.assertFalse((u.ROOT / 'ready').exists())

    def test_resume_requires_new_boot_and_preserves_cli_options(self):
        u.ROOT.mkdir()
        u.store(u.ROOT / 'state.json', {'stage': 'awaiting-reboot', 'boot_id': 'old-boot'})
        u.store(u.ROOT / 'options.json', {'site': 'example.org', 'panel': 'panel.example.org',
                'email': 'admin@example.org', 'reality_name': ['xh.example.org'],
                'manual_inbounds': True, 'no_default_inbounds': True})
        with patch.object(u, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'Reboot'):
                u.resume()
            command.assert_not_called()
            u.BOOT_ID.write_text('new-boot')
            u.OS_RELEASE.write_text('ID=debian\nVERSION_ID="13"\n')
            (u.ROOT / 'ready').touch()
            u.resume()
        args = command.call_args_list[0].args
        for option in ('--site', '--panel', '--email', '--reality-name', '--manual-inbounds', '--no-default-inbounds'):
            self.assertIn(option, args)
        self.assertFalse((u.ROOT / 'ready').exists())
        self.assertEqual(json.loads((u.ROOT / 'state.json').read_text())['stage'], 'installed')

    def test_debian13_never_offers_or_schedules_upgrade(self):
        with patch.object(m.platform, 'freedesktop_os_release', return_value={'ID': 'debian', 'VERSION_ID': '13'}):
            self.assertTrue(m.ensure_debian13(argparse.Namespace(upgrade_debian=False)))

    def test_other_distributions_older_debian_and_downgrades_are_rejected(self):
        for system, version in [('ubuntu', '24.04'), ('debian', '11'), ('debian', '14')]:
            with patch.object(m.platform, 'freedesktop_os_release', return_value={'ID': system, 'VERSION_ID': version}):
                with self.assertRaisesRegex(ValueError, '12 → 13 only'):
                    m.ensure_debian13(argparse.Namespace(upgrade_debian=True))


if __name__ == '__main__':
    unittest.main()
