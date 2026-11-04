import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / 'install.sh'
GITHUB_URL = 'https://github.com/DarkSidr/panel/archive/refs/heads/main.tar.gz'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.work = self.root / 'work'
        self.work.mkdir()
        self.bundle = self.root / 'bundle.tar.gz'
        self.log = self.root / 'download.json'
        self.env = dict(os.environ, PATH=str(self.bin), TMPDIR=str(self.work),
                        TEST_BUNDLE=str(self.bundle), TEST_DOWNLOAD_LOG=str(self.log))
        self.env.pop('PROXY_BUNDLE_URL', None)
        self.env.pop('PROXY_BUNDLE_SHA256', None)
        for name in ('mktemp', 'mkdir', 'rm', 'tar', 'gzip', 'sha256sum'):
            (self.bin / name).symlink_to(shutil.which(name))
        (self.bin / 'python3').symlink_to(sys.executable)

    def downloader(self, name):
        script = self.bin / name
        script.write_text(f'#!{sys.executable}\n' + '''
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
flag = '-o' if pathlib.Path(sys.argv[0]).name == 'curl' else '-O'
shutil.copyfile(os.environ['TEST_BUNDLE'], args[args.index(flag) + 1])
pathlib.Path(os.environ['TEST_DOWNLOAD_LOG']).write_text(json.dumps(args))
''')
        script.chmod(0o755)

    def archive(self, prefix, valid=True):
        payload = (b'import json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(7)\n'
                   if valid else b'not a source archive\n')
        with tarfile.open(self.bundle, 'w:gz') as archive:
            entry = tarfile.TarInfo(prefix + ('/proxyctl.py' if valid else '/README.md'))
            entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload))

    def run_installer(self, *args):
        result = subprocess.run(['/bin/sh', str(INSTALLER), *args], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(list(self.work.iterdir()), [], 'temporary files were not removed')
        return result

    def test_github_archive_with_curl_forwards_arguments_and_exit_code(self):
        self.downloader('curl')
        self.archive('panel-main')
        args = ['install', '--site', 'example.org', '--panel', 'lk.example.org']
        result = self.run_installer(*args)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(json.loads(result.stdout), args)
        self.assertIn(GITHUB_URL, json.loads(self.log.read_text()))

    def test_wget_fallback(self):
        self.downloader('wget')
        self.archive('panel-main')
        result = self.run_installer('--help')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(json.loads(result.stdout), ['--help'])
        self.assertIn(GITHUB_URL, json.loads(self.log.read_text()))

    def test_custom_bundle_and_checksum_keep_legacy_layout_working(self):
        self.downloader('curl')
        self.archive('proxy-stack')
        self.env['PROXY_BUNDLE_URL'] = 'https://example.org/custom.tar.gz'
        self.env['PROXY_BUNDLE_SHA256'] = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        result = self.run_installer('--help')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[-1]), ['--help'])
        self.assertIn(self.env['PROXY_BUNDLE_URL'], json.loads(self.log.read_text()))

    def test_bad_checksum_stops_before_execution(self):
        self.downloader('curl')
        self.archive('panel-main')
        self.env['PROXY_BUNDLE_SHA256'] = '0' * 64
        result = self.run_installer('--help')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('["--help"]', result.stdout)
        self.assertIn('FAILED', result.stdout)

    def test_archive_without_entrypoint_fails(self):
        self.downloader('curl')
        self.archive('panel-main', valid=False)
        result = self.run_installer('--help')
        self.assertEqual(result.returncode, 1)
        self.assertIn('proxyctl.py is missing', result.stderr)


if __name__ == '__main__':
    unittest.main()
