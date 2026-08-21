import ast
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def install_commands():
    commands = []
    for name in ('install-ports.py', 'create-iso.py'):
        tree = ast.parse((ROOT / 'build/tools' / name).read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == 'chroot' and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)):
                command = node.args[1].value
                if isinstance(command, str) and 'pkg ' in command and ' install ' in command:
                    commands.append((name, command))
    return commands


class SaslBatchInstallTests(unittest.TestCase):
    def fixture(self, root):
        template = os.environ.get('FREECORE_CYRUS_INSTALL_TEMPLATE')
        if not template:
            self.skipTest('set FREECORE_CYRUS_INSTALL_TEMPLATE to the reviewed ports pkg-install.in')
        script = Path(template).read_text()
        values = {'SASLDB_DIR': str(root / 'database'), 'SASLDB_NAME': 'sasldb2.db',
                  'CYRUS_USER': 'cyrus', 'CYRUS_GROUP': 'cyrus'}
        for key, value in values.items():
            script = script.replace('%%' + key + '%%', value)
        (root / 'database').mkdir()
        script_path = root / 'pkg-install'
        script_path.write_text(script)
        (root / 'sbin').mkdir()
        sentinel = root / 'account-command-called'
        for name in ('saslpasswd2', 'sasldblistusers2'):
            stub = root / 'sbin' / name
            stub.write_text('#!/bin/sh\ntouch ' + shlex.quote(str(sentinel)) + '\nexit 1\n')
            stub.chmod(0o755)
        pkg = root / 'pkg'
        pkg.write_text('#!/bin/sh\nexec /bin/sh ' + shlex.quote(str(script_path)) + ' fixture POST-INSTALL\n')
        pkg.chmod(0o755)
        env = {**os.environ, 'PATH': str(root) + ':/usr/bin:/bin', 'PKG_PREFIX': str(root),
               'CYRUS_USER': 'cyrus', 'CYRUS_GROUP': 'cyrus'}
        env.pop('BATCH', None)
        return env, sentinel, root / 'database/sasldb2.db'

    def test_actual_build_commands_skip_temporary_accounts_and_preserve_existing_database(self):
        commands = install_commands()
        self.assertEqual(len(commands), 3)
        for filename, command in commands:
            for existing in (False, True):
                with self.subTest(file=filename, command=command, existing=existing), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    env, sentinel, database = self.fixture(root)
                    original = b'opaque existing database fixture'
                    if existing:
                        database.write_bytes(original)
                    command = command.replace('${pkgs}', 'fixture').replace('${path}', 'fixture')
                    result = subprocess.run(['/bin/sh', '-c', command], env=env, capture_output=True)
                    self.assertEqual(result.returncode, 0)
                    self.assertFalse(sentinel.exists())
                    if existing:
                        self.assertEqual(database.read_bytes(), original)
                    else:
                        self.assertFalse(database.exists())

    def test_nonbatch_control_reaches_the_original_account_generator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env, sentinel, database = self.fixture(root)
            subprocess.run(['/bin/sh', str(root / 'pkg-install'), 'fixture', 'POST-INSTALL'],
                           env=env, capture_output=True, check=True)
            self.assertTrue(sentinel.exists())
            self.assertFalse(database.exists())


if __name__ == '__main__':
    unittest.main()
