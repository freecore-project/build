import ast
from contextlib import closing
import importlib.util
from pathlib import Path
import tempfile
import sqlite3
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('package_input', ROOT / 'build/lib/package_input.py')
INPUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUT)


def pkgdb(world, description='Source: https://codeberg.org/freecore/iocage.',
          relative='var/db/pkg/local.sqlite', origin='sysutils/iocage'):
    database = world / relative
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute('CREATE TABLE packages (origin TEXT, "desc" TEXT)')
        connection.execute('INSERT INTO packages VALUES (?, ?)', (origin, description))
    return database


class PackageInputTests(unittest.TestCase):
    def test_all_database_layouts_block_packaging_before_output_mutation(self):
        tree = ast.parse((ROOT / 'build/tools/build-packages.py').read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'build_packages')
        for prefix in ('usr/local/etc', 'etc/local', 'var/db/sasl2',
                       'conf/base/usr/local/etc', 'conf/base/etc/local', 'conf/base/var/db/sasl2'):
            for name in ('sasldb2', 'sasldb2.db', 'sasldb2-lock', 'sasldb2.db-lock'):
                with self.subTest(prefix=prefix, name=name), tempfile.TemporaryDirectory() as tmp:
                    world = Path(tmp) / 'world'
                    database = world / prefix / name
                    database.parent.mkdir(parents=True)
                    original = b'opaque fixture bytes\x00deleted record residue'
                    database.write_bytes(original)
                    shell = mock.Mock()
                    namespace = {'require_clean_package_input': INPUT.require_clean_package_input,
                                 'e': lambda value: str(world), 'sh': shell, 'info': mock.Mock()}
                    exec(compile(ast.Module(body=[function], type_ignores=[]), '<packaging>', 'exec'), namespace)
                    # The guard must inspect names only, even for a known path.
                    with mock.patch('builtins.open', side_effect=AssertionError('database opened')):
                        with self.assertRaisesRegex(ValueError, 'SASL database entry'):
                            namespace['build_packages']()
                    shell.assert_not_called()
                    self.assertEqual(database.read_bytes(), original)

    def test_empty_database_and_broken_database_symlink_still_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            world = Path(tmp)
            database = world / 'sasldb2.db'
            database.touch()
            with self.assertRaisesRegex(ValueError, 'sasldb2.db'):
                INPUT.require_clean_package_input(world)
            database.unlink()  # Synthetic fixture only, never a build database.
            database.symlink_to(world / 'missing-target')
            with self.assertRaisesRegex(ValueError, 'sasldb2.db'):
                INPUT.require_clean_package_input(world)
            self.assertTrue(database.is_symlink())

    def test_clean_world_passes_and_directory_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            world = root / 'world'
            world.mkdir()
            (world / 'sasldb2.md').write_text('documentation fixture')
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'sasldb2.db').touch()
            (world / 'linked-directory').symlink_to(outside, target_is_directory=True)
            pkgdb(world)
            INPUT.require_clean_package_input(world)

    def test_missing_or_symlink_world_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                INPUT.require_clean_package_input(root / 'missing')
            (root / 'linked-world').symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                INPUT.require_clean_package_input(root / 'linked-world')

    def test_stale_iocage_description_blocks_without_changing_database_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            world = Path(tmp)
            database = pkgdb(world, 'Source: https://old-build.example.invalid/project/iocage.')
            original = database.read_bytes()
            with self.assertRaisesRegex(ValueError, 'Rebuild cached iocage package metadata'):
                INPUT.require_clean_package_input(world)
            self.assertEqual(database.read_bytes(), original)
            self.assertEqual(sorted(path.name for path in database.parent.iterdir()), ['local.sqlite'])

    def test_public_iocage_description_passes_in_primary_and_template_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            world = Path(tmp)
            databases = [pkgdb(world), pkgdb(world, '(codeberg.org/freecore/iocage).',
                                            'conf/base/var/db/pkg/local.sqlite')]
            original = [database.read_bytes() for database in databases]
            INPUT.require_clean_package_input(world)
            self.assertEqual([database.read_bytes() for database in databases], original)

    def test_stale_template_metadata_blocks_even_with_clean_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            world = Path(tmp)
            pkgdb(world)
            database = pkgdb(world, 'old package metadata', 'conf/base/var/db/pkg/local.sqlite')
            original = database.read_bytes()
            with self.assertRaisesRegex(ValueError, 'conf/base/var/db/pkg/local.sqlite'):
                INPUT.require_clean_package_input(world)
            self.assertEqual(database.read_bytes(), original)

    def test_missing_iocage_wrong_schema_malformed_and_pending_journal_fail(self):
        for case in ('missing-database', 'missing-iocage', 'malformed', 'wrong-schema', 'pending-journal', 'lookalike-url'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                world = Path(tmp)
                if case == 'missing-iocage':
                    pkgdb(world, origin='sysutils/unrelated')
                elif case == 'malformed':
                    database = world / 'var/db/pkg/local.sqlite'
                    database.parent.mkdir(parents=True)
                    database.write_bytes(b'not a SQLite database')
                elif case == 'wrong-schema':
                    database = world / 'var/db/pkg/local.sqlite'
                    database.parent.mkdir(parents=True)
                    with closing(sqlite3.connect(database)) as connection, connection:
                        connection.execute('CREATE TABLE unrelated (value TEXT)')
                elif case == 'pending-journal':
                    database = pkgdb(world)
                    Path(str(database) + '-wal').touch()
                elif case == 'lookalike-url':
                    pkgdb(world, 'https://codeberg.org/freecore/iocage-unrelated')
                with self.assertRaisesRegex(ValueError, 'Rebuild cached iocage package metadata'):
                    INPUT.require_clean_package_input(world)


if __name__ == '__main__':
    unittest.main()
