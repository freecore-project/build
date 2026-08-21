import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'repo_manifest', ROOT / 'build/lib/repo_manifest.py'
)
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)
NAMES = (
    'build', 'freebsd-src', 'middleware', 'webui', 'ports', 'py-bsd',
    'py-cam', 'py-netif', 'py-libzfs', 'samba', 'py-licenselib',
    'freenas-pkgtools', 'iocage',
)
PINS = [format(index + 1, 'x') * (7 + index) for index in range(len(NAMES))]


def source_manifest():
    return ''.join('https://source.example.invalid/project/{}.git {}\n'.format(name, pin)
                   for name, pin in zip(NAMES, PINS))


class RepoManifestTests(unittest.TestCase):
    def test_render_preserves_exact_pins_and_removes_clone_locations(self):
        text, versions = MANIFEST.render_shipped_manifest(source_manifest())
        expected = '# FreeCORE source provenance v1\n' + ''.join(
            '{} {}\n'.format(name, pin) for name, pin in zip(NAMES, PINS))
        self.assertEqual(text, expected)
        self.assertEqual(versions, PINS)
        self.assertNotIn('example.invalid', text)

    def test_unknown_duplicate_missing_malformed_and_reordered_sources_fail(self):
        rows = source_manifest().splitlines(keepends=True)
        cases = [
            ''.join(rows).replace('/build.git', '/unknown.git'),
            ''.join(rows).replace('/webui.git', '/middleware.git'),
            ''.join(rows[:-1]),
            ''.join(rows[1:] + rows[:1]),
            ''.join(rows).replace('/build.git', '/%62uild.git'),
            ''.join(rows).replace('/build.git', '/build'),
            ''.join(rows).replace(PINS[0], '123xyz!', 1),
            ''.join(rows).replace(PINS[0], '123456', 1),
            ''.join(rows).replace(PINS[0], 'a' * 41, 1),
        ]
        for source in cases:
            with self.subTest(source=source.splitlines()[0]), self.assertRaises(ValueError):
                MANIFEST.render_shipped_manifest(source)

    def test_public_dependency_name_and_ssh_remotes_are_supported(self):
        source = source_manifest().replace('/py-licenselib.git', '/licenselib.git')
        source = source.replace('https://source.example.invalid/', 'git@source.example.invalid:')
        self.assertEqual(MANIFEST.render_shipped_manifest(source)[1], PINS)

    def test_packaging_keeps_private_evidence_and_existing_hash_inputs(self):
        # Execute the real packaging function without importing build DSL
        # setup or running any build command.
        tree = ast.parse((ROOT / 'build/tools/build-packages.py').read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'read_repo_manifest')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            world = root / 'world'
            (world / 'etc').mkdir(parents=True)
            private = root / 'repo-manifest'
            private.write_text(source_manifest(), encoding='utf-8')
            values = {'${BE_ROOT}': str(root), '${WORLD_DESTDIR}': str(world),
                      '${TRAIN}': 'FreeCORE-15.1-STABLE', '${VERSION}': '15.1-RC1'}

            def expand(value):
                for token, replacement in values.items():
                    value = value.replace(token, replacement)
                return value

            namespace = {'hashlib': hashlib, 'os': os, 'e': expand,
                         'render_shipped_manifest': MANIFEST.render_shipped_manifest}
            exec(compile(ast.Module(body=[function], type_ignores=[]), '<packaging>', 'exec'), namespace)
            namespace['read_repo_manifest']()
            self.assertEqual(private.read_text(), source_manifest())
            shipped = MANIFEST.render_shipped_manifest(source_manifest())[0]
            self.assertEqual((world / 'etc/repo-manifest').read_text(), shipped)
            # the boot seed: /etc is a tmpfs seeded from /conf/base/etc, and
            # conf-base has already copied etc when packaging runs
            self.assertEqual((world / 'conf/base/etc/repo-manifest').read_text(), shipped)
            self.assertEqual(namespace['pkgversion'],
                             hashlib.md5('-'.join(PINS).encode('ascii')).hexdigest())
            self.assertEqual(namespace['sequence'], hashlib.md5(
                '-'.join(PINS + ['FreeCORE-15.1-STABLE', '15.1-RC1']).encode('ascii')).hexdigest())


if __name__ == '__main__':
    unittest.main()
