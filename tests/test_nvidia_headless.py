import ast
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
PROFILE = ROOT / 'build/profiles/freenas'
CUSTOMIZER = ROOT / 'build/customize/nvidia-headless.py'
spec = importlib.util.spec_from_file_location('nvidia_headless', CUSTOMIZER)
nvidia = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nvidia)


class SelectionTests(unittest.TestCase):
    def test_selects_headless_only_and_retains_existing_drm(self):
        ports = []
        for node in ast.walk(ast.parse((PROFILE / 'ports-system.pyd').read_text())):
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                if node.target.id == 'ports' and isinstance(node.value, ast.Constant):
                    ports.append(node.value.value)
        self.assertEqual(ports.count('x11/nvidia-driver-headless'), 1)
        self.assertEqual(ports.count('graphics/drm-66-kmod'), 1)
        self.assertEqual([p for p in ports if 'nvidia' in p], ['x11/nvidia-driver-headless'])

    def test_both_image_variants_verify_before_conf_base(self):
        lists = []
        for node in ast.walk(ast.parse((PROFILE / 'config.pyd').read_text())):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == 'customize_tasks' for t in node.targets
            ):
                lists.append(ast.literal_eval(node.value))
        self.assertEqual(len(lists), 2)
        for tasks in lists:
            self.assertEqual(tasks.count('nvidia-headless'), 1)
            self.assertLess(tasks.index('nvidia-headless'), tasks.index('conf-base'))
            if 'remove-bits' in tasks:
                self.assertLess(tasks.index('remove-bits'), tasks.index('nvidia-headless'))
        self.assertTrue(CUSTOMIZER.stat().st_mode & 0o111)

    def test_kernel_source_mount_is_read_only_and_image_owned(self):
        mounts = []
        for node in ast.walk(ast.parse((PROFILE / 'jail.pyd').read_text())):
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                if node.target.id == 'link':
                    mounts.append(node.value)
        self.assertEqual(len(mounts), 1)
        fields = dict(zip((k.value for k in mounts[0].keys), mounts[0].values))
        self.assertEqual(fields['source'].id, 'OS_ROOT')
        self.assertEqual(fields['dest'].value, '/usr/src')
        self.assertEqual(fields['flags'].value, 'ro')


class ImageGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.hashes = {}
        for relative in nvidia.BINARY_HASHES:
            content = b'\x7fELF fixture ' + relative.encode()
            self.write(relative, content)
            self.hashes[relative] = hashlib.sha256(content).hexdigest()
        self.patch = patch.object(nvidia, 'BINARY_HASHES', self.hashes)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        for module in nvidia.MODULES:
            self.write(f'boot/modules/{module}.ko', b'\x7fELF module fixture')
        for relative in nvidia.BASE_LIBRARIES:
            self.write(relative, b'\x7fELF base library fixture')
        (self.root / 'usr/local/lib/libnvidia-ml.so').symlink_to('libnvidia-ml.so.1')
        self.write('usr/local/share/nvidia-headless/license.txt', b'license fixture')

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_complete_fixture_installs_only_idempotent_policy(self):
        before = {p.relative_to(self.root) for p in self.root.rglob('*') if p.is_file()}
        nvidia.prepare_image(self.root)
        nvidia.prepare_image(self.root)
        policy = self.root / nvidia.POLICY_PATH
        self.assertEqual(policy.read_text(), nvidia.POLICY)
        self.assertEqual(policy.stat().st_mode & 0o777, 0o644)
        after = {p.relative_to(self.root) for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(after - before, {Path(nvidia.POLICY_PATH)})

    def test_binary_version_mismatch_fails_before_policy_write(self):
        self.write('usr/local/bin/nvidia-smi', b'wrong version')
        with self.assertRaisesRegex(RuntimeError, 'version/content mismatch'):
            nvidia.prepare_image(self.root)
        self.assertFalse((self.root / nvidia.POLICY_PATH).exists())

    def test_every_kernel_and_base_dependency_is_required(self):
        relatives = [*(f'boot/modules/{m}.ko' for m in nvidia.MODULES), *nvidia.BASE_LIBRARIES]
        for relative in relatives:
            with self.subTest(relative=relative):
                path = self.root / relative
                content = path.read_bytes()
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    nvidia.prepare_image(self.root)
                self.assertFalse((self.root / nvidia.POLICY_PATH).exists())
                path.write_bytes(content)

    def test_non_elf_dependency_is_rejected(self):
        self.write('boot/modules/nvidia.ko', b'not a module')
        with self.assertRaisesRegex(RuntimeError, 'invalid NVIDIA dependency'):
            nvidia.prepare_image(self.root)

    def test_missing_license_is_rejected(self):
        (self.root / 'usr/local/share/nvidia-headless/license.txt').unlink()
        with self.assertRaisesRegex(RuntimeError, 'license is missing'):
            nvidia.prepare_image(self.root)

    def test_missing_nvml_dlopen_link_is_rejected(self):
        (self.root / 'usr/local/lib/libnvidia-ml.so').unlink()
        with self.assertRaisesRegex(RuntimeError, 'NVML dlopen symlink'):
            nvidia.prepare_image(self.root)

    def test_desktop_libmap_override_is_rejected(self):
        self.write('usr/local/etc/libmap.d/nvidia.conf', b'desktop override')
        with self.assertRaisesRegex(RuntimeError, 'Desktop NVIDIA libmap'):
            nvidia.prepare_image(self.root)

    def test_unexpected_policy_is_not_overwritten(self):
        self.write(nvidia.POLICY_PATH, b'operator-owned contents')
        with self.assertRaisesRegex(RuntimeError, 'unexpected NVIDIA loading policy'):
            nvidia.prepare_image(self.root)
        self.assertEqual((self.root / nvidia.POLICY_PATH).read_bytes(), b'operator-owned contents')

    def test_policy_symlink_is_not_followed(self):
        target = self.root / 'untouched'
        target.write_text('operator-owned')
        policy = self.root / nvidia.POLICY_PATH
        policy.parent.mkdir(parents=True)
        policy.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'symlinked NVIDIA loading policy'):
            nvidia.prepare_image(self.root)
        self.assertEqual(target.read_text(), 'operator-owned')

    def test_policy_preserves_existing_blocklist_and_opt_in_controls(self):
        nvidia.prepare_image(self.root)
        for current, legacy, prefix in [('', '', ''), ('if_foo', '', 'if_foo'),
                                        ('', 'if_old', 'if_old'), ('if_new', 'if_old', 'if_new')]:
            with self.subTest(current=current, legacy=legacy):
                shell = '''
devmatch_blocklist=$2
devmatch_blacklist=$3
kld_list="hwpmc t4_tom nvidia"
devmatch_enable=YES
. "$1"
printf '%s\n' "$devmatch_blocklist" "$kld_list" "$devmatch_enable"
'''
                result = subprocess.run(
                    ['/bin/sh', '-c', shell, 'policy-test', str(self.root / nvidia.POLICY_PATH), current, legacy],
                    check=True, capture_output=True, text=True,
                )
                self.assertEqual(result.stdout.splitlines(), [
                    f'{prefix} nvidia nvidia-modeset nvidia-drm', 'hwpmc t4_tom nvidia', 'YES',
                ])


if __name__ == '__main__':
    unittest.main()
