import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'kernel_identity', ROOT / 'build/lib/kernel_identity.py'
)
KI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KI)

GIT = shutil.which('git')

BAKED_N73 = (
    '#define SCCSSTR "@(#)FreeBSD 15.1-RELEASE-p6 '
    'freecore/15.0-maintenance-n73-fa8a77475be9 FreeCORE.amd64"\n'
    '#define VERSTR "FreeBSD 15.1-RELEASE-p6 '
    'freecore/15.0-maintenance-n73-fa8a77475be9 FreeCORE.amd64\\n"\n'
)


def git(cwd, *args):
    subprocess.run(
        [GIT, '-c', 'user.name=FreeCORE Test', '-c', 'user.email=test@invalid', *args],
        cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def rev(cwd, *args):
    return subprocess.run(
        [GIT, *args], cwd=cwd, check=True, stdout=subprocess.PIPE, universal_newlines=True
    ).stdout.strip()


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def vers_c(self, text):
        path = self.root / 'vers.c'
        path.write_text(text)
        return str(path)

    def test_baked_matches_expected(self):
        stale, baked = KI.stale_kernel_obj(
            self.vers_c(BAKED_N73), 'freecore/15.0-maintenance-n73-fa8a77475be9')
        self.assertFalse(stale)
        self.assertIn('-n73-fa8a77475be9', baked)

    def test_baked_differs_from_expected(self):
        stale, baked = KI.stale_kernel_obj(
            self.vers_c(BAKED_N73), 'freecore/15.0-maintenance-n75-f51d144a6266')
        self.assertTrue(stale)
        self.assertEqual(
            baked,
            'FreeBSD 15.1-RELEASE-p6 freecore/15.0-maintenance-n73-fa8a77475be9 FreeCORE.amd64')

    def test_missing_vers_c_is_not_stale(self):
        self.assertEqual(
            KI.stale_kernel_obj(str(self.root / 'vers.c'), 'x-n1-0123456789ab'),
            (False, None))

    def test_unknown_expected_is_not_stale(self):
        self.assertEqual(KI.stale_kernel_obj(self.vers_c(BAKED_N73), None), (False, None))

    def test_dirty_and_branch_are_part_of_the_token(self):
        dirty = BAKED_N73.replace('fa8a77475be9 ', 'fa8a77475be9-dirty ')
        self.assertFalse(KI.ident_matches(dirty, 'freecore/15.0-maintenance-n73-fa8a77475be9'))
        self.assertTrue(KI.ident_matches(dirty, 'freecore/15.0-maintenance-n73-fa8a77475be9-dirty'))
        # Detached build of the same commit: newvers.sh drops the branch.
        self.assertFalse(KI.ident_matches(BAKED_N73, 'n73-fa8a77475be9'))

    def test_metadata_form_matches(self):
        text = 'FreeBSD 15.2-STABLE #0 freecore/15.2-stable-n5-0123456789ab: Sat Nov  1'
        self.assertTrue(KI.ident_matches(text, 'freecore/15.2-stable-n5-0123456789ab'))

    def test_kernel_bytes_match(self):
        blob = (b'\x7fELF\x00junk\x00@(#)FreeBSD 15.1-RELEASE-p6 '
                b'freecore/15.0-maintenance-n75-f51d144a6266 FreeCORE.amd64\x00'
                b'FreeBSD 15.1-RELEASE-p6 freecore/15.0-maintenance-n75-f51d144a6266 '
                b'FreeCORE.amd64\n\x00')
        text = blob.decode('latin-1')
        self.assertTrue(KI.ident_matches(text, 'freecore/15.0-maintenance-n75-f51d144a6266'))
        self.assertEqual(
            KI.baked_version(text),
            'FreeBSD 15.1-RELEASE-p6 freecore/15.0-maintenance-n75-f51d144a6266 FreeCORE.amd64')


@unittest.skipUnless(GIT, 'git not available')
class ExpectedIdentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.os_root = Path(self.tmp.name) / 'os'
        (self.os_root / 'sys' / 'conf').mkdir(parents=True)
        git(self.os_root, 'init', '-q', '-b', 'freecore/15.0-maintenance')
        for n in range(3):
            (self.os_root / 'sys' / 'conf' / 'f').write_text(str(n))
            git(self.os_root, 'add', '-A')
            git(self.os_root, 'commit', '-q', '-m', str(n))
        self.hash12 = rev(self.os_root, 'rev-parse', '--short=12', 'HEAD')

    def tearDown(self):
        self.tmp.cleanup()

    def test_branch_count_hash(self):
        self.assertEqual(
            KI.expected_ident(str(self.os_root), git=GIT),
            'freecore/15.0-maintenance-n3-' + self.hash12)

    def test_detached_head_drops_branch(self):
        git(self.os_root, 'checkout', '-q', '--detach', 'HEAD~1')
        hash12 = rev(self.os_root, 'rev-parse', '--short=12', 'HEAD')
        self.assertEqual(KI.expected_ident(str(self.os_root), git=GIT), 'n2-' + hash12)

    def test_dirty_tree(self):
        (self.os_root / 'sys' / 'conf' / 'f').write_text('changed')
        self.assertEqual(
            KI.expected_ident(str(self.os_root), git=GIT),
            'freecore/15.0-maintenance-n3-' + self.hash12 + '-dirty')

    def test_userland_move_makes_obj_stale(self):
        vers_c = Path(self.tmp.name) / 'vers.c'
        vers_c.write_text(
            '#define VERSTR "FreeBSD 15.1-RELEASE-p6 {0} FreeCORE.amd64\\n"\n'.format(
                KI.expected_ident(str(self.os_root), git=GIT)))
        self.assertFalse(KI.stale_kernel_obj(str(vers_c), KI.expected_ident(str(self.os_root), git=GIT))[0])
        (self.os_root / 'lib').mkdir()
        (self.os_root / 'lib' / 'libarchive.c').write_text('x')
        git(self.os_root, 'add', '-A')
        git(self.os_root, 'commit', '-q', '-m', 'userland')
        self.assertTrue(KI.stale_kernel_obj(str(vers_c), KI.expected_ident(str(self.os_root), git=GIT))[0])

    def test_not_a_checkout(self):
        plain = Path(self.tmp.name) / 'plain'
        plain.mkdir()
        # findvcs walks up; only assert when no ancestor carries .git.
        if KI.findvcs(str(plain), '.git') is None:
            self.assertIsNone(KI.expected_ident(str(plain), git=GIT))

    def test_no_git_binary(self):
        self.assertIsNone(KI.find_git(dirs=(os.path.join(self.tmp.name, 'nobin'),)))


if __name__ == '__main__':
    unittest.main()
