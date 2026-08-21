import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOL = Path(__file__).parents[1] / "build" / "tools" / "freecore-build-slot.py"


def git(cwd, *args):
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=FreeCORE Test",
            "-c",
            "user.email=test@invalid",
            *args,
        ],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


class BuildSlotTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.build = self.root / "build-15.0"
        self.build.mkdir()
        git(self.build, "init", "-q")
        git(self.build, "checkout", "-q", "-b", "freecore/15.0-maintenance")

        common = self.build / "build" / "config" / "env.pyd"
        profile = self.build / "build" / "profiles" / "freenas"
        common.parent.mkdir(parents=True)
        profile.mkdir(parents=True)
        common.write_text('PRODUCT = PRODUCT or "FreeCORE"\n', encoding="utf-8")
        (profile / "env.pyd").write_text(
            'FREEBSD_RELEASE_VERSION = "15.1-RELEASE"\nVERSION_NUMBER = "15.0"\n',
            encoding="utf-8",
        )
        (profile / "config.pyd").write_text(
            'make_conf = {"DEFAULT_VERSIONS": "python=3.11 python3=3.11 ssl=base"}\n',
            encoding="utf-8",
        )
        git(self.build, "add", "build")
        git(self.build, "commit", "-q", "-m", "fixture")

        be_root = self.build / "freenas" / "_BE"
        (be_root / "objs" / "ports" / "distfiles").mkdir(parents=True)
        (be_root / "repo-manifest").write_text("repo revision\n", encoding="utf-8")

        self.lock = self.root / "build.lock"
        self.config = self.root / "slots.json"
        self.write_config()

    def tearDown(self):
        self.temporary.cleanup()

    def write_config(self, **slot_changes):
        slot = {
            "branch": "freecore/15.0-maintenance",
            "freebsd_release": "15.1-RELEASE",
            "manifest_min_entries": 1,
            "minimum_free_gib": 0,
            "product": "FreeCORE",
            "profile": "freenas",
            "python": "3.11",
            "root": str(self.build),
            "version": "15.0",
        }
        slot.update(slot_changes)
        self.config.write_text(
            json.dumps(
                {
                    "lock_file": str(self.lock),
                    "process_guard": False,
                    "schema_version": 1,
                    "slots": {"15.0": slot},
                }
            ),
            encoding="utf-8",
        )

    def invoke(self, action="check", *extra):
        return subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--config",
                str(self.config),
                action,
                "--slot",
                "15.0",
                *extra,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_accepts_matching_isolated_slot(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["branch"], "freecore/15.0-maintenance")
        self.assertEqual(evidence["python"], "3.11")
        self.assertEqual(evidence["global_lock"], "acquired")

    def test_rejects_wrong_branch(self):
        git(self.build, "checkout", "-q", "-b", "wrong-branch")
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("branch mismatch", result.stderr)

    def test_rejects_tracked_source_changes(self):
        path = self.build / "build" / "config" / "env.pyd"
        path.write_text(path.read_text(encoding="utf-8") + "# dirty\n", encoding="utf-8")
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("tracked source changes", result.stderr)

    def test_rejects_wrong_python_identity(self):
        path = self.build / "build" / "profiles" / "freenas" / "config.pyd"
        path.write_text(
            'make_conf = {"DEFAULT_VERSIONS": "python=3.12 python3=3.12 ssl=base"}\n',
            encoding="utf-8",
        )
        git(self.build, "add", str(path.relative_to(self.build)))
        git(self.build, "commit", "-q", "-m", "wrong Python")
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("Python mismatch", result.stderr)

    def test_rejects_foreign_python_package(self):
        package = (
            self.build
            / "freenas"
            / "_BE"
            / "objs"
            / "ports"
            / "data"
            / "packages"
            / "ja-p"
            / "All"
            / "py312-example-1.pkg"
        )
        package.parent.mkdir(parents=True)
        package.write_bytes(b"fixture")
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("wrong Python flavor", result.stderr)

    def test_rejects_second_global_lock_holder(self):
        with self.lock.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("global lock", result.stderr)

    def test_run_executes_in_selected_root_with_slot_environment(self):
        evidence = self.root / "run-evidence.json"
        code = (
            "import json, os, pathlib; "
            f"pathlib.Path({str(evidence)!r}).write_text(json.dumps({{"
            "'cwd': os.getcwd(), 'slot': os.environ.get('FREECORE_BUILD_SLOT'), "
            "'build_root': os.environ.get('BUILD_ROOT')}, sort_keys=True))"
        )
        result = self.invoke("run", "--", sys.executable, "-c", code)
        self.assertEqual(result.returncode, 0, result.stderr)
        recorded = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(recorded["cwd"], str(self.build.resolve()))
        self.assertEqual(recorded["slot"], "15.0")
        self.assertEqual(recorded["build_root"], str(self.build.resolve()))

    def test_run_keeps_global_lock_across_exec(self):
        command = [
            sys.executable,
            str(TOOL),
            "--config",
            str(self.config),
            "run",
            "--slot",
            "15.0",
            "--",
            sys.executable,
            "-c",
            "import time; time.sleep(2)",
        ]
        running = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertTrue(running.stdout.readline())
            second = self.invoke()
            self.assertEqual(second.returncode, 2)
            self.assertIn("global lock", second.stderr)
            _stdout, stderr = running.communicate(timeout=5)
            self.assertEqual(running.returncode, 0, stderr)
        finally:
            if running.poll() is None:
                running.terminate()
                running.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
