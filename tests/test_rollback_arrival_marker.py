import configparser
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "build/profiles/freenas/packages/base-os/config"

class RollbackArrivalMarkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parser = configparser.ConfigParser()
        parser.read(CONFIG)
        scripts = dict(parser.items("Scripts"))
        cls.post_install = scripts["post-install"]
        cls.post_upgrade = scripts["post-upgrade"]
        helper_end = cls.post_upgrade.index("has_alembic=")
        cls.helper = cls.post_upgrade[:helper_end]
        marker = cls.post_upgrade.index('record_rollback_arrival "/data/system-rollback.arrival"')
        producer_start = cls.post_upgrade.rfind('if [ ! -f "/data/update.failed" ]; then', 0, marker)
        producer_end = cls.post_upgrade.index("rm -f /data/sentinels/unscheduled-reboot", marker)
        cls.producer = cls.post_upgrade[producer_start:producer_end]

    def run_producer(self, data_path, script_mtime=None):
        script = self.helper + self.producer.replace("/data", str(data_path))
        script_path = data_path.parent / "base-os-post-upgrade"
        script_path.write_text(script)
        if script_mtime is not None:
            os.utime(script_path, (script_mtime, script_mtime))
        return subprocess.run(["/bin/sh", "-eu", script_path], capture_output=True, text=True)

    def test_success_is_atomic_root_only_and_uses_script_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            data.mkdir()
            marker = data / "system-rollback.arrival"
            marker.write_text("stale\n")
            marker.chmod(0o644)
            source_epoch = 1_700_000_123

            result = self.run_producer(data, source_epoch)

            self.assertEqual(result.returncode, 0, result.stderr)
            arrival, recorded_at = marker.read_text().split()
            self.assertEqual(arrival, "unknown")
            self.assertEqual(int(recorded_at), source_epoch)
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            self.assertEqual(list(data.glob("system-rollback.arrival.*")), [])

    def test_package_template_interpolation_preserves_printf_format(self):
        self.assertIn("recorded_at=$(/usr/bin/stat -f '%m' \"$0\")", self.post_upgrade)
        self.assertIn("printf '%s %s\\n' unknown \"$recorded_at\"", self.post_upgrade)

    def test_nonpositive_script_mtime_fails_the_package_script(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            data.mkdir()

            result = self.run_producer(data, 0)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unable to persist", result.stderr)
            self.assertFalse((data / "system-rollback.arrival").exists())

    def test_migration_failure_does_not_mark_the_new_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            data.mkdir()
            (data / "update.failed").write_text("migration failed\n")

            result = self.run_producer(data)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((data / "system-rollback.arrival").exists())

    def test_marker_failure_fails_the_package_script(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "not-a-directory"
            data.write_text("fixture\n")

            result = self.run_producer(data)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unable to persist", result.stderr)

    def test_fresh_install_has_no_marker_producer(self):
        self.assertNotIn("system-rollback.arrival", self.post_install)
        self.assertIn("system-rollback.arrival", self.post_upgrade)

    def test_producer_is_after_database_migration(self):
        migration = self.post_upgrade.index("/usr/local/sbin/migrate")
        producer = self.post_upgrade.index('record_rollback_arrival "/data/system-rollback.arrival"')
        self.assertLess(migration, producer)


if __name__ == "__main__":
    unittest.main()
