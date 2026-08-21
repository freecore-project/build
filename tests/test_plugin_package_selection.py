from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "build/tools/zfs-one-publish-plugin-pkg-repo.py"


def load_publisher():
    spec = importlib.util.spec_from_file_location("plugin_pkg_publisher", PUBLISHER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PUBLISHER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PluginPackageSelectionTests(unittest.TestCase):
    def test_nextcloud_keeps_its_complete_selected_service_stack(self):
        packages = load_publisher().DEFAULT_PACKAGES

        self.assertEqual(len(packages), len(set(packages)))
        application = packages.index("nextcloud-php84")
        self.assertEqual(
            packages[application + 1:application + 5],
            ["nginx", "postgresql18-server", "redis", "php84-pecl-redis"],
        )

    def test_transmission_daemon_keeps_its_separate_web_interface(self):
        packages = load_publisher().DEFAULT_PACKAGES

        self.assertEqual(len(packages), len(set(packages)))
        daemon = packages.index("transmission-daemon")
        self.assertEqual(packages[daemon + 1], "transmission-web")


if __name__ == "__main__":
    unittest.main()
