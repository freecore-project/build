from pathlib import Path
import re
import unittest


ROOT = Path(__file__).parents[1]


class GoDefaultTests(unittest.TestCase):
    """the internal development record: every Go port builds with a Go that still gets security fixes."""

    def default_versions(self):
        config = (ROOT / "build/profiles/freenas/config.pyd").read_text(encoding="utf-8")
        match = re.search(r'make_conf_pkg = \{.*?"DEFAULT_VERSIONS":\s*"([^"]+)"', config, re.S)
        self.assertIsNotNone(match, "make_conf_pkg has no DEFAULT_VERSIONS")
        return dict(item.split("=", 1) for item in match.group(1).split())

    def test_packages_default_to_go_1_26(self):
        # Without it the ports default (1.24) builds buildah, skopeo, the CNI plugins and conmon, and
        # go:1.25+ resolves to 1.25 for versitygw: both are past Go's support window.
        self.assertEqual(self.default_versions().get("go"), "1.26")

    def test_python_and_ssl_defaults_are_unchanged(self):
        values = self.default_versions()
        self.assertEqual((values["python"], values["python3"], values["ssl"]), ("3.12", "3.12", "base"))


if __name__ == "__main__":
    unittest.main()
