from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class PythonRuntimeTests(unittest.TestCase):
    def test_appliance_selects_python_3_12(self):
        config = (
            ROOT / "build/profiles/freenas/config.pyd"
        ).read_text(encoding="utf-8")
        self.assertIn('"DEFAULT_VERSIONS":             "python=3.12 python3=3.12 ssl=base"', config)
        self.assertIn('"WITH_SAMBA4_PYTHON3":          "python3.12"', config)
        self.assertNotIn("python3.11", config)

    def test_appliance_packages_explicit_python_3_12_runtime(self):
        ports = (
            ROOT / "build/profiles/freenas/ports-system.pyd"
        ).read_text(encoding="utf-8")
        self.assertIn('ports += "lang/python312"', ports)
        self.assertNotIn('ports += "lang/python311"', ports)

    def test_cleanup_targets_match_the_selected_runtime(self):
        makefile = (ROOT / "Makefile.inc1").read_text(encoding="utf-8")
        self.assertIn("clean-package p=py312-freenas", makefile)
        self.assertNotIn("clean-package p=py311-", makefile)


if __name__ == "__main__":
    unittest.main()
