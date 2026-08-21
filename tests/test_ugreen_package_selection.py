from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
PROFILE_ROOT = ROOT / 'build' / 'profiles' / 'freenas'
PORTS_SYSTEM = PROFILE_ROOT / 'ports-system.pyd'
PORT_SELECTION = 'ports += "sysutils/ugreen-led-ctl"'


class UgreenPackageSelectionTests(unittest.TestCase):
    def test_validation_cli_is_selected_once(self):
        self.assertEqual(PORTS_SYSTEM.read_text().splitlines().count(PORT_SELECTION), 1)

    def test_profile_has_no_automatic_ugreen_integration(self):
        mentions = []
        for path in sorted(PROFILE_ROOT.rglob('*')):
            if not path.is_file():
                continue
            for line in path.read_text(errors='ignore').splitlines():
                if 'ugreen' in line.lower():
                    mentions.append((path.relative_to(PROFILE_ROOT).as_posix(), line.strip()))

        self.assertEqual(mentions, [('ports-system.pyd', PORT_SELECTION)])


if __name__ == '__main__':
    unittest.main()
