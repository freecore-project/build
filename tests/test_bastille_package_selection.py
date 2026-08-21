import ast
from pathlib import Path
import unittest


PORTS_SYSTEM = Path(__file__).parents[1] / 'build' / 'profiles' / 'freenas' / 'ports-system.pyd'


def string_port_additions():
    additions = []
    for node in ast.walk(ast.parse(PORTS_SYSTEM.read_text())):
        if not isinstance(node, ast.AugAssign):
            continue
        if not isinstance(node.target, ast.Name) or node.target.id != 'ports':
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            additions.append(node.value.value)
    return additions


def active_profile_source():
    return '\n'.join(line.partition('#')[0] for line in PORTS_SYSTEM.read_text().splitlines())


class BastillePackageSelectionTests(unittest.TestCase):
    def test_bastille_and_legacy_iocage_are_both_packaged_once(self):
        ports = string_port_additions()

        self.assertEqual(ports.count('sysutils/bastille'), 1)
        self.assertEqual(ports.count('sysutils/iocage'), 1)

    def test_image_selection_does_not_configure_or_enable_bastille(self):
        source = active_profile_source()

        for forbidden in ('bastille setup', 'bastille_enable', 'pf_enable'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
