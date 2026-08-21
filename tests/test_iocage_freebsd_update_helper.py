import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
CONFIG = ROOT / 'build' / 'profiles' / 'freenas' / 'config.pyd'
PORTS_SYSTEM = ROOT / 'build' / 'profiles' / 'freenas' / 'ports-system.pyd'


def assigned_literal(path, name):
    tree = ast.parse(path.read_text())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f'{path} does not assign {name}')


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


class IocageFreeBSDUpdateHelperTests(unittest.TestCase):
    def test_iocage_keeps_standalone_phttpget_without_host_updater(self):
        make_conf_build = assigned_literal(CONFIG, 'make_conf_build')
        local_dirs = make_conf_build['LOCAL_DIRS'].split()

        self.assertIn('sysutils/iocage', string_port_additions())
        self.assertEqual(make_conf_build['WITHOUT_FREEBSD_UPDATE'], 'yes')
        self.assertEqual(local_dirs.count('libexec/phttpget'), 1)
        self.assertNotIn('usr.sbin/freebsd-update', local_dirs)


if __name__ == '__main__':
    unittest.main()
