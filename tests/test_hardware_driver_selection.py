import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
CONFIG = ROOT / 'build' / 'profiles' / 'freenas' / 'config.pyd'
KERNEL_CONFIG = ROOT / 'build' / 'profiles' / 'freenas' / 'kernel' / 'TRUENAS.amd64'
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


def kernel_devices():
    devices = []
    for line in KERNEL_CONFIG.read_text().splitlines():
        fields = line.partition('#')[0].split()
        if len(fields) >= 2 and fields[0] == 'device':
            devices.append(fields[1])
    return devices


class HardwareDriverSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kernel_devices = kernel_devices()
        cls.kernel_modules = assigned_literal(CONFIG, 'kernel_modules')
        cls.ports = string_port_additions()

    def test_13_3_nic_coverage_uses_fb15_safe_driver_split(self):
        for port in {'net/aquantia-atlantic-kmod', 'net/realtek-rge-kmod'}:
            self.assertEqual(self.ports.count(port), 1)

        self.assertNotIn('net/realtek-re-kmod', self.ports)

    def test_modern_in_tree_nic_modules_ship_in_the_image(self):
        for module in {'ena', 'enic', 'gve', 'mana'}:
            self.assertEqual(self.kernel_modules.count(module), 1)

    def test_representative_storage_and_server_nic_coverage_is_retained(self):
        expected_modules = {
            'bnxt', 'cxgbe', 'ice', 'igc', 'mlx5en', 'qlnx',
            'ctl', 'iscsi', 'iser', 'mpi3mr', 'nvme', 'nvmf', 'smartpqi',
        }
        expected_devices = {
            'aacraid', 'ahci', 'arcmsr', 'ciss', 'isci', 'mfi', 'mpr', 'mps',
            'mrsas', 'nvme', 'smartpqi', 'vmd',
            'bxe', 'cxgbe', 'em', 'iavf', 'ice', 'igc', 'ix', 'mlx5en', 're',
            'vtnet',
        }

        self.assertEqual(expected_modules - set(self.kernel_modules), set())
        self.assertEqual(expected_devices - set(self.kernel_devices), set())
        self.assertEqual(len(self.kernel_modules), len(set(self.kernel_modules)))
        self.assertEqual(len(self.kernel_devices), len(set(self.kernel_devices)))


if __name__ == '__main__':
    unittest.main()
