import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
PORTS_SYSTEM = ROOT / 'build' / 'profiles' / 'freenas' / 'ports-system.pyd'


def port_additions():
    additions = []
    for node in ast.walk(ast.parse(PORTS_SYSTEM.read_text())):
        if not isinstance(node, ast.AugAssign):
            continue
        if not isinstance(node.target, ast.Name) or node.target.id != 'ports':
            continue
        value = ast.literal_eval(node.value)
        additions.append(value['name'] if isinstance(value, dict) else value)
    return additions


class GpuFirmwareSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ports = port_additions()

    def test_full_firmware_set_is_selected_through_the_metaport_once(self):
        # 13.3 parity: 13.3 pulled graphics/gpu-firmware-kmod through drm-kmod.
        self.assertEqual(self.ports.count('graphics/gpu-firmware-kmod'), 1)

    def test_driver_is_still_named_explicitly(self):
        self.assertEqual(self.ports.count('graphics/drm-66-kmod'), 1)
        self.assertNotIn('graphics/drm-kmod', self.ports)

    def test_no_individual_firmware_flavors_beside_the_metaport(self):
        for port in self.ports:
            for family in ('intel', 'amd', 'radeon'):
                self.assertFalse(port.startswith(f'graphics/gpu-firmware-{family}-kmod'), port)


if __name__ == '__main__':
    unittest.main()
