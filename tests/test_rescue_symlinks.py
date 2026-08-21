import ast
from pathlib import Path
import unittest


CREATE_ISO = Path(__file__).parents[1] / 'build' / 'tools' / 'create-iso.py'
PORTS_SYSTEM = Path(__file__).parents[1] / 'build' / 'profiles' / 'freenas' / 'ports-system.pyd'


def rescue_symlinks():
    tree = ast.parse(CREATE_ISO.read_text())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == 'symlinks' for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('create-iso.py does not define symlinks')


class RescueSymlinkTests(unittest.TestCase):
    def test_fb15_rescue_members_are_exposed_in_the_installer(self):
        expected = {
            'nos-tun': '/sbin/nos-tun',
            'ping6': '/sbin/ping6',
            'routed': '/sbin/routed',
            'rtquery': '/sbin/rtquery',
            'rtsol': '/sbin/rtsol',
        }

        links = rescue_symlinks()
        for rescue_name, installed_path in expected.items():
            self.assertEqual(links.get(rescue_name), installed_path)

    def test_installer_uses_base_dhclient_provider(self):
        links = rescue_symlinks()

        self.assertEqual(links.get('dhclient'), '/sbin/dhclient')
        self.assertEqual(links.get('dhclient-script'), '/sbin/dhclient-script')
        self.assertNotIn('dhcpcd', links)

    def test_system_profile_does_not_install_dhcpcd(self):
        self.assertNotIn('ports += "net/dhcpcd"', PORTS_SYSTEM.read_text())


if __name__ == '__main__':
    unittest.main()
