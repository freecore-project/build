import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
CUSTOMIZER = ROOT / 'build/customize/remove-bits.py'
PROFILE = ROOT / 'build/profiles/freenas/config.pyd'


def shell_commands():
    """Every literal handed to sh() by the remove-bits customizer."""
    commands = []
    for node in ast.walk(ast.parse(CUSTOMIZER.read_text())):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'sh':
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    commands.append(argument.value)
    return commands


class CompiledMagicDatabaseTests(unittest.TestCase):
    """the internal development record: the image keeps /usr/share/misc/magic.mgc.

    file 5.46 warns about duplicate entries whenever it has to parse the text
    database; the compiled one is the only quiet load path, so it is not a
    removable optimisation any more.
    """

    def test_remove_bits_never_touches_the_magic_database(self):
        commands = shell_commands()
        self.assertTrue(commands)
        for command in commands:
            self.assertNotIn('magic', command, command)
            self.assertNotIn('share/misc', command, command)

    def test_remove_bits_still_runs_in_the_image_profile(self):
        lists = []
        for node in ast.walk(ast.parse(PROFILE.read_text())):
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'customize_tasks' for target in node.targets
            ):
                lists.append(ast.literal_eval(node.value))
        self.assertTrue(any('remove-bits' in tasks for tasks in lists))


if __name__ == '__main__':
    unittest.main()
