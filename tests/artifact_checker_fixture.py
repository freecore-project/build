"""Protocol fixture for delivery tests; real scanner integration is separate."""
from pathlib import Path
import sys


def make_checker(root):
    checker = Path(root) / 'fixture-artifact-checker'
    checker.write_text('#!' + sys.executable + '\n' + "import hashlib, json, pathlib, sys\npath = pathlib.Path(sys.argv[sys.argv.index('--package') + 1])\ndata = path.read_bytes()\nprint(json.dumps({'schema_version': 1, 'package': path.name,\n'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),\n'members_scanned': 1, 'files_scanned': 1, 'decoded_streams': 0,\n'bytes_scanned': len(data), 'findings': [], 'incomplete': [],\n'limitation': 'Fixture only; not a scanner.'}))\n")
    checker.chmod(0o700)
    return checker
