"""Reject generated authentication state before packaging a release world."""

import os
from pathlib import Path
import re
import sqlite3


SASL_DATABASE_NAMES = frozenset((
    'sasldb2', 'sasldb2.db', 'sasldb2-lock', 'sasldb2.db-lock',
))
IOCAGE_SOURCE = re.compile(r'(?<![A-Za-z0-9./_-])(?:https://)?codeberg\.org/freecore/iocage(?:\.git)?/?(?=$|[\s).,])')


def require_public_iocage_metadata(root):
    """Require regenerated installed metadata; read immutable SQLite only."""
    for relative in ('var/db/pkg/local.sqlite', 'conf/base/var/db/pkg/local.sqlite'):
        database = root / relative
        if relative.startswith('conf/') and not os.path.lexists(database):
            continue
        reason = ('Rebuild cached iocage package metadata before packaging: ' + relative)
        # Do not follow a database or directory link into a different world.
        if any((root / Path(*Path(relative).parts[:index])).is_symlink()
               for index in range(1, len(Path(relative).parts) + 1)) or not database.is_file():
            raise ValueError(reason)
        # Immutable mode must not silently ignore pending SQLite journal data.
        if any(os.path.lexists(str(database) + suffix) for suffix in ('-wal', '-shm', '-journal')):
            raise ValueError(reason)
        connection = None
        try:
            connection = sqlite3.connect(database.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
            rows = connection.execute('SELECT "desc" FROM packages WHERE origin = ?', ('sysutils/iocage',)).fetchall()
            if len(rows) != 1 or not isinstance(rows[0][0], str) or not IOCAGE_SOURCE.search(rows[0][0]):
                raise ValueError(reason)
        except sqlite3.Error:
            raise ValueError(reason) from None
        finally:
            if connection is not None:
                connection.close()


def require_clean_package_input(world):
    """Reject SASL entries by name, then read immutable package provenance.

    An apparently empty database may retain deleted records. Release input
    must therefore have no generated SASL database, including configuration
    template copies and symlinks. SASL databases are never opened. Only the
    installed package metadata is read; no database or installed system changes.
    """
    root = Path(world)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Package input world must be an existing directory')

    def unreadable(error):
        raise ValueError('Package input directory could not be inspected') from error

    for directory, names, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in sorted(names + files):
            if name in SASL_DATABASE_NAMES:
                relative = (Path(directory) / name).relative_to(root).as_posix()
                raise ValueError(
                    'Package input contains a SASL database entry: {}. '
                    'Prepare clean build input before packaging.'.format(relative)
                )
    require_public_iocage_metadata(root)
