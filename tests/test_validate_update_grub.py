import os
from pathlib import Path
import shutil
import sqlite3
import subprocess

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPOSITORY_ROOT / 'build/profiles/freenas/ValidateUpdate'


def database(path, rows=()):
    with sqlite3.connect(path) as connection:
        connection.execute(
            'CREATE TABLE vm_vm ('
            'id INTEGER PRIMARY KEY, name TEXT NOT NULL, bootloader TEXT NOT NULL, grubconfig TEXT)'
        )
        connection.executemany(
            'INSERT INTO vm_vm (id, name, bootloader, grubconfig) VALUES (?, ?, ?, ?)', rows,
        )


def validator_copy(tmp_path):
    sqlite = shutil.which('sqlite3') or str(tmp_path / 'missing-sqlite3')
    path = tmp_path / 'ValidateUpdate'
    source = VALIDATOR.read_text()
    source = source.replace('database=/data/freenas-v1.db', f'database="{tmp_path / "freenas-v1.db"}"')
    source = source.replace('sqlite3=/usr/local/bin/sqlite3', f'sqlite3="{sqlite}"')
    path.write_text(source)
    path.chmod(0o755)
    return path


def validate(tmp_path, current='FreeCORE-15.0-RELEASE', new='FreeCORE-15.1-STABLE'):
    return subprocess.run(
        [str(validator_copy(tmp_path))],
        env={**os.environ, 'CURRENT_VERSION': current, 'NEW_VERSION': new},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


@pytest.mark.parametrize('new', ['FreeCORE-15.1-RC4', 'FreeCORE-15.1-RC5'])
@pytest.mark.parametrize('inventory', ['missing', 'unreadable', 'grub', 'uefi'])
def test_15_0_upgrade_does_not_require_vm_inventory(tmp_path, inventory, new):
    path = tmp_path / 'freenas-v1.db'
    before = None
    if inventory != 'missing':
        bootloader = 'GRUB' if inventory == 'grub' else 'UEFI'
        database(path, [(1, 'existing_vm', bootloader, 'private-guest-configuration')])
        before = path.read_bytes()
        if inventory == 'unreadable':
            path.chmod(0)

    try:
        result = validate(tmp_path, current='FreeCORE-15.0-U1.7', new=new)
    finally:
        if inventory == 'unreadable':
            path.chmod(0o600)

    assert result.returncode == 0
    assert result.stdout == result.stderr == ''
    if before is None:
        assert not path.exists()
    else:
        assert path.read_bytes() == before


@pytest.mark.parametrize(('current', 'new'), [
    ('FreeCORE-15.0-RELEASE', 'FreeCORE-15.0-STABLE-U1'),
    ('FreeCORE-15.1-STABLE', 'FreeCORE-15.1-STABLE-U1'),
])
def test_non_transition_is_unchanged_without_requiring_inventory(tmp_path, current, new):
    result = validate(tmp_path, current=current, new=new)

    assert result.returncode == 0
    assert result.stdout == result.stderr == ''


def test_15_1_profile_no_longer_selects_grub2_bhyve():
    profile = (REPOSITORY_ROOT / 'build/profiles/freenas/ports-system.pyd').read_text()

    assert 'sysutils/grub2-bhyve' not in profile
    assert '"name": "sysutils/vm-bhyve"' in profile
    assert 'OPTIONS_FILE_UNSET+=GRUB2_BHYVE' in profile
