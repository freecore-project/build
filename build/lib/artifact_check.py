"""Require an operator-configured, read-only package privacy checker.

The policy executable is private deployment configuration, never plan data.
Its JSON protocol is shared with the private artifact_host_gate tool.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


CHECKER_ENV = 'FREECORE_ARTIFACT_CHECKER'
REPORT_FIELDS = frozenset(('schema_version', 'package', 'sha256', 'size',
                          'members_scanned', 'files_scanned', 'decoded_streams',
                          'bytes_scanned', 'findings', 'incomplete', 'limitation'))


class ArtifactCheckError(RuntimeError):
    pass


def file_identity(path):
    if path.is_symlink() or not path.is_file():
        raise ArtifactCheckError('artifact input must be a regular file')
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest(), path.stat().st_size


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate report field')
        result[key] = value
    return result


def require_checked_artifact(path, expected_sha256, expected_size):
    """Scan exact input bytes; never relay potentially sensitive tool output."""
    if (not isinstance(expected_sha256, str)
            or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)
            or type(expected_size) is not int or expected_size < 0):
        raise ArtifactCheckError('invalid expected artifact identity')
    configured = os.environ.get(CHECKER_ENV, '')
    checker = Path(configured)
    if (not configured or not checker.is_absolute() or not checker.is_file()
            or not os.access(checker, os.X_OK)):
        raise ArtifactCheckError('FREECORE_ARTIFACT_CHECKER must name an absolute executable path')
    path = Path(path).absolute()
    expected = (expected_sha256, expected_size)
    try:
        if file_identity(path) != expected:
            raise ArtifactCheckError('artifact input differs from reviewed SHA-256 or size')
        # Bound the report read and suppress stderr; neither is safe to echo.
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                [str(checker), '--package', str(path), '--sha256', expected_sha256, '--json'],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                timeout=3600, check=False,
            )
            if result.returncode != 0:
                raise ArtifactCheckError('artifact checker blocked the input or did not complete')
            if output.tell() > 1024 * 1024:
                raise ArtifactCheckError('artifact checker report exceeds the protocol limit')
            output.seek(0)
            report = json.loads(output.read(), object_pairs_hook=unique_object)
        counts = ('size', 'members_scanned', 'files_scanned', 'decoded_streams', 'bytes_scanned')
        if (not isinstance(report, dict) or set(report) != REPORT_FIELDS
                or type(report['schema_version']) is not int or report['schema_version'] != 1
                or any(type(report[key]) is not int or report[key] < 0 for key in counts)
                or not isinstance(report['package'], str)
                or not isinstance(report['limitation'], str) or not report['limitation']
                or report['findings'] != [] or report['incomplete'] != []
                or (report['sha256'], report['size']) != expected):
            raise ArtifactCheckError('artifact checker report is invalid, blocked, incomplete, or mismatched')
        if file_identity(path) != expected:
            raise ArtifactCheckError('artifact input changed during its privacy check')
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise ArtifactCheckError('artifact checker or input could not be completely validated') from error

