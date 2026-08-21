"""Render hostname-free source provenance without changing build identity."""

import re
from urllib.parse import urlsplit


SHIPPED_MANIFEST_HEADER = '# FreeCORE source provenance v1'
ARTIFACT_REPOSITORIES = (
    'build', 'freebsd-src', 'middleware', 'webui', 'ports', 'py-bsd',
    'py-cam', 'py-netif', 'py-libzfs', 'samba', 'py-licenselib',
    'freenas-pkgtools', 'iocage',
)
COMMIT_PREFIX = re.compile(r'[0-9a-f]{7,40}')


def render_shipped_manifest(content):
    """Return public-safe provenance and the original ordered commit prefixes.

    The input is the private checkout manifest. Names identify source
    components, not public Git commits: publication cuts have different IDs.
    Neither the private manifest nor its hash inputs are rewritten.
    """
    pins = {}
    for number, raw in enumerate(content.splitlines(), 1):
        if not raw.strip():
            continue
        fields = raw.split()
        if len(fields) != 2:
            raise ValueError('source manifest line {} must have URL and commit'.format(number))
        source, prefix = fields
        # Support ordinary Git URLs and scp-style SSH remotes. The hostname
        # and owner are intentionally not copied into the shipped manifest.
        if '://' in source:
            parsed = urlsplit(source)
            if (parsed.scheme not in ('https', 'http', 'ssh', 'git', 'file')
                    or parsed.query or parsed.fragment):
                raise ValueError('source manifest line {} has an invalid Git URL'.format(number))
            path = parsed.path
        else:
            match = re.fullmatch(r'(?:[^/@:]+@)?[^/:]+:(.+)', source)
            if match is None:
                raise ValueError('source manifest line {} has an invalid Git URL'.format(number))
            path = match.group(1)
        parts = path.split('/')
        if not parts[-1].endswith('.git') or any(part in ('.', '..') for part in parts):
            raise ValueError('source manifest line {} has an invalid repository name'.format(number))
        name = parts[-1][:-4]
        # The unchanged upstream dependency uses this shorter public name.
        if name == 'licenselib':
            name = 'py-licenselib'
        if name not in ARTIFACT_REPOSITORIES:
            raise ValueError('source manifest line {} names an unknown repository'.format(number))
        if name in pins:
            raise ValueError('source manifest line {} duplicates a repository'.format(number))
        if not COMMIT_PREFIX.fullmatch(prefix):
            raise ValueError('source manifest line {} has an invalid commit abbreviation'.format(number))
        pins[name] = prefix
    if tuple(pins) != ARTIFACT_REPOSITORIES:
        raise ValueError('source manifest repository order/inventory mismatch')
    text = SHIPPED_MANIFEST_HEADER + '\n'
    text += ''.join('{} {}\n'.format(name, prefix) for name, prefix in pins.items())
    return text, list(pins.values())
