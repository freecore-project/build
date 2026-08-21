#!/usr/bin/env python3
"""Ship a last-known-good copy of the Daemonless application catalog.

the internal development record retired the signed Applications catalog: the appliance
reads the Daemonless organisation directly (its version index, its repository
list, each application's compose contract) and keeps a cache.  Since
the internal development record (the internal development record) it also reads the provider's fjord catalog
-- presentation, icons and a manifest per application -- which is optional
here exactly as it is on the box: without it the seed ships the rest.  A box with no
egress would otherwise list nothing, so the image build takes the same reads
once and ships the result as a seed with the exact cache shape middleware
uses.  Nothing is signed and nothing expires: a successful refresh on the box
replaces it.  The seed is authority for nothing; it is the last copy we saw.

Fails closed when the version index cannot be read: a release image without a
seed is a worse product than a failed build.  Set FREECORE_CATALOG_SEED=skip
to build an image without one (development only; the box then lists nothing
until its first refresh).
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ORGANIZATION = 'daemonless'
INDEX_URL = f'https://raw.githubusercontent.com/{ORGANIZATION}/{ORGANIZATION}/main/daemonless-versions.json'
REPOSITORIES_URL = f'https://api.github.com/orgs/{ORGANIZATION}/repos'
COMPOSE_URL = f'https://raw.githubusercontent.com/{ORGANIZATION}/{{name}}/main/compose.yaml'
FJORD_BASE_URL = f'https://catalog.daemonless.io/v1/{ORGANIZATION}/'
FJORD_CATALOG_URL = f'{FJORD_BASE_URL}catalog.json'
FJORD_VERSIONS = {'0.1'}
# The same pinned relative paths middleware accepts; nothing else is fetched.
FJORD_MANIFEST_PATH = re.compile(r'^manifests/([a-z0-9][a-z0-9._-]{0,62})\.yaml$')
FJORD_ICON_PATH = re.compile(r'^icons/[a-z0-9][a-z0-9._-]{0,62}\.(?:svg|png)$')
MAX_ICON_SIZE = 64 * 1024
MAX_FJORD_CATALOG_SIZE = 1024 * 1024
SEED_PATH = 'usr/local/share/freecore/applications/catalog-seed.json'
CACHE_SCHEMA = 4
MAX_INDEX_SIZE = 1024 * 1024
MAX_PAGE_SIZE = 4 * 1024 * 1024
MAX_COMPOSE_SIZE = 1024 * 1024
MAX_COMPOSES = 512
SERVICE_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}$')
TOKEN_ENVIRONMENT = 'FREECORE_CATALOG_GITHUB_TOKEN'
USER_AGENT = 'FreeCORE-build-applications-seed/1'


def fetch(url, maximum, accept='application/json'):
    headers = {'Accept': accept, 'User-Agent': USER_AGENT}
    token = os.environ.get(TOKEN_ENVIRONMENT)
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = f'Bearer {token}'
        headers['X-GitHub-Api-Version'] = '2022-11-28'
    request = Request(url, headers=headers)
    with urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https hosts
        if response.status != 200:
            raise RuntimeError(f'{url}: HTTP {response.status}')
        content = response.read(maximum + 1)
    if len(content) > maximum:
        raise RuntimeError(f'{url}: response exceeds {maximum} bytes')
    return content


def fetch_index():
    index = json.loads(fetch(INDEX_URL, MAX_INDEX_SIZE))
    if not isinstance(index, dict) or index.get('schema_version') != 2 or not isinstance(index.get('services'), dict):
        raise RuntimeError('Daemonless version index has an unexpected shape')
    return index


def fetch_repositories():
    pages = []
    for page in range(1, 9):
        data = json.loads(fetch(
            f'{REPOSITORIES_URL}?per_page=100&page={page}&type=public',
            MAX_PAGE_SIZE, accept='application/vnd.github+json',
        ))
        if not isinstance(data, list):
            raise RuntimeError('Daemonless repository page has an unexpected shape')
        if not data:
            break
        pages.append(data)
        if len(data) < 100:
            break
    if not pages:
        raise RuntimeError('Daemonless organisation lists no repositories')
    return pages


def document(content, now):
    return {
        'sha256': hashlib.sha256(content.encode('utf-8')).hexdigest(),
        'content': content,
        'fetched_at': now,
    }


def fetch_composes(index, now):
    composes = {}
    for name in sorted(index['services']):
        if not SERVICE_NAME.fullmatch(name):
            continue
        if len(composes) >= MAX_COMPOSES:
            break
        try:
            content = fetch(COMPOSE_URL.format(name=name), MAX_COMPOSE_SIZE, accept='text/plain').decode('utf-8')
        except (HTTPError, URLError, UnicodeDecodeError) as error:
            # A service without a compose contract is listed but not reviewable
            # until the box fetches it itself; that is the runtime behaviour too.
            print(f'seed: no compose for {name}: {error}', file=sys.stderr)
            continue
        if '\x00' in content:
            continue
        composes[name] = document(content, now)
    return composes


def fetch_fjord(index, now):
    """``(catalog, manifests, icons)`` from the fjord catalog, or ``(None, {}, {})``.

    Only applications the version index lists are fetched (the box lists no
    others); a stack's manifest is skipped (the box refuses stacks before
    reading one).  Every failure is logged and skipped.
    """
    try:
        catalog = json.loads(fetch(FJORD_CATALOG_URL, MAX_FJORD_CATALOG_SIZE))
    except (HTTPError, URLError, RuntimeError, ValueError) as error:
        print(f'seed: fjord catalog unavailable: {error}', file=sys.stderr)
        return None, {}, {}
    if (
        not isinstance(catalog, dict) or str(catalog.get('fjord_version')) not in FJORD_VERSIONS or
        not isinstance(catalog.get('apps'), list)
    ):
        print('seed: fjord catalog is in a format this build does not read', file=sys.stderr)
        return None, {}, {}
    listed = set(index['services'])
    manifests, icons = {}, {}
    for app in catalog['apps']:
        name = app.get('id') if isinstance(app, dict) else None
        if not isinstance(name, str) or name not in listed or not SERVICE_NAME.fullmatch(name):
            continue
        manifest = app.get('manifest_url')
        match = FJORD_MANIFEST_PATH.fullmatch(manifest) if isinstance(manifest, str) else None
        if match is not None and match.group(1) == name and app.get('class') != 'stack':
            try:
                content = fetch(f'{FJORD_BASE_URL}{manifest}', MAX_COMPOSE_SIZE, accept='text/plain').decode('utf-8')
            except (HTTPError, URLError, RuntimeError, UnicodeDecodeError) as error:
                print(f'seed: no fjord manifest for {name}: {error}', file=sys.stderr)
            else:
                if '\x00' not in content:
                    manifests[name] = document(content, now)
        icon = app.get('icon')
        if isinstance(icon, str) and FJORD_ICON_PATH.fullmatch(icon):
            try:
                content = fetch(f'{FJORD_BASE_URL}{icon}', MAX_ICON_SIZE, accept='image/*')
            except (HTTPError, URLError, RuntimeError) as error:
                print(f'seed: no icon for {name}: {error}', file=sys.stderr)
            else:
                icons[name] = {
                    'sha256': hashlib.sha256(content).hexdigest(),
                    'data': base64.b64encode(content).decode('ascii'),
                    'fetched_at': now,
                    'path': icon,
                }
    return catalog, manifests, icons


def build_seed():
    now = int(time.time())
    index = fetch_index()
    try:
        repositories = fetch_repositories()
    except (HTTPError, URLError, RuntimeError) as error:
        # Categories and licences degrade gracefully at runtime as well.
        print(f'seed: repository metadata unavailable: {error}', file=sys.stderr)
        repositories = None
    fjord, manifests, icons = fetch_fjord(index, now)
    return {
        'schema': CACHE_SCHEMA,
        'provider': ORGANIZATION,
        'source': 'seed',
        'fetched_at': now,
        'repositories_fetched_at': now if repositories is not None else 0,
        'index': index,
        'repositories': repositories,
        'composes': fetch_composes(index, now),
        'fjord': fjord,
        'fjord_fetched_at': now if fjord is not None else 0,
        'manifests': manifests,
        'icons': icons,
    }


def install_seed(root, seed):
    target = Path(root) / SEED_PATH
    if target.is_symlink() or target.parent.is_symlink():
        raise RuntimeError('Refusing a symlinked catalog seed path')
    target.parent.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o755)
    target.write_text(json.dumps(seed, indent=2, sort_keys=True) + '\n')
    target.chmod(0o644)
    print(f'seed: {len(seed["index"]["services"])} services, {len(seed["composes"])} contracts, '
          f'repositories={"yes" if seed["repositories"] else "no"}, '
          f'fjord={"yes" if seed["fjord"] else "no"} ({len(seed["manifests"])} manifests, '
          f'{len(seed["icons"])} icons) -> {SEED_PATH}')


def main(root):
    if os.environ.get('FREECORE_CATALOG_SEED') == 'skip':
        print('seed: skipped by FREECORE_CATALOG_SEED=skip; the image ships no catalog copy', file=sys.stderr)
        return
    try:
        seed = build_seed()
    except (HTTPError, URLError, RuntimeError, ValueError) as error:
        raise RuntimeError(f'Applications catalog seed could not be built: {error}') from error
    install_seed(root, seed)


if __name__ == '__main__':
    main(sys.argv[1])
