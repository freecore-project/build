#!/usr/bin/env python3
"""Verify and materialize the immutable public inputs for a FreeCORE release.

Ordinary repositories are verified at their declared commit and tree. Source
deltas are downloaded over HTTPS, checked by SHA-256, applied to an isolated
Git index, checked against the declared final tree, and committed locally with
deterministic metadata. The local commit has the public base as its only parent.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path


MAX_DELTA_BYTES = 16 * 1024 * 1024
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "freecore-release-sources.json"


class MaterializationError(RuntimeError):
    pass


def git(repo: Path, *args: str, input_bytes: bytes | None = None,
        env: dict | None = None, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_bytes,
        capture_output=True,
        env={**os.environ, **(env or {})},
    )
    if check and result.returncode != 0:
        raise MaterializationError(
            f"git {' '.join(args)} failed in {repo}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout.decode(errors="replace").strip()


def require_sha(value: object, field: str) -> str:
    if not isinstance(value, str) or not FULL_SHA.fullmatch(value):
        raise MaterializationError(f"{field} must be one full lowercase Git object ID")
    return value


def require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise MaterializationError(f"{field} must be one full lowercase SHA-256 digest")
    return value


def require_branch(value: object) -> str:
    if not isinstance(value, str) or not value or FULL_SHA.fullmatch(value):
        raise MaterializationError(
            "source branch must be a real non-empty branch name, not a commit ID"
        )
    return value


def repository_path(build_root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise MaterializationError("source path must be a non-empty relative path")
    root = build_root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise MaterializationError(f"source path escapes build root: {relative}") from error
    if not (path / ".git" / "HEAD").exists():
        raise MaterializationError(f"source checkout is missing or is not a Git repository: {path}")
    return path


def fetch_delta(source: dict) -> bytes:
    override = os.environ.get("FREECORE_RELEASE_DELTA_DIR")
    filename = source.get("delta_filename")
    if not isinstance(filename, str) or Path(filename).name != filename:
        raise MaterializationError("delta_filename must be one plain filename")

    if override:
        directory = Path(override).resolve()
        path = (directory / filename).resolve()
        try:
            path.relative_to(directory)
        except ValueError as error:
            raise MaterializationError("delta override path escapes its directory") from error
        data = path.read_bytes()
    else:
        url = source.get("delta_url")
        if not isinstance(url, str) or urllib.parse.urlparse(url).scheme != "https":
            raise MaterializationError("release deltas must use an HTTPS URL")
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "FreeCORE-release-source-materializer/1"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(MAX_DELTA_BYTES + 1)

    if len(data) > MAX_DELTA_BYTES:
        raise MaterializationError("release delta exceeds the 16 MiB safety limit")
    expected = require_sha256(source.get("delta_sha256"), "delta_sha256")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise MaterializationError(
            f"release delta checksum mismatch: expected {expected}, received {actual}"
        )
    return data


def verify_origin(repo: Path, expected: object) -> str:
    if not isinstance(expected, str) or not expected.startswith("https://"):
        raise MaterializationError("source URL must be HTTPS")
    observed = git(repo, "remote", "get-url", "origin")
    if observed != expected and not os.environ.get("FREECORE_ALLOW_SOURCE_MIRRORS"):
        raise MaterializationError(
            f"source origin mismatch for {repo.name}: expected {expected}, observed {observed}"
        )
    return observed


def clean(repo: Path) -> None:
    if git(repo, "status", "--porcelain"):
        raise MaterializationError(f"source checkout has local modifications: {repo}")


def materialized_head(repo: Path, base: str, tree: str) -> str | None:
    head = git(repo, "rev-parse", "HEAD")
    if git(repo, "rev-parse", "HEAD^{tree}") != tree:
        return None
    parents = git(repo, "rev-list", "--parents", "-1", head).split()
    if parents != [head, base]:
        return None
    clean(repo)
    return head


def deterministic_commit(repo: Path, source: dict, tree: str, base: str) -> str:
    date = source.get("materialized_commit_date")
    if not isinstance(date, str) or not date:
        raise MaterializationError("materialized_commit_date is required for a delta source")
    name = source["name"]
    env = {
        "TZ": "UTC",
        "GIT_AUTHOR_NAME": "FreeCORE",
        "GIT_AUTHOR_EMAIL": "dev@freecore.org",
        "GIT_COMMITTER_NAME": "FreeCORE",
        "GIT_COMMITTER_EMAIL": "dev@freecore.org",
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    }
    return git(
        repo, "commit-tree", tree, "-p", base,
        "-m", f"FreeCORE: materialize {name} release source",
        env=env,
    )


def materialize_delta(repo: Path, source: dict) -> dict:
    base = require_sha(source.get("commit"), "commit")
    expected_tree = require_sha(source.get("tree"), "tree")
    clean(repo)

    existing = materialized_head(repo, base, expected_tree)
    if existing:
        return {
            "head": existing,
            "tree": expected_tree,
            "base_commit": base,
            "delta_sha256": source["delta_sha256"],
            "already_materialized": True,
        }

    head = git(repo, "rev-parse", "HEAD")
    if head != base:
        raise MaterializationError(
            f"delta base mismatch for {source['name']}: expected {base}, observed {head}"
        )

    patch = fetch_delta(source)
    with tempfile.TemporaryDirectory(prefix="freecore-materialize-") as tmp:
        index = Path(tmp) / "index"
        index_env = {"GIT_INDEX_FILE": str(index)}
        git(repo, "read-tree", base, env=index_env)
        git(
            repo, "apply", "--cached", "--whitespace=nowarn", "-",
            input_bytes=patch, env=index_env,
        )
        tree = git(repo, "write-tree", env=index_env)
    if tree != expected_tree:
        raise MaterializationError(
            f"delta result tree mismatch for {source['name']}: "
            f"expected {expected_tree}, produced {tree}"
        )

    commit = deterministic_commit(repo, source, tree, base)
    git(repo, "checkout", "--quiet", "--detach", commit)
    clean(repo)
    if git(repo, "rev-parse", "HEAD^{tree}") != expected_tree:
        raise MaterializationError(f"materialized checkout verification failed for {source['name']}")
    return {
        "head": commit,
        "tree": tree,
        "base_commit": base,
        "delta_sha256": source["delta_sha256"],
        "already_materialized": False,
    }


def verify_direct(repo: Path, source: dict) -> dict:
    expected_commit = require_sha(source.get("commit"), "commit")
    expected_tree = require_sha(source.get("tree"), "tree")
    clean(repo)
    head = git(repo, "rev-parse", "HEAD")
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    if head != expected_commit:
        raise MaterializationError(
            f"source commit mismatch for {source['name']}: "
            f"expected {expected_commit}, observed {head}"
        )
    if tree != expected_tree:
        raise MaterializationError(
            f"source tree mismatch for {source['name']}: expected {expected_tree}, observed {tree}"
        )
    return {"head": head, "tree": tree}


def materialize_all(config: dict, build_root: Path) -> dict:
    if config.get("schema") != 1:
        raise MaterializationError("unsupported release-source manifest schema")
    sources = config.get("sources")
    if not isinstance(sources, list) or not sources:
        raise MaterializationError("release-source manifest has no sources")

    names: set[str] = set()
    resolved = []
    for source in sources:
        name = source.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise MaterializationError("release-source names must be unique non-empty strings")
        names.add(name)
        branch = require_branch(source.get("branch"))
        repo = repository_path(build_root, source.get("path"))
        observed_origin = verify_origin(repo, source.get("url"))
        result = (
            materialize_delta(repo, source)
            if "delta_url" in source
            else verify_direct(repo, source)
        )
        # Whether this invocation created the local deterministic commit is a
        # runtime detail, not source provenance. Keep the resolved manifest
        # byte-stable across the first and every subsequent checkout run.
        result.pop("already_materialized", None)
        resolved.append({
            "name": name,
            "path": source["path"],
            "url": source["url"],
            "observed_origin": observed_origin,
            "branch": branch,
            "requested_commit": source["commit"],
            **result,
        })

    build_record = None
    if (build_root / ".git" / "HEAD").exists():
        build_record = {
            "head": git(build_root, "rev-parse", "HEAD"),
            "tree": git(build_root, "rev-parse", "HEAD^{tree}"),
            "origin": git(build_root, "remote", "get-url", "origin", check=False),
        }
    return {
        "schema": 1,
        "release": config.get("release"),
        "build": build_record,
        "sources": resolved,
    }


def main() -> int:
    config_path = Path(os.environ.get("FREECORE_RELEASE_SOURCES", DEFAULT_CONFIG))
    build_root_text = os.environ.get("BE_ROOT")
    if not build_root_text:
        raise MaterializationError("BE_ROOT is not set")
    build_root = Path(build_root_text).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    resolved = materialize_all(config, build_root)
    output = build_root / "public-source-manifest.json"
    output.write_text(
        json.dumps(resolved, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Verified {len(resolved['sources'])} immutable public source inputs")
    print(f"Resolved source manifest: {output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (MaterializationError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Public source materialization failed: {error}", file=sys.stderr)
        sys.exit(1)
