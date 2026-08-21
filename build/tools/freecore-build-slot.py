#!/usr/bin/env python3

"""Fail-closed launcher for isolated FreeCORE build-host slots."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


DEFAULT_CONFIG = Path("/usr/local/etc/freecore-build-slots.json")


class PreflightError(RuntimeError):
    pass


def load_config(path):
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PreflightError(f"slot configuration is missing: {path}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise PreflightError(f"cannot read slot configuration {path}: {error}") from error

    if config.get("schema_version") != 1:
        raise PreflightError("slot configuration schema_version must be 1")
    if not isinstance(config.get("slots"), dict) or not config["slots"]:
        raise PreflightError("slot configuration has no slots")
    if not config.get("lock_file"):
        raise PreflightError("slot configuration has no lock_file")
    return config


def command_output(command, cwd=None):
    result = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise PreflightError(f"command failed: {' '.join(command)}: {detail}")
    return result.stdout.strip()


def parse_assignment(path, name):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise PreflightError(f"cannot read {path}: {error}") from error
    match = re.search(rf"^{re.escape(name)}\s*=\s*[\"']([^\"']+)[\"']", text, re.MULTILINE)
    if not match:
        raise PreflightError(f"cannot find {name} in {path}")
    return match.group(1)


def parse_product(path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise PreflightError(f"cannot read {path}: {error}") from error
    match = re.search(r'^PRODUCT\s*=\s*PRODUCT\s+or\s+[\"\']([^\"\']+)[\"\']', text, re.MULTILINE)
    if not match:
        raise PreflightError(f"cannot find the default PRODUCT in {path}")
    return match.group(1)


def parse_python_defaults(path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise PreflightError(f"cannot read {path}: {error}") from error
    match = re.search(r'[\"\']DEFAULT_VERSIONS[\"\']\s*:\s*[\"\']([^\"\']+)[\"\']', text)
    if not match:
        raise PreflightError(f"cannot find DEFAULT_VERSIONS in {path}")
    values = dict(
        item.split("=", 1)
        for item in match.group(1).split()
        if "=" in item
    )
    return values.get("python"), values.get("python3")


def is_within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def package_flavors(package_root):
    flavors = set()
    count = 0
    if not package_root.is_dir():
        return count, flavors
    pattern = re.compile(r"(?:^|[-_])(?:py|python)(3\d{2})(?:[-_.]|$)")
    for package in package_root.rglob("*.pkg"):
        if not package.is_file():
            continue
        count += 1
        flavors.update(match.group(1) for match in pattern.finditer(package.name))
    return count, flavors


def process_table():
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise PreflightError(f"cannot inspect the process table: {result.stderr.strip()}")
    rows = []
    parents = {}
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        pid, ppid = int(fields[0]), int(fields[1])
        parents[pid] = ppid
        rows.append((pid, fields[2]))
    ancestors = {os.getpid()}
    current = os.getpid()
    while current in parents and parents[current] not in ancestors:
        current = parents[current]
        ancestors.add(current)
    return [(pid, command) for pid, command in rows if pid not in ancestors]


def check_process_guard():
    patterns = [
        re.compile(r"\b(?:bmake|gmake|make)\b.*\brelease\b", re.IGNORECASE),
        re.compile(r"\bpoudriere\b.*\bbulk\b", re.IGNORECASE),
        re.compile(r"/build-ports\.py\b"),
        re.compile(r"/run-freecore-[^ ]*build[^ ]*\b"),
    ]
    matches = []
    for pid, command in process_table():
        if any(pattern.search(command) for pattern in patterns):
            matches.append(pid)
    if matches:
        raise PreflightError(
            "an unmanaged build process is already running (PID(s): "
            + ", ".join(str(pid) for pid in matches)
            + ")"
        )


def validate_slot(name, slot):
    required = {"root", "branch", "product", "version", "python", "freebsd_release"}
    missing = sorted(required - set(slot))
    if missing:
        raise PreflightError(f"slot {name} is missing: {', '.join(missing)}")

    root = Path(slot["root"])
    if not root.is_dir() or root.is_symlink():
        raise PreflightError(f"slot {name} root is missing or is a symlink: {root}")
    root = root.resolve()

    top = Path(command_output(["git", "rev-parse", "--show-toplevel"], cwd=root)).resolve()
    if top != root:
        raise PreflightError(f"slot {name} root is not its Git worktree root")
    branch = command_output(["git", "branch", "--show-current"], cwd=root)
    if branch != slot["branch"]:
        raise PreflightError(
            f"slot {name} branch mismatch: expected {slot['branch']}, found {branch or 'detached HEAD'}"
        )
    tracked_status = command_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=root
    )
    if tracked_status:
        raise PreflightError(f"slot {name} has tracked source changes")

    profile = slot.get("profile", "freenas")
    be_root = root / profile / "_BE"
    env_profile = root / "build" / "profiles" / profile / "env.pyd"
    config_profile = root / "build" / "profiles" / profile / "config.pyd"
    common_env = root / "build" / "config" / "env.pyd"

    product = parse_product(common_env)
    version = parse_assignment(env_profile, "VERSION_NUMBER")
    freebsd_release = parse_assignment(env_profile, "FREEBSD_RELEASE_VERSION")
    python, python3 = parse_python_defaults(config_profile)

    if product != slot["product"]:
        raise PreflightError(
            f"slot {name} product mismatch: expected {slot['product']}, found {product}"
        )
    if version != slot["version"]:
        raise PreflightError(
            f"slot {name} version mismatch: expected {slot['version']}, found {version}"
        )
    if freebsd_release != slot["freebsd_release"]:
        raise PreflightError(
            f"slot {name} FreeBSD release mismatch: expected {slot['freebsd_release']}, "
            f"found {freebsd_release}"
        )
    if python != slot["python"] or python3 != slot["python"]:
        raise PreflightError(
            f"slot {name} Python mismatch: expected {slot['python']}, "
            f"found python={python or 'unset'} python3={python3 or 'unset'}"
        )

    manifest = be_root / "repo-manifest"
    if not manifest.is_file():
        raise PreflightError(f"slot {name} has no repo-manifest; run and review make checkout")
    manifest_entries = len([line for line in manifest.read_text(encoding="utf-8").splitlines() if line])
    minimum = int(slot.get("manifest_min_entries", 1))
    if manifest_entries < minimum:
        raise PreflightError(
            f"slot {name} repo-manifest has {manifest_entries} entries; expected at least {minimum}"
        )

    distfiles = be_root / "objs" / "ports" / "distfiles"
    if not distfiles.is_dir() or distfiles.is_symlink():
        raise PreflightError(f"slot {name} local distfiles directory is missing or is a symlink")
    if not is_within(distfiles.resolve(), be_root.resolve()):
        raise PreflightError(f"slot {name} distfiles resolve outside its build environment")
    if distfiles.stat().st_dev != root.stat().st_dev:
        raise PreflightError(f"slot {name} distfiles are mounted on an external filesystem")

    package_root = be_root / "objs" / "ports" / "data" / "packages"
    if package_root.exists():
        if package_root.is_symlink() or not is_within(package_root.resolve(), be_root.resolve()):
            raise PreflightError(f"slot {name} package repository resolves outside its build environment")
        if package_root.stat().st_dev != root.stat().st_dev:
            raise PreflightError(f"slot {name} package repository is on an external filesystem")
    package_count, flavors = package_flavors(package_root)
    expected_flavor = slot["python"].replace(".", "")
    wrong_flavors = sorted(flavor for flavor in flavors if flavor != expected_flavor)
    if wrong_flavors:
        raise PreflightError(
            f"slot {name} package repository contains wrong Python flavor(s): "
            + ", ".join(wrong_flavors)
        )

    free_gib = shutil.disk_usage(root).free / (1024 ** 3)
    minimum_free_gib = float(slot.get("minimum_free_gib", 0))
    if free_gib < minimum_free_gib:
        raise PreflightError(
            f"slot {name} has {free_gib:.1f} GiB free; requires {minimum_free_gib:.1f} GiB"
        )

    return {
        "slot": name,
        "root": str(root),
        "branch": branch,
        "product": product,
        "version": version,
        "freebsd_release": freebsd_release,
        "python": python,
        "be_root": str(be_root),
        "repo_manifest_entries": manifest_entries,
        "package_files": package_count,
        "package_python_flavors": sorted(flavors),
        "free_gib": round(free_gib, 1),
    }


def acquire_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.open("a+")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        lock.close()
        raise PreflightError(f"another build holds the global lock: {path}") from error
    return lock


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("check", "run"):
        subparser = subparsers.add_parser(action)
        subparser.add_argument("--slot", required=True)
        if action == "run":
            subparser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        config = load_config(args.config)
        if args.slot not in config["slots"]:
            raise PreflightError(f"unknown slot: {args.slot}")
        lock = acquire_lock(Path(config["lock_file"]))
        if config.get("process_guard", True):
            check_process_guard()
        result = validate_slot(args.slot, config["slots"][args.slot])
        result["global_lock"] = "acquired"
        print(json.dumps(result, sort_keys=True))
        sys.stdout.flush()

        if args.action == "check":
            lock.close()
            return 0

        command = list(args.command)
        if command and command[0] == "--":
            command.pop(0)
        if not command:
            raise PreflightError("run requires a command after --")
        os.chdir(result["root"])
        os.set_inheritable(lock.fileno(), True)
        environment = os.environ.copy()
        environment["BUILD_ROOT"] = result["root"]
        environment["FREECORE_BUILD_SLOT"] = args.slot
        try:
            os.execvpe(command[0], command, environment)
        except OSError as error:
            raise PreflightError(f"cannot execute {command[0]}: {error}") from error
    except PreflightError as error:
        print(f"freecore-build-slot: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
