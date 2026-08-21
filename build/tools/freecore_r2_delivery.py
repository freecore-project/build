#!/usr/bin/env python3
"""Deterministic FreeCORE update and plugin delivery plans.

This tool deliberately separates the two public surfaces (``update`` and
``plugin``) from the four operations (``plan``, ``apply``, ``verify``, and
``rollback``).  Planning is credential-free.  R2 credentials are read only by
the rclone backend, from its protected environment/configuration, and apply or
rollback additionally requires the exact reviewed plan SHA-256.

There is intentionally no recursive sync, delete mode, signing operation, or
implicit default operation here.
"""

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request


# Keep the checker implementation and private policy outside public plan data.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from artifact_check import ArtifactCheckError, require_checked_artifact


SCHEMA_VERSION = 1
DEFAULT_UPDATE_TRAIN = "FreeCORE-15.1-STABLE"
# Compatibility alias for callers that imported the original constant.
UPDATE_TRAIN = DEFAULT_UPDATE_TRAIN
DEFAULT_TRAIN_REGISTRY = (
    Path(__file__).resolve().parents[1] / "config" / "zfs-one-trains.json"
)
STABLE_TRAIN_RE = re.compile(r"^FreeCORE-([0-9]+\.[0-9]+)-STABLE$")
PLUGIN_ABI = "FreeBSD:15:amd64"
PLUGIN_NOARCH_ABI = "FreeBSD:15:*"
PLUGIN_PACKAGE_ABIS = frozenset({PLUGIN_ABI, PLUGIN_NOARCH_ABI})
CATALOG_KEY = "plugins/git/iocage-freecore-plugins.git"
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
NO_STORE = "no-store"
# The frozen-update file the GUI "Install Manual Update File" path and
# `freenas-update <file>` consume: the signed LATEST manifest, its validator and
# the full packages, exactly as the train serves them. No separate signing step
# exists or is wanted; the manifest's signature is the train's.
MANUAL_UPDATE_SUFFIX = "-manual-update.tar"
MANUAL_UPDATE_MANIFEST_MEMBER = "./MANIFEST"
MANUAL_UPDATE_VALIDATOR_MEMBER = "./ValidateUpdate"
MANUAL_UPDATE_CONTENT_TYPE = "application/x-tar"
ICON_CACHE = "public, max-age=300, must-revalidate"
PUBLIC_USER_AGENT = "FreeCORE-R2-Delivery/1"
MAX_INLINE_ROLLBACK = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+,:$~-]*$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|credential|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
PRIVATE_VALUE_RE = re.compile(
    r"(?:-----BEGIN [^-]*PRIVATE KEY-----|://[^/@\s]+:[^/@\s]+@|\bAKIA[0-9A-Z]{16}\b)"
)
QUERY_SECRET_RE = re.compile(
    r"([?&](?:token|secret|key|password|credential)=)[^&\s]+", re.IGNORECASE
)


class DeliveryError(RuntimeError):
    """A fail-closed validation or delivery error."""


def canonical_bytes(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seal_plan(plan):
    sealed = copy.deepcopy(plan)
    sealed.pop("plan_sha256", None)
    sealed["plan_sha256"] = sha256_bytes(canonical_bytes(sealed))
    return sealed


def verify_plan_hash(plan):
    expected = plan.get("plan_sha256")
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        raise DeliveryError("plan_sha256 is missing or invalid")
    unsigned = copy.deepcopy(plan)
    unsigned.pop("plan_sha256", None)
    actual = sha256_bytes(canonical_bytes(unsigned))
    if actual != expected:
        raise DeliveryError("plan_sha256 does not match the canonical plan")
    return actual


def validate_generated_at(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DeliveryError("generated_at must be an explicit RFC3339 UTC timestamp")
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise DeliveryError("generated_at is not valid RFC3339") from error
    return value


def validate_hostname(value):
    if not isinstance(value, str) or not HOST_RE.fullmatch(value):
        raise DeliveryError("requested host must be a hostname without scheme or path")
    return value.lower()


def validate_update_train(value):
    if not isinstance(value, str) or not STABLE_TRAIN_RE.fullmatch(value):
        raise DeliveryError("update train must be a versioned FreeCORE STABLE train")
    return value


def validate_train_description(value):
    if not isinstance(value, str) or "\n" in value or "\r" in value or not value.strip():
        raise DeliveryError("train description must be one nonempty line")
    return value.strip()


def default_train_description(train):
    # The web interface classifies a train by a tag in this text: "[release]"
    # is a release train, "[prerelease]" a candidate train, and anything else
    # is treated as nightly and shown with the not-for-production banner. The
    # registry carries the reviewed text per train; this fallback covers the
    # no-registry path and must never lose the tag (the internal development record).
    series = STABLE_TRAIN_RE.fullmatch(validate_update_train(train)).group(1)
    return f"FreeCORE {series} stable releases [release]"


def public_stable_trains(registry_path, selected_train, selected_description=None):
    """Return the stable trains that may be exposed in public trains.txt."""
    selected_train = validate_update_train(selected_train)
    if registry_path is None:
        return [(selected_train, validate_train_description(
            selected_description or default_train_description(selected_train)
        ))]

    registry = load_json(Path(registry_path), "train registry")
    if not isinstance(registry, dict) or set(registry) != {"trains", "redirects"}:
        raise DeliveryError("train registry schema is invalid")
    entries = registry.get("trains")
    if not isinstance(entries, list):
        raise DeliveryError("train registry entries are invalid")

    result = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "description"}:
            raise DeliveryError("train registry entry is invalid")
        name = entry["name"]
        if "Nightlies" in str(name):
            continue
        validate_update_train(name)
        if name in seen:
            raise DeliveryError("train registry contains a duplicate STABLE train")
        seen.add(name)
        description = entry["description"]
        if name == selected_train and selected_description is not None:
            description = selected_description
        result.append((name, validate_train_description(description)))

    if selected_train not in seen:
        raise DeliveryError("selected update train is absent from the train registry")
    if result != sorted(result):
        raise DeliveryError("STABLE train registry entries are not in canonical order")
    return result


def validate_bucket(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value):
        raise DeliveryError("destination bucket name is invalid")
    return value


def validate_source_identity(value):
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\n" in value
        or "\r" in value
    ):
        raise DeliveryError("source_identity must be a public, non-path provenance identifier")
    reject_secrets(value, "source_identity")
    return value


def normalize_relative(value, what="path"):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise DeliveryError(f"invalid {what}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise DeliveryError(f"{what} must be a normalized relative path")
    return path.as_posix()


def normalize_key(value):
    key = normalize_relative(value, "object key")
    if key.startswith(".real_") or "/.real_" in key:
        raise DeliveryError("internal package revision names cannot be public keys")
    return key


def reject_forbidden_source_path(value):
    path = PurePosixPath(normalize_relative(value, "source path"))
    lowered = [part.lower() for part in path.parts]
    basename = lowered[-1]
    if (
        basename.endswith(".key")
        or basename in (".services.json", "fetch_head")
        or any(part in ("private", ".snapshots", "snapshots", "hooks", "logs", "reflogs") for part in lowered)
        or any(part.endswith(".lock") for part in lowered)
    ):
        raise DeliveryError(f"forbidden source path: {value}")
    return path.as_posix()


def validate_sha256(value, what="SHA-256"):
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise DeliveryError(f"invalid {what}")
    return value


def validate_git_oid(value, what="Git object ID"):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise DeliveryError(f"invalid {what}")
    return value


def reject_secrets(value, path="plan"):
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_KEY_RE.search(str(key)) and child not in (None, "", False):
                raise DeliveryError(f"sensitive field is forbidden in {path}")
            reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if PRIVATE_VALUE_RE.search(value) or QUERY_SECRET_RE.search(value):
            raise DeliveryError(f"credential or private-key material is forbidden in {path}")


def safe_regular_file(root, relative):
    relative = normalize_relative(relative, "source path")
    root = Path(root).resolve(strict=True)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise DeliveryError(f"unexpected source symlink: {relative}")
    if not current.is_file():
        raise DeliveryError(f"required source file is missing: {relative}")
    try:
        current.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise DeliveryError(f"source path escapes its root: {relative}") from error
    return current


def safe_directory(root, relative):
    relative = normalize_relative(relative, "source directory")
    root = Path(root).resolve(strict=True)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise DeliveryError(f"unexpected source symlink: {relative}")
    if not current.is_dir():
        raise DeliveryError(f"required source directory is missing: {relative}")
    try:
        current.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise DeliveryError(f"source directory escapes its root: {relative}") from error
    return current


def reject_unexpected_symlinks(root, allowed):
    root = Path(root).resolve(strict=True)
    allowed = {normalize_relative(item, "allowed symlink") for item in allowed}
    found = set()
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            if not path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if relative not in allowed:
                raise DeliveryError(f"unexpected source symlink: {relative}")
            found.add(relative)
    if found != allowed:
        missing = sorted(allowed - found)
        raise DeliveryError(f"required source symlink is missing: {missing[0]}")


def validate_update_symlinks(root):
    root = Path(root).resolve(strict=True)
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            if not path.is_symlink():
                continue
            relative = path.relative_to(root)
            target = os.readlink(path)
            if (
                len(relative.parts) != 2
                or relative.name != "LATEST"
                or "/" in target
                or "\\" in target
                or not re.fullmatch(r"FreeCORE-[A-Za-z0-9._-]+", target)
            ):
                raise DeliveryError(f"unexpected source symlink: {relative.as_posix()}")
            destination = path.parent / target
            if destination.is_symlink() or not destination.is_file():
                raise DeliveryError(f"LATEST target is missing or is another symlink: {relative.as_posix()}")


def recognized_symlink(parent, name, pattern):
    link = parent / name
    if not link.is_symlink():
        raise DeliveryError(f"{name} must be the documented symlink")
    target = os.readlink(link)
    if "/" in target or "\\" in target or not re.fullmatch(pattern, target):
        raise DeliveryError(f"{name} has an unrecognized target")
    resolved = parent / target
    if resolved.is_symlink() or not resolved.is_dir() and not resolved.is_file():
        raise DeliveryError(f"{name} target is missing or is another symlink")
    return target, resolved


def load_json(path, what):
    try:
        with open(path, "r", encoding="utf-8") as source:
            return json.load(source)
    except (OSError, ValueError) as error:
        raise DeliveryError(f"cannot read {what}: {error}") from error


def write_json(path, value):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=destination.parent, delete=False
    ) as temporary:
        temporary.write(data)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, destination)


def load_previous_state(path, bucket):
    if path is None:
        return {}
    state = load_json(path, "destination pre-state")
    if state.get("schema_version") != SCHEMA_VERSION:
        raise DeliveryError("destination pre-state schema is unsupported")
    if state.get("destination_bucket") != bucket:
        raise DeliveryError("destination pre-state bucket does not match")
    objects = state.get("objects")
    if not isinstance(objects, dict):
        raise DeliveryError("destination pre-state objects must be a map")
    reject_secrets(state, "destination pre-state")
    return objects


def previous_for(key, states):
    if key not in states:
        return {"captured": False}
    value = copy.deepcopy(states[key])
    if not isinstance(value, dict) or not isinstance(value.get("exists"), bool):
        raise DeliveryError(f"invalid destination pre-state for {key}")
    value["captured"] = True
    if not value["exists"]:
        allowed = {"captured", "exists"}
        if set(value) - allowed:
            raise DeliveryError(f"nonexistent pre-state has unexpected fields for {key}")
        return value

    required = {"size", "sha256", "content_type", "cache_control"}
    if not required.issubset(value):
        raise DeliveryError(f"existing pre-state is incomplete for {key}")
    if not isinstance(value["size"], int) or value["size"] < 0:
        raise DeliveryError(f"invalid prior size for {key}")
    validate_sha256(value["sha256"], f"prior SHA-256 for {key}")
    if not isinstance(value["content_type"], str) or not isinstance(value["cache_control"], str):
        raise DeliveryError(f"invalid prior metadata for {key}")

    has_inline = "bytes_base64" in value
    has_rollback = "rollback_object" in value
    if has_inline == has_rollback:
        raise DeliveryError(f"prior bytes or one rollback object is required for {key}")
    if has_inline:
        try:
            prior = base64.b64decode(value["bytes_base64"], validate=True)
        except (TypeError, ValueError) as error:
            raise DeliveryError(f"invalid prior bytes for {key}") from error
        if len(prior) > MAX_INLINE_ROLLBACK:
            raise DeliveryError(f"inline rollback bytes are too large for {key}")
        if len(prior) != value["size"] or sha256_bytes(prior) != value["sha256"]:
            raise DeliveryError(f"prior bytes do not match metadata for {key}")
        reject_secrets(prior.decode("utf-8", "replace"), f"prior bytes for {key}")
    else:
        value["rollback_object"] = normalize_key(value["rollback_object"])
    allowed = {
        "captured", "exists", "size", "sha256", "content_type",
        "cache_control", "bytes_base64", "rollback_object",
    }
    if set(value) - allowed:
        raise DeliveryError(f"existing pre-state has unexpected fields for {key}")
    return value


def file_object(
    root,
    source_path,
    key,
    source_revision,
    content_type,
    cache_control,
    mutability_class,
    phase,
    dependencies=None,
    expected_size=None,
    expected_sha256=None,
    previous_states=None,
):
    source_path = reject_forbidden_source_path(source_path)
    path = safe_regular_file(root, source_path)
    size = path.stat().st_size
    digest = sha256_file(path)
    if expected_size is not None and size != expected_size:
        raise DeliveryError(f"source size mismatch for {source_path}")
    if expected_sha256 is not None and digest != expected_sha256:
        raise DeliveryError(f"source SHA-256 mismatch for {source_path}")
    obj = {
        "key": normalize_key(key),
        "source_path": source_path,
        "source_revision": str(source_revision),
        "size": size,
        "sha256": digest,
        "content_type": content_type,
        "cache_control": cache_control,
        "class": mutability_class,
        "phase": phase,
        "dependencies": sorted(dependencies or []),
    }
    if mutability_class == "pointer":
        obj["previous"] = previous_for(obj["key"], previous_states or {})
    return obj


def inline_object(
    data,
    source_path,
    key,
    source_revision,
    content_type,
    cache_control,
    phase,
    dependencies=None,
    previous_states=None,
):
    obj = {
        "key": normalize_key(key),
        "source_path": normalize_relative(source_path, "generated source path"),
        "source_revision": str(source_revision),
        "size": len(data),
        "sha256": sha256_bytes(data),
        "content_type": content_type,
        "cache_control": cache_control,
        "class": "pointer",
        "phase": phase,
        "dependencies": sorted(dependencies or []),
        "inline_base64": base64.b64encode(data).decode("ascii"),
    }
    obj["previous"] = previous_for(obj["key"], previous_states or {})
    return obj


def validate_object(obj):
    required = {
        "key",
        "source_path",
        "source_revision",
        "size",
        "sha256",
        "content_type",
        "cache_control",
        "class",
        "phase",
        "dependencies",
    }
    if not required.issubset(obj):
        raise DeliveryError("plan object is missing required fields")
    allowed = required | {"inline_base64", "previous"}
    if set(obj) - allowed:
        raise DeliveryError(f"plan object has unexpected fields: {obj.get('key', '<unknown>')}")
    normalize_key(obj["key"])
    reject_forbidden_source_path(obj["source_path"])
    validate_sha256(obj["sha256"])
    if not isinstance(obj["size"], int) or obj["size"] < 0:
        raise DeliveryError(f"invalid object size for {obj['key']}")
    if obj["class"] not in ("immutable", "pointer"):
        raise DeliveryError(f"invalid mutability class for {obj['key']}")
    if not isinstance(obj["phase"], int) or obj["phase"] < 0:
        raise DeliveryError(f"invalid phase for {obj['key']}")
    if not isinstance(obj["dependencies"], list):
        raise DeliveryError(f"invalid dependencies for {obj['key']}")
    if obj["dependencies"] != sorted(set(obj["dependencies"])):
        raise DeliveryError(f"dependencies are not canonical for {obj['key']}")
    for dependency in obj["dependencies"]:
        normalize_key(dependency)
    if obj["key"] in obj["dependencies"]:
        raise DeliveryError(f"object depends on itself: {obj['key']}")
    if not isinstance(obj["content_type"], str) or not isinstance(obj["cache_control"], str):
        raise DeliveryError(f"invalid metadata for {obj['key']}")
    if not isinstance(obj["source_revision"], str) or not obj["source_revision"] or "\n" in obj["source_revision"]:
        raise DeliveryError(f"invalid source revision for {obj['key']}")
    if obj["class"] == "pointer":
        if "previous" not in obj:
            raise DeliveryError(f"pointer lacks destination pre-state for {obj['key']}")
        previous = obj["previous"]
        if previous == {"captured": False}:
            pass
        elif isinstance(previous, dict) and previous.get("captured") is True:
            raw = {key: value for key, value in previous.items() if key != "captured"}
            if previous_for(obj["key"], {obj["key"]: raw}) != previous:
                raise DeliveryError(f"pointer pre-state is not canonical for {obj['key']}")
        else:
            raise DeliveryError(f"pointer pre-state is invalid for {obj['key']}")
    elif "previous" in obj:
        raise DeliveryError(f"immutable object has pointer pre-state: {obj['key']}")
    if "inline_base64" in obj:
        if obj["class"] != "pointer" or not obj["source_path"].startswith("generated/"):
            raise DeliveryError(f"only generated pointers may contain inline bytes: {obj['key']}")
        try:
            data = base64.b64decode(obj["inline_base64"], validate=True)
        except (TypeError, ValueError) as error:
            raise DeliveryError(f"invalid inline bytes for {obj['key']}") from error
        if len(data) != obj["size"] or sha256_bytes(data) != obj["sha256"]:
            raise DeliveryError(f"inline bytes do not match {obj['key']}")


def require_object_metadata(obj, content_type, cache_control, mutability_class):
    if (
        obj["content_type"] != content_type
        or obj["cache_control"] != cache_control
        or obj["class"] != mutability_class
    ):
        raise DeliveryError(f"metadata matrix mismatch for {obj['key']}")


def validate_metadata_matrix(plan, obj):
    key = obj["key"]
    if plan["surface"] == "update":
        train = plan["metadata"]["train"]
        target = plan["metadata"]["latest_target"]
        exact = {
            "FreeCORE/trains.txt": ("text/plain; charset=utf-8", NO_STORE, "pointer"),
            "FreeCORE/trains_redir.json": ("application/json", NO_STORE, "pointer"),
            f"FreeCORE/{train}/ChangeLog.txt": ("text/plain; charset=utf-8", NO_STORE, "pointer"),
            f"FreeCORE/{train}/LATEST": ("application/json", NO_STORE, "pointer"),
            f"FreeCORE/{train}/{target}": ("application/json", IMMUTABLE_CACHE, "immutable"),
            "FreeCORE/pki/freecore-update-ca.pem": ("application/x-pem-file", IMMUTABLE_CACHE, "immutable"),
        }
        if key in exact:
            require_object_metadata(obj, *exact[key])
            return
        if key.startswith("FreeCORE/Packages/"):
            filename = key.removeprefix("FreeCORE/Packages/")
            if "/" in filename or not filename.endswith(".tgz") or not SAFE_NAME_RE.fullmatch(filename):
                raise DeliveryError(f"object is outside the package allowlist: {key}")
            require_object_metadata(obj, "application/octet-stream", IMMUTABLE_CACHE, "immutable")
            return
        if key.startswith("FreeCORE/Validators/"):
            filename = key.removeprefix("FreeCORE/Validators/")
            if "/" in filename or not SAFE_NAME_RE.fullmatch(filename):
                raise DeliveryError(f"object is outside the validator allowlist: {key}")
            require_object_metadata(obj, "text/plain; charset=utf-8", IMMUTABLE_CACHE, "immutable")
            return
        if key == plan["metadata"].get("iso_key") and key is not None:
            require_object_metadata(obj, "application/octet-stream", IMMUTABLE_CACHE, "immutable")
            return
        manual_update_key = plan["metadata"].get("manual_update_key")
        if manual_update_key is not None:
            if key == manual_update_key:
                require_object_metadata(obj, MANUAL_UPDATE_CONTENT_TYPE, IMMUTABLE_CACHE, "immutable")
                return
            if key == manual_update_key + ".sha256":
                require_object_metadata(obj, "text/plain; charset=utf-8", IMMUTABLE_CACHE, "immutable")
                return
        raise DeliveryError(f"object is outside the update allowlist: {key}")

    package_prefix = f"plugins/pkg/{PLUGIN_ABI}/latest/"
    if key.startswith(package_prefix):
        relative = key[len(package_prefix):]
        if relative.startswith("All/") or relative.startswith("Hashed/"):
            require_object_metadata(obj, "application/octet-stream", IMMUTABLE_CACHE, "immutable")
            return
        content_type = package_metadata_kind(relative)
        if content_type:
            require_object_metadata(obj, content_type, NO_STORE, "pointer")
            return
        raise DeliveryError(f"object is outside the package allowlist: {key}")
    plugins = set(plan["metadata"]["plugins"])
    if key.startswith("plugins/icons/") and key.endswith(".svg"):
        icon_name = key.removeprefix("plugins/icons/").removesuffix(".svg")
        if "/" in icon_name or icon_name not in plugins:
            raise DeliveryError(f"object is outside the accepted icon allowlist: {key}")
        require_object_metadata(obj, "image/svg+xml; charset=utf-8", ICON_CACHE, "immutable")
        return
    if key.startswith("plugins/git/"):
        catalog_prefix = f"{CATALOG_KEY}/"
        artifact_match = re.fullmatch(
            r"plugins/git/artifacts/([A-Za-z0-9._+,:$~-]+)\.git/(.+)", key
        )
        if key.startswith(catalog_prefix):
            relative = key[len(catalog_prefix):]
        elif artifact_match and artifact_match.group(1) in plugins:
            relative = artifact_match.group(2)
        else:
            raise DeliveryError(f"object is outside the accepted Git allowlist: {key}")
        kind = git_file_kind(relative)
        if kind is not None:
            expected_class, content_type, cache_control, _ = kind
            require_object_metadata(obj, content_type, cache_control, expected_class)
            return
    raise DeliveryError(f"object is outside the plugin allowlist: {key}")


def validate_plan(plan, require_applyable=False):
    reject_secrets(plan)
    required_plan_fields = {
        "schema_version", "generated_at", "surface", "source_identity",
        "destination_bucket", "requested_host", "metadata", "objects",
        "plan_sha256",
    }
    if set(plan) != required_plan_fields:
        raise DeliveryError("plan has missing or unexpected top-level fields")
    if plan.get("schema_version") != SCHEMA_VERSION:
        raise DeliveryError("unsupported plan schema")
    if plan.get("surface") not in ("update", "plugin"):
        raise DeliveryError("invalid delivery surface")
    validate_generated_at(plan.get("generated_at"))
    validate_bucket(plan.get("destination_bucket"))
    validate_hostname(plan.get("requested_host"))
    validate_source_identity(plan.get("source_identity"))
    metadata = plan.get("metadata")
    if not isinstance(metadata, dict):
        raise DeliveryError("plan metadata must be an object")
    if plan["surface"] == "update":
        # Plans sealed before the manual-update slot existed carry no
        # manual_update_key; they stay readable and simply have none.
        if set(metadata) - {"manual_update_key"} != {"train", "sequence", "latest_target", "iso_key"}:
            raise DeliveryError("update plan metadata schema is invalid")
        validate_update_train(metadata["train"])
        if (
            not isinstance(metadata["sequence"], str)
            or metadata["latest_target"] != f"FreeCORE-{metadata['sequence']}"
            or not re.fullmatch(r"FreeCORE-[A-Za-z0-9._-]+", metadata["latest_target"])
        ):
            raise DeliveryError("update plan sequence identity is invalid")
        if metadata["iso_key"] is not None:
            normalize_key(metadata["iso_key"])
        manual_update_key = metadata.get("manual_update_key")
        if manual_update_key is not None:
            if not isinstance(manual_update_key, str) or not manual_update_key.endswith(MANUAL_UPDATE_SUFFIX):
                raise DeliveryError("update plan manual update key is invalid")
            normalize_key(manual_update_key)
    else:
        if set(metadata) != {
            "abi", "package_revision", "catalog_key", "catalog_index_revision", "plugins",
        }:
            raise DeliveryError("plugin plan metadata schema is invalid")
        if metadata["abi"] != PLUGIN_ABI or metadata["catalog_key"] != CATALOG_KEY:
            raise DeliveryError("plugin plan metadata is outside the accepted surface")
        if not re.fullmatch(r"\.real_[0-9]{14}", str(metadata["package_revision"])):
            raise DeliveryError("plugin package revision is invalid")
        validate_git_oid(metadata["catalog_index_revision"], "catalog INDEX revision")
        plugins = metadata["plugins"]
        if not isinstance(plugins, list) or not plugins:
            raise DeliveryError("plugin list is invalid")
        if any(not isinstance(plugin, str) or not SAFE_NAME_RE.fullmatch(plugin) for plugin in plugins):
            raise DeliveryError("plugin list is invalid")
        if plugins != sorted(set(plugins)):
            raise DeliveryError("plugin list is invalid")
    objects = plan.get("objects")
    if not isinstance(objects, list) or not objects:
        raise DeliveryError("plan must contain objects")
    if objects != sorted(objects, key=lambda item: (item["phase"], item["key"])):
        raise DeliveryError("plan objects are not in canonical phase/key order")

    keys = set()
    phases = {}
    for obj in objects:
        validate_object(obj)
        validate_metadata_matrix(plan, obj)
        if obj["key"] in keys:
            raise DeliveryError(f"duplicate object key: {obj['key']}")
        keys.add(obj["key"])
        phases[obj["key"]] = obj["phase"]
        if require_applyable and obj["class"] == "pointer":
            if obj["previous"].get("captured") is not True:
                raise DeliveryError(f"destination pre-state is not captured for {obj['key']}")

    for obj in objects:
        for dependency in obj["dependencies"]:
            if dependency not in keys:
                raise DeliveryError(f"unknown dependency {dependency} for {obj['key']}")
            if (phases[dependency], dependency) >= (obj["phase"], obj["key"]):
                raise DeliveryError(f"dependency follows {obj['key']}")

    reject_secrets(plan)
    verify_plan_hash(plan)
    return plan


def reject_unused_previous_states(previous, objects):
    pointer_keys = {obj["key"] for obj in objects if obj["class"] == "pointer"}
    unused = sorted(set(previous) - pointer_keys)
    if unused:
        raise DeliveryError(f"destination pre-state contains an unplanned pointer: {unused[0]}")


def new_plan(surface, generated_at, source_identity, bucket, host, objects, metadata):
    plan = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": validate_generated_at(generated_at),
        "surface": surface,
        "source_identity": validate_source_identity(source_identity),
        "destination_bucket": validate_bucket(bucket),
        "requested_host": validate_hostname(host),
        "metadata": metadata,
        "objects": sorted(objects, key=lambda item: (item["phase"], item["key"])),
    }
    reject_secrets(plan)
    return seal_plan(plan)


def stable_latest_manifest(root, update_train):
    """Resolve and vet the signed LATEST manifest of a STABLE train under root."""
    train_rel = update_train
    train_dir = safe_directory(root, train_rel)
    target, manifest_path = recognized_symlink(
        train_dir, "LATEST", r"FreeCORE-[A-Za-z0-9._-]+"
    )
    manifest = load_json(manifest_path, "signed STABLE manifest")
    if manifest.get("Train") != update_train:
        raise DeliveryError("LATEST manifest is not the STABLE train")
    if not manifest.get("Signature"):
        raise DeliveryError("LATEST manifest is unsigned")
    if "Nightlies" in json.dumps(manifest, ensure_ascii=False):
        raise DeliveryError("STABLE manifest contains a Nightlies reference")
    sequence = manifest.get("Sequence")
    if not isinstance(sequence, str) or target != f"FreeCORE-{sequence}":
        raise DeliveryError("LATEST target does not match manifest Sequence")
    series = STABLE_TRAIN_RE.fullmatch(update_train).group(1)
    version = manifest.get("Version")
    if not isinstance(version, str) or not version.startswith(f"FreeCORE-{series}-"):
        raise DeliveryError("LATEST manifest version does not match its STABLE train series")
    if not SAFE_NAME_RE.fullmatch(version):
        raise DeliveryError("LATEST manifest version is not a safe object name")
    return train_rel, target, manifest_path, manifest, sequence, version


def manifest_package_files(manifest):
    """Yield (package, name, version, filename, sha256, size) for each full package."""
    packages = manifest.get("Packages")
    if not isinstance(packages, list) or not packages:
        raise DeliveryError("STABLE manifest has no referenced packages")
    for package in packages:
        if not isinstance(package, dict):
            raise DeliveryError("invalid package entry in STABLE manifest")
        name = package.get("Name")
        version = package.get("Version")
        if not isinstance(name, str) or not SAFE_NAME_RE.fullmatch(name):
            raise DeliveryError("invalid package name in STABLE manifest")
        if not isinstance(version, str) or not SAFE_NAME_RE.fullmatch(version):
            raise DeliveryError("invalid package version in STABLE manifest")
        filename = f"{name}-{version}.tgz"
        expected_sha = validate_sha256(
            package.get("Checksum"), f"manifest checksum for {filename}"
        )
        expected_size = package.get("FileSize")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise DeliveryError(f"invalid manifest size for {filename}")
        yield package, name, version, filename, expected_sha, expected_size


def manifest_validator(manifest):
    """Return (name, sha256) of the manifest's UpdateCheckProgram, or None."""
    validator = manifest.get("UpdateCheckProgram")
    if validator is None:
        return None
    if not isinstance(validator, dict):
        raise DeliveryError("invalid UpdateCheckProgram")
    name = validator.get("Name")
    if not isinstance(name, str) or not SAFE_NAME_RE.fullmatch(name):
        raise DeliveryError("invalid UpdateCheckProgram name")
    checksum = validate_sha256(validator.get("Checksum"), "UpdateCheckProgram checksum")
    return name, checksum


def manifest_build_time(manifest):
    """freenas-release writes BuildTime as a decimal string; the build writes an int."""
    value = manifest.get("BuildTime")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise DeliveryError("STABLE manifest has no usable BuildTime")
    if isinstance(value, str):
        if not re.fullmatch(r"[0-9]{1,12}", value):
            raise DeliveryError("STABLE manifest has no usable BuildTime")
        value = int(value)
    if value < 0:
        raise DeliveryError("STABLE manifest has no usable BuildTime")
    return value


def manual_update_name(version):
    return f"{version}{MANUAL_UPDATE_SUFFIX}"


def manual_update_members(root, manifest_path, manifest):
    """The exact member set a frozen-update file must carry, as (member, path, sha256, size).

    ExtractFrozenUpdate() keeps only ``./``-prefixed members with two path
    components; VerifyUpdate() then loads ``MANIFEST`` with its signature,
    runs ``ValidateUpdate`` after checking its digest against the manifest, and
    looks for each full package by digest. Deltas are not part of the file.
    """
    members = [(MANUAL_UPDATE_MANIFEST_MEMBER, manifest_path,
                sha256_file(manifest_path), manifest_path.stat().st_size)]
    validator = manifest_validator(manifest)
    if validator is not None:
        name, checksum = validator
        path = safe_regular_file(root, f"Validators/{name}")
        if sha256_file(path) != checksum:
            raise DeliveryError("UpdateCheckProgram digest does not match its validator file")
        members.append((MANUAL_UPDATE_VALIDATOR_MEMBER, path, checksum, path.stat().st_size))
    for _, _, _, filename, expected_sha, expected_size in sorted(
        manifest_package_files(manifest), key=lambda item: item[3]
    ):
        path = safe_regular_file(root, f"Packages/{filename}")
        if path.stat().st_size != expected_size or sha256_file(path) != expected_sha:
            raise DeliveryError(f"package {filename} does not match the STABLE manifest")
        members.append((f"./{filename}", path, expected_sha, expected_size))
    return members


def manual_update_sidecar_bytes(name, digest):
    return f"SHA256 ({name}) = {digest}\n".encode("ascii")


def build_manual_update(source_root, update_train=DEFAULT_UPDATE_TRAIN):
    """Write ``<Version>-manual-update.tar`` and its ``.sha256`` into the source root.

    The file is reproducible: ustar members in a fixed order, owned by root,
    mode 0644, mtime = the manifest's BuildTime. Re-running against the same
    inputs yields identical bytes; a differing file already in place is an
    error rather than something to overwrite.
    """
    root = Path(source_root).resolve(strict=True)
    update_train = validate_update_train(update_train)
    _, _, manifest_path, manifest, _, version = stable_latest_manifest(root, update_train)
    build_time = manifest_build_time(manifest)
    name = manual_update_name(version)
    tar_path = root / name
    sidecar_path = root / (name + ".sha256")
    members = manual_update_members(root, manifest_path, manifest)
    fd, temp_name = tempfile.mkstemp(prefix=name + ".", dir=root)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with tarfile.open(temp_path, "w:", format=tarfile.USTAR_FORMAT) as archive:
            top = tarfile.TarInfo("./")
            top.type = tarfile.DIRTYPE
            top.mode = 0o755
            top.mtime = build_time
            top.uname = top.gname = "root"
            archive.addfile(top)
            for member, path, _, size in members:
                info = tarfile.TarInfo(member)
                info.size = size
                info.mode = 0o644
                info.mtime = build_time
                info.uname = info.gname = "root"
                with open(path, "rb") as stream:
                    archive.addfile(info, stream)
        digest = sha256_file(temp_path)
        if tar_path.exists():
            if sha256_file(tar_path) != digest:
                raise DeliveryError(f"{name} already exists with different content")
            temp_path.unlink()
        else:
            os.chmod(temp_path, 0o644)
            temp_path.replace(tar_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    sidecar = manual_update_sidecar_bytes(name, digest)
    if sidecar_path.exists() and sidecar_path.read_bytes() != sidecar:
        raise DeliveryError(f"{name}.sha256 already exists with different content")
    sidecar_path.write_bytes(sidecar)
    return tar_path, sidecar_path


def verify_manual_update(root, tar_path, manifest_path, manifest):
    """Refuse a frozen-update file whose members are not exactly the train's."""
    expected = {member: (digest, size)
                for member, _, digest, size in manual_update_members(root, manifest_path, manifest)}
    seen = set()
    try:
        with tarfile.open(tar_path, "r:") as archive:
            for info in archive:
                if info.name in ("./", ".", "./."):
                    if not info.isdir():
                        raise DeliveryError("manual update top-level entry is not a directory")
                    continue
                if info.name not in expected:
                    raise DeliveryError(f"manual update carries an unexpected member: {info.name}")
                if info.name in seen:
                    raise DeliveryError(f"manual update repeats a member: {info.name}")
                if not info.isfile() or info.issym() or info.islnk():
                    raise DeliveryError(f"manual update member is not a regular file: {info.name}")
                if len(info.name.split("/")) != 2:
                    raise DeliveryError(f"manual update member has the wrong depth: {info.name}")
                digest, size = expected[info.name]
                if info.size != size:
                    raise DeliveryError(f"manual update member size drift: {info.name}")
                hasher = hashlib.sha256()
                with archive.extractfile(info) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        hasher.update(chunk)
                if hasher.hexdigest() != digest:
                    raise DeliveryError(f"manual update member digest drift: {info.name}")
                seen.add(info.name)
    except tarfile.TarError as error:
        raise DeliveryError("manual update is not a plain tar file") from error
    missing = sorted(set(expected) - seen)
    if missing:
        raise DeliveryError(f"manual update is missing members: {', '.join(missing)}")


def manual_update_objects(root, manifest_path, manifest, version, source_identity):
    name = manual_update_name(version)
    tar_path = safe_regular_file(root, name)
    verify_manual_update(root, tar_path, manifest_path, manifest)
    digest = sha256_file(tar_path)
    sidecar_path = safe_regular_file(root, name + ".sha256")
    if sidecar_path.read_bytes() != manual_update_sidecar_bytes(name, digest):
        raise DeliveryError(f"{name}.sha256 does not describe the staged file")
    key = f"FreeCORE/{name}"
    return [
        file_object(root, name, key, source_identity, MANUAL_UPDATE_CONTENT_TYPE,
                    IMMUTABLE_CACHE, "immutable", 10, expected_sha256=digest),
        file_object(root, name + ".sha256", key + ".sha256", source_identity,
                    "text/plain; charset=utf-8", IMMUTABLE_CACHE, "immutable", 10,
                    dependencies=[key]),
    ]


def update_plan(
    source_root,
    source_identity,
    destination_bucket,
    requested_host,
    generated_at,
    previous_state=None,
    update_train=DEFAULT_UPDATE_TRAIN,
    train_registry=None,
    train_description=None,
    iso_spec=None,
    manual_update=False,
):
    root = Path(source_root).resolve(strict=True)
    if not root.is_dir():
        raise DeliveryError("update source root is not a directory")
    validate_update_symlinks(root)
    previous = load_previous_state(previous_state, destination_bucket)
    update_train = validate_update_train(update_train)
    stable_trains = public_stable_trains(
        train_registry, update_train, selected_description=train_description
    )
    stable_train_names = {name for name, _ in stable_trains}

    train_rel, target, manifest_path, manifest, sequence, release_version = (
        stable_latest_manifest(root, update_train)
    )
    manifest_rel = f"{train_rel}/{target}"

    objects = []
    immutable_keys = []
    iso_key = None
    manual_update_key = None
    for package, name, version, filename, expected_sha, expected_size in (
        manifest_package_files(manifest)
    ):
        key = f"FreeCORE/Packages/{filename}"
        objects.append(
            file_object(
                root,
                f"Packages/{filename}",
                key,
                source_identity,
                "application/octet-stream",
                IMMUTABLE_CACHE,
                "immutable",
                10,
                expected_size=expected_size,
                expected_sha256=expected_sha,
            )
        )
        immutable_keys.append(key)

        upgrades = package.get("Upgrades", [])
        if upgrades is None:
            upgrades = []
        if not isinstance(upgrades, list):
            raise DeliveryError(f"invalid delta list for {filename}")
        for upgrade in upgrades:
            if not isinstance(upgrade, dict):
                raise DeliveryError(f"invalid delta entry for {filename}")
            old_version = upgrade.get("Version")
            if not isinstance(old_version, str) or not SAFE_NAME_RE.fullmatch(old_version):
                raise DeliveryError(f"invalid delta base version for {filename}")
            delta_name = f"{name}-{old_version}-{version}.tgz"
            delta_sha = validate_sha256(
                upgrade.get("Checksum"), f"manifest checksum for {delta_name}"
            )
            delta_size = upgrade.get("FileSize")
            if not isinstance(delta_size, int) or delta_size < 0:
                raise DeliveryError(f"invalid manifest size for {delta_name}")
            delta_key = f"FreeCORE/Packages/{delta_name}"
            objects.append(
                file_object(
                    root,
                    f"Packages/{delta_name}",
                    delta_key,
                    source_identity,
                    "application/octet-stream",
                    IMMUTABLE_CACHE,
                    "immutable",
                    10,
                    expected_size=delta_size,
                    expected_sha256=delta_sha,
                )
            )
            immutable_keys.append(delta_key)

    validator = manifest_validator(manifest)
    if validator is not None:
        name, checksum = validator
        key = f"FreeCORE/Validators/{name}"
        objects.append(
            file_object(
                root,
                f"Validators/{name}",
                key,
                source_identity,
                "text/plain; charset=utf-8",
                IMMUTABLE_CACHE,
                "immutable",
                10,
                expected_sha256=checksum,
            )
        )
        immutable_keys.append(key)

    ca_path = safe_regular_file(root, "pki/freecore-update-ca.pem")
    ca_bytes = ca_path.read_bytes()
    if b"BEGIN CERTIFICATE" not in ca_bytes or b"PRIVATE KEY" in ca_bytes:
        raise DeliveryError("update CA must contain only a public certificate")
    ca_key = "FreeCORE/pki/freecore-update-ca.pem"
    objects.append(
        file_object(
            root,
            "pki/freecore-update-ca.pem",
            ca_key,
            source_identity,
            "application/x-pem-file",
            IMMUTABLE_CACHE,
            "immutable",
            10,
        )
    )
    immutable_keys.append(ca_key)

    if iso_spec:
        iso = load_json(iso_spec, "approved ISO specification")
        required = {"key", "source_path", "size", "sha256", "url"}
        if set(iso) != required:
            raise DeliveryError("ISO specification must contain exactly key/source_path/size/sha256/url")
        if not isinstance(iso["url"], str) or not isinstance(iso["key"], str):
            raise DeliveryError("ISO URL and key must be strings")
        if not isinstance(iso["size"], int) or iso["size"] < 0:
            raise DeliveryError("ISO size is invalid")
        parsed = urllib.parse.urlparse(iso["url"])
        if (
            parsed.scheme != "https"
            or parsed.netloc != requested_host
            or parsed.path.lstrip("/") != iso["key"]
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise DeliveryError("ISO URL and key do not match the requested public host")
        validate_sha256(iso["sha256"], "approved ISO SHA-256")
        iso_key = normalize_key(iso["key"])
        objects.append(
            file_object(
                root,
                iso["source_path"],
                iso_key,
                source_identity,
                "application/octet-stream",
                IMMUTABLE_CACHE,
                "immutable",
                10,
                expected_size=iso["size"],
                expected_sha256=iso["sha256"],
            )
        )
        immutable_keys.append(iso_key)

    if manual_update:
        # The frozen-update file is derived from objects this plan already
        # carries; it is re-read here so the plan vouches for its members, not
        # for whatever build_manual_update() happened to write.
        for obj in manual_update_objects(
            root, manifest_path, manifest, release_version, source_identity
        ):
            objects.append(obj)
            immutable_keys.append(obj["key"])
        manual_update_key = f"FreeCORE/{manual_update_name(release_version)}"

    sequence_key = f"FreeCORE/{update_train}/{target}"
    objects.append(
        file_object(
            root,
            manifest_rel,
            sequence_key,
            source_identity,
            "application/json",
            IMMUTABLE_CACHE,
            "immutable",
            20,
            dependencies=immutable_keys,
        )
    )

    changelog_key = f"FreeCORE/{update_train}/ChangeLog.txt"
    objects.append(
        file_object(
            root,
            f"{update_train}/ChangeLog.txt",
            changelog_key,
            source_identity,
            "text/plain; charset=utf-8",
            NO_STORE,
            "pointer",
            30,
            dependencies=[sequence_key],
            previous_states=previous,
        )
    )
    latest_key = f"FreeCORE/{update_train}/LATEST"
    objects.append(
        file_object(
            root,
            manifest_rel,
            latest_key,
            source_identity,
            "application/json",
            NO_STORE,
            "pointer",
            40,
            dependencies=[sequence_key, changelog_key],
            previous_states=previous,
        )
    )

    redirects_path = safe_regular_file(root, "trains_redir.json")
    redirects = load_json(redirects_path, "public redirect map")
    if not isinstance(redirects, dict):
        raise DeliveryError("redirect map must be an object")
    for source_train, redirect in redirects.items():
        if "Nightlies" in source_train or not isinstance(redirect, dict):
            raise DeliveryError("redirect map is not STABLE-only")
        if redirect.get("redirect") not in stable_train_names or set(redirect) != {"redirect"}:
            raise DeliveryError("redirect map contains an unapproved destination")
    redirects_key = "FreeCORE/trains_redir.json"
    objects.append(
        file_object(
            root,
            "trains_redir.json",
            redirects_key,
            source_identity,
            "application/json",
            NO_STORE,
            "pointer",
            50,
            dependencies=[latest_key],
            previous_states=previous,
        )
    )

    trains = "".join(
        f"{name} {description}\n" for name, description in stable_trains
    ).encode("utf-8")
    trains_key = "FreeCORE/trains.txt"
    objects.append(
        inline_object(
            trains,
            "generated/trains.txt",
            trains_key,
            f"{source_identity}:{sequence}",
            "text/plain; charset=utf-8",
            NO_STORE,
            60,
            dependencies=[redirects_key],
            previous_states=previous,
        )
    )

    reject_unused_previous_states(previous, objects)

    plan = new_plan(
        "update",
        generated_at,
        source_identity,
        destination_bucket,
        requested_host,
        objects,
        {
            "train": update_train,
            "sequence": sequence,
            "latest_target": target,
            "iso_key": iso_key,
            "manual_update_key": manual_update_key,
        },
    )
    if b"Nightlies" in canonical_bytes(plan):
        raise DeliveryError("update plan is not STABLE-only")
    validate_plan(plan)
    check_update_packages(plan, root)
    return plan


def run_git(repo, *args, text=True):
    command = ["git", f"--git-dir={repo}", *args]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text)
    if result.returncode:
        error = result.stderr if text else result.stderr.decode("utf-8", "replace")
        raise DeliveryError(f"Git validation failed: {redact(error.strip())}")
    return result.stdout


def reject_tree_symlinks(root, label):
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            if path.is_symlink():
                raise DeliveryError(f"unexpected symlink in {label}: {path.relative_to(root)}")


def verify_server_info(repo):
    for relative in ("info/refs", "objects/info/packs"):
        path = repo / relative
        before = path.read_bytes() if path.is_file() else None
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "repo.git"
            shutil.copytree(repo, candidate, symlinks=True)
            run_git(candidate, "update-server-info")
            generated = candidate / relative
            after = generated.read_bytes() if generated.is_file() else None
        if before != after:
            raise DeliveryError(f"{repo.name} has stale {relative}; run git update-server-info")


def git_refs(repo):
    output = run_git(repo, "for-each-ref", "--format=%(refname) %(objectname)")
    refs = {}
    for line in output.splitlines():
        ref, revision = line.split(" ", 1)
        refs[ref] = revision
    return refs


def validate_bare_repo(root, relative, spec, label):
    repo = safe_directory(root, relative)
    reject_tree_symlinks(repo, label)
    if run_git(repo, "rev-parse", "--is-bare-repository").strip() != "true":
        raise DeliveryError(f"{label} is not a bare Git repository")
    expected_refs = spec.get("refs")
    if not isinstance(expected_refs, dict) or not expected_refs:
        raise DeliveryError(f"{label} has no reviewed refs")
    for ref, revision in expected_refs.items():
        if not re.fullmatch(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+", ref):
            raise DeliveryError(f"{label} contains an invalid ref")
        validate_git_oid(revision, f"{label} Git object ID")
    if git_refs(repo) != expected_refs:
        raise DeliveryError(f"{label} refs differ from the reviewed selection")
    head = spec.get("head")
    if head not in expected_refs:
        raise DeliveryError(f"{label} HEAD is not a reviewed ref")
    head_bytes = (repo / "HEAD").read_text(encoding="ascii")
    if head_bytes != f"ref: {head}\n":
        raise DeliveryError(f"{label} HEAD differs from the reviewed selection")
    verify_server_info(repo)
    return repo


def git_show(repo, revision, relative):
    relative = normalize_relative(relative, "Git tree path")
    return run_git(repo, "show", f"{revision}:{relative}", text=False)


def git_tree(repo, revision):
    return run_git(repo, "rev-parse", f"{revision}^{{tree}}").strip()


def git_file_kind(relative):
    if relative == "info/refs":
        return "pointer", "text/plain; charset=utf-8", NO_STORE, 2
    if relative == "HEAD" or relative == "packed-refs":
        return "pointer", "text/plain; charset=utf-8", NO_STORE, 1
    if relative == "objects/info/packs":
        return "pointer", "text/plain; charset=utf-8", NO_STORE, 1
    if relative.startswith("refs/"):
        return "pointer", "text/plain; charset=utf-8", NO_STORE, 1
    if re.fullmatch(r"objects/[0-9a-f]{2}/[0-9a-f]{38,62}", relative):
        return "immutable", "application/octet-stream", IMMUTABLE_CACHE, 0
    if re.fullmatch(r"objects/pack/pack-[0-9a-f]{40,64}\.(?:pack|idx|rev)", relative):
        return "immutable", "application/octet-stream", IMMUTABLE_CACHE, 0
    return None


def git_objects(root, repo_relative, destination_prefix, source_revision, base_phase, previous):
    repo = safe_directory(root, repo_relative)
    entries = []
    relative_files = []
    for path in sorted(repo.rglob("*")):
        if path.is_symlink():
            raise DeliveryError(f"unexpected Git symlink: {path.relative_to(repo)}")
        if path.is_file():
            relative = path.relative_to(repo).as_posix()
            if git_file_kind(relative):
                relative_files.append(relative)
    if "HEAD" not in relative_files or "info/refs" not in relative_files:
        raise DeliveryError(f"{repo_relative} lacks dumb-HTTP metadata")

    immutable_keys = [
        f"{destination_prefix}/{relative}"
        for relative in relative_files
        if git_file_kind(relative)[0] == "immutable"
    ]
    repo_keys = []
    for relative in relative_files:
        klass, content_type, cache_control, offset = git_file_kind(relative)
        key = f"{destination_prefix}/{relative}"
        dependencies = []
        if relative == "objects/info/packs":
            dependencies = [item for item in immutable_keys if "/objects/pack/" in item]
        elif klass == "pointer":
            dependencies = list(immutable_keys)
            if relative == "info/refs":
                dependencies = list(repo_keys)
        entries.append(
            file_object(
                root,
                f"{repo_relative}/{relative}",
                key,
                source_revision,
                content_type,
                cache_control,
                klass,
                base_phase + offset,
                dependencies=dependencies,
                previous_states=previous,
            )
        )
        repo_keys.append(key)
    all_repo_keys = [entry["key"] for entry in entries]
    for entry in entries:
        if entry["key"] == f"{destination_prefix}/info/refs":
            entry["dependencies"] = sorted(
                key for key in all_repo_keys if key != entry["key"]
            )
    return entries


def extract_packagesite_records(path):
    try:
        with tarfile.open(path, "r:*") as archive:
            names = archive.getnames()
            required = {"packagesite.yaml", "packagesite.yaml.sig", "packagesite.yaml.pub"}
            if not required.issubset(names):
                raise DeliveryError("packagesite.pkg is not a signed modern repository index")
            if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in names):
                raise DeliveryError("packagesite.pkg contains an unsafe member path")
            member = archive.extractfile("packagesite.yaml")
            payload = member.read() if member else b""
            signature = archive.extractfile("packagesite.yaml.sig")
            public_key = archive.extractfile("packagesite.yaml.pub")
            if not signature or not signature.read() or not public_key or not public_key.read():
                raise DeliveryError("packagesite.pkg signature material is empty")
    except (tarfile.TarError, OSError, tarfile.CompressionError):
        # Python versions predating stdlib zstd support cannot open modern
        # pkg(8) metadata.  FreeBSD bsdtar can, and this fallback still reads
        # only the three allowlisted members without extracting to disk.
        listing = subprocess.run(
            ["tar", "-tf", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if listing.returncode:
            raise DeliveryError(
                f"cannot read packagesite.pkg: {redact(listing.stderr.strip())}"
            )
        names = listing.stdout.splitlines()
        required = {"packagesite.yaml", "packagesite.yaml.sig", "packagesite.yaml.pub"}
        if not required.issubset(names):
            raise DeliveryError("packagesite.pkg is not a signed modern repository index")
        if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in names):
            raise DeliveryError("packagesite.pkg contains an unsafe member path")

        extracted = {}
        for name in sorted(required):
            result = subprocess.run(
                ["tar", "-xOf", str(path), name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode:
                raise DeliveryError(
                    f"cannot read packagesite.pkg member: {redact(result.stderr.decode('utf-8', 'replace').strip())}"
                )
            extracted[name] = result.stdout
        if not extracted["packagesite.yaml.sig"] or not extracted["packagesite.yaml.pub"]:
            raise DeliveryError("packagesite.pkg signature material is empty")
        payload = extracted["packagesite.yaml"]

    records = []
    for line in payload.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError as error:
            raise DeliveryError("packagesite.yaml contains invalid JSON") from error
        if not isinstance(record, dict):
            raise DeliveryError("packagesite.yaml contains a non-object record")
        records.append(record)
    if not records:
        raise DeliveryError("packagesite.yaml contains no package records")
    return records


def package_metadata_kind(name):
    if name in ("meta", "meta.conf"):
        return "text/plain; charset=utf-8"
    if name in ("packagesite.pkg", "packagesite.txz", "data.pkg", "data.txz"):
        return "application/octet-stream"
    if re.fullmatch(r"(?:filesite\..+|digests.*)", name):
        return "application/octet-stream"
    return None


def plugin_plan(
    source_root,
    selection_path,
    source_identity,
    destination_bucket,
    requested_host,
    generated_at,
    previous_state=None,
):
    root = Path(source_root).resolve(strict=True)
    selection = load_json(selection_path, "reviewed plugin selection")
    previous = load_previous_state(previous_state, destination_bucket)
    reject_secrets(selection, "plugin selection")

    if set(selection) != {"catalog", "artifacts", "icons", "packages"}:
        raise DeliveryError("plugin selection has missing or unexpected fields")

    catalog_spec = selection.get("catalog")
    artifacts = selection.get("artifacts")
    icons = selection.get("icons")
    package_spec = selection.get("packages")
    if not all(isinstance(value, dict) for value in (catalog_spec, artifacts, icons, package_spec)):
        raise DeliveryError("plugin selection is incomplete")
    if set(catalog_spec) != {"path", "refs", "head", "index_revision", "tree"}:
        raise DeliveryError("catalog selection schema is invalid")
    if set(package_spec) != {"abi", "path", "revision"}:
        raise DeliveryError("package selection schema is invalid")

    package_abi = package_spec.get("abi")
    if package_abi != PLUGIN_ABI:
        raise DeliveryError("only the FreeBSD 15 amd64 package surface is allowed")
    package_rel = normalize_relative(package_spec.get("path"), "package ABI path")
    reject_unexpected_symlinks(root, {f"{package_rel}/latest"})

    catalog_rel = normalize_relative(catalog_spec.get("path"), "catalog path")
    if PurePosixPath(catalog_rel).name != "iocage-freecore-plugins.git":
        raise DeliveryError("plugin selection must use the renamed FreeCORE catalog")
    catalog = validate_bare_repo(root, catalog_rel, catalog_spec, "catalog")
    index_revision = catalog_spec.get("index_revision")
    validate_git_oid(index_revision, "catalog INDEX revision")
    if index_revision not in catalog_spec["refs"].values():
        raise DeliveryError("catalog INDEX revision is not a reviewed ref")
    expected_tree = catalog_spec.get("tree")
    validate_git_oid(expected_tree, "catalog tree")
    for revision in set(catalog_spec["refs"].values()):
        if git_tree(catalog, revision) != expected_tree:
            raise DeliveryError("catalog tree differs from the reviewed selection")
    try:
        index = json.loads(git_show(catalog, index_revision, "INDEX"))
    except ValueError as error:
        raise DeliveryError("catalog INDEX is invalid JSON") from error
    if not isinstance(index, dict) or not index:
        raise DeliveryError("catalog INDEX is empty")
    if set(index) != set(artifacts) or set(index) != set(icons):
        raise DeliveryError("artifact/icon selection differs from the accepted launch INDEX")

    objects = []
    package_root = safe_directory(root, package_rel)
    revision, revision_root = recognized_symlink(
        package_root, "latest", r"\.real_[0-9]{14}"
    )
    if package_spec.get("revision") != revision:
        raise DeliveryError("package latest differs from the reviewed revision")
    reject_tree_symlinks(revision_root, "package revision")

    packagesite = revision_root / "packagesite.pkg"
    if not packagesite.is_file():
        raise DeliveryError("selected package revision lacks packagesite.pkg")
    records = extract_packagesite_records(packagesite)
    package_keys = []
    seen_package_paths = set()
    for record in records:
        record_abi = record.get("abi")
        if not isinstance(record_abi, str) or record_abi not in PLUGIN_PACKAGE_ABIS:
            raise DeliveryError(
                "packagesite contains a package outside the FreeBSD 15 "
                "amd64/noarch ABI allowlist"
            )
        if record.get("path") and record.get("repopath") and record["path"] != record["repopath"]:
            raise DeliveryError("packagesite path and repopath differ")
        relative = record.get("repopath") or record.get("path")
        relative = normalize_relative(relative, "signed package path")
        if not (relative.startswith("All/") or relative.startswith("Hashed/")):
            raise DeliveryError("signed package path is outside All/ or Hashed/")
        if relative in seen_package_paths:
            raise DeliveryError("packagesite contains duplicate package paths")
        seen_package_paths.add(relative)
        checksum = validate_sha256(record.get("sum"), f"signed package checksum for {relative}")
        size = record.get("pkgsize")
        if not isinstance(size, int) or size < 0:
            raise DeliveryError(f"invalid signed package size for {relative}")
        source_path = f"{package_rel}/{revision}/{relative}"
        key = f"plugins/pkg/{PLUGIN_ABI}/latest/{relative}"
        objects.append(
            file_object(
                root,
                source_path,
                key,
                revision,
                "application/octet-stream",
                IMMUTABLE_CACHE,
                "immutable",
                10,
                expected_size=size,
                expected_sha256=checksum,
            )
        )
        package_keys.append(key)

    metadata_keys = []
    packagesite_key = None
    for path in sorted(revision_root.iterdir()):
        if path.is_symlink() or not path.is_file():
            continue
        content_type = package_metadata_kind(path.name)
        if not content_type:
            continue
        key = f"plugins/pkg/{PLUGIN_ABI}/latest/{path.name}"
        phase = 40
        dependencies = list(package_keys)
        if path.name == "packagesite.pkg":
            dependencies += metadata_keys
            packagesite_key = key
        objects.append(
            file_object(
                root,
                f"{package_rel}/{revision}/{path.name}",
                key,
                revision,
                content_type,
                NO_STORE,
                "pointer",
                phase,
                dependencies=dependencies,
                previous_states=previous,
            )
        )
        metadata_keys.append(key)
    if packagesite_key is None:
        raise DeliveryError("packagesite.pkg was not inventoried")

    artifact_final_keys = []
    for plugin in sorted(index):
        if not SAFE_NAME_RE.fullmatch(plugin):
            raise DeliveryError("catalog contains an invalid plugin name")
        entry = index[plugin]
        if not isinstance(entry, dict):
            raise DeliveryError(f"invalid INDEX entry for {plugin}")
        manifest_name = entry.get("MANIFEST")
        if not isinstance(manifest_name, str):
            raise DeliveryError(f"INDEX entry lacks MANIFEST for {plugin}")
        try:
            manifest = json.loads(git_show(catalog, index_revision, manifest_name))
        except ValueError as error:
            raise DeliveryError(f"catalog manifest is invalid JSON for {plugin}") from error
        if not isinstance(manifest, dict):
            raise DeliveryError(f"catalog manifest is not an object for {plugin}")
        expected_artifact_url = (
            f"https://plugins.freecore.org/plugins/git/artifacts/{plugin}.git"
        )
        expected_icon_url = f"https://plugins.freecore.org/plugins/icons/{plugin}.svg"
        if manifest.get("artifact") != expected_artifact_url:
            raise DeliveryError(f"catalog artifact URL is not canonical for {plugin}")
        if entry.get("icon") != expected_icon_url:
            raise DeliveryError(f"catalog icon URL is not canonical for {plugin}")
        packagesite_url = manifest.get("packagesite")
        if packagesite_url != "https://plugins.freecore.org/plugins/pkg/${ABI}/latest":
            raise DeliveryError(f"catalog package URL is not canonical for {plugin}")

        artifact_spec = artifacts[plugin]
        if not isinstance(artifact_spec, dict) or set(artifact_spec) != {
            "path", "refs", "head", "tree", "parent",
        }:
            raise DeliveryError(f"artifact selection schema is invalid for {plugin}")
        artifact_rel = normalize_relative(artifact_spec.get("path"), "artifact path")
        if PurePosixPath(artifact_rel).name != f"{plugin}.git":
            raise DeliveryError(f"artifact repo name does not match {plugin}")
        artifact_repo = validate_bare_repo(root, artifact_rel, artifact_spec, f"{plugin} artifact")
        artifact_tree = artifact_spec.get("tree")
        validate_git_oid(artifact_tree, f"artifact tree for {plugin}")
        artifact_revisions = set(artifact_spec["refs"].values())
        if len(artifact_revisions) != 1:
            raise DeliveryError(f"artifact refs do not share one reviewed commit for {plugin}")
        artifact_revision = next(iter(artifact_revisions))
        artifact_parent = artifact_spec.get("parent")
        artifact_line = run_git(
            artifact_repo, "rev-list", "--parents", "-n", "1", artifact_revision
        ).strip().split()
        if artifact_parent is None:
            if artifact_line != [artifact_revision]:
                raise DeliveryError(f"artifact commit is not a reviewed root for {plugin}")
        else:
            validate_git_oid(artifact_parent, f"artifact parent for {plugin}")
            if artifact_line != [artifact_revision, artifact_parent]:
                raise DeliveryError(
                    f"artifact commit does not preserve the reviewed parent for {plugin}"
                )
        if artifact_tree and git_tree(artifact_repo, artifact_revision) != artifact_tree:
            raise DeliveryError(f"artifact tree differs from reviewed source for {plugin}")
        artifact_objects = git_objects(
            root,
            artifact_rel,
            f"plugins/git/artifacts/{plugin}.git",
            artifact_revision,
            20,
            previous,
        )
        objects.extend(artifact_objects)
        artifact_final_keys.append(f"plugins/git/artifacts/{plugin}.git/info/refs")

        icon_spec = icons[plugin]
        if not isinstance(icon_spec, dict) or set(icon_spec) != {"path", "sha256"}:
            raise DeliveryError(f"invalid icon selection for {plugin}")
        icon_rel = normalize_relative(icon_spec.get("path"), "icon path")
        if PurePosixPath(icon_rel).name != f"{plugin}.svg":
            raise DeliveryError(f"icon name does not match {plugin}")
        icon_sha = validate_sha256(icon_spec.get("sha256"), f"icon SHA-256 for {plugin}")
        objects.append(
            file_object(
                root,
                icon_rel,
                f"plugins/icons/{plugin}.svg",
                source_identity,
                "image/svg+xml; charset=utf-8",
                ICON_CACHE,
                "immutable",
                30,
                dependencies=artifact_final_keys,
                expected_sha256=icon_sha,
            )
        )

    catalog_objects = git_objects(
        root,
        catalog_rel,
        CATALOG_KEY,
        index_revision,
        50,
        previous,
    )
    all_prior = [obj["key"] for obj in objects]
    for obj in catalog_objects:
        if obj["key"] == f"{CATALOG_KEY}/info/refs":
            obj["phase"] = 60
            obj["dependencies"] = sorted(all_prior + [
                item["key"] for item in catalog_objects if item["key"] != obj["key"]
            ])
    objects.extend(catalog_objects)

    reject_unused_previous_states(previous, objects)

    plan = new_plan(
        "plugin",
        generated_at,
        source_identity,
        destination_bucket,
        requested_host,
        objects,
        {
            "abi": PLUGIN_ABI,
            "package_revision": revision,
            "catalog_key": CATALOG_KEY,
            "catalog_index_revision": index_revision,
            "plugins": sorted(index),
        },
    )
    validate_plan(plan)
    if plan["objects"][-1]["key"] != f"{CATALOG_KEY}/info/refs":
        raise DeliveryError("catalog info/refs is not the final visibility object")
    return plan


def object_source(obj, source_root):
    inline = obj.get("inline_base64")
    if inline is not None:
        try:
            return "bytes", base64.b64decode(inline, validate=True)
        except (TypeError, ValueError) as error:
            raise DeliveryError(f"invalid inline bytes for {obj['key']}") from error
    return "file", safe_regular_file(source_root, obj["source_path"])


def metadata_equal(head, obj):
    return (
        head is not None
        and head.get("size") == obj["size"]
        and head.get("content_type") == obj["content_type"]
        and head.get("cache_control") == obj["cache_control"]
    )


class LocalObjectStore:
    """Filesystem-backed object store used only for offline integration tests."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.metadata_root = self.root / ".freecore-r2-metadata"
        self.metadata_root.mkdir(exist_ok=True)

    def _path(self, key):
        key = normalize_key(key)
        path = self.root.joinpath(*PurePosixPath(key).parts)
        try:
            path.resolve().relative_to(self.root)
        except ValueError as error:
            raise DeliveryError("local object path escapes its root") from error
        return path

    def _metadata_path(self, key):
        return self.metadata_root / f"{sha256_bytes(key.encode('utf-8'))}.json"

    def head(self, key):
        path = self._path(key)
        metadata_path = self._metadata_path(key)
        if not path.is_file():
            return None
        if not metadata_path.is_file():
            raise DeliveryError(f"local object lacks metadata: {key}")
        metadata = load_json(metadata_path, f"local metadata for {key}")
        return {
            "size": path.stat().st_size,
            "content_type": metadata.get("content_type"),
            "cache_control": metadata.get("cache_control"),
        }

    def digest(self, key):
        path = self._path(key)
        if not path.is_file():
            raise DeliveryError(f"object not found: {key}")
        return sha256_file(path)

    def read_bytes(self, key):
        path = self._path(key)
        if not path.is_file():
            raise DeliveryError(f"object not found: {key}")
        return path.read_bytes()

    def put_file(self, key, source, content_type, cache_control):
        destination = self._path(key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
        try:
            shutil.copyfile(source, temporary_path)
            os.replace(temporary_path, destination)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
        write_json(
            self._metadata_path(key),
            {"content_type": content_type, "cache_control": cache_control},
        )

    def put_bytes(self, key, data, content_type, cache_control):
        with tempfile.NamedTemporaryFile(delete=False) as temporary:
            temporary.write(data)
            temporary_path = Path(temporary.name)
        try:
            self.put_file(key, temporary_path, content_type, cache_control)
        finally:
            temporary_path.unlink(missing_ok=True)

    def delete(self, key):
        path = self._path(key)
        if path.exists():
            path.unlink()
        metadata = self._metadata_path(key)
        if metadata.exists():
            metadata.unlink()


def redact(value):
    value = PRIVATE_VALUE_RE.sub("<redacted>", value or "")
    value = QUERY_SECRET_RE.sub(r"\1<redacted>", value)
    for name, secret in os.environ.items():
        if SENSITIVE_KEY_RE.search(name) and secret:
            value = value.replace(secret, "<redacted>")
    return value


class RcloneObjectStore:
    """R2/S3 data plane through a protected rclone configuration."""

    def __init__(self, bucket):
        configured_bucket = os.environ.get("FREECORE_R2_BUCKET")
        remote = os.environ.get("FREECORE_R2_REMOTE")
        if configured_bucket != bucket:
            raise DeliveryError("FREECORE_R2_BUCKET does not match the reviewed plan")
        if (
            not remote
            or any(char.isspace() for char in remote)
            or "://" in remote
            or "@" in remote
            or not re.fullmatch(r"[A-Za-z0-9_.-]+:[A-Za-z0-9._/-]+", remote)
        ):
            raise DeliveryError("FREECORE_R2_REMOTE must name a configured rclone bucket remote")
        if subprocess.run(["rclone", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            raise DeliveryError("rclone is unavailable")
        self.remote = remote.rstrip("/")

    def _target(self, key):
        return f"{self.remote}/{normalize_key(key)}"

    def _run(self, args, binary=False, allow_missing=False):
        result = subprocess.run(
            ["rclone", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=not binary,
        )
        if result.returncode:
            error = result.stderr if not binary else result.stderr.decode("utf-8", "replace")
            if allow_missing and re.search(r"not found|directory not found|object not found", error, re.I):
                return None
            raise DeliveryError(f"rclone failed: {redact(error.strip())}")
        return result.stdout

    def head(self, key):
        output = self._run(["lsjson", "--stat", "--metadata", self._target(key)], allow_missing=True)
        if output is None:
            return None
        try:
            value = json.loads(output)
        except ValueError as error:
            raise DeliveryError("rclone returned invalid object metadata") from error
        if not isinstance(value, dict):
            raise DeliveryError("rclone returned invalid object metadata")
        if value.get("IsDir") is True:
            return None
        metadata = {str(k).lower(): v for k, v in (value.get("Metadata") or {}).items()}
        return {
            "size": value.get("Size"),
            "content_type": metadata.get("content-type") or value.get("MimeType"),
            "cache_control": metadata.get("cache-control"),
        }

    def digest(self, key):
        process = subprocess.Popen(
            ["rclone", "cat", self._target(key)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        digest = hashlib.sha256()
        for chunk in iter(lambda: process.stdout.read(1024 * 1024), b""):
            digest.update(chunk)
        error = process.stderr.read().decode("utf-8", "replace")
        if process.wait():
            raise DeliveryError(f"rclone download failed: {redact(error.strip())}")
        return digest.hexdigest()

    def read_bytes(self, key):
        return self._run(["cat", self._target(key)], binary=True)

    def put_file(self, key, source, content_type, cache_control):
        self._run([
            "copyto",
            "--metadata",
            "--metadata-set", f"content-type={content_type}",
            "--metadata-set", f"cache-control={cache_control}",
            "--s3-upload-cutoff", "64Mi",
            "--s3-chunk-size", "64Mi",
            str(source),
            self._target(key),
        ])

    def put_bytes(self, key, data, content_type, cache_control):
        with tempfile.NamedTemporaryFile(delete=False) as temporary:
            temporary.write(data)
            temporary_path = Path(temporary.name)
        try:
            self.put_file(key, temporary_path, content_type, cache_control)
        finally:
            temporary_path.unlink(missing_ok=True)

    def delete(self, key):
        self._run(["deletefile", self._target(key)], allow_missing=True)


def state_matches(store, key, state):
    head = store.head(key)
    if not state.get("exists"):
        return head is None
    if head is None:
        return False
    expected = {
        "size": state["size"],
        "content_type": state["content_type"],
        "cache_control": state["cache_control"],
    }
    return head == expected and store.digest(key) == state["sha256"]


def target_matches(store, obj):
    head = store.head(obj["key"])
    return metadata_equal(head, obj) and store.digest(obj["key"]) == obj["sha256"]


def check_update_packages(plan, source_root):
    if plan["surface"] != "update":
        return
    packages = [obj for obj in plan["objects"] if obj["key"].startswith("FreeCORE/Packages/")]
    if not packages:
        raise DeliveryError("update plan contains no package inputs to check")
    for obj in packages:
        kind, source = object_source(obj, source_root)
        if kind != "file":
            raise DeliveryError("update package privacy checks require actual source files")
        try:
            require_checked_artifact(source, obj["sha256"], obj["size"])
        except ArtifactCheckError as error:
            raise DeliveryError(str(error)) from error


def preflight_apply(plan, source_root, store):
    # Check every package, including deltas and already-present objects, before
    # any object-store writes. A previously approved plan never skips this.
    check_update_packages(plan, source_root)
    for obj in plan["objects"]:
        kind, source = object_source(obj, source_root)
        digest = sha256_bytes(source) if kind == "bytes" else sha256_file(source)
        size = len(source) if kind == "bytes" else source.stat().st_size
        if digest != obj["sha256"] or size != obj["size"]:
            raise DeliveryError(f"source drift for {obj['key']}")
        head = store.head(obj["key"])
        if head is None:
            if obj["class"] == "pointer" and obj["previous"].get("exists"):
                raise DeliveryError(f"destination pointer pre-state drift for {obj['key']}")
            continue
        if target_matches(store, obj):
            continue
        if obj["class"] == "immutable":
            raise DeliveryError(f"conflicting immutable object: {obj['key']}")
        if not state_matches(store, obj["key"], obj["previous"]):
            raise DeliveryError(f"destination pointer pre-state drift for {obj['key']}")


def load_journal(path, plan_sha256):
    path = Path(path)
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "plan_sha256": plan_sha256, "applied": [], "completed": False}
    journal = load_json(path, "apply journal")
    if journal.get("schema_version") != SCHEMA_VERSION or journal.get("plan_sha256") != plan_sha256:
        raise DeliveryError("journal does not belong to the reviewed plan")
    if not isinstance(journal.get("applied"), list):
        raise DeliveryError("journal is invalid")
    return journal


def apply_plan(plan, source_root, store, journal_path, approved_sha256):
    validate_plan(plan, require_applyable=True)
    if approved_sha256 != plan["plan_sha256"]:
        raise DeliveryError("approved plan SHA-256 does not match")
    journal = load_journal(journal_path, approved_sha256)
    preflight_apply(plan, source_root, store)
    applied = set(journal["applied"])
    for obj in plan["objects"]:
        if target_matches(store, obj):
            applied.add(obj["key"])
        else:
            kind, source = object_source(obj, source_root)
            if kind == "bytes":
                store.put_bytes(obj["key"], source, obj["content_type"], obj["cache_control"])
            else:
                store.put_file(obj["key"], source, obj["content_type"], obj["cache_control"])
            if not target_matches(store, obj):
                raise DeliveryError(f"post-upload verification failed for {obj['key']}")
            applied.add(obj["key"])
        journal["applied"] = sorted(applied)
        write_json(journal_path, journal)
    journal["completed"] = True
    write_json(journal_path, journal)
    return journal


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def verify_public_object(base_url, obj):
    url = f"{base_url.rstrip('/')}/{urllib.parse.quote(obj['key'], safe='/:$,+~')}"
    request = urllib.request.Request(
        url, headers={"User-Agent": PUBLIC_USER_AGENT}, method="GET"
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=120) as response:
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
            if urllib.parse.urlparse(response.geturl()).hostname != urllib.parse.urlparse(base_url).hostname:
                raise DeliveryError(f"public verification redirected for {obj['key']}")
            if size != obj["size"] or digest.hexdigest() != obj["sha256"]:
                raise DeliveryError(f"public bytes differ for {obj['key']}")
            if response.headers.get("Content-Type") != obj["content_type"]:
                raise DeliveryError(f"public Content-Type differs for {obj['key']}")
            if response.headers.get("Cache-Control") != obj["cache_control"]:
                raise DeliveryError(f"public Cache-Control differs for {obj['key']}")
    except DeliveryError:
        raise
    except Exception as error:
        raise DeliveryError(f"public verification failed for {obj['key']}: {redact(str(error))}") from error


def verify_destination(plan, store, public_base_url=None):
    validate_plan(plan)
    if public_base_url:
        parsed = urllib.parse.urlparse(public_base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != plan["requested_host"]
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise DeliveryError("public base URL must be HTTPS on the requested host")
    for obj in plan["objects"]:
        if not target_matches(store, obj):
            raise DeliveryError(f"destination bytes or metadata differ for {obj['key']}")
        if public_base_url:
            verify_public_object(public_base_url, obj)
    return len(plan["objects"])


def prior_bytes(store, state):
    if "bytes_base64" in state:
        try:
            data = base64.b64decode(state["bytes_base64"], validate=True)
        except (TypeError, ValueError) as error:
            raise DeliveryError("captured rollback bytes are invalid") from error
    else:
        data = store.read_bytes(state["rollback_object"])
    if len(data) != state["size"] or sha256_bytes(data) != state["sha256"]:
        raise DeliveryError("rollback bytes differ from captured destination pre-state")
    return data


def rollback_plan(plan, store, journal_path, approved_sha256):
    validate_plan(plan, require_applyable=True)
    if approved_sha256 != plan["plan_sha256"]:
        raise DeliveryError("approved plan SHA-256 does not match")
    journal = load_journal(journal_path, approved_sha256)
    pointers = [obj for obj in plan["objects"] if obj["class"] == "pointer"]
    for obj in reversed(pointers):
        previous = obj["previous"]
        current = store.head(obj["key"])
        if state_matches(store, obj["key"], previous):
            continue
        if current is not None and not target_matches(store, obj):
            raise DeliveryError(f"destination pointer drift blocks rollback for {obj['key']}")
        if previous["exists"]:
            store.put_bytes(
                obj["key"],
                prior_bytes(store, previous),
                previous["content_type"],
                previous["cache_control"],
            )
        elif plan["surface"] == "plugin" or obj["key"] == "FreeCORE/trains.txt":
            store.delete(obj["key"])
        if previous["exists"] and not state_matches(store, obj["key"], previous):
            raise DeliveryError(f"rollback verification failed for {obj['key']}")
    journal["rolled_back"] = True
    write_json(journal_path, journal)
    return journal


def load_plan(path, surface):
    plan = load_json(path, "delivery plan")
    validate_plan(plan)
    if plan["surface"] != surface:
        raise DeliveryError("plan surface does not match the selected command")
    return plan


def add_plan_common(parser):
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--source-identity", required=True)
    parser.add_argument("--destination-bucket", required=True)
    parser.add_argument("--requested-host", required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--previous-state")
    parser.add_argument("--output", required=True)


def add_store_common(parser, journal=False, approval=False, source=False):
    parser.add_argument("--plan", required=True)
    parser.add_argument("--local-store", help="offline-test object-store root")
    if source:
        parser.add_argument("--source-root", required=True)
    if journal:
        parser.add_argument("--journal", required=True)
    if approval:
        parser.add_argument("--plan-sha256", required=True)


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    surfaces = root.add_subparsers(dest="surface", required=True)
    for surface_name in ("update", "plugin"):
        surface = surfaces.add_parser(surface_name)
        operations = surface.add_subparsers(dest="operation", required=True)
        plan = operations.add_parser("plan")
        add_plan_common(plan)
        if surface_name == "update":
            plan.add_argument("--train", default=DEFAULT_UPDATE_TRAIN)
            plan.add_argument("--train-registry", default=str(DEFAULT_TRAIN_REGISTRY))
            plan.add_argument("--train-description")
            plan.add_argument("--iso-spec")
            plan.add_argument(
                "--manual-update", action="store_true",
                help="build <Version>-manual-update.tar (+ .sha256) from the staged "
                     "train and carry both as immutable objects",
            )
        else:
            plan.add_argument("--selection", required=True)
        apply = operations.add_parser("apply")
        add_store_common(apply, journal=True, approval=True, source=True)
        verify = operations.add_parser("verify")
        add_store_common(verify)
        verify.add_argument("--public-base-url")
        rollback = operations.add_parser("rollback")
        add_store_common(rollback, journal=True, approval=True)
    return root


def selected_store(args, plan):
    if args.local_store:
        return LocalObjectStore(args.local_store)
    return RcloneObjectStore(plan["destination_bucket"])


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.operation == "plan":
            common = dict(
                source_root=args.source_root,
                source_identity=args.source_identity,
                destination_bucket=args.destination_bucket,
                requested_host=args.requested_host,
                generated_at=args.generated_at,
                previous_state=args.previous_state,
            )
            if args.surface == "update":
                if args.manual_update:
                    tar_path, _ = build_manual_update(args.source_root, args.train)
                    print(f"manual_update={tar_path.name} sha256={sha256_file(tar_path)}")
                plan = update_plan(
                    **common,
                    update_train=args.train,
                    train_registry=args.train_registry,
                    train_description=args.train_description,
                    iso_spec=args.iso_spec,
                    manual_update=args.manual_update,
                )
            else:
                plan = plugin_plan(**common, selection_path=args.selection)
            write_json(args.output, plan)
            print(f"plan_sha256={plan['plan_sha256']} objects={len(plan['objects'])}")
            return 0

        plan = load_plan(args.plan, args.surface)
        store = selected_store(args, plan)
        if args.operation == "apply":
            apply_plan(plan, args.source_root, store, args.journal, args.plan_sha256)
            print(f"applied plan_sha256={plan['plan_sha256']}")
        elif args.operation == "verify":
            count = verify_destination(plan, store, args.public_base_url)
            print(f"verified plan_sha256={plan['plan_sha256']} objects={count}")
        elif args.operation == "rollback":
            rollback_plan(plan, store, args.journal, args.plan_sha256)
            print(f"rolled_back plan_sha256={plan['plan_sha256']}")
        return 0
    except DeliveryError as error:
        print(f"error: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
