import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


TOOL = Path(__file__).parents[1] / "build" / "tools" / "freecore_r2_delivery.py"
SPEC = importlib.util.spec_from_file_location("freecore_r2_delivery", TOOL)
delivery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(delivery)


GENERATED_AT = "2026-08-14T08:00:00Z"
SOURCE_ID = "fixture@0123456789abcdef"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def sha256(data):
    return delivery.sha256_bytes(data)


def git(cwd, *args):
    result = subprocess.run(
        ["git", "-c", "user.name=FreeCORE Test", "-c", "user.email=test@invalid", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def add_tar_member(archive, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def write_packagesite(path, records):
    yaml = b"".join(
        (json.dumps(record, sort_keys=True) + "\n").encode()
        for record in records
    )
    with tarfile.open(path, "w:gz") as archive:
        add_tar_member(archive, "packagesite.yaml.sig", b"signature")
        add_tar_member(archive, "packagesite.yaml.pub", b"public-key")
        add_tar_member(archive, "packagesite.yaml", yaml)


class FixtureMixin:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def make_update_source(self, capture=True, prior=None):
        root = self.root / "update"
        train = root / delivery.UPDATE_TRAIN
        (root / "Packages").mkdir(parents=True)
        (root / "Validators").mkdir()
        (root / "pki").mkdir()
        train.mkdir()

        package = b"signed-package-bytes"
        delta = b"signed-delta-bytes"
        validator = b"#!/bin/sh\nexit 0\n"
        (root / "Packages" / "base-os-1.0.tgz").write_bytes(package)
        (root / "Packages" / "base-os-0.9-1.0.tgz").write_bytes(delta)
        (root / "Packages" / "unreferenced-9.9.tgz").write_bytes(b"do-not-export")
        (root / "Validators" / "ValidateUpdate").write_bytes(validator)
        (root / "pki" / "freecore-update-ca.pem").write_text(
            "-----BEGIN CERTIFICATE-----\npublic-only\n-----END CERTIFICATE-----\n",
            encoding="ascii",
        )
        sequence = "0123456789abcdef0123456789abcdef"
        manifest = {
            "Train": delivery.UPDATE_TRAIN,
            "Sequence": sequence,
            "Version": "FreeCORE-15.0-STABLE-202608140800",
            "Signature": "fixture-signature",
            "Packages": [
                {
                    "Name": "base-os",
                    "Version": "1.0",
                    "Checksum": sha256(package),
                    "FileSize": len(package),
                    "Upgrades": [
                        {
                            "Version": "0.9",
                            "Checksum": sha256(delta),
                            "FileSize": len(delta),
                        }
                    ],
                }
            ],
            "UpdateCheckProgram": {
                "Name": "ValidateUpdate",
                "Checksum": sha256(validator),
            },
        }
        target = f"FreeCORE-{sequence}"
        write_json(train / target, manifest)
        os.symlink(target, train / "LATEST")
        (train / "ChangeLog.txt").write_text("FreeCORE stable fixture\n", encoding="utf-8")
        write_json(root / "trains_redir.json", {"FreeCORE-15.0": {"redirect": delivery.UPDATE_TRAIN}})

        previous_path = None
        if capture:
            pointer_keys = [
                f"FreeCORE/{delivery.UPDATE_TRAIN}/ChangeLog.txt",
                f"FreeCORE/{delivery.UPDATE_TRAIN}/LATEST",
                "FreeCORE/trains_redir.json",
                "FreeCORE/trains.txt",
            ]
            states = {key: {"exists": False} for key in pointer_keys}
            if prior:
                states.update(prior)
            previous_path = self.root / "update-previous.json"
            write_json(
                previous_path,
                {
                    "schema_version": delivery.SCHEMA_VERSION,
                    "destination_bucket": "freecore-updates",
                    "objects": states,
                },
            )
        return root, previous_path

    def update_plan(self, capture=True, prior=None):
        root, previous = self.make_update_source(capture=capture, prior=prior)
        return root, delivery.update_plan(
            root,
            SOURCE_ID,
            "freecore-updates",
            "updates.freecore.org",
            GENERATED_AT,
            previous_state=previous,
        )

    def make_repo(self, name, files, branches, head, parent_files=None):
        work = self.root / f"{name}-work"
        bare = self.root / name
        work.mkdir()
        git(work, "init", "-q")
        parent_revision = None
        if parent_files:
            for relative, data in parent_files.items():
                path = work / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            git(work, "add", ".")
            git(work, "commit", "-q", "-m", "served fixture parent")
            parent_revision = git(work, "rev-parse", "HEAD")
        for relative, data in files.items():
            path = work / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        git(work, "add", ".")
        git(work, "commit", "-q", "-m", "fixture")
        git(work, "branch", "-M", head)
        revision = git(work, "rev-parse", "HEAD")
        for branch in branches:
            if branch != head:
                git(work, "branch", branch, revision)
        git(self.root, "clone", "-q", "--bare", str(work), str(bare))
        git(self.root, f"--git-dir={bare}", "update-server-info")
        tree = git(work, "rev-parse", "HEAD^{tree}")
        return bare, revision, tree, parent_revision

    def make_plugin_source(self, capture=False, artifact_has_parent=True):
        source = self.root / "plugin"
        source.mkdir()

        index = {
            "qbittorrent": {
                "MANIFEST": "qbittorrent.json",
                "name": "qBittorrent",
                "icon": "https://plugins.freecore.org/plugins/icons/qbittorrent.svg",
                "primary_pkg": "qbittorrent-nox",
            }
        }
        manifest = {
            "name": "qbittorrent",
            "artifact": "https://plugins.freecore.org/plugins/git/artifacts/qbittorrent.git",
            "packagesite": "https://plugins.freecore.org/plugins/pkg/${ABI}/latest",
            "pkgs": ["qbittorrent-nox"],
        }
        catalog, catalog_revision, catalog_tree, _ = self.make_repo(
            "catalog-source.git",
            {
                "INDEX": (json.dumps(index, sort_keys=True) + "\n").encode(),
                "qbittorrent.json": (json.dumps(manifest, sort_keys=True) + "\n").encode(),
            },
            ["main", "15.1-RELEASE"],
            "main",
        )
        catalog_destination = source / "catalog" / "iocage-freecore-plugins.git"
        catalog_destination.parent.mkdir()
        shutil_copytree(catalog, catalog_destination)

        artifact, artifact_revision, artifact_tree, artifact_parent = self.make_repo(
            "qbittorrent-source.git",
            {"post_install.sh": b"#!/bin/sh\nexit 0\n", "ui.json": b"{}\n"},
            ["master", "15.1-RELEASE"],
            "master",
            parent_files=(
                {
                    "post_install.sh": b"#!/bin/sh\n# retired catalog name\nexit 0\n",
                    "ui.json": b"{}\n",
                }
                if artifact_has_parent
                else None
            ),
        )
        artifact_destination = source / "artifacts" / "qbittorrent.git"
        artifact_destination.parent.mkdir()
        shutil_copytree(artifact, artifact_destination)

        icon = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>\n'
        icon_path = source / "icons" / "qbittorrent.svg"
        icon_path.parent.mkdir()
        icon_path.write_bytes(icon)

        abi_root = source / "pkg" / delivery.PLUGIN_ABI
        revision = ".real_20260814080000"
        package_root = abi_root / revision
        package_path = package_root / "All" / "Hashed" / "qbittorrent-nox-5.1.pkg"
        package_path.parent.mkdir(parents=True)
        package_bytes = b"signed-qbittorrent-package"
        package_path.write_bytes(package_bytes)
        noarch_path = package_root / "All" / "Hashed" / "transmission-web-4.1.3.pkg"
        noarch_bytes = b"signed-transmission-web-package"
        noarch_path.write_bytes(noarch_bytes)
        records = [{
            "name": "qbittorrent-nox",
            "version": "5.1",
            "abi": delivery.PLUGIN_ABI,
            "repopath": "All/Hashed/qbittorrent-nox-5.1.pkg",
            "pkgsize": len(package_bytes),
            "sum": sha256(package_bytes),
        }, {
            "name": "transmission-web",
            "version": "4.1.3",
            "abi": delivery.PLUGIN_NOARCH_ABI,
            "repopath": "All/Hashed/transmission-web-4.1.3.pkg",
            "pkgsize": len(noarch_bytes),
            "sum": sha256(noarch_bytes),
        }]
        write_packagesite(package_root / "packagesite.pkg", records)
        for name in ("meta", "meta.conf", "packagesite.txz", "data.pkg", "data.txz"):
            (package_root / name).write_bytes(f"{name}\n".encode())
        abi_root.mkdir(parents=True, exist_ok=True)
        os.symlink(revision, abi_root / "latest")

        selection = {
            "catalog": {
                "path": "catalog/iocage-freecore-plugins.git",
                "refs": {
                    "refs/heads/15.1-RELEASE": catalog_revision,
                    "refs/heads/main": catalog_revision,
                },
                "head": "refs/heads/main",
                "index_revision": catalog_revision,
                "tree": catalog_tree,
            },
            "artifacts": {
                "qbittorrent": {
                    "path": "artifacts/qbittorrent.git",
                    "refs": {
                        "refs/heads/15.1-RELEASE": artifact_revision,
                        "refs/heads/master": artifact_revision,
                    },
                    "head": "refs/heads/master",
                    "tree": artifact_tree,
                    "parent": artifact_parent,
                }
            },
            "icons": {
                "qbittorrent": {
                    "path": "icons/qbittorrent.svg",
                    "sha256": sha256(icon),
                }
            },
            "packages": {
                "abi": delivery.PLUGIN_ABI,
                "path": f"pkg/{delivery.PLUGIN_ABI}",
                "revision": revision,
            },
        }
        selection_path = self.root / "plugin-selection.json"
        write_json(selection_path, selection)

        previous_path = None
        if capture:
            first = delivery.plugin_plan(
                source,
                selection_path,
                SOURCE_ID,
                "freecore-plugins",
                "plugins.freecore.org",
                GENERATED_AT,
            )
            pointers = {
                obj["key"]: {"exists": False}
                for obj in first["objects"]
                if obj["class"] == "pointer"
            }
            previous_path = self.root / "plugin-previous.json"
            write_json(
                previous_path,
                {
                    "schema_version": delivery.SCHEMA_VERSION,
                    "destination_bucket": "freecore-plugins",
                    "objects": pointers,
                },
            )
        return source, selection_path, previous_path

    def plugin_plan(self, capture=False):
        source, selection, previous = self.make_plugin_source(capture=capture)
        plan = delivery.plugin_plan(
            source,
            selection,
            SOURCE_ID,
            "freecore-plugins",
            "plugins.freecore.org",
            GENERATED_AT,
            previous_state=previous,
        )
        return source, selection, plan


def shutil_copytree(source, destination):
    import shutil
    shutil.copytree(source, destination)


class PlanTests(FixtureMixin, unittest.TestCase):
    def test_update_plan_is_stable_only_and_pointer_last(self):
        _, plan = self.update_plan()
        keys = [obj["key"] for obj in plan["objects"]]
        rendered = json.dumps(plan)
        self.assertNotIn("Nightlies", rendered)
        self.assertNotIn("unreferenced-9.9", rendered)
        self.assertIn("base-os-0.9-1.0.tgz", rendered)
        self.assertEqual(keys[-1], "FreeCORE/trains.txt")
        self.assertEqual(plan["metadata"]["train"], delivery.UPDATE_TRAIN)
        latest = next(obj for obj in plan["objects"] if obj["key"].endswith("/LATEST"))
        sequence = next(
            obj for obj in plan["objects"]
            if obj["key"].endswith(plan["metadata"]["latest_target"])
        )
        self.assertEqual(latest["sha256"], sequence["sha256"])
        self.assertEqual(latest["cache_control"], delivery.NO_STORE)
        delivery.validate_plan(plan, require_applyable=True)

    def test_plan_hash_is_deterministic_and_detects_tampering(self):
        root, first = self.update_plan()
        previous = self.root / "update-previous.json"
        second = delivery.update_plan(
            root,
            SOURCE_ID,
            "freecore-updates",
            "updates.freecore.org",
            GENERATED_AT,
            previous_state=previous,
        )
        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        changed = copy.deepcopy(first)
        changed["objects"][0]["size"] += 1
        with self.assertRaises(delivery.DeliveryError):
            delivery.validate_plan(changed)

    def test_update_rejects_unrecognized_latest_symlink(self):
        root, previous = self.make_update_source()
        latest = root / delivery.UPDATE_TRAIN / "LATEST"
        latest.unlink()
        os.symlink("../Packages/base-os-1.0.tgz", latest)
        with self.assertRaisesRegex(delivery.DeliveryError, "source symlink|unrecognized target"):
            delivery.update_plan(
                root, SOURCE_ID, "freecore-updates", "updates.freecore.org",
                GENERATED_AT, previous_state=previous,
            )

    def test_update_rejects_an_unreferenced_symlink(self):
        root, previous = self.make_update_source()
        os.symlink("Packages/base-os-1.0.tgz", root / "unreferenced-link")
        with self.assertRaisesRegex(delivery.DeliveryError, "unexpected source symlink"):
            delivery.update_plan(
                root, SOURCE_ID, "freecore-updates", "updates.freecore.org",
                GENERATED_AT, previous_state=previous,
            )

    def test_update_ignores_a_well_formed_nightlies_pointer_in_the_archive(self):
        root, previous = self.make_update_source()
        nightly = root / "FreeCORE-15.0-Nightlies"
        nightly.mkdir()
        target = "FreeCORE-deadbeefdeadbeefdeadbeefdeadbeef"
        (nightly / target).write_text("{}\n", encoding="utf-8")
        os.symlink(target, nightly / "LATEST")
        plan = delivery.update_plan(
            root, SOURCE_ID, "freecore-updates", "updates.freecore.org",
            GENERATED_AT, previous_state=previous,
        )
        self.assertNotIn("Nightlies", json.dumps(plan))

    def test_source_path_traversal_is_rejected(self):
        with self.assertRaises(delivery.DeliveryError):
            delivery.normalize_relative("../private.key")

    def test_secret_bearing_plan_field_is_rejected(self):
        _, plan = self.update_plan()
        unsigned = copy.deepcopy(plan)
        unsigned.pop("plan_sha256")
        unsigned["api_token"] = True
        changed = delivery.seal_plan(unsigned)
        with self.assertRaisesRegex(delivery.DeliveryError, "sensitive field"):
            delivery.validate_plan(changed)

    def test_metadata_matrix_rejects_a_resealed_wrong_header(self):
        _, plan = self.update_plan()
        changed = copy.deepcopy(plan)
        changed.pop("plan_sha256")
        changed["objects"][-1]["cache_control"] = delivery.IMMUTABLE_CACHE
        changed = delivery.seal_plan(changed)
        with self.assertRaisesRegex(delivery.DeliveryError, "metadata matrix"):
            delivery.validate_plan(changed)

    def test_iso_is_absent_unless_every_reviewed_identity_is_supplied(self):
        root, previous = self.make_update_source()
        iso_bytes = b"fixture-iso-bytes"
        iso_path = root / "isos" / "FreeCORE-fixture.iso"
        iso_path.parent.mkdir()
        iso_path.write_bytes(iso_bytes)
        key = "FreeCORE/ISO/FreeCORE-fixture.iso"
        spec = self.root / "iso-spec.json"
        write_json(
            spec,
            {
                "key": key,
                "source_path": "isos/FreeCORE-fixture.iso",
                "size": len(iso_bytes),
                "sha256": sha256(iso_bytes),
                "url": f"https://updates.freecore.org/{key}",
            },
        )
        plan = delivery.update_plan(
            root, SOURCE_ID, "freecore-updates", "updates.freecore.org",
            GENERATED_AT, previous_state=previous, iso_spec=spec,
        )
        self.assertEqual(plan["metadata"]["iso_key"], key)
        self.assertEqual(next(obj for obj in plan["objects"] if obj["key"] == key)["sha256"], sha256(iso_bytes))

    def test_uncaptured_pointer_state_cannot_apply(self):
        root, plan = self.update_plan(capture=False)
        store = delivery.LocalObjectStore(self.root / "store")
        with self.assertRaisesRegex(delivery.DeliveryError, "pre-state is not captured"):
            delivery.apply_plan(
                plan, root, store, self.root / "journal.json", plan["plan_sha256"]
            )
        self.assertEqual(list((self.root / "store").rglob("trains.txt")), [])


class PluginPlanTests(FixtureMixin, unittest.TestCase):
    def test_plugin_plan_exports_only_accepted_client_surface(self):
        _, _, plan = self.plugin_plan()
        keys = [obj["key"] for obj in plan["objects"]]
        rendered = json.dumps(plan)
        self.assertEqual(keys[-1], f"{delivery.CATALOG_KEY}/info/refs")
        self.assertIn(
            f"plugins/pkg/{delivery.PLUGIN_ABI}/latest/All/Hashed/qbittorrent-nox-5.1.pkg",
            keys,
        )
        self.assertIn("plugins/icons/qbittorrent.svg", keys)
        self.assertNotIn("iocage-zfs-plugins", rendered)
        self.assertNotIn("FreeBSD:13", rendered)
        self.assertNotIn("/.real_", "\n".join(keys))
        self.assertFalse(any(key.endswith("/config") for key in keys))
        packagesite = next(
            obj for obj in plan["objects"] if obj["key"].endswith("/packagesite.pkg")
        )
        package = next(obj for obj in plan["objects"] if obj["key"].endswith(".pkg") and "/Hashed/" in obj["key"])
        self.assertEqual(packagesite["class"], "pointer")
        self.assertEqual(packagesite["cache_control"], delivery.NO_STORE)
        self.assertGreater(packagesite["phase"], package["phase"])

    def test_plugin_accepts_freebsd_15_noarch_package(self):
        _, _, plan = self.plugin_plan()
        self.assertTrue(any(
            obj["key"].endswith("/All/Hashed/transmission-web-4.1.3.pkg")
            for obj in plan["objects"]
        ))

    def test_plugin_rejects_foreign_package_abis(self):
        source, selection_path, _ = self.make_plugin_source()
        packagesite = (
            source / "pkg" / delivery.PLUGIN_ABI /
            ".real_20260814080000" / "packagesite.pkg"
        )
        records = delivery.extract_packagesite_records(packagesite)
        noarch = next(record for record in records if record["name"] == "transmission-web")
        for abi in ("FreeBSD:14:*", "FreeBSD:15:aarch64", "FreeBSD:16:*"):
            with self.subTest(abi=abi):
                noarch["abi"] = abi
                write_packagesite(packagesite, records)
                with self.assertRaisesRegex(delivery.DeliveryError, "ABI allowlist"):
                    delivery.plugin_plan(
                        source, selection_path, SOURCE_ID, "freecore-plugins",
                        "plugins.freecore.org", GENERATED_AT,
                    )

    def test_plugin_accepts_reviewed_root_artifact_commit(self):
        source, selection_path, _ = self.make_plugin_source(artifact_has_parent=False)
        selection = json.loads(selection_path.read_text())
        self.assertIsNone(selection["artifacts"]["qbittorrent"]["parent"])
        plan = delivery.plugin_plan(
            source, selection_path, SOURCE_ID, "freecore-plugins",
            "plugins.freecore.org", GENERATED_AT,
        )
        self.assertTrue(any(
            obj["key"] == "plugins/git/artifacts/qbittorrent.git/info/refs"
            for obj in plan["objects"]
        ))

    def test_plugin_rejects_nonroot_artifact_labeled_as_root(self):
        source, selection_path, _ = self.make_plugin_source()
        selection = json.loads(selection_path.read_text())
        selection["artifacts"]["qbittorrent"]["parent"] = None
        write_json(selection_path, selection)
        with self.assertRaisesRegex(delivery.DeliveryError, "not a reviewed root"):
            delivery.plugin_plan(
                source, selection_path, SOURCE_ID, "freecore-plugins",
                "plugins.freecore.org", GENERATED_AT,
            )

    def test_plugin_rejects_artifact_not_in_index(self):
        source, selection_path, _ = self.make_plugin_source()
        selection = json.loads(selection_path.read_text())
        selection["artifacts"]["sonarr"] = selection["artifacts"]["qbittorrent"]
        selection["icons"]["sonarr"] = selection["icons"]["qbittorrent"]
        write_json(selection_path, selection)
        with self.assertRaisesRegex(delivery.DeliveryError, "accepted launch INDEX"):
            delivery.plugin_plan(
                source, selection_path, SOURCE_ID, "freecore-plugins",
                "plugins.freecore.org", GENERATED_AT,
            )

    def test_plugin_rejects_wrong_package_pointer_shape(self):
        source, selection_path, _ = self.make_plugin_source()
        latest = source / "pkg" / delivery.PLUGIN_ABI / "latest"
        latest.unlink()
        os.symlink("../FreeBSD:13:amd64", latest)
        with self.assertRaisesRegex(delivery.DeliveryError, "unrecognized target"):
            delivery.plugin_plan(
                source, selection_path, SOURCE_ID, "freecore-plugins",
                "plugins.freecore.org", GENERATED_AT,
            )

    def test_plugin_rejects_stale_dumb_http_metadata(self):
        source, selection_path, _ = self.make_plugin_source()
        info_refs = source / "catalog" / "iocage-freecore-plugins.git" / "info" / "refs"
        info_refs.write_text(info_refs.read_text() + "stale\n", encoding="ascii")
        with self.assertRaisesRegex(delivery.DeliveryError, "stale info/refs"):
            delivery.plugin_plan(
                source, selection_path, SOURCE_ID, "freecore-plugins",
                "plugins.freecore.org", GENERATED_AT,
            )

    def test_plugin_rejects_package_digest_drift(self):
        source, selection_path, _ = self.make_plugin_source()
        package = (
            source / "pkg" / delivery.PLUGIN_ABI / ".real_20260814080000" /
            "All" / "Hashed" / "qbittorrent-nox-5.1.pkg"
        )
        package.write_bytes(b"tampered-package-content")
        with self.assertRaisesRegex(delivery.DeliveryError, "source (?:size|SHA-256) mismatch"):
            delivery.plugin_plan(
                source, selection_path, SOURCE_ID, "freecore-plugins",
                "plugins.freecore.org", GENERATED_AT,
            )

    def test_modern_packagesite_has_external_tar_fallback(self):
        source, _, _ = self.make_plugin_source()
        packagesite = (
            source / "pkg" / delivery.PLUGIN_ABI /
            ".real_20260814080000" / "packagesite.pkg"
        )
        with mock.patch.object(tarfile, "open", side_effect=tarfile.ReadError("no zstd")):
            records = delivery.extract_packagesite_records(packagesite)
        self.assertEqual(records[0]["name"], "qbittorrent-nox")


class RecordingStore(delivery.LocalObjectStore):
    def __init__(self, root, fail_at=None):
        super().__init__(root)
        self.puts = []
        self.fail_at = fail_at

    def put_file(self, key, source, content_type, cache_control):
        self.puts.append(key)
        if self.fail_at and len(self.puts) == self.fail_at:
            raise delivery.DeliveryError("simulated interrupted apply")
        return super().put_file(key, source, content_type, cache_control)


class DataPlaneTests(FixtureMixin, unittest.TestCase):
    def test_apply_is_idempotent_pointer_last_and_verifiable(self):
        source, plan = self.update_plan()
        store = RecordingStore(self.root / "store")
        journal = self.root / "journal.json"
        delivery.apply_plan(plan, source, store, journal, plan["plan_sha256"])
        self.assertEqual(store.puts[-1], "FreeCORE/trains.txt")
        self.assertEqual(delivery.verify_destination(plan, store), len(plan["objects"]))
        count = len(store.puts)
        delivery.apply_plan(plan, source, store, journal, plan["plan_sha256"])
        self.assertEqual(len(store.puts), count)

    def test_conflicting_immutable_fails_before_any_plan_upload(self):
        source, plan = self.update_plan()
        store = RecordingStore(self.root / "store")
        immutable = next(obj for obj in plan["objects"] if obj["class"] == "immutable")
        store.put_bytes(
            immutable["key"], b"x" * immutable["size"],
            immutable["content_type"], immutable["cache_control"],
        )
        store.puts.clear()
        with self.assertRaisesRegex(delivery.DeliveryError, "conflicting immutable"):
            delivery.apply_plan(
                plan, source, store, self.root / "journal.json", plan["plan_sha256"]
            )
        self.assertEqual(store.puts, [])
        self.assertIsNone(store.head("FreeCORE/trains.txt"))

    def test_interrupted_apply_recovers_from_journal_and_exact_objects(self):
        source, plan = self.update_plan()
        store_root = self.root / "store"
        journal = self.root / "journal.json"
        failing = RecordingStore(store_root, fail_at=3)
        with self.assertRaisesRegex(delivery.DeliveryError, "simulated interrupted"):
            delivery.apply_plan(plan, source, failing, journal, plan["plan_sha256"])
        recovered = RecordingStore(store_root)
        delivery.apply_plan(plan, source, recovered, journal, plan["plan_sha256"])
        delivery.verify_destination(plan, recovered)
        self.assertTrue(json.loads(journal.read_text())["completed"])

    def test_verify_uses_full_digest_not_etag_or_size(self):
        source, plan = self.update_plan()
        store = delivery.LocalObjectStore(self.root / "store")
        journal = self.root / "journal.json"
        delivery.apply_plan(plan, source, store, journal, plan["plan_sha256"])
        target = next(obj for obj in plan["objects"] if obj["class"] == "immutable")
        path = store._path(target["key"])
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        self.assertEqual(store.head(target["key"])["size"], target["size"])
        with self.assertRaisesRegex(delivery.DeliveryError, "destination bytes or metadata differ"):
            delivery.verify_destination(plan, store)

    def test_public_verify_uses_a_deterministic_client_identity(self):
        body = b"public fixture"
        obj = {
            "key": "plugins/example.pkg",
            "size": len(body),
            "sha256": sha256(body),
            "content_type": "application/octet-stream",
            "cache_control": delivery.IMMUTABLE_CACHE,
        }
        response = mock.MagicMock()
        response.read.side_effect = [body, b""]
        response.geturl.return_value = "https://plugins.freecore.org/plugins/example.pkg"
        response.headers = {
            "Content-Type": obj["content_type"],
            "Cache-Control": obj["cache_control"],
        }
        context = mock.MagicMock()
        context.__enter__.return_value = response
        opener = mock.Mock()
        opener.open.return_value = context
        with mock.patch.object(delivery.urllib.request, "build_opener", return_value=opener):
            delivery.verify_public_object("https://plugins.freecore.org", obj)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("User-agent"), delivery.PUBLIC_USER_AGENT)

    def test_rollback_restores_prior_pointer_and_keeps_immutable_bytes(self):
        prior_bytes = b"old stable registry\n"
        prior = {
            "FreeCORE/trains.txt": {
                "exists": True,
                "size": len(prior_bytes),
                "sha256": sha256(prior_bytes),
                "content_type": "text/plain; charset=utf-8",
                "cache_control": delivery.NO_STORE,
                "bytes_base64": base64.b64encode(prior_bytes).decode("ascii"),
            }
        }
        source, plan = self.update_plan(prior=prior)
        store = delivery.LocalObjectStore(self.root / "store")
        store.put_bytes(
            "FreeCORE/trains.txt", prior_bytes,
            "text/plain; charset=utf-8", delivery.NO_STORE,
        )
        journal = self.root / "journal.json"
        delivery.apply_plan(plan, source, store, journal, plan["plan_sha256"])
        immutable = next(obj for obj in plan["objects"] if obj["class"] == "immutable")
        delivery.rollback_plan(plan, store, journal, plan["plan_sha256"])
        self.assertEqual(store.read_bytes("FreeCORE/trains.txt"), prior_bytes)
        self.assertEqual(store.digest(immutable["key"]), immutable["sha256"])

    def test_first_update_rollback_removes_only_visibility_pointer(self):
        source, plan = self.update_plan()
        store = delivery.LocalObjectStore(self.root / "store")
        journal = self.root / "journal.json"
        delivery.apply_plan(plan, source, store, journal, plan["plan_sha256"])
        changelog_key = f"FreeCORE/{delivery.UPDATE_TRAIN}/ChangeLog.txt"
        delivery.rollback_plan(plan, store, journal, plan["plan_sha256"])
        self.assertIsNone(store.head("FreeCORE/trains.txt"))
        self.assertIsNotNone(store.head(changelog_key))

    def test_wrong_approval_hash_causes_no_mutation(self):
        source, plan = self.update_plan()
        store = delivery.LocalObjectStore(self.root / "store")
        with self.assertRaisesRegex(delivery.DeliveryError, "approved plan"):
            delivery.apply_plan(plan, source, store, self.root / "journal.json", "0" * 64)
        self.assertIsNone(store.head("FreeCORE/trains.txt"))

    def test_plugin_apply_and_reverse_pointer_rollback(self):
        source, _, plan = self.plugin_plan(capture=True)
        store = delivery.LocalObjectStore(self.root / "plugin-store")
        journal = self.root / "plugin-journal.json"
        delivery.apply_plan(plan, source, store, journal, plan["plan_sha256"])
        delivery.verify_destination(plan, store)
        visibility = f"{delivery.CATALOG_KEY}/info/refs"
        package = next(obj for obj in plan["objects"] if "/Hashed/" in obj["key"])
        delivery.rollback_plan(plan, store, journal, plan["plan_sha256"])
        self.assertIsNone(store.head(visibility))
        self.assertEqual(store.digest(package["key"]), package["sha256"])

    def test_rclone_upload_is_metadata_exact_and_multipart_capable(self):
        source = self.root / "large-object"
        source.write_bytes(b"fixture")
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        environment = {
            "FREECORE_R2_BUCKET": "freecore-plugins",
            "FREECORE_R2_REMOTE": "r2fixture:freecore-plugins",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch.object(delivery.subprocess, "run", return_value=completed) as run:
                store = delivery.RcloneObjectStore("freecore-plugins")
                store.put_file(
                    "plugins/example.pkg", source,
                    "application/octet-stream", delivery.IMMUTABLE_CACHE,
                )
        command = run.call_args_list[-1].args[0]
        self.assertIn("--s3-upload-cutoff", command)
        self.assertIn("--s3-chunk-size", command)
        self.assertIn("content-type=application/octet-stream", command)
        self.assertIn(f"cache-control={delivery.IMMUTABLE_CACHE}", command)
        self.assertFalse(any("etag" in value.lower() for value in command))

    def test_rclone_directory_shaped_stat_is_a_missing_object(self):
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        environment = {
            "FREECORE_R2_BUCKET": "freecore-plugins",
            "FREECORE_R2_REMOTE": "r2fixture:freecore-plugins",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch.object(delivery.subprocess, "run", return_value=completed):
                store = delivery.RcloneObjectStore("freecore-plugins")
        response = json.dumps({
            "Path": "",
            "Name": "",
            "Size": -1,
            "MimeType": "inode/directory",
            "IsDir": True,
            "Metadata": None,
        })
        with mock.patch.object(store, "_run", return_value=response):
            self.assertIsNone(store.head("plugins/git/artifacts/jellyfin.git/HEAD"))


class CliTests(FixtureMixin, unittest.TestCase):
    def test_no_operation_is_not_an_implicit_apply(self):
        store = self.root / "store"
        result = subprocess.run(
            [sys.executable, str(TOOL), "update"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(store.exists())

    def test_cli_plan_needs_no_destination_credential(self):
        source, previous = self.make_update_source()
        output = self.root / "plan.json"
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("FREECORE_R2_")
        }
        result = subprocess.run(
            [
                sys.executable, str(TOOL), "update", "plan",
                "--source-root", str(source),
                "--source-identity", SOURCE_ID,
                "--destination-bucket", "freecore-updates",
                "--requested-host", "updates.freecore.org",
                "--generated-at", GENERATED_AT,
                "--previous-state", str(previous),
                "--output", str(output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        self.assertIn("plan_sha256=", result.stdout)


if __name__ == "__main__":
    unittest.main()
