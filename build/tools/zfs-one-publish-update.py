#!/usr/bin/env python3
"""
Publish a signed FreeCORE update archive for updates.freecore.org.

Expected source is a build release/LATEST directory containing FreeCORE-MANIFEST
and Packages/. freenas-release performs manifest signing and archive layout.

The archive root is the product name, because the client fetches
UPDATE_SERVER = "https://updates.freecore.org/" + _os_type (freenas-pkgtools
lib/__init__.py, _os_type = "FreeCORE"). Product, archive root, the serving location blocks and the train names in
config/zfs-one-trains.json all have to agree, or the client 404s on the train
list while every individual piece still looks correct in isolation.
"""

import argparse
import datetime as dt
import os
import subprocess
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="release/LATEST directory from the build")
    parser.add_argument("--product", default="FreeCORE")
    parser.add_argument("--archive", required=True)
    parser.add_argument("--database", default="/usr/local/var/db/zfs-one-updates/FreeCORE-updates.db")
    parser.add_argument(
        "--key",
        default="/usr/local/etc/zfs-one-update-pki/private/FreeCORE-15.0-Nightlies.key",
    )
    parser.add_argument(
        "--registry",
        default=str(Path(__file__).resolve().parents[1] / "config" / "zfs-one-trains.json"),
    )
    parser.add_argument("--deltas", default="5")
    parser.add_argument("--snapshot-dataset")
    parser.add_argument("--skip-snapshots", action="store_true")
    parser.add_argument("--skip-signature-verify", action="store_true")
    return parser.parse_args()


def run(cmd):
    subprocess.run(cmd, check=True)


def snapshot(dataset, suffix):
    stamp = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    run(["zfs", "snapshot", f"{dataset}@ix-publish-{stamp}-{suffix}"])


def main():
    args = parse_args()
    source = Path(args.source)
    archive = Path(args.archive)
    db = Path(args.database)

    if not (source / f"{args.product}-MANIFEST").is_file():
        raise SystemExit(f"{source} does not contain {args.product}-MANIFEST")
    if not (source / "Packages").is_dir():
        raise SystemExit(f"{source} does not contain Packages/")
    if not Path(args.key).is_file():
        raise SystemExit(f"signing key not found: {args.key}")

    archive.mkdir(parents=True, exist_ok=True)
    db.parent.mkdir(parents=True, exist_ok=True)

    if not args.skip_snapshots and not args.snapshot_dataset:
        raise SystemExit("--snapshot-dataset is required unless --skip-snapshots is used")
    if not args.skip_snapshots:
        snapshot(args.snapshot_dataset, "before")

    run([
        "freenas-release",
        "-P", args.product,
        "-D", str(db),
        "--archive", str(archive),
        "-K", args.key,
        "--deltas", args.deltas,
        "add", str(source),
    ])

    run([
        "freenas-release",
        "-P", args.product,
        "-D", str(db),
        "--archive", str(archive),
        "check",
    ])

    registry_cmd = [
        str(Path(__file__).with_name("zfs-one-generate-trains.py")),
        "--archive", str(archive),
        "--registry", args.registry,
    ]
    if args.skip_signature_verify:
        registry_cmd.append("--skip-signature-verify")
    run(registry_cmd)

    if not args.skip_snapshots:
        snapshot(args.snapshot_dataset, "after")


if __name__ == "__main__":
    main()
