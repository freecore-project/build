#!/usr/bin/env python3
"""
Generate FreeCORE train metadata from a small registry.

Only trains with an existing, signature-verified LATEST manifest are written
to trains.txt. This keeps partially staged trains invisible to clients.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument(
        "--registry",
        default=str(Path(__file__).resolve().parents[1] / "config" / "zfs-one-trains.json"),
    )
    parser.add_argument("--skip-signature-verify", action="store_true")
    return parser.parse_args()


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_manifest(path, skip_signature_verify=False):
    if skip_signature_verify:
        return True

    result = subprocess.run(
        ["manifest_util", "-M", str(path), "verify"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return False
    return True


def atomic_write(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


def main():
    args = parse_args()
    archive = Path(args.archive)

    with open(args.registry, "r", encoding="utf-8") as f:
        registry = json.load(f)

    visible_trains = []
    for entry in registry.get("trains", []):
        train = entry["name"]
        latest = archive / train / "LATEST"
        if not latest.is_file():
            continue
        try:
            manifest = load_manifest(latest)
        except Exception as e:
            print(f"Skipping {train}: cannot parse {latest}: {e}", file=sys.stderr)
            continue
        if manifest.get("Train") != train:
            print(f"Skipping {train}: LATEST manifest train mismatch", file=sys.stderr)
            continue
        if not manifest.get("Signature"):
            print(f"Skipping {train}: LATEST manifest is unsigned", file=sys.stderr)
            continue
        if not verify_manifest(latest, args.skip_signature_verify):
            print(f"Skipping {train}: LATEST signature verification failed", file=sys.stderr)
            continue
        visible_trains.append(entry)

    trains_txt = "".join(f"{t['name']} {t['description']}\n" for t in visible_trains)
    redirects = {
        src: {"redirect": dst}
        for src, dst in registry.get("redirects", {}).items()
        if any(t["name"] == dst for t in visible_trains)
    }

    archive.mkdir(parents=True, exist_ok=True)
    atomic_write(archive / "trains.txt", trains_txt)
    atomic_write(archive / "trains_redir.json", json.dumps(redirects, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
