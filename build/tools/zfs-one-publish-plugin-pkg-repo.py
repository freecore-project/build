#!/usr/bin/env python3
"""
Build and publish a signed FreeCORE iocage plugin pkg repository.

The iocage plugin installer writes pkg repository configuration with
signature_type=fingerprints, so this uses pkg repo's signing_command mode.
That embeds the public key in repository metadata while keeping only the
public-key fingerprint in plugin manifests.

Signing material lives in the FreeCORE plugin PKI on the release signer; create it
with freecore-init-plugin-pki.sh. That PKI is separate from the update/ISO
PKI on purpose: pkg validates a raw public key against a sha256 fingerprint
and does no X.509 chain validation, so the update CA cannot sign for it.
"""

import argparse
import datetime as dt
import hashlib
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path


# The wave-1 plugin set. publish_latest() replaces the served repo rather than
# adding to it, so this list must stay complete: dropping a name removes it from
# the packagesite that already-installed plugin jails use for pkg upgrade.
DEFAULT_PACKAGES = [
    "plexmediaserver",
    "jellyfin",
    "nextcloud-php84",  # flavored; plain "nextcloud" is not a package
    "nginx",
    "postgresql18-server",
    "redis",
    "php84-pecl-redis",
    "sonarr",
    "radarr",
    "qbittorrent-nox",
    "tailscale",
    "syncthing",
    "transmission-daemon",
    "transmission-web",
]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--abi", default="FreeBSD:15:amd64")
    parser.add_argument("--archive", required=True)
    parser.add_argument("--package-repo", default="FreeBSD-ports")
    parser.add_argument(
        "--package-repo-url",
        help="optional package repository URL, e.g. file:///path/to/poudriere/repo",
    )
    parser.add_argument(
        "--key",
        default="/usr/local/etc/freecore-plugin-pki/private/freecore-plugin-pkg.key",
        help="private signing key; lives only on the release signer, never on the build host",
    )
    parser.add_argument(
        "--pubkey",
        default="/usr/local/etc/freecore-plugin-pki/public/freecore-plugin-pkg.pub",
    )
    parser.add_argument(
        "--osversion",
        help="explicit pkg OSVERSION; normally unnecessary, IGNORE_OSVERSION is set",
    )
    parser.add_argument("--workdir")
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument("packages", nargs="*", default=DEFAULT_PACKAGES)
    return parser.parse_args()


def run(cmd, **kwargs):
    subprocess.run(cmd, check=True, **kwargs)


def fingerprint(pubkey):
    return hashlib.sha256(Path(pubkey).read_bytes()).hexdigest()


def write_signer(path, key, pubkey):
    path.write_text(
        f"""#!/bin/sh
set -eu
read sum
[ -n "$sum" ]
echo SIGNATURE
printf '%s' "$sum" | /usr/bin/openssl dgst -sign {key} -sha256 -binary
echo
echo CERT
cat {pubkey}
echo END
""",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def write_pkg_repo_config(path, name, url):
    path.write_text(
        f"""{name}: {{
  url: "{url}",
  enabled: yes,
  signature_type: none
}}
""",
        encoding="utf-8",
    )


def pkg_command(args, workdir):
    # Force the target ABI. Otherwise pkg resolves packages for the ABI of
    # whatever host runs this script: the release signer is a FreeBSD 13 jail while the
    # published repo is FreeBSD:15:amd64, so the fetch would pull 13 packages,
    # sign them, and publish them under the 15 ABI without erroring.
    #
    # IGNORE_OSVERSION because we are MIRRORING packages, not installing them.
    # pkg otherwise refuses any catalog containing a package built against a
    # newer __FreeBSD_version than the running userland (upstream ships 1500068
    # while this jail reports 1304000), which rejects all 38k entries. Deriving
    # an OSVERSION instead is a trap: too low and every update fails, high
    # enough to pass and the check was meaningless anyway.
    cmd = ["pkg", "-o", f"ABI={args.abi}", "-o", "IGNORE_OSVERSION=yes"]
    if args.osversion:
        cmd.extend(["-o", f"OSVERSION={args.osversion}"])
    if not args.package_repo_url:
        return cmd

    repos_dir = workdir / "pkg-repos"
    dbdir = workdir / "pkg-db"
    repos_dir.mkdir()
    dbdir.mkdir()
    write_pkg_repo_config(
        repos_dir / f"{args.package_repo}.conf",
        args.package_repo,
        args.package_repo_url,
    )
    cmd.extend(["-o", f"PKG_DBDIR={dbdir}", "-R", str(repos_dir)])
    return cmd


def publish_latest(stage, archive, abi):
    abi_dir = archive / abi
    abi_dir.mkdir(parents=True, exist_ok=True)

    stamp = dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    real_name = f".real_{stamp}"
    real_path = abi_dir / real_name
    shutil.move(str(stage), str(real_path))

    tmp_link = abi_dir / ".latest.tmp"
    latest = abi_dir / "latest"
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    os.symlink(real_name, tmp_link)
    os.replace(tmp_link, latest)
    return latest


def write_xz_legacy_metadata(stage, legacy, current):
    current_path = stage / current
    legacy_path = stage / legacy
    if legacy_path.exists() or not current_path.exists():
        return

    with tempfile.TemporaryDirectory(dir=stage) as tmpdir:
        extract_dir = Path(tmpdir)
        run(["tar", "-xf", str(current_path), "-C", str(extract_dir)])

        with tarfile.open(legacy_path, "w:xz") as archive:
            for path in sorted(extract_dir.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=str(path.relative_to(extract_dir)))


def main():
    args = parse_args()
    archive = Path(args.archive)
    key = Path(args.key)
    pubkey = Path(args.pubkey)

    if not key.is_file():
        raise SystemExit(f"signing key not found: {key}")
    if not pubkey.is_file():
        raise SystemExit(f"public key not found: {pubkey}")

    work_parent = Path(args.workdir) if args.workdir else None
    tmp = tempfile.TemporaryDirectory(dir=work_parent)
    try:
        workdir = Path(tmp.name)
        stage = workdir / "repo"
        stage.mkdir()
        signer = workdir / "sign-pkg-repo.sh"
        write_signer(signer, key, pubkey)

        run([
            *pkg_command(args, workdir),
            "fetch",
            "-y",
            "-r",
            args.package_repo,
            "-d",
            "-o",
            str(stage),
            *args.packages,
        ])

        run(["pkg", "repo", str(stage), "signing_command:", str(signer)])

        # iocage still probes *.txz metadata with Python tarfile. pkg 2.x
        # writes zstd-compressed *.pkg metadata, so repack readable xz copies.
        for legacy, current in (
            ("packagesite.txz", "packagesite.pkg"),
            ("data.txz", "data.pkg"),
        ):
            write_xz_legacy_metadata(stage, legacy, current)

        latest = publish_latest(stage, archive, args.abi)
        print(f"abi={args.abi}")
        print(f"latest={latest}")
        print(f"fingerprint={fingerprint(pubkey)}")
    finally:
        if args.keep_workdir:
            print(f"workdir={tmp.name}")
            tmp._finalizer.detach()
        else:
            tmp.cleanup()


if __name__ == "__main__":
    main()
