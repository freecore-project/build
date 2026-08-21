# Build FreeCORE 15.0 from public source

[FreeCORE](https://freecore.org) is an independently maintained FreeBSD/OpenZFS NAS
operating system carrying TrueNAS CORE 13.3 forward. It is not affiliated
with or endorsed by iXsystems, Inc.

This repository is the release driver for FreeCORE 15.0. Every source input is
declared with a real cloneable branch, an exact commit, and an expected Git
tree. `make checkout` verifies ordinary repositories and automatically
materializes the checksum-pinned FreeBSD and Samba release deltas. The complete
ports release source is directly cloneable from its history-free source branch.

## Build host

Run the build as `root` on an amd64 FreeBSD 15.0-RELEASE host (or a compatible
FreeBSD 15 build environment). The inherited build system's floor is 16 GiB of
memory plus swap and 80 GiB of free disk, but a clean Poudriere run benefits
substantially from additional CPU, memory, and storage.

Do not use a shallow checkout: two upstream repositories are intentionally
checked out at immutable commits behind their named public branches.

## Dependencies

```sh
pkg install -y lang/python3 lang/python ports-mgmt/poudriere-devel \
  devel/git devel/gmake archivers/pigz net/rsync
python -m ensurepip
python -m pip install six
```

The equivalent repository-owned target is:

```sh
make bootstrap-pkgs
```

## Checkout and verify every source

```sh
git clone --branch v15.0-U1.2 https://codeberg.org/freecore/build.git /usr/freecore-build
cd /usr/freecore-build
make checkout
```

Checkout fails closed if a URL, commit, delta checksum, or resulting Git tree
does not match the release manifest. On success it writes the independently
inspectable resolved inventory to:

```text
/usr/freecore-build/freenas/_BE/public-source-manifest.json
```

The authoritative expected inventory is
`build/config/freecore-release-sources.json`. The checkout needs GitHub and
Codeberg only; it does not require access to FreeCORE's private development
forge or build infrastructure.

For an offline delta cache, place the two published patch files in one
directory and set `FREECORE_RELEASE_DELTA_DIR` to that directory. Their
SHA-256 values and resulting source trees are still verified.

## Build the release

First inspect the selected environment:

```sh
make dumpenv
```

For the 15.0 release identity:

```sh
env MILESTONE=RELEASE VERSION=15.0-U1.2 \
  TRAIN=FreeCORE-15.0-STABLE make release
```

The ISO and update outputs are written below `freenas/_BE/release/`; detailed
logs are written below `freenas/_BE/objs/logs/` and to
`freenas/_BE/release.build.log`.

A source-equivalent build is the supported reproducibility claim. ISO bytes
may include timestamps and other build-environment inputs unless a separate
bit-for-bit reproducible-build result is recorded for that artifact.

## Contributions and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as
described in [SECURITY.md](SECURITY.md).

## Licence and attribution

The build framework is GPL-3.0. Component repositories retain their own
licences and copyright notices. See [NOTICE](NOTICE) and
[TRADEMARKS.md](TRADEMARKS.md).
