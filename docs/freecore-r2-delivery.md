# FreeCORE R2 delivery plans

`build/tools/freecore_r2_delivery.py` converts an already accepted update or
plugin handoff into a canonical object plan. It does not build or sign an
artifact, create infrastructure, choose a public ISO path, or expose a train.

The interface is deliberately two-dimensional:

```text
freecore_r2_delivery.py {update,plugin} {plan,apply,verify,rollback}
```

Both choices are mandatory. There is no default operation and no recursive
sync or delete mode.

## Safety boundary

- `plan` reads one allowlisted source root and needs no destination credential.
- `apply` and `rollback` require both the plan and its exact reviewed
  `plan_sha256`.
- Production object access is through an rclone R2/S3 remote configured in a
  protected environment/config. Credential values and endpoints are not CLI
  arguments and are never written to a plan or journal.
- `--local-store` selects the filesystem fake used by the automated tests. It
  is not a production backend.
- Existing identical immutable objects are accepted. A conflicting immutable
  key, changed pointer pre-state, source drift, metadata drift, or digest drift
  stops the operation.
- Verification always hashes a full download. An S3 multipart ETag is never a
  content digest.

The production environment supplies `FREECORE_R2_BUCKET` and
`FREECORE_R2_REMOTE`. The former must exactly match the reviewed plan. The
latter names a configured rclone bucket remote; rclone obtains any S3 endpoint
and credential from its protected configuration. Uploads use rclone's
multipart-capable S3 path.

## Canonical plan

The canonical hash covers every top-level and object field except the hash
field itself. `generated_at` is mandatory instead of being generated inside
the tool, so identical reviewed inputs produce identical plan hashes.

Every object records:

- public key and source-relative path;
- exact source revision, size, and SHA-256;
- `Content-Type` and `Cache-Control`;
- immutable/pointer class, phase, and dependencies.

Every pointer additionally records destination pre-state. A credential-free
preflight may leave a pointer as `captured: false`, but such a plan cannot be
applied. An executable plan must incorporate a separately reviewed pre-state
file with this envelope:

```json
{
  "schema_version": 1,
  "destination_bucket": "bucket-name",
  "objects": {
    "public/pointer/key": {
      "exists": false
    }
  }
}
```

For an existing pointer, the entry also supplies its size, SHA-256,
Content-Type, Cache-Control, and exactly one of inline recoverable bytes or a
protected rollback-object key. Inline prior pointer bytes are capped at 1 MiB.

`source_identity` is a public provenance identifier, not a filesystem path.
All source paths in a plan are relative to `--source-root`; private keys,
credentials, hooks, logs/reflogs, lock files, snapshots, and traversal are
rejected.

## Update surface

The source root is the accepted `FreeCORE` archive root. Planning requires:

- `FreeCORE-15.0-STABLE/LATEST` as the single recognized
  `LATEST -> FreeCORE-<Sequence>` symlink shape;
- the signed sequence manifest and only its referenced packages and update
  validator, including any explicitly referenced package deltas;
- curated `ChangeLog.txt` and reviewed stable-only redirect map;
- `pki/freecore-update-ca.pem`, containing public certificate bytes only.

The public plan is STABLE-only. It dereferences `LATEST`, generates a real
stable-only `trains.txt`, and orders immutable packages/validator/CA, sequence
manifest, ChangeLog, LATEST, redirects, then `trains.txt` last. Nightlies and
unreferenced archive objects cannot enter the plan.

An ISO is absent unless `--iso-spec` supplies exactly its reviewed public key,
HTTPS URL, source-relative path, size, and SHA-256. The tool does not derive or
invent any of them.

## Mandatory update-package privacy check

The operator environment must set `FREECORE_ARTIFACT_CHECKER` to the absolute
path of an executable private checker (or a fixed interpreter wrapper). The
checker and its policy stay in private deployment configuration, never in the
plan. Update planning checks every referenced full package and delta after
size/hash validation. Apply checks them again before any object-store writes,
including packages already present at the destination. Missing configuration,
nonzero exit, invalid output, findings, incomplete coverage, or mismatched
SHA-256/size blocks the operation. There is no skip flag.

The command protocol is `CHECKER --package ABSOLUTE_PATH --sha256 DIGEST --json`.
The private `artifact_host_gate.py` returns protocol version 1 with the exact
input digest/size, nonnegative scan counters, empty `findings` and `incomplete`
lists on success, and its scope limitation. The caller independently verifies
the file digest/size before and after checking and does not relay checker output.
Deploy the matching checker/helper versions together before using this path.
The checker performs privacy-pattern checks; passing does not certify absence
of all secrets. ISO filesystems, signatures, plugin packages, and non-package
objects are outside this hook's archive coverage.

The existing internal archive/signing publisher is a separate operation;
packages and deltas it generates are checked when selected by an update plan.
A manual exact-key transfer based on that plan must still preserve its reviewed
source bytes. `apply` provides the additional mandatory check immediately before
its writes; arbitrary direct object-store commands do not run this Python hook.

## Plugin surface

`--selection` is the reviewed bridge between an accepted catalog/package
handoff and the plan. It names:

- the bare `iocage-freecore-plugins.git` source, exact accepted refs, HEAD,
  INDEX revision, and shared tree;
- one bare artifact repository per plugin in the accepted INDEX, with exact
  refs, HEAD, commit, source tree, and either its preserved prior parent or an
  explicit null parent for a reviewed root commit;
- one accepted SVG and SHA-256 per INDEX plugin;
- the exact `FreeBSD:15:amd64` package root and selected
  `latest -> .real_<timestamp>` revision.

The planner checks each bare repository is bare, has exactly the reviewed refs
and HEAD, and already has current `git update-server-info` output. It exports
only dumb-HTTP client files: Git objects/packs, `objects/info/packs`, refs,
HEAD/packed-refs, and `info/refs`. Git configuration, hooks, logs/reflogs,
credentials, `FETCH_HEAD`, and other server files are never inventoried.

The signed modern `packagesite.pkg` supplies the exact package paths, sizes,
SHA-256 values, and per-package ABIs. Within the selected `FreeBSD:15:amd64`
repository, records may use exactly `FreeBSD:15:amd64` or the standard noarch
ABI `FreeBSD:15:*`; every other major, architecture, or wildcard is rejected.
Only those package archives are inventoried. The selected `.real_*` source is
flattened beneath literal public `latest/`; no `.real_*` name becomes a public
key. Package archives precede mutable repository metadata, and
`packagesite.pkg` follows its referenced packages and companion metadata.

Artifact repositories, accepted icons, and the package surface all precede
the renamed catalog. The canonical final visibility object is:

```text
plugins/git/iocage-freecore-plugins.git/info/refs
```

The retired catalog key, FreeBSD 13 surfaces, and authored-but-unlisted plugin
artifacts/icons fail closed.

## Apply, verify, and rollback

An apply first validates every source byte and all destination pre-state before
uploading anything. It then performs only the listed operations in phase/key
order and records an atomic local journal. Re-running the same reviewed plan is
idempotent and safely resumes an interrupted apply.

`verify` independently checks destination size, full SHA-256, Content-Type,
and Cache-Control for every object. With `--public-base-url`, it repeats the
full-byte and header checks through the exact HTTPS host in the plan and
refuses redirects to another host.

Rollback walks pointers in reverse promotion order and never deletes immutable
objects. Existing pointers are restored byte-for-byte with their captured
headers. On a first update publication with no prior safe pointer, containment
removes only `FreeCORE/trains.txt`; already staged immutable and supporting
objects remain invisible. Plugin rollback restores or removes pointer/ref
objects, beginning with the catalog visibility refs because of reverse order.

## Offline tests

Run the credential-free suite with:

```sh
python3 -m unittest -v tests.test_freecore_r2_delivery
```

The fixtures cover allowlists and traversal, the two documented symlinks,
stable-only generation, canonical hashing, metadata and phase ordering,
signed update/package metadata, dumb-HTTP bare Git repositories, exact renamed
catalog selection, idempotence, immutable conflicts, interrupted recovery,
full-download verification, rollback, and CLI non-mutation without an explicit
operation and reviewed hash.
