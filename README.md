# Tratto Control release controller

Public trust root for Tratto Control Plane release authorizations. This
repository contains reviewed release intents, canonical policy, schemas,
independent validators, and the candidate workflow. It never contains product
source, customer data, credentials, private URLs, logs, database exports, or
release binaries.

## Current state

`RELEASE_POLICY_UNAVAILABLE`

`release-readiness.json` is normative and intentionally contains unresolved
blockers. Every pre-sign job calls `scripts/policy-gate.py`; the source-free
signer has an equivalent inline refusal. Unavailable or inconsistent state
returns exit code 78. Removing a message from documentation does not enable a
release. Readiness requires a reviewed commit that clears every
machine-readable blocker and independent evidence for the external controls.

The candidate workflow is manual-only. It cannot build, verify, sign, stage, or
deploy a release in its current state.

## Trust split

- The protected public controller is the append-only authorization root.
- API, Web, and `ops/control` remain in private product repositories.
- API, Web, and Ops are produced in distinct fresh jobs without OIDC.
- The verifier uses a fresh job without product credentials or OIDC and tests
  the actual archives in isolated runtimes.
- The signer uses a fresh `control-release` environment, has OIDC only there,
  checks out no source, and receives no API/Web read credential.
- `PluckXD/tratto-control-release-carrier` is private transport only. Its
  commits, tags, releases, workflows, administrators, and asset IDs never
  authorize promotion; signed digests do.

All `uses:` references in controller workflows are pinned to a full commit
SHA. Repository-level action restrictions and SHA-pinning enforcement remain
external blockers until independently proven.

## Append-only approval

An approval under `approvals/<release_id>.json` is accepted only when it:

1. is canonical JSON, regular mode 0644, and the only file added by a
   single-parent commit on the exact remote protected `main`;
2. preserves every previous authorization byte-for-byte;
3. has a unique release ID and at least 128 bits of canonical base64url nonce;
4. expires within 24 hours and passes the bounded UTC clock check;
5. pins exact remote-main API/Operations and Web commits plus required
   ancestors;
6. requires API and Operations to use the same `tratto-api` commit;
7. pins controller workflow and policy digests from the approval commit parent;
8. pins the Control and tenant-fleet migration contract, tenant catalog digest,
   fleet preflight digest, and catalog count.

The production policy also binds the exact canonical
`policies/control-runtime-v1.json` digest. An approval cannot silently select a
different interpreter, platform, or toolchain policy.

Passing JSON Schema alone never authorizes a release. The normative contract is
the schema plus `scripts/validate-approval.py`.

## Signed envelope candidate

The next host contract is schema v5 in
`schemas/release-envelope.schema.json`. It requires three distinct carrier
assets:

- `api.tar.gz`;
- `web.tar.gz`;
- `ops.tar.gz`, built from the approved `ops/control` subtree.

The Ops block uses the same provenance fields as API/Web and binds its archive
SHA-256, size, carrier asset ID/name, component-manifest SHA-256, service-tree
digest, source tree/commit, builder job, and runner identity. `ops.commit_sha`
must equal `api.commit_sha`.

`ops.tar.gz` has `RELEASE_SHA`, `artifact-manifest.json`, and the contents of
`ops/control` at archive root. Its component manifest uses:

- `schema_version: 4`;
- `artifact_kind: tratto-control-ops`;
- the approved release SHA and approval-manifest SHA-256;
- the exact migration/fleet block from the approval;
- build metadata for Linux/x86_64, exact CPython 3.12.13, shell, and the
  canonical tree-digest algorithm;
- the exact `control-runtime-v1` policy digest shared with API and Web.

The Ops service digest uses `tratto-tree-v1`. Paths are sorted by their UTF-8
bytes. Directories are excluded from the digest but must exist with mode 0555.
Regular executables are normalized to 0555 and other regular files to 0444.
Each payload record is exactly `file\0mode4\0sha256\0path\0`, where the digest
covers the file bytes. `RELEASE_SHA` and `artifact-manifest.json` are excluded.
Symlinks, hardlinks, special files, duplicate/noncanonical paths, oversized
archives, and unsafe directory modes are rejected.

Behavioral verification uses schema 3 and binds API, Ops, and Web by exact
carrier asset ID, archive SHA-256, component-manifest SHA-256, and service
digest. It must include `ops_tree_digest_verified: true`; a report tied only to
source commits is insufficient.

The carrier remains non-authoritative in the envelope. The signer must validate
the canonical envelope and exact downloaded bytes before signing.

## Build and runtime boundary

Build provenance and runtime compatibility are separate:

- API and Ops are built with exact CPython 3.12.13. The supported host ABI is
  non-debug CPython 3.12, cache tag `cpython-312`, and SOABI
  `cpython-312-x86_64-linux-gnu`. Safe Python patch updates within 3.12 are
  allowed; a build-version field may never be rewritten to the host patch.
- Builders must observe and record their real platform. Ops rejects the build
  unless it is actually Linux x86_64 CPython 3.12.13; the isolated API and Web
  builders must provide the equivalent attested platform checks before
  readiness.
- Every Control unit uses the real, non-symlink
  `/usr/bin/python3.12`. `/usr/bin/python3` and any interpreter shipped inside
  an artifact are outside the host trust boundary.
- The host baseline is Ubuntu 24.04 x86_64 with glibc 2.39 or later. Python
  metadata is checked after dropping privileges to all six users that execute
  it: API, executor, both migrators, proxy, and Web.
- Web is built and run with exact Node v22.22.0. The system
  `/usr/bin/node` v20 is deliberately not used. The dedicated executable is
  `/opt/tratto-control/toolchains/node-v22.22.0-linux-x64/bin/node`.
- The official Node tar.xz is pinned to 30,779,824 bytes and SHA-256
  `9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37`.
  The sole installed `bin/node` is pinned to 123,405,064 bytes and SHA-256
  `1bec56ef7cfa9a76f3e0b7c0a87f220eb73f23102b9c0b4c7529a3f7c3ce7c31`.

The canonical host policy is installed as root:root 0444 at
`/etc/tratto-control/runtime-policy.json`. The normative host attestor rejects
symlinks, writable or non-traversable ancestors, hardlinks, wrong modes,
inode/metadata changes, unexpected users, and digest or ABI drift. It hashes
stable open file descriptors, then executes only metadata probes after
`setpriv`; it never executes artifact interpreters as root.

## Host requirement before readiness

The synchronized host candidate must ingest and validate the third archive, add
the following trusted metadata to `release.env` and `bundle.env`, and reject
any mismatch:

```text
OPS_SHA
OPS_ARTIFACT_SHA256
OPS_COMPONENT_MANIFEST_SHA256
OPS_SERVICE_DIGEST
```

`OPS_SHA` must equal `API_SHA`. The immutable bundle must contain `/ops`.
`/opt/tratto-control/ops` must be a stable symlink to `current/ops`; only the
single `current` symlink is switched, so API, Web, and Ops change or roll back
together. Before the first `current` exists, bootstrap/stage/recovery use their
physical validated bootstrap paths and never the intentionally unresolved Ops
convenience link. No release path may copy or overwrite active Operations
files.

The dedicated Node toolchain must be provisioned outside a release. Verify the
bounded official archive first, read only its exact regular `bin/node` member,
verify the bounded binary, and publish a new root-owned version directory
with atomic no-replace semantics. Re-running an already satisfied operation
must be idempotent only after revalidating the existing bytes and metadata.
Never install npm/corepack links or trust archive owners/modes.
Retain every toolchain needed by both current and rollback generations.

The remaining stable-controller blocker is architectural: workflow execution
must move to an immutable tagged controller SHA while approvals move to a
separately protected append-only public ledger. The signer must revalidate that
ledger and all external controls after environment approval and immediately
before OIDC signing. Until that follow-up contract and the runtime
provisioning/attestation evidence exist, readiness stays unavailable.

Before switching or recovering a non-committed release, the host closes the
proxy and stops every readiness/reconcile timer, oneshot, and service that may
execute Operations. It then switches `current`, reloads systemd and validates
Nginx, restores the previous generation when applicable, and starts timers and
the proxy last.

See [RUNBOOK.md](RUNBOOK.md) for the exact external setup and evidence needed
before changing readiness.
