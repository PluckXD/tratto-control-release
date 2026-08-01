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

- `schema_version: 3`;
- `artifact_kind: tratto-control-ops`;
- the approved release SHA and approval-manifest SHA-256;
- the exact migration/fleet block from the approval;
- build metadata for Linux/x86_64, exact observed Python 3.12.x, shell, and the
  canonical tree-digest algorithm.

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

## Host requirement before readiness

The current host contract accepts only API/Web and installs Operations from a
worktree in place. That is unsafe and blocks signing.

The host must ingest and validate the third archive, add the following trusted
metadata to `release.env` and `bundle.env`, and reject any mismatch:

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

Before switching or recovering a non-committed release, the host closes the
proxy and stops every readiness/reconcile timer, oneshot, and service that may
execute Operations. It then switches `current`, reloads systemd and validates
Nginx, restores the previous generation when applicable, and starts timers and
the proxy last.

See [RUNBOOK.md](RUNBOOK.md) for the exact external setup and evidence needed
before changing readiness.
