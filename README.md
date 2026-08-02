# Tratto Control release controller

Public trust root for Tratto Control Plane release authorizations. This
repository contains reviewed release intents, canonical policy, schemas,
independent validators, and the candidate workflow. It never contains product
source, customer data, credentials, private URLs, logs, database exports, or
release binaries.

## Current state

`RELEASE_POLICY_UNAVAILABLE`

Both `release-readiness.json` (the legacy v1/v5 candidate) and
`release-readiness-v2.json` (the v2/v6 candidate) are intentionally
unavailable. Unavailable or inconsistent state returns exit code 78. Removing
a message from documentation does not enable a release. Readiness requires a
reviewed commit that clears every machine-readable blocker and independent
evidence for the external controls.

The workflow currently installed under `.github/workflows` remains
manual-only and fail-closed. `workflow-v6-shape.yml` is deliberately outside
that directory: it is a review artifact, not an executable workflow. Neither
candidate can currently build, verify, sign, stage, or deploy a release.

## Initial one-shot bootstrap

The permanent multi-review release controller remains unavailable. The first
Control Plane generation may instead use the narrowly scoped
`single-operator-bootstrap` path exactly once:

- the private carrier workflow must be
  `.github/workflows/control-bootstrap-v1.yml` on its exact `main` commit,
  with its complete LF/UTF-8 bytes matching the controller's compile-time
  SHA-256;
- a canonical approval pins the final API/Ops, Web, and reviewed public
  controller commits, runtime policy, migrations, and fleet preflight;
- isolated jobs build and test API, Ops, and Web, while a checkout-free job
  signs the canonical bootstrap schema-v6 envelope, the exact Ops archive,
  and the reviewed bootstrap-source helper separately with GitHub OIDC and
  Cosign;
- the host independently verifies the signature identity, envelope, approval,
  behavioral report, helper origin, artifact IDs and bytes before staging;
- the helper runs only from the root-owned incoming directory under the
  inherited deploy lock. It installs the signed Ops archive through an
  append-only recovery journal and atomic exchange, retains the old source,
  and then invokes the newly installed fixed publisher under the same lock;
- bootstrap is accepted only while both `current` and the root-owned
  consumption marker are absent, with every Control runtime unit stopped;
- successful validation creates the no-overwrite consumption marker before
  any activation. Replays, a second generation, or the normal release path
  remain fail-closed.

This exception establishes the initial immutable runtime only. It does not
change either readiness document, enable the permanent candidate, authorize a
carrier commit, or weaken the separate runtime, database, egress, and edge
controls. The bootstrap workflow, temporary repository credentials, and its
signing environment must be disabled or removed after the single successful
run.

The signed carrier output adds
`install-bootstrap-source-kit.py`,
`bootstrap-source-kit.sigstore.json`, and the canonical helper-origin
receipt to the existing attestation, Ops archive, and their separate bundles.
The receipt is canonical JSON with exactly `controller_sha`, `name`, `sha256`,
and `size_bytes`; the identical object is embedded as the signed
`bootstrap_source_helper` envelope block. Transfer those seven files as
`root:root 0400` into the root-only
`/var/lib/tratto-control/incoming`.

Directly invoking the helper pathname is forbidden. Before this ceremony,
populate the four `EXPECTED_*` values from authenticated evidence outside the
incoming directory; in particular, do not derive them from the files about to
be consumed. The ceremony opens the fixed helper once, binds that descriptor
back to the root-owned pathname, verifies the expected digest and the Cosign
identity against that same descriptor, and only then gives a duplicate of the
descriptor to the pre-existing immutable lock wrapper as standard input:

```bash
/usr/bin/env -i \
  HOME=/nonexistent \
  LANG=C \
  LC_ALL=C \
  NO_COLOR=1 \
  PATH=/usr/bin:/bin \
  XDG_CACHE_HOME=/var/cache/tratto-control/cosign \
  EXPECTED_HELPER_SHA256="$EXPECTED_HELPER_SHA256" \
  EXPECTED_ATTESTATION_SHA256="$EXPECTED_ATTESTATION_SHA256" \
  EXPECTED_CARRIER_SHA="$EXPECTED_CARRIER_SHA" \
  EXPECTED_CONTROLLER_SHA="$EXPECTED_CONTROLLER_SHA" \
  EXPECTED_PREDECESSOR_KIT_ID="${EXPECTED_PREDECESSOR_KIT_ID:-}" \
  EXPECTED_PREDECESSOR_CONTROLLER_SHA="${EXPECTED_PREDECESSOR_CONTROLLER_SHA:-}" \
  EXPECTED_PREDECESSOR_PUBLISHER_INTENT_SHA256="${EXPECTED_PREDECESSOR_PUBLISHER_INTENT_SHA256:-}" \
  /usr/bin/bash --noprofile --norc <<'TRATTO_BOOTSTRAP'
set -Eeuo pipefail
: "${EXPECTED_HELPER_SHA256:?authenticated helper SHA-256 required}"
: "${EXPECTED_ATTESTATION_SHA256:?authenticated attestation SHA-256 required}"
: "${EXPECTED_CARRIER_SHA:?authenticated carrier commit required}"
: "${EXPECTED_CONTROLLER_SHA:?reviewed controller commit required}"
[[ "$EXPECTED_HELPER_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ "$EXPECTED_ATTESTATION_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ "$EXPECTED_CARRIER_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$EXPECTED_CONTROLLER_SHA" =~ ^[0-9a-f]{40}$ ]]
predecessor_args=()
if [[ -n "$EXPECTED_PREDECESSOR_KIT_ID" ||
      -n "$EXPECTED_PREDECESSOR_CONTROLLER_SHA" ||
      -n "$EXPECTED_PREDECESSOR_PUBLISHER_INTENT_SHA256" ]]; then
  [[ "$EXPECTED_PREDECESSOR_KIT_ID" =~ ^[0-9a-f]{64}$ ]]
  [[ "$EXPECTED_PREDECESSOR_CONTROLLER_SHA" =~ ^[0-9a-f]{40}$ ]]
  [[ "$EXPECTED_PREDECESSOR_PUBLISHER_INTENT_SHA256" =~ ^[0-9a-f]{64}$ ]]
  predecessor_args=(
    --expected-predecessor-kit-id "$EXPECTED_PREDECESSOR_KIT_ID"
    --expected-predecessor-controller-sha \
      "$EXPECTED_PREDECESSOR_CONTROLLER_SHA"
    --expected-predecessor-publisher-intent-sha256 \
      "$EXPECTED_PREDECESSOR_PUBLISHER_INTENT_SHA256"
  )
fi

incoming=/var/lib/tratto-control/incoming
helper="$incoming/install-bootstrap-source-kit.py"
helper_bundle="$incoming/bootstrap-source-kit.sigstore.json"
/usr/bin/test ! -L "$helper"
exec {helper_fd}<"$helper"
/usr/bin/test ! -L "$helper"
helper_fd_path="/proc/self/fd/$helper_fd"
/usr/bin/test "$(
  /usr/bin/stat -Lc '%F:%a:%u:%g:%h' "$helper_fd_path"
)" = \
  "regular file:400:0:0:1"
helper_size="$(/usr/bin/stat -Lc '%s' "$helper_fd_path")"
/usr/bin/test "$helper_size" -gt 0
/usr/bin/test "$helper_size" -le 2097152
/usr/bin/test "$(
  /usr/bin/stat -Lc \
    '%d:%i:%f:%h:%u:%g:%s' "$helper_fd_path"
)" = "$(
  /usr/bin/stat -Lc '%d:%i:%f:%h:%u:%g:%s' "$helper"
)"
/usr/bin/test "$(
  /usr/bin/sha256sum "$helper_fd_path" \
    | /usr/bin/awk '{print $1}'
)" = \
  "$EXPECTED_HELPER_SHA256"

/usr/local/bin/cosign verify-blob \
  --bundle "$helper_bundle" \
  --certificate-identity \
    "https://github.com/PluckXD/tratto-control-release-carrier/.github/workflows/control-bootstrap-v1.yml@refs/heads/main" \
  --certificate-oidc-issuer \
    https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha "$EXPECTED_CARRIER_SHA" \
  --certificate-github-workflow-ref refs/heads/main \
  --certificate-github-workflow-repository \
    PluckXD/tratto-control-release-carrier \
  --certificate-github-workflow-trigger workflow_dispatch \
  "$helper_fd_path"

/usr/bin/python3.12 -I -B \
  /opt/tratto-control/bootstrap/scripts/with-deploy-lock.py -- \
  /usr/bin/python3.12 -I -B /proc/self/fd/0 \
    --helper-fd 0 \
    --expected-helper-sha256 "$EXPECTED_HELPER_SHA256" \
    --expected-attestation-sha256 "$EXPECTED_ATTESTATION_SHA256" \
    --expected-carrier-sha "$EXPECTED_CARRIER_SHA" \
    --expected-controller-sha "$EXPECTED_CONTROLLER_SHA" \
    "${predecessor_args[@]}" \
  <&"$helper_fd"
exec {helper_fd}<&-
TRATTO_BOOTSTRAP
```

The helper reopens the fixed pathname with no-follow semantics, requires it to
be the same inode and metadata as descriptor 0, rechecks all four external
bindings, validates the signed helper block and every archive byte, and
verifies all three separate blob signatures before it writes state or executes
installed Operations. The helper-origin receipt is retained as release
evidence; it is not an independent host trust root.

The three predecessor bindings are normally empty. They may be supplied only
to recover the exact authenticated state in which a previous source kit
completed source exchange and retention but its bootstrap publisher failed
before exchange. The successor approval must list the predecessor API commit
in both API and Ops `required_ancestors`. The externally authenticated kit ID,
controller SHA, and canonical publisher-intent SHA-256 must all match. The
helper then records an append-only predecessor-to-successor authorization,
archives the predecessor records and candidate by no-overwrite renames, and
passes a bounded one-use authorization to the publisher over an inherited
read-only pipe. A used predecessor, a post-exchange publisher, missing rollback
evidence, mixed digests, partial records, or any different successor remains
fail-closed.

### One-use post-publisher/pre-stage recovery

One additional bridge exists for a narrower terminal state: the source kit
and bootstrap publisher both completed and wrote their exact `used` records,
but runtime staging never began because the newly published lock wrapper
cannot classify the installed systemd fleet. This is not a second bootstrap
authorization and cannot recover a host after stage or activation.

Every attempt requires:

- six values authenticated outside `incoming`: predecessor source kit ID,
  predecessor controller SHA, SHA-256 of the canonical source `intent` and
  `used` records, and SHA-256 of the canonical publisher `intent` and `used`
  records;
- the predecessor API commit in both signed successor `required_ancestors`
  lists, a different signed successor kit/tree, the exact immutable source,
  source rollback, published bootstrap, and publisher rollback;
- no `current`, bundles, bootstrap-release, release-state, activation,
  activation-epoch, or bootstrap-consumption marker;
- a corrected quiescence verifier from the newly signed Ops archive, copied
  only to a sealed anonymous Linux `memfd`, plus a canonical catalog in a
  separate sealed read-only `memfd`. The catalog has the exact unit names and
  `0444` modes required by the signed successor inventory, but hashes the
  corresponding files in the currently published, journal-authenticated
  `/opt/tratto-control/bootstrap/systemd` tree. Under the same deploy lock,
  the helper runs the verifier through `/proc/self/fd` first with
  `--sealed-packaged-unit-catalog-pre-reload-fd`, then executes the fixed
  `/usr/bin/systemctl --no-ask-password daemon-reload`, and finally runs the
  same verifier and catalog with
  `--sealed-packaged-unit-catalog-fd`. Both verifier processes inherit that
  same lock descriptor. Each proof also snapshots the system manager's
  authoritative `UnitPath` twice and rejects applicable drop-ins, aliases,
  dependency directories, generated/transient duplicates, and load-path
  drift for every signed unit, including templates with no runtime instance.

The currently published lock wrapper is deliberately not part of this
bridge. The separately signed and already Cosign-verified helper acquires the
fixed root-owned `/run/tratto-control/deploy.lock` itself with a non-blocking
exclusive `flock`, retains that descriptor for its entire execution, and
passes the same valid lock to the successor publisher. The signed helper
forks a guardian for the pre-verifier, `daemon-reload`, and final verifier;
the guardian inherits the same open-file-description lock, so a `SIGKILL` of
the main helper cannot expose an unlocked reload window. The lock becomes
available only after the guardian terminates. Normal installs and
pre-publisher recovery continue to require the inherited lock wrapper.

Populate the ten values below only from authenticated evidence outside the
seven transferred files. The ceremony repeats the same descriptor identity,
metadata, digest, and Cosign checks as the normal path, then invokes the
helper FD directly with the complete post-publisher binding group:

```bash
/usr/bin/env -i \
  HOME=/nonexistent \
  LANG=C \
  LC_ALL=C \
  NO_COLOR=1 \
  PATH=/usr/bin:/bin \
  XDG_CACHE_HOME=/var/cache/tratto-control/cosign \
  EXPECTED_HELPER_SHA256="$EXPECTED_HELPER_SHA256" \
  EXPECTED_ATTESTATION_SHA256="$EXPECTED_ATTESTATION_SHA256" \
  EXPECTED_CARRIER_SHA="$EXPECTED_CARRIER_SHA" \
  EXPECTED_CONTROLLER_SHA="$EXPECTED_CONTROLLER_SHA" \
  EXPECTED_POST_PUBLISHER_PREDECESSOR_KIT_ID="$EXPECTED_POST_PUBLISHER_PREDECESSOR_KIT_ID" \
  EXPECTED_POST_PUBLISHER_PREDECESSOR_CONTROLLER_SHA="$EXPECTED_POST_PUBLISHER_PREDECESSOR_CONTROLLER_SHA" \
  EXPECTED_POST_PUBLISHER_SOURCE_INTENT_SHA256="$EXPECTED_POST_PUBLISHER_SOURCE_INTENT_SHA256" \
  EXPECTED_POST_PUBLISHER_SOURCE_USED_SHA256="$EXPECTED_POST_PUBLISHER_SOURCE_USED_SHA256" \
  EXPECTED_POST_PUBLISHER_PUBLISHER_INTENT_SHA256="$EXPECTED_POST_PUBLISHER_PUBLISHER_INTENT_SHA256" \
  EXPECTED_POST_PUBLISHER_PUBLISHER_USED_SHA256="$EXPECTED_POST_PUBLISHER_PUBLISHER_USED_SHA256" \
  /usr/bin/bash --noprofile --norc <<'TRATTO_POST_PUBLISHER'
set -Eeuo pipefail
for value in \
  EXPECTED_HELPER_SHA256 \
  EXPECTED_ATTESTATION_SHA256 \
  EXPECTED_POST_PUBLISHER_PREDECESSOR_KIT_ID \
  EXPECTED_POST_PUBLISHER_SOURCE_INTENT_SHA256 \
  EXPECTED_POST_PUBLISHER_SOURCE_USED_SHA256 \
  EXPECTED_POST_PUBLISHER_PUBLISHER_INTENT_SHA256 \
  EXPECTED_POST_PUBLISHER_PUBLISHER_USED_SHA256
do
  [[ "${!value}" =~ ^[0-9a-f]{64}$ ]]
done
for value in \
  EXPECTED_CARRIER_SHA \
  EXPECTED_CONTROLLER_SHA \
  EXPECTED_POST_PUBLISHER_PREDECESSOR_CONTROLLER_SHA
do
  [[ "${!value}" =~ ^[0-9a-f]{40}$ ]]
done

incoming=/var/lib/tratto-control/incoming
helper="$incoming/install-bootstrap-source-kit.py"
helper_bundle="$incoming/bootstrap-source-kit.sigstore.json"
/usr/bin/test ! -L "$helper"
exec {helper_fd}<"$helper"
/usr/bin/test ! -L "$helper"
helper_fd_path="/proc/self/fd/$helper_fd"
/usr/bin/test "$(
  /usr/bin/stat -Lc '%F:%a:%u:%g:%h' "$helper_fd_path"
)" = "regular file:400:0:0:1"
/usr/bin/test "$(
  /usr/bin/stat -Lc '%d:%i:%f:%h:%u:%g:%s' "$helper_fd_path"
)" = "$(
  /usr/bin/stat -Lc '%d:%i:%f:%h:%u:%g:%s' "$helper"
)"
/usr/bin/test "$(
  /usr/bin/sha256sum "$helper_fd_path" | /usr/bin/awk '{print $1}'
)" = "$EXPECTED_HELPER_SHA256"

/usr/local/bin/cosign verify-blob \
  --bundle "$helper_bundle" \
  --certificate-identity \
    "https://github.com/PluckXD/tratto-control-release-carrier/.github/workflows/control-bootstrap-v1.yml@refs/heads/main" \
  --certificate-oidc-issuer \
    https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha "$EXPECTED_CARRIER_SHA" \
  --certificate-github-workflow-ref refs/heads/main \
  --certificate-github-workflow-repository \
    PluckXD/tratto-control-release-carrier \
  --certificate-github-workflow-trigger workflow_dispatch \
  "$helper_fd_path"

/usr/bin/python3.12 -I -B "$helper_fd_path" \
  --helper-fd "$helper_fd" \
  --expected-helper-sha256 "$EXPECTED_HELPER_SHA256" \
  --expected-attestation-sha256 "$EXPECTED_ATTESTATION_SHA256" \
  --expected-carrier-sha "$EXPECTED_CARRIER_SHA" \
  --expected-controller-sha "$EXPECTED_CONTROLLER_SHA" \
  --expected-post-publisher-predecessor-kit-id \
    "$EXPECTED_POST_PUBLISHER_PREDECESSOR_KIT_ID" \
  --expected-post-publisher-predecessor-controller-sha \
    "$EXPECTED_POST_PUBLISHER_PREDECESSOR_CONTROLLER_SHA" \
  --expected-post-publisher-source-intent-sha256 \
    "$EXPECTED_POST_PUBLISHER_SOURCE_INTENT_SHA256" \
  --expected-post-publisher-source-used-sha256 \
    "$EXPECTED_POST_PUBLISHER_SOURCE_USED_SHA256" \
  --expected-post-publisher-publisher-intent-sha256 \
    "$EXPECTED_POST_PUBLISHER_PUBLISHER_INTENT_SHA256" \
  --expected-post-publisher-publisher-used-sha256 \
    "$EXPECTED_POST_PUBLISHER_PUBLISHER_USED_SHA256"
exec {helper_fd}<&-
TRATTO_POST_PUBLISHER
```

Before its first rename, the helper writes a canonical append-only
post-publisher authorization binding that exact predecessor to that exact
successor. It archives predecessor source `used`, publisher `used`, publisher
`intent`, and publisher rollback by no-overwrite renames. The existing
source-supersede transaction archives the remaining source records and
performs the source exchange. The publisher receives no pre-exchange
override: it starts a new ordinary upgrade only after the terminal
predecessor evidence is outside its reserved namespace.

The authorization journal remains schema v1 for a flat terminal predecessor.
When that predecessor already contains one complete source/publisher
supersede, the helper writes schema v2 and binds the SHA-256 of both canonical
nested supersede records. Before mutation it proves the nested source
predecessor phases and rollback, cross-binds the publisher supersede to that
source succession, and verifies the retained publisher intent name/hash and
candidate name/digest/modes. It then preserves that history, in a fixed
prefix order, under deterministic
`.bootstrap-post-publisher.nested-*` names using only no-overwrite renames.
The new standard source supersede cannot begin until the prelude has archived
current source `used`, the current publisher terminal evidence, and every
nested-history entry.

Every archive boundary is retryable with the same ten values and signed
inputs. Replay revalidates the journal bindings, the exact namespace, and the
completed archival prefix before continuing idempotently. Except for the
separately validated current `bootstrap-source-kit.supersede.json`, an
archived historical name may never coexist with any active entry, even one
with different bytes. Coexistence, tamper, missing or extra evidence,
out-of-order history, a non-prefix partial record, a different successor,
mixed `used` evidence, unknown journal, occupied deploy lock, failed or
inconclusive quiescence proof, staged bundle, marker, or replay after stage is
rejected before further mutation and without a cleanup bypass. Never delete,
edit, or manually move these journals.

## Stable controller v2 / envelope v6

The v2/v6 candidate separates stable release authority from product source and
from the untrusted artifact carrier:

- `policies/control-production-v2.json` is validated only against
  compile-time audited pins; its production pins are deliberately empty;
- approval schema v2 binds an immutable signed controller tag/release, the
  exact workflow and signer-verifier bytes, and one entry in a separate
  protected append-only ledger;
- `scripts/validate-ledger.py` replays the full linear ledger instead of
  trusting a selected JSON file;
- envelope schema v6 embeds the validated approval, binds the ledger head,
  immutable controller evidence, all three artifacts, behavioral evidence,
  and an exact signer-freshness block;
- the source-free signer must obtain a second authenticated observation of the
  ledger, controller tag, and GitHub controls after environment approval and
  immediately before requesting an OIDC signature.

Raw GitHub API JSON, a carrier release, an embedded `verified` flag, or a tag
name never authorizes promotion by itself. The fixed validators and their
independently pinned trust roots must authenticate the evidence.

The v2/v6 command-line gates remain unavailable until the separate ledger,
owner-enforced immutable releases, selected/SHA-pinned Actions policy,
two-person protection, source-free signer identity, cryptographic annotated-tag
verifier, and the real Ubuntu HML kill/resume drill are provisioned and pinned.

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
The bootstrap source minimum is additionally fail-closed: the node
provisioner, bootstrap-tree publisher, stack-quiescence verifier, and deploy
lock wrapper must all be tracked as executables and must be 0555 in the Ops
archive. Both the builder and the independent verifier enforce this shared
mode contract.
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
