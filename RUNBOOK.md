# Controller activation runbook

This runbook provisions external controls; it does not authorize bypassing
them. Keep `release-readiness.json` unavailable until every item has reviewed
evidence.

## 1. Product and host prerequisites

1. Merge the edge-first recovery fix. Recovery must stop the proxy and all
   readiness/reconcile units before restoring symlinks, state, or timers.
2. Add schema-v5 support for a distinct signed Ops artifact to host ingestion,
   provenance validation, immutable bundles, activation, and recovery.
3. Replace every in-place Operations copy with
   `/opt/tratto-control/ops -> current/ops`.
4. Add order tests proving quiescence before switch/recovery and proxy-last
   restoration.
5. Remove `Before=` edges from recovery to the readiness/reconcile one-shot
   services when recovery starts and waits for those services itself; retain
   ordering on their timers so recovery cannot deadlock.
6. Resolve Operations validators through `current/ops/scripts`, not the old
   unversioned root.
7. Make each candidate migration unit execute
   `/opt/tratto-control/bundles/%i/ops/scripts/run-*` after a trusted bootstrap
   validates that candidate bundle. A migration must not use CURRENT
   Operations bytes for a different `%i` candidate.
8. Keep only a minimal pinned bootstrap outside `current`; units, launchers,
   migration runners, Nginx fragments, and recovery logic that vary by release
   must resolve through the signed generation.
9. Keep `/opt/tratto-control/ops -> current/ops` as a stable convenience link.
   It is intentionally unresolved before the first activation; no bootstrap
   command may depend on it. First stage/activation and recovery entrypoints
   resolve through the physical, validated
   `/opt/tratto-control/bootstrap/scripts`. All three `%i` migration templates
   execute the already-validated candidate under
   `/opt/tratto-control/bundles/%i/ops/scripts`. The first atomic `current`
   publication makes the convenience link valid without a separate handoff.
   Recovery remains callable through bootstrap when `current` is absent or
   broken.
10. Stage bootstrap scripts, units, Nginx, and tmpfiles together in a root-only
   temporary tree; validate all of them before atomic rename/link publication.
   A failed install must leave resumable/cleanable staging rather than a
   permanent partial bootstrap.
11. Remove root execution of `bundle/api/runtime/bin/python` from bundle
   validation. Root opens only reviewed host binaries and drops to the actual
   runtime users for metadata probes; artifact runtime execution belongs in the
   unprivileged isolated verifier/unit.
12. Use `/usr/bin/python3.12` across API, executor, migrators, proxy, Web
   preflight, and Operations. Attest CPython 3.12/cpython-312, exact SOABI,
   non-debug ABI, Ubuntu 24.04, and glibc 2.39 or later. Do not use the mutable
   `/usr/bin/python3` alias.
13. Record the accepted host commit as a required approval ancestor.
14. Install canonical `control-runtime-v1.json` atomically as root:root 0444 at
   `/etc/tratto-control/runtime-policy.json`; candidate/stage copies may be
   root-only 0400, but the attestor accepts only the canonical installed path
   and mode.

### Dedicated Node v22 toolchain

The toolchain is infrastructure, not a release payload. Provision it in a
separate reviewed maintenance operation:

1. obtain only
   `https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz`;
2. require exactly 30,779,824 bytes and SHA-256
   `9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37`;
3. stream only the exact regular member
   `node-v22.22.0-linux-x64/bin/node` into a root-only staging directory.
   Reject links, additional extraction, sparse/PAX surprises, or size drift;
4. require exactly 123,405,064 binary bytes and SHA-256
   `1bec56ef7cfa9a76f3e0b7c0a87f220eb73f23102b9c0b4c7529a3f7c3ce7c31`;
5. run `scripts/extract-reviewed-node.py` against the already local archive and
   canonical runtime policy. The script creates one root-only 0400 staging
   file with `O_EXCL`; it performs no download or installation;
6. in the separately reviewed host provisioner, chown root:root and chmod 0555,
   fsync the file and every affected directory, then publish with atomic
   no-replace semantics at
   `/opt/tratto-control/toolchains/node-v22.22.0-linux-x64/bin/node`, fsync the
   tree, and reject any pre-existing destination unless its exact bytes,
   ownership, mode, and ancestors re-attest successfully. Do not install npm,
   npx, corepack, or any tar symlink;
7. make `tratto-control-web.service` use that exact path and retain toolchains
   referenced by current and previous generations;
8. run `scripts/attest-host-runtime.py` as root. It opens fixed root-owned
   binaries without following links, checks stable inode metadata and hashes,
   then uses `/usr/bin/setpriv` to probe Python as all six runtime users and
   Node as `tratto-control-web`.

No controller workflow downloads or provisions this toolchain.

The previously reviewed candidate `025fb61` is not releasable because it lacks
these guarantees. The boot fix at API `3a3b864` does not by itself close the
Ops artifact/atomicity blocker.

## 2. Public controller settings

On `PluckXD/tratto-control-release`:

1. Protect `main`.
2. Require pull requests, stale-review dismissal, CODEOWNERS review, approval
   from someone other than the last pusher, signed commits, linear history, and
   resolved conversations.
3. Keep every pull-request review bypass allowance empty, include
   administrators, and disable force pushes and branch deletion.
4. Configure a second Tratto reviewer independent of the initiator and last
   pusher.
5. Set Actions to `selected`, disable the broad GitHub-owned and
   verified-creator allowances, allow only these exact action revisions, and
   require full-SHA references:
   - `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`;
   - `actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548`.
   The currently observed `allowed_actions: all` and
   `sha_pinning_required: false` are blockers.

Do not change these settings from a release workflow.

## 3. Protected signer environment

For `control-release`:

1. keep `prevent_self_review=true`;
2. configure the independent Tratto reviewer;
3. set `can_admins_bypass=false`;
4. allow OIDC only to the signer job on protected `main`;
5. expose no product repository token or source checkout to the signer.
6. after the environment reviewer admits the signer, revalidate branch,
   selected-Actions, environment, and append-only ledger controls immediately
   before requesting OIDC. A pre-build snapshot is not fresh enough.

The currently observed administrator bypass is a blocker.

## 4. Isolated identities and images

Provision separate least-privilege identities for:

- read-only API/Operations source;
- read-only Web source;
- carrier upload for each build;
- carrier read/write for the verifier;
- carrier read/write for the signer.

Carrier credentials must have no product or controller administration access.
Product read credentials must not have carrier write access.

Review and pin by immutable digest:

- API builder image;
- Web builder image;
- Ops packager image;
- runtime verifier/Chrome image;
- Cosign binary version and SHA-256.

The candidate expects these exact names when the corresponding implementation
PR is reviewed; none is created by this repository:

```text
CONTROL_CONTROLLER_AUDIT_TOKEN
CONTROL_API_READ_TOKEN
CONTROL_WEB_READ_TOKEN
CONTROL_API_CARRIER_WRITE_TOKEN
CONTROL_OPS_CARRIER_WRITE_TOKEN
CONTROL_WEB_CARRIER_WRITE_TOKEN
CONTROL_VERIFY_CARRIER_TOKEN
CONTROL_SIGN_CARRIER_TOKEN
CONTROL_API_BUILDER_IMAGE
CONTROL_OPS_BUILDER_IMAGE
CONTROL_WEB_BUILDER_IMAGE
CONTROL_RUNTIME_VERIFIER_IMAGE
CONTROL_COSIGN_VERSION
CONTROL_COSIGN_SHA256
```

Every image value is `registry/repository@sha256:<64 lowercase hex>`. Source
tokens are read-only GitHub App/fine-grained credentials scoped to one product
repository. Carrier tokens are scoped only to private Release assets and are
different for each listed role. The audit token has read-only controller
administration/actions/environment visibility and no product/carrier access.
Missing values return code 78; never substitute a broad personal token.

Build jobs receive no OIDC. Source tokens are used only for checkout and exact
remote-main/ancestor verification with `persist-credentials: false`, then
removed before product code executes. The carrier credential is introduced
only after the isolated build process has terminated.

## 5. Carrier contract

Keep `PluckXD/tratto-control-release-carrier` private and Actions disabled.
Upload API, Web, Ops, build records, the verified envelope, and the Sigstore
bundle only as private GitHub Release assets. Use unique release IDs/run IDs.

Always download by numeric asset ID and independently approved digest. Asset
name, release tag, carrier commit, and carrier administrator are metadata, not
authority.

## 6. Evidence and readiness commit

Collect, review, and retain outside the carrier:

- branch-protection and action-policy API responses;
- selected-Actions allowlist response proving the exact checkout SHA;
- protected-environment response showing no self-review or admin bypass;
- reviewer identities and separation;
- builder/verifier/signer image and binary digests;
- builder evidence proving the recorded OS, architecture, and exact build
  runtime are observed rather than hardcoded for API, Ops, and Web;
- least-privilege token/app installation scopes;
- host schema-v5 and atomic Ops test results;
- component-manifest schema-v4 and host runtime-attestation results;
- installed runtime-policy digest, Node archive/binary sizes and SHA-256s, and
  current/rollback toolchain retention;
- final workflow SHA-256 and controller commit;
- exact required product ancestors.

Only then submit a dedicated PR that changes
`release-readiness.json` to `state: ready` with an empty blocker list. The same
review must pin the final controller/workflow values in host-owned provenance
policy. Never reuse an expired approval or simulate missing evidence.

The current append-only approvals and mutable controller HEAD cannot become
ready as-is because the host controller pin would change on every release. A
follow-up reviewed contract must dispatch an immutable controller tag/SHA, keep
approvals in a separately protected linear append-only public ledger, recheck
ledger ancestry in the signer, and rotate controller pins only with an audited
dual-pin upgrade. This remains the `stable-controller-ledger` blocker.
