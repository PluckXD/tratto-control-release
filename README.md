# Tratto Control Release

Public trust root for Tratto Control Plane release authorizations.

This repository contains only:

- reviewed release intents;
- schemas and independent validators;
- public policy metadata;
- workflow definitions that never publish product artifacts.

It must never contain Tratto source code, binaries, archives, customer data,
credentials, internal configuration, logs, database exports, private URLs, or
unencrypted artifacts. API, Web, and Ops sources remain in private
repositories. Build outputs remain in a private carrier and are referenced here
only by immutable SHA-256 digests.

## Current state

`RELEASE_POLICY_UNAVAILABLE`

The repository is intentionally fail-closed while branch protection, a second
Tratto reviewer, protected environments, private source carriers, and the
signer identity are being provisioned. There is no active release workflow in
this bootstrap commit.

## Authorization model

Each file under `approvals/` must:

1. conform exactly to `schemas/approval.schema.json`;
2. be canonical JSON with sorted keys and no insignificant whitespace;
3. be the only file added by a single-parent commit whose parent is the pinned
   controller base;
4. preserve every prior authorization byte-for-byte in the parent Git tree;
5. pin API, Web, Ops, controller workflow, and policy commits or digests;
6. pin reviewed ancestors and the expected Control-only migration range;
7. use a unique release ID and canonical 128-bit-or-stronger nonce;
8. include `issued_at`, expire within 24 hours, and pass the bounded clock check;
9. pass `scripts/validate-approval.py` without duplicate keys, unknown fields,
   replay, symlinks, symbolic refs, controller drift, or policy drift;
10. pass `scripts/verify-source-revision.py` in isolated private checkouts,
    proving through the authenticated GitHub API that each source SHA is the
    exact remote `main` head and contains every required ancestor.

The example lives under `examples/`; no filename convention is excluded from
the real history scan.

The private-repository read token is exposed only to the source-verification
step and is removed before any product code executes. Product source must never
run in a job that can request an OIDC token.

The release signer must run only after independent build and runtime
verification. It receives OIDC only in its own fresh job, checks out no product
source, receives no product read credential, and signs only a verified
digest envelope.

## Repository controls

`main` must be protected with:

- pull requests and one approval required;
- CODEOWNERS review and stale-review dismissal;
- approval from someone other than the last pusher;
- administrators included;
- signed commits, linear history, and resolved conversations;
- force pushes and branch deletion disabled.

The `control-release` environment must require a Tratto reviewer other than the
workflow initiator. Until a second reviewer is configured, release remains
unavailable by design.
