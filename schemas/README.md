# Schema scope

`approval.schema.json` documents the portable JSON shape. The normative
security contract is the combination of that schema and
`scripts/validate-approval.py`.

The validator intentionally enforces invariants that JSON Schema cannot express
or whose JSON data-model semantics are broader than the canonical wire format:

- `schema_version` must be serialized as the integer token `1`; `1.0` is
  rejected even though JSON Schema treats it as mathematically integral;
- canonical JSON bytes, duplicate-key rejection, and canonical base64url;
- timestamp equality, maximum lifetime, and clock skew;
- cross-field equality and inequality;
- append-only Git ancestry, exact remote `main`, file ownership/mode, replay
  history, and policy/workflow/source digests.

Passing the JSON Schema alone never authorizes a release.

`approval-v2.schema.json` documents the stable-controller approval shape. Its
normative validator is `scripts/validate-approval-v2.py`. In addition to the
portable shape, the validator enforces canonical bytes, bounded UTC validity,
the exact production-policy digest and positive trust epoch, immutable
controller tag/release bindings, distinct tag-crypto and signer-freshness
verifier digests, and linear continuity with the separately protected
approval ledger. `scripts/validate-ledger.py` replays every historical
approval and validates repository/ref/genesis/parent/sequence continuity
before emitting a canonical summary.

`release-envelope.schema.json` is the candidate host/signer shape for schema
v5. Its normative validator is `scripts/validate-envelope.py`. Schema v5 adds a
distinct signed Operations artifact and behavioral schema 3 binds API, Ops, and
Web by asset ID and exact byte/manifests/service digests.

`release-envelope-v6.schema.json` documents the stable-controller envelope.
Its normative validator is `scripts/validate-envelope-v6.py`. Schema v6 binds
the complete approval-v2 manifest and digest, the independently validated
ledger head, immutable controller tag/release evidence, API/Ops/Web artifacts,
behavioral verification, and the exact result of signer-side freshness
revalidation. Permanent v6 is selected by the exact additional discriminator
`envelope_profile=control-release-permanent-v6`, never by the version integer
alone; the bootstrap v6 keyset is a different contract.

`scripts/validate-signer-freshness-v2.py` uses the explicit evidence model
`workflow-signed-summary-v1`. It requires typed, authenticated initial and
fresh observations whose repository ID, workflow run ID, and run attempt all
match the signer runtime and envelope controller. Embedded JSON is never
accepted as its own proof, and evidence sidecars are not host authority. The
host must verify the signed summary and maintain separate replay indices for
run/attempt, release ID, and ledger sequence.

Signer-side approval validation is current-time validation. Envelope
historical validation preserves old bytes but grants no new authority; the
host signature verifier must independently require authenticated signing time
to satisfy `issued_at <= signing_time < expires_at` before staging.

`component-manifest.schema.json` documents component schema 4. API, Ops, and
Web retain exact build provenance and all bind the same reviewed
`control-runtime-v1` digest. `scripts/component_manifest.py` is normative and
enforces the cross-artifact runtime/migration equality.

`runtime-policy.schema.json` documents the exact Ubuntu 24.04, CPython cp312,
and dedicated Node v22 contract. `scripts/runtime_policy.py` requires canonical
bytes and the reviewed exact values. `host-runtime-attestation.schema.json`
documents the output of `scripts/attest-host-runtime.py`; that script is
normative and checks stable root-owned paths and unprivileged execution probes.

The current host must not accept or sign either candidate envelope until
immutable `ops.tar.gz` ingestion, atomic bundle switching/recovery,
unprivileged runtime verification, and all external v2 controls are implemented
and independently approved. Until then, the controller returns code 78.
