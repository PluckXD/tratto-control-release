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

`release-envelope.schema.json` is the candidate host/signer shape for schema
v5. Its normative validator is `scripts/validate-envelope.py`. Schema v5 adds a
distinct signed Operations artifact and behavioral schema 3 binds API, Ops, and
Web by asset ID and exact byte/manifests/service digests.

`component-manifest.schema.json` documents component schema 4. API, Ops, and
Web retain exact build provenance and all bind the same reviewed
`control-runtime-v1` digest. `scripts/component_manifest.py` is normative and
enforces the cross-artifact runtime/migration equality.

`runtime-policy.schema.json` documents the exact Ubuntu 24.04, CPython cp312,
and dedicated Node v22 contract. `scripts/runtime_policy.py` requires canonical
bytes and the reviewed exact values. `host-runtime-attestation.schema.json`
documents the output of `scripts/attest-host-runtime.py`; that script is
normative and checks stable root-owned paths and unprivileged execution probes.

The current host must not accept or sign this envelope until immutable
`ops.tar.gz` ingestion, atomic bundle switching/recovery, and unprivileged
runtime verification are implemented and independently approved. Until then,
the controller returns code 78.
