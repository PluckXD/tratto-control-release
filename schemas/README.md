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

The current host must not accept or sign this envelope until immutable
`ops.tar.gz` ingestion, atomic bundle switching/recovery, and unprivileged
runtime verification are implemented and independently approved. Until then,
the controller returns code 78.
