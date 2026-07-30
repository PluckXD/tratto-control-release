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

