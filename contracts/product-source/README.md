# Controller-owned product source contracts

These canonical JSON documents bind security-critical API and Ops source bytes
to the exact migration head authorized by the permanent release controller.
They are reviewed controller inputs, not files supplied by the product build.

Current reviewed identities:

- `f51legalpublish.json` binds 41 files from Tratto API commit
  `4ced794135bea9f0bdc7aa841f925b1d9e36581e`; contract SHA-256
  `314f19fb5b73b179120eb9b06543e553307d33f9a9f18880d23139e7e2d47fde`.
- `f52provisionactivate.json` binds 65 files from Tratto API commit
  `35bc7a2d1409230e6771c7a5835d2dee00a9271f`; contract SHA-256
  `ba54f37d60f5b7fa9f4fa9a67c8221d6d772ac060d81a8e7a805aca9292a88ab`.

The v6 set is a strict superset of the v5 set. The builder verifies every
listed file twice: once in the immutable approved checkout and once in the
prepared runtime tree. Both byte streams must equal the controller-owned
digest. A migration head without an explicit head-specific required set and a
canonical contract is rejected.

These contracts do not authorize a release by themselves. The controller
readiness gate must remain `unavailable` until its independent identities,
reviewers, immutable release, ledger, signer, verifier, runtime evidence and
HML drills are all provisioned and freshly revalidated.
