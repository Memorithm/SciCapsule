# SciCapsule Hub execution evidence v3

`capsule.execute@4.0.0` is the lifecycle-policy evidence contract. It invokes
the lifecycle-aware `capsule.execute@3.0.0` bounded execution contract and
requires trust-policy media type
`application/vnd.scicapsule.trust-policy.v2+json`.

The `scicapsule-hub-evidence-v3` launcher snapshots the caller-provided capsule,
trust policy, and Hub request into a private temporary directory, computes
immutable SHA-256 identities, and invokes `scicapsule hub-run` on those pinned
snapshots. The source result retains wire schema v1 and is itself hashed into
the v3 evidence record. Its lifecycle policy digest and revision are copied into
the evidence record and must be present.

The v3 result media type is
`application/vnd.scicapsule.hub-run-result.v3+json` and records:

- exact capsule, trust-policy, Hub-request, and signature-envelope identities;
- lifecycle policy canonical digest and monotonic revision;
- source-result SHA-256, schema version, and media type;
- launcher and invoked `scicapsule` binary SHA-256 values;
- compiled package version, OS, architecture, bounded execution mode, and the
  explicit sandbox value `none`;
- trust decision fields and capsule identity.

The exact request hash binds the exact serialized request, including its
embedded signatures. Per-signature hashes are deterministic indexing values,
not substitutes for the request hash.

## Versioning and compatibility

Evidence v3 is a new contract rather than a mutation of
`capsule.execute@2.0.0`. Evidence v2 remains tied to the legacy execution
contract and policy-v1 input. Lifecycle policy v2 is a breaking authorization
requirement, so it is advertised only by the v4 capability and v3 result media
type.

Unknown or malformed request/result schema versions fail closed. Inputs and
runtime binaries must be regular non-symlink files within explicit size bounds.
Existing result destinations are never overwritten. The contract does not claim
OS sandboxing or scientific correctness; `trust_is_scientific_verdict` is
always `false`.

SciRust-Verify may ingest this record as evidence, while retaining ownership of
claim and verdict semantics. SciRust Hub retains outer orchestration and
artifact-lineage ownership.
