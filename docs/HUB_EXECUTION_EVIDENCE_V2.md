# SciCapsule Hub execution evidence v2

`capsule.execute@2.0.0` is the additive evidence-record contract. Its launcher
now invokes the lifecycle-aware SciCapsule `capsule.execute@3.0.0` bounded
execution contract and therefore requires trust-policy media type v2.

The `scicapsule-hub-evidence-v2` launcher snapshots the caller-provided capsule,
trust policy, and Hub request into a private temporary directory, computes
immutable SHA-256 identities, and invokes `scicapsule hub-run` on those pinned
snapshots. The source result retains wire schema v1 and is itself hashed into
the v2 evidence record; its policy digest/revision fields bind the lifecycle
authorization decision.

The v2 result media type is `application/vnd.scicapsule.hub-run-result.v2+json` and records:

- exact capsule SHA-256;
- exact trust-policy SHA-256;
- exact Hub-request SHA-256;
- deterministic identities for the signature envelope values embedded in that request;
- the v1 result SHA-256 and media type;
- the v2 launcher binary SHA-256;
- the invoked `scicapsule` binary SHA-256;
- compiled package version;
- OS and architecture scope;
- the explicit execution mode `bounded_process_unix`;
- the explicit sandbox value `none`;
- the v1 trust decision fields and capsule identity.

The exact request hash is the authoritative binding for the exact serialized request, including its embedded signatures. Per-signature hashes are deterministic value identities for indexing and comparison; they are not substitutes for the request hash.

## Security and semantic boundary

This contract does not claim OS sandboxing. It does not make a scientific-correctness verdict. Detached signatures establish authenticity under the supplied local trust policy; the field `trust_is_scientific_verdict` is therefore always `false` in v2.

Unknown or malformed request/result schema versions fail closed. Inputs and runtime binaries must be regular non-symlink files within explicit size bounds. Existing result destinations are never overwritten.

SciRust-Verify may ingest this record as provenance/trust/execution evidence, but remains responsible for evidence-dossier claim and verdict semantics. SciRust Hub remains responsible for outer orchestration and artifact lineage.
