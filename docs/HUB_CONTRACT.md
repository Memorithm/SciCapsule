# SciCapsule ↔ SciRust Hub contract v1

## Scope

This document defines the product-layer contract by which SciRust Hub may invoke
SciCapsule. It does not modify or extend the canonical `.scicap` container.
Canonical capsule schema, encoding, manifest fields, entrypoint semantics and
payload integrity remain owned by the pinned SciRust capsule crates.

Contract v1 deliberately uses the Hub's existing `process` execution binding.
The Hub supplies immutable input artifacts as direct argv values; SciCapsule
performs capsule integrity validation, local trust-policy authorization and the
bounded execution defined by `scicapsule run`.

## Capability

The generated Hub component manifest declares:

- capability: `capsule.execute`;
- contract version: `1.0.0`;
- component kind: `tool`;
- execution binding: `process`;
- no shell interpolation.

The capability has three required inputs and one required output:

| Port | Direction | Media type |
| --- | --- | --- |
| `capsule` | input | `application/vnd.scirust.scicap` |
| `policy` | input | `application/vnd.scicapsule.trust-policy.v1+json` |
| `request` | input | `application/vnd.scicapsule.hub-run-request.v1+json` |
| `result` | output | `application/vnd.scicapsule.hub-run-result.v1+json` |

`hub-manifest` requires an absolute path to the `scicapsule` executable. The
binding invokes that path directly as:

```text
hub-run
--capsule {input:capsule}
--policy {input:policy}
--request {input:request}
--result {output:result}
```

The Hub owns artifact materialization and result ingestion. SciCapsule never
uses a path embedded in the capsule as a trust anchor or host-side executable.

## Hub execution request v1

`create-hub-request` emits deterministic pretty JSON with a trailing newline.
Unknown fields are rejected when the request is consumed.

The request object contains fields in this order:

```json
{
  "schema_version": 1,
  "signatures": [],
  "timeout_seconds": 300,
  "max_files": 4096,
  "max_bytes": 1073741824,
  "environment": [],
  "arguments": []
}
```

Rules:

- `schema_version` must be exactly `1`;
- at least one detached SciCapsule signature envelope is required;
- the number of signatures is bounded by the trust layer's signature limit;
- signature envelopes must be valid v1 Ed25519 envelopes;
- signatures are serialized in strict bytewise signature order and duplicates
  are rejected;
- `timeout_seconds` is in `1..=86400`;
- extraction file/byte limits use the same semantics as `scicapsule run`;
- environment names are unique and serialized in strict lexical order;
- environment count and aggregate bytes use the same limits as `run`;
- arguments are ordered, passed verbatim, and use the same count/byte limits as
  `run`;
- NUL bytes are rejected;
- the encoded request is bounded to 512 KiB.

Signatures live inside the request artifact rather than being separate Hub
ports. This preserves arbitrary trust-policy thresholds without requiring a
fixed number of signature inputs in the Hub component manifest.

## Hub execution result v1

A successful `hub-run` creates a new result file. If the result destination
already exists as any filesystem object, including a symlink, `hub-run` refuses
to execute the payload. Final publication still uses create-new semantics, so a
concurrent destination appearing after the preflight is never overwritten.

The result contains:

```json
{
  "schema_version": 1,
  "status": "succeeded",
  "capsule_sha256": "<sha256 of exact canonical capsule bytes>",
  "capsule_name": "<canonical manifest name>",
  "entrypoint": "<canonical manifest entrypoint>",
  "matched_signers": ["<local trust-policy signer name>"],
  "required_signatures": 1
}
```

The result is deterministic for the same capsule bytes, trust policy and
successful request. It intentionally contains no timestamps, random IDs, host
paths or platform-specific process identifiers. Its capsule digest, canonical
manifest fields and matched-signers decision describe the same in-memory bytes
that are pinned into private snapshots for execution; caller-controlled capsule
or policy paths are not reopened after that decision.

On trust failure, malformed input, extraction failure, timeout or non-zero
entrypoint exit, `hub-run` returns non-zero and does not fabricate a success
result. The Hub therefore records the process failure through its ordinary run
outcome/provenance path.

## Authorization and execution order

`hub-run` performs these gates before creating the payload process:

1. reject an already-existing result destination using symlink-aware metadata;
2. bounded no-follow read of the request, capsule and trust policy where the
   platform implementation supports those guarantees;
3. strict request decode and validation;
4. canonical `Capsule::decode` integrity validation;
5. local trust-policy evaluation against the exact capsule bytes;
6. create a private temporary snapshot directory and write the exact verified
   capsule bytes, exact parsed policy bytes and validated detached signature
   envelopes into new files there;
7. delegate to the same trusted bounded execution path used by `scicapsule run`,
   using only those private snapshot paths.

This pinning step closes the path-reopen reproducibility window between the
Hub-facing trust decision and Phase 5 execution. Even if the caller replaces
the original capsule or policy path after the bounded read, the delegated run
continues against the already verified snapshot. The request itself is decoded
once into memory and is not reopened for execution.

The execution path then privately materializes the canonical payload, resolves
only the canonical manifest entrypoint, clears the inherited environment,
passes explicit environment/arguments only, uses a deterministic capsule-root
cwd, applies the wall-clock timeout and cleans up the dedicated Unix process
group.

## Security boundary

This contract does **not** turn SciRust Hub or SciCapsule into an OS sandbox.
It makes authorization and invocation explicit and reproducible, but v1 does
not provide filesystem, network, syscall, privilege, CPU or memory isolation.
Hostile payloads require a real external sandbox/container boundary.

The Hub's own executor timeout and capture limits are an outer control plane;
the request's SciCapsule timeout and extraction bounds remain the inner capsule
execution policy. Neither layer should claim stronger isolation than it
actually implements.

The early result-path check is a side-effect guard, not a filesystem
reservation. A racing creator can still occupy that path after preflight; the
final create-new write then fails closed instead of overwriting it. The payload
may already have run in that narrow publication race, so callers needing
transactional output reservation must provide that boundary externally.

## Versioning

The wire request/result schema version and capability contract version are
independent from the SciCapsule package version and the canonical `.scicap`
format version.

A breaking change to request/result semantics requires a new Hub contract
version. Additive Hub capabilities should not mutate the canonical capsule
format. Unknown request fields and unknown request schema versions fail closed
in v1.
