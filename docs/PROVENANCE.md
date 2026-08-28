# SciCapsule provenance contract

## Scope

SciCapsule provenance is product-layer evidence kept outside the canonical
`.scicap` container. It does not add fields to or redefine the SciRust capsule
schema.

`attest-provenance` creates an in-toto Statement v1 carrying a SLSA Provenance
v1 predicate and wraps the statement in a DSSE envelope signed with explicitly
supplied Ed25519 private keys. `verify-provenance` verifies that envelope against
an explicit local SciCapsule trust policy and checks that the statement applies
to the exact capsule bytes supplied by the caller.

Provenance evidence is not execution authorization. A verified statement may be
used as evidence by a higher-level policy, but SciCapsule's execution
authorization remains the separate local trust-policy/signature gate.

## Capsule input gate

Both provenance commands read the capsule through SciCapsule's default
read-only capsule gate before `Capsule::decode`:

- maximum capsule input is the default 1 GiB payload allowance plus 16 MiB of
  capsule metadata;
- the input must be a regular file;
- on Unix it is opened with no-follow and nonblocking flags, so capsule symlinks
  and special-file streams are rejected;
- inputs whose file metadata already exceeds the bound are rejected before the
  content is allocated or read;
- the read remains bounded even if the underlying file changes after metadata
  inspection.

After this resource gate, canonical `scirust-capsule::Capsule::decode` remains
the authority for encoding, length and payload-integrity validation.

The provenance subject digest is computed from the exact capsule byte vector
that passed this gate and decode. Verification compares provenance to the exact
byte vector read for that invocation.

## Attestation inputs

`attest-provenance` requires explicit values for:

- one or more Ed25519 PKCS#8 private PEM files;
- builder identifier;
- build type;
- resolved source/dependency URI;
- resolved source/dependency SHA-256 digest;
- a new provenance output path.

Private-key inputs use the product's bounded regular-file/no-follow reader.
The command creates a DSSE envelope only after the capsule passes the bounded
input gate and canonical decode. Provenance output uses create-new semantics and
is never silently overwritten.

## Verification inputs

`verify-provenance` requires:

- the exact capsule being checked;
- a DSSE provenance envelope;
- a local SciCapsule trust policy.

The provenance envelope is bounded to 2 MiB. The policy uses the trust-policy
size bound. On Unix both sidecars use no-follow regular-file reads.

Verification first establishes the envelope's configured trust-policy
threshold and then validates the provenance statement, including the capsule
subject digest. A statement for different capsule bytes is rejected even when
its DSSE signatures are otherwise trusted.

## Determinism and format boundary

The capsule remains unchanged by provenance creation or verification. The
canonical `.scicap` bytes are the subject of the evidence; the DSSE/in-toto/SLSA
object is a detached product artifact.

This separation lets provenance evolve without forking the SciRust capsule
format and lets trust/execution policy decide independently whether particular
provenance evidence is required.

## Non-goals

The current provenance layer does not itself provide:

- execution authorization;
- certificate-chain identity or public CA semantics;
- key revocation or expiration;
- transparency-log inclusion;
- trusted timestamps or freshness;
- an OS sandbox;
- network, syscall, filesystem, CPU or memory isolation.

Those properties require separate policy or isolation layers and must not be
inferred from a successful provenance verification.
