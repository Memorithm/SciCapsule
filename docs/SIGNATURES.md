# SciCapsule detached signatures

## Scope

This document specifies the SciCapsule product-layer detached signature
envelope version 1. It does not modify or extend the canonical `.scicap`
container owned by the SciRust `scirust-capsule-schema` and
`scirust-capsule` crates.

A signature is authenticity evidence relative to a public key. It is not, by
itself, a trust decision, identity proof, provenance policy, timestamp, or
sandbox guarantee.

## Primitive and key encodings

Envelope version 1 uses Ed25519. SciCapsule delegates signing and verification
to `ed25519-dalek` 2.2.x and uses strict verification.

Private keys accepted by `sign` are Ed25519 PKCS#8 PEM. Public keys accepted by
`verify-signature` are Ed25519 SubjectPublicKeyInfo (SPKI) PEM. These are
standard key encodings; SciCapsule does not define a private key container of
its own.

## Signed message

The Ed25519 message is the concatenation of:

1. the ASCII/UTF-8 domain-separation byte string
   `SciCapsule detached signature v1` followed by one NUL byte; and
2. the exact canonical `.scicap` bytes.

The CLI first decodes the capsule using `scirust-capsule::Capsule::decode`.
Therefore malformed, non-canonical, length-inconsistent, or payload-corrupted
capsules are rejected before signing or signature acceptance.

The detached signature does not change the capsule bytes. A signature for one
byte representation cannot authenticate a different byte representation.

## Envelope v1

The detached envelope is UTF-8 JSON with exactly these fields:

```json
{
  "version": 1,
  "algorithm": "ed25519",
  "signature": [0, 1, 2]
}
```

The illustrative `signature` array above is intentionally incomplete. In a
valid envelope it contains exactly 64 JSON integers in the inclusive range
0..255, representing the 64 Ed25519 signature bytes in order.

Validation is fail-closed:

- `version` must be exactly `1`;
- `algorithm` must be exactly `ed25519`;
- `signature` must contain exactly 64 bytes;
- unknown JSON object fields are rejected;
- malformed JSON and unsupported versions or algorithms are rejected.

The envelope intentionally does **not** contain a trusted public key. The
caller supplies the verification key separately with `--key`. This prevents a
signer-controlled envelope from defining its own trust anchor.

## CLI contract

Create a detached signature:

```text
scicapsule sign CAPSULE --key PRIVATE_KEY.pem --output SIGNATURE_FILE
```

The capsule must decode successfully before signing. The output path is opened
with create-new semantics and is never silently overwritten.

Verify a detached signature:

```text
scicapsule verify-signature CAPSULE \
  --signature SIGNATURE_FILE \
  --key PUBLIC_KEY.pem
```

Verification succeeds only if both canonical capsule validation and strict
Ed25519 verification succeed against the explicitly supplied public key.
Signature-envelope and key-file reads are bounded. On Unix, these auxiliary
inputs are opened with no-follow semantics so a symlink is rejected.

## Non-goals of v1

Envelope v1 deliberately does not define:

- a trust store or certificate-authority model;
- key discovery, key rotation, revocation, or transparency logs;
- signer identity claims;
- timestamps or freshness;
- multiple signatures or threshold signatures;
- network retrieval of keys or signatures;
- execution authorization or sandboxing.

Those are separate product-policy layers and can evolve without changing the
canonical `.scicap` format.
