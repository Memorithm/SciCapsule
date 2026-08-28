# SciCapsule trust policy v1

## Scope

A SciCapsule trust policy is local product configuration. It is not part of the
canonical `.scicap` container and is not carried by a detached signature.

The policy answers one question only: how many distinct explicitly configured
Ed25519 trust anchors must authenticate the exact canonical capsule bytes before
SciCapsule reports the capsule as trusted under that policy?

It does not assert signer identity, revocation state, timestamp validity,
provenance, or execution authorization.

## Policy format

Trust policy version 1 is strict JSON with exactly these top-level fields:

```json
{
  "version": 1,
  "algorithm": "ed25519",
  "minimum_signatures": 2,
  "trusted_keys": [
    {
      "name": "release-a",
      "public_key": [1, 2, 3]
    }
  ]
}
```

The example public key above is intentionally incomplete. A valid Ed25519
public key contains exactly 32 JSON byte values in the inclusive range 0..255.

Validation is fail-closed:

- `version` must be exactly `1`;
- `algorithm` must be exactly `ed25519`;
- the policy must contain at least one and at most 64 trusted keys;
- `minimum_signatures` must be between 1 and the number of trusted keys;
- every key must be a valid 32-byte Ed25519 public key;
- key names are 1..64 bytes and contain only ASCII letters, digits, `.`, `_`,
  or `-`;
- duplicate key names are rejected;
- duplicate public keys are rejected;
- unknown JSON fields are rejected.

The CLI creates this raw-key form from standard Ed25519 SPKI PEM files. PEM
paths are inputs to policy construction only; a policy does not retain external
file references.

## Creating a policy

```text
scicapsule create-trust-policy \
  --output release-policy.json \
  --require 2 \
  release-a=release-a-public.pem \
  release-b=release-b-public.pem \
  recovery=recovery-public.pem
```

The output path uses create-new semantics and is never silently overwritten.
Security-sensitive public-key inputs are size-bounded and, on Unix, opened with
no-follow semantics.

## Evaluating trust

```text
scicapsule verify-trusted demo.scicap \
  --policy release-policy.json \
  --signature demo.release-a.sig \
  --signature demo.release-b.sig
```

Evaluation order is:

1. decode and fully verify the canonical `.scicap` bytes;
2. load and validate the local trust policy;
3. load and validate each detached signature envelope;
4. test those signatures only against keys present in the local policy;
5. count distinct trusted keys that successfully authenticate the capsule;
6. require the configured threshold.

At most 64 signature envelopes are accepted in one evaluation. Policy and
signature sidecars are size-bounded and opened with no-follow semantics on
Unix.

A signature file is not a vote. Repeating the same signature file, supplying
multiple equivalent signatures from one key, or otherwise producing more
signature objects from one trusted key still counts as exactly one matched
trusted signer. The threshold is over distinct policy keys.

Signatures from keys absent from the local policy do not count. Signer-provided
metadata cannot add or replace trust anchors.

## Non-goals

Trust policy v1 deliberately does not define:

- certificates or certificate-authority chains;
- remote key discovery;
- revocation or key expiration;
- transparency logs;
- signer identity claims;
- timestamps or freshness;
- provenance statements;
- execution permissions or sandbox policy.

Those are separate layers and can evolve without changing `.scicap` or trust
policy v1 semantics.
