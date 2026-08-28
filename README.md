# SciCapsule

SciCapsule is the independently distributable product layer for SciRust portable, reproducible execution capsules.

The reusable `.scicap` schema and deterministic container implementation live in the [`Memorithm/scirust`](https://github.com/Memorithm/scirust) monorepo. This repository provides the user-facing CLI on top of those shared primitives.

## Current CLI

Create a deterministic capsule by mapping portable capsule paths to source files explicitly:

```text
scicapsule pack \
  --name demo \
  --entrypoint bin/run \
  --output demo.scicap \
  bin/run=./run.bin \
  data/input.bin=./input.bin
```

Decode, fully verify, and print the manifest:

```text
scicapsule inspect demo.scicap
```

Verify canonical encoding, declared lengths, and every payload SHA-256:

```text
scicapsule verify demo.scicap
```

Safely materialize verified payload bytes into a new directory on Unix:

```text
scicapsule extract demo.scicap \
  --output ./materialized \
  --max-files 4096 \
  --max-bytes 1073741824 \
  --json
```

`extract` rejects an existing destination of any type, including a symlink. It
preflights all path conflicts and resource limits before writing, creates only
regular files inside a private staging directory, and publishes that directory
with an atomic no-replace rename. The current fail-closed implementation does
not publish extracted directories on non-Unix platforms.

## Detached signatures

SciCapsule keeps authenticity metadata outside the canonical `.scicap`
container. Signature envelope v1 uses Ed25519 and requires standard PEM key
material: PKCS#8 for the private key and SPKI for the public key.

One way to create a compatible Ed25519 key pair with OpenSSL is:

```text
openssl genpkey -algorithm ED25519 -out signer-private.pem
openssl pkey -in signer-private.pem -pubout -out signer-public.pem
```

Sign an already-valid canonical capsule without modifying it:

```text
scicapsule sign demo.scicap \
  --key signer-private.pem \
  --output demo.scicap.sig
```

Verify both canonical capsule integrity and the detached signature against an
explicitly selected public key:

```text
scicapsule verify-signature demo.scicap \
  --signature demo.scicap.sig \
  --key signer-public.pem
```

`sign` refuses to overwrite an existing signature file. `verify-signature`
does not trust key material from the signature envelope: the verification key
must be provided separately by the caller. A valid signature therefore proves
only that the exact canonical capsule bytes were signed by the holder of the
corresponding private key; deciding whether that public key is trusted remains
a separate policy decision.

`inspect`, `verify`, `extract`, `sign`, and `verify-signature` all preserve the
canonical format boundary. Signature trust, provenance policy, and execution
are separate product layers. See [the security model](docs/SECURITY_MODEL.md)
and [the detached signature specification](docs/SIGNATURES.md).
