# SciCapsule security model

## Canonical format boundary

The `.scicap` schema and deterministic container belong to the SciRust
`scirust-capsule-schema` and `scirust-capsule` crates. SciCapsule consumes the
exact pinned implementation; it does not add product metadata to the canonical
container.

Container v1 provides integrity, not authenticity. A successful decode proves
that the canonical manifest matches the embedded payload lengths and SHA-256
digests. It does not establish who produced the capsule, whether that producer
is trusted, or whether executing the payload is safe.

## Extraction guarantees

Before the first filesystem write, extraction:

- relies on canonical decode to reject malformed encoding, absolute paths,
  `.` and `..` components, duplicate paths, corruption, and trailing bytes;
- independently revalidates every portable path;
- rejects file/directory path conflicts such as `bin` and `bin/run`;
- enforces configurable file-count and total-payload-byte limits;
- rejects an existing destination using symlink-aware metadata.

Materialization creates a private sibling staging directory. Only directories
and new regular files are created there. Capsule bytes cannot request symlinks,
devices, sockets, ownership, or file modes because the canonical v1 schema has
no such fields. Each file is written with `create_new`, synchronized, and the
completed tree is published on Unix with an atomic `RENAME_NOREPLACE`-style
operation. A concurrent destination creation therefore causes extraction to
fail instead of being overwritten.

The extraction CLI also opens the capsule input on Unix with no-follow and
nonblocking flags, requires a regular file, and bounds the read before decode.

## Detached signature guarantees

SciCapsule signature envelope v1 is a product-layer sidecar and never changes
the canonical `.scicap` bytes. It uses Ed25519 through `ed25519-dalek` and
strict signature verification. Private keys are accepted as PKCS#8 PEM and
public keys as SPKI PEM.

The signed message contains a SciCapsule v1 domain-separation prefix followed
by the exact canonical capsule bytes. `sign` first requires the capsule to pass
canonical decode. `verify-signature` likewise validates the capsule before
accepting a signature.

The v1 envelope carries only its version, algorithm identifier, and 64-byte
signature. It deliberately carries no trusted public key. The caller must
provide a public key separately, so signer-controlled metadata cannot become a
trust anchor merely by being present in the sidecar.

Signature and key sidecars are size-bounded. On Unix they are opened with
no-follow semantics. Signature output uses create-new semantics and is not
silently overwritten. The exact wire contract and non-goals are documented in
[`SIGNATURES.md`](SIGNATURES.md).

## Explicit non-guarantees

- Integrity verification is not signature verification or trust evaluation.
- A cryptographically valid signature does not establish that its public key is
  trusted, belongs to a claimed identity, is unrevoked, or is authorized to
  execute code.
- Detached signature v1 does not provide timestamps, revocation, transparency,
  certificate chains, threshold authorization, or network key discovery.
- Extraction is not process execution.
- Future `run` support is not a hostile-code sandbox unless it applies real OS
  isolation and reports that isolation explicitly.
- The current atomic no-replace publication path fails closed on non-Unix
  platforms rather than silently using a racy replacement operation.
