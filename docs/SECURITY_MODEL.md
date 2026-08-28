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

## Explicit non-guarantees

- Integrity verification is not signature verification or trust evaluation.
- Extraction is not process execution.
- Future `run` support is not a hostile-code sandbox unless it applies real OS
  isolation and reports that isolation explicitly.
- The current atomic no-replace publication path fails closed on non-Unix
  platforms rather than silently using a racy replacement operation.
