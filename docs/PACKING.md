# SciCapsule packing contract

## Scope

`scicapsule pack` is the product-layer producer for the canonical `.scicap`
container implemented by the pinned SciRust capsule crates. It maps explicit
portable capsule paths to local source-file bytes and delegates canonical
manifest/container validation and encoding to `scirust-capsule`.

This contract adds resource and filesystem safety around production. It does
not add fields to or redefine the canonical `.scicap` schema.

## Resource limits

`pack` accepts:

```text
--max-files N
--max-bytes N
```

The defaults match the product extraction limits:

- maximum payload mappings: 4096;
- maximum aggregate payload bytes: 1 GiB (1073741824 bytes).

The payload-mapping count is checked before any payload source is opened. The
aggregate byte budget is then consumed in mapping order. Each source is read
with the remaining aggregate budget as its maximum allowed size. A source whose
metadata size already exceeds the remaining budget is rejected before its
contents are allocated/read, and the bounded reader still detects growth beyond
the budget while reading.

The implementation may retain the bounded payload set and encoded capsule in
memory. This is an explicit finite product resource bound, not a streaming
encoding guarantee.

## Source-file safety

Each `PATH=FILE` mapping must reference a regular source file. On Unix the
source path is opened with `RDONLY`, `CLOEXEC`, `NOFOLLOW`, and `NONBLOCK` before
its metadata and bytes are consumed. Symlink source paths and special-file
streams are therefore rejected rather than followed or blocked on.

The bytes read from a valid regular source are preserved exactly in the
`CapsulePayload` passed to the canonical SciRust implementation. Portable
capsule-path validation, duplicate-path rejection, entrypoint validation,
payload hashing, canonical ordering and deterministic encoding remain the
responsibility of the pinned canonical capsule crates.

## Output publication

The output path is created only after all payload inputs have passed the product
resource/filesystem gates and the canonical capsule has been constructed and
encoded successfully.

The output uses create-new semantics. An existing file, symlink, directory or
other occupied output path is not overwritten. After writing the encoded bytes,
SciCapsule synchronizes the file. If writing or synchronization fails, it makes
a best effort to remove the partial output created by that invocation.

This is a no-clobber publication guarantee, not an atomic rename transaction.
The output path is written directly after successful create-new creation; a
reader that races the producer could observe the file before the final sync.
Consumers that require transactional distribution should publish or move the
completed capsule through an external atomic artifact-management boundary.

## Determinism

For identical capsule name, entrypoint, portable mappings and source bytes, the
canonical encoder determines the resulting `.scicap` bytes. Product-side
resource limits and no-follow checks do not inject timestamps, host metadata,
source filesystem permissions or source path strings into the canonical
container.

Changing the order of equivalent explicit mappings therefore does not change
the deterministic capsule representation when the canonical implementation
normalizes them as required by its schema.

## Non-goals

Packing does not itself provide:

- authenticity or execution authorization;
- provenance assertions;
- source-file content stability against a writer that mutates an already-open
  regular file while it is being read;
- transactional/atomic output publication;
- streaming canonical encoding;
- an OS sandbox.

Detached signatures, trust policy, provenance, Hub orchestration and execution
remain separate product layers.
