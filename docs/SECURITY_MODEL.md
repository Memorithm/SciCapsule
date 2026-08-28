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
by the exact canonical capsule bytes. `sign` and `verify-signature` first read
the capsule through the same regular-file/no-follow gate used for other
security-sensitive product inputs. Their capsule read is bounded to the
product default allowance: 1 GiB of payload bytes plus 16 MiB of capsule
metadata. `Capsule::decode` remains the canonical integrity/encoding authority
after that resource gate.

The v1 envelope carries only its version, algorithm identifier, and 64-byte
signature. It deliberately carries no trusted public key. The caller must
provide a public key separately, so signer-controlled metadata cannot become a
trust anchor merely by being present in the sidecar.

Capsule, signature and key inputs are size-bounded. On Unix they are opened
with no-follow semantics. Signature output uses create-new semantics and is not
silently overwritten. The exact wire contract and non-goals are documented in
[`SIGNATURES.md`](SIGNATURES.md).

## Trust policy guarantees

Trust policy v1 is local product configuration, separate from both `.scicap`
and detached signature envelopes. It contains an explicit finite allowlist of
raw Ed25519 public keys and a minimum number of distinct configured keys that
must authenticate the capsule.

`create-trust-policy` converts explicitly supplied SPKI PEM public keys into a
self-contained JSON policy. It rejects duplicate names, duplicate public keys,
invalid key names, unsupported algorithms or versions, impossible thresholds,
and policies larger than the configured limits. Policy output uses create-new
semantics.

`verify-trusted` first reads the capsule through the same bounded regular-file
input gate used by `sign` and `verify-signature`, then requires canonical
`Capsule::decode` to succeed before loading the local policy and detached
signature envelopes. It never learns trust anchors from capsule bytes or
signature metadata. A trusted key contributes at most one unit toward the
threshold regardless of how many matching signature envelopes are supplied.
Unknown signers contribute zero.

Trust policies are limited to 64 configured keys and one evaluation accepts at
most 64 signature envelopes. Capsule, policy and signature inputs are
size-bounded; on Unix they are opened with no-follow semantics. The exact policy
wire format and evaluation rules are documented in
[`TRUST_POLICY.md`](TRUST_POLICY.md).

## Execution v1 guarantees

`run` is an authorization-and-lifecycle layer above canonical `.scicap`; it does
not modify the format. Execution v1 is implemented only on Unix. Other
platforms fail closed rather than falling back to weaker process semantics.

Before materialization or process creation, `run`:

- reads the capsule through the bounded regular-file/no-follow path;
- performs canonical `Capsule::decode` integrity validation;
- requires an explicit local trust policy;
- requires at least one detached signature and enforces the policy threshold;
- enforces the same configurable materialization file-count and byte limits as
  `extract`;
- bounds the number and total bytes of explicit environment entries and
  entrypoint arguments;
- requires a positive wall-clock timeout no larger than 24 hours.

Only after trust succeeds does `run` create a private temporary run directory
and materialize the capsule with the extraction implementation. It resolves the
entrypoint exclusively from the canonical manifest, verifies the materialized
entrypoint is a regular file, and marks only that entrypoint executable. It does
not consult `PATH` and does not invoke a shell around the entrypoint.

The child starts with:

- the materialized capsule root as its working directory;
- the inherited environment cleared, followed only by explicitly requested
  `--env NAME=VALUE` entries;
- arguments after `--` passed verbatim;
- null stdin;
- inherited stdout and stderr;
- a dedicated Unix process group.

The process group is killed on timeout and is also cleaned up when the runner
returns, preventing descendants from intentionally outliving the command. The
private temporary materialization is removed when the run scope ends.

The complete execution contract and its limits are documented in
[`EXECUTION.md`](EXECUTION.md).

## SciRust Hub adapter guarantees

The Hub adapter remains a product layer above the same canonical container and
execution implementation. `hub-run` first rejects a result destination that
already exists, then bounded-reads and validates the request, capsule and local
trust policy. The trust decision is made against the exact capsule bytes held in
memory.

After that decision and before delegating to `run`, `hub-run` creates a private
temporary input-snapshot directory. It writes the exact verified capsule bytes,
the exact trust-policy bytes and the already validated detached signature
envelopes into new files there. The Phase 5 runner receives only those private
snapshot paths. It therefore does not reopen the caller-controlled capsule or
policy path after the Hub-facing trust decision.

The machine-readable Hub result is derived from the same in-memory capsule and
trust decision used to construct those snapshots. Its capsule digest, manifest
name/entrypoint and matched signers therefore describe the bytes that were
supplied to the delegated execution path rather than a later path lookup.

Result publication still uses create-new semantics. The early result-path check
prevents an already occupied destination from causing payload side effects, and
the final create-new write prevents overwrite if a racing creator appears after
the preflight. The early check is not a transactional reservation: in that
narrow race the payload may already have run before final publication fails.

The exact adapter wire contract and its media types are documented in
[`HUB_CONTRACT.md`](HUB_CONTRACT.md).

## Explicit non-guarantees

- Integrity verification is not signature verification or trust evaluation.
- A cryptographically valid signature does not establish that its public key is
  trusted, belongs to a claimed identity, is unrevoked, or is authorized to
  execute code.
- Trust policy v1 establishes only membership in a local key allowlist plus a
  distinct-key threshold. It does not provide signer identity, revocation,
  expiration, timestamps, certificate chains, transparency, or provenance.
- A valid SLSA/in-toto provenance statement is evidence about asserted build
  provenance; it is not by itself execution authorization.
- `run` and `hub-run` are **not OS sandboxes**. They do not restrict payload
  filesystem access outside the temporary tree, network access, syscalls,
  child-process creation, credentials, user/group privileges, CPU consumption,
  memory consumption, or other host resources beyond their stated
  file/byte/input and wall-clock bounds.
- A trust-policy decision means only that the configured signature threshold
  authenticated the exact capsule bytes. It is not a claim that the payload is
  benign.
- Host-level isolation for hostile code must be supplied externally, for
  example with an appropriately configured sandbox, container, VM, namespace,
  seccomp policy, or equivalent platform mechanism.
- The current atomic no-replace extraction publication and execution lifecycle
  implementations fail closed on non-Unix platforms rather than silently using
  weaker behavior.
