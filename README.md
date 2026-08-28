# SciCapsule

SciCapsule is the independently distributable product layer for SciRust portable, reproducible execution capsules.

The reusable `.scicap` schema and deterministic container implementation live in the [`Memorithm/scirust`](https://github.com/Memorithm/scirust) monorepo. This repository provides the user-facing CLI on top of those shared primitives.

## Current CLI

Create a deterministic capsule by mapping portable capsule paths to regular
source files explicitly:

```text
scicapsule pack \
  --name demo \
  --entrypoint bin/run \
  --output demo.scicap \
  --max-files 4096 \
  --max-bytes 1073741824 \
  bin/run=./run.bin \
  data/input.bin=./input.bin
```

`pack` bounds both payload count and aggregate payload bytes. On Unix each
source is opened as a regular file with no-follow/nonblocking semantics. The
output uses create-new semantics, is synchronized after a successful write, and
never silently overwrites an existing path. These product limits do not change
the canonical `.scicap` schema or deterministic encoding.

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
corresponding private key.

## Explicit trust policies

Trust policy v1 promotes explicitly selected public keys into local trust
anchors without adding trust metadata to `.scicap` or to signature envelopes.
Policies can require more than one distinct trusted signer.

Create a policy requiring two of three configured keys:

```text
scicapsule create-trust-policy \
  --output release-policy.json \
  --require 2 \
  release-a=release-a-public.pem \
  release-b=release-b-public.pem \
  recovery=recovery-public.pem
```

Then evaluate one or more detached signatures against that policy:

```text
scicapsule verify-trusted demo.scicap \
  --policy release-policy.json \
  --signature demo.release-a.sig \
  --signature demo.release-b.sig
```

The threshold counts distinct trusted keys, not signature files. Repeating the
same signature or producing multiple signatures from one trusted key cannot
satisfy a multi-key threshold. Signatures from keys absent from the local
policy do not count. Trust policies and security-sensitive sidecars are bounded
and opened with no-follow semantics on Unix.

## Trusted bounded execution

On Unix, `run` verifies canonical capsule integrity and the explicit local trust
policy before materializing or launching any payload. It then executes exactly
the manifest entrypoint, directly and without shell interpolation:

```text
scicapsule run demo.scicap \
  --policy release-policy.json \
  --signature demo.release-a.sig \
  --signature demo.release-b.sig \
  --timeout-seconds 30 \
  --max-files 4096 \
  --max-bytes 1073741824 \
  --env LANG=C \
  -- --example literal-argument
```

The run directory is private and temporary, the entrypoint working directory is
the materialized capsule root, inherited environment variables are cleared,
stdin is null, and only explicit `--env NAME=VALUE` entries are added. Arguments
after `--` are passed verbatim. A wall-clock timeout and a dedicated Unix
process group prevent the entrypoint and its descendants from outliving the
runner.

**This is not an OS sandbox.** SciCapsule v1 does not isolate filesystem access,
networking, syscalls, user privileges, CPU, or memory. Use an external sandbox,
container, VM, or other OS isolation layer when executing hostile payloads.
Non-Unix execution fails closed rather than silently weakening these process
lifecycle guarantees.

## SciRust Hub contract

SciCapsule exposes a versioned process contract for SciRust Hub without adding
Hub metadata to `.scicap`. A Hub run uses three immutable input artifacts — the
canonical capsule, the local trust policy, and a deterministic execution request
containing detached signatures and bounded run options — and produces one
required machine-readable result artifact.

Create a request artifact from the signatures and run options:

```text
scicapsule create-hub-request \
  --output request.json \
  --signature demo.release-a.sig \
  --signature demo.release-b.sig \
  --timeout-seconds 30 \
  --env LANG=C \
  -- --example literal-argument
```

Generate a SciRust Hub schema-v1 component manifest. The executable path is
explicit and absolute so Hub never relies on `PATH` lookup for the component:

```text
scicapsule hub-manifest \
  --component-id 00000000-0000-0000-0000-000000000001 \
  --program /opt/scicapsule/bin/scicapsule \
  --output scicapsule-component.json
```

The generated component declares capability `capsule.execute`. Hub resolves its
`{input:capsule}`, `{input:policy}`, `{input:request}`, and `{output:result}`
placeholders as direct argv values. `hub-run` then performs canonical capsule
validation and local trust authorization before delegating to the same bounded
execution path as `scicapsule run`.

After that authorization decision, `hub-run` pins the exact verified capsule
bytes, exact policy bytes and validated signature envelopes into new files in a
private temporary snapshot directory. The delegated runner receives only these
snapshot paths, so replacing the original caller-controlled capsule or policy
path cannot change the bytes executed after the Hub-facing trust decision.

A successful result contains the exact capsule SHA-256, canonical manifest name
and entrypoint, matched local signer names, and required signature threshold. It
therefore describes the same pinned bytes supplied to execution. It contains no
timestamps, random IDs, host paths, or process IDs. On trust or execution
failure, `hub-run` exits non-zero and does not fabricate a success result.

`hub-run` also refuses an already-existing result destination before payload
execution. Final result publication still uses create-new semantics, so a
racing destination is never overwritten. That early check is not a
transactional reservation: if a path appears only after preflight, execution
may already have occurred before final publication fails closed.

The Hub contract does not strengthen the execution boundary into an OS sandbox;
it only makes the authorization and machine interface explicit and
reproducible. See [the Hub contract specification](docs/HUB_CONTRACT.md).

`pack`, `inspect`, `verify`, `extract`, `sign`, `verify-signature`,
`verify-trusted`, provenance commands, `run`, and the Hub adapter commands
preserve the canonical format boundary. Trust policy, provenance, Hub
orchestration, and execution remain separate product layers. See
[the packing contract](docs/PACKING.md),
[the security model](docs/SECURITY_MODEL.md),
[the detached signature specification](docs/SIGNATURES.md),
[the trust policy specification](docs/TRUST_POLICY.md),
[the provenance contract](docs/PROVENANCE.md),
[the execution security contract](docs/EXECUTION.md), and
[the SciRust Hub contract](docs/HUB_CONTRACT.md).
