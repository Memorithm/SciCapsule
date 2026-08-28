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

`inspect`, `verify`, and `extract` perform the same core integrity validation as
`scirust-capsule::Capsule::decode`. Signature trust, provenance policy, and
execution are separate product layers and are not implied by successful
integrity verification or extraction. See [the security model](docs/SECURITY_MODEL.md).
