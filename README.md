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

`inspect` and `verify` perform the same core integrity validation as `scirust-capsule::Capsule::decode`. Signature trust, provenance policy, extraction and execution are intentionally not part of this first operational CLI layer.
