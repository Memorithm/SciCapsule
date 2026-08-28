# SciCapsule execution v1

## Scope

Execution v1 is a SciCapsule product-layer contract. It consumes the canonical
SciRust `.scicap` container without changing its schema or encoding.

The command is:

```text
scicapsule run FILE \
  --policy POLICY.json \
  --signature FILE.sig [--signature FILE.sig ...] \
  [--timeout-seconds N] \
  [--max-files N] \
  [--max-bytes N] \
  [--env NAME=VALUE ...] \
  [-- ARG ...]
```

Execution v1 is Unix-only. Unsupported platforms fail closed.

## Authorization order

`run` does not execute a capsule merely because it decodes successfully or has
a valid provenance statement. The order is deliberate:

1. bounded, no-follow capsule read;
2. canonical `Capsule::decode` integrity verification;
3. bounded local trust-policy read and validation;
4. bounded detached-signature reads;
5. trust-policy threshold evaluation over the exact capsule bytes;
6. private materialization;
7. exact manifest-entrypoint execution.

A signature key is trusted only when it is explicitly configured in the local
policy. Signature envelopes, provenance metadata, payload bytes, and the
capsule manifest cannot introduce trust roots.

## Materialization and entrypoint

The runner reuses SciCapsule's safe extraction implementation and its
file-count/total-byte limits. Materialization occurs below a private temporary
directory that is removed when the command ends.

The executed path is exactly the entrypoint carried by the validated canonical
manifest. The runner does not search `PATH`, reinterpret the manifest string, or
wrap the entrypoint in `sh -c` or another command shell. The materialized
entrypoint must be a regular file; the runner applies executable permission to
that file after materialization.

The child working directory is the root of the materialized capsule, making
relative file access within the capsule deterministic with respect to the
runner.

## Arguments and environment

The inherited host environment is cleared before launch. Only explicitly
provided `--env NAME=VALUE` pairs are added. Duplicate names are rejected.
Execution v1 accepts at most 128 environment entries and at most 64 KiB of
combined explicit environment name/value bytes.

Arguments following `--` are passed directly to the entrypoint without shell
interpolation. Execution v1 accepts at most 256 arguments and at most 64 KiB of
combined argument bytes.

Stdin is connected to null. Stdout and stderr are inherited from SciCapsule so
normal program output remains visible to the caller.

## Lifecycle bounds

The default wall-clock timeout is 300 seconds. The caller may select a positive
value up to 86400 seconds.

The entrypoint is launched in a dedicated Unix process group. On timeout the
whole group is killed, not only the initial child. A process-group cleanup guard
also runs on other command exits, so descendants are not permitted to outlive
the SciCapsule `run` invocation.

The existing extraction limits remain independently configurable with
`--max-files` and `--max-bytes`.

## Not a sandbox

Execution v1 is intentionally not described as a sandbox. Trust and bounded
process lifecycle do not make arbitrary code safe.

SciCapsule v1 does **not** isolate or deny:

- filesystem access outside the materialized capsule;
- network access;
- syscalls;
- credentials, UID/GID capabilities, or host privileges;
- child-process creation while the run is active;
- CPU or memory consumption;
- devices, IPC, namespaces, or other host resources.

If the payload may be hostile, invoke SciCapsule from an external isolation
boundary that actually implements the controls required by the deployment,
such as a hardened container, VM, namespace/seccomp sandbox, or equivalent OS
mechanism.

## Provenance separation

DSSE-wrapped in-toto/SLSA provenance remains a separate evidence layer.
`verify-provenance` can authenticate and validate that evidence, but execution
v1 does not treat provenance alone as authorization. The authorization gate for
`run` is the explicit local trust policy applied to detached signatures over
the exact capsule bytes.
