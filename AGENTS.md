# SciCapsule Agent Bootstrap Contract

Before autonomous coding, capsule schema-boundary work, trust/signature changes, execution-boundary changes, Hub/Verify integration, PR creation, or merge decisions, read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCICAPSULE_ECOSYSTEM_ROADMAP.yaml
```

For ML model/data/checkpoint packaging, reproducible ML execution, large-artifact handling, sandbox-boundary, Hub/Verify, or cross-repository ML work, also read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/ML_MATURITY_5_OF_5.yaml
```

The ML maturity overlay makes 5/5 an evidence-backed exit criterion. Large real model workloads must be packageable with immutable model/config/tokenizer/data/checkpoint identity; signatures establish authenticity under a trust policy, not scientific correctness; process supervision remains distinct from OS sandboxing.

If the roadmap or applicable ML overlay cannot be fetched or read, fail closed for major schema-boundary, trust, execution, cross-repository contract, or merge decisions. Read-only diagnosis is allowed.

SciCapsule is the portable capsule product layer. Canonical `.scicap` schema primitives remain owned in SciRust. Hub owns outer orchestration. SciRust-Verify owns evidence-dossier claim/verdict semantics.

Never equate integrity with authenticity, authenticity with local trust, or bounded process execution with OS sandboxing. Never place private keys or implicit trust anchors inside capsules.

Required CI must be green on the exact PR head before merge. A 5/5 ML packaging/execution claim additionally requires the applicable large-artifact, reproducible-request, external-isolation and Hub/Verify interoperability gates in the ML overlay.

Reread the roadmap and applicable ML overlay at every session start, before schema/trust/execution/Hub/Verify changes, before cross-repository packaging work, after ML-priority changes, and before merge decisions.

Do not merge the roadmap or ML maturity overlay itself into `main` unless the user explicitly requests it.
