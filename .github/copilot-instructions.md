# SciCapsule repository agent instructions

Before repository changes, fetch and read the persistent off-main roadmap:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCICAPSULE_ECOSYSTEM_ROADMAP.yaml
```

For ML model/data/checkpoint packaging, reproducible ML execution, large-artifact handling, sandbox-boundary, Hub/Verify, or cross-repository ML work, also read:

```bash
git show origin/agent/ecosystem-roadmap:.agent/ML_MATURITY_5_OF_5.yaml
```

Treat root `AGENTS.md` as mandatory bootstrap policy. If the roadmap or applicable ML overlay is unavailable, fail closed for major schema-boundary, trust, execution, cross-repository contract, or merge decisions.

Preserve the canonical SciRust schema boundary and the distinctions between integrity, authenticity, local trust, bounded execution, and OS sandboxing. A `5/5` ML packaging/execution claim requires large real-model artifact support, immutable model/config/tokenizer/data/checkpoint identity, reproducible execution requests, explicit isolation semantics and Hub/Verify interoperability.
