# SciCapsule Agent Bootstrap Contract

Before autonomous coding, capsule schema-boundary work, trust/signature changes, execution-boundary changes, Hub/Verify integration, PR creation, or merge decisions, read:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCICAPSULE_ECOSYSTEM_ROADMAP.yaml
```

If the roadmap cannot be fetched or read, fail closed for major schema-boundary, trust, execution, cross-repository contract, or merge decisions. Read-only diagnosis is allowed.

SciCapsule is the portable capsule product layer. Canonical `.scicap` schema primitives remain owned in SciRust. Hub owns outer orchestration. SciRust-Verify owns evidence-dossier claim/verdict semantics.

Never equate integrity with authenticity, authenticity with local trust, or bounded process execution with OS sandboxing. Never place private keys or implicit trust anchors inside capsules.

Required CI must be green on the exact PR head before merge.

Reread the roadmap at every session start, before schema/trust/execution/Hub/Verify changes, before cross-repository packaging work, and before merge decisions.

Do not merge the roadmap itself into `main` unless the user explicitly requests it.
