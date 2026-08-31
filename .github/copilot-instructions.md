# SciCapsule repository agent instructions

Before repository changes, fetch and read the persistent off-main roadmap:

```bash
git fetch origin agent/ecosystem-roadmap && \
git show origin/agent/ecosystem-roadmap:.agent/SCICAPSULE_ECOSYSTEM_ROADMAP.yaml
```

Treat root `AGENTS.md` as mandatory bootstrap policy. If the roadmap is unavailable, fail closed for major schema-boundary, trust, execution, cross-repository contract, or merge decisions.

Preserve the canonical SciRust schema boundary and the distinctions between integrity, authenticity, local trust, bounded execution, and OS sandboxing.
