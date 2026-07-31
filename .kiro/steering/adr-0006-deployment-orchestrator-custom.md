---
inclusion: auto
---

# ADR-0006: Custom Deployment Orchestrator (Not Sceptre)

Date: 2026-07-31
Status: Accepted

## Context

Sceptre is an established CFN deployment tool that handles stack ordering,
parameter passing, and hooks. However:

- Sceptre assumes a "build once, drift" model — you designed the infrastructure
  and want to keep it stable
- We do the inverse: discovery-first, reproduce-what-exists
- Sceptre is static; our deployment sequence is dynamic (determined by graph)
- The orchestrator must be embedded in the customer deliverable, not an external
  tool dependency they need to install

Options considered:
1. Sceptre (existing tool, battle-tested)
2. Custom `deploy.py` (tight coupling to our graph output)
3. Hybrid (generate Sceptre config from graph)

## Decision

Custom orchestrator that directly consumes the graph's output. The deployment
guide (`DEPLOY.md`) is the human-readable orchestration artifact. A future
`deploy.py` will automate the sequence but the templates are designed to be
deployable manually via console or CLI without any orchestrator.

Sceptre's patterns remain a style target for output quality, but its runtime
is not a dependency.

## Consequences

- No external tool dependency for customers
- Templates must be self-deployable (no Sceptre resolver magic)
- DEPLOY.md is the "runbook" — ordered table with pre/post steps
- Future orchestrator will read DEPLOY.md or the graph directly
- Trade-off: we own the event-polling and rollback logic if automated
