---
inclusion: auto
---

# ADR-0001: Graph-Driven Deployment Groups

Date: 2026-07-31
Status: Accepted

## Context

The v1 IaC blueprint hardcoded 8 deployment tiers (00-foundation through 06-supporting).
This was an artifact of one customer's environment (N-Able). A different customer might
need 3 stacks or 20. The number of deployment groups should be an *output* of analyzing
resource dependencies, not an assumption baked into code structure.

## Decision

Deployment group count and composition are determined by a dependency graph
(`dependency_graph.py`). Resources are assigned to tiers based on their CFN type
and known ordering patterns. Tiers are partitioned into groups respecting the
CFN 500-resource limit (we cap at 200 for operational sanity). If a customer has
5 resources, they get fewer stacks. If they have 3000, the graph splits appropriately.

## Consequences

- Output structure adapts to any customer environment automatically
- No code changes needed when a new customer has a different resource mix
- The v1 generator is preserved as `iac_blueprint_v1.py` (accessible via `--v1`) for
  regression safety during transition
- Testing must verify against multiple customer environments (N-Able, Instem, OAG)
  since output shape varies
