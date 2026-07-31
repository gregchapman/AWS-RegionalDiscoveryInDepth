---
inclusion: auto
---

# ADR-0003: Bespoke Handlers for SGs and Load Balancers

Date: 2026-07-31
Status: Accepted

## Context

A fully generic schema-driven generator can emit valid CFN for most resource types.
However, two resource categories require relationship-aware logic that a generic
property dump cannot produce:

1. **Security Groups** — Cross-SG ingress rules must use `!Ref` within the same
   template. Self-referencing rules require separate `SecurityGroupIngress` resources
   to avoid circular dependency. These patterns cannot be derived from schema alone.

2. **Load Balancers** — The LB → Listener → TG → Target chain requires ordered
   wiring. DefaultActions reference TGs by `!Ref`. TLS listeners need conditional
   certificate handling. Target Groups must be in the same template as their LB
   for the Ref to resolve.

## Decision

SGs and LBs get purpose-built generators that understand their relationship
semantics. Everything else goes through the standard per-tier generators
(foundation, compute, data, serverless, connectivity, supporting) which emit
resources with proper typed parameters and cross-stack ImportValue.

## Consequences

- SG cross-references always resolve correctly (no broken ImportValue chains)
- LB listener wiring is complete (action → TG → port)
- Adding a new "bespoke" tier requires writing a new generator function
- The dispatch logic in `generate_group_template()` routes groups by tier name
- Future candidates for bespoke handling: ECS services (task def → service → LB),
  Step Functions (state machine → Lambda targets)
