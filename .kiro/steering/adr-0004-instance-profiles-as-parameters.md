---
inclusion: auto
---

# ADR-0004: Source Instance Profiles as Parameters with SSM Fallback

Date: 2026-07-31
Status: Accepted

## Context

EC2 instances in CCPM-managed accounts have instance profiles created by the
management stack (e.g., `primary-CcpmNetworking-DC1InstanceProfile95081309-xxx`).
These profiles carry customer-specific policies beyond SSM. Recreating them in
the DR template would require enumerating every attached policy — data we don't
capture in the EC2 inventory.

Options considered:
1. Recreate identical IAM roles/profiles per instance (requires policy capture)
2. Use a single generic SSM-only profile for all instances (loses source policies)
3. Parameterize with source profile ARN as default, SSM fallback if unavailable

## Decision

Option 3. Each instance gets an `InstanceProfile` parameter with the source ARN
as `Default`. The description notes it must include `AmazonSSMManagedInstanceCore`.
A shared `EC2SSMRole` + `EC2SSMProfile` is created in the template as fallback
for instances without a captured profile or where the source profile doesn't
exist in DR.

## Consequences

- If CCPM deployed the same profiles in DR (same naming), defaults work as-is
- If not, operator sees exactly what was attached and can create equivalent
- SSM access is always guaranteed (either via source profile or fallback)
- We don't need to enumerate IAM policies in the discovery step
- Trade-off: operator must verify source profiles include SSM policy manually
