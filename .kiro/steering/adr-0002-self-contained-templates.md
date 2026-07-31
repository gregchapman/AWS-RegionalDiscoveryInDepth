---
inclusion: auto
---

# ADR-0002: Self-Contained Templates (No Separate Param Files)

Date: 2026-07-31
Status: Accepted

## Context

An earlier iteration used Sceptre-style separation: one generic template per
resource type + one parameter file per resource instance. This is elegant for
DevOps "build once, drift" workflows but produces output that requires correlating
two files to understand what's being deployed. In a DR scenario, a human deploys
this once, under pressure, and needs to read the template top-to-bottom.

The N-Able reference implementation proved that self-contained templates —
parameters with typed defaults, resources with full config, deploy command in
the header — are what operators actually use.

## Decision

Each template is self-contained and deployable:
- Parameters use proper CFN types (`AWS::EC2::Image::Id`, `AWS::EC2::Subnet::Id`)
- Source-region values appear as `Default` on each parameter
- No separate params directory; one template per deployment group is the artifact
- Each template header includes the `aws cloudformation create-stack` command
- Templates can be deployed via console (fill in blanks) or CLI (override params)

## Consequences

- Templates are readable as standalone documents
- Sceptre-style template reuse is not supported (acceptable: we deploy once)
- Larger YAML files per template (all resources + all params in one file)
- Operators don't need to hunt for matching param files
- The "prove our work" test is: can you read this template and understand
  exactly what it creates, in what order, with what dependencies?
