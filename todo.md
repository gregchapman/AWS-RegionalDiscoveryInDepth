# Discovery In-Depth — TODO

## Project Context

This tool inventories AWS accounts and generates CloudFormation templates for
disaster recovery (recreate environment in a different region). It runs as a
pipeline: enumerate services → discover resources → generate IaC → assess gaps.

**Active customer test case:** Instem (account 048766100331, us-gov-west-1).
They want to simulate their region being unavailable and rebuild in us-gov-east-1.
Their environment: 30 EC2, 3 RDS (Aurora Postgres + 2 Oracle), 1 FSx Windows
(AD-joined), 4 NLBs, 44 SGs, 647 EBS snapshots, 10 KMS keys, 7 Lambda,
4 Transit Gateways, VPN to on-prem.

**Reference implementations:**
- `C:\RGS-Code\N-Able\n-able-nonprod\generated\` — Earlier manually-guided
  tier templates (01-security-groups through 05-serverless) showing correct
  patterns for SG cross-refs, compute AMI params, data tier snapshot restore,
  network tier LB wiring with ALB listener rules
- `C:\RGS-Code\Instem-rgs-3808821-048766100331\2026073100\` — Latest full
  pipeline run with updated code

---

## Critical Next Step: Graph-Driven IaC Generation

### Problem Statement

The current `iac_blueprint.py` has two fundamental flaws:

1. **Hardcoded tier structure.** It assumes 8 output files (00-foundation through
   06-supporting). This is an artifact of one customer's environment. A different
   customer might need 3 stacks or 20. The number of deployment groups should be
   an *output* of analyzing the dependency graph, not a hardcoded assumption.

2. **Only handles resources with bespoke generator functions.** If the inventory
   contains EKS, DynamoDB, Cognito, API Gateway, SQS, Step Functions, or any
   service we haven't written a specific generator for, those resources are
   silently dropped. We invested in CFN schemas that know every property of every
   resource type — we should be using them to generate templates dynamically for
   ANY resource in the inventory.

### Required Architecture

The new `iac_blueprint.py` should work like this:

```
INVENTORY (any resource)
    ↓
MAP to CFN type (CATEGORY_TO_CFN_TYPE + dynamic lookup)
    ↓
PULL CFN schema (cfn_schema_cache.py — all properties, immutables, dependencies)
    ↓
BUILD DEPENDENCY GRAPH
  - VPC before Subnet before NAT/Endpoints
  - SGs before anything that references them
  - KMS before anything encrypted
  - DCs/Directories before AD-joined resources (FSx, domain-joined EC2)
  - Subnet Groups before RDS/ElastiCache
  - LBs before Listeners, TGs before Listener actions
  - Compute before Target Registration
    ↓
PARTITION GRAPH into deployment groups (blast radius boundaries)
  - Each group = one CFN stack
  - Group size limited by CFN resource limit (500) and logical affinity
  - Groups ordered by dependency (no group deploys before its dependencies)
    ↓
GENERATE TEMPLATE per group
  - For each resource: emit ALL properties from inventory that match the schema
  - Region-specific values → Parameters (with source value in comments)
  - Immutable properties → forced into template or params with warnings
  - Cross-group references → !ImportValue
  - Intra-group references → !Ref
    ↓
GENERATE PARAMS per group
  - YAML with comments showing source values
  - IMMUTABLE properties called out explicitly
  - REQUIRED markers for values not in inventory
    ↓
GENERATE DEPLOY.md
  - Deployment order from graph
  - Pre/post steps per group (AD health check, target registration, etc.)
```

### Key Design Principles

1. **No hardcoded tier names or counts.** The output structure is determined by
   the graph, not by the code structure.

2. **Schema-driven property emission.** For any resource in inventory, look up
   its CFN type schema. Emit every property that exists in both the inventory
   config AND the schema. Don't hardcode which fields to emit per resource type.

3. **Bespoke handling for complex wiring only.** Some resources need special
   treatment that a generic approach can't handle:
   - SG self-referencing rules (need separate SecurityGroupIngress resources)
   - LB → Listener → TG → Target chain (ordering and action wiring)
   - DC boot-order detection (from tags or DHCP DNS server IPs)
   - FSx AD-join dependency
   These stay as specialized logic, but the *default path* for any resource
   should be schema-driven generation.

4. **The service enumerator finds it, the schema handles it.** If a customer
   has EKS and we have no hand-crafted template for it, the auto-template
   system captures what it can, and the IaC generator uses the CFN schema to
   know what properties exist and which are immutable. We don't need to
   anticipate every service — the schema IS the anticipation.

5. **Dependency graph comes from CFN schema `dependencies` + known patterns.**
   The schema tells us which properties reference other resource types
   (e.g., SubnetId references a Subnet). Combined with a small set of known
   ordering rules (VPC → Subnet → SG → Compute), we can auto-derive order.

### Implementation Plan

1. Build a `dependency_graph.py` module:
   - Input: inventory categories + their CFN types
   - Derives edges from: property references, known patterns, AD dependencies
   - Outputs: ordered list of deployment groups with resources assigned

2. Build a `schema_template_generator.py` module:
   - Input: resource config dict + CFN schema
   - Outputs: CFN resource properties block with all matching fields
   - Handles: parameterization of region-specific values, immutable marking

3. Rewrite `iac_blueprint.py` to orchestrate:
   - Load inventory → map to CFN types → build graph → partition → generate
   - Keep bespoke handlers for SGs (cross-refs) and LBs (action wiring)
   - Everything else goes through the generic schema-driven path

4. Retain the current bespoke generators as fallbacks:
   - If a resource type has a bespoke handler AND is in inventory, use it
   - Otherwise, fall through to schema-driven generation
   - This means Instem's output doesn't regress while we build the generic path

---

## Completed

### Chained Calls (foreach) — DONE

The template engine supports `foreach` directives for per-resource
follow-up API calls (Listeners per LB, Rules per Listener, etc.).

### DR Readiness Discovery Templates — DONE

Templates for backup/replication gap analysis: s3_replication, backup,
ebs_snapshots, ami_inventory, fsx, vpn, secretsmanager, vpc, elbv2, rds.

### DR Readiness Assessment (`dr_assess.py`) — DONE

Produces `dr-gaps.md` with 10 severity-ranked checks and recommended
recovery sequence.

### IaC Blueprint v1 (Tier-Based) — DONE (but being superseded)

Current `iac_blueprint.py` produces 8 tier templates for Instem's environment:
00-foundation, 01-security-groups, 02-data-tier, 03a-dc-compute,
03-compute-tier, 04-network-tier, 05-serverless, 06-supporting.

This works for Instem but doesn't generalize. Being replaced by graph-driven
approach (see above).

### CFN Schema Integration — DONE

- `cfn_schema_cache.py` — fetches/caches schemas from DescribeType
- `cfn_immutables.py` — audit tool comparing templates vs schemas
- `enforce_immutables()` in iac_blueprint.py — forces missing immutables
  into parameter files with warnings
- `discover.py` pipeline builds cache before IaC generation (Step 5)

### Immutable Properties Expansion — DONE

Discovery templates updated with all known immutable fields:
- EC2: Tenancy, PlacementGroup, HostId, BlockDeviceMappings, CpuOptions,
  MetadataOptions, CreditSpecification, NetworkInterfaces, HibernationOptions
- RDS: CharacterSetName, NcharCharacterSetName, LicenseModel, NetworkType
- RDS Clusters: GlobalClusterIdentifier, ServerlessV2ScalingConfiguration
- FSx: FileSystemTypeVersion, OpenZFS, Lustre PerUnitStorageThroughput
- ELBv2 TGs: ProtocolVersion, IpAddressType
- KMS: KeySpec, KeyUsage, MultiRegion (via describe_key foreach_detail)
- VPC: InstanceTenancy, IPv6 CIDRs
- ElastiCache: TransitEncryptionMode, NetworkType, ClusterEnabled
- SNS: FifoTopic, ContentBasedDeduplication (via get_topic_attributes foreach_detail)
- VPN: EnableAcceleration, TunnelInsideCidr, OutsideIpAddressType

---

## In Progress

### foreach_detail Pattern Validation

The KMS and SNS templates use a `foreach_detail` directive pattern
(call describe_key / get_topic_attributes per resource found by list operation).
This pattern needs verification that `deep_discover.py` actually supports it.
If not, either add support to the discovery engine or convert these to
standard `foreach` operations.

### Route Table Handling

The foundation tier creates subnets but doesn't recreate route table
associations or custom routes. Route tables have routes that reference
TGWs, NAT GWs, Internet GWs — all with region-specific IDs. Need to:
- Include route tables in foundation template
- Parameterize gateway references
- Associate route tables to subnets

---

## Planned (Priority Order)

### 1. Graph-Driven IaC Blueprint Rewrite

See "Critical Next Step" section above. This is the primary work item.

### 2. Remediation IaC Generator

Prescriptive CFN to fix DR readiness gaps BEFORE a recovery is needed:
- AWS Backup plan + vault + cross-region copy rules
- S3 versioning + CRR for critical buckets
- DLM policies with cross-region copy
- AMI copy automation (Lambda + EventBridge)

This goes into the *source region* to establish replication foundation.

### 3. Hand-Crafted Templates for Common Services

Priority based on GovCloud prevalence:
- `ecs.yaml` — clusters, services, task definitions (chained)
- `eks.yaml` — clusters, node groups, Fargate profiles, addons
- `dynamodb.yaml` — tables, GSIs, streams, global tables
- `sqs.yaml` — queues, DLQ configs, policies
- `route53.yaml` — hosted zones + `list_resource_record_sets` per zone
- `apigateway.yaml` — REST/HTTP APIs, stages, authorizers
- `stepfunctions.yaml` — state machines, activities
- `ecr.yaml` — repositories, lifecycle policies

### 4. Deployment Orchestrator

Options remain: Sceptre, custom deploy.py, or hybrid.
Decision deferred until graph-driven IaC generation is complete
(the orchestrator consumes whatever the graph produces).

### 5. CFN Linting

Validate generated templates with cfn-lint before writing.

### 6. Import Mode

The `--mode import` flag (exact state reproduction) needs testing.

---

## Known Issues

- `auto_template.py` generates poor discovery schemas for many services
  (picks wrong operations, captures no fields). Until the schema-driven
  IaC generator exists, services without hand-crafted templates get
  shallow coverage.
- The `foreach_detail` pattern in KMS/SNS templates may not be implemented
  in `deep_discover.py`. Needs verification on next live run.
- Route tables are discovered but not reproduced in IaC output.
- No per-resource param files in new approach (one param file per tier).
  May need to reconsider for environments with 100+ instances where a
  single compute param file becomes unwieldy.

---

## Design Decisions Log

| Decision | Rationale |
|----------|-----------|
| YAML param files, not JSON | Comments with source values, human-readable |
| Schemas cached to ~/.cfn-schemas/ | No hard dependency on live API at generation time |
| Immutables enforcement is graceful | Works without cache, just skips enforcement |
| Assessment-only categories excluded from IaC | Snapshots, AMIs, volumes are inputs to restore, not deploy targets |
| SG cross-refs resolved via Ref | Most reliable CFN pattern for circular SG dependencies |
| DC detection from tags (Role: DC) | Works across all customers who follow CCPM tagging |
| DCs separated into boot-first template | AD must be healthy before FSx and domain-joined compute |
| Gateway LBs excluded from network tier | Infrastructure-managed, not customer-recoverable |
| Shared TGWs (OwnerId ≠ account) excluded | Can't recreate resources owned by another account |
