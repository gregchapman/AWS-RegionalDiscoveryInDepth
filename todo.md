# Discovery In-Depth — TODO

## Project Context

This tool inventories AWS accounts and generates CloudFormation templates for
disaster recovery (recreate environment in a different region). The pipeline:
enumerate services → discover resources → generate IaC → assess gaps.

**Active customer:** Instem (account 048766100331, us-gov-west-1 → us-gov-east-1).
Environment: 30 EC2, 3 RDS (Aurora Postgres + 2 Oracle), 1 FSx Windows
(AD-joined), 4 NLBs, 44 SGs, 647 EBS snapshots, 10 KMS keys, 7 Lambda,
4 Transit Gateways, VPN to on-prem.

**Reference implementations:**
- `C:\RGS-Code\N-Able\n-able-nonprod\generated\` — Gold standard for template
  quality: typed params, SG cross-refs, compute AMI params, data tier snapshot
  restore, network tier LB wiring. Use as style target.
- `C:\RGS-Code\Instem-rgs-3808821-048766100331\20260731-175636\` — Latest Instem
  run with v3 graph-driven generator

**Architecture Decision Records:** `.kiro/steering/adr-*.md` (7 ADRs capturing
key decisions — read these before making architectural changes)

---

## Current State (as of 2026-07-31)

The v3 graph-driven IaC generator works end-to-end:

```
discover.py orchestrates:
  1. service_enumerator.py  → what services have resources
  2. auto_template.py      → generate discovery schemas for found services  
  3. deep_discover.py      → detailed inventory (YAML templates drive API calls)
  4. graph_discover.py     → architecture views + draw.io diagram
  5. cfn_schema_cache.py   → cache CFN schemas for immutables
  6. iac_blueprint.py (v3) → graph-driven CloudFormation templates
  7. dr_assess.py          → DR readiness gap report
```

**IaC generation pipeline:**
```
inventory → dependency_graph.py → ordered deployment groups
    → schema_template_generator.py → per-group CFN templates
    → iac_blueprint.py orchestrates, writes templates/ + DEPLOY.md
```

**Latest Instem output (10 templates, zero errors):**
- 00-foundation: VPC, 12 subnets, 14 route tables + routes, IGW, DHCP, NATs
- 01-security: 44 SGs with cross-ref !Ref and ingress rules
- 02-encryption: 10 KMS keys + aliases (KeySpec/KeyUsage/MultiRegion immutables)
- 03-data: Aurora cluster, 3 RDS (Oracle immutables), FSx with AD join config
- 04-dc_compute: 2 DCs (boot-first, AD health verification)
- 05-compute: 28 instances (SubnetId, source instance profiles, SGs)
- 06-network: 3 NLBs + TGs + Listeners wired
- 07-serverless: 7 Lambda + 4 EventBridge
- 08-supporting: 48 CW Alarms, 8 VPC Endpoints, 2 ACM, 3 SNS
- 09-connectivity: 1 TGW + 1 CGW + 1 VPN

---

## In Progress — Template Rendering Quality

Fixes committed but not yet tested in a fresh Instem run:
- ✅ SG ingress rules: now reads `IpPermissions` (was looking for wrong field name)
- ✅ DHCP options: parses `DhcpConfigurations[].Key/Values` structure correctly
- ✅ SNS topics: parses TopicName from TopicArn when not stored directly

**Still needed (next session):**
- SG egress rules: `IpPermissionsEgress` not yet rendered in template
- Multi-VPC: foundation takes `vpcs[0]`; should iterate or split per VPC
- VPC Endpoint subnet associations not rendered
- S3 Buckets not rendered in supporting tier (policy, lifecycle, versioning)
- `foreach_detail` pattern verification (KMS describe_key, SNS get_topic_attributes)
  — these immutable fields may not be in the inventory yet

---

## Planned (Priority Order)

### 1. Template Completeness Audit

Run v3 against Instem with all fixes, then:
- cfn-lint the output templates
- Compare resource-by-resource against the N-Able reference for quality
- Verify every resource in the inventory appears in exactly one template
  (or is explicitly in manual-steps.md / assessment-only)

### 2. Remediation IaC Generator

Prescriptive CFN to fix DR readiness gaps BEFORE a recovery is needed:
- AWS Backup plan + vault + cross-region copy rules
- S3 versioning + CRR for critical buckets
- DLM policies with cross-region copy
- AMI copy automation (Lambda + EventBridge)

### 3. Hand-Crafted Discovery Templates

Priority based on GovCloud prevalence:
- `ecs.yaml` — clusters, services, task definitions (chained)
- `eks.yaml` — clusters, node groups, Fargate profiles, addons
- `dynamodb.yaml` — tables, GSIs, streams, global tables
- `sqs.yaml` — queues, DLQ configs, policies
- `route53.yaml` — hosted zones + records (chained)

### 4. Deployment Orchestrator

Custom `deploy.py` consuming graph output (see ADR-0006).
Decision: NOT Sceptre — we need dynamic, discovery-driven deployment.

### 5. CFN Linting

Validate generated templates with cfn-lint before writing.

### 6. Import Mode

The `--mode import` flag (exact state reproduction) needs testing.

---

## Known Issues

- `auto_template.py` generates poor discovery schemas for many services
  (picks wrong operations, captures no fields)
- `foreach_detail` pattern in KMS/SNS templates not verified in deep_discover.py
- Foundation template takes first VPC only — breaks for multi-VPC accounts
- No egress rules in SG template (ingress only)
- Inventory field names are raw AWS API names with collision-safe suffixes
  (`SubnetId_SubnetId`, `IpPermissions` not `IngressRules`) — see ADR-0005
- Generator must always be tested against REAL inventory, not synthetic data

---

## Design Decisions Log

| Decision | Rationale |
|----------|-----------|
| Graph determines stack count | ADR-0001: adapts to any customer |
| Self-contained templates, no param files | ADR-0002: operator-readable, console-deployable |
| Bespoke handlers for SGs + LBs only | ADR-0003: relationship wiring can't be generic |
| Source instance profiles as params | ADR-0004: CCPM profiles may already exist in DR |
| Field names match AWS API exactly | ADR-0005: no normalization layer |
| Custom orchestrator, not Sceptre | ADR-0006: discovery-driven, not design-driven |
| .get() everywhere, iterate all lists | ADR-0007: never assume dimension or existence |
| Schemas cached to ~/.cfn-schemas/ | No hard dependency on live API at generation time |
| Assessment-only categories excluded | Snapshots/AMIs are inputs to restore, not deploy targets |
| DC detection from tags (Role: DC) | Works across CCPM-tagged customers |
| Gateway LBs excluded | Infrastructure-managed, not customer-recoverable |
| Shared TGWs (OwnerId ≠ account) excluded | Can't recreate resources owned by another account |
