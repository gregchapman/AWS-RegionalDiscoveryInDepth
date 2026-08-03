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
- `C:\RGS-Code\Instem-rgs-3808821-048766100331\20260803-144711\` — Latest Instem
  run (2026-08-03) with all fixes applied

**Architecture Decision Records:** `.kiro/steering/adr-*.md` (7 ADRs capturing
key decisions — read these before making architectural changes)

---

## Current State (as of 2026-08-03)

The v3 graph-driven IaC generator is functional and producing operator-ready
CloudFormation templates. Pipeline runs clean against Instem with zero errors.

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

**Latest Instem output (10 templates, 419 CFN resources, zero errors):**
- 00-foundation (171): VPC, 12 subnets, 14 route tables + routes + associations, IGW, 2 DHCP + associations, 2 NATs
- 01-security (75): 44 SGs with full ingress rules + 31 self-ref SecurityGroupIngress resources
- 02-encryption (20): 10 KMS keys (KeySpec/KeyUsage/MultiRegion immutables) + 10 aliases
- 03-data (11): Aurora cluster, 3 RDS (Port, IOPS, StorageThroughput, DeletionProtection, Monitoring, PerfInsights, Oracle immutables), FSx with AD join + backup retention + aliases
- 04-dc_compute (6): 2 DCs + SSM role + profile + 2 instance-bound CW alarms
- 05-compute (73): 28 instances (SubnetId, BDM with data volumes, MetadataOptions, source instance profiles, SGs) + SSM role/profile + 43 instance-bound CW alarms with `!Ref` dimensions
- 06-network (14): 3 NLBs + 5 TGs with registered targets (parameterized) + 6 Listeners
- 07-serverless (11): 7 Lambda (Role ARNs parameterized) + 4 EventBridge rules
- 08-supporting (35): 19 S3 buckets (non-CRR only, tagged NoCRR), 8 VPC Endpoints (with SubnetIds), 2 ACM, 3 SNS, non-instance CW alarms
- 09-connectivity (3): 1 TGW + 1 CGW + 1 VPN

---

## In Progress

### Remaining Template Gaps (lower priority)

- SG egress rules: `IpPermissionsEgress` not rendered (default allow-all is fine for most)
- Multi-VPC: foundation takes `vpcs[0]`; should iterate or split per VPC
- `foreach_detail` pattern (KMS describe_key, SNS get_topic_attributes) not verified
- Listener Rules with conditions (path/host routing) — code ready, untested on ALB customer
- Route53 hosted zones + record sets — discovery template exists, IaC generator doesn't render
- SSM Documents — regional scope, may need to be copied to DR region

---

## Planned (Priority Order)

### 1. Remediation IaC Generator

Prescriptive CFN to fix DR readiness gaps BEFORE a recovery is needed:
- AWS Backup plan + vault + cross-region copy rules
- S3 versioning + CRR for critical buckets
- DLM policies with cross-region copy
- AMI copy automation (Lambda + EventBridge)

### 2. Hand-Crafted Discovery Templates

Priority based on GovCloud prevalence:
- `ecs.yaml` — clusters, services, task definitions (chained)
- `eks.yaml` — clusters, node groups, Fargate profiles, addons
- `dynamodb.yaml` — tables, GSIs, streams, global tables
- `sqs.yaml` — queues, DLQ configs, policies
- `route53.yaml` — hosted zones + records (chained)

### 3. Deployment Orchestrator

Custom `deploy.py` consuming graph output (see ADR-0006).
Decision: NOT Sceptre — we need dynamic, discovery-driven deployment.

### 4. CFN Linting

Validate generated templates with cfn-lint before writing.

### 5. Import Mode

The `--mode import` flag (exact state reproduction) needs testing.

---

## Known Issues

- `auto_template.py` generates poor discovery schemas for many services
- `foreach_detail` pattern in KMS/SNS templates not verified in deep_discover.py
- Foundation template takes first VPC only — breaks for multi-VPC accounts
- No egress rules in SG template (default allow-all covers most cases)
- Inventory field names are raw AWS API with collision-safe suffixes — see ADR-0005
- Generator must always be tested against REAL inventory, not synthetic data
- CW Alarm Dimensions with `!Ref` are correct at deploy time but won't auto-update
  if instances are replaced outside CFN
- S3 bucket names with `dr-` prefix may conflict if customer has naming conventions

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
| CW alarms deploy with instances | Alarm must reference DR instance via !Ref, not hardcoded source ID |
| TG targets parameterized | IPs and instance IDs change in DR |
| S3 buckets: skip CRR-covered | CRR destination already exists in DR with data |
| Schemas cached to ~/.cfn-schemas/ | No hard dependency on live API at generation time |
| Assessment-only categories excluded | Snapshots/AMIs are inputs to restore, not deploy targets |
| DC detection from tags (Role: DC) | Works across CCPM-tagged customers |
| Gateway LBs excluded | Infrastructure-managed, not customer-recoverable |
| Shared TGWs (OwnerId ≠ account) excluded | Can't recreate resources owned by another account |
