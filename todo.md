# Discovery In-Depth — TODO

## Completed

### Chained Calls (foreach) — DONE

The template engine now supports `foreach` directives for per-resource
follow-up API calls. This replaces the originally planned `secondary_calls`
concept with a simpler, more composable approach.

Implemented in:
- `deep_discover.py` — `discover_service()` handles `foreach` operations
- `templates/elbv2.yaml` — Listeners, Listener Rules, Registered Targets
- `templates/rds.yaml` — full RDS supporting resources
- `templates/s3_replication.yaml` — Versioning, Replication, Lifecycle per bucket
- `templates/backup.yaml` — Backup Selections per Plan

### DR Readiness Discovery Templates — DONE

New templates for comprehensive backup/replication gap analysis:
- `s3_replication.yaml` — versioning, CRR config, lifecycle per bucket
- `backup.yaml` — vaults, plans, selections, protected resources
- `ebs_snapshots.yaml` — snapshots (owner=self), volumes, DLM policies
- `ami_inventory.yaml` — AMIs (owner=self), instance-to-AMI mapping
- `fsx.yaml` — file systems (all types), backups, data repository associations
- `vpn.yaml` — customer gateways, VPN connections, virtual private gateways
- Enhanced `secretsmanager.yaml` — ReplicationStatus, PrimaryRegion
- Enhanced `vpc.yaml` — DHCP Option Sets
- Enhanced `elbv2.yaml` — Listeners, Rules, Targets (chained)
- Enhanced `rds.yaml` — Clusters, Subnet Groups, Parameter Groups, Option Groups

### IaC Blueprint Expansion — DONE

CFN_TYPE_MAP expanded from 24 to 53 entries. Added BESPOKE_HANDLED set
for categories that have custom generators or are purely diagnostic.

### DR Readiness Assessment (`dr_assess.py`) — DONE

Standalone script (also integrated as Step 6 in `discover.py`) that reads
inventory and produces `dr-gaps.md`:

- 10 severity-ranked checks (Critical, High, Medium, Info)
- DNS/AD boot-order dependency detection from DHCP options
- S3 versioning and CRR gap analysis (per-bucket)
- Secrets Manager replication status check
- AWS Backup plan and coverage analysis
- EBS snapshot coverage vs DLM policy analysis
- AMI ownership gap (marketplace AMIs used but not owned)
- FSx backup and cross-region copy readiness
- SSM Parameter Store replication needs
- VPN connectivity DR considerations
- Target group re-registration requirements
- Recommended recovery sequence based on findings

## In Progress

### IaC Blueprint Rewrite — Tier-Based Templates with Rich YAML Params

The current `iac_blueprint.py` produces generic one-template-per-type output
that's too thin to be useful and generates noise for assessment-only categories.

**Status: COMPLETE — Phase 1 (noise elimination) + Phase 2 (tier templates) done.**

**Phase 1 — DONE:**
- `ASSESSMENT_ONLY` set (18 categories) — EBS Snapshots, AMIs, S3 Versioning,
  DLM Policies, FSx Backups, auto-template catalog data — all silently skipped
- Clean separation: BESPOKE_HANDLED (10), ASSESSMENT_ONLY (18), NO_CFN (2), CFN_TYPE_MAP (54)

**Phase 2 — DONE:**
Full rewrite to tier-based output:

```
00-foundation.yaml      VPC, Subnets, Route Tables, DHCP Options, NAT Gateways
01-security-groups.yaml All SGs with cross-references resolved via Ref
02-data-tier.yaml       RDS/Aurora + param groups + option groups + FSx (AD-joined)
03a-dc-compute.yaml     Domain Controllers (boot-order critical, deploy FIRST)
03-compute-tier.yaml    All other EC2 instances with full config
04-network-tier.yaml    LBs + Listeners + TGs wired with Ref
05-serverless.yaml      Lambda + EventBridge rules
06-supporting.yaml      VPC Endpoints, KMS, ACM, SNS, TGW, VPN, CW
```

Each tier template:
- Groups related resources into one CFN stack with internal wiring
- Uses `!ImportValue` for cross-stack dependencies (SG IDs, VPC ID)
- Includes all tags from source for traceability
- YAML parameter files with comments showing source values
- Empty keys with REQUIRED markers for DR-specific values

**Phase 3 — DONE: Immutables Enforcement**
- `cfn_schema_cache.py` fetches and caches CFN Resource Type Schemas
- `cfn_immutables.py` audits templates against schemas to find gaps
- `iac_blueprint.py` calls `enforce_immutables()` at param generation time
- If a `createOnlyProperty` is not in inventory, it's forced into the
  parameter file with `⚠ IMMUTABLE` warnings
- `discover.py` pipeline builds schema cache before IaC generation (Step 5)
- Graceful degradation: works without cache, just skips enforcement

**Immutable Properties Added to Discovery Templates:**
- EC2: Tenancy, PlacementGroup, HostId, BlockDeviceMappings, CpuOptions,
  MetadataOptions, CreditSpecification, NetworkInterfaces, HibernationOptions
- RDS: CharacterSetName, NcharCharacterSetName, LicenseModel, NetworkType,
  Iops, StorageThroughput, AvailabilityZone, DedicatedLogVolume
- RDS Clusters: GlobalClusterIdentifier, ServerlessV2ScalingConfiguration, NetworkType
- FSx: FileSystemTypeVersion, Lustre PerUnitStorageThroughput/DriveCacheType,
  ONTAP HAPairs, OpenZFS section
- ELBv2 TGs: ProtocolVersion, IpAddressType, HealthCheckTimeoutSeconds
- KMS: KeySpec, KeyUsage, MultiRegion, Origin (via describe_key foreach)
- VPC: InstanceTenancy, Ipv6CidrBlockAssociationSet, CidrBlockAssociationSet
- Subnets: Ipv6Native, AssignIpv6AddressOnCreation, AvailabilityZoneId
- ElastiCache: TransitEncryptionMode, NetworkType, ClusterEnabled, DataTiering
- SNS: FifoTopic, ContentBasedDeduplication (via get_topic_attributes foreach)
- VPN: EnableAcceleration, OutsideIpAddressType, IPv6 CIDRs

### Remediation IaC Generator

Prescriptive CloudFormation stacks to fix identified gaps:
- AWS Backup plans with cross-region copy rules
- S3 CRR configurations for critical buckets
- DLM policies with cross-region copy for uncovered volumes
- Scheduled AMI copy automation (Lambda + EventBridge)

## Planned

### Sceptre-Style Deployment Orchestrator

The IaC blueprint already produces the Sceptre-compatible structure:
one template per resource type, one parameter file per resource instance.
What's missing is the orchestration layer that deploys them in dependency
order with blast radius control.

**Why Sceptre's approach works for DR:**
- Stack groups = blast radius boundaries (deploy security tier, then data, then compute)
- Python hooks = pre/post-create logic (wait for AD health, register targets, validate connectivity)
- Dependency DAG = correct ordering without manual sequencing
- Partial launch = deploy a single stack group without touching others
- Drift detection = verify deployed state matches inventory

**Options:**

1. **Use Sceptre directly** — Generate `sceptre/` project structure from inventory.
   Sceptre uses boto3 internally so GovCloud works (set `region: us-gov-west-1`
   in stack configs). The GovCloud "support" issue in their repo is a CI/testing
   gap, not a functional one. Validate by running against a GovCloud account.
   - Pro: Mature tool, Python hooks, community support
   - Con: External dependency, may have edge cases in GovCloud endpoints

2. **Build a lightweight orchestrator** — A `deploy.py` that reads a simple
   YAML dependency graph, calls CloudFormation directly via boto3, supports
   pre/post hooks as Python callables, and handles stack groups.
   - Pro: Zero dependencies, full control, guaranteed GovCloud support
   - Con: Maintaining our own orchestrator, reinventing solved problems

3. **Hybrid** — Generate both `DEPLOY.md` (current human-readable approach) AND
   a `sceptre/` project structure. Operators choose their comfort level.

**Implementation (whichever option):**
- `iac_blueprint.py` gains a `--orchestrator sceptre|native|both` flag
- Generates stack group configs with dependency ordering
- Hook scripts for: AD health wait, target registration, DNS validation
- Parameter resolution from inventory cross-references (SG ID → new SG ID)

**Blast radius groups (deploy order):**
```
01-foundation/     VPCs, Subnets, Route Tables, DHCP Options
02-security/       Security Groups, KMS Keys, ACM Certs
03-network/        NAT Gateways, VPC Endpoints, TGW, VPN
04-identity/       Directories, IAM Roles
05-data/           RDS, ElastiCache, FSx, DynamoDB (restore from backup)
06-compute/        EC2, ASGs, ECS, EKS
07-routing/        Load Balancers, Target Groups, Listeners
08-serverless/     Lambda, Step Functions, EventBridge
09-dns/            Route 53, DHCP Option Set updates
10-monitoring/     CloudWatch Alarms, SNS Topics
```

### Route 53 Record Set Discovery

For accounts that have hosted zones, add chained discovery:
- `list_resource_record_sets` per hosted zone
- Captures all A, CNAME, ALIAS records for DNS reconstruction in DR

### Container Service Templates

- `eks.yaml` — clusters, node groups, Fargate profiles
- `ecr.yaml` — repositories, image tags, lifecycle policies
- `ecs.yaml` — clusters, services, task definitions (chained)

### View Files for graph_discover.py

User-controlled category selection for architecture diagrams:
- `--view path/to/view.yaml` parameter
- Example views: compute-only, data-tier, serverless, container-platform
- Documented in README

### Noise Reduction in manual-steps.md

The auto-template generator creates categories for AWS service catalog
data (Health Event Types, Artifact Reports, pricing) that shouldn't
appear in manual-steps.md. Options:

1. Add a `catalog_noise` set to `iac_blueprint.py` that suppresses these
2. Filter by source: auto-generated templates produce `auto_generated: true`
   in the template — skip those categories in IaC output
3. Only include categories in manual-steps that come from hand-crafted templates

### CFN Linting

Validate generated templates with cfn-lint before writing. Catch issues
like invalid resource property combinations before the user tries to deploy.

### Import Mode Validation

The `--mode import` flag (exact state reproduction vs DR parameterized)
needs testing against real deployments. Currently only `--mode dr` is
well-tested.
