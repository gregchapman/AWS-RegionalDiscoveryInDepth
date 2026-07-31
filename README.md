# Discovery In-Depth — AWS Account Inventory & Visualization

## What This Does

Exhaustively inventories an AWS account/region and produces output for
diagramming tools, DR planning, compliance audits, cost analysis, and
audience-specific architecture views.

**Two documents, two audiences:**

- **This README** — How to run the tool, configure templates, understand the pipeline
- **[RECOVERY-GUIDE.md](RECOVERY-GUIDE.md)** — How to use the output to plan and execute disaster recovery (the "I have results, now what?" document)

Five scripts, one orchestrator:

| Script | Purpose | Speed |
|--------|---------|-------|
| `service_enumerator.py` | Fast scan — what services have resources? | ~90s |
| `auto_template.py` | Generate discovery schemas for found services | ~30s |
| `deep_discover.py` | Detailed inventory using all templates | ~60s |
| `graph_discover.py` | Audience-driven architecture views + draw.io diagram | ~10s |
| `cfn_schema_cache.py` | Cache CFN type schemas for immutables enforcement | ~60s |
| `iac_blueprint.py` | Graph-driven CloudFormation templates from inventory | ~15s |
| `dr_assess.py` | DR readiness gap analysis from inventory | ~5s |
| `cfn_immutables.py` | Audit tool — find uncaptured immutable properties | dev use |
| **`discover.py`** | **Orchestrator — runs the full pipeline with resume** | — |

## Quick Start

```bash
# Full pipeline — one command
python3 discover.py --label acme-prod --region us-east-1

# GovCloud
python3 discover.py --label govcloud-prod --region us-gov-west-1

# Adjust parallelism for the enumerator
python3 discover.py --label acme-prod --region us-east-1 --workers 30
```

## Output Directory Structure

Every run produces a timestamped, self-contained directory. The label
comes from the customer/project — each scan is a point in time.

```
output/
└── <label>/
    └── <region>/
        └── <YYYYMMDD-HHMMSS>/
            ├── enum-results.yaml              # Step 1: service enumeration
            ├── _discovery-schemas/            # Step 2: API discovery schemas (internal)
            │   ├── stepfunctions.yaml
            │   ├── codebuild.yaml
            │   └── ...
            ├── inventory-<region>.yaml         # Step 3: detailed inventory
            ├── inventory-<region>.json
            ├── inventory-<region>.csv          # draw.io CSV import format
            ├── inventory-<region>.mermaid.md
            ├── summary.txt
            ├── architecture-executive-<region>.md    # Step 4: audience views
            ├── architecture-engineering-<region>.md
            ├── architecture-operations-<region>.md
            ├── architecture-<region>.drawio          # Native draw.io diagram
            ├── iac-templates/                        # Step 5: CloudFormation templates
            │   ├── templates/                        #   One CFN template per deployment group
            │   ├── params/                           #   One param file per deployment group
            │   ├── DEPLOY.md                         #   Deployment order from graph
            │   └── manual-steps.md                   #   Resources needing manual action
            ├── dr-gaps.md                            # Step 6: DR readiness gap report
            └── errors.md                             # Error log for this run
```

## Resume / Retry

If a step fails (credential expiry, API throttling, network blip), fix
the issue and resume from where it left off:

```bash
python3 discover.py --resume output/acme-prod/us-east-1/20260504-183545/
```

The orchestrator checks for step completion markers in the run directory:
- `enum-results.yaml` exists → skip enumeration
- `_discovery-schemas/*.yaml` exist → skip template generation
- `inventory-*.yaml` exists → skip deep discovery
- `architecture-*.md` exists → skip graph discovery
- `iac-templates/templates/*.yaml` exist → skip IaC blueprint generation
- `dr-gaps.md` exists → skip DR assessment

Only incomplete steps re-run. Completed steps are never repeated.

## Running Steps Individually

Each script works standalone for targeted use:

```bash
# Step 1: Enumerate services
python3 service_enumerator.py --region us-east-1 --output enum-results.yaml

# Step 2: Generate templates for discovered services
python3 auto_template.py --from-enum enum-results.yaml --region us-east-1

# Step 3: Deep discovery with all templates
python3 deep_discover.py --region us-east-1 --output ./my-output \
  --templates ./templates --auto-templates ./auto-templates

# Step 4: Generate audience views from inventory
python3 graph_discover.py --input output/inventory-us-east-1.yaml --audience all
```

## Pipeline Steps

### Step 1: Service Enumeration (`service_enumerator.py`)

Probes every boto3 service in the target region to find which ones have
resources. No hardcoded per-service logic — introspects service models at
runtime to find the best list/describe operation for each service.

- Parallel execution (default 20 threads, configurable with `--workers`)
- Categorizes results: found, empty, access denied, not in region, error
- Outputs `enum-results.yaml` with counts and metadata

### Step 2: Auto-Template Generation (`auto_template.py`)

For services that have resources but lack hand-crafted templates,
auto-generates YAML discovery templates by introspecting boto3 output
shapes. Identifies result keys, ID fields, name fields, and config
fields automatically.

- Reads `enum-results.yaml` to know which services to target
- Skips services that already have hand-crafted templates
- Outputs to `auto-templates/` within the run directory

### Step 3: Deep Discovery (`deep_discover.py`)

Template-driven detailed inventory. Reads YAML templates and executes
the described API calls. Hand-crafted templates always take precedence
over auto-generated ones.

Output formats:

| File | Format | Use Case |
|------|--------|----------|
| `inventory-<region>.yaml` | YAML | Human review, DR planning, version control |
| `inventory-<region>.json` | JSON | Programmatic consumption, custom tooling |
| `inventory-<region>.csv` | CSV | draw.io CSV import, Lucidchart, Excel |
| `inventory-<region>.mermaid.md` | Mermaid | GitHub/Confluence rendering |
| `summary.txt` | Text | Quick resource counts |

### Step 4: Graph Discovery (`graph_discover.py`)

Reads the inventory and renders audience-specific architecture views.
No AWS API calls — pure data transformation.

| Audience | Focus | Detail Level |
|----------|-------|-------------|
| `executive` | HA, encryption, DR readiness | Abstract — no IDs or instance types |
| `engineering` | Topology, security posture, data flow, anomalies | Full — IDs, IPs, subnet placement |
| `operations` | Recovery priority, dependency chains, DR notes | Full — ordered by recovery sequence |

All three audiences include Mermaid topology diagrams inline.

Additionally generates a native **draw.io XML** file (`architecture-<region>.drawio`)
with:
- AWS Architecture Icons (mxgraph stencils)
- VPC containment with subnet grouping by AZ
- Traffic flow: Internet → LBs → Compute → Data tier
- NAT Gateways, VPC-attached Lambdas, public Lambdas
- Transit Gateway connections (local and remote)
- VPC Peering connections (local and cross-region/cross-account)

## Inventory vs. Diagram: What Gets Depicted

The inventory and the architecture diagram serve different purposes:

- **Inventory** (`inventory-*.yaml/json`) captures **everything** — every
  service that has resources gets recorded with full config details. This
  is your DR reference, compliance artifact, and data source for custom
  tooling.

- **Architecture diagram** (`architecture-*.drawio`) is **curated** — only
  resources that have a defined placement in the visual topology are
  rendered. Platform services (CloudWatch, Config, Trusted Advisor),
  catalog data (pricing, service quotas), and auto-discovered services
  without hand-crafted templates appear in the inventory but not the
  diagram.

This is intentional. A diagram with 6000+ resources is unreadable. The
diagram shows workload topology — what runs your application, how traffic
flows, and where the security boundaries are.

### Controlling What Appears in the Diagram

The `CATEGORY_TIERS` dict in `graph_discover.py` determines which
inventory categories are rendered. Each entry maps an operation name
(the category key in the inventory) to a tier and functional group:

```python
CATEGORY_TIERS = {
    'EC2 Instances':       ('workload', 'compute'),
    'RDS Instances':       ('workload', 'database'),
    'Lambda Functions':    ('workload', 'serverless'),
    'Load Balancers':      ('routing', 'load_balancing'),
    'VPCs':                ('boundary', 'network'),
    'Security Groups':     ('attached', 'security'),
    'CloudWatch Alarms':   ('platform', 'monitoring'),
    # ... etc
}
```

**Tiers:**
| Tier | Purpose | Example |
|------|---------|---------|
| `workload` | Things that run your application | EC2, RDS, Lambda |
| `routing` | Things that direct traffic | LBs, NAT, TGW |
| `boundary` | Things that contain other things | VPCs, Subnets |
| `attached` | Properties of other resources | SGs, certs, keys |
| `platform` | Logging, monitoring, compliance | CloudWatch, SNS |

**To add a service to the diagram:**
1. Create a hand-crafted template in `templates/` with a meaningful
   operation `name` (e.g., "Step Functions" not "List State Machines")
2. Add that name to `CATEGORY_TIERS` with the appropriate tier
3. The service will appear in the next scan's diagram and audience views

Categories NOT in `CATEGORY_TIERS` are silently excluded from the
diagram but remain in the inventory. The audience markdown views note
how many "noise" categories were excluded.

## Cross-Region & Cross-Account Visibility

The pipeline captures cross-region communication paths and renders them
in both the markdown views and the draw.io diagram.

### What's Captured

**VPC Peering Connections** — The `vpc_peering.yaml` template captures
both sides of every peering connection: requester VPC, accepter VPC,
their CIDRs, owner accounts, and regions. When one side is outside the
scanned region or account, it appears as a labeled dashed edge in the
draw.io diagram and is listed in the Cross-Region Dependencies section
of the engineering and operations views.

**Transit Gateway Attachments** — The `tgw.yaml` template captures TGW
attachments including the resource type, resource ID, and resource owner.
Attachments to VPCs in the current inventory get solid edges to the VPC
container. Attachments to resources outside the inventory (other regions,
other accounts) get dashed edges to a labeled text node showing the
remote resource type, ID, and owner account.

**RDS Cross-Region Read Replicas** — The `rds.yaml` template captures
`ReadReplicaSourceDBInstanceIdentifier` and
`ReadReplicaDBInstanceIdentifiers` from the existing
`describe_db_instances` response. When a replica source or target is not
in the current inventory, it's flagged as a likely cross-region
dependency.

### draw.io Rendering

| Connection Type | Local (both sides in inventory) | Remote (one side external) |
|----------------|--------------------------------|---------------------------|
| VPC Peering | Dashed edge between VPC containers | Dashed edge to labeled text node with remote VPC, region, account |
| TGW Attachment | Solid edge from TGW to VPC | Dashed edge to labeled text node with resource type, ID, account |
| RDS Replica | Listed in inventory | Flagged in Cross-Region Dependencies sections |

### Cross-Region Replication Detection

The template engine supports chained calls via `foreach` for per-resource
follow-up API calls. This enables detection of:

- **S3 CRR** — `s3_replication.yaml` calls `get_bucket_replication` per
  bucket. Buckets without entries have no CRR configured.
- **S3 Versioning** — `get_bucket_versioning` per bucket (required for CRR)
- **Secrets Manager replication** — `ReplicationStatus` and `PrimaryRegion`
  fields captured in `secretsmanager.yaml`
- **RDS cross-region read replicas** — captured from `describe_db_instances`
  response fields

Still planned:
- DynamoDB global tables (`describe_table` → `Replicas[]`)
- Aurora global databases (`describe_global_clusters`)
- ElastiCache global datastores (`describe_global_replication_groups`)

## Templates

### Hand-Crafted (`templates/`)

High-quality templates with curated field lists, DR notes, and skip
filters. 22 templates included covering core AWS services:


`acm`, `ami_inventory`, `autoscaling`, `backup`, `cloudwatch`,
`ebs_snapshots`, `ec2`, `elasticache`, `elb_classic`, `elbv2`, `events`,
`fsx`, `kms`, `lambda`, `nat_gateways`, `rds`, `route53`, `s3`,
`s3_replication`, `secretsmanager`, `security_groups`, `sns`, `ssm`,
`tgw`, `vpc`, `vpc_endpoints`, `vpc_peering`, `vpn`, `wafv2`

### Auto-Generated (`_discovery-schemas/` in run directory)

Created by `auto_template.py` from boto3 service model introspection.
Captures resource IDs, names, and top-level config fields. Good enough
for inventory — review and promote to `templates/` for production use.

Hand-crafted templates always take precedence over auto-generated ones.

**Note:** The `_discovery-schemas/` folder contains API discovery schemas
used internally by `deep_discover.py`. These are NOT CloudFormation
templates. Deployable CloudFormation templates are in `iac-templates/`.

### Adding a New Template

```yaml
service: my-service
client: my-service
display_name: My Service

operations:
  - name: My Resources
    method: describe_my_resources
    paginator: true
    result_key: MyResources
    id_field: ResourceId
    name_field: ResourceName
    tag_name: true
    key_prefix: mysvc
    dr_note: "Optional DR guidance"
    config_fields:
      - ResourceId
      - ResourceType
      - Status
      - nested.field.path
      - ListField[].SubField
```

### Template Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `service` | Yes | Unique service identifier |
| `client` | No | boto3 client name (defaults to service) |
| `display_name` | No | Human-readable name for output |
| `operations` | Yes | List of API operations to execute |
| `operations[].method` | Yes | boto3 method name (snake_case) |
| `operations[].paginator` | No | Use paginator (default: false) |
| `operations[].result_key` | No | Response key containing the resource list |
| `operations[].unwrap_key` | No | For nested lists (e.g., EC2 Reservations→Instances) |
| `operations[].id_field` | No | Field path for resource ID |
| `operations[].name_field` | No | Field path for resource name |
| `operations[].tag_name` | No | Extract Name from Tags list (default: false) |
| `operations[].key_prefix` | No | Prefix for resource_key (default: service name) |
| `operations[].dr_note` | No | DR-specific guidance text |
| `operations[].config_fields` | No | List of field paths to include in config |
| `operations[].kwargs` | No | Extra kwargs to pass to the API call |
| `operations[].skip_if` | No | Filter: skip resources matching field values |
| `operations[].foreach` | No | Chained call config — iterate parent results (see below) |

### Chained Calls (foreach)

Some APIs require a parent resource ID as input (e.g., describe_listeners
needs a LoadBalancerArn). The `foreach` directive iterates results from a
parent operation and calls the child API once per parent resource:

```yaml
  - name: Listeners
    method: describe_listeners
    result_key: Listeners
    id_field: ListenerArn
    foreach:
      parent_operation: Load Balancers    # must match a 'name' earlier in this template
      parent_field: LoadBalancerArn       # field from parent's config dict
      kwarg_name: LoadBalancerArn         # kwarg passed to the child API call
      attach_parent_field: LoadBalancerArn  # stored on each child for back-reference
    config_fields:
      - ListenerArn
      - Port
      - Protocol
```

| foreach field | Required | Description |
|---------------|----------|-------------|
| `parent_operation` | Yes | Name of the operation whose results to iterate |
| `parent_field` | Yes | Config field from parent to use as the call argument |
| `kwarg_name` | Yes | The boto3 keyword argument name for the child API |
| `attach_parent_field` | No | Field name to store the parent value on each child (default: `_parent_arn`) |

The engine handles per-call errors gracefully — if one parent's child call
fails (e.g., `get_bucket_replication` on a bucket without CRR), it logs a
warning and continues with the next parent.

### Field Path Syntax

- Simple: `InstanceId`
- Nested: `Endpoint.Address`
- List extraction: `SecurityGroups[].GroupId`

Collision-safe key handling: when two config fields resolve to the same
key (e.g., `RequesterVpcInfo.VpcId` and `AccepterVpcInfo.VpcId` both
produce `VpcId`), the engine disambiguates with parent prefixes
(`RequesterVpcInfo_VpcId`, `AccepterVpcInfo_VpcId`).

## Architecture

```
discover.py (orchestrator, --resume support)
  │
  ├─ Step 1: service_enumerator.py
  │    What services have resources?
  │    → enum-results.yaml
  │
  ├─ Step 2: auto_template.py
  │    Generate discovery schemas for services without hand-crafted ones
  │    → _discovery-schemas/*.yaml
  │
  ├─ Step 3: deep_discover.py
  │    Template-driven detailed inventory
  │    → inventory.yaml, .json, .csv, .mermaid.md, summary.txt
  │
  ├─ Step 4: graph_discover.py
  │    Audience-driven architecture views + draw.io diagram
  │    → architecture-{audience}-{region}.md
  │    → architecture-{region}.drawio
  │
  ├─ Step 5: iac_blueprint.py
  │    Graph-driven CloudFormation templates from inventory
  │    Uses: dependency_graph.py, schema_template_generator.py
  │    → iac-templates/templates/*.yaml (one per deployment group)
  │    → iac-templates/params/*.yaml
  │    → iac-templates/DEPLOY.md
  │
  └─ Step 6: dr_assess.py
       DR readiness gap analysis from inventory
       → dr-gaps.md (severity-ranked findings + recovery sequence)

All output lands in: output/<label>/<region>/<YYYYMMDD-HHMMSS>/
```

## Anomaly Detection

`graph_discover.py` automatically detects and flags:

- Security groups with `0.0.0.0/0` ingress
- EC2 instances with public IPs
- RDS instances that are publicly accessible
- RDS instances with unencrypted storage
- RDS instances with zero backup retention
- Lambda functions running outside a VPC

Anomalies are rendered with severity icons (🔴 critical, 🟡 warning,
🔵 info) in all audience views.

## Error Handling

Every run produces an `errors.md` in the run directory. Non-fatal errors
(e.g., auto-template generation failure) are logged but don't stop the
pipeline — deep discovery continues with hand-crafted templates only.
Fatal errors (enumeration failure, deep discovery failure) halt the
pipeline with a message to fix the issue and `--resume`.

## IaC Blueprint (`iac_blueprint.py`)

Transforms a discovery inventory into deployable CloudFormation templates.
Runs automatically as Step 5 of the pipeline. Can also be run standalone
to regenerate templates (e.g., after modifying include/exclude filters).

**Architecture (v3 — graph-driven):**

1. Load inventory from `deep_discover.py` output
2. Build a dependency graph (`dependency_graph.py`) — assigns resources to
   tiers, derives ordering from CFN schema references + known patterns
3. Partition into deployment groups (respecting CFN 500-resource limit)
4. Generate a CFN template per group:
   - Security Groups → bespoke handler (cross-SG `!Ref`, self-ref rules)
   - Load Balancers → bespoke handler (Listener→TG action wiring)
   - Everything else → schema-driven generation (`schema_template_generator.py`)
5. Generate `DEPLOY.md` with ordered deployment sequence from graph
6. Generate `manual-steps.md` for non-CFN resources

**Key modules:**

| Module | Purpose |
|--------|---------|
| `dependency_graph.py` | Graph builder, tier assignment, group partitioning |
| `schema_template_generator.py` | Generic CFN block generation from config + schema |
| `iac_blueprint.py` | Orchestrator — routes groups to handlers, writes output |
| `iac_blueprint_v1.py` | Previous tier-based generator (fallback via `--v1`) |

**Philosophy:** The number of output stacks is an *output* of analyzing
the dependency graph, not a hardcoded assumption. Any resource in the
inventory that has a CFN type mapping gets a template — no hand-crafted
generator function required.

### Usage

```bash
# Generate IaC from a discovery run (graph-driven, default)
python3 iac_blueprint.py --input output/acme-prod/us-east-1/20260505-151053/

# Fallback to v1 tier-based generator
python3 iac_blueprint.py --input output/acme-prod/us-east-1/20260505-151053/ --v1
```

### Output Structure

```
<run-directory>/iac-templates/
├── templates/                    ← One CFN template per deployment group
│   ├── 00-foundation.yaml
│   ├── 01-security.yaml
│   ├── 02-encryption.yaml
│   ├── 03-dc_compute.yaml       (only if DCs detected)
│   ├── 04-compute.yaml
│   ├── 05-network.yaml
│   ├── 06-serverless.yaml
│   ├── ...                       (groups split if > 200 resources)
│   └── NN-connectivity.yaml
├── params/                       ← One param file per deployment group
│   ├── 00-foundation-params.yaml
│   ├── 01-security-params.yaml
│   └── ...
├── DEPLOY.md                     ← Deployment order from graph
└── manual-steps.md               ← Resources needing manual action
```

Group names and count are determined by the dependency graph — not
hardcoded. An environment with 5 resources might produce 3 stacks.
An environment with 3000 resources might produce 25 stacks.

### Filtering (include/exclude)

Filtering is based on resource tag key:value pairs defined in include.yaml and exclude.yaml. Place these files in the directory specified with --input before running the blueprint:

```yaml
# exclude.yaml — skip resources matching these tag patterns
- Key: aws:cloudformation:stack-name
  Value: "*Ccpm*"
- Key: ManagedBy
  Value: "terraform"

# include.yaml — force-include (overrides exclude)
- Key: DR
  Value: "required"
```

**Precedence:** include overrides exclude. Both empty = include everything.

### Resource Types Covered (53)

| Category | CFN Type |
|----------|----------|
| VPCs | AWS::EC2::VPC |
| Subnets | AWS::EC2::Subnet |
| Route Tables | AWS::EC2::RouteTable |
| DHCP Options | AWS::EC2::DHCPOptions |
| EC2 Instances | AWS::EC2::Instance |
| Auto Scaling Groups | AWS::AutoScaling::AutoScalingGroup |
| ECS Clusters | AWS::ECS::Cluster |
| ECS Services | AWS::ECS::Service |
| EKS Clusters | AWS::EKS::Cluster |
| Lambda Functions | AWS::Lambda::Function |
| Step Functions | AWS::StepFunctions::StateMachine |
| EventBridge Rules | AWS::Events::Rule |
| API Gateways | AWS::ApiGatewayV2::Api |
| RDS Instances | AWS::RDS::DBInstance |
| RDS DB Clusters | AWS::RDS::DBCluster |
| RDS DB Subnet Groups | AWS::RDS::DBSubnetGroup |
| RDS Parameter Groups | AWS::RDS::DBParameterGroup |
| RDS Cluster Parameter Groups | AWS::RDS::DBClusterParameterGroup |
| RDS Option Groups | AWS::RDS::OptionGroup |
| ElastiCache Clusters | AWS::ElastiCache::CacheCluster |
| ElastiCache Replication Groups | AWS::ElastiCache::ReplicationGroup |
| DynamoDB Tables | AWS::DynamoDB::Table |
| FSx File Systems | AWS::FSx::FileSystem |
| S3 Buckets | AWS::S3::Bucket |
| Classic Load Balancers | AWS::ElasticLoadBalancing::LoadBalancer |
| Load Balancers (ALB/NLB) | AWS::ElasticLoadBalancingV2::LoadBalancer |
| Target Groups | AWS::ElasticLoadBalancingV2::TargetGroup |
| Listeners | AWS::ElasticLoadBalancingV2::Listener |
| NAT Gateways | AWS::EC2::NatGateway |
| VPC Endpoints | AWS::EC2::VPCEndpoint |
| VPC Peering Connections | AWS::EC2::VPCPeeringConnection |
| Transit Gateways | AWS::EC2::TransitGateway |
| Transit Gateway Attachments | AWS::EC2::TransitGatewayAttachment |
| Customer Gateways | AWS::EC2::CustomerGateway |
| VPN Connections | AWS::EC2::VPNConnection |
| Virtual Private Gateways | AWS::EC2::VPNGateway |
| Hosted Zones | AWS::Route53::HostedZone |
| Directories | AWS::DirectoryService::MicrosoftAD |
| SNS Topics | AWS::SNS::Topic |
| SQS Queues | AWS::SQS::Queue |
| KMS Keys | AWS::KMS::Key |
| ACM Certificates | AWS::CertificateManager::Certificate |
| WAF Web ACLs | AWS::WAFv2::WebACL |
| CloudWatch Alarms | AWS::CloudWatch::Alarm |
| Backup Vaults | AWS::Backup::BackupVault |
| Backup Plans | AWS::Backup::BackupPlan |
| Backup Selections | AWS::Backup::BackupSelection |
| EBS Snapshots | AWS::EC2::Snapshot |
| AMIs | AWS::EC2::Image |
| DLM Lifecycle Policies | AWS::DLM::LifecyclePolicy |
| IAM Roles | AWS::IAM::Role |
| CloudTrail Trails | AWS::CloudTrail::Trail |
| Security Groups | (bespoke — cross-reference resolution) |

Resources not in this list go to `manual-steps.md` with their ARN and
a note about what manual action is needed.

### Adding a New Resource Type

Add an entry to `CFN_TYPE_MAP` in `iac_blueprint.py`:

```python
'My Resources': {
    'cfn_type': 'AWS::Service::Resource',
    'id_field': 'ResourceId',           # inventory field for the ID
    'properties': {                      # fields that map directly to CFN props
        'CfnPropertyName': 'InventoryFieldName',
    },
    'params': {                          # fields that become template parameters
        'SubnetId': {
            'type': 'AWS::EC2::Subnet::Id',
            'source': 'SubnetId',        # inventory field (None = user must provide)
            'description': 'Target subnet',
        },
    },
}
```

The category name must match the operation `name` in your discovery template.

## Operational Scripts (`scripts/`)

Standalone utilities for DR preparation and post-implementation assessment.
See [scripts/README.md](scripts/README.md) for full documentation.

| Category | Scripts |
|----------|---------|
| **DR Preparation** | `replicate-secrets.py`, `replicate-parameters.py`, `map-backup-to-resources.py` |
| **Verification** | `map-all-internet-facing-resources.py`, `dns-to-target-walk.py` |
| **Change Auditing** | `sg-vpc-config-changes.py`, `rt-config-changes.py`, `compute-config-changes.py`, `iam-policy-config-changes.py` |

All scripts use CLI arguments (no hardcoded customer values) and work in
both commercial and GovCloud regions.

## Requirements

- Python 3.8+
- `boto3` and `botocore`
- `pyyaml`
- Valid AWS credentials with read access to the target account/region

```bash
# Optional: use a virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
