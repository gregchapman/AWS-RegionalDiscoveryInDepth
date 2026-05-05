# Discovery In-Depth — AWS Account Inventory & Visualization

## What This Does

Exhaustively inventories an AWS account/region and produces output for
diagramming tools, DR planning, compliance audits, cost analysis, and
audience-specific architecture views.

Four scripts, one orchestrator:

| Script | Purpose | Speed |
|--------|---------|-------|
| `service_enumerator.py` | Fast scan — what services have resources? | ~90s |
| `auto_template.py` | Generate discovery templates for found services | ~30s |
| `deep_discover.py` | Detailed inventory using all templates | ~60s |
| `graph_discover.py` | Audience-driven architecture views + draw.io diagram | ~10s |
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
            ├── auto-templates/                 # Step 2: generated templates
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
- `auto-templates/*.yaml` exist → skip template generation
- `inventory-*.yaml` exists → skip deep discovery
- `architecture-*.md` exists → skip graph discovery

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

### Cross-Region Replication (Planned)

See `todo.md` for the roadmap on detecting cross-region replication for
S3 (bucket replication), DynamoDB (global tables), Aurora (global
databases), and ElastiCache (global datastores). This requires a
`secondary_calls` concept in the template engine for per-resource
follow-up API calls.

## Templates

### Hand-Crafted (`templates/`)

High-quality templates with curated field lists, DR notes, and skip
filters. 22 templates included covering core AWS services:


`acm`, `cloudwatch`, `ec2`, `elasticache`, `elb_classic`, `elbv2`,
`events`, `kms`, `lambda`, `nat_gateways`, `rds`, `route53`, `s3`,
`secretsmanager`, `security_groups`, `sns`, `ssm`, `tgw`, `vpc`,
`vpc_endpoints`, `vpc_peering`, `wafv2`

### Auto-Generated (`auto-templates/` in run directory)

Created by `auto_template.py` from boto3 service model introspection.
Captures resource IDs, names, and top-level config fields. Good enough
for inventory — review and promote to `templates/` for production use.

Hand-crafted templates always take precedence over auto-generated ones.

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
  │    Generate templates for services without hand-crafted ones
  │    → auto-templates/*.yaml
  │
  ├─ Step 3: deep_discover.py
  │    Template-driven detailed inventory
  │    → inventory.yaml, .json, .csv, .mermaid.md, summary.txt
  │
  └─ Step 4: graph_discover.py
       Audience-driven architecture views + draw.io diagram
       → architecture-{audience}-{region}.md
       → architecture-{region}.drawio

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

## Requirements

- Python 3.8+
- `boto3` and `botocore`
- `pyyaml`
- Valid AWS credentials with read access to the target account/region

