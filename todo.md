# Discovery In-Depth — TODO

## Cross-Region Replication Detection

The template engine currently handles single list/describe operations per service. Detecting cross-region replication requires per-resource follow-up calls, which the engine doesn't support yet.

### Services needing per-resource secondary calls
- **S3 Buckets** — `get_bucket_replication` per bucket (throws `ReplicationConfigurationNotFoundError` if not configured, needs per-bucket error handling)
- **DynamoDB** — `describe_table` per table returns `Replicas[]` with region info

### Services with standalone list operations (easier)
- **Aurora Global Databases** — `describe_global_clusters` returns cluster members and their regions
- **ElastiCache Global Datastores** — `describe_global_replication_groups` returns member regions

### What's needed
1. Add a `secondary_calls` concept to the template engine in `deep_discover.py` — after the primary list operation, make per-resource follow-up API calls and merge results into the resource config
2. Handle per-resource errors gracefully (e.g., S3 buckets without replication)
3. Surface replication status in draw.io diagrams and audience views
4. Add replication targets to the Cross-Region Dependencies sections in engineering and operations views

### Already done
- RDS cross-region read replicas — `ReadReplicaSourceDBInstanceIdentifier` and `ReadReplicaDBInstanceIdentifiers` are captured from the existing `describe_db_instances` response (no secondary call needed)

## Diagram Views — User-Controlled Category Selection

Currently `CATEGORY_TIERS` in `graph_discover.py` is a hardcoded dict that
determines which inventory categories appear in the architecture diagram.
Users can't control what's depicted without editing source code.

### Problem
- A full account scan may inventory 50+ categories but only 10-15 are
  relevant to a specific architecture question
- Different audiences want different slices: "show me the container
  platform" vs "show me the data tier" vs "show me everything"
- New services (EKS, ECR, Step Functions) need to be added to the code
  to appear in diagrams

### Proposed Approach: View Files

Add a `--view path/to/view.yaml` parameter to `graph_discover.py`.

A view file is a YAML dict that replaces `CATEGORY_TIERS` for that run:

```yaml
# views/container-platform.yaml
name: Container Platform
description: EKS/ECR workloads and supporting infrastructure
categories:
  EKS Clusters:        [workload, containers]
  ECR Repositories:    [workload, containers]
  EC2 Instances:       [workload, compute]
  Load Balancers:      [routing, load_balancing]
  VPCs:                [boundary, network]
  Subnets:             [boundary, network]
  Security Groups:     [attached, security]
  NAT Gateways:        [routing, network]
```

### Behavior
- If `--view` is specified, load categories from that file
- If not specified, use the built-in `CATEGORY_TIERS` (current behavior)
- Ship example views in a `views/` directory:
  - `full.yaml` — everything in the current `CATEGORY_TIERS`
  - `compute-only.yaml` — EC2, ASG, LBs, VPCs, subnets
  - `data-tier.yaml` — RDS, ElastiCache, DynamoDB, S3
  - `serverless.yaml` — Lambda, Step Functions, API Gateway, EventBridge
  - `container-platform.yaml` — EKS, ECR, EC2, LBs, VPCs

### Implementation Steps
1. Add `--view` argument to `graph_discover.py`
2. Load YAML file and convert to the `{category: (tier, group)}` dict format
3. Pass to `InventoryModel` instead of the module-level `CATEGORY_TIERS`
4. Update `discover.py` orchestrator to pass `--view` through if specified
5. Create example view files
6. Document in README

### Also Needed: Hand-Crafted Templates for Container Services
- `eks.yaml` — `describe_cluster` (needs secondary calls per cluster name from `list_clusters`)
- `ecr.yaml` — `describe_repositories`
- `ecs.yaml` — `list_clusters`, `list_services` per cluster
- `stepfunctions.yaml` — promote from auto-generated, add `describe_state_machine` secondary call

## Template Generator — IaC from Inventory

### Vision

Extend `template_generator.py` to generate CloudFormation templates for
ALL inventoried resources, not just the current DR-focused subset. The
goal: "We not only captured everything but we can reproduce it as proof."

This steps beyond inventory and diagrams into codifying environment
replication, one-for-one.

### Architecture

```
template_generator.py (lives at repo root)
  --input output/<label>/<region>/<timestamp>/
  --include <input-path>/include.yaml   (optional)
  --exclude <input-path>/exclude.yaml   (optional)
  --mode import|dr

Output lands INSIDE the input path:
  output/<label>/<region>/<timestamp>/
    ├── iac-templates/
    │   ├── 01-security-groups.yaml
    │   ├── 01-security-groups.md        ← parameter docs
    │   ├── 02-data-tier.yaml
    │   ├── 02-data-tier.md
    │   ├── ...
    │   └── manual-steps.md              ← resources that can't be CFN-managed
    ├── include.yaml                     ← user creates here
    └── exclude.yaml                     ← user creates here
```

### Filter Logic (include/exclude)

Both files are lists of tag Key:Value patterns (supports wildcards):

```yaml
# exclude.yaml
- Key: aws:cloudformation:stack-name
  Value: "*Ccpm*"
- Key: ManagedBy
  Value: "terraform"

# include.yaml
- Key: DR
  Value: "required"
- Key: Project
  Value: "txwise"
```

**Precedence:**
1. Resource matches include → always generate (overrides exclude)
2. Resource matches exclude and NOT include → skip
3. Both files empty → include everything
4. Include empty → include everything except exclude matches

### Modes

- **`import`** — Generates templates matching current state exactly.
  For CFN resource import or environment cloning.
- **`dr`** — Parameterizes region-specific values (AMIs, snapshots,
  subnets, certs, endpoints). Current template_generator behavior.

### Output Per Template

Each `.yaml` template gets a matching `.md` file documenting:
- Template purpose and what resources it creates
- Every parameter: name, type, what it expects, required vs optional
- Cross-stack dependencies (which stacks must deploy first)
- Manual steps required after deployment

### `manual-steps.md`

Resources that can't be fully reproduced via CFN:
- Lists each resource by name and ARN
- Describes what manual action is needed (e.g., "enable cross-region
  replication on S3 bucket X", "restore DynamoDB table from backup",
  "configure Route53 health checks")
- Groups by priority/dependency order

### Dependency Ordering

Assumed deployment order (can be refined later):
1. Security Groups (no dependencies)
2. Data Tier — RDS, ElastiCache, DynamoDB (needs SGs, subnets)
3. Compute Tier — EC2, ASG (needs SGs, subnets, AMIs)
4. Supporting Services — ACM, SNS, SQS, CloudWatch, WAF
5. Network Tier — LBs, listeners, TGs (needs SGs, subnets, certs, compute)
6. Serverless — Lambda, Step Functions, EventBridge, API GW (needs roles, VPC)
7. DNS — Route53 records (needs LB endpoints, instance IPs)

### What Needs to Mature

- **Secondary calls** in deep_discover.py (S3 replication config, DynamoDB
  table details, Lambda code locations, Step Function definitions)
- **Per-resource-type generators** for complex resources (SGs with
  cross-refs, RDS from snapshots, Lambda with S3 code packages)
- **Generic generator** for simple resources (SNS, SQS, DynamoDB) that
  maps inventory config fields directly to CFN properties
- **Validation** — can we lint the generated templates before writing?

### Integration with discover.py

`template_generator.py` is NOT part of the main pipeline. It's a
separate tool run after discovery completes:

```bash
# Run discovery first
python3 discover.py --label acme-prod --region us-east-1

# Then generate IaC from the results
python3 template_generator.py \
  --input output/acme-prod/us-east-1/20260505-151053/
```

The user creates `include.yaml` and `exclude.yaml` in the run directory
before running the generator. If they don't exist, everything is included.
