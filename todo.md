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

### Status: DONE (integrated as Step 5)

`iac_blueprint.py` now runs automatically as Step 5 of the `discover.py`
pipeline. The original `template_generator.py` concept has been fully
implemented and renamed to `iac_blueprint.py`.

### Remaining Enhancements

- **Secondary calls** in deep_discover.py (S3 replication config, DynamoDB
  table details, Lambda code locations, Step Function definitions) would
  improve the quality of generated templates
- **CFN Linting** — validate generated templates with cfn-lint before writing
- **Additional resource types** — EKS, ECR, ECS services, API Gateway
  need hand-crafted templates before they can produce good IaC output
- **Mode: import** — Currently only `dr` mode is well-tested. The `import`
  mode (exact state reproduction) needs validation

### Integration with discover.py

`iac_blueprint.py` IS now part of the main pipeline (Step 5). It runs
automatically after graph discovery completes. Users can also re-run it
standalone to regenerate templates after modifying include/exclude filters:

```bash
python3 iac_blueprint.py --input output/acme-prod/us-east-1/20260505-151053/
```
