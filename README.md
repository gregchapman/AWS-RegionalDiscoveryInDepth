# Discovery In-Depth — AWS Account Inventory & Visualization

## What This Does

Exhaustively identifies everything in an AWS account and produces
output in formats consumable by diagramming tools, DR planning,
compliance audits, and cost analysis.

Three scripts, one pipeline:

| Script | Purpose | Speed |
|--------|---------|-------|
| `service_enumerator.py` | Fast scan — what services have resources? | ~90s |
| `auto_template.py` | Generate discovery templates for found services | ~30s |
| `deep_discover.py` | Detailed inventory using templates | ~60s |

## Quick Start

```bash
# Step 1: Find what's there (fast, broad)
python3 ../AWS-Services/service_enumerator.py \
  --region us-gov-west-1 --output enum-results.yaml

# Step 2: Auto-generate templates for services we don't have hand-crafted ones for
python3 auto_template.py --from-enum enum-results.yaml

# Step 3: Deep discovery (detailed, uses all templates)
python3 deep_discover.py --region us-gov-west-1
```

Or skip Steps 1-2 and just scan services that have hand-crafted templates:
```bash
python3 deep_discover.py --region us-gov-west-1
```

## Output Formats

All output goes to `./output/` by default.

| File | Format | Use Case |
|------|--------|----------|
| `inventory-<region>.yaml` | YAML | Human review, DR planning, version control |
| `inventory-<region>.json` | JSON | Programmatic consumption, custom tooling |
| `inventory-<region>.csv` | CSV | draw.io, Lucidchart, Excel, data analysis |
| `inventory-<region>.mermaid.md` | Mermaid | GitHub/Confluence rendering, presentations |
| `summary.txt` | Text | Quick resource counts |

### CSV Columns
```
ResourceType, Name, ResourceId, ResourceKey, Category,
VpcId, SubnetId, SecurityGroups, ConnectsTo
```
- **ConnectsTo** contains semicolon-separated resource IDs that this
  resource references (VPCs, subnets, SGs, etc.) — these become edges
  in a diagram.

### Mermaid
Renders directly in GitHub markdown, VS Code preview, Confluence.
Resources are grouped by category with relationship edges.

## Templates

### Hand-Crafted (`templates/`)
High-quality templates with curated field lists and DR notes.
19 templates included for core AWS services.

### Auto-Generated (`templates/auto/`)
Created by `auto_template.py` from boto3 service model introspection.
Good enough for inventory — captures IDs, names, and top-level config.
Review and promote to `templates/` for production use.

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

## Architecture

```
service_enumerator.py          auto_template.py
  (what's there?)         →     (how to describe it?)
         ↓                              ↓
    enum-results.yaml            templates/auto/*.yaml
                    ↘            ↙
                  deep_discover.py
                  (detailed inventory)
                        ↓
              output/
              ├── inventory.yaml
              ├── inventory.json
              ├── inventory.csv
              ├── inventory.mermaid.md
              └── summary.txt
```

