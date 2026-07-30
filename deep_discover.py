#!/usr/bin/env python3
"""
Deep Discovery Engine — Template-driven AWS resource inventory.

Reads YAML templates from ./templates/ and executes the described
API calls to produce a detailed inventory of all resources in an
AWS account/region.

No per-service Python code. Adding a new service = adding a YAML template.

Usage:
    python3 deep_discover.py --region us-gov-west-1
    python3 deep_discover.py --region us-gov-west-1 --services ec2,rds
    python3 deep_discover.py --region us-gov-west-1 --all
    python3 deep_discover.py --region us-gov-west-1 --output ./my-output
"""

import boto3
import botocore
import yaml
import json
import os
import sys
import time
import argparse
import glob
from datetime import datetime, date, timezone
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ═══════════════════════════════════════════════════════════════════
# JSON/YAML serialization helpers
# ═══════════════════════════════════════════════════════════════════

class AWSEncoder(json.JSONEncoder):
    """Handles datetime objects from AWS APIs."""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


def datetime_representer(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data.isoformat())

yaml.add_representer(datetime, datetime_representer)
yaml.add_representer(date, datetime_representer)


# Thread-safe print
_print_lock = Lock()
def tprint(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs, flush=True)


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE LOADER
# ═══════════════════════════════════════════════════════════════════

def load_templates(template_dir: str,
                   auto_template_dir: str = '') -> Dict[str, dict]:
    """Load all YAML templates from the template directory.
    Also loads auto-generated templates as fallback.
    Hand-crafted templates take precedence over auto-generated ones.

    Args:
        template_dir: path to hand-crafted templates
        auto_template_dir: explicit path to auto-generated templates.
                           If empty, falls back to <template_dir>/auto/
    Returns a dict of service_name -> template_dict.
    """
    templates = {}

    # Load auto-generated templates first (lower priority)
    auto_dir = auto_template_dir or os.path.join(template_dir, 'auto')
    if os.path.isdir(auto_dir):
        pattern = os.path.join(auto_dir, '*.yaml')
        for filepath in sorted(glob.glob(pattern)):
            try:
                with open(filepath, 'r') as f:
                    tmpl = yaml.safe_load(f)
                if tmpl and 'service' in tmpl:
                    templates[tmpl['service']] = tmpl
            except Exception as e:
                tprint(f"  WARNING: Failed to load auto template {filepath}: {e}")

    # Load hand-crafted templates (override auto-generated)
    pattern = os.path.join(template_dir, '*.yaml')
    for filepath in sorted(glob.glob(pattern)):
        try:
            with open(filepath, 'r') as f:
                tmpl = yaml.safe_load(f)
            if tmpl and 'service' in tmpl:
                templates[tmpl['service']] = tmpl
        except Exception as e:
            tprint(f"  WARNING: Failed to load template {filepath}: {e}")

    return templates


# ═══════════════════════════════════════════════════════════════════
# FIELD EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def extract_field(resource: dict, field_path: str, default='') -> Any:
    """Extract a value from a resource dict using dot-notation paths.

    Supports:
      - Simple: 'InstanceId'
      - Nested: 'Endpoint.Address'
      - List extraction: 'SecurityGroups[].GroupId'
      - Deep nested: 'IamInstanceProfile.Arn'
    """
    if not field_path or not isinstance(resource, dict):
        return default

    # Handle list extraction: 'SecurityGroups[].GroupId'
    if '[]' in field_path:
        parts = field_path.split('[]', 1)
        list_key = parts[0].strip('.')
        sub_path = parts[1].strip('.') if len(parts) > 1 else ''

        items = resource.get(list_key, [])
        if not isinstance(items, list):
            return default
        if not sub_path:
            return items
        return [extract_field(item, sub_path, default) for item in items]

    # Handle dot notation: 'Endpoint.Address'
    current = resource
    for key in field_path.split('.'):
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current


def extract_tags_dict(resource: dict) -> dict:
    """Extract Tags from AWS resource into a simple dict.
    Handles both [{'Key':'k','Value':'v'}] and {k:v} formats.
    """
    tags = resource.get('Tags', [])
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):
        return {t.get('Key', ''): t.get('Value', '') for t in tags if 'Key' in t}
    return {}


def get_name(resource: dict, op_config: dict) -> str:
    """Get the resource name using the template's name strategy."""
    # Strategy 1: explicit name_field
    name_field = op_config.get('name_field', '')
    if name_field:
        val = extract_field(resource, name_field)
        if val and val != '':
            return str(val)

    # Strategy 2: tag_name flag — pull from Tags
    if op_config.get('tag_name', False):
        tags = extract_tags_dict(resource)
        name = tags.get('Name', '')
        if name:
            return name

    # Strategy 3: fall back to ID field
    id_field = op_config.get('id_field', '')
    if id_field:
        return str(extract_field(resource, id_field, 'unnamed'))

    return 'unnamed'


# ═══════════════════════════════════════════════════════════════════
# DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════════

def discover_operation(client, op_config: dict, service_name: str) -> List[Dict]:
    """Execute a single discovery operation from a template.

    Args:
        client: boto3 client
        op_config: operation config from the template
        service_name: service name for resource_key prefix

    Returns:
        List of standardized resource dicts
    """
    method_name = op_config['method']
    result_key = op_config.get('result_key', '')
    use_paginator = op_config.get('paginator', False)
    id_field = op_config.get('id_field', '')
    resource_type = op_config.get('name', service_name)
    dr_note = op_config.get('dr_note', '')
    config_fields = op_config.get('config_fields', [])
    extra_kwargs = op_config.get('kwargs', {})
    skip_filter = op_config.get('skip_if', {})

    resources = []

    try:
        # Collect all items from the API
        raw_items = []

        if use_paginator:
            try:
                paginator = client.get_paginator(method_name)
                for page in paginator.paginate(**extra_kwargs):
                    if result_key:
                        # Handle nested result keys like 'Reservations'
                        items = page.get(result_key, [])
                        # EC2 special case: Reservations[].Instances[]
                        unwrap = op_config.get('unwrap_key', '')
                        if unwrap and isinstance(items, list):
                            for group in items:
                                if isinstance(group, dict):
                                    raw_items.extend(group.get(unwrap, []))
                        else:
                            if isinstance(items, list):
                                raw_items.extend(items)
                    else:
                        # Find the largest list in the response
                        for k, v in page.items():
                            if k == 'ResponseMetadata':
                                continue
                            if isinstance(v, list) and len(v) > 0:
                                raw_items.extend(v)
                                break
            except botocore.exceptions.OperationNotPageableError:
                # Fall back to single call
                method = getattr(client, method_name)
                response = method(**extra_kwargs)
                if result_key:
                    raw_items = response.get(result_key, [])
                    unwrap = op_config.get('unwrap_key', '')
                    if unwrap:
                        expanded = []
                        for group in raw_items:
                            if isinstance(group, dict):
                                expanded.extend(group.get(unwrap, []))
                        raw_items = expanded
        else:
            method = getattr(client, method_name)
            response = method(**extra_kwargs)
            if result_key:
                raw_items = response.get(result_key, [])
                unwrap = op_config.get('unwrap_key', '')
                if unwrap:
                    expanded = []
                    for group in raw_items:
                        if isinstance(group, dict):
                            expanded.extend(group.get(unwrap, []))
                    raw_items = expanded
            else:
                for k, v in response.items():
                    if k == 'ResponseMetadata':
                        continue
                    if isinstance(v, list):
                        raw_items = v
                        break

        # Process each item
        for item in raw_items:
            if not isinstance(item, dict):
                continue

            # Apply skip filter
            skip = False
            for skip_field, skip_values in skip_filter.items():
                val = extract_field(item, skip_field)
                if isinstance(skip_values, list) and val in skip_values:
                    skip = True
                    break
                elif val == skip_values:
                    skip = True
                    break
            if skip:
                continue

            # Extract ID
            res_id = str(extract_field(item, id_field, 'unknown'))

            # Extract name
            name = get_name(item, op_config)

            # Build config dict from config_fields
            config = {}
            used_keys = {}
            for field in config_fields:
                # Use the leaf of the path as the config key
                if '[]' in field:
                    # e.g. 'ListenerDescriptions[].Listener.Protocol' → 'Protocol'
                    # e.g. 'SecurityGroups[].GroupId' → 'GroupId'
                    # e.g. 'SecurityGroups[]' → 'SecurityGroups'
                    after_bracket = field.split('[]', 1)[1].strip('.')
                    if after_bracket:
                        key = after_bracket.split('.')[-1]
                    else:
                        key = field.split('[]')[0].split('.')[-1]
                elif '.' in field:
                    key = field.split('.')[-1]
                else:
                    key = field

                # Detect key collisions from different parent paths
                # e.g. RequesterVpcInfo.VpcId and AccepterVpcInfo.VpcId
                # both produce key 'VpcId' — disambiguate with parent prefix
                if key in used_keys and used_keys[key] != field:
                    # Rename the previously stored value with its parent prefix
                    prev_field = used_keys[key]
                    if key in config:
                        # Build a qualified key for the previous entry
                        if '.' in prev_field:
                            parts = prev_field.replace('[]', '').split('.')
                            qualified_prev = f"{parts[-2]}_{parts[-1]}"
                        else:
                            qualified_prev = f"{prev_field}_{key}"
                        config[qualified_prev] = config.pop(key)
                        used_keys[qualified_prev] = prev_field
                    # Use parent-qualified key for the current field too
                    if '.' in field:
                        parts = field.replace('[]', '').split('.')
                        key = f"{parts[-2]}_{parts[-1]}"
                    else:
                        key = f"{field}_{key}"

                used_keys[key] = field
                config[key] = extract_field(item, field)

            # Always include tags
            config['Tags'] = extract_tags_dict(item)

            # Build the standardized resource entry
            prefix = op_config.get('key_prefix', service_name)
            resources.append({
                'resource_key': f"{prefix}:{res_id}",
                'resource_type': resource_type,
                'resource_id': res_id,
                'name': name,
                'dr_note': dr_note,
                'config': config,
            })

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        tprint(f"    ⚠ {service_name}.{method_name} failed: {error_code}")
    except Exception as e:
        tprint(f"    ⚠ {service_name}.{method_name} error: {type(e).__name__}: {str(e)[:200]}")

    return resources


def discover_service(template: dict, region: str) -> Dict[str, List]:
    """Run all operations for a single service template.

    Returns:
        Dict of operation_name -> list of resource dicts
    """
    service_name = template['service']
    client_name = template.get('client', service_name)
    display_name = template.get('display_name', service_name)
    operations = template.get('operations', [])

    results = {}
    start = time.time()

    try:
        session = boto3.Session(region_name=region)
        client = session.client(client_name)
    except Exception as e:
        tprint(f"  ✗ {display_name}: Failed to create client: {e}")
        return results

    for op in operations:
        op_name = op.get('name', op.get('method', 'unknown'))
        try:
            # Check if this is a chained operation (depends on parent results)
            foreach = op.get('foreach', None)
            if foreach:
                # Chained call: iterate parent results and call API per parent
                parent_op = foreach.get('parent_operation', '')
                parent_field = foreach.get('parent_field', '')
                kwarg_name = foreach.get('kwarg_name', '')
                parent_results = results.get(parent_op, [])

                if not parent_results:
                    tprint(f"    {op_name}: skipped (no parent results from '{parent_op}')")
                    continue

                all_child_items = []
                for parent_res in parent_results:
                    parent_val = parent_res.get('config', {}).get(parent_field, '')
                    if not parent_val:
                        # Try resource_id as fallback
                        parent_val = parent_res.get('resource_id', '')
                    if not parent_val:
                        continue

                    # Build kwargs for the child call
                    child_op = dict(op)
                    child_kwargs = dict(op.get('kwargs', {}))
                    child_kwargs[kwarg_name] = parent_val
                    child_op['kwargs'] = child_kwargs

                    child_items = discover_operation(client, child_op, service_name)

                    # Attach parent reference to each child resource
                    parent_ref_field = foreach.get('attach_parent_field', '')
                    for child in child_items:
                        if parent_ref_field:
                            child['config'][parent_ref_field] = parent_val
                        else:
                            child['config']['_parent_arn'] = parent_val

                    all_child_items.extend(child_items)

                if all_child_items:
                    results[op_name] = all_child_items
                    tprint(f"    {op_name}: {len(all_child_items)} resources (chained from {len(parent_results)} {parent_op})")
            else:
                items = discover_operation(client, op, service_name)
                if items:
                    results[op_name] = items
                    tprint(f"    {op_name}: {len(items)} resources")
        except Exception as e:
            tprint(f"    ⚠ {op_name}: {e}")

    elapsed = round(time.time() - start, 1)
    total = sum(len(v) for v in results.values())
    if total > 0:
        tprint(f"  ✓ {display_name}: {total} resources ({elapsed}s)")
    else:
        auto = template.get('auto_generated', False)
        marker = '·' if auto else '⚠'
        tprint(f"  {marker} {display_name}: 0 resources ({elapsed}s)")

    return results


# ═══════════════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════════════

def build_inventory(all_results: Dict[str, Dict], region: str,
                    account_id: str) -> Dict:
    """Build the final inventory structure."""
    inventory = {
        'metadata': {
            'account_id': account_id,
            'region': region,
            'scan_date': datetime.now(tz=timezone.utc).isoformat(),
            'tool': 'deep_discover.py',
            'note': 'Review and remove resources already deployed by '
                    'CCPM/management infrastructure.',
        },
        'resources': {},
    }

    for service_name, ops_results in sorted(all_results.items()):
        for op_name, resources in ops_results.items():
            if resources:
                inventory['resources'][op_name] = resources

    return inventory


def write_yaml(inventory: Dict, filepath: str):
    """Write inventory as YAML."""
    with open(filepath, 'w', newline='\n') as f:
        f.write(f"# Deep Discovery Inventory — {inventory['metadata']['region']}\n")
        f.write(f"# Generated: {inventory['metadata']['scan_date']}\n")
        f.write(f"# Account: {inventory['metadata']['account_id']}\n")
        f.write(f"#\n")
        f.write(f"# To exclude a resource from DR reproduction, comment out\n")
        f.write(f"# its entire block (resource_key through config).\n")
        f.write(f"# {'─' * 53}\n")
        yaml.dump(inventory, f, default_flow_style=False, sort_keys=False,
                  allow_unicode=True)
    tprint(f"  YAML: {filepath}")


def write_json(inventory: Dict, filepath: str):
    """Write inventory as JSON."""
    with open(filepath, 'w', newline='\n') as f:
        json.dump(inventory, f, indent=2, cls=AWSEncoder)
    tprint(f"  JSON: {filepath}")


def write_summary(inventory: Dict, filepath: str):
    """Write a human-readable summary."""
    with open(filepath, 'w', newline='\n') as f:
        meta = inventory['metadata']
        f.write(f"Deep Discovery Summary\n")
        f.write(f"{'=' * 50}\n")
        f.write(f"Account:  {meta['account_id']}\n")
        f.write(f"Region:   {meta['region']}\n")
        f.write(f"Scanned:  {meta['scan_date']}\n")
        f.write(f"{'=' * 50}\n\n")

        total = 0
        for category, resources in inventory.get('resources', {}).items():
            count = len(resources)
            total += count
            f.write(f"  {category:40s} {count:5d}\n")

        f.write(f"\n  {'TOTAL':40s} {total:5d}\n")
    tprint(f"  Summary: {filepath}")


def write_csv(inventory: Dict, filepath: str):
    """Write a draw.io compatible CSV with shape mapping directives.

    draw.io CSV import requires # directive lines that define how
    columns map to shapes, labels, connections, and styles.
    ## lines are comments, # lines are configuration.

    Import in draw.io: Arrange → Insert → Advanced → CSV,
    then paste the file contents.
    """
    # Map resource types to draw.io AWS 19 icon styles
    ICON_MAP = {
        'EC2 Instances': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.ec2_instance',
        'Security Groups': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.security_group',
        'VPCs': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.vpc',
        'Subnets': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.subnet',
        'Route Tables': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.route_table',
        'RDS Instances': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.rds_instance',
        'Load Balancers': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elastic_load_balancing',
        'Classic Load Balancers': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elastic_load_balancing',
        'Target Groups': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elastic_load_balancing',
        'Lambda Functions': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.lambda_function',
        'S3 Buckets': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.s3',
        'NAT Gateways': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.nat_gateway',
        'VPC Endpoints': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.vpc_endpoint',
        'ElastiCache Clusters': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elasticache',
        'ElastiCache Replication Groups': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elasticache',
        'ACM Certificates': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.certificate_manager_3',
        'KMS Keys': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.kms',
        'SSM Parameters': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.systems_manager',
        'Secrets': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.secrets_manager',
        'CloudWatch Alarms': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.cloudwatch_2',
        'SNS Topics': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.sns',
        'Hosted Zones': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.route_53',
        'WAF Web ACLs': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.waf',
        'EventBridge Rules': 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.eventbridge',
    }
    DEFAULT_ICON = 'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.general_AWScloud'

    # Build styles JSON from ICON_MAP
    styles_dict = {}
    for cat, style in ICON_MAP.items():
        safe_key = cat.replace(' ', '_')
        styles_dict[safe_key] = style + ';whiteSpace=wrap;html=1;'
    styles_dict['default'] = DEFAULT_ICON + ';whiteSpace=wrap;html=1;'

    import json as _json
    styles_json = _json.dumps(styles_dict)

    with open(filepath, 'w', newline='\n') as f:
        # draw.io CSV directives (# = config, ## = comment)
        f.write(f"## AWS Account Inventory — {inventory['metadata'].get('region', '')}\n")
        f.write(f"## Account: {inventory['metadata'].get('account_id', '')}\n")
        f.write(f"## Generated: {inventory['metadata'].get('scan_date', '')}\n")
        f.write(f"##\n")
        f.write(f"# label: %Name%<br><i style=\"font-size:11px;color:gray;\">%ResourceType%</i>\n")
        f.write(f"# stylename: StyleKey\n")
        f.write(f"# styles: {styles_json}\n")
        f.write(f"# identity: ResourceId\n")
        f.write(f"# namespace: awsinv-\n")
        f.write(f"# connect: {{\"from\": \"ConnectsTo\", \"to\": \"ResourceId\", \"style\": \"curved=1;endArrow=blockThin;endFill=1;fontSize=11;strokeColor=#545B64;\"}}\n")
        f.write(f"# width: 78\n")
        f.write(f"# height: 78\n")
        f.write(f"# padding: 15\n")
        f.write(f"# ignore: StyleKey,ConnectsTo\n")
        f.write(f"# nodespacing: 60\n")
        f.write(f"# levelspacing: 100\n")
        f.write(f"# layout: auto\n")
        f.write(f"##\n")
        f.write('ResourceId,Name,ResourceType,Category,VpcId,SubnetId,StyleKey,ConnectsTo\n')

        for category, resources in inventory.get('resources', {}).items():
            style_key = category.replace(' ', '_')
            if style_key not in styles_dict:
                style_key = 'default'

            for res in resources:
                config = res.get('config', {})
                # Sanitize fields — no commas or quotes in CSV values
                name = str(res.get('name', '')).replace(',', ' ').replace('"', "'")
                res_id = str(res.get('resource_id', '')).replace(',', ' ')
                res_type = str(res.get('resource_type', '')).replace(',', ' ')
                vpc_id = str(config.get('VpcId', '')).replace(',', ' ')
                subnet_id = str(config.get('SubnetId', '')).replace(',', ' ')

                # Build ConnectsTo — resource references become edges
                connects = []
                for k, v in config.items():
                    if k == 'Tags':
                        continue
                    if isinstance(v, str) and (
                        v.startswith('vpc-') or v.startswith('subnet-') or
                        v.startswith('sg-') or v.startswith('i-') or
                        v.startswith('rtb-') or v.startswith('nat-') or
                        v.startswith('vpce-')
                    ):
                        if v != res_id:
                            connects.append(v)
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, str) and (
                                item.startswith('sg-') or
                                item.startswith('subnet-')
                            ):
                                if item != res_id:
                                    connects.append(item)

                connects_str = ','.join(connects)
                f.write(f'{res_id},{name},{res_type},{category},{vpc_id},{subnet_id},{style_key},{connects_str}\n')

    tprint(f"  CSV (draw.io): {filepath}")


def write_mermaid(inventory: Dict, filepath: str):
    """Write a Mermaid diagram showing resources grouped by type.

    Renders in GitHub markdown, Confluence, VS Code preview, etc.
    """
    with open(filepath, 'w', newline='\n') as f:
        meta = inventory['metadata']
        f.write(f"# Account {meta['account_id']} — {meta['region']}\n")
        f.write(f"# Generated: {meta['scan_date']}\n\n")
        f.write("```mermaid\ngraph TD\n")

        # Group resources by category, create subgraphs
        node_id = 0
        node_map = {}  # resource_id -> mermaid node id
        vpc_nodes = {}  # vpc_id -> list of child node ids

        for category, resources in inventory.get('resources', {}).items():
            safe_cat = category.replace(' ', '_').replace('-', '_')
            f.write(f"\n  subgraph {safe_cat}[\"{category} ({len(resources)})\"]\n")

            for res in resources:
                node_id += 1
                nid = f"n{node_id}"
                label = res.get('name', res.get('resource_id', '?'))
                rtype = res.get('resource_type', '')
                # Truncate long labels
                if len(label) > 40:
                    label = label[:37] + '...'
                # Escape quotes
                label = label.replace('"', "'")
                f.write(f"    {nid}[\"{label}\"]\n")
                node_map[res.get('resource_id', '')] = nid

                # Track VPC membership
                vpc_id = res.get('config', {}).get('VpcId', '')
                if vpc_id:
                    vpc_nodes.setdefault(vpc_id, []).append(nid)

            f.write("  end\n")

        # Draw edges for VPC membership and SG references
        f.write("\n  %% Relationships\n")
        for category, resources in inventory.get('resources', {}).items():
            for res in resources:
                src = node_map.get(res.get('resource_id', ''))
                if not src:
                    continue
                config = res.get('config', {})
                # Link to VPC
                vpc_id = config.get('VpcId', '')
                if vpc_id and vpc_id in node_map:
                    f.write(f"  {src} -.-> {node_map[vpc_id]}\n")
                # Link to subnet
                subnet_id = config.get('SubnetId', '')
                if subnet_id and subnet_id in node_map:
                    f.write(f"  {src} --> {node_map[subnet_id]}\n")

        f.write("```\n")
    tprint(f"  Mermaid: {filepath}")



# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Deep Discovery — Template-driven AWS resource inventory.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 deep_discover.py --region us-gov-west-1
  python3 deep_discover.py --region us-gov-west-1 --services ec2,rds,elbv2
  python3 deep_discover.py --region us-gov-west-1 --all
  python3 deep_discover.py --region us-gov-west-1 --output ./my-inventory
        """,
    )
    parser.add_argument('--region', default='us-gov-west-1',
                        help='AWS region to scan (default: us-gov-west-1)')
    parser.add_argument('--services', default='',
                        help='Comma-separated list of services to scan')
    parser.add_argument('--all', action='store_true',
                        help='Scan all services that have templates')
    parser.add_argument('--output', default='',
                        help='Output directory (default: ./output)')
    parser.add_argument('--workers', type=int, default=10,
                        help='Parallel workers (default: 10)')
    parser.add_argument('--templates', default='',
                        help='Template directory (default: ./templates)')
    parser.add_argument('--auto-templates', default='',
                        help='Auto-generated template directory (default: <templates>/auto)')
    args = parser.parse_args()

    # Resolve paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = args.templates or os.path.join(script_dir, 'templates')
    output_dir = args.output or os.path.join(script_dir, 'output')
    os.makedirs(output_dir, exist_ok=True)

    # Load templates
    templates = load_templates(template_dir, args.auto_templates)
    if not templates:
        tprint(f"ERROR: No templates found in {template_dir}")
        sys.exit(1)

    tprint(f"\n{'=' * 60}")
    tprint(f"Deep Discovery — {args.region}")
    tprint(f"{'=' * 60}")
    tprint(f"Templates loaded: {len(templates)}")
    tprint(f"  Services: {', '.join(sorted(templates.keys()))}")

    # Filter services
    if args.services:
        requested = [s.strip() for s in args.services.split(',')]
        templates = {k: v for k, v in templates.items() if k in requested}
        missing = [s for s in requested if s not in templates]
        if missing:
            tprint(f"  WARNING: No templates for: {', '.join(missing)}")

    if not templates:
        tprint("ERROR: No matching templates to run.")
        sys.exit(1)

    tprint(f"Scanning: {len(templates)} services")
    tprint(f"Workers: {args.workers}")
    tprint(f"{'=' * 60}\n")

    # Get account ID
    try:
        sts = boto3.client('sts', region_name=args.region)
        account_id = sts.get_caller_identity()['Account']
    except Exception:
        account_id = 'unknown'

    # Run discovery in parallel
    all_results = {}
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_svc = {
            executor.submit(discover_service, tmpl, args.region): svc
            for svc, tmpl in templates.items()
        }
        for future in as_completed(future_to_svc):
            svc = future_to_svc[future]
            try:
                result = future.result()
                if result:
                    all_results[svc] = result
            except Exception as e:
                tprint(f"  ✗ {svc}: {e}")

    elapsed = round(time.time() - start_time, 1)

    # Build and write inventory
    inventory = build_inventory(all_results, args.region, account_id)

    tprint(f"\n{'=' * 60}")
    tprint(f"Writing output to {output_dir}")
    tprint(f"{'=' * 60}")

    base = f"inventory-{args.region}"
    write_yaml(inventory, os.path.join(output_dir, f"{base}.yaml"))
    write_json(inventory, os.path.join(output_dir, f"{base}.json"))
    write_csv(inventory, os.path.join(output_dir, f"{base}.csv"))
    write_mermaid(inventory, os.path.join(output_dir, f"{base}.mermaid.md"))
    write_summary(inventory, os.path.join(output_dir, "summary.txt"))

    total = sum(len(v) for v in inventory.get('resources', {}).values())
    tprint(f"\n{'=' * 60}")
    tprint(f"Complete — {total} resources across "
           f"{len(inventory.get('resources', {}))} categories ({elapsed}s)")
    tprint(f"{'=' * 60}")


if __name__ == "__main__":
    main()
