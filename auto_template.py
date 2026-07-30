#!/usr/bin/env python3
"""
Auto Template Generator — Introspects boto3 service models to generate
discovery templates for services that don't have hand-crafted ones.

Given a list of services (from service_enumerator.py output or --services),
this script:
1. Creates a boto3 client for each service
2. Finds the best list/describe operation (same logic as service_enumerator)
3. Introspects the operation's output shape to find the result list and fields
4. Writes a YAML template to ./templates/auto/

Auto-generated templates are "good enough" — they capture resource IDs,
names, and top-level config fields. Hand-crafted templates in ./templates/
take precedence when both exist.

Usage:
    # Generate templates for services found by the enumerator
    python3 auto_template.py --from-enum enum-results.yaml

    # Generate for specific services
    python3 auto_template.py --services ec2,rds,elbv2,lambda

    # Generate for ALL boto3 services (slow, mostly empty)
    python3 auto_template.py --all --region us-gov-west-1
"""

import boto3
import botocore
import yaml
import os
import sys
import argparse
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════
# SERVICE MODEL INTROSPECTION
# ═══════════════════════════════════════════════════════════════════

# Operations known to require parameters — skip these
SKIP_OPERATIONS = {
    'describe_db_log_files', 'describe_db_snapshots', 'describe_events',
    'list_tags_for_resource', 'get_bucket_location', 'describe_log_streams',
    'list_objects_v2', 'describe_pending_maintenance_actions',
}

# Preferred operations per service (same as service_enumerator)
PREFERRED_OPS = {
    'ec2': 'describe_instances',
    's3': 'list_buckets',
    'rds': 'describe_db_instances',
    'lambda': 'list_functions',
    'dynamodb': 'list_tables',
    'elbv2': 'describe_load_balancers',
    'iam': 'list_roles',
    'cloudformation': 'list_stacks',
    'sns': 'list_topics',
    'sqs': 'list_queues',
    'secretsmanager': 'list_secrets',
    'ssm': 'describe_parameters',
    'kms': 'list_keys',
    'acm': 'list_certificates',
    'route53': 'list_hosted_zones',
    'elasticache': 'describe_cache_clusters',
    'stepfunctions': 'list_state_machines',
    'events': 'list_rules',
    'wafv2': 'list_web_acls',
    'cloudwatch': 'describe_alarms',
}

# Special kwargs needed for certain operations
SPECIAL_KWARGS = {
    ('wafv2', 'list_web_acls'): {'Scope': 'REGIONAL'},
    ('cognito-identity', 'list_identity_pools'): {'MaxResults': 10},
    ('cognito-idp', 'list_user_pools'): {'MaxResults': 10},
}


def find_best_operation(service_name: str, client) -> Optional[str]:
    """Find the best list/describe operation for a service."""
    if service_name in PREFERRED_OPS:
        op = PREFERRED_OPS[service_name]
        if hasattr(client, op):
            return op

    try:
        operations = client.meta.service_model.operation_names
    except Exception:
        return None

    candidates = []
    for op in operations:
        method_name = botocore.xform_name(op)
        if method_name in SKIP_OPERATIONS:
            continue
        if not hasattr(client, method_name):
            continue

        try:
            op_model = client.meta.service_model.operation_model(op)
            required = op_model.input_shape.required_members if op_model.input_shape else []
            if required:
                continue
        except Exception:
            continue

        score = 0
        if method_name.startswith('list_'):
            score = 10
        elif method_name.startswith('describe_'):
            score = 8
        elif method_name.startswith('get_'):
            score = 5
        else:
            continue

        score -= len(method_name) * 0.01
        candidates.append((score, method_name, op))

    if not candidates:
        return None

    candidates.sort(reverse=True)
    return candidates[0][1]


def introspect_output(service_name: str, method_name: str,
                      client) -> Tuple[str, str, List[str], List[str]]:
    """Introspect the output shape of an API operation.

    Returns:
        (result_key, id_field, config_fields, name_candidates)
    """
    # Convert snake_case method to CamelCase operation name
    op_name = None
    for op in client.meta.service_model.operation_names:
        if botocore.xform_name(op) == method_name:
            op_name = op
            break

    if not op_name:
        return '', '', [], []

    op_model = client.meta.service_model.operation_model(op_name)
    output_shape = op_model.output_shape
    if not output_shape:
        return '', '', [], []

    # Find the result key — the member that's a list of structures
    result_key = ''
    item_shape = None

    for member_name, member_shape in output_shape.members.items():
        if member_name in ('ResponseMetadata', 'NextToken', 'nextToken',
                           'Marker', 'IsTruncated', 'NextMarker'):
            continue

        if member_shape.type_name == 'list':
            list_member = member_shape.member
            if list_member.type_name == 'structure':
                result_key = member_name
                item_shape = list_member
                break
            elif list_member.type_name == 'string':
                # Simple string list (e.g., list_tables returns TableNames: [str])
                result_key = member_name
                return result_key, '', [], []

    if not item_shape:
        return result_key, '', [], []

    # Extract fields from the item shape
    all_fields = []
    id_candidates = []
    name_candidates = []

    for field_name, field_shape in item_shape.members.items():
        all_fields.append(field_name)

        # Identify likely ID fields
        lower = field_name.lower()
        if lower.endswith('id') or lower.endswith('arn'):
            id_candidates.append(field_name)
        if lower.endswith('name') or lower == 'name':
            name_candidates.append(field_name)

    # Pick the best ID field
    id_field = ''
    if id_candidates:
        # Prefer fields with 'Arn' (globally unique), then 'Id'
        arn_fields = [f for f in id_candidates if f.lower().endswith('arn')]
        id_fields = [f for f in id_candidates if f.lower().endswith('id')]
        if arn_fields:
            id_field = arn_fields[0]
        elif id_fields:
            id_field = id_fields[0]
        else:
            id_field = id_candidates[0]

    # Limit config fields to scalar/simple types (skip deeply nested structures)
    config_fields = []
    for field_name, field_shape in item_shape.members.items():
        if field_shape.type_name in ('string', 'integer', 'long', 'float',
                                      'double', 'boolean', 'timestamp'):
            config_fields.append(field_name)
        elif field_shape.type_name == 'list':
            # Include simple lists
            if field_shape.member.type_name in ('string',):
                config_fields.append(field_name)

    return result_key, id_field, config_fields, name_candidates


def check_paginator(service_name: str, method_name: str, client) -> bool:
    """Check if a paginator exists for this operation."""
    try:
        client.get_paginator(method_name)
        return True
    except botocore.exceptions.OperationNotPageableError:
        return False
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_template(service_name: str, region: str) -> Optional[dict]:
    """Generate a discovery template for a service by introspecting its model."""
    try:
        session = boto3.Session(region_name=region)
        client = session.client(service_name)
    except Exception:
        return None

    method_name = find_best_operation(service_name, client)
    if not method_name:
        return None

    result_key, id_field, config_fields, name_candidates = \
        introspect_output(service_name, method_name, client)

    if not result_key:
        return None

    has_paginator = check_paginator(service_name, method_name, client)

    # Build the name field
    name_field = ''
    tag_name = False
    if name_candidates:
        # Prefer shorter name fields
        name_candidates.sort(key=len)
        name_field = name_candidates[0]
    else:
        tag_name = True  # Fall back to Tags

    # Build display name from service name
    display_name = service_name.replace('-', ' ').replace('_', ' ').title()

    # Build operation name from method
    op_display = method_name.replace('_', ' ').title()

    # Build kwargs if needed
    kwargs = {}
    key = (service_name, method_name)
    if key in SPECIAL_KWARGS:
        kwargs = SPECIAL_KWARGS[key]

    template = {
        'service': service_name,
        'client': service_name,
        'display_name': display_name,
        'auto_generated': True,
        'operations': [{
            'name': op_display,
            'method': method_name,
            'paginator': has_paginator,
            'result_key': result_key,
            'id_field': id_field,
            'key_prefix': service_name.replace('-', ''),
            'dr_note': '',
            'config_fields': config_fields[:20],  # Cap at 20 fields
        }],
    }

    # Add name strategy
    if name_field:
        template['operations'][0]['name_field'] = name_field
    if tag_name:
        template['operations'][0]['tag_name'] = True
    if kwargs:
        template['operations'][0]['kwargs'] = kwargs

    return template


def write_template(template: dict, output_dir: str):
    """Write a template YAML file."""
    service_name = template['service']
    filepath = os.path.join(output_dir, f"{service_name.replace('-', '_')}.yaml")

    with open(filepath, 'w', newline='\n') as f:
        f.write(f"# Auto-generated discovery template for {service_name}\n")
        f.write(f"# Review and adjust config_fields for your needs.\n")
        f.write(f"# Move to ../templates/ and remove auto_generated flag\n")
        f.write(f"# to make it a permanent hand-crafted template.\n")
        f.write(f"# {'─' * 50}\n\n")
        yaml.dump(template, f, default_flow_style=False, sort_keys=False)

    return filepath


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Auto-generate discovery templates from boto3 service models.',
    )
    parser.add_argument('--region', default='us-gov-west-1',
                        help='AWS region (for service model introspection)')
    parser.add_argument('--services', default='',
                        help='Comma-separated list of services')
    parser.add_argument('--from-enum', default='',
                        help='Path to service_enumerator.py YAML output')
    parser.add_argument('--all', action='store_true',
                        help='Generate for all boto3 services')
    parser.add_argument('--output', default='',
                        help='Output directory (default: ./templates/auto)')
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output or os.path.join(script_dir, 'templates', 'auto')
    os.makedirs(output_dir, exist_ok=True)

    # Determine which services to process
    services = []

    if args.from_enum:
        # Read enumerator output — only services that had resources
        with open(args.from_enum, 'r') as f:
            enum_data = yaml.safe_load(f)
        for entry in enum_data.get('services_with_resources', []):
            services.append(entry['service'])
        print(f"Loaded {len(services)} services from enumerator output")

        # Filter out platform noise services
        try:
            from service_enumerator import SKIP_SERVICES
            before = len(services)
            services = [s for s in services if s not in SKIP_SERVICES]
            skipped = before - len(services)
            if skipped:
                print(f"  Filtered {skipped} platform/catalog services (SKIP_SERVICES)")
        except ImportError:
            pass

    elif args.services:
        services = [s.strip() for s in args.services.split(',')]

    elif args.all:
        session = boto3.Session(region_name=args.region)
        services = sorted(session.get_available_services())
        print(f"All boto3 services: {len(services)}")

    else:
        print("Specify --services, --from-enum, or --all")
        sys.exit(1)

    # Check which services already have hand-crafted templates
    handcrafted_dir = os.path.join(script_dir, 'templates')
    existing = set()
    if os.path.isdir(handcrafted_dir):
        for f in os.listdir(handcrafted_dir):
            if f.endswith('.yaml') and f != 'auto':
                try:
                    with open(os.path.join(handcrafted_dir, f)) as fh:
                        t = yaml.safe_load(fh)
                        if t and 'service' in t:
                            existing.add(t['service'])
                            # Also track the client name for multi-template services
                            existing.add(t.get('client', t['service']))
                except Exception:
                    pass

    print(f"Hand-crafted templates exist for: {len(existing)} services")
    print(f"Generating auto-templates for services without hand-crafted ones...\n")

    generated = 0
    skipped_existing = 0
    skipped_no_op = 0

    for svc in services:
        # Skip if hand-crafted template exists
        if svc in existing:
            skipped_existing += 1
            continue

        template = generate_template(svc, args.region)
        if template:
            filepath = write_template(template, output_dir)
            print(f"  ✓ {svc:35s} -> {os.path.basename(filepath)}")
            generated += 1
        else:
            skipped_no_op += 1

    print(f"\nDone: {generated} generated, "
          f"{skipped_existing} skipped (hand-crafted exists), "
          f"{skipped_no_op} skipped (no usable list operation)")
    print(f"Output: {output_dir}")


if __name__ == "__main__":
    main()
