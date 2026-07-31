#!/usr/bin/env python3
"""
CFN Immutables Auditor — Schema-driven discovery of create-only properties.

Pulls the CloudFormation Resource Type Schema for every resource type we
care about and extracts `createOnlyProperties` — the fields that CANNOT
be changed after creation (require resource replacement).

Two modes:
  1. audit   — Compare against our discovery templates, report gaps
  2. dump    — Dump all immutable properties for a list of resource types
  3. enrich  — Auto-add missing immutable fields to discovery templates

The CFN Registry schema is the single source of truth for what's immutable.
No more guessing.

Usage:
    python3 cfn_immutables.py --mode audit
    python3 cfn_immutables.py --mode dump --types AWS::EC2::Instance AWS::RDS::DBInstance
    python3 cfn_immutables.py --mode dump --all-mapped
    python3 cfn_immutables.py --mode audit --region us-gov-west-1

Requires: boto3 with cloudformation access (DescribeType is read-only).
"""

import boto3
import json
import yaml
import os
import sys
import re
import argparse
from typing import Dict, List, Set, Optional, Any
from collections import OrderedDict


# ═══════════════════════════════════════════════════════════════════
# MAP: inventory category → CFN resource type
# This bridges our discovery world to the CFN schema world.
# ═══════════════════════════════════════════════════════════════════

CATEGORY_TO_CFN_TYPE = {
    'EC2 Instances': 'AWS::EC2::Instance',
    'Security Groups': 'AWS::EC2::SecurityGroup',
    'VPCs': 'AWS::EC2::VPC',
    'Subnets': 'AWS::EC2::Subnet',
    'Route Tables': 'AWS::EC2::RouteTable',
    'NAT Gateways': 'AWS::EC2::NatGateway',
    'VPC Endpoints': 'AWS::EC2::VPCEndpoint',
    'DHCP Options': 'AWS::EC2::DHCPOptions',
    'Transit Gateways': 'AWS::EC2::TransitGateway',
    'Transit Gateway Attachments': 'AWS::EC2::TransitGatewayAttachment',
    'Customer Gateways': 'AWS::EC2::CustomerGateway',
    'VPN Connections': 'AWS::EC2::VPNConnection',
    'Load Balancers': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
    'Target Groups': 'AWS::ElasticLoadBalancingV2::TargetGroup',
    'Listeners': 'AWS::ElasticLoadBalancingV2::Listener',
    'RDS DB Clusters': 'AWS::RDS::DBCluster',
    'RDS Instances': 'AWS::RDS::DBInstance',
    'RDS DB Subnet Groups': 'AWS::RDS::DBSubnetGroup',
    'RDS Parameter Groups': 'AWS::RDS::DBParameterGroup',
    'RDS Cluster Parameter Groups': 'AWS::RDS::DBClusterParameterGroup',
    'RDS Option Groups': 'AWS::RDS::OptionGroup',
    'FSx File Systems': 'AWS::FSx::FileSystem',
    'Lambda Functions': 'AWS::Lambda::Function',
    'EventBridge Rules': 'AWS::Events::Rule',
    'S3 Buckets': 'AWS::S3::Bucket',
    'KMS Keys': 'AWS::KMS::Key',
    'ACM Certificates': 'AWS::CertificateManager::Certificate',
    'SNS Topics': 'AWS::SNS::Topic',
    'CloudWatch Alarms': 'AWS::CloudWatch::Alarm',
    'ElastiCache Clusters': 'AWS::ElastiCache::CacheCluster',
    'ElastiCache Replication Groups': 'AWS::ElastiCache::ReplicationGroup',
    'Auto Scaling Groups': 'AWS::AutoScaling::AutoScalingGroup',
    'ECS Clusters': 'AWS::ECS::Cluster',
    'ECS Services': 'AWS::ECS::Service',
    'EKS Clusters': 'AWS::EKS::Cluster',
    'DynamoDB Tables': 'AWS::DynamoDB::Table',
    'SQS Queues': 'AWS::SQS::Queue',
    'Directories': 'AWS::DirectoryService::MicrosoftAD',
    'Hosted Zones': 'AWS::Route53::HostedZone',
    'WAF Web ACLs': 'AWS::WAFv2::WebACL',
}


# ═══════════════════════════════════════════════════════════════════
# SCHEMA FETCHING
# ═══════════════════════════════════════════════════════════════════

def get_type_schema(cfn_client, type_name: str) -> Optional[dict]:
    """Fetch the CloudFormation Resource Type Schema via DescribeType.

    Returns the parsed schema dict, or None if the type isn't available.
    """
    try:
        response = cfn_client.describe_type(
            Type='RESOURCE',
            TypeName=type_name
        )
        schema_str = response.get('Schema', '{}')
        return json.loads(schema_str)
    except cfn_client.exceptions.TypeNotFoundException:
        print(f"  WARNING: Type {type_name} not found in this region")
        return None
    except cfn_client.exceptions.CFNRegistryException as e:
        print(f"  WARNING: Registry error for {type_name}: {e}")
        return None
    except Exception as e:
        print(f"  ERROR fetching schema for {type_name}: {e}")
        return None


def extract_immutable_properties(schema: dict) -> List[str]:
    """Extract createOnlyProperties from a CFN type schema.

    These are JSON Pointer paths like '/properties/Engine'.
    We convert them to simple property names.
    """
    create_only = schema.get('createOnlyProperties', [])
    # Convert JSON Pointer format: /properties/SubnetId -> SubnetId
    result = []
    for prop_path in create_only:
        # Remove leading /properties/
        clean = prop_path.replace('/properties/', '')
        # Handle nested: /properties/WindowsConfiguration/DeploymentType
        # -> WindowsConfiguration.DeploymentType
        clean = clean.replace('/', '.')
        result.append(clean)
    return sorted(result)


def extract_all_properties(schema: dict) -> Dict[str, Any]:
    """Extract all properties from schema with their types."""
    props = schema.get('properties', {})
    return props


def extract_read_only_properties(schema: dict) -> List[str]:
    """Extract readOnlyProperties — can't set these, they're computed."""
    read_only = schema.get('readOnlyProperties', [])
    result = []
    for prop_path in read_only:
        clean = prop_path.replace('/properties/', '').replace('/', '.')
        result.append(clean)
    return sorted(result)


def extract_write_only_properties(schema: dict) -> List[str]:
    """Extract writeOnlyProperties — can set but can't read back (passwords etc)."""
    write_only = schema.get('writeOnlyProperties', [])
    result = []
    for prop_path in write_only:
        clean = prop_path.replace('/properties/', '').replace('/', '.')
        result.append(clean)
    return sorted(result)


# ═══════════════════════════════════════════════════════════════════
# TEMPLATE COMPARISON
# ═══════════════════════════════════════════════════════════════════

def load_discovery_templates(templates_dir: str) -> Dict[str, List[str]]:
    """Load all discovery templates and extract config_fields per operation.

    Returns: {operation_name: [field1, field2, ...]}
    """
    fields_by_operation = {}
    for filename in sorted(os.listdir(templates_dir)):
        if not filename.endswith('.yaml'):
            continue
        filepath = os.path.join(templates_dir, filename)
        with open(filepath, 'r') as f:
            template = yaml.safe_load(f)
        if not template or 'operations' not in template:
            continue
        for op in template['operations']:
            op_name = op.get('name', '')
            fields = op.get('config_fields', [])
            # Normalize field names: SecurityGroups[].GroupId -> SecurityGroups.GroupId
            normalized = []
            for field in fields:
                clean = str(field).replace('[]', '')
                normalized.append(clean)
            fields_by_operation[op_name] = normalized
    return fields_by_operation


def normalize_cfn_prop_to_api_field(cfn_prop: str) -> List[str]:
    """Convert a CFN property name to possible API response field names.

    CFN and boto3 API responses don't always use the same names.
    Returns a list of possible matches.
    """
    candidates = [cfn_prop]

    # Common renames
    renames = {
        'VpcId': ['VpcId', 'VPCId'],
        'SubnetId': ['SubnetId', 'SubnetIds'],
        'SubnetIds': ['SubnetIds', 'SubnetId'],
        'SecurityGroupIds': ['SecurityGroups', 'SecurityGroupIds', 'GroupId'],
        'SecurityGroups': ['SecurityGroups', 'SecurityGroupIds'],
        'ImageId': ['ImageId'],
        'InstanceType': ['InstanceType'],
        'KeyName': ['KeyName'],
        'AvailabilityZone': ['AvailabilityZone', 'Placement.AvailabilityZone', 'PreferredAvailabilityZone'],
        'Tenancy': ['Tenancy', 'Placement.Tenancy', 'InstanceTenancy'],
        'PlacementGroupName': ['Placement.GroupName', 'PlacementGroupName'],
        'HostId': ['Placement.HostId', 'HostId'],
        'Engine': ['Engine'],
        'StorageEncrypted': ['StorageEncrypted'],
        'KmsKeyId': ['KmsKeyId'],
        'DBInstanceIdentifier': ['DBInstanceIdentifier'],
        'DBClusterIdentifier': ['DBClusterIdentifier'],
        'Protocol': ['Protocol'],
        'Port': ['Port'],
        'TargetType': ['TargetType'],
        'ProtocolVersion': ['ProtocolVersion'],
        'IpAddressType': ['IpAddressType'],
        'Type': ['Type', 'FileSystemType', 'VpcEndpointType'],
        'Scheme': ['Scheme'],
        'FileSystemType': ['FileSystemType'],
        'StorageType': ['StorageType'],
        'DeploymentType': ['DeploymentType', 'WindowsConfiguration.DeploymentType',
                           'LustreConfiguration.DeploymentType', 'OntapConfiguration.DeploymentType'],
        'StorageCapacity': ['StorageCapacity'],
        'CharacterSetName': ['CharacterSetName'],
        'LicenseModel': ['LicenseModel'],
        'NetworkType': ['NetworkType'],
        'MasterUsername': ['MasterUsername'],
        'DatabaseName': ['DatabaseName', 'DBName'],
        'EngineMode': ['EngineMode'],
        'CidrBlock': ['CidrBlock'],
        'BgpAsn': ['BgpAsn'],
        'IpAddress': ['IpAddress'],
    }

    if cfn_prop in renames:
        candidates = renames[cfn_prop]
    else:
        # Try dotted notation for nested props
        # WindowsConfiguration.DeploymentType -> WindowsConfiguration.DeploymentType
        candidates.append(cfn_prop)

    return candidates


def audit_category(category: str, cfn_type: str, immutables: List[str],
                   captured_fields: List[str]) -> List[dict]:
    """Compare immutable properties against what we capture.

    Returns list of gap dicts: {property, cfn_type, category, severity}
    """
    gaps = []

    for immutable in immutables:
        # Check if any of the possible field name variants are captured
        possible_names = normalize_cfn_prop_to_api_field(immutable)

        found = False
        for candidate in possible_names:
            # Check exact match or prefix match (for nested fields)
            for captured in captured_fields:
                if (captured == candidate or
                    captured.startswith(candidate + '.') or
                    candidate.startswith(captured + '.') or
                    captured.endswith('.' + candidate) or
                    candidate.endswith('.' + captured)):
                    found = True
                    break
            if found:
                break

        if not found:
            gaps.append({
                'property': immutable,
                'cfn_type': cfn_type,
                'category': category,
                'severity': 'HIGH',
                'note': f'Immutable (createOnly) property not captured in discovery',
            })

    return gaps


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='CFN Immutables Auditor — find missing create-only properties.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--mode', default='audit', choices=['audit', 'dump'],
                        help='audit: compare against templates. dump: show immutables.')
    parser.add_argument('--region', default=None,
                        help='AWS region for DescribeType calls')
    parser.add_argument('--types', nargs='*', default=None,
                        help='Specific CFN type names to check (dump mode)')
    parser.add_argument('--all-mapped', action='store_true',
                        help='Process all types in CATEGORY_TO_CFN_TYPE')
    parser.add_argument('--templates-dir', default='templates',
                        help='Path to discovery templates directory')
    parser.add_argument('--output', default=None,
                        help='Output file for results (YAML)')
    args = parser.parse_args()

    # Determine which types to process
    if args.types:
        types_to_check = {t: t for t in args.types}  # type_name -> type_name
    elif args.all_mapped or args.mode == 'audit':
        types_to_check = CATEGORY_TO_CFN_TYPE  # category -> type_name
    else:
        print("ERROR: Specify --types or --all-mapped")
        sys.exit(1)

    # Create CloudFormation client
    session_kwargs = {}
    if args.region:
        session_kwargs['region_name'] = args.region
    session = boto3.Session(**session_kwargs)
    cfn = session.client('cloudformation')
    region = session.region_name
    print(f"Region: {region}")
    print(f"Checking {len(types_to_check)} resource types...\n")

    # Load discovery templates for audit mode
    discovery_fields = {}
    if args.mode == 'audit':
        templates_dir = os.path.abspath(args.templates_dir)
        if os.path.isdir(templates_dir):
            discovery_fields = load_discovery_templates(templates_dir)
            print(f"Loaded {len(discovery_fields)} operation field sets from {templates_dir}/\n")
        else:
            print(f"WARNING: Templates dir not found: {templates_dir}")
            print("  Running in dump mode instead.\n")
            args.mode = 'dump'

    all_results = OrderedDict()
    all_gaps = []

    for category, cfn_type in sorted(types_to_check.items(),
                                       key=lambda x: x[1]):
        print(f"  {cfn_type}...", end=' ', flush=True)
        schema = get_type_schema(cfn, cfn_type)
        if not schema:
            print("UNAVAILABLE")
            continue

        immutables = extract_immutable_properties(schema)
        read_only = extract_read_only_properties(schema)
        write_only = extract_write_only_properties(schema)

        result = {
            'cfn_type': cfn_type,
            'category': category,
            'create_only_properties': immutables,
            'read_only_count': len(read_only),
            'write_only_properties': write_only,
        }

        if args.mode == 'audit' and category in discovery_fields:
            captured = discovery_fields[category]
            gaps = audit_category(category, cfn_type, immutables, captured)
            result['captured_fields_count'] = len(captured)
            result['gaps'] = gaps
            all_gaps.extend(gaps)

            if gaps:
                print(f"{len(immutables)} immutables, {len(gaps)} GAPS")
                for gap in gaps:
                    print(f"    ⚠ MISSING: {gap['property']}")
            else:
                print(f"{len(immutables)} immutables, all captured ✓")
        else:
            print(f"{len(immutables)} immutables")
            if immutables:
                for prop in immutables:
                    print(f"    • {prop}")

        all_results[cfn_type] = result

    # Summary
    print(f"\n{'═' * 60}")
    print(f"SUMMARY: {len(all_results)} types checked")
    if args.mode == 'audit':
        print(f"  Total gaps found: {len(all_gaps)}")
        if all_gaps:
            print(f"\n  MISSING IMMUTABLE PROPERTIES:")
            by_category = {}
            for gap in all_gaps:
                cat = gap['category']
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(gap['property'])
            for cat in sorted(by_category.keys()):
                props = by_category[cat]
                print(f"    {cat}:")
                for p in props:
                    print(f"      - {p}")
    print(f"{'═' * 60}")

    # Output
    if args.output:
        output_data = {
            'region': region,
            'mode': args.mode,
            'types_checked': len(all_results),
            'total_gaps': len(all_gaps) if args.mode == 'audit' else None,
            'results': dict(all_results),
        }
        with open(args.output, 'w') as f:
            yaml.dump(output_data, f, default_flow_style=False, sort_keys=False)
        print(f"\nResults written to: {args.output}")


if __name__ == '__main__':
    main()
