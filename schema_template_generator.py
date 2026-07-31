#!/usr/bin/env python3
"""
Schema Template Generator — Generic CFN resource block generation.

For ANY resource in the inventory, this module:
  1. Looks up its CFN type schema (via cfn_schema_cache)
  2. Matches inventory config fields to schema properties
  3. Emits a CFN resource properties block with all matching fields
  4. Parameterizes region-specific values (IDs, ARNs, AZs)
  5. Marks immutable properties in the parameter file

This is the "default path" for resource generation. Bespoke handlers
(SG cross-refs, LB action wiring) override this for resources that
need special treatment.

Usage:
    from schema_template_generator import generate_resource_block
    result = generate_resource_block(
        cfn_type='AWS::EC2::Instance',
        resource_config=instance_config_dict,
        resource_name='AppServer1',
        resource_id='i-abc123',
        region='us-gov-west-1',
    )
    # result.properties  -> OrderedDict for CFN template
    # result.parameters  -> OrderedDict of parameters to declare
    # result.param_values -> OrderedDict for the params YAML file
    # result.param_comments -> dict of comments per param
"""

import re
import os
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import OrderedDict
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ResourceBlock:
    """Result of generating a single resource's CFN block."""
    logical_id: str
    cfn_type: str
    properties: OrderedDict = field(default_factory=OrderedDict)
    parameters: OrderedDict = field(default_factory=OrderedDict)
    param_values: OrderedDict = field(default_factory=OrderedDict)
    param_comments: Dict[str, str] = field(default_factory=dict)
    outputs: OrderedDict = field(default_factory=OrderedDict)
    depends_on: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════
# CONSTANTS — field classification for parameterization
# ═══════════════════════════════════════════════════════════════════

# Fields that contain region-specific resource IDs and must be
# parameterized (the DR region will have different values).
REGION_SPECIFIC_PATTERNS = [
    r'^arn:',                          # Any ARN
    r'^ami-',                          # AMI IDs
    r'^subnet-',                       # Subnet IDs
    r'^sg-',                           # Security Group IDs
    r'^vpc-',                          # VPC IDs
    r'^rtb-',                          # Route Table IDs
    r'^igw-',                          # Internet Gateway IDs
    r'^nat-',                          # NAT Gateway IDs
    r'^eni-',                          # ENI IDs
    r'^vol-',                          # Volume IDs
    r'^snap-',                         # Snapshot IDs
    r'^key-',                          # KMS Key IDs
    r'^vpce-',                         # VPC Endpoint IDs
    r'^tgw-',                          # Transit Gateway IDs
    r'^cgw-',                          # Customer Gateway IDs
    r'^vgw-',                          # Virtual Private Gateway IDs
    r'^dopt-',                         # DHCP Options IDs
    r'^acl-',                          # Network ACL IDs
    r'^pcx-',                          # VPC Peering Connection IDs
    r'us-gov-\w+-\d',                  # Region names in values
    r'us-east-\d',
    r'us-west-\d',
    r'eu-\w+-\d',
    r'ap-\w+-\d',
]

_REGION_SPECIFIC_RE = [re.compile(p) for p in REGION_SPECIFIC_PATTERNS]


# Properties to NEVER include in templates (computed, read-only, or AWS-managed)
SKIP_PROPERTIES = {
    # Computed values / resource identifiers (assigned by AWS)
    'Arn', 'Id', 'DnsName', 'Endpoint', 'PrivateIpAddress',
    'PublicIpAddress', 'PublicDnsName', 'PrivateDnsName',
    'CreatedTime', 'CreateTime', 'LaunchTime', 'CreationDate',
    'Status', 'State', 'InstanceState',
    'InstanceId', 'VolumeId', 'SnapshotId', 'AllocationId',
    'AssociationId', 'NetworkInterfaceId', 'AttachmentId',
    'DBInstanceArn', 'DBClusterArn', 'FileSystemId',
    'CacheClusterId', 'ReplicationGroupId',
    'LoadBalancerArn', 'TargetGroupArn', 'ListenerArn',
    'CertificateArn', 'TopicArn', 'QueueUrl',
    'FunctionArn', 'RuleArn',
    'NatGatewayId', 'VpcEndpointId', 'TransitGatewayId',
    'CustomerGatewayId', 'VpnConnectionId', 'VpnGatewayId',
    'VpcPeeringConnectionId', 'InternetGatewayId',
    'RouteTableId', 'SubnetId', 'VpcId', 'DhcpOptionsId',
    # AWS-managed metadata
    'OwnerId', 'AccountId', 'RequesterId',
    # State fields
    'StateTransitionReason', 'StateReason',
    'AvailabilityZone',  # derived from subnet, not set directly
}

# Properties that are typically cross-stack references (import from another group)
CROSS_STACK_FIELDS = {
    'VpcId', 'SubnetId', 'SubnetIds', 'SecurityGroupIds',
    'SecurityGroups', 'GroupId',
}

# Config field names that map to different CFN property names
# (inventory uses API response names, CFN uses different names sometimes)
CONFIG_TO_CFN_RENAMES = {
    'GroupId': 'SecurityGroupIds',       # EC2 instance SGs
    'VpcSecurityGroupId': 'VpcSecurityGroupIds',  # RDS
    'Address': 'Endpoint',               # skip (read-only)
}


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

def safe_logical_id(name: str) -> str:
    """Convert a resource name/ID to a valid CFN logical ID."""
    clean = re.sub(r'[^a-zA-Z0-9]', '', name)
    if clean and not clean[0].isalpha():
        clean = 'R' + clean
    return clean[:64] or 'Unknown'


def _is_region_specific(value: Any) -> bool:
    """Check if a value contains region-specific content that needs
    parameterization for DR."""
    if not isinstance(value, str):
        return False
    if not value:
        return False
    return any(p.search(value) for p in _REGION_SPECIFIC_RE)


def _is_empty(value: Any) -> bool:
    """Check if a value is effectively empty."""
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == '':
        return True
    if isinstance(value, list) and len(value) == 0:
        return True
    if isinstance(value, dict) and len(value) == 0:
        return True
    return False


def _make_param_name(logical_id: str, prop_name: str) -> str:
    """Create a parameter name from logical ID and property."""
    # Keep it readable: AppServer1ImageId
    return f'{logical_id}{prop_name}'


# ═══════════════════════════════════════════════════════════════════
# SCHEMA PROPERTY MATCHING
#
# The core logic: match inventory config fields to CFN schema
# properties, deciding for each one whether to:
#   - Hardcode it in the template (non-region-specific static value)
#   - Parameterize it (region-specific, needs DR value)
#   - Reference another stack (!ImportValue)
#   - Skip it (read-only, computed)
# ═══════════════════════════════════════════════════════════════════

def _get_schema_properties(schema: Optional[dict]) -> Dict[str, dict]:
    """Extract the properties dict from a CFN schema."""
    if not schema:
        return {}
    return schema.get('properties', {})


def _get_required_properties(schema: Optional[dict]) -> Set[str]:
    """Get required properties from schema."""
    if not schema:
        return set()
    return set(schema.get('required', []))


def _get_create_only(schema: Optional[dict]) -> Set[str]:
    """Get immutable (create-only) property names from schema."""
    if not schema:
        return set()
    result = set()
    for path in schema.get('createOnlyProperties', []):
        # /properties/Engine -> Engine
        clean = path.replace('/properties/', '').replace('/', '.')
        # Take just the top-level name for matching
        result.add(clean.split('.')[0])
    return result


def _get_read_only(schema: Optional[dict]) -> Set[str]:
    """Get read-only property names from schema."""
    if not schema:
        return set()
    result = set()
    for path in schema.get('readOnlyProperties', []):
        clean = path.replace('/properties/', '').replace('/', '.')
        result.add(clean.split('.')[0])
    return result


def _match_config_to_schema(config: dict, schema_props: Dict[str, dict],
                             read_only: Set[str]) -> Dict[str, Any]:
    """Match inventory config fields to schema properties.

    Returns dict of {cfn_property_name: value_from_config}.
    Only includes properties that:
      - Exist in the schema
      - Have a non-empty value in config
      - Are not read-only
    """
    matched = {}

    # Direct match: config key == schema property name (case-insensitive lookup)
    schema_lower = {k.lower(): k for k in schema_props.keys()}

    for config_key, value in config.items():
        if config_key == 'Tags':
            # Tags handled separately
            continue
        if _is_empty(value):
            continue

        # Check for renames
        cfn_key = CONFIG_TO_CFN_RENAMES.get(config_key, config_key)
        if cfn_key in SKIP_PROPERTIES:
            continue

        # Try exact match first
        if cfn_key in schema_props:
            if cfn_key not in read_only:
                matched[cfn_key] = value
            continue

        # Try case-insensitive match
        cfn_key_lower = cfn_key.lower()
        if cfn_key_lower in schema_lower:
            actual_key = schema_lower[cfn_key_lower]
            if actual_key not in read_only:
                matched[actual_key] = value
            continue

        # Try common API-to-CFN name transformations
        # e.g., InstanceType in both API and CFN — usually matches directly
        # But some like GroupId -> SecurityGroupIds need the renames dict

    return matched


# ═══════════════════════════════════════════════════════════════════
# PROPERTY VALUE HANDLING
#
# For each matched property, decide how it appears in the template:
#   - Static: hardcoded value in Properties block
#   - Parameterized: {Ref: ParamName} with value in params file
#   - Cross-stack: {Fn::ImportValue: ...} for refs to other groups
# ═══════════════════════════════════════════════════════════════════

def _classify_value(prop_name: str, value: Any,
                    immutables: Set[str],
                    cross_stack_ids: Set[str]) -> str:
    """Classify how a property value should be represented.

    Returns one of: 'static', 'parameter', 'cross_stack', 'skip'
    """
    # Cross-stack references take priority
    if prop_name in CROSS_STACK_FIELDS:
        if isinstance(value, str) and value in cross_stack_ids:
            return 'cross_stack'
        if isinstance(value, list):
            if any(v in cross_stack_ids for v in value if isinstance(v, str)):
                return 'cross_stack'

    # Region-specific values must be parameterized
    if isinstance(value, str) and _is_region_specific(value):
        return 'parameter'

    if isinstance(value, list):
        if any(_is_region_specific(v) for v in value if isinstance(v, str)):
            return 'parameter'

    # Immutable properties should be parameterized (operator must verify)
    if prop_name in immutables:
        return 'parameter'

    return 'static'


def _build_cfn_value(prop_name: str, value: Any, classification: str,
                     logical_id: str, param_name: str,
                     foundation_stack: str) -> Any:
    """Build the CFN template value for a property based on classification.

    Returns the value to place in the Properties block.
    """
    if classification == 'static':
        return value

    if classification == 'parameter':
        return {'Ref': param_name}

    if classification == 'cross_stack':
        # Cross-stack references use ImportValue from the foundation or SG stack.
        # The actual stack name is parameterized at the template level.
        return {'Fn::ImportValue': {
            'Fn::Sub': f'${{{foundation_stack}}}-{safe_logical_id(str(value))}'
        }}

    return value  # fallback


def _build_param_type(value: Any) -> str:
    """Determine the CFN parameter type for a value."""
    if isinstance(value, list):
        return 'CommaDelimitedList'
    if isinstance(value, bool):
        return 'String'  # CFN has no bool param type
    if isinstance(value, int):
        return 'Number'
    return 'String'


# ═══════════════════════════════════════════════════════════════════
# TAGS HANDLING
# ═══════════════════════════════════════════════════════════════════

def _build_tags(resource_name: str, resource_id: str,
                source_tags: dict) -> List[dict]:
    """Build the Tags array for a CFN resource.

    Preserves meaningful source tags, adds DR metadata tags.
    Strips AWS-managed tags (aws: prefix).
    """
    tags = [
        {'Key': 'Name', 'Value': resource_name},
        {'Key': 'SourceResourceId', 'Value': resource_id},
    ]

    # Preserve customer tags (skip aws: prefix and CDK internal tags)
    skip_prefixes = ('aws:', 'aws-cdk:', 'cloudformation:')
    for key, val in sorted(source_tags.items()):
        if key == 'Name':
            continue  # Already added
        if any(key.lower().startswith(p) for p in skip_prefixes):
            continue
        tags.append({'Key': key, 'Value': str(val)})

    return tags


# ═══════════════════════════════════════════════════════════════════
# OUTPUT GENERATION — per-resource CFN block
# ═══════════════════════════════════════════════════════════════════

# Fields that should generate Outputs (exports for other stacks)
OUTPUT_FIELDS = {
    'AWS::EC2::VPC': [('VpcId', 'Ref')],
    'AWS::EC2::Subnet': [('SubnetId', 'Ref')],
    'AWS::EC2::SecurityGroup': [('GroupId', 'GetAtt.GroupId')],
    'AWS::EC2::NatGateway': [('NatGatewayId', 'Ref')],
    'AWS::EC2::Instance': [('InstanceId', 'Ref'),
                           ('PrivateIp', 'GetAtt.PrivateIp')],
    'AWS::RDS::DBCluster': [('Endpoint', 'GetAtt.Endpoint.Address')],
    'AWS::RDS::DBInstance': [('Endpoint', 'GetAtt.Endpoint.Address')],
    'AWS::ElasticLoadBalancingV2::LoadBalancer': [
        ('DNSName', 'GetAtt.DNSName'),
        ('LoadBalancerArn', 'Ref'),
    ],
    'AWS::ElasticLoadBalancingV2::TargetGroup': [
        ('TargetGroupArn', 'Ref')],
    'AWS::KMS::Key': [('KeyArn', 'GetAtt.Arn')],
    'AWS::Lambda::Function': [('FunctionArn', 'GetAtt.Arn')],
    'AWS::FSx::FileSystem': [('DNSName', 'GetAtt.DNSName')],
    'AWS::SNS::Topic': [('TopicArn', 'Ref')],
    'AWS::SQS::Queue': [('QueueUrl', 'Ref')],
}


def _build_outputs(logical_id: str, cfn_type: str,
                   stack_name_ref: str) -> OrderedDict:
    """Build Outputs for a resource based on its type."""
    outputs = OrderedDict()
    output_defs = OUTPUT_FIELDS.get(cfn_type, [])

    for suffix, value_type in output_defs:
        output_key = f'{logical_id}{suffix}'
        if value_type == 'Ref':
            value = {'Ref': logical_id}
        elif value_type.startswith('GetAtt.'):
            attr = value_type[len('GetAtt.'):]
            value = {'Fn::GetAtt': [logical_id, attr]}
        else:
            continue

        outputs[output_key] = {
            'Value': value,
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical_id}{suffix}'}},
        }

    return outputs


# ═══════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════

def generate_resource_block(cfn_type: str,
                            resource_config: dict,
                            resource_name: str,
                            resource_id: str,
                            region: str = '',
                            schema: Optional[dict] = None,
                            cross_stack_ids: Optional[Set[str]] = None,
                            foundation_stack: str = 'FoundationStack',
                            ) -> ResourceBlock:
    """Generate a complete CFN resource block from config + schema.

    This is the main entry point for schema-driven generation.

    Args:
        cfn_type: e.g., 'AWS::EC2::Instance'
        resource_config: config dict from inventory
        resource_name: human-readable name
        resource_id: source resource ID (e.g., 'i-abc123')
        region: source region (for parameterization detection)
        schema: pre-fetched CFN schema dict (optional, fetched if None)
        cross_stack_ids: set of resource IDs from other deployment groups
        foundation_stack: parameter name referencing the foundation stack

    Returns:
        ResourceBlock with all template artifacts
    """
    cross_stack_ids = cross_stack_ids or set()
    logical_id = safe_logical_id(resource_name or resource_id)

    # Fetch schema if not provided
    if schema is None:
        try:
            from cfn_schema_cache import fetch_schema
            schema = fetch_schema(cfn_type, region) or {}
        except Exception:
            schema = {}

    schema_props = _get_schema_properties(schema)
    read_only = _get_read_only(schema)
    immutables = _get_create_only(schema)

    # Match config fields to schema
    matched = _match_config_to_schema(resource_config, schema_props, read_only)

    # If no schema available, fall back to including all non-empty config fields
    # (minus known skip properties and Tags)
    if not schema_props:
        matched = {}
        for key, value in resource_config.items():
            if key == 'Tags' or key in SKIP_PROPERTIES or _is_empty(value):
                continue
            matched[key] = value

    # Build the properties block
    result = ResourceBlock(
        logical_id=logical_id,
        cfn_type=cfn_type,
    )

    properties = OrderedDict()
    for prop_name, value in sorted(matched.items()):
        classification = _classify_value(
            prop_name, value, immutables, cross_stack_ids)

        if classification == 'skip':
            continue

        param_name = _make_param_name(logical_id, prop_name)

        if classification == 'static':
            properties[prop_name] = value

        elif classification == 'parameter':
            properties[prop_name] = {'Ref': param_name}
            # Declare the parameter
            param_type = _build_param_type(value)
            result.parameters[param_name] = {
                'Type': param_type,
                'Description': f'{prop_name} for {resource_name} '
                               f'(source: {_summarize_value(value)})',
            }
            # Parameter file entry
            if isinstance(value, list):
                result.param_values[param_name] = value
            else:
                result.param_values[param_name] = str(value) if value else ''

            # Comment for param file
            is_immutable = prop_name in immutables
            comment = f'Source value: {_summarize_value(value)}'
            if is_immutable:
                comment = (f'IMMUTABLE: {prop_name} — cannot change after '
                           f'creation. Source: {_summarize_value(value)}')
            result.param_comments[param_name] = comment

        elif classification == 'cross_stack':
            # For list values, build a list of ImportValue refs
            if isinstance(value, list):
                refs = []
                for v in value:
                    if isinstance(v, str) and v in cross_stack_ids:
                        refs.append({'Fn::ImportValue': {
                            'Fn::Sub': f'${{{foundation_stack}}}-'
                                       f'{safe_logical_id(v)}'
                        }})
                    else:
                        refs.append(v)
                properties[prop_name] = refs
            else:
                properties[prop_name] = {'Fn::ImportValue': {
                    'Fn::Sub': f'${{{foundation_stack}}}-'
                               f'{safe_logical_id(str(value))}'
                }}

    # Add Tags
    source_tags = resource_config.get('Tags', {})
    if isinstance(source_tags, dict):
        tags = _build_tags(resource_name, resource_id, source_tags)
        properties['Tags'] = tags

    result.properties = properties

    # Build outputs
    result.outputs = _build_outputs(logical_id, cfn_type, foundation_stack)

    # Warn about immutable properties not in inventory
    for prop in immutables:
        if prop not in matched and prop not in read_only:
            result.warnings.append(
                f'IMMUTABLE property {prop} not found in inventory config. '
                f'Verify value before deploying.')

    return result


def _summarize_value(value: Any) -> str:
    """Create a short summary of a value for parameter comments."""
    if isinstance(value, str):
        if len(value) > 60:
            return value[:57] + '...'
        return value
    if isinstance(value, list):
        if len(value) <= 3:
            return str(value)
        return f'[{value[0]}, ... ({len(value)} items)]'
    return str(value)[:60]


# ═══════════════════════════════════════════════════════════════════
# BATCH GENERATION — generate blocks for an entire deployment group
# ═══════════════════════════════════════════════════════════════════

def generate_group_template(group_name: str,
                            resources: list,
                            region: str = '',
                            cross_stack_ids: Optional[Set[str]] = None,
                            schemas: Optional[Dict[str, dict]] = None,
                            description: str = '',
                            depends_on_stacks: Optional[List[str]] = None,
                            ) -> Tuple[OrderedDict, OrderedDict, Dict[str, str]]:
    """Generate a complete CFN template for a deployment group.

    Args:
        group_name: e.g., 'foundation', 'security', 'compute'
        resources: list of ResourceNode objects from dependency_graph
        region: source region
        cross_stack_ids: resource IDs that live in other groups
        schemas: pre-fetched {cfn_type: schema_dict}
        description: template description
        depends_on_stacks: stack names this group depends on

    Returns:
        (template_dict, param_values_dict, param_comments_dict)
    """
    cross_stack_ids = cross_stack_ids or set()
    schemas = schemas or {}
    depends_on_stacks = depends_on_stacks or []

    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = description or f'DR {group_name} stack'

    # Standard parameters for cross-stack references
    template['Parameters'] = OrderedDict()
    for dep_stack in depends_on_stacks:
        param_key = safe_logical_id(dep_stack) + 'Stack'
        template['Parameters'][param_key] = {
            'Type': 'String',
            'Default': f'dr-{dep_stack}',
            'Description': f'Name of the {dep_stack} stack',
        }

    template['Resources'] = OrderedDict()
    template['Outputs'] = OrderedDict()

    all_param_values = OrderedDict()
    all_param_comments = {}

    # Add default param values for stack references
    for dep_stack in depends_on_stacks:
        param_key = safe_logical_id(dep_stack) + 'Stack'
        all_param_values[param_key] = f'dr-{dep_stack}'
        all_param_comments[param_key] = f'Stack name for {dep_stack} tier'

    for res in resources:
        schema = schemas.get(res.cfn_type)

        # Determine which foundation stack param to use for imports
        # Default to 'FoundationStack' but could be 'SecurityStack' etc.
        foundation_param = 'foundationStack'
        if res.tier in ('compute', 'dc_compute', 'network', 'data',
                        'containers', 'serverless'):
            # These reference both foundation and security
            foundation_param = 'foundationStack'

        block = generate_resource_block(
            cfn_type=res.cfn_type,
            resource_config=res.config,
            resource_name=res.name,
            resource_id=res.resource_id,
            region=region,
            schema=schema,
            cross_stack_ids=cross_stack_ids,
            foundation_stack=foundation_param,
        )

        # Add resource to template
        template['Resources'][block.logical_id] = {
            'Type': block.cfn_type,
            'Properties': block.properties,
        }

        # Merge parameters
        for pname, pconfig in block.parameters.items():
            if pname not in template['Parameters']:
                template['Parameters'][pname] = pconfig

        # Merge outputs
        template['Outputs'].update(block.outputs)

        # Merge param values and comments
        all_param_values.update(block.param_values)
        all_param_comments.update(block.param_comments)

    # Clean up empty sections
    if not template['Outputs']:
        del template['Outputs']

    return template, all_param_values, all_param_comments


# ═══════════════════════════════════════════════════════════════════
# CLI (for testing)
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Quick smoke test with a fake resource
    fake_config = {
        'InstanceId': 'i-abc123',
        'InstanceType': 't3.medium',
        'ImageId': 'ami-0123456789abcdef0',
        'SubnetId': 'subnet-111',
        'KeyName': 'my-key',
        'PrivateIpAddress': '10.0.1.5',
        'GroupId': ['sg-001', 'sg-002'],
        'Tags': {'Name': 'AppServer1', 'Env': 'prod', 'Role': 'web'},
    }

    block = generate_resource_block(
        cfn_type='AWS::EC2::Instance',
        resource_config=fake_config,
        resource_name='AppServer1',
        resource_id='i-abc123',
        region='us-gov-west-1',
        schema=None,  # No schema — will use fallback mode
        cross_stack_ids={'subnet-111', 'sg-001', 'sg-002'},
    )

    print(f"Logical ID: {block.logical_id}")
    print(f"Type: {block.cfn_type}")
    print(f"Properties ({len(block.properties)} fields):")
    for k, v in block.properties.items():
        vstr = str(v)[:60]
        print(f"  {k}: {vstr}")
    print(f"\nParameters ({len(block.parameters)}):")
    for k, v in block.parameters.items():
        print(f"  {k}: {v.get('Type', '?')}")
    print(f"\nParam values for file:")
    for k, v in block.param_values.items():
        print(f"  {k}: {v}")
    print(f"\nOutputs ({len(block.outputs)}):")
    for k in block.outputs:
        print(f"  {k}")
    if block.warnings:
        print(f"\nWarnings:")
        for w in block.warnings:
            print(f"  ⚠ {w}")
    print("\n✓ schema_template_generator.py works.")
