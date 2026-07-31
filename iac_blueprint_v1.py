#!/usr/bin/env python3
"""
IaC Blueprint v2 — Tier-Based DR Template Generator

Reads the YAML inventory produced by deep_discover.py and generates
ordered CloudFormation templates grouped into deployment tiers:

  00-foundation.yaml       VPC, Subnets, Route Tables, DHCP Options, NAT GWs
  01-security-groups.yaml  All SGs with cross-references resolved
  02-data-tier.yaml        RDS clusters/instances + subnet groups + param groups + FSx
  03-compute-tier.yaml     EC2 instances (non-DC) with full config
  03a-dc-compute.yaml      Domain Controllers (boot-order critical)
  04-network-tier.yaml     LBs + Listeners + TGs wired to compute
  05-serverless.yaml       Lambda + EventBridge + Step Functions
  06-supporting.yaml       VPC Endpoints, KMS, ACM, SNS, TGW, VPN, CloudWatch

Each tier template uses:
  - !ImportValue for cross-stack references (SG IDs, subnet IDs, VPC ID)
  - YAML parameter files with comments showing source-region values
  - Full resource detail from the discovery inventory

Usage:
    python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730-194817/
    python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730-194817/ --mode dr
"""

import yaml
import os
import sys
import re
import json
import fnmatch
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import OrderedDict, defaultdict


# ═══════════════════════════════════════════════════════════════════
# YAML helpers
# ═══════════════════════════════════════════════════════════════════

def ordered_dict_representer(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items())

yaml.add_representer(OrderedDict, ordered_dict_representer)


def safe_logical_id(name: str) -> str:
    """Convert a resource name/ID to a valid CFN logical ID (alphanumeric only)."""
    clean = re.sub(r'[^a-zA-Z0-9]', '', name)
    if clean and not clean[0].isalpha():
        clean = 'R' + clean
    return clean[:64] or 'Unknown'


def short_name(full_name: str) -> str:
    """Extract a short name from full resource names like 'primary-CcpmNetworking/DC1'."""
    if '/' in full_name:
        return full_name.split('/')[-1]
    return full_name


def subnet_label(subnet: dict) -> str:
    """Get a human-readable label for a subnet from its tags."""
    tags = subnet.get('config', {}).get('Tags', {})
    name = tags.get('Name', '')
    subnet_name_tag = tags.get('aws-cdk:subnet-name', '')
    if subnet_name_tag:
        return subnet_name_tag
    if '/' in name:
        return name.split('/')[-1]
    return name or subnet.get('resource_id', 'unnamed')


# ═══════════════════════════════════════════════════════════════════
# FILTERS
# ═══════════════════════════════════════════════════════════════════

def load_filter_file(filepath: str) -> List[dict]:
    """Load include/exclude YAML filter file."""
    if not filepath or not os.path.isfile(filepath):
        return []
    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def resource_matches_filter(resource: dict, filter_rules: List[dict]) -> bool:
    """Check if a resource matches ANY rule in a filter list."""
    if not filter_rules:
        return False
    config = resource.get('config', {})
    tags = config.get('Tags', {})
    for rule in filter_rules:
        key = rule.get('Key', '')
        pattern = rule.get('Value', '')
        if not key:
            continue
        if key == 'Name' and fnmatch.fnmatch(resource.get('name', ''), pattern):
            return True
        tag_val = tags.get(key, '')
        if tag_val and fnmatch.fnmatch(str(tag_val), pattern):
            return True
        config_val = config.get(key, '')
        if isinstance(config_val, str) and fnmatch.fnmatch(config_val, pattern):
            return True
    return False


def should_include(resource: dict, include_rules: List[dict],
                   exclude_rules: List[dict]) -> bool:
    """Include overrides exclude. No rules = include all."""
    if resource_matches_filter(resource, include_rules):
        return True
    if resource_matches_filter(resource, exclude_rules):
        return False
    return True


# ═══════════════════════════════════════════════════════════════════
# OUTPUT HELPERS
# ═══════════════════════════════════════════════════════════════════

def write_template(template: dict, filepath: str, header_comment: str = ''):
    """Write a CFN template as YAML."""
    with open(filepath, 'w', encoding='utf-8') as f:
        if header_comment:
            for line in header_comment.strip().split('\n'):
                f.write(f"# {line}\n")
            f.write('\n')
        yaml.dump(dict(template), f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False, width=120)
    print(f"  Written: {os.path.basename(filepath)}")


def write_params_yaml(params: dict, filepath: str, comments: dict = None):
    """Write a YAML parameter file with inline comments showing source values."""
    comments = comments or {}
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Parameter file — fill in DR-region values before deploying.\n")
        f.write("# Source values shown in comments for reference.\n")
        f.write("# Fields marked IMMUTABLE cannot be changed after resource creation.\n")
        f.write("# ─────────────────────────────────────────────────────\n\n")
        for key, val in params.items():
            comment = comments.get(key, '')
            if comment:
                f.write(f"# {comment}\n")
            if val is None or val == '':
                f.write(f"{key}: ''  # REQUIRED — provide DR value\n")
            elif isinstance(val, (list, dict)):
                f.write(f"{key}:\n")
                yaml.dump(val, f, default_flow_style=False, sort_keys=False)
            else:
                f.write(f"{key}: {val}\n")
            f.write("\n")


# ═══════════════════════════════════════════════════════════════════
# IMMUTABLE PROPERTY ENFORCEMENT
#
# At template generation time, consult the CFN schema to ensure
# every create-only property is either set from inventory or
# surfaced in the parameter file with IMMUTABLE warnings.
# ═══════════════════════════════════════════════════════════════════

_schema_available = False
_cfn_client = None

try:
    from cfn_schema_cache import get_immutable_params_for_resource, get_create_only_properties
    _schema_available = True
except ImportError:
    pass


def enforce_immutables(cfn_type: str, resource_config: dict,
                       params: OrderedDict, comments: dict,
                       region: str = None):
    """Check a resource's immutable properties and add missing ones to params.

    If the CFN schema is available (cached or fetchable), this ensures every
    createOnlyProperty for this resource type is either:
      - Already present in the template with a value from inventory
      - Added to the params dict with an IMMUTABLE warning

    If schemas aren't available (no cache, no credentials), this is a no-op.
    """
    if not _schema_available:
        return

    try:
        immutable_info = get_immutable_params_for_resource(
            cfn_type, resource_config, region
        )
    except Exception:
        # Schema not available — graceful degradation
        return

    for prop_name, info in immutable_info.items():
        # Skip if value is present in inventory (will be set in template)
        if info['present_in_inventory']:
            continue

        # Skip properties we can't reasonably parameterize
        # (e.g., deeply nested structures)
        if '.' in prop_name and prop_name.count('.') > 1:
            continue

        # Add to params with IMMUTABLE warning
        safe_key = prop_name.replace('.', '_')
        if safe_key not in params:
            params[safe_key] = ''
            comments[safe_key] = (
                f"⚠ IMMUTABLE: {prop_name} — Cannot change after creation! "
                f"CFN will REPLACE the resource if this value is wrong. "
                f"Verify against source inventory before deploying."
            )


# ═══════════════════════════════════════════════════════════════════
# ASSESSMENT_ONLY — categories skipped for IaC generation
# ═══════════════════════════════════════════════════════════════════

ASSESSMENT_ONLY = {
    'EBS Snapshots', 'AMIs', 'FSx Backups', 'Protected Resources',
    'EBS Volumes', 'S3 Versioning', 'S3 Lifecycle', 'S3 Replication',
    'FSx Data Repository Associations', 'List Stacks', 'List Roles',
    'List Trails', 'List Work Groups', 'List Resolver Rules',
    'List Registries', 'List Instances', 'Describe Db Clusters',
    'Get Lifecycle Policies', 'Backup Vaults', 'Backup Plans',
    'Backup Selections',
}

# Categories that require manual action (secrets, can't export values)
MANUAL_ONLY = {'SSM Parameters', 'Secrets'}


# ═══════════════════════════════════════════════════════════════════
# TIER 00 — FOUNDATION (VPC, Subnets, Route Tables, DHCP, NAT GWs)
# ═══════════════════════════════════════════════════════════════════

def generate_foundation(inventory: dict, inc: list, exc: list) -> Tuple[dict, dict]:
    """Generate 00-foundation.yaml and its params file.

    Returns (template, params_with_comments).
    """
    resources = inventory.get('resources', {})
    vpcs = [r for r in resources.get('VPCs', []) if should_include(r, inc, exc)]
    subnets = [r for r in resources.get('Subnets', []) if should_include(r, inc, exc)]
    dhcp_opts = [r for r in resources.get('DHCP Options', []) if should_include(r, inc, exc)]
    nat_gws = [r for r in resources.get('NAT Gateways', []) if should_include(r, inc, exc)]

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Foundation — VPC, {len(subnets)} Subnets, DHCP Options, '
        f'{len(nat_gws)} NAT Gateways. Deploy FIRST.'
    )

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcCidr'] = {
        'Type': 'String',
        'Description': 'VPC CIDR block for DR region',
    }
    t['Parameters']['TargetRegion'] = {
        'Type': 'String',
        'Description': 'DR target region (e.g., us-gov-east-1)',
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # ── VPC ──
    if vpcs:
        vpc = vpcs[0]
        vc = vpc['config']
        t['Resources']['VPC'] = {
            'Type': 'AWS::EC2::VPC',
            'Properties': OrderedDict([
                ('CidrBlock', {'Ref': 'VpcCidr'}),
                ('EnableDnsSupport', True),
                ('EnableDnsHostnames', True),
                ('Tags', [
                    {'Key': 'Name', 'Value': f"DR-{vpc.get('name', 'VPC')}"},
                    {'Key': 'SourceVpcId', 'Value': vc.get('VpcId', '')},
                ]),
            ]),
        }
        t['Outputs']['VpcId'] = {
            'Value': {'Ref': 'VPC'},
            'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-VpcId'}},
        }
        t['Outputs']['VpcCidr'] = {
            'Value': {'Ref': 'VpcCidr'},
            'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-VpcCidr'}},
        }

    # ── Subnets ──
    # Sort by AZ then CIDR for predictable ordering
    subnets.sort(key=lambda s: (
        s['config'].get('AvailabilityZone', ''),
        s['config'].get('CidrBlock', '')
    ))

    for sub in subnets:
        sc = sub['config']
        label = subnet_label(sub)
        logical = safe_logical_id(label)

        # Parameter for each subnet CIDR (operator may need to adjust)
        param_name = f'{logical}Cidr'
        t['Parameters'][param_name] = {
            'Type': 'String',
            'Default': sc.get('CidrBlock', ''),
            'Description': f"CIDR for {label} (source AZ: {sc.get('AvailabilityZone', '')})",
        }

        az_suffix = sc.get('AvailabilityZone', '')[-1] if sc.get('AvailabilityZone') else 'a'
        t['Resources'][logical] = {
            'Type': 'AWS::EC2::Subnet',
            'Properties': OrderedDict([
                ('VpcId', {'Ref': 'VPC'}),
                ('CidrBlock', {'Ref': param_name}),
                ('AvailabilityZone', {'Fn::Select': [
                    0 if az_suffix == 'a' else 1,
                    {'Fn::GetAZs': {'Ref': 'AWS::Region'}}
                ]}),
                ('MapPublicIpOnLaunch', sc.get('MapPublicIpOnLaunch', False)),
                ('Tags', [
                    {'Key': 'Name', 'Value': f"DR-{label}"},
                    {'Key': 'SourceSubnetId', 'Value': sc.get('SubnetId', '')},
                    {'Key': 'SubnetPurpose', 'Value': sc.get('Tags', {}).get('aws-cdk:subnet-name', '')},
                ]),
            ]),
        }
        t['Outputs'][f'{logical}Id'] = {
            'Value': {'Ref': logical},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    # ── DHCP Options ──
    for dhcp in dhcp_opts:
        dc = dhcp['config']
        dhcp_id = dc.get('DhcpOptionsId', 'unknown')
        logical = safe_logical_id(dhcp_id)

        props = OrderedDict()
        # Extract DHCP configuration values
        for key in ['domain-name', 'domain-name-servers', 'ntp-servers',
                    'netbios-name-servers', 'netbios-node-type']:
            val = dc.get(key)
            if val:
                cfn_key = key.replace('-', ' ').title().replace(' ', '')
                if key == 'domain-name':
                    cfn_key = 'DomainName'
                elif key == 'domain-name-servers':
                    cfn_key = 'DomainNameServers'
                elif key == 'ntp-servers':
                    cfn_key = 'NtpServers'
                elif key == 'netbios-name-servers':
                    cfn_key = 'NetbiosNameServers'
                elif key == 'netbios-node-type':
                    cfn_key = 'NetbiosNodeType'
                props[cfn_key] = val

        props['Tags'] = [
            {'Key': 'Name', 'Value': f'DR-DHCP-{dhcp_id}'},
            {'Key': 'WARNING', 'Value': 'DNS server IPs must point to DR DCs after they boot'},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::EC2::DHCPOptions',
            'Properties': props,
        }
        t['Resources'][f'{logical}Assoc'] = {
            'Type': 'AWS::EC2::VPCDHCPOptionsAssociation',
            'Properties': {
                'VpcId': {'Ref': 'VPC'},
                'DhcpOptionsId': {'Ref': logical},
            },
        }

    # ── NAT Gateways (need EIPs) ──
    for idx, nat in enumerate(nat_gws, 1):
        nc = nat['config']
        logical = f'NatGW{idx}'
        eip_logical = f'NatEIP{idx}'
        source_subnet = nc.get('SubnetId', '')

        # Find the matching subnet logical ID
        subnet_ref = {'Ref': 'VPC'}  # fallback
        for sub in subnets:
            if sub['config'].get('SubnetId') == source_subnet:
                subnet_ref = {'Ref': safe_logical_id(subnet_label(sub))}
                break

        t['Resources'][eip_logical] = {
            'Type': 'AWS::EC2::EIP',
            'Properties': {
                'Domain': 'vpc',
                'Tags': [{'Key': 'Name', 'Value': f'DR-NAT-EIP-{idx}'}],
            },
        }
        t['Resources'][logical] = {
            'Type': 'AWS::EC2::NatGateway',
            'Properties': OrderedDict([
                ('AllocationId', {'Fn::GetAtt': [eip_logical, 'AllocationId']}),
                ('SubnetId', subnet_ref),
                ('Tags', [
                    {'Key': 'Name', 'Value': f'DR-NatGW-{idx}'},
                    {'Key': 'SourceNatGwId', 'Value': nc.get('NatGatewayId', '')},
                    {'Key': 'SourcePublicIp', 'Value':
                        nc.get('NatGatewayAddresses', [{}])[0].get('PublicIp', '')
                        if nc.get('NatGatewayAddresses') else ''},
                ]),
            ]),
        }
        t['Outputs'][f'{logical}Id'] = {
            'Value': {'Ref': logical},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    # Build params with comments
    params = OrderedDict()
    comments = {}
    if vpcs:
        vc = vpcs[0]['config']
        params['VpcCidr'] = vc.get('CidrBlock', '')
        comments['VpcCidr'] = f"Source VPC CIDR: {vc.get('CidrBlock')} (VpcId: {vc.get('VpcId')})"
    params['TargetRegion'] = ''
    comments['TargetRegion'] = 'Target DR region (e.g., us-gov-east-1)'

    return t, params, comments


# ═══════════════════════════════════════════════════════════════════
# TIER 01 — SECURITY GROUPS
# ═══════════════════════════════════════════════════════════════════

def generate_security_groups(inventory: dict, inc: list, exc: list) -> dict:
    """Generate 01-security-groups.yaml with full cross-SG resolution."""
    all_sgs = inventory.get('resources', {}).get('Security Groups', [])
    customer_sgs = [sg for sg in all_sgs if should_include(sg, inc, exc)]
    excluded_sg_ids = {sg['config']['GroupId'] for sg in all_sgs
                       if not should_include(sg, inc, exc)}

    # Map SG ID -> logical name
    sg_id_to_logical = {}
    for sg in customer_sgs:
        sg_id = sg['config']['GroupId']
        sg_name = sg['config'].get('GroupName', sg_id)
        sg_id_to_logical[sg_id] = safe_logical_id(sg_name)

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Security Groups — {len(customer_sgs)} SGs with cross-references. '
        f'Excluded {len(excluded_sg_ids)} infrastructure SGs.'
    )

    t['Parameters'] = OrderedDict()
    t['Parameters']['FoundationStack'] = {
        'Type': 'String', 'Default': 'dr-foundation',
        'Description': 'Name of the 00-foundation stack',
    }

    t['Resources'] = OrderedDict()

    for sg in customer_sgs:
        config = sg['config']
        sg_id = config['GroupId']
        sg_name = config.get('GroupName', 'unnamed')
        logical = sg_id_to_logical[sg_id]
        description = config.get('Description', f'DR copy of {sg_name}')[:255]

        ingress_rules = []
        self_ref_rules = []

        for rule in config.get('IngressRules', []):
            ip_protocol = rule.get('IpProtocol', '-1')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')

            for ip_range in rule.get('IpRanges', []):
                entry = OrderedDict()
                entry['IpProtocol'] = str(ip_protocol)
                if from_port is not None and from_port != -1:
                    entry['FromPort'] = from_port
                if to_port is not None and to_port != -1:
                    entry['ToPort'] = to_port
                entry['CidrIp'] = ip_range.get('CidrIp', '')
                if ip_range.get('Description'):
                    entry['Description'] = ip_range['Description']
                ingress_rules.append(entry)

            for sg_pair in rule.get('UserIdGroupPairs', []):
                ref_sg_id = sg_pair.get('GroupId', '')
                entry = OrderedDict()
                entry['IpProtocol'] = str(ip_protocol)
                if from_port is not None and from_port != -1:
                    entry['FromPort'] = from_port
                if to_port is not None and to_port != -1:
                    entry['ToPort'] = to_port

                if ref_sg_id == sg_id:
                    entry['SourceSecurityGroupId'] = {'Ref': logical}
                    if sg_pair.get('Description'):
                        entry['Description'] = sg_pair['Description']
                    self_ref_rules.append(entry)
                elif ref_sg_id in sg_id_to_logical:
                    entry['SourceSecurityGroupId'] = {'Ref': sg_id_to_logical[ref_sg_id]}
                    if sg_pair.get('Description'):
                        entry['Description'] = sg_pair['Description']
                    ingress_rules.append(entry)
                elif ref_sg_id not in excluded_sg_ids:
                    print(f"    WARNING: {sg_name} references unknown SG {ref_sg_id}")

        sg_resource = OrderedDict()
        sg_resource['Type'] = 'AWS::EC2::SecurityGroup'
        sg_resource['Properties'] = OrderedDict([
            ('GroupDescription', description),
            ('GroupName', f'{sg_name}-DR'),
            ('VpcId', {'Fn::ImportValue': {'Fn::Sub': '${FoundationStack}-VpcId'}}),
        ])
        if ingress_rules:
            sg_resource['Properties']['SecurityGroupIngress'] = ingress_rules
        sg_resource['Properties']['Tags'] = [
            {'Key': 'Name', 'Value': f'{sg_name}-DR'},
            {'Key': 'SourceSG', 'Value': sg_id},
        ]
        t['Resources'][logical] = sg_resource

        # Self-referencing rules as separate resources
        for idx, sr in enumerate(self_ref_rules):
            sr_resource = OrderedDict()
            sr_resource['Type'] = 'AWS::EC2::SecurityGroupIngress'
            props = OrderedDict([
                ('GroupId', {'Ref': logical}),
                ('IpProtocol', sr['IpProtocol']),
            ])
            if 'FromPort' in sr:
                props['FromPort'] = sr['FromPort']
            if 'ToPort' in sr:
                props['ToPort'] = sr['ToPort']
            props['SourceSecurityGroupId'] = {'Ref': logical}
            if 'Description' in sr:
                props['Description'] = sr['Description']
            sr_resource['Properties'] = props
            t['Resources'][f'{logical}Self{idx}'] = sr_resource

    # Outputs — export every SG for use by other tiers
    t['Outputs'] = OrderedDict()
    for sg in customer_sgs:
        sg_id = sg['config']['GroupId']
        logical = sg_id_to_logical[sg_id]
        sg_name = sg['config'].get('GroupName', 'unnamed')
        t['Outputs'][f'{logical}Id'] = {
            'Value': {'Fn::GetAtt': [logical, 'GroupId']},
            'Description': f'{sg_name} (source: {sg_id})',
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    return t, sg_id_to_logical


# ═══════════════════════════════════════════════════════════════════
# TIER 02 — DATA TIER (RDS, Aurora, FSx)
# ═══════════════════════════════════════════════════════════════════

def generate_data_tier(inventory: dict, inc: list, exc: list,
                       sg_id_to_logical: dict) -> Tuple[dict, dict, dict]:
    """Generate 02-data-tier.yaml with full RDS and FSx config."""
    resources = inventory.get('resources', {})
    rds_clusters = [r for r in resources.get('RDS DB Clusters', []) if should_include(r, inc, exc)]
    rds_instances = [r for r in resources.get('RDS Instances', []) if should_include(r, inc, exc)]
    rds_subnet_groups = resources.get('RDS DB Subnet Groups', [])
    rds_param_groups = resources.get('RDS Parameter Groups', [])
    rds_cluster_param_groups = resources.get('RDS Cluster Parameter Groups', [])
    rds_option_groups = resources.get('RDS Option Groups', [])
    fsx_systems = [r for r in resources.get('FSx File Systems', []) if should_include(r, inc, exc)]

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Data Tier — {len(rds_clusters)} Aurora clusters, '
        f'{len(rds_instances)} RDS instances, {len(fsx_systems)} FSx file systems. '
        f'Restore from cross-region snapshot/backup copies.'
    )

    t['Parameters'] = OrderedDict()
    t['Parameters']['FoundationStack'] = {
        'Type': 'String', 'Default': 'dr-foundation',
    }
    t['Parameters']['SGStack'] = {
        'Type': 'String', 'Default': 'dr-security-groups',
    }
    t['Parameters']['DataSubnet1'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Data/Production subnet AZ1',
    }
    t['Parameters']['DataSubnet2'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Data/Production subnet AZ2',
    }
    t['Parameters']['KmsKeyArn'] = {
        'Type': 'String',
        'Description': 'KMS key ARN for encryption in DR region',
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # ── DB Subnet Group ──
    if rds_subnet_groups:
        sg_config = rds_subnet_groups[0]['config']
        t['Resources']['DBSubnetGroup'] = {
            'Type': 'AWS::RDS::DBSubnetGroup',
            'Properties': OrderedDict([
                ('DBSubnetGroupName', sg_config.get('DBSubnetGroupName', 'dr-db-subnet-group')),
                ('DBSubnetGroupDescription',
                    sg_config.get('DBSubnetGroupDescription', 'DR Database subnets')),
                ('SubnetIds', [{'Ref': 'DataSubnet1'}, {'Ref': 'DataSubnet2'}]),
            ]),
        }

    # ── RDS Parameter Groups (custom ones only) ──
    for pg in rds_param_groups:
        pc = pg['config']
        pg_name = pc.get('DBParameterGroupName', '')
        if pg_name.startswith('default.'):
            continue  # Skip AWS defaults
        logical = safe_logical_id(pg_name)
        t['Resources'][logical] = {
            'Type': 'AWS::RDS::DBParameterGroup',
            'Properties': OrderedDict([
                ('Family', pc.get('DBParameterGroupFamily', '')),
                ('Description', pc.get('Description', f'DR copy of {pg_name}')),
                ('Tags', [{'Key': 'Name', 'Value': pg_name}]),
            ]),
        }

    # ── RDS Cluster Parameter Groups (custom ones only) ──
    for cpg in rds_cluster_param_groups:
        pc = cpg['config']
        cpg_name = pc.get('DBClusterParameterGroupName', '')
        if cpg_name.startswith('default.'):
            continue
        logical = safe_logical_id(cpg_name)
        t['Resources'][logical] = {
            'Type': 'AWS::RDS::DBClusterParameterGroup',
            'Properties': OrderedDict([
                ('Family', pc.get('DBParameterGroupFamily', '')),
                ('Description', pc.get('Description', f'DR copy of {cpg_name}')),
                ('Tags', [{'Key': 'Name', 'Value': cpg_name}]),
            ]),
        }

    # ── RDS Option Groups (custom ones only) ──
    for og in rds_option_groups:
        oc = og['config']
        og_name = oc.get('OptionGroupName', '')
        if og_name.startswith('default:'):
            continue
        logical = safe_logical_id(og_name)
        t['Resources'][logical] = {
            'Type': 'AWS::RDS::OptionGroup',
            'Properties': OrderedDict([
                ('OptionGroupName', og_name),
                ('EngineName', oc.get('EngineName', '')),
                ('MajorEngineVersion', oc.get('MajorEngineVersion', '')),
                ('OptionGroupDescription',
                    oc.get('OptionGroupDescription', f'DR copy of {og_name}')),
                ('Tags', [{'Key': 'Name', 'Value': og_name}]),
            ]),
        }

    # ── Aurora Clusters ──
    for cluster in rds_clusters:
        cc = cluster['config']
        cid = cc.get('DBClusterIdentifier', 'unnamed')
        logical = safe_logical_id(cid)

        # Snapshot parameter
        snap_param = f'{logical}SnapshotArn'
        t['Parameters'][snap_param] = {
            'Type': 'String',
            'Description': f'Cluster snapshot ARN for {cid} in DR region',
        }

        # Map SGs
        sg_refs = []
        for sg_id in cc.get('VpcSecurityGroupId', []):
            if sg_id in sg_id_to_logical:
                sg_refs.append({'Fn::ImportValue': {'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}})

        cluster_props = OrderedDict([
            ('DBClusterIdentifier', cid),
            ('Engine', cc.get('Engine', '')),
            ('EngineVersion', cc.get('EngineVersion', '')),
            ('EngineMode', cc.get('EngineMode', 'provisioned')),
            ('Port', cc.get('Port', 5432)),
            ('DatabaseName', cc.get('DatabaseName', '')),
            ('MasterUsername', cc.get('MasterUsername', '')),
            ('SnapshotIdentifier', {'Ref': snap_param}),
            ('DBSubnetGroupName', {'Ref': 'DBSubnetGroup'} if rds_subnet_groups else cc.get('DBSubnetGroup', '')),
            ('VpcSecurityGroupIds', sg_refs if sg_refs else cc.get('VpcSecurityGroupId', [])),
            ('BackupRetentionPeriod', cc.get('BackupRetentionPeriod', 7)),
            ('PreferredBackupWindow', cc.get('PreferredBackupWindow', '')),
            ('PreferredMaintenanceWindow', cc.get('PreferredMaintenanceWindow', '')),
            ('StorageEncrypted', cc.get('StorageEncrypted', True)),
            ('KmsKeyId', {'Ref': 'KmsKeyArn'}),
            ('DeletionProtection', cc.get('DeletionProtection', True)),
            ('CopyTagsToSnapshot', cc.get('CopyTagsToSnapshot', True)),
        ])
        if cc.get('EnabledCloudwatchLogsExports'):
            cluster_props['EnableCloudwatchLogsExports'] = cc['EnabledCloudwatchLogsExports']

        # Custom cluster param group reference
        cpg_name = cc.get('DBClusterParameterGroup', '')
        if cpg_name and not cpg_name.startswith('default.'):
            cluster_props['DBClusterParameterGroupName'] = {'Ref': safe_logical_id(cpg_name)}

        cluster_props['Tags'] = [
            {'Key': 'Name', 'Value': cid},
            {'Key': 'SourceClusterArn', 'Value': cc.get('DBClusterArn', '')},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::RDS::DBCluster',
            'Properties': cluster_props,
        }
        t['Outputs'][f'{logical}Endpoint'] = {
            'Value': {'Fn::GetAtt': [logical, 'Endpoint.Address']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}Endpoint'}},
        }

    # ── RDS Instances (standalone + cluster members) ──
    for rds in rds_instances:
        rc = rds['config']
        db_id = rc.get('DBInstanceIdentifier', 'unnamed')
        logical = safe_logical_id(db_id)
        cluster_id = rc.get('DBClusterIdentifier', '')

        instance_props = OrderedDict([
            ('DBInstanceIdentifier', db_id),
            ('DBInstanceClass', rc.get('DBInstanceClass', 'db.t3.medium')),
            ('Engine', rc.get('Engine', '')),
            ('EngineVersion', rc.get('EngineVersion', '')),
        ])

        if cluster_id:
            # Aurora cluster member — references the cluster
            cluster_logical = safe_logical_id(cluster_id)
            instance_props['DBClusterIdentifier'] = {'Ref': cluster_logical}
        else:
            # Standalone instance — restore from snapshot
            snap_param = f'{logical}SnapshotId'
            t['Parameters'][snap_param] = {
                'Type': 'String',
                'Description': f'Snapshot ID for {db_id} in DR region',
            }
            instance_props['DBSnapshotIdentifier'] = {'Ref': snap_param}
            instance_props['AllocatedStorage'] = rc.get('AllocatedStorage', 20)
            instance_props['StorageType'] = rc.get('StorageType', 'gp3')
            instance_props['StorageEncrypted'] = rc.get('StorageEncrypted', True)
            instance_props['KmsKeyId'] = {'Ref': 'KmsKeyArn'}
            instance_props['DBSubnetGroupName'] = (
                {'Ref': 'DBSubnetGroup'} if rds_subnet_groups else ''
            )

            # SGs for standalone
            sg_refs = []
            for sg_id in rc.get('VpcSecurityGroupId', []):
                if sg_id in sg_id_to_logical:
                    sg_refs.append({'Fn::ImportValue': {'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}})
            if sg_refs:
                instance_props['VPCSecurityGroups'] = sg_refs

        instance_props['MultiAZ'] = rc.get('MultiAZ', False)
        instance_props['PubliclyAccessible'] = rc.get('PubliclyAccessible', False)
        instance_props['AutoMinorVersionUpgrade'] = rc.get('AutoMinorVersionUpgrade', True)
        instance_props['BackupRetentionPeriod'] = rc.get('BackupRetentionPeriod', 7)
        instance_props['PreferredBackupWindow'] = rc.get('PreferredBackupWindow', '')
        instance_props['PreferredMaintenanceWindow'] = rc.get('PreferredMaintenanceWindow', '')
        instance_props['CopyTagsToSnapshot'] = rc.get('CopyTagsToSnapshot', True)
        instance_props['DeletionProtection'] = rc.get('DeletionProtection', True)

        if rc.get('MonitoringInterval') and rc.get('MonitoringInterval') > 0:
            instance_props['MonitoringInterval'] = rc['MonitoringInterval']
            instance_props['MonitoringRoleArn'] = rc.get('MonitoringRoleArn', '')

        if rc.get('PerformanceInsightsEnabled'):
            instance_props['EnablePerformanceInsights'] = True

        # Parameter/Option group refs
        for pg_name in rc.get('DBParameterGroupName', []):
            if not pg_name.startswith('default.'):
                instance_props['DBParameterGroupName'] = {'Ref': safe_logical_id(pg_name)}
                break
        for og_name in rc.get('OptionGroupName', []):
            if not og_name.startswith('default:'):
                instance_props['OptionGroupName'] = {'Ref': safe_logical_id(og_name)}
                break

        instance_props['Tags'] = [
            {'Key': 'Name', 'Value': db_id},
            {'Key': 'SourceDBId', 'Value': db_id},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::RDS::DBInstance',
            'Properties': instance_props,
        }
        if not cluster_id:
            t['Outputs'][f'{logical}Endpoint'] = {
                'Value': {'Fn::GetAtt': [logical, 'Endpoint.Address']},
                'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}Endpoint'}},
            }

    # ── FSx File Systems ──
    for fsx in fsx_systems:
        fc = fsx['config']
        fs_id = fc.get('FileSystemId', 'unnamed')
        logical = safe_logical_id(fsx.get('name', fs_id))

        backup_param = f'{logical}BackupId'
        t['Parameters'][backup_param] = {
            'Type': 'String',
            'Description': f'FSx backup ID to restore from (cross-region copy of {fs_id})',
        }

        fsx_props = OrderedDict([
            ('FileSystemType', fc.get('FileSystemType', 'WINDOWS')),
            ('StorageCapacity', fc.get('StorageCapacity', 0)),
            ('StorageType', fc.get('StorageType', 'SSD')),
            ('SubnetIds', [{'Ref': 'DataSubnet1'}, {'Ref': 'DataSubnet2'}]),
            ('KmsKeyId', {'Ref': 'KmsKeyArn'}),
            ('BackupId', {'Ref': backup_param}),
        ])

        # Windows-specific configuration
        if fc.get('FileSystemType') == 'WINDOWS':
            win_config = OrderedDict()
            win_config['DeploymentType'] = fc.get('WindowsConfiguration_DeploymentType', 'MULTI_AZ_1')
            win_config['ThroughputCapacity'] = fc.get('WindowsConfiguration_ThroughputCapacity', 32)
            win_config['PreferredSubnetId'] = {'Ref': 'DataSubnet1'}
            win_config['AutomaticBackupRetentionDays'] = fc.get('AutomaticBackupRetentionDays', 30)
            win_config['DailyAutomaticBackupStartTime'] = fc.get('DailyAutomaticBackupStartTime', '04:00')
            win_config['WeeklyMaintenanceStartTime'] = fc.get('WindowsConfiguration_WeeklyMaintenanceStartTime', '')
            win_config['CopyTagsToBackups'] = fc.get('CopyTagsToBackups', False)

            # AD join config — DCs must be running first
            if fc.get('DomainName'):
                ad_config = OrderedDict()
                ad_config['DomainName'] = fc['DomainName']
                ad_config['UserName'] = fc.get('UserName', '')
                # DnsIps will be the DR DC IPs — parameterize
                dns_param = f'{logical}DnsIps'
                t['Parameters'][dns_param] = {
                    'Type': 'CommaDelimitedList',
                    'Description': (
                        f"DNS IPs for AD domain {fc['DomainName']} in DR "
                        f"(source: {fc.get('DnsIps', [])})"
                    ),
                }
                ad_config['DnsIps'] = {'Ref': dns_param}
                win_config['SelfManagedActiveDirectoryConfiguration'] = ad_config

            if fc.get('AuditLogConfiguration'):
                audit = fc['AuditLogConfiguration']
                win_config['AuditLogConfiguration'] = {
                    'FileAccessAuditLogLevel': audit.get('FileAccessAuditLogLevel', 'DISABLED'),
                    'FileShareAccessAuditLogLevel': audit.get('FileShareAccessAuditLogLevel', 'DISABLED'),
                }

            fsx_props['WindowsConfiguration'] = win_config

        # SG refs
        sg_refs = []
        # FSx may not have direct SG in config — check VpcId relationships
        fsx_props['SecurityGroupIds'] = sg_refs or [
            {'Fn::ImportValue': {'Fn::Sub': '${SGStack}-' + list(sg_id_to_logical.values())[0]}}
        ] if sg_id_to_logical else []

        fsx_props['Tags'] = [
            {'Key': 'Name', 'Value': fsx.get('name', fs_id)},
            {'Key': 'SourceFileSystemId', 'Value': fs_id},
            {'Key': 'WARNING', 'Value': 'DCs must be healthy before this resource can be created (AD join)'},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::FSx::FileSystem',
            'Properties': fsx_props,
        }
        t['Outputs'][f'{logical}DnsName'] = {
            'Value': {'Fn::GetAtt': [logical, 'DNSName']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}DnsName'}},
        }

    # Build params
    params = OrderedDict()
    comments = {}
    params['FoundationStack'] = 'dr-foundation'
    params['SGStack'] = 'dr-security-groups'
    params['DataSubnet1'] = ''
    comments['DataSubnet1'] = 'Production/Data subnet AZ1 from foundation stack'
    params['DataSubnet2'] = ''
    comments['DataSubnet2'] = 'Production/Data subnet AZ2 from foundation stack'
    params['KmsKeyArn'] = ''
    comments['KmsKeyArn'] = 'KMS key ARN in DR region for encryption'

    for p_name, p_config in t.get('Parameters', {}).items():
        if p_name not in params:
            params[p_name] = ''
            comments[p_name] = p_config.get('Description', '')

    return t, params, comments


# ═══════════════════════════════════════════════════════════════════
# TIER 03/03a — COMPUTE (EC2 instances, split DCs out)
# ═══════════════════════════════════════════════════════════════════

def is_domain_controller(instance: dict) -> bool:
    """Detect if an instance is a Domain Controller."""
    tags = instance.get('config', {}).get('Tags', {})
    name = instance.get('name', '').lower()
    return (tags.get('Role', '').upper() == 'DC' or
            'dc1' in name or 'dc2' in name or
            '/DC' in instance.get('name', ''))


def generate_compute_template(instances: list, sg_id_to_logical: dict,
                              subnets: list, is_dc: bool = False) -> Tuple[dict, dict, dict]:
    """Generate a compute tier template (03 or 03a)."""
    tier_name = 'DC Compute (Boot First)' if is_dc else 'Compute Tier'

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = f'DR {tier_name} — {len(instances)} instances.'

    t['Parameters'] = OrderedDict()
    t['Parameters']['FoundationStack'] = {
        'Type': 'String', 'Default': 'dr-foundation',
    }
    t['Parameters']['SGStack'] = {
        'Type': 'String', 'Default': 'dr-security-groups',
    }

    # Build subnet map: source subnet ID -> param name
    subnet_ids_used = set()
    for inst in instances:
        sid = inst['config'].get('SubnetId', '')
        if sid:
            subnet_ids_used.add(sid)

    # Map source subnet IDs to their labels from inventory
    subnet_id_to_label = {}
    for sub in subnets:
        sid = sub['config'].get('SubnetId', '')
        subnet_id_to_label[sid] = subnet_label(sub)

    subnet_param_map = {}
    for idx, sid in enumerate(sorted(subnet_ids_used), 1):
        label = subnet_id_to_label.get(sid, f'Subnet{idx}')
        param_name = f'Subnet{safe_logical_id(label)}'
        t['Parameters'][param_name] = {
            'Type': 'AWS::EC2::Subnet::Id',
            'Description': f'DR subnet for {label} (source: {sid})',
        }
        subnet_param_map[sid] = param_name

    # Per-instance AMI parameters
    for inst in instances:
        name = short_name(inst.get('name', 'unnamed'))
        logical = safe_logical_id(name)
        ami = inst['config'].get('ImageId', '')
        t['Parameters'][f'{logical}AmiId'] = {
            'Type': 'AWS::EC2::Image::Id',
            'Description': f'AMI for {name} (source: {ami})',
        }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # Shared IAM role for SSM access
    t['Resources']['EC2SSMRole'] = {
        'Type': 'AWS::IAM::Role',
        'Properties': OrderedDict([
            ('RoleName', {'Fn::Sub': f'${{AWS::StackName}}-ssm-role'}),
            ('AssumeRolePolicyDocument', {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'ec2.amazonaws.com'},
                    'Action': 'sts:AssumeRole',
                }],
            }),
            ('ManagedPolicyArns', [
                {'Fn::Sub': 'arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore'},
            ]),
        ]),
    }

    for inst in instances:
        config = inst['config']
        name = short_name(inst.get('name', 'unnamed'))
        logical = safe_logical_id(name)
        instance_type = config.get('InstanceType', 't3.medium')
        subnet_id = config.get('SubnetId', '')
        tags = config.get('Tags', {})

        # Instance profile
        profile_logical = f'{logical}Profile'
        t['Resources'][profile_logical] = {
            'Type': 'AWS::IAM::InstanceProfile',
            'Properties': {
                'Roles': [{'Ref': 'EC2SSMRole'}],
            },
        }

        # Map SGs to imports
        sg_refs = []
        for sg_id in config.get('GroupId', []):
            if sg_id in sg_id_to_logical:
                sg_refs.append({
                    'Fn::ImportValue': {'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}
                })

        # Build instance
        props = OrderedDict()
        props['InstanceType'] = instance_type
        props['ImageId'] = {'Ref': f'{logical}AmiId'}
        props['IamInstanceProfile'] = {'Ref': profile_logical}

        if config.get('KeyName'):
            props['KeyName'] = config['KeyName']

        if subnet_id in subnet_param_map:
            props['SubnetId'] = {'Ref': subnet_param_map[subnet_id]}

        if sg_refs:
            props['SecurityGroupIds'] = sg_refs

        # Preserve all meaningful tags
        cfn_tags = [
            {'Key': 'Name', 'Value': inst.get('name', name)},
            {'Key': 'SourceInstance', 'Value': config.get('InstanceId', '')},
        ]
        for key in sorted(tags.keys()):
            if key in ('Name', 'aws:cloudformation:stack-name',
                       'aws:cloudformation:stack-id',
                       'aws:cloudformation:logical-id'):
                continue
            cfn_tags.append({'Key': key, 'Value': str(tags[key])})
        props['Tags'] = cfn_tags

        t['Resources'][logical] = {
            'Type': 'AWS::EC2::Instance',
            'DependsOn': profile_logical,
            'Properties': props,
        }

        t['Outputs'][f'{logical}Id'] = {
            'Value': {'Ref': logical},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }
        t['Outputs'][f'{logical}PrivateIp'] = {
            'Value': {'Fn::GetAtt': [logical, 'PrivateIp']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}Ip'}},
        }

    # Build params
    params = OrderedDict()
    comments = {}
    params['FoundationStack'] = 'dr-foundation'
    params['SGStack'] = 'dr-security-groups'
    for p_name, p_config in t.get('Parameters', {}).items():
        if p_name not in params:
            params[p_name] = ''
            comments[p_name] = p_config.get('Description', '')

    return t, params, comments


# ═══════════════════════════════════════════════════════════════════
# TIER 04 — NETWORK (Load Balancers, Target Groups, Listeners)
# ═══════════════════════════════════════════════════════════════════

def generate_network_tier(inventory: dict, inc: list, exc: list,
                          sg_id_to_logical: dict) -> Tuple[dict, dict, dict]:
    """Generate 04-network-tier.yaml with full LB/TG/Listener wiring."""
    resources = inventory.get('resources', {})
    all_lbs = [r for r in resources.get('Load Balancers', []) if should_include(r, inc, exc)]
    all_tgs = resources.get('Target Groups', [])
    all_listeners = resources.get('Listeners', [])
    all_rules = resources.get('Listener Rules', [])
    registered_targets = resources.get('Registered Targets', [])

    # Skip gateway LBs (infrastructure-managed)
    customer_lbs = [lb for lb in all_lbs if lb['config'].get('Type', '') != 'gateway']

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Network Tier — {len(customer_lbs)} load balancers with listeners and target groups.'
    )

    t['Parameters'] = OrderedDict()
    t['Parameters']['FoundationStack'] = {'Type': 'String', 'Default': 'dr-foundation'}
    t['Parameters']['SGStack'] = {'Type': 'String', 'Default': 'dr-security-groups'}
    t['Parameters']['ComputeStack'] = {'Type': 'String', 'Default': 'dr-compute-tier'}
    t['Parameters']['LBSubnet1'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Subnet AZ1 for load balancers (DMZ for internet-facing)',
    }
    t['Parameters']['LBSubnet2'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Subnet AZ2 for load balancers',
    }
    t['Parameters']['CertificateArn'] = {
        'Type': 'String', 'Default': '',
        'Description': 'ACM certificate ARN in DR region (for TLS listeners)',
    }

    t['Conditions'] = OrderedDict()
    t['Conditions']['HasCert'] = {
        'Fn::Not': [{'Fn::Equals': [{'Ref': 'CertificateArn'}, '']}]
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # Build TG ARN -> TG name map for listener wiring
    tg_arn_to_name = {}
    for tg in all_tgs:
        arn = tg['config'].get('TargetGroupArn', '')
        name = tg['config'].get('TargetGroupName', '')
        tg_arn_to_name[arn] = name

    # Build LB ARN -> LB name map
    lb_arn_to_name = {}
    for lb in customer_lbs:
        arn = lb['config'].get('LoadBalancerArn', '')
        lb_arn_to_name[arn] = lb['config'].get('LoadBalancerName', '')

    # ── Load Balancers ──
    for lb in customer_lbs:
        lc = lb['config']
        lb_name = lc.get('LoadBalancerName', 'unnamed')
        lb_logical = safe_logical_id(lb_name)
        lb_type = lc.get('Type', 'network')
        lb_scheme = lc.get('Scheme', 'internet-facing')

        lb_props = OrderedDict()
        lb_props['Name'] = lb_name
        lb_props['Type'] = lb_type
        lb_props['Scheme'] = lb_scheme
        lb_props['Subnets'] = [{'Ref': 'LBSubnet1'}, {'Ref': 'LBSubnet2'}]
        lb_props['IpAddressType'] = lc.get('IpAddressType', 'ipv4')

        # SG references
        sg_refs = []
        for sg_id in (lc.get('SecurityGroups') or []):
            if isinstance(sg_id, str) and sg_id in sg_id_to_logical:
                sg_refs.append({
                    'Fn::ImportValue': {'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}
                })
        if sg_refs:
            lb_props['SecurityGroups'] = sg_refs

        lb_props['Tags'] = [
            {'Key': 'Name', 'Value': lb_name},
            {'Key': 'SourceLBArn', 'Value': lc.get('LoadBalancerArn', '')},
        ]

        t['Resources'][lb_logical] = {
            'Type': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
            'Properties': lb_props,
        }
        t['Outputs'][f'{lb_logical}DnsName'] = {
            'Value': {'Fn::GetAtt': [lb_logical, 'DNSName']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{lb_logical}DnsName'}},
        }

    # ── Target Groups ──
    for tg in all_tgs:
        tc = tg['config']
        tg_name = tc.get('TargetGroupName', 'unnamed')
        tg_logical = safe_logical_id(tg_name)

        # Only include TGs attached to our customer LBs
        tg_lb_arns = tc.get('LoadBalancerArns', [])
        if not any(arn in lb_arn_to_name for arn in tg_lb_arns):
            continue

        tg_props = OrderedDict()
        tg_props['Name'] = tg_name
        tg_props['Protocol'] = tc.get('Protocol', 'TCP')
        tg_props['Port'] = tc.get('Port', 443)
        tg_props['VpcId'] = {'Fn::ImportValue': {'Fn::Sub': '${FoundationStack}-VpcId'}}
        tg_props['TargetType'] = tc.get('TargetType', 'instance')

        # Health check
        tg_props['HealthCheckEnabled'] = tc.get('HealthCheckEnabled', True)
        tg_props['HealthCheckProtocol'] = tc.get('HealthCheckProtocol', 'TCP')
        if tc.get('HealthCheckPort') and tc['HealthCheckPort'] != 'traffic-port':
            tg_props['HealthCheckPort'] = str(tc['HealthCheckPort'])
        if tc.get('HealthCheckPath'):
            tg_props['HealthCheckPath'] = tc['HealthCheckPath']
        tg_props['HealthCheckIntervalSeconds'] = tc.get('HealthCheckIntervalSeconds', 30)
        tg_props['HealthyThresholdCount'] = tc.get('HealthyThresholdCount', 5)
        tg_props['UnhealthyThresholdCount'] = tc.get('UnhealthyThresholdCount', 2)

        tg_props['Tags'] = [
            {'Key': 'Name', 'Value': tg_name},
            {'Key': 'SourceTGArn', 'Value': tc.get('TargetGroupArn', '')},
            {'Key': 'NOTE', 'Value': 'Targets must be registered post-deploy with DR instance IDs/IPs'},
        ]

        t['Resources'][tg_logical] = {
            'Type': 'AWS::ElasticLoadBalancingV2::TargetGroup',
            'Properties': tg_props,
        }

    # ── Listeners ──
    for listener in all_listeners:
        lc = listener['config']
        lb_arn = lc.get('LoadBalancerArn', '')
        lb_name = lb_arn_to_name.get(lb_arn, '')
        if not lb_name:
            continue  # Skip listeners for non-customer LBs

        port = lc.get('Port', 443)
        protocol = lc.get('Protocol', 'TCP')
        lb_logical = safe_logical_id(lb_name)
        ln_logical = f'{lb_logical}Listener{port}{protocol}'

        ln_props = OrderedDict()
        ln_props['LoadBalancerArn'] = {'Ref': lb_logical}
        ln_props['Port'] = port
        ln_props['Protocol'] = protocol

        # TLS/HTTPS cert
        needs_cert = protocol in ('TLS', 'HTTPS')
        if needs_cert and lc.get('Certificates'):
            ln_props['Certificates'] = [{'CertificateArn': {'Ref': 'CertificateArn'}}]
        if lc.get('SslPolicy'):
            ln_props['SslPolicy'] = lc['SslPolicy']

        # Default action — find the target group
        default_actions = lc.get('DefaultActions', [])
        for action in default_actions:
            action_type = action.get('Type', 'forward')
            tg_arn = action.get('TargetGroupArn', '')
            tg_name = tg_arn_to_name.get(tg_arn, '')

            if action_type == 'forward' and tg_name:
                ln_props['DefaultActions'] = [{
                    'Type': 'forward',
                    'TargetGroupArn': {'Ref': safe_logical_id(tg_name)},
                }]
                break
            elif action_type == 'redirect':
                ln_props['DefaultActions'] = [action]
                break

        if 'DefaultActions' not in ln_props:
            # Fallback — forward to first TG found in the action
            if default_actions:
                fc = default_actions[0].get('ForwardConfig', {})
                tg_list = fc.get('TargetGroups', [])
                if tg_list:
                    tg_arn = tg_list[0].get('TargetGroupArn', '')
                    tg_name = tg_arn_to_name.get(tg_arn, '')
                    if tg_name:
                        ln_props['DefaultActions'] = [{
                            'Type': 'forward',
                            'TargetGroupArn': {'Ref': safe_logical_id(tg_name)},
                        }]

        if 'DefaultActions' not in ln_props:
            print(f"    WARNING: Listener {port}/{protocol} on {lb_name} has no resolvable action — skipped")
            continue

        resource_def = {
            'Type': 'AWS::ElasticLoadBalancingV2::Listener',
            'Properties': ln_props,
        }
        if needs_cert:
            resource_def['Condition'] = 'HasCert'

        t['Resources'][ln_logical] = resource_def

    # Build params
    params = OrderedDict()
    comments = {}
    for p_name, p_config in t.get('Parameters', {}).items():
        params[p_name] = p_config.get('Default', '')
        comments[p_name] = p_config.get('Description', '')

    return t, params, comments


# ═══════════════════════════════════════════════════════════════════
# TIER 05 — SERVERLESS (Lambda, EventBridge)
# ═══════════════════════════════════════════════════════════════════

def generate_serverless(inventory: dict, inc: list, exc: list) -> Tuple[dict, dict, dict]:
    """Generate 05-serverless.yaml."""
    resources = inventory.get('resources', {})
    lambdas = [r for r in resources.get('Lambda Functions', []) if should_include(r, inc, exc)]
    eb_rules = [r for r in resources.get('EventBridge Rules', []) if should_include(r, inc, exc)]

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = f'DR Serverless — {len(lambdas)} Lambda functions, {len(eb_rules)} EventBridge rules.'

    t['Parameters'] = OrderedDict()
    t['Parameters']['LambdaCodeBucket'] = {
        'Type': 'String',
        'Description': 'S3 bucket containing Lambda deployment packages in DR region',
    }
    t['Parameters']['FoundationStack'] = {'Type': 'String', 'Default': 'dr-foundation'}
    t['Parameters']['SGStack'] = {'Type': 'String', 'Default': 'dr-security-groups'}

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    for fn in lambdas:
        fc = fn['config']
        fn_name = fc.get('FunctionName', 'unnamed')
        logical = safe_logical_id(fn_name)

        # Code key parameter
        code_param = f'{logical}CodeKey'
        t['Parameters'][code_param] = {
            'Type': 'String',
            'Description': f'S3 key for {fn_name} (CodeSize: {fc.get("CodeSize", 0)} bytes)',
        }

        fn_props = OrderedDict()
        fn_props['FunctionName'] = fn_name
        fn_props['Runtime'] = fc.get('Runtime', 'python3.12')
        fn_props['Handler'] = fc.get('Handler', 'index.handler')
        fn_props['Role'] = fc.get('Role', '')
        fn_props['MemorySize'] = fc.get('MemorySize', 128)
        fn_props['Timeout'] = fc.get('Timeout', 30)
        fn_props['Architectures'] = fc.get('Architectures', ['x86_64'])
        fn_props['Code'] = {
            'S3Bucket': {'Ref': 'LambdaCodeBucket'},
            'S3Key': {'Ref': code_param},
        }

        # VPC config
        subnet_ids = fc.get('SubnetIds', '') or ''
        sg_ids = fc.get('SecurityGroupIds', '') or ''
        if subnet_ids and subnet_ids != '':
            fn_props['VpcConfig'] = {
                'SubnetIds': subnet_ids if isinstance(subnet_ids, list) else [],
                'SecurityGroupIds': sg_ids if isinstance(sg_ids, list) else [],
            }

        fn_props['Tags'] = [
            {'Key': 'Name', 'Value': fn_name},
            {'Key': 'SourceArn', 'Value': fc.get('FunctionArn', '')},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::Lambda::Function',
            'Properties': fn_props,
        }
        t['Outputs'][f'{logical}Arn'] = {
            'Value': {'Fn::GetAtt': [logical, 'Arn']},
        }

    # EventBridge Rules
    for rule in eb_rules:
        rc = rule['config']
        rule_name = rc.get('Name', 'unnamed')
        logical = safe_logical_id(rule_name)

        rule_props = OrderedDict()
        rule_props['Name'] = rule_name
        rule_props['State'] = rc.get('State', 'ENABLED')
        if rc.get('ScheduleExpression'):
            rule_props['ScheduleExpression'] = rc['ScheduleExpression']
        if rc.get('EventPattern'):
            rule_props['EventPattern'] = rc['EventPattern']
        if rc.get('Description'):
            rule_props['Description'] = rc['Description']

        rule_props['Tags'] = [{'Key': 'SourceRule', 'Value': rule_name}]

        t['Resources'][logical] = {
            'Type': 'AWS::Events::Rule',
            'Properties': rule_props,
        }

    params = OrderedDict()
    comments = {}
    for p_name, p_config in t.get('Parameters', {}).items():
        params[p_name] = p_config.get('Default', '')
        comments[p_name] = p_config.get('Description', '')

    return t, params, comments


# ═══════════════════════════════════════════════════════════════════
# TIER 06 — SUPPORTING (VPC Endpoints, KMS, ACM, SNS, TGW, VPN, CW)
# ═══════════════════════════════════════════════════════════════════

def generate_supporting(inventory: dict, inc: list, exc: list,
                        sg_id_to_logical: dict) -> Tuple[dict, dict, dict]:
    """Generate 06-supporting.yaml."""
    resources = inventory.get('resources', {})
    vpc_endpoints = [r for r in resources.get('VPC Endpoints', []) if should_include(r, inc, exc)]
    kms_keys = [r for r in resources.get('KMS Keys', []) if should_include(r, inc, exc)]
    acm_certs = [r for r in resources.get('ACM Certificates', []) if should_include(r, inc, exc)]
    sns_topics = [r for r in resources.get('SNS Topics', []) if should_include(r, inc, exc)]
    tgws = [r for r in resources.get('Transit Gateways', []) if should_include(r, inc, exc)]
    tgw_attachments = resources.get('Transit Gateway Attachments', [])
    cgws = [r for r in resources.get('Customer Gateways', []) if should_include(r, inc, exc)]
    vpn_conns = [r for r in resources.get('VPN Connections', []) if should_include(r, inc, exc)]
    cw_alarms = [r for r in resources.get('CloudWatch Alarms', []) if should_include(r, inc, exc)]

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Supporting Services — {len(vpc_endpoints)} VPC Endpoints, '
        f'{len(kms_keys)} KMS Keys, {len(acm_certs)} ACM Certs, '
        f'{len(sns_topics)} SNS Topics, {len(tgws)} Transit Gateways, '
        f'{len(vpn_conns)} VPN Connections, {len(cw_alarms)} CloudWatch Alarms.'
    )

    t['Parameters'] = OrderedDict()
    t['Parameters']['FoundationStack'] = {'Type': 'String', 'Default': 'dr-foundation'}
    t['Parameters']['SGStack'] = {'Type': 'String', 'Default': 'dr-security-groups'}
    t['Parameters']['TargetRegion'] = {
        'Type': 'String',
        'Description': 'DR target region for service name replacement',
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # ── VPC Endpoints ──
    for vpce in vpc_endpoints:
        vc = vpce['config']
        vpce_type = vc.get('VpcEndpointType', 'Gateway')
        service_name = vc.get('ServiceName', '')

        # Skip GWLB endpoints (tied to infrastructure)
        if vpce_type == 'GatewayLoadBalancer':
            continue

        # Replace source region in service name with DR region ref
        logical = safe_logical_id(service_name.split('.')[-1] if '.' in service_name else vpce['resource_id'])

        vpce_props = OrderedDict()
        # Service name needs region replacement — use Fn::Sub
        # e.g., com.amazonaws.us-gov-west-1.s3 -> com.amazonaws.${TargetRegion}.s3
        source_region = inventory.get('metadata', {}).get('region', '')
        if source_region and source_region in service_name:
            vpce_props['ServiceName'] = {'Fn::Sub': service_name.replace(source_region, '${TargetRegion}')}
        else:
            vpce_props['ServiceName'] = service_name

        vpce_props['VpcId'] = {'Fn::ImportValue': {'Fn::Sub': '${FoundationStack}-VpcId'}}
        vpce_props['VpcEndpointType'] = vpce_type

        if vpce_type == 'Interface':
            vpce_props['PrivateDnsEnabled'] = vc.get('PrivateDnsEnabled', True)
            # SGs for interface endpoints
            sg_refs = []
            for sg_id in (vc.get('GroupId') or []):
                if sg_id in sg_id_to_logical:
                    sg_refs.append({
                        'Fn::ImportValue': {'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}
                    })
            if sg_refs:
                vpce_props['SecurityGroupIds'] = sg_refs

        vpce_props['Tags'] = [
            {'Key': 'Name', 'Value': f'DR-{service_name.split(".")[-1]}'},
            {'Key': 'SourceVpceId', 'Value': vc.get('VpcEndpointId', '')},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::EC2::VPCEndpoint',
            'Properties': vpce_props,
        }

    # ── KMS Keys ──
    for key in kms_keys:
        kc = key['config']
        key_id = kc.get('KeyId', 'unnamed')
        logical = safe_logical_id(key_id)

        t['Resources'][logical] = {
            'Type': 'AWS::KMS::Key',
            'Properties': OrderedDict([
                ('Description', kc.get('Description', f'DR copy of key {key_id}')),
                ('Enabled', kc.get('Enabled', True)),
                ('KeyUsage', kc.get('KeyUsage', 'ENCRYPT_DECRYPT')),
                ('Tags', [
                    {'Key': 'Name', 'Value': kc.get('Description', key_id)[:128]},
                    {'Key': 'SourceKeyId', 'Value': key_id},
                ]),
            ]),
        }
        t['Resources'][f'{logical}Alias'] = {
            'Type': 'AWS::KMS::Alias',
            'Properties': {
                'AliasName': f'alias/dr-{key_id[:20]}',
                'TargetKeyId': {'Ref': logical},
            },
        }
        t['Outputs'][f'{logical}Arn'] = {
            'Value': {'Fn::GetAtt': [logical, 'Arn']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    # ── ACM Certificates ──
    for cert in acm_certs:
        cc = cert['config']
        domain = cc.get('DomainName', '')
        if not domain:
            continue
        logical = safe_logical_id(domain.replace('*', 'wildcard').replace('.', ''))

        cert_props = OrderedDict()
        cert_props['DomainName'] = domain
        if cc.get('SubjectAlternativeNames') and cc['SubjectAlternativeNames'] != '':
            sans = cc['SubjectAlternativeNames']
            if isinstance(sans, list):
                cert_props['SubjectAlternativeNames'] = sans
        cert_props['ValidationMethod'] = 'DNS'
        cert_props['Tags'] = [
            {'Key': 'Name', 'Value': domain},
            {'Key': 'SourceStatus', 'Value': cc.get('Status', '')},
            {'Key': 'NOTE', 'Value': 'Cannot copy cross-region. Must re-issue and validate DNS.'},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::CertificateManager::Certificate',
            'Properties': cert_props,
        }
        t['Outputs'][f'{logical}Arn'] = {
            'Value': {'Ref': logical},
            'Description': f'ACM cert for {domain}',
        }

    # ── SNS Topics ──
    for topic in sns_topics:
        tc = topic['config']
        topic_name = tc.get('TopicName', 'unnamed')
        logical = safe_logical_id(topic_name)

        t['Resources'][logical] = {
            'Type': 'AWS::SNS::Topic',
            'Properties': OrderedDict([
                ('TopicName', topic_name),
                ('DisplayName', tc.get('DisplayName', topic_name)),
                ('Tags', [{'Key': 'Name', 'Value': topic_name}]),
            ]),
        }
        t['Outputs'][f'{logical}Arn'] = {
            'Value': {'Ref': logical},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    # ── Transit Gateways (only customer-owned) ──
    for tgw in tgws:
        tc = tgw['config']
        # Only include TGWs owned by this account
        owner = str(tc.get('OwnerId', ''))
        account_id = str(inventory.get('metadata', {}).get('account_id', ''))
        if owner != account_id:
            continue  # Skip shared TGWs from other accounts

        tgw_id = tc.get('TransitGatewayId', '')
        logical = safe_logical_id(tgw.get('name', tgw_id))

        t['Resources'][logical] = {
            'Type': 'AWS::EC2::TransitGateway',
            'Properties': OrderedDict([
                ('AmazonSideAsn', tc.get('AmazonSideAsn', 64512)),
                ('DefaultRouteTableAssociation', tc.get('DefaultRouteTableAssociation', 'enable')),
                ('DefaultRouteTablePropagation', tc.get('DefaultRouteTablePropagation', 'enable')),
                ('DnsSupport', tc.get('DnsSupport', 'enable')),
                ('Tags', [
                    {'Key': 'Name', 'Value': tgw.get('name', tgw_id)},
                    {'Key': 'SourceTgwId', 'Value': tgw_id},
                ]),
            ]),
        }

    # ── Customer Gateways ──
    for cgw in cgws:
        gc = cgw['config']
        cgw_id = gc.get('CustomerGatewayId', '')
        logical = safe_logical_id(cgw_id)

        t['Resources'][logical] = {
            'Type': 'AWS::EC2::CustomerGateway',
            'Properties': OrderedDict([
                ('Type', gc.get('Type', 'ipsec.1')),
                ('BgpAsn', gc.get('BgpAsn', 65000)),
                ('IpAddress', gc.get('IpAddress', '')),
                ('Tags', [
                    {'Key': 'Name', 'Value': gc.get('DeviceName', cgw_id)},
                    {'Key': 'SourceCgwId', 'Value': cgw_id},
                ]),
            ]),
        }

    # ── VPN Connections ──
    for vpn in vpn_conns:
        vc = vpn['config']
        vpn_id = vc.get('VpnConnectionId', '')
        logical = safe_logical_id(vpn_id)

        vpn_props = OrderedDict()
        vpn_props['Type'] = vc.get('Type', 'ipsec.1')
        vpn_props['StaticRoutesOnly'] = vc.get('StaticRoutesOnly', False)

        # Reference CGW if we created it
        cgw_id = vc.get('CustomerGatewayId', '')
        if cgw_id:
            cgw_logical = safe_logical_id(cgw_id)
            if cgw_logical in [safe_logical_id(c['config'].get('CustomerGatewayId', '')) for c in cgws]:
                vpn_props['CustomerGatewayId'] = {'Ref': cgw_logical}
            else:
                vpn_props['CustomerGatewayId'] = cgw_id

        # TGW reference
        tgw_id = vc.get('TransitGatewayId', '')
        if tgw_id:
            # Check if we created this TGW
            our_tgws = [tg for tg in tgws if tg['config'].get('TransitGatewayId') == tgw_id
                        and str(tg['config'].get('OwnerId', '')) == str(inventory.get('metadata', {}).get('account_id', ''))]
            if our_tgws:
                vpn_props['TransitGatewayId'] = {'Ref': safe_logical_id(our_tgws[0].get('name', tgw_id))}
            else:
                vpn_props['TransitGatewayId'] = tgw_id  # Shared TGW — use ID directly

        vpn_props['Tags'] = [
            {'Key': 'Name', 'Value': f'DR-VPN-{vpn_id}'},
            {'Key': 'SourceVpnId', 'Value': vpn_id},
        ]

        t['Resources'][logical] = {
            'Type': 'AWS::EC2::VPNConnection',
            'Properties': vpn_props,
        }

    # Build params
    params = OrderedDict()
    comments = {}
    for p_name, p_config in t.get('Parameters', {}).items():
        params[p_name] = p_config.get('Default', '')
        comments[p_name] = p_config.get('Description', '')

    return t, params, comments


# ═══════════════════════════════════════════════════════════════════
# MANUAL STEPS
# ═══════════════════════════════════════════════════════════════════

def generate_manual_steps(inventory: dict, inc: list, exc: list, output_dir: str):
    """Write manual-steps.md for resources that can't be CFN-managed."""
    resources = inventory.get('resources', {})
    manual_items = []

    for category in MANUAL_ONLY:
        items = resources.get(category, [])
        for r in items:
            if should_include(r, inc, exc):
                manual_items.append({
                    'category': category,
                    'name': r.get('name', 'unnamed'),
                    'note': r.get('dr_note', ''),
                })

    filepath = os.path.join(output_dir, 'manual-steps.md')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Manual Steps Required\n\n")
        f.write("These resources require manual action — they cannot be fully\n")
        f.write("reproduced via CloudFormation.\n\n")

        by_category = defaultdict(list)
        for item in manual_items:
            by_category[item['category']].append(item)

        for category in sorted(by_category.keys()):
            items = by_category[category]
            f.write(f"## {category} ({len(items)} items)\n\n")
            if category == 'Secrets':
                f.write("Run `scripts/replicate-secrets.py` to copy values to DR region.\n\n")
            elif category == 'SSM Parameters':
                f.write("Run `scripts/replicate-parameters.py` to copy values to DR region.\n\n")
            for item in items:
                f.write(f"- **{item['name']}**\n")
                if item['note']:
                    f.write(f"  {item['note']}\n")
            f.write("\n")

    print(f"  Written: manual-steps.md ({len(manual_items)} items)")


# ═══════════════════════════════════════════════════════════════════
# DEPLOY.md
# ═══════════════════════════════════════════════════════════════════

def generate_deploy_guide(inventory: dict, output_dir: str, tiers_generated: list):
    """Write DEPLOY.md with the correct tier deployment order."""
    meta = inventory.get('metadata', {})
    filepath = os.path.join(output_dir, 'DEPLOY.md')

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# DR Deployment Guide\n\n")
        f.write(f"**Source Account:** {meta.get('account_id', 'unknown')}\n")
        f.write(f"**Source Region:** {meta.get('region', 'unknown')}\n")
        f.write(f"**Inventory Date:** {meta.get('scan_date', 'unknown')}\n")
        f.write(f"**Generated:** {datetime.now(tz=timezone.utc).isoformat()}\n\n")
        f.write("---\n\n")

        f.write("## Pre-Deployment Checklist\n\n")
        f.write("- [ ] Copy customer-owned AMIs to DR region\n")
        f.write("- [ ] Copy latest EBS snapshots to DR region\n")
        f.write("- [ ] Copy FSx backups to DR region (AWS Backup cross-region copy)\n")
        f.write("- [ ] Copy RDS/Aurora snapshots to DR region\n")
        f.write("- [ ] Run `scripts/replicate-secrets.py` to copy secrets\n")
        f.write("- [ ] Run `scripts/replicate-parameters.py` to copy SSM params\n")
        f.write("- [ ] Verify ACM certificate DNS validation records exist\n")
        f.write("- [ ] Confirm VPN peer IPs are reachable from DR region\n\n")

        f.write("## Deployment Order\n\n")
        f.write("Deploy each tier in sequence. Wait for each to complete before proceeding.\n\n")

        deploy_order = [
            ('00-foundation.yaml', 'VPC, Subnets, DHCP, NAT Gateways', 'None'),
            ('01-security-groups.yaml', 'All Security Groups with cross-refs', '00-foundation'),
            ('02-data-tier.yaml', 'RDS/Aurora (restore from snapshot), FSx (restore from backup)', '00, 01'),
            ('03a-dc-compute.yaml', 'Domain Controllers — WAIT FOR AD HEALTH', '00, 01'),
            ('03-compute-tier.yaml', 'All other EC2 instances', '00, 01, 03a'),
            ('04-network-tier.yaml', 'Load Balancers, Target Groups, Listeners', '00, 01, 03'),
            ('05-serverless.yaml', 'Lambda, EventBridge', '00, 01'),
            ('06-supporting.yaml', 'VPC Endpoints, KMS, ACM, SNS, TGW, VPN', '00, 01'),
        ]

        f.write("| # | Template | Contents | Dependencies |\n")
        f.write("|---|----------|----------|---------------|\n")
        for idx, (template, desc, deps) in enumerate(deploy_order, 1):
            if template in tiers_generated:
                f.write(f"| {idx} | `{template}` | {desc} | {deps} |\n")
        f.write("\n")

        f.write("## Critical Boot-Order Note\n\n")
        f.write("**Domain Controllers (03a) must be deployed and verified healthy**\n")
        f.write("**BEFORE deploying 03-compute-tier or 02-data-tier (FSx).**\n\n")
        f.write("After deploying 03a-dc-compute.yaml:\n")
        f.write("1. Wait for DC instances to pass both status checks (2-5 min)\n")
        f.write("2. Verify AD health via SSM:\n")
        f.write("   ```bash\n")
        f.write("   aws ssm send-command --instance-ids <DC_ID> \\\n")
        f.write("     --document-name AWS-RunPowerShellScript \\\n")
        f.write("     --parameters 'commands=[\"dcdiag /s:localhost\"]'\n")
        f.write("   ```\n")
        f.write("3. Then proceed with compute and data tiers.\n\n")

        f.write("## Post-Deployment Steps\n\n")
        f.write("- [ ] Register targets with Target Groups (new instance IDs/IPs)\n")
        f.write("- [ ] Update DHCP Option DNS IPs to DR DC private IPs\n")
        f.write("- [ ] Verify DNS resolution from instances\n")
        f.write("- [ ] Test application connectivity end-to-end\n")
        f.write("- [ ] Re-establish VPN tunnels (new VPN connection IDs)\n")
        f.write("- [ ] Validate CloudWatch alarms fire correctly\n")

    print(f"  Written: DEPLOY.md")


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def find_inventory_file(input_dir: str) -> Optional[str]:
    """Find the inventory YAML file in a run directory."""
    import glob
    pattern = os.path.join(input_dir, 'inventory-*.yaml')
    matches = glob.glob(pattern)
    return matches[0] if matches else None


def main():
    parser = argparse.ArgumentParser(
        description='IaC Blueprint v2 — Tier-based DR template generation.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730-194817/
  python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730-194817/ --mode dr
        """,
    )
    parser.add_argument('--input', required=True,
                        help='Path to a discovery run directory (contains inventory-*.yaml)')
    parser.add_argument('--mode', default='dr', choices=['import', 'dr'],
                        help='Generation mode: import (exact state) or dr (parameterized)')
    args = parser.parse_args()

    input_dir = os.path.abspath(args.input)
    if not os.path.isdir(input_dir):
        print(f"ERROR: Input directory does not exist: {input_dir}")
        sys.exit(1)

    inventory_path = find_inventory_file(input_dir)
    if not inventory_path:
        print(f"ERROR: No inventory-*.yaml found in {input_dir}")
        sys.exit(1)

    print(f"Loading inventory: {inventory_path}")
    with open(inventory_path, 'r', encoding='utf-8') as f:
        inventory = yaml.safe_load(f)

    meta = inventory.get('metadata', {})
    region = meta.get('region', 'unknown')
    account = meta.get('account_id', 'unknown')
    print(f"Account: {account}, Region: {region}, Mode: {args.mode}")

    # Load filters
    include_rules = load_filter_file(os.path.join(input_dir, 'include.yaml'))
    exclude_rules = load_filter_file(os.path.join(input_dir, 'exclude.yaml'))
    if include_rules:
        print(f"Include filter: {len(include_rules)} rules")
    if exclude_rules:
        print(f"Exclude filter: {len(exclude_rules)} rules")

    # Output directory
    output_dir = os.path.join(input_dir, 'iac-templates')
    os.makedirs(output_dir, exist_ok=True)
    params_dir = os.path.join(output_dir, 'params')
    os.makedirs(params_dir, exist_ok=True)

    tiers_generated = []

    # ── Count resources ──
    print(f"\nResource summary:")
    resources = inventory.get('resources', {})
    total = 0
    for category, items in resources.items():
        if category.startswith('_'):
            continue
        included = [r for r in items if should_include(r, include_rules, exclude_rules)]
        if included:
            marker = ''
            if category in ASSESSMENT_ONLY:
                marker = ' [assessment-only]'
            elif category in MANUAL_ONLY:
                marker = ' [manual]'
            print(f"  {category:40s} {len(included):5d}{marker}")
            total += len(included)
    print(f"  {'TOTAL':40s} {total:5d}")

    print(f"\nGenerating tier templates in {output_dir}/...")

    # ═══ TIER 00: Foundation ═══
    print("\n─── 00-foundation ───")
    foundation_template, found_params, found_comments = generate_foundation(
        inventory, include_rules, exclude_rules)
    write_template(foundation_template,
                   os.path.join(output_dir, '00-foundation.yaml'),
                   f"DR Foundation — Deploy FIRST\n"
                   f"Source: {account} / {region}\n"
                   f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
    write_params_yaml(found_params, os.path.join(params_dir, '00-foundation-params.yaml'), found_comments)
    tiers_generated.append('00-foundation.yaml')

    # ═══ TIER 01: Security Groups ═══
    print("\n─── 01-security-groups ───")
    sg_template, sg_id_to_logical = generate_security_groups(inventory, include_rules, exclude_rules)
    write_template(sg_template,
                   os.path.join(output_dir, '01-security-groups.yaml'),
                   f"DR Security Groups — Cross-references resolved via Ref\n"
                   f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
    tiers_generated.append('01-security-groups.yaml')
    print(f"  {len(sg_id_to_logical)} SGs mapped")

    # ═══ TIER 02: Data Tier ═══
    print("\n─── 02-data-tier ───")
    data_template, data_params, data_comments = generate_data_tier(
        inventory, include_rules, exclude_rules, sg_id_to_logical)
    write_template(data_template,
                   os.path.join(output_dir, '02-data-tier.yaml'),
                   f"DR Data Tier — RDS/Aurora restore from snapshot, FSx restore from backup\n"
                   f"REQUIRES: 00-foundation, 01-security-groups, DCs healthy (for FSx)\n"
                   f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
    write_params_yaml(data_params, os.path.join(params_dir, '02-data-tier-params.yaml'), data_comments)
    tiers_generated.append('02-data-tier.yaml')

    # ═══ TIER 03/03a: Compute ═══
    all_instances = resources.get('EC2 Instances', [])
    customer_instances = [i for i in all_instances if should_include(i, include_rules, exclude_rules)]
    subnets = resources.get('Subnets', [])

    dc_instances = [i for i in customer_instances if is_domain_controller(i)]
    non_dc_instances = [i for i in customer_instances if not is_domain_controller(i)]

    if dc_instances:
        print(f"\n─── 03a-dc-compute ─── ({len(dc_instances)} DCs)")
        dc_template, dc_params, dc_comments = generate_compute_template(
            dc_instances, sg_id_to_logical, subnets, is_dc=True)
        write_template(dc_template,
                       os.path.join(output_dir, '03a-dc-compute.yaml'),
                       f"DR Domain Controllers — Deploy BEFORE other compute!\n"
                       f"After deploy: verify AD health, THEN deploy 03-compute-tier.\n"
                       f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
        write_params_yaml(dc_params, os.path.join(params_dir, '03a-dc-compute-params.yaml'), dc_comments)
        tiers_generated.append('03a-dc-compute.yaml')

    if non_dc_instances:
        print(f"\n─── 03-compute-tier ─── ({len(non_dc_instances)} instances)")
        compute_template, compute_params, compute_comments = generate_compute_template(
            non_dc_instances, sg_id_to_logical, subnets, is_dc=False)
        write_template(compute_template,
                       os.path.join(output_dir, '03-compute-tier.yaml'),
                       f"DR Compute Tier — {len(non_dc_instances)} instances\n"
                       f"REQUIRES: 00-foundation, 01-security-groups, 03a-dc-compute (AD healthy)\n"
                       f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
        write_params_yaml(compute_params, os.path.join(params_dir, '03-compute-tier-params.yaml'), compute_comments)
        tiers_generated.append('03-compute-tier.yaml')

    # ═══ TIER 04: Network ═══
    print("\n─── 04-network-tier ───")
    network_template, net_params, net_comments = generate_network_tier(
        inventory, include_rules, exclude_rules, sg_id_to_logical)
    write_template(network_template,
                   os.path.join(output_dir, '04-network-tier.yaml'),
                   f"DR Network Tier — Load Balancers, Target Groups, Listeners\n"
                   f"REQUIRES: 00-foundation, 01-security-groups, 03-compute-tier\n"
                   f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
    write_params_yaml(net_params, os.path.join(params_dir, '04-network-tier-params.yaml'), net_comments)
    tiers_generated.append('04-network-tier.yaml')

    # ═══ TIER 05: Serverless ═══
    print("\n─── 05-serverless ───")
    serverless_template, sv_params, sv_comments = generate_serverless(
        inventory, include_rules, exclude_rules)
    write_template(serverless_template,
                   os.path.join(output_dir, '05-serverless.yaml'),
                   f"DR Serverless — Lambda, EventBridge\n"
                   f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
    write_params_yaml(sv_params, os.path.join(params_dir, '05-serverless-params.yaml'), sv_comments)
    tiers_generated.append('05-serverless.yaml')

    # ═══ TIER 06: Supporting ═══
    print("\n─── 06-supporting ───")
    supporting_template, sup_params, sup_comments = generate_supporting(
        inventory, include_rules, exclude_rules, sg_id_to_logical)
    write_template(supporting_template,
                   os.path.join(output_dir, '06-supporting.yaml'),
                   f"DR Supporting — VPC Endpoints, KMS, ACM, SNS, TGW, VPN\n"
                   f"Generated: {datetime.now(tz=timezone.utc).isoformat()}")
    write_params_yaml(sup_params, os.path.join(params_dir, '06-supporting-params.yaml'), sup_comments)
    tiers_generated.append('06-supporting.yaml')

    # ═══ Manual Steps ═══
    print("\n─── manual-steps ───")
    generate_manual_steps(inventory, include_rules, exclude_rules, output_dir)

    # ═══ DEPLOY.md ═══
    print("\n─── DEPLOY.md ───")
    generate_deploy_guide(inventory, output_dir, tiers_generated)

    # ═══ Summary ═══
    print(f"\n{'═' * 60}")
    print(f"Done. {len(tiers_generated)} tier templates generated in {output_dir}/")
    print(f"  Templates:  {', '.join(tiers_generated)}")
    print(f"  Params:     params/*.yaml")
    print(f"  Guide:      DEPLOY.md")
    print(f"  Manual:     manual-steps.md")
    print(f"{'═' * 60}")


if __name__ == "__main__":
    main()
