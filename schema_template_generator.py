#!/usr/bin/env python3
"""
Schema Template Generator — Produces operator-ready CloudFormation templates.

Each template is self-contained and deployable: either via the CloudFormation
console (fill in parameter fields) or via CLI with a parameter file. Templates
follow the patterns established in the N-Able reference implementation:

  - Parameters use proper CFN types (AWS::EC2::Image::Id, AWS::EC2::Subnet::Id)
  - Defaults show source-region values (operator knows what to replace)
  - Cross-stack references use named stack parameters with sensible defaults
  - Resources contain only deploy-relevant properties, no runtime state
  - Shared resources (IAM roles, subnet groups) are created once per template

The generator understands resource types and produces type-appropriate output:
  - EC2: AMI param, instance profile, SG imports, subnet param, all tags
  - RDS: Snapshot param, subnet group, KMS param, SG ref
  - LB: Subnet params, SG imports, TG wiring, listener chain
  - Lambda: Code bucket/key params, VPC config if attached
  - Generic: Schema-driven property emission for unknown types
"""

import re
import os
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import OrderedDict
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

def safe_logical_id(name: str) -> str:
    """Convert a resource name/ID to a valid CFN logical ID (alphanumeric)."""
    clean = re.sub(r'[^a-zA-Z0-9]', '', name)
    if clean and not clean[0].isalpha():
        clean = 'R' + clean
    return clean[:64] or 'Unknown'


def short_name(full_name: str) -> str:
    """Extract short name from paths like 'primary-CcpmNetworking/DC1'."""
    if '/' in full_name:
        return full_name.split('/')[-1]
    return full_name


# ═══════════════════════════════════════════════════════════════════
# FOUNDATION TEMPLATE
# ═══════════════════════════════════════════════════════════════════

def generate_foundation(resources, inventory):
    """Generate foundation template: VPC, Subnets, Route Tables, DHCP, NAT GWs.

    Args:
        resources: list of ResourceNode for this group
        inventory: full inventory dict (for metadata)
    Returns:
        (template_dict, description)
    """
    # Separate by category
    vpcs = [r for r in resources if r.category == 'VPCs']
    subnets = [r for r in resources if r.category == 'Subnets']
    route_tables = [r for r in resources if r.category == 'Route Tables']
    dhcp_opts = [r for r in resources if r.category == 'DHCP Options']
    nat_gws = [r for r in resources if r.category == 'NAT Gateways']

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Foundation — {len(vpcs)} VPC, {len(subnets)} Subnets, '
        f'{len(route_tables)} Route Tables, {len(nat_gws)} NAT Gateways. '
        f'Deploy FIRST.')

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcCidr'] = {
        'Type': 'String',
        'Default': vpcs[0].config.get('CidrBlock', '') if vpcs else '',
        'Description': 'VPC CIDR block (same as source unless DR uses different range)',
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # ── VPC ──
    if vpcs:
        vpc = vpcs[0]
        vc = vpc.config
        t['Resources']['VPC'] = {
            'Type': 'AWS::EC2::VPC',
            'Properties': OrderedDict([
                ('CidrBlock', {'Ref': 'VpcCidr'}),
                ('EnableDnsSupport', vc.get('EnableDnsSupport', True)),
                ('EnableDnsHostnames', vc.get('EnableDnsHostnames', True)),
                ('Tags', [
                    {'Key': 'Name', 'Value': f"DR-{vpc.name}"},
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
    subnets.sort(key=lambda s: (
        s.config.get('AvailabilityZone', ''),
        s.config.get('CidrBlock', '')
    ))
    for sub in subnets:
        sc = sub.config
        label = _subnet_label(sub)
        logical = safe_logical_id(label)

        param_name = f'{logical}Cidr'
        t['Parameters'][param_name] = {
            'Type': 'String',
            'Default': sc.get('CidrBlock', ''),
            'Description': f'CIDR for {label} (source AZ: {sc.get("AvailabilityZone", "")})',
        }

        az = sc.get('AvailabilityZone', '')
        az_suffix = az[-1] if az else 'a'
        t['Resources'][logical] = {
            'Type': 'AWS::EC2::Subnet',
            'Properties': OrderedDict([
                ('VpcId', {'Ref': 'VPC'}),
                ('CidrBlock', {'Ref': param_name}),
                ('AvailabilityZone', {'Fn::Select': [
                    0 if az_suffix in ('a', 'c') else 1,
                    {'Fn::GetAZs': {'Ref': 'AWS::Region'}}
                ]}),
                ('MapPublicIpOnLaunch', sc.get('MapPublicIpOnLaunch', False)),
                ('Tags', [
                    {'Key': 'Name', 'Value': f'DR-{label}'},
                    {'Key': 'SourceSubnetId', 'Value': sc.get('SubnetId', '')},
                ]),
            ]),
        }
        t['Outputs'][f'{logical}Id'] = {
            'Value': {'Ref': logical},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    # ── NAT Gateways ──
    for idx, nat in enumerate(nat_gws, 1):
        nc = nat.config
        eip_logical = f'NatEIP{idx}'
        nat_logical = f'NatGW{idx}'
        source_subnet = nc.get('SubnetId', '')

        # Find matching subnet
        subnet_ref = {'Ref': 'VPC'}  # fallback
        for sub in subnets:
            if sub.config.get('SubnetId') == source_subnet:
                subnet_ref = {'Ref': safe_logical_id(_subnet_label(sub))}
                break

        t['Resources'][eip_logical] = {
            'Type': 'AWS::EC2::EIP',
            'Properties': {'Domain': 'vpc'},
        }
        t['Resources'][nat_logical] = {
            'Type': 'AWS::EC2::NatGateway',
            'Properties': OrderedDict([
                ('AllocationId', {'Fn::GetAtt': [eip_logical, 'AllocationId']}),
                ('SubnetId', subnet_ref),
                ('Tags', [
                    {'Key': 'Name', 'Value': f'DR-NatGW-{idx}'},
                    {'Key': 'SourceNatGwId', 'Value': nc.get('NatGatewayId', '')},
                ]),
            ]),
        }

    return t


def _subnet_label(sub) -> str:
    """Get human-readable label for a subnet."""
    tags = sub.config.get('Tags', {})
    name = tags.get('Name', '')
    cdk_name = tags.get('aws-cdk:subnet-name', '')
    if cdk_name:
        return cdk_name
    if '/' in name:
        return name.split('/')[-1]
    return name or sub.resource_id or 'unnamed'


# ═══════════════════════════════════════════════════════════════════
# SECURITY GROUPS TEMPLATE
# ═══════════════════════════════════════════════════════════════════

def generate_security_groups(resources, inventory):
    """Generate SG template with cross-ref resolution via Ref."""

    # Build SG ID -> logical name map
    sg_id_to_logical = {}
    for node in resources:
        sg_id = node.config.get('GroupId', node.resource_id)
        sg_name = node.config.get('GroupName', sg_id)
        sg_id_to_logical[sg_id] = safe_logical_id(sg_name)

    vpc_id = ''
    vpc_cidr = ''
    res = inventory.get('resources', {})
    vpcs = res.get('VPCs', [])
    if vpcs:
        vpc_id = vpcs[0].get('config', {}).get('VpcId', '')
        vpc_cidr = vpcs[0].get('config', {}).get('CidrBlock', '')

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = f'DR Security Groups — {len(resources)} SGs with cross-references resolved via Ref.'

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Default': vpc_id,
        'Description': 'DR VPC ID',
    }
    t['Parameters']['VpcCidr'] = {
        'Type': 'String',
        'Default': vpc_cidr,
        'Description': 'VPC CIDR (for CIDR-based rules)',
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    for node in resources:
        config = node.config
        sg_id = config.get('GroupId', node.resource_id)
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

        sg_resource = OrderedDict()
        sg_resource['Type'] = 'AWS::EC2::SecurityGroup'
        props = OrderedDict()
        props['GroupDescription'] = description
        props['GroupName'] = f'{sg_name}-DR'
        props['VpcId'] = {'Ref': 'VpcId'}
        if ingress_rules:
            props['SecurityGroupIngress'] = ingress_rules
        props['Tags'] = [
            {'Key': 'Name', 'Value': f'{sg_name}-DR'},
            {'Key': 'SourceSG', 'Value': sg_id},
        ]
        sg_resource['Properties'] = props
        t['Resources'][logical] = sg_resource

        # Self-referencing rules as separate resources
        for idx, sr in enumerate(self_ref_rules):
            sr_props = OrderedDict([
                ('GroupId', {'Ref': logical}),
                ('IpProtocol', sr['IpProtocol']),
            ])
            if 'FromPort' in sr:
                sr_props['FromPort'] = sr['FromPort']
            if 'ToPort' in sr:
                sr_props['ToPort'] = sr['ToPort']
            sr_props['SourceSecurityGroupId'] = {'Ref': logical}
            if 'Description' in sr:
                sr_props['Description'] = sr['Description']
            t['Resources'][f'{logical}Self{idx}'] = {
                'Type': 'AWS::EC2::SecurityGroupIngress',
                'Properties': sr_props,
            }

        # Export
        t['Outputs'][f'{logical}Id'] = {
            'Value': {'Fn::GetAtt': [logical, 'GroupId']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    return t, sg_id_to_logical


# ═══════════════════════════════════════════════════════════════════
# COMPUTE TEMPLATE (EC2 Instances)
# ═══════════════════════════════════════════════════════════════════

def generate_compute(resources, inventory, sg_id_to_logical, is_dc=False):
    """Generate compute template: EC2 instances with instance profiles.

    Args:
        resources: list of ResourceNode (EC2 instances)
        inventory: full inventory dict
        sg_id_to_logical: map from SG ID to logical name (from SG template)
        is_dc: True if these are domain controllers
    """
    tier_label = 'DC Compute (Boot First)' if is_dc else 'Compute Tier'

    # Gather subnet info from inventory
    all_subnets = inventory.get('resources', {}).get('Subnets', [])
    subnet_id_to_label = {}
    for sub in all_subnets:
        sid = sub.get('config', {}).get('SubnetId', '')
        tags = sub.get('config', {}).get('Tags', {})
        label = tags.get('Name', '') or tags.get('aws-cdk:subnet-name', '') or sid
        if '/' in label:
            label = label.split('/')[-1]
        subnet_id_to_label[sid] = label

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = f'DR {tier_label} — {len(resources)} instances.'

    t['Parameters'] = OrderedDict()
    t['Parameters']['SGStack'] = {
        'Type': 'String',
        'Default': 'dr-security-groups',
        'Description': 'Name of the security groups stack',
    }

    # Collect unique subnets used
    subnet_ids_used = set()
    for inst in resources:
        sid = inst.config.get('SubnetId', '')
        if sid:
            subnet_ids_used.add(sid)

    # Subnet parameters
    subnet_param_map = {}
    for idx, sid in enumerate(sorted(subnet_ids_used), 1):
        label = subnet_id_to_label.get(sid, f'Subnet{idx}')
        param_name = f'Subnet{safe_logical_id(label)}'
        t['Parameters'][param_name] = {
            'Type': 'AWS::EC2::Subnet::Id',
            'Default': sid,
            'Description': f'DR subnet replacing {sid} ({label})',
        }
        subnet_param_map[sid] = param_name

    # Per-instance AMI parameters
    for inst in resources:
        name = short_name(inst.name)
        logical = safe_logical_id(name)
        ami = inst.config.get('ImageId', '')
        t['Parameters'][f'{logical}AmiId'] = {
            'Type': 'AWS::EC2::Image::Id',
            'Description': f'AMI for {name} (source: {ami})',
        }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # Shared IAM role for SSM
    t['Resources']['EC2SSMRole'] = {
        'Type': 'AWS::IAM::Role',
        'Properties': OrderedDict([
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

    for inst in resources:
        config = inst.config
        name = short_name(inst.name)
        logical = safe_logical_id(name)
        subnet_id = config.get('SubnetId', '')

        # Instance profile
        profile_logical = f'{logical}Profile'
        t['Resources'][profile_logical] = {
            'Type': 'AWS::IAM::InstanceProfile',
            'Properties': {'Roles': [{'Ref': 'EC2SSMRole'}]},
        }

        # Map SGs to ImportValue from SG stack
        sg_refs = []
        for sg_id in config.get('GroupId', []):
            if isinstance(sg_id, str) and sg_id in sg_id_to_logical:
                sg_refs.append({'Fn::ImportValue': {
                    'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}})

        props = OrderedDict()
        props['ImageId'] = {'Ref': f'{logical}AmiId'}
        props['InstanceType'] = config.get('InstanceType', 't3.medium')
        props['IamInstanceProfile'] = {'Ref': profile_logical}
        if config.get('KeyName'):
            props['KeyName'] = config['KeyName']
        if subnet_id in subnet_param_map:
            props['SubnetId'] = {'Ref': subnet_param_map[subnet_id]}
        if sg_refs:
            props['SecurityGroupIds'] = sg_refs

        # Tags — preserve all meaningful customer tags
        tags = config.get('Tags', {})
        cfn_tags = [
            {'Key': 'Name', 'Value': inst.name},
            {'Key': 'SourceInstanceId', 'Value': config.get('InstanceId', inst.resource_id)},
        ]
        for key in sorted(tags.keys()):
            if key in ('Name', ) or key.startswith('aws:'):
                continue
            cfn_tags.append({'Key': key, 'Value': str(tags[key])})
        props['Tags'] = cfn_tags

        t['Resources'][logical] = {
            'Type': 'AWS::EC2::Instance',
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

    return t


# ═══════════════════════════════════════════════════════════════════
# DATA TIER TEMPLATE (RDS, Aurora, FSx, ElastiCache)
# ═══════════════════════════════════════════════════════════════════

def generate_data_tier(resources, inventory, sg_id_to_logical):
    """Generate data tier: RDS, Aurora clusters, FSx, ElastiCache."""

    rds_clusters = [r for r in resources if r.category == 'RDS DB Clusters']
    rds_instances = [r for r in resources if r.category == 'RDS Instances']
    rds_subnet_groups = [r for r in resources if r.category == 'RDS DB Subnet Groups']
    rds_param_groups = [r for r in resources if r.category == 'RDS Parameter Groups']
    rds_cluster_pg = [r for r in resources if r.category == 'RDS Cluster Parameter Groups']
    rds_option_groups = [r for r in resources if r.category == 'RDS Option Groups']
    fsx_systems = [r for r in resources if r.category == 'FSx File Systems']
    elasticache = [r for r in resources
                   if r.category in ('ElastiCache Clusters', 'ElastiCache Replication Groups')]

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Data Tier — {len(rds_clusters)} Aurora clusters, '
        f'{len(rds_instances)} RDS instances, {len(fsx_systems)} FSx, '
        f'{len(elasticache)} ElastiCache. Restore from cross-region snapshots.')

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID',
    }
    t['Parameters']['SGStack'] = {
        'Type': 'String',
        'Default': 'dr-security-groups',
        'Description': 'Name of the security groups stack',
    }
    t['Parameters']['DataSubnet1'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Data subnet AZ1',
    }
    t['Parameters']['DataSubnet2'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Data subnet AZ2',
    }
    t['Parameters']['KmsKeyArn'] = {
        'Type': 'String',
        'Description': 'KMS key ARN in DR region for encryption',
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # ── DB Subnet Group ──
    if rds_subnet_groups or rds_instances or rds_clusters:
        t['Resources']['DBSubnetGroup'] = {
            'Type': 'AWS::RDS::DBSubnetGroup',
            'Properties': OrderedDict([
                ('DBSubnetGroupDescription', 'DR database subnets'),
                ('SubnetIds', [{'Ref': 'DataSubnet1'}, {'Ref': 'DataSubnet2'}]),
            ]),
        }

    # ── RDS Parameter Groups (custom only) ──
    for pg in rds_param_groups:
        pc = pg.config
        pg_name = pc.get('DBParameterGroupName', '')
        if pg_name.startswith('default.'):
            continue
        logical = safe_logical_id(pg_name)
        t['Resources'][logical] = {
            'Type': 'AWS::RDS::DBParameterGroup',
            'Properties': OrderedDict([
                ('Family', pc.get('DBParameterGroupFamily', '')),
                ('Description', pc.get('Description', f'DR copy of {pg_name}')),
            ]),
        }

    # ── Aurora Clusters ──
    for cluster in rds_clusters:
        cc = cluster.config
        cid = cc.get('DBClusterIdentifier', 'unnamed')
        logical = safe_logical_id(cid)

        snap_param = f'{logical}SnapshotArn'
        t['Parameters'][snap_param] = {
            'Type': 'String',
            'Description': f'Cluster snapshot ARN for {cid} in DR region',
        }

        sg_refs = []
        for sg_id in cc.get('VpcSecurityGroupId', []):
            if sg_id in sg_id_to_logical:
                sg_refs.append({'Fn::ImportValue': {
                    'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}})

        t['Resources'][logical] = {
            'Type': 'AWS::RDS::DBCluster',
            'Properties': OrderedDict([
                ('DBClusterIdentifier', cid),
                ('Engine', cc.get('Engine', '')),
                ('EngineVersion', cc.get('EngineVersion', '')),
                ('Port', cc.get('Port', 5432)),
                ('SnapshotIdentifier', {'Ref': snap_param}),
                ('DBSubnetGroupName', {'Ref': 'DBSubnetGroup'}),
                ('VpcSecurityGroupIds', sg_refs or []),
                ('StorageEncrypted', cc.get('StorageEncrypted', True)),
                ('KmsKeyId', {'Ref': 'KmsKeyArn'}),
                ('DeletionProtection', cc.get('DeletionProtection', True)),
                ('BackupRetentionPeriod', cc.get('BackupRetentionPeriod', 7)),
            ]),
        }
        t['Outputs'][f'{logical}Endpoint'] = {
            'Value': {'Fn::GetAtt': [logical, 'Endpoint.Address']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}Endpoint'}},
        }

    # ── RDS Instances ──
    for rds in rds_instances:
        rc = rds.config
        db_id = rc.get('DBInstanceIdentifier', 'unnamed')
        logical = safe_logical_id(db_id)
        cluster_id = rc.get('DBClusterIdentifier', '')

        props = OrderedDict()
        props['DBInstanceIdentifier'] = db_id
        props['DBInstanceClass'] = rc.get('DBInstanceClass', 'db.t3.medium')
        props['Engine'] = rc.get('Engine', '')

        if cluster_id:
            props['DBClusterIdentifier'] = {'Ref': safe_logical_id(cluster_id)}
        else:
            snap_param = f'{logical}SnapshotId'
            t['Parameters'][snap_param] = {
                'Type': 'String',
                'Description': f'Snapshot ID for {db_id} in DR region',
            }
            props['DBSnapshotIdentifier'] = {'Ref': snap_param}
            props['DBSubnetGroupName'] = {'Ref': 'DBSubnetGroup'}
            props['StorageEncrypted'] = rc.get('StorageEncrypted', True)
            props['KmsKeyId'] = {'Ref': 'KmsKeyArn'}
            sg_refs = []
            for sg_id in rc.get('VpcSecurityGroupId', []):
                if sg_id in sg_id_to_logical:
                    sg_refs.append({'Fn::ImportValue': {
                        'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}})
            if sg_refs:
                props['VPCSecurityGroups'] = sg_refs

        props['MultiAZ'] = rc.get('MultiAZ', False)
        props['PubliclyAccessible'] = rc.get('PubliclyAccessible', False)

        t['Resources'][logical] = {
            'Type': 'AWS::RDS::DBInstance',
            'Properties': props,
        }
        if not cluster_id:
            t['Outputs'][f'{logical}Endpoint'] = {
                'Value': {'Fn::GetAtt': [logical, 'Endpoint.Address']},
                'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}Endpoint'}},
            }

    # ── FSx ──
    for fsx in fsx_systems:
        fc = fsx.config
        fs_id = fc.get('FileSystemId', fsx.resource_id)
        logical = safe_logical_id(fsx.name or fs_id)

        backup_param = f'{logical}BackupId'
        t['Parameters'][backup_param] = {
            'Type': 'String',
            'Description': f'FSx backup ID for {fsx.name} (cross-region copy of {fs_id})',
        }

        fsx_props = OrderedDict([
            ('FileSystemType', fc.get('FileSystemType', 'WINDOWS')),
            ('StorageCapacity', fc.get('StorageCapacity', 0)),
            ('StorageType', fc.get('StorageType', 'SSD')),
            ('SubnetIds', [{'Ref': 'DataSubnet1'}, {'Ref': 'DataSubnet2'}]),
            ('KmsKeyId', {'Ref': 'KmsKeyArn'}),
            ('BackupId', {'Ref': backup_param}),
        ])

        if fc.get('FileSystemType') == 'WINDOWS':
            win_config = OrderedDict()
            win_config['DeploymentType'] = fc.get('WindowsConfiguration_DeploymentType', 'MULTI_AZ_1')
            win_config['ThroughputCapacity'] = fc.get('WindowsConfiguration_ThroughputCapacity', 32)
            win_config['PreferredSubnetId'] = {'Ref': 'DataSubnet1'}
            fsx_props['WindowsConfiguration'] = win_config

        fsx_props['Tags'] = [
            {'Key': 'Name', 'Value': fsx.name or fs_id},
            {'Key': 'SourceFileSystemId', 'Value': fs_id},
            {'Key': 'WARNING', 'Value': 'DCs must be healthy before this resource (AD join)'},
        ]
        t['Resources'][logical] = {
            'Type': 'AWS::FSx::FileSystem',
            'Properties': fsx_props,
        }

    return t


# ═══════════════════════════════════════════════════════════════════
# NETWORK TEMPLATE (Load Balancers, Target Groups, Listeners)
# ═══════════════════════════════════════════════════════════════════

def generate_network(resources, inventory, sg_id_to_logical):
    """Generate network tier: LBs, TGs, Listeners with wiring."""

    lbs = [r for r in resources if r.category == 'Load Balancers']
    customer_lbs = [lb for lb in lbs if lb.config.get('Type', '') != 'gateway']

    # Pull TGs and Listeners from inventory (they may not be in this group)
    all_res = inventory.get('resources', {})
    all_tgs = all_res.get('Target Groups', [])
    all_listeners = all_res.get('Listeners', [])

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = f'DR Network Tier — {len(customer_lbs)} load balancers with target groups and listeners.'

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID',
    }
    t['Parameters']['SGStack'] = {
        'Type': 'String',
        'Default': 'dr-security-groups',
        'Description': 'Name of the security groups stack',
    }
    t['Parameters']['ComputeStack'] = {
        'Type': 'String',
        'Default': 'dr-compute',
        'Description': 'Name of the compute stack (for target registration)',
    }
    t['Parameters']['LBSubnet1'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Subnet AZ1 for load balancers',
    }
    t['Parameters']['LBSubnet2'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Subnet AZ2 for load balancers',
    }
    t['Parameters']['CertificateArn'] = {
        'Type': 'String',
        'Default': '',
        'Description': 'ACM certificate ARN in DR region (for TLS listeners)',
    }

    t['Conditions'] = {'HasCert': {
        'Fn::Not': [{'Fn::Equals': [{'Ref': 'CertificateArn'}, '']}]
    }}

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # Maps
    tg_arn_to_name = {tg.get('config', {}).get('TargetGroupArn', ''): tg.get('config', {}).get('TargetGroupName', '')
                      for tg in all_tgs}
    lb_arn_to_name = {lb.config.get('LoadBalancerArn', ''): lb.config.get('LoadBalancerName', '')
                      for lb in customer_lbs}

    # ── LBs ──
    for lb in customer_lbs:
        lc = lb.config
        lb_name = lc.get('LoadBalancerName', 'unnamed')
        lb_logical = safe_logical_id(lb_name)

        lb_props = OrderedDict()
        lb_props['Name'] = lb_name
        lb_props['Type'] = lc.get('Type', 'network')
        lb_props['Scheme'] = lc.get('Scheme', 'internet-facing')
        lb_props['Subnets'] = [{'Ref': 'LBSubnet1'}, {'Ref': 'LBSubnet2'}]

        sg_refs = []
        for sg_id in (lc.get('SecurityGroups') or []):
            if isinstance(sg_id, str) and sg_id in sg_id_to_logical:
                sg_refs.append({'Fn::ImportValue': {
                    'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}})
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
    for tg_item in all_tgs:
        tc = tg_item.get('config', {})
        tg_name = tc.get('TargetGroupName', 'unnamed')
        tg_lb_arns = tc.get('LoadBalancerArns', [])
        if not any(arn in lb_arn_to_name for arn in tg_lb_arns):
            continue
        tg_logical = safe_logical_id(tg_name)
        tg_props = OrderedDict()
        tg_props['Name'] = tg_name
        tg_props['Protocol'] = tc.get('Protocol', 'TCP')
        tg_props['Port'] = tc.get('Port', 443)
        tg_props['VpcId'] = {'Ref': 'VpcId'}
        tg_props['TargetType'] = tc.get('TargetType', 'instance')
        tg_props['HealthCheckProtocol'] = tc.get('HealthCheckProtocol', 'TCP')
        tg_props['HealthCheckIntervalSeconds'] = tc.get('HealthCheckIntervalSeconds', 30)
        if tc.get('HealthCheckPath'):
            tg_props['HealthCheckPath'] = tc['HealthCheckPath']
        tg_props['Tags'] = [
            {'Key': 'Name', 'Value': tg_name},
            {'Key': 'SourceTGArn', 'Value': tc.get('TargetGroupArn', '')},
            {'Key': 'NOTE', 'Value': 'Targets registered post-deploy with DR instance IDs'},
        ]
        t['Resources'][tg_logical] = {
            'Type': 'AWS::ElasticLoadBalancingV2::TargetGroup',
            'Properties': tg_props,
        }

    # ── Listeners ──
    for ln_item in all_listeners:
        lc = ln_item.get('config', {})
        lb_arn = lc.get('LoadBalancerArn', '')
        lb_name = lb_arn_to_name.get(lb_arn, '')
        if not lb_name:
            continue
        port = lc.get('Port', 443)
        protocol = lc.get('Protocol', 'TCP')
        lb_logical = safe_logical_id(lb_name)
        ln_logical = f'{lb_logical}Listener{port}{protocol}'

        ln_props = OrderedDict()
        ln_props['LoadBalancerArn'] = {'Ref': lb_logical}
        ln_props['Port'] = port
        ln_props['Protocol'] = protocol

        needs_cert = protocol in ('TLS', 'HTTPS')
        if needs_cert and lc.get('Certificates'):
            ln_props['Certificates'] = [{'CertificateArn': {'Ref': 'CertificateArn'}}]
        if lc.get('SslPolicy'):
            ln_props['SslPolicy'] = lc['SslPolicy']

        # Default action
        for action in lc.get('DefaultActions', []):
            tg_arn = action.get('TargetGroupArn', '')
            tg_name = tg_arn_to_name.get(tg_arn, '')
            if action.get('Type') == 'forward' and tg_name:
                ln_props['DefaultActions'] = [{
                    'Type': 'forward',
                    'TargetGroupArn': {'Ref': safe_logical_id(tg_name)},
                }]
                break
        if 'DefaultActions' not in ln_props:
            continue

        resource_def = {'Type': 'AWS::ElasticLoadBalancingV2::Listener', 'Properties': ln_props}
        if needs_cert:
            resource_def['Condition'] = 'HasCert'
        t['Resources'][ln_logical] = resource_def

    return t


# ═══════════════════════════════════════════════════════════════════
# SERVERLESS TEMPLATE (Lambda, EventBridge)
# ═══════════════════════════════════════════════════════════════════

def generate_serverless(resources, inventory):
    """Generate serverless tier: Lambda functions + EventBridge rules."""
    lambdas = [r for r in resources if r.category == 'Lambda Functions']
    eb_rules = [r for r in resources if r.category == 'EventBridge Rules']

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = f'DR Serverless — {len(lambdas)} Lambda, {len(eb_rules)} EventBridge rules.'

    t['Parameters'] = OrderedDict()
    t['Parameters']['LambdaCodeBucket'] = {
        'Type': 'String',
        'Description': 'S3 bucket with Lambda deployment packages in DR region',
    }

    t['Resources'] = OrderedDict()

    for fn in lambdas:
        fc = fn.config
        fn_name = fc.get('FunctionName', 'unnamed')
        logical = safe_logical_id(fn_name)

        code_param = f'{logical}CodeKey'
        t['Parameters'][code_param] = {
            'Type': 'String',
            'Description': f'S3 key for {fn_name} (source size: {fc.get("CodeSize", 0)} bytes)',
        }

        props = OrderedDict()
        props['FunctionName'] = fn_name
        props['Runtime'] = fc.get('Runtime', 'python3.12')
        props['Handler'] = fc.get('Handler', 'index.handler')
        props['Role'] = fc.get('Role', '')
        props['MemorySize'] = fc.get('MemorySize', 128)
        props['Timeout'] = fc.get('Timeout', 30)
        props['Code'] = {
            'S3Bucket': {'Ref': 'LambdaCodeBucket'},
            'S3Key': {'Ref': code_param},
        }
        props['Tags'] = [{'Key': 'Name', 'Value': fn_name}]

        t['Resources'][logical] = {
            'Type': 'AWS::Lambda::Function',
            'Properties': props,
        }

    for rule in eb_rules:
        rc = rule.config
        rule_name = rc.get('Name', 'unnamed')
        logical = safe_logical_id(rule_name)
        props = OrderedDict()
        props['Name'] = rule_name
        props['State'] = rc.get('State', 'ENABLED')
        if rc.get('ScheduleExpression'):
            props['ScheduleExpression'] = rc['ScheduleExpression']
        if rc.get('EventPattern'):
            props['EventPattern'] = rc['EventPattern']
        t['Resources'][logical] = {
            'Type': 'AWS::Events::Rule',
            'Properties': props,
        }

    return t


# ═══════════════════════════════════════════════════════════════════
# SUPPORTING TEMPLATE (VPC Endpoints, KMS, ACM, SNS, CW Alarms)
# ═══════════════════════════════════════════════════════════════════

def generate_supporting(resources, inventory, sg_id_to_logical):
    """Generate supporting services template."""

    vpc_endpoints = [r for r in resources if r.category == 'VPC Endpoints']
    kms_keys = [r for r in resources if r.category == 'KMS Keys']
    acm_certs = [r for r in resources if r.category == 'ACM Certificates']
    sns_topics = [r for r in resources if r.category == 'SNS Topics']
    cw_alarms = [r for r in resources if r.category == 'CloudWatch Alarms']
    s3_buckets = [r for r in resources if r.category == 'S3 Buckets']

    meta = inventory.get('metadata', {})
    source_region = meta.get('region', '')

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Supporting — {len(kms_keys)} KMS, {len(vpc_endpoints)} VPC Endpoints, '
        f'{len(acm_certs)} ACM, {len(sns_topics)} SNS, {len(cw_alarms)} CloudWatch Alarms.')

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID',
    }
    t['Parameters']['SGStack'] = {
        'Type': 'String',
        'Default': 'dr-security-groups',
        'Description': 'Security groups stack name',
    }

    t['Resources'] = OrderedDict()
    t['Outputs'] = OrderedDict()

    # ── KMS Keys ──
    for key in kms_keys:
        kc = key.config
        key_id = kc.get('KeyId', 'unnamed')
        logical = safe_logical_id(key_id)
        t['Resources'][logical] = {
            'Type': 'AWS::KMS::Key',
            'Properties': OrderedDict([
                ('Description', kc.get('Description', f'DR key {key_id}')),
                ('Enabled', kc.get('Enabled', True)),
                ('KeyUsage', kc.get('KeyUsage', 'ENCRYPT_DECRYPT')),
                ('Tags', [{'Key': 'Name', 'Value': kc.get('Description', key_id)[:128]},
                          {'Key': 'SourceKeyId', 'Value': key_id}]),
            ]),
        }
        t['Outputs'][f'{logical}Arn'] = {
            'Value': {'Fn::GetAtt': [logical, 'Arn']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    # ── VPC Endpoints ──
    for vpce in vpc_endpoints:
        vc = vpce.config
        vpce_type = vc.get('VpcEndpointType', 'Gateway')
        service_name = vc.get('ServiceName', '')
        if vpce_type == 'GatewayLoadBalancer':
            continue
        logical = safe_logical_id(service_name.split('.')[-1] if '.' in service_name else vpce.resource_id)

        props = OrderedDict()
        if source_region and source_region in service_name:
            props['ServiceName'] = {'Fn::Sub': service_name.replace(source_region, '${AWS::Region}')}
        else:
            props['ServiceName'] = service_name
        props['VpcId'] = {'Ref': 'VpcId'}
        props['VpcEndpointType'] = vpce_type
        if vpce_type == 'Interface':
            props['PrivateDnsEnabled'] = vc.get('PrivateDnsEnabled', True)
            sg_refs = []
            for sg_id in (vc.get('GroupId') or []):
                if sg_id in sg_id_to_logical:
                    sg_refs.append({'Fn::ImportValue': {
                        'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'}})
            if sg_refs:
                props['SecurityGroupIds'] = sg_refs
        props['Tags'] = [{'Key': 'Name', 'Value': f'DR-{service_name.split(".")[-1]}'}]
        t['Resources'][logical] = {'Type': 'AWS::EC2::VPCEndpoint', 'Properties': props}

    # ── ACM Certificates ──
    for cert in acm_certs:
        cc = cert.config
        domain = cc.get('DomainName', '')
        if not domain:
            continue
        logical = safe_logical_id(domain.replace('*', 'wildcard').replace('.', ''))
        t['Resources'][logical] = {
            'Type': 'AWS::CertificateManager::Certificate',
            'Properties': OrderedDict([
                ('DomainName', domain),
                ('ValidationMethod', 'DNS'),
                ('Tags', [{'Key': 'Name', 'Value': domain},
                          {'Key': 'NOTE', 'Value': 'Must re-issue and validate DNS in DR'}]),
            ]),
        }

    # ── SNS Topics ──
    for topic in sns_topics:
        tc = topic.config
        topic_name = tc.get('TopicName', 'unnamed')
        logical = safe_logical_id(topic_name)
        t['Resources'][logical] = {
            'Type': 'AWS::SNS::Topic',
            'Properties': OrderedDict([
                ('TopicName', topic_name),
                ('DisplayName', tc.get('DisplayName', topic_name)),
            ]),
        }

    # ── CloudWatch Alarms ──
    for alarm in cw_alarms:
        ac = alarm.config
        alarm_name = ac.get('AlarmName', 'unnamed')
        logical = safe_logical_id(alarm_name)
        props = OrderedDict()
        props['AlarmName'] = alarm_name
        if ac.get('AlarmDescription'):
            props['AlarmDescription'] = ac['AlarmDescription']
        props['MetricName'] = ac.get('MetricName', '')
        props['Namespace'] = ac.get('Namespace', '')
        props['Statistic'] = ac.get('Statistic', 'Average')
        props['Period'] = ac.get('Period', 300)
        props['EvaluationPeriods'] = ac.get('EvaluationPeriods', 1)
        props['Threshold'] = ac.get('Threshold', 0)
        props['ComparisonOperator'] = ac.get('ComparisonOperator', 'GreaterThanThreshold')
        t['Resources'][logical] = {
            'Type': 'AWS::CloudWatch::Alarm',
            'Properties': props,
        }

    return t


# ═══════════════════════════════════════════════════════════════════
# CONNECTIVITY TEMPLATE (TGW, VPN, Customer Gateways)
# ═══════════════════════════════════════════════════════════════════

def generate_connectivity(resources, inventory):
    """Generate connectivity template: TGW, VPN, CGW."""

    tgws = [r for r in resources if r.category == 'Transit Gateways']
    tgw_attachments = [r for r in resources if r.category == 'Transit Gateway Attachments']
    cgws = [r for r in resources if r.category == 'Customer Gateways']
    vpns = [r for r in resources if r.category == 'VPN Connections']

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Connectivity — {len(tgws)} TGWs, {len(cgws)} CGWs, '
        f'{len(vpns)} VPN Connections.')

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID',
    }

    t['Resources'] = OrderedDict()

    # ── TGWs ──
    for tgw in tgws:
        tc = tgw.config
        tgw_id = tc.get('TransitGatewayId', '')
        logical = safe_logical_id(tgw.name or tgw_id)
        t['Resources'][logical] = {
            'Type': 'AWS::EC2::TransitGateway',
            'Properties': OrderedDict([
                ('AmazonSideAsn', tc.get('AmazonSideAsn', 64512)),
                ('DefaultRouteTableAssociation', tc.get('DefaultRouteTableAssociation', 'enable')),
                ('DefaultRouteTablePropagation', tc.get('DefaultRouteTablePropagation', 'enable')),
                ('DnsSupport', tc.get('DnsSupport', 'enable')),
                ('Tags', [{'Key': 'Name', 'Value': tgw.name or tgw_id},
                          {'Key': 'SourceTgwId', 'Value': tgw_id}]),
            ]),
        }

    # ── Customer Gateways ──
    for cgw in cgws:
        gc = cgw.config
        cgw_id = gc.get('CustomerGatewayId', '')
        logical = safe_logical_id(cgw.name or cgw_id)
        t['Resources'][logical] = {
            'Type': 'AWS::EC2::CustomerGateway',
            'Properties': OrderedDict([
                ('Type', gc.get('Type', 'ipsec.1')),
                ('BgpAsn', gc.get('BgpAsn', 65000)),
                ('IpAddress', gc.get('IpAddress', '')),
                ('Tags', [{'Key': 'Name', 'Value': cgw.name or cgw_id},
                          {'Key': 'SourceCgwId', 'Value': cgw_id}]),
            ]),
        }

    # ── VPN Connections ──
    for vpn in vpns:
        vc = vpn.config
        vpn_id = vc.get('VpnConnectionId', '')
        logical = safe_logical_id(vpn.name or vpn_id)

        props = OrderedDict()
        props['Type'] = vc.get('Type', 'ipsec.1')
        props['StaticRoutesOnly'] = vc.get('StaticRoutesOnly', False)

        # Reference CGW if we created it
        cgw_id = vc.get('CustomerGatewayId', '')
        for cgw in cgws:
            if cgw.config.get('CustomerGatewayId') == cgw_id:
                props['CustomerGatewayId'] = {'Ref': safe_logical_id(cgw.name or cgw_id)}
                break
        else:
            if cgw_id:
                props['CustomerGatewayId'] = cgw_id

        # TGW reference
        tgw_id = vc.get('TransitGatewayId', '')
        for tgw in tgws:
            if tgw.config.get('TransitGatewayId') == tgw_id:
                props['TransitGatewayId'] = {'Ref': safe_logical_id(tgw.name or tgw_id)}
                break
        else:
            if tgw_id:
                props['TransitGatewayId'] = tgw_id

        props['Tags'] = [{'Key': 'Name', 'Value': vpn.name or vpn_id},
                         {'Key': 'SourceVpnId', 'Value': vpn_id}]
        t['Resources'][logical] = {
            'Type': 'AWS::EC2::VPNConnection',
            'Properties': props,
        }

    return t


# ═══════════════════════════════════════════════════════════════════
# GENERIC FALLBACK — for tiers without a bespoke generator
# ═══════════════════════════════════════════════════════════════════

def generate_generic(resources, inventory, sg_id_to_logical):
    """Fallback generator for tiers without specialized handling.

    Emits resources with all non-skip properties. Better than nothing,
    but should be replaced with bespoke handlers as needed.
    """
    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'

    categories = set(r.category for r in resources)
    cat_counts = ', '.join(f'{sum(1 for r in resources if r.category == c)} {c}' for c in sorted(categories))
    t['Description'] = f'DR Supporting — {cat_counts}.'

    t['Parameters'] = OrderedDict()
    t['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID',
    }
    t['Parameters']['SGStack'] = {
        'Type': 'String',
        'Default': 'dr-security-groups',
    }

    t['Resources'] = OrderedDict()

    SKIP = {'Tags', 'Arn', 'Id', 'Status', 'State', 'OwnerId',
            'CreatedTime', 'CreateTime', 'LaunchTime', 'CreationDate'}

    for res in resources:
        logical = safe_logical_id(res.name or res.resource_id)
        props = OrderedDict()
        for key, val in res.config.items():
            if key in SKIP or val is None or val == '' or val == []:
                continue
            if isinstance(val, dict) and not val:
                continue
            props[key] = val
        # Ensure Tags
        tags = res.config.get('Tags', {})
        if isinstance(tags, dict):
            props['Tags'] = [{'Key': 'Name', 'Value': res.name},
                             {'Key': 'SourceId', 'Value': res.resource_id}]
            for k, v in tags.items():
                if k != 'Name' and not k.startswith('aws:'):
                    props['Tags'].append({'Key': k, 'Value': str(v)})

        t['Resources'][logical] = {
            'Type': res.cfn_type,
            'Properties': props,
        }

    return t


# ═══════════════════════════════════════════════════════════════════
# DISPATCH — route a deployment group to the right generator
# ═══════════════════════════════════════════════════════════════════

def generate_group_template(group, inventory, sg_id_to_logical=None):
    """Route a DeploymentGroup to the appropriate generator.

    Args:
        group: DeploymentGroup from dependency_graph
        inventory: full inventory dict
        sg_id_to_logical: SG ID map (populated after security group generation)

    Returns:
        (template_dict, sg_id_to_logical_updated)
    """
    sg_id_to_logical = sg_id_to_logical or {}
    tier = group.name.split('-')[0]  # handle 'security-1', 'security-2' etc.

    if tier == 'foundation':
        return generate_foundation(group.resources, inventory), sg_id_to_logical

    elif tier == 'security':
        template, new_sg_map = generate_security_groups(group.resources, inventory)
        sg_id_to_logical.update(new_sg_map)
        return template, sg_id_to_logical

    elif tier == 'data':
        return generate_data_tier(group.resources, inventory, sg_id_to_logical), sg_id_to_logical

    elif tier in ('dc_compute', 'compute'):
        is_dc = (tier == 'dc_compute')
        return generate_compute(group.resources, inventory, sg_id_to_logical, is_dc=is_dc), sg_id_to_logical

    elif tier == 'network':
        return generate_network(group.resources, inventory, sg_id_to_logical), sg_id_to_logical

    elif tier == 'serverless':
        return generate_serverless(group.resources, inventory), sg_id_to_logical

    elif tier == 'connectivity':
        return generate_connectivity(group.resources, inventory), sg_id_to_logical

    elif tier in ('supporting', 'encryption'):
        # Encryption tier uses supporting generator (KMS keys are there)
        return generate_supporting(group.resources, inventory, sg_id_to_logical), sg_id_to_logical

    else:
        return generate_generic(group.resources, inventory, sg_id_to_logical), sg_id_to_logical
