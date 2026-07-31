#!/usr/bin/env python3
"""
IaC Blueprint — Transforms a discovery inventory into deployable
CloudFormation templates.

Reads the YAML inventory produced by deep_discover.py (via the discover.py
pipeline) and generates a set of ordered CFN templates that reproduce the
inventoried resources. Each template gets a matching .md documentation file.

Two modes:
  - import: Templates match current state exactly (for CFN resource import
    or environment cloning)
  - dr: Region-specific values are parameterized (AMIs, snapshots, subnets,
    certs, endpoints) for disaster recovery deployment

Filtering:
  - exclude.yaml: Skip resources matching tag patterns (e.g., CCPM-managed)
  - include.yaml: Force-include resources (overrides exclude)
  - Both files are optional; if absent, all resources are included

Usage:
    python3 iac_blueprint.py --input output/acme-prod/us-east-1/20260505-151053/
    python3 iac_blueprint.py --input output/acme-prod/us-east-1/20260505-151053/ --mode dr

Output:
    <input-path>/iac-templates/
      ├── 01-security-groups.yaml + .md
      ├── 02-data-tier.yaml + .md
      ├── 03-compute-tier.yaml + .md
      ├── 03b-supporting-services.yaml + .md
      ├── 04-network-tier.yaml + .md
      ├── 05-serverless-tier.yaml + .md
      └── manual-steps.md
"""

import yaml
import os
import sys
import re
import fnmatch
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional
from collections import OrderedDict


# ═══════════════════════════════════════════════════════════════════
# YAML helpers — preserve key order in output
# ═══════════════════════════════════════════════════════════════════

def ordered_dict_representer(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items())

yaml.add_representer(OrderedDict, ordered_dict_representer)


def cfn_str(val):
    """Ensure a value is a string for CFN."""
    if val is None:
        return ''
    return str(val)


def safe_logical_id(name: str) -> str:
    """Convert a resource name/ID to a valid CFN logical ID.
    CFN logical IDs must be alphanumeric only.
    """
    # Remove common prefixes
    clean = name.replace('sg-', 'sg').replace('vpc-', 'vpc')
    # Replace non-alphanumeric with nothing
    clean = re.sub(r'[^a-zA-Z0-9]', '', clean)
    # Ensure it starts with a letter
    if clean and not clean[0].isalpha():
        clean = 'R' + clean
    return clean or 'Unknown'


# ═══════════════════════════════════════════════════════════════════
# FILTERS — Include/Exclude based on external YAML files
# ═══════════════════════════════════════════════════════════════════

def load_filter_file(filepath: str) -> List[dict]:
    """Load a filter file (include.yaml or exclude.yaml).

    Each entry is a dict with 'Key' and 'Value' (supports wildcards).
    Returns empty list if file doesn't exist.
    """
    if not filepath or not os.path.isfile(filepath):
        return []
    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def resource_matches_filter(resource: dict, filter_rules: List[dict]) -> bool:
    """Check if a resource matches ANY rule in a filter list.

    Each rule has 'Key' and 'Value'. Value supports fnmatch wildcards.
    Matches against the resource's Tags dict.
    """
    if not filter_rules:
        return False

    config = resource.get('config', {})
    tags = config.get('Tags', {})

    for rule in filter_rules:
        key = rule.get('Key', '')
        pattern = rule.get('Value', '')
        if not key:
            continue

        # Check in Tags
        tag_val = tags.get(key, '')
        if tag_val and fnmatch.fnmatch(tag_val, pattern):
            return True

        # Also check top-level config fields (for resources without tags)
        config_val = config.get(key, '')
        if isinstance(config_val, str) and fnmatch.fnmatch(config_val, pattern):
            return True

        # Check resource name
        if key == 'Name' and fnmatch.fnmatch(resource.get('name', ''), pattern):
            return True

    return False


def should_include_resource(resource: dict,
                            include_rules: List[dict],
                            exclude_rules: List[dict]) -> bool:
    """Determine if a resource should be included in template generation.

    Precedence:
    1. Matches include → always include (overrides exclude)
    2. Matches exclude and NOT include → skip
    3. Both empty → include everything
    4. Include empty → include everything except exclude matches
    """
    matches_include = resource_matches_filter(resource, include_rules)
    matches_exclude = resource_matches_filter(resource, exclude_rules)

    # Rule 1: include overrides exclude
    if matches_include:
        return True

    # Rule 2: exclude without include match → skip
    if matches_exclude:
        return False

    # Rule 3 & 4: not matched by either → include
    return True


# ═══════════════════════════════════════════════════════════════════
# CFN RESOURCE TYPE MAPPING
#
# Maps inventory category names to CFN resource types and defines
# which inventory config fields map to CFN properties vs parameters.
# ═══════════════════════════════════════════════════════════════════

# Fields that are always region-specific and become parameters
REGION_SPECIFIC_FIELDS = {
    'ImageId', 'SubnetId', 'VpcId', 'KmsKeyId', 'CertificateArn',
    'TargetGroupArn', 'LoadBalancerArn', 'SecurityGroups', 'SecurityGroupIds',
    'DBSnapshotIdentifier', 'HostedZoneId', 'DomainName',
}

# Maps inventory categories to their CFN resource type and field mappings
# Format: category -> {cfn_type, id_field, properties: {cfn_prop: inventory_field}, params: [fields that become parameters]}
CFN_TYPE_MAP = {
    # ── Foundation (deploy first) ──
    'VPCs': {
        'cfn_type': 'AWS::EC2::VPC',
        'id_field': 'VpcId',
        'properties': {
            'CidrBlock': 'CidrBlock',
            'EnableDnsSupport': 'EnableDnsSupport',
            'EnableDnsHostnames': 'EnableDnsHostnames',
        },
        'params': {},
    },
    'Subnets': {
        'cfn_type': 'AWS::EC2::Subnet',
        'id_field': 'SubnetId',
        'properties': {
            'CidrBlock': 'CidrBlock',
            'AvailabilityZone': 'AvailabilityZone',
            'MapPublicIpOnLaunch': 'MapPublicIpOnLaunch',
        },
        'params': {
            'VpcId': {'type': 'AWS::EC2::VPC::Id', 'source': 'VpcId',
                      'description': 'VPC to create subnet in'},
        },
    },
    'Route Tables': {
        'cfn_type': 'AWS::EC2::RouteTable',
        'id_field': 'RouteTableId',
        'properties': {},
        'params': {
            'VpcId': {'type': 'AWS::EC2::VPC::Id', 'source': 'VpcId',
                      'description': 'VPC for this route table'},
        },
    },
    'DHCP Options': {
        'cfn_type': 'AWS::EC2::DHCPOptions',
        'id_field': 'DhcpOptionsId',
        'properties': {
            'DomainName': 'domain-name',
            'DomainNameServers': 'domain-name-servers',
            'NtpServers': 'ntp-servers',
            'NetbiosNameServers': 'netbios-name-servers',
            'NetbiosNodeType': 'netbios-node-type',
        },
        'params': {},
        'note': 'DNS server IPs must be updated to DR DC addresses. Boot-order dependency.',
    },
    # ── Compute ──
    'EC2 Instances': {
        'cfn_type': 'AWS::EC2::Instance',
        'id_field': 'InstanceId',
        'properties': {
            'InstanceType': 'InstanceType',
            'KeyName': 'KeyName',
        },
        'params': {
            'ImageId': {'type': 'AWS::EC2::Image::Id', 'source': 'ImageId',
                        'description': 'AMI ID in target region'},
            'SubnetId': {'type': 'AWS::EC2::Subnet::Id', 'source': 'SubnetId',
                         'description': 'Target subnet'},
            'SecurityGroupIds': {'type': 'List<AWS::EC2::SecurityGroup::Id>', 'source': 'SecurityGroups',
                                 'description': 'Security group IDs'},
        },
    },
    'Auto Scaling Groups': {
        'cfn_type': 'AWS::AutoScaling::AutoScalingGroup',
        'id_field': 'AutoScalingGroupName',
        'properties': {
            'AutoScalingGroupName': 'AutoScalingGroupName',
            'MinSize': 'MinSize',
            'MaxSize': 'MaxSize',
            'DesiredCapacity': 'DesiredCapacity',
            'HealthCheckType': 'HealthCheckType',
            'HealthCheckGracePeriod': 'HealthCheckGracePeriod',
        },
        'params': {
            'VPCZoneIdentifier': {'type': 'CommaDelimitedList', 'source': 'VPCZoneIdentifier',
                                   'description': 'Subnet IDs (comma-separated)'},
            'LaunchTemplateId': {'type': 'String', 'source': 'LaunchTemplate.LaunchTemplateId',
                                  'description': 'Launch template ID'},
        },
    },
    # ── Containers ──
    'ECS Clusters': {
        'cfn_type': 'AWS::ECS::Cluster',
        'id_field': 'ClusterArn',
        'properties': {
            'ClusterName': 'ClusterName',
        },
        'params': {},
    },
    'ECS Services': {
        'cfn_type': 'AWS::ECS::Service',
        'id_field': 'ServiceArn',
        'properties': {
            'ServiceName': 'ServiceName',
            'DesiredCount': 'DesiredCount',
            'LaunchType': 'LaunchType',
        },
        'params': {
            'Cluster': {'type': 'String', 'source': 'ClusterArn',
                        'description': 'ECS cluster ARN'},
            'TaskDefinition': {'type': 'String', 'source': 'TaskDefinition',
                               'description': 'Task definition ARN'},
            'Subnets': {'type': 'CommaDelimitedList', 'source': None,
                        'description': 'Subnet IDs for awsvpc networking'},
            'SecurityGroups': {'type': 'CommaDelimitedList', 'source': None,
                               'description': 'Security group IDs'},
        },
    },
    'EKS Clusters': {
        'cfn_type': 'AWS::EKS::Cluster',
        'id_field': 'ClusterName',
        'properties': {
            'Name': 'ClusterName',
            'Version': 'Version',
        },
        'params': {
            'RoleArn': {'type': 'String', 'source': 'RoleArn',
                        'description': 'IAM role ARN for the cluster'},
            'SubnetIds': {'type': 'CommaDelimitedList', 'source': None,
                          'description': 'Subnet IDs for cluster networking'},
            'SecurityGroupIds': {'type': 'CommaDelimitedList', 'source': None,
                                 'description': 'Security group IDs'},
        },
    },
    # ── Serverless ──
    'Lambda Functions': {
        'cfn_type': 'AWS::Lambda::Function',
        'id_field': 'FunctionName',
        'properties': {
            'FunctionName': 'FunctionName',
            'Runtime': 'Runtime',
            'Handler': 'Handler',
            'MemorySize': 'MemorySize',
            'Timeout': 'Timeout',
        },
        'params': {
            'Role': {'type': 'String', 'source': 'Role',
                     'description': 'IAM role ARN'},
            'CodeS3Bucket': {'type': 'String', 'source': None,
                             'description': 'S3 bucket with deployment package'},
            'CodeS3Key': {'type': 'String', 'source': None,
                          'description': 'S3 key for deployment package'},
        },
    },
    'Step Functions': {
        'cfn_type': 'AWS::StepFunctions::StateMachine',
        'id_field': 'stateMachineArn',
        'properties': {
            'StateMachineName': 'name',
            'StateMachineType': 'type',
        },
        'params': {
            'RoleArn': {'type': 'String', 'source': None,
                        'description': 'IAM role ARN for state machine execution'},
            'DefinitionS3Location': {'type': 'String', 'source': None,
                                      'description': 'S3 URI for state machine definition JSON'},
        },
    },
    'EventBridge Rules': {
        'cfn_type': 'AWS::Events::Rule',
        'id_field': 'Name',
        'properties': {
            'Name': 'Name',
            'State': 'State',
            'ScheduleExpression': 'ScheduleExpression',
            'Description': 'Description',
        },
        'params': {},
    },
    # ── Data ──
    'RDS Instances': {
        'cfn_type': 'AWS::RDS::DBInstance',
        'id_field': 'DBInstanceIdentifier',
        'properties': {
            'DBInstanceClass': 'DBInstanceClass',
            'Engine': 'Engine',
            'EngineVersion': 'EngineVersion',
            'AllocatedStorage': 'AllocatedStorage',
            'StorageType': 'StorageType',
            'StorageEncrypted': 'StorageEncrypted',
            'MultiAZ': 'MultiAZ',
            'PubliclyAccessible': 'PubliclyAccessible',
            'BackupRetentionPeriod': 'BackupRetentionPeriod',
        },
        'params': {
            'DBSnapshotIdentifier': {'type': 'String', 'source': None,
                                      'description': 'Snapshot ID to restore from'},
            'VPCSecurityGroups': {'type': 'CommaDelimitedList', 'source': None,
                                  'description': 'Security group IDs'},
            'DBSubnetGroupName': {'type': 'String', 'source': None,
                                   'description': 'DB subnet group name'},
            'KmsKeyId': {'type': 'String', 'source': 'KmsKeyId',
                         'description': 'KMS key ARN for encryption'},
        },
    },
    'ElastiCache Clusters': {
        'cfn_type': 'AWS::ElastiCache::CacheCluster',
        'id_field': 'CacheClusterId',
        'properties': {
            'Engine': 'Engine',
            'EngineVersion': 'EngineVersion',
            'CacheNodeType': 'CacheNodeType',
            'NumCacheNodes': 'NumCacheNodes',
        },
        'params': {
            'CacheSubnetGroupName': {'type': 'String', 'source': None,
                                      'description': 'Cache subnet group name'},
            'VpcSecurityGroupIds': {'type': 'CommaDelimitedList', 'source': None,
                                    'description': 'Security group IDs'},
        },
    },
    'ElastiCache Replication Groups': {
        'cfn_type': 'AWS::ElastiCache::ReplicationGroup',
        'id_field': 'ReplicationGroupId',
        'properties': {
            'ReplicationGroupDescription': 'Description',
            'AutomaticFailoverEnabled': 'AutomaticFailover',
            'MultiAZEnabled': 'MultiAZ',
            'CacheNodeType': 'CacheNodeType',
            'Engine': 'Engine',
            'EngineVersion': 'EngineVersion',
            'NumCacheClusters': 'MemberClusters',
            'AtRestEncryptionEnabled': 'AtRestEncryptionEnabled',
            'TransitEncryptionEnabled': 'TransitEncryptionEnabled',
        },
        'params': {
            'CacheSubnetGroupName': {'type': 'String', 'source': None,
                                      'description': 'Cache subnet group name in DR'},
            'SecurityGroupIds': {'type': 'CommaDelimitedList', 'source': None,
                                  'description': 'Security group IDs'},
        },
    },
    'FSx File Systems': {
        'cfn_type': 'AWS::FSx::FileSystem',
        'id_field': 'FileSystemId',
        'properties': {
            'FileSystemType': 'FileSystemType',
            'StorageCapacity': 'StorageCapacity',
            'StorageType': 'StorageType',
        },
        'params': {
            'SubnetIds': {'type': 'CommaDelimitedList', 'source': 'SubnetIds',
                          'description': 'Subnet IDs in DR region'},
            'SecurityGroupIds': {'type': 'CommaDelimitedList', 'source': None,
                                  'description': 'Security group IDs in DR'},
            'KmsKeyId': {'type': 'String', 'source': 'KmsKeyId',
                          'description': 'KMS key ARN for encryption in DR'},
            'BackupId': {'type': 'String', 'source': None,
                          'description': 'FSx backup ID to restore from (cross-region copy)'},
            'ActiveDirectoryId': {'type': 'String', 'source': 'ActiveDirectoryId',
                                   'description': 'AWS Managed AD directory ID in DR (Windows type)'},
        },
        'note': 'Restore from cross-region backup copy. DCs must be running first (AD join). Match throughput and storage capacity.',
    },
    'DynamoDB Tables': {
        'cfn_type': 'AWS::DynamoDB::Table',
        'id_field': 'TableName',
        'properties': {
            'TableName': 'TableName',
            'BillingMode': 'BillingMode',
        },
        'params': {},
    },
    # ── Networking ──
    'Classic Load Balancers': {
        'cfn_type': 'AWS::ElasticLoadBalancing::LoadBalancer',
        'id_field': 'LoadBalancerName',
        'properties': {
            'LoadBalancerName': 'LoadBalancerName',
            'Scheme': 'Scheme',
        },
        'params': {
            'Subnets': {'type': 'CommaDelimitedList', 'source': 'Subnets',
                        'description': 'Subnet IDs'},
            'SecurityGroups': {'type': 'CommaDelimitedList', 'source': 'SecurityGroups',
                               'description': 'Security group IDs'},
        },
    },
    'Load Balancers': {
        'cfn_type': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
        'id_field': 'LoadBalancerName',
        'properties': {
            'Name': 'LoadBalancerName',
            'Type': 'Type',
            'Scheme': 'Scheme',
        },
        'params': {
            'Subnets': {'type': 'CommaDelimitedList', 'source': 'Subnets',
                        'description': 'Subnet IDs'},
            'SecurityGroups': {'type': 'CommaDelimitedList', 'source': 'SecurityGroups',
                               'description': 'Security group IDs'},
        },
    },
    'Target Groups': {
        'cfn_type': 'AWS::ElasticLoadBalancingV2::TargetGroup',
        'id_field': 'TargetGroupName',
        'properties': {
            'Name': 'TargetGroupName',
            'Protocol': 'Protocol',
            'Port': 'Port',
            'TargetType': 'TargetType',
            'HealthCheckProtocol': 'HealthCheckProtocol',
            'HealthCheckPath': 'HealthCheckPath',
        },
        'params': {
            'VpcId': {'type': 'AWS::EC2::VPC::Id', 'source': 'VpcId',
                      'description': 'VPC ID'},
        },
    },
    'NAT Gateways': {
        'cfn_type': 'AWS::EC2::NatGateway',
        'id_field': 'NatGatewayId',
        'properties': {},
        'params': {
            'SubnetId': {'type': 'AWS::EC2::Subnet::Id', 'source': 'SubnetId',
                         'description': 'Public subnet for NAT gateway'},
            'AllocationId': {'type': 'String', 'source': None,
                             'description': 'Elastic IP allocation ID'},
        },
    },
    'VPC Endpoints': {
        'cfn_type': 'AWS::EC2::VPCEndpoint',
        'id_field': 'VpcEndpointId',
        'properties': {
            'ServiceName': 'ServiceName',
            'VpcEndpointType': 'VpcEndpointType',
        },
        'params': {
            'VpcId': {'type': 'AWS::EC2::VPC::Id', 'source': 'VpcId',
                      'description': 'VPC ID'},
        },
    },
    'VPC Peering Connections': {
        'cfn_type': 'AWS::EC2::VPCPeeringConnection',
        'id_field': 'VpcPeeringConnectionId',
        'properties': {
            'RequesterVpcInfo_VpcId': 'RequesterVpcInfo.VpcId',
            'AccepterVpcInfo_VpcId': 'AccepterVpcInfo.VpcId',
        },
        'params': {
            'VpcId': {'type': 'AWS::EC2::VPC::Id', 'source': 'RequesterVpcInfo_VpcId',
                      'description': 'Requester VPC ID'},
            'PeerVpcId': {'type': 'AWS::EC2::VPC::Id', 'source': 'AccepterVpcInfo_VpcId',
                          'description': 'Peer VPC ID'},
            'PeerOwnerId': {'type': 'String', 'source': 'AccepterVpcInfo_OwnerId',
                             'description': 'Peer account ID'},
            'PeerRegion': {'type': 'String', 'source': 'AccepterVpcInfo_Region',
                            'description': 'Peer VPC region'},
        },
    },
    'Hosted Zones': {
        'cfn_type': 'AWS::Route53::HostedZone',
        'id_field': 'Id',
        'properties': {
            'Name': 'Name',
        },
        'params': {},
    },
    # ── Identity & Directory ──
    'Directories': {
        'cfn_type': 'AWS::DirectoryService::MicrosoftAD',
        'id_field': 'DirectoryId',
        'properties': {
            'Name': 'Name',
            'ShortName': 'ShortName',
            'Edition': 'Edition',
            'Type': 'Type',
        },
        'params': {
            'VpcId': {'type': 'AWS::EC2::VPC::Id', 'source': None,
                      'description': 'VPC for directory'},
            'SubnetIds': {'type': 'CommaDelimitedList', 'source': None,
                          'description': 'Two subnet IDs in different AZs'},
            'Password': {'type': 'String', 'source': None,
                         'description': 'Directory admin password (NoEcho)'},
        },
    },
    # ── Messaging & Integration ──
    'SNS Topics': {
        'cfn_type': 'AWS::SNS::Topic',
        'id_field': 'TopicName',
        'properties': {
            'TopicName': 'TopicName',
            'DisplayName': 'DisplayName',
        },
        'params': {},
    },
    'SQS Queues': {
        'cfn_type': 'AWS::SQS::Queue',
        'id_field': 'QueueName',
        'properties': {
            'QueueName': 'QueueName',
            'VisibilityTimeout': 'VisibilityTimeout',
            'MessageRetentionPeriod': 'MessageRetentionPeriod',
        },
        'params': {},
    },
    # ── Security & Encryption ──
    'KMS Keys': {
        'cfn_type': 'AWS::KMS::Key',
        'id_field': 'KeyId',
        'properties': {
            'Description': 'Description',
            'Enabled': 'Enabled',
            'KeyUsage': 'KeyUsage',
        },
        'params': {},
    },
    'ACM Certificates': {
        'cfn_type': 'AWS::CertificateManager::Certificate',
        'id_field': 'CertificateArn',
        'properties': {
            'DomainName': 'DomainName',
            'ValidationMethod': 'ValidationMethod',
        },
        'params': {},
    },
    'WAF Web ACLs': {
        'cfn_type': 'AWS::WAFv2::WebACL',
        'id_field': 'Name',
        'properties': {
            'Name': 'Name',
            'Scope': 'Scope',
        },
        'params': {},
    },
    # ── Storage ──
    'S3 Buckets': {
        'cfn_type': 'AWS::S3::Bucket',
        'id_field': 'Name',
        'properties': {
            'BucketName': 'Name',
        },
        'params': {},
    },
    # ── Monitoring ──
    'CloudWatch Alarms': {
        'cfn_type': 'AWS::CloudWatch::Alarm',
        'id_field': 'AlarmName',
        'properties': {
            'AlarmName': 'AlarmName',
            'AlarmDescription': 'AlarmDescription',
            'Namespace': 'Namespace',
            'MetricName': 'MetricName',
            'Statistic': 'Statistic',
            'Period': 'Period',
            'EvaluationPeriods': 'EvaluationPeriods',
            'Threshold': 'Threshold',
            'ComparisonOperator': 'ComparisonOperator',
        },
        'params': {},
    },
    # ── API ──
    'API Gateways': {
        'cfn_type': 'AWS::ApiGatewayV2::Api',
        'id_field': 'ApiId',
        'properties': {
            'Name': 'Name',
            'ProtocolType': 'ProtocolType',
            'Description': 'Description',
        },
        'params': {},
    },
    # ── Data (Aurora Clusters) ──
    'RDS DB Clusters': {
        'cfn_type': 'AWS::RDS::DBCluster',
        'id_field': 'DBClusterIdentifier',
        'properties': {
            'DBClusterIdentifier': 'DBClusterIdentifier',
            'Engine': 'Engine',
            'EngineVersion': 'EngineVersion',
            'DatabaseName': 'DatabaseName',
            'Port': 'Port',
            'MasterUsername': 'MasterUsername',
            'BackupRetentionPeriod': 'BackupRetentionPeriod',
            'PreferredBackupWindow': 'PreferredBackupWindow',
            'PreferredMaintenanceWindow': 'PreferredMaintenanceWindow',
            'StorageEncrypted': 'StorageEncrypted',
            'DeletionProtection': 'DeletionProtection',
            'CopyTagsToSnapshot': 'CopyTagsToSnapshot',
            'EnableCloudwatchLogsExports': 'EnabledCloudwatchLogsExports',
        },
        'params': {
            'SnapshotIdentifier': {'type': 'String', 'source': None,
                                    'description': 'Cluster snapshot ARN to restore from'},
            'DBSubnetGroupName': {'type': 'String', 'source': 'DBSubnetGroup',
                                   'description': 'DB subnet group name in DR region'},
            'VpcSecurityGroupIds': {'type': 'CommaDelimitedList', 'source': None,
                                    'description': 'Security group IDs'},
            'KmsKeyId': {'type': 'String', 'source': 'KmsKeyId',
                         'description': 'KMS key ARN for encryption in DR region'},
            'DBClusterParameterGroupName': {'type': 'String', 'source': 'DBClusterParameterGroup',
                                             'description': 'Cluster parameter group name'},
        },
    },
    'RDS DB Subnet Groups': {
        'cfn_type': 'AWS::RDS::DBSubnetGroup',
        'id_field': 'DBSubnetGroupName',
        'properties': {
            'DBSubnetGroupName': 'DBSubnetGroupName',
            'DBSubnetGroupDescription': 'DBSubnetGroupDescription',
        },
        'params': {
            'SubnetIds': {'type': 'CommaDelimitedList', 'source': None,
                          'description': 'Subnet IDs in DR region'},
        },
    },
    'RDS Parameter Groups': {
        'cfn_type': 'AWS::RDS::DBParameterGroup',
        'id_field': 'DBParameterGroupName',
        'properties': {
            'DBParameterGroupName': 'DBParameterGroupName',
            'Family': 'DBParameterGroupFamily',
            'Description': 'Description',
        },
        'params': {},
    },
    'RDS Cluster Parameter Groups': {
        'cfn_type': 'AWS::RDS::DBClusterParameterGroup',
        'id_field': 'DBClusterParameterGroupName',
        'properties': {
            'DBClusterParameterGroupName': 'DBClusterParameterGroupName',
            'Family': 'DBParameterGroupFamily',
            'Description': 'Description',
        },
        'params': {},
    },
    'RDS Option Groups': {
        'cfn_type': 'AWS::RDS::OptionGroup',
        'id_field': 'OptionGroupName',
        'properties': {
            'OptionGroupName': 'OptionGroupName',
            'OptionGroupDescription': 'OptionGroupDescription',
            'EngineName': 'EngineName',
            'MajorEngineVersion': 'MajorEngineVersion',
        },
        'params': {},
    },
    # ── Networking (Transit Gateway & VPN) ──
    'Transit Gateways': {
        'cfn_type': 'AWS::EC2::TransitGateway',
        'id_field': 'TransitGatewayId',
        'properties': {
            'AmazonSideAsn': 'AmazonSideAsn',
            'DefaultRouteTableAssociation': 'DefaultRouteTableAssociation',
            'DefaultRouteTablePropagation': 'DefaultRouteTablePropagation',
            'DnsSupport': 'DnsSupport',
        },
        'params': {},
    },
    'Transit Gateway Attachments': {
        'cfn_type': 'AWS::EC2::TransitGatewayAttachment',
        'id_field': 'TransitGatewayAttachmentId',
        'properties': {
            'TransitGatewayId': 'TransitGatewayId',
            'ResourceType': 'ResourceType',
        },
        'params': {
            'VpcId': {'type': 'AWS::EC2::VPC::Id', 'source': 'ResourceId',
                      'description': 'VPC ID to attach (when ResourceType=vpc)'},
            'SubnetIds': {'type': 'CommaDelimitedList', 'source': None,
                          'description': 'Subnet IDs for the attachment'},
        },
    },
    'Customer Gateways': {
        'cfn_type': 'AWS::EC2::CustomerGateway',
        'id_field': 'CustomerGatewayId',
        'properties': {
            'Type': 'Type',
            'BgpAsn': 'BgpAsn',
            'IpAddress': 'IpAddress',
            'DeviceName': 'DeviceName',
        },
        'params': {},
    },
    'VPN Connections': {
        'cfn_type': 'AWS::EC2::VPNConnection',
        'id_field': 'VpnConnectionId',
        'properties': {
            'Type': 'Type',
            'StaticRoutesOnly': 'StaticRoutesOnly',
        },
        'params': {
            'CustomerGatewayId': {'type': 'String', 'source': 'CustomerGatewayId',
                                   'description': 'Customer gateway ID in DR'},
            'TransitGatewayId': {'type': 'String', 'source': 'TransitGatewayId',
                                  'description': 'Transit gateway ID in DR'},
            'VpnGatewayId': {'type': 'String', 'source': 'VpnGatewayId',
                              'description': 'VPN gateway ID in DR (if not using TGW)'},
        },
    },
    'Virtual Private Gateways': {
        'cfn_type': 'AWS::EC2::VPNGateway',
        'id_field': 'VpnGatewayId',
        'properties': {
            'Type': 'Type',
            'AmazonSideAsn': 'AmazonSideAsn',
        },
        'params': {},
    },
    # ── Listeners (ELBv2) ──
    'Listeners': {
        'cfn_type': 'AWS::ElasticLoadBalancingV2::Listener',
        'id_field': 'ListenerArn',
        'properties': {
            'Port': 'Port',
            'Protocol': 'Protocol',
            'SslPolicy': 'SslPolicy',
            'AlpnPolicy': 'AlpnPolicy',
        },
        'params': {
            'LoadBalancerArn': {'type': 'String', 'source': 'LoadBalancerArn',
                                'description': 'Load balancer ARN in DR'},
            'DefaultTargetGroupArn': {'type': 'String', 'source': None,
                                       'description': 'Default target group ARN in DR'},
            'CertificateArn': {'type': 'String', 'source': None,
                                'description': 'ACM certificate ARN in DR region'},
        },
    },
    # ── IAM ──
    'List Roles': {
        'cfn_type': 'AWS::IAM::Role',
        'id_field': 'RoleName',
        'properties': {
            'RoleName': 'RoleName',
            'Description': 'Description',
            'MaxSessionDuration': 'MaxSessionDuration',
            'Path': 'Path',
        },
        'params': {},
    },
    # ── Backup & Lifecycle ──
    'Get Lifecycle Policies': {
        'cfn_type': 'AWS::DLM::LifecyclePolicy',
        'id_field': 'PolicyId',
        'properties': {
            'Description': 'Description',
            'State': 'State',
        },
        'params': {},
    },
    # ── Audit & Compliance ──
    'List Trails': {
        'cfn_type': 'AWS::CloudTrail::Trail',
        'id_field': 'Name',
        'properties': {
            'TrailName': 'Name',
            'IsMultiRegionTrail': 'IsMultiRegionTrail',
        },
        'params': {
            'S3BucketName': {'type': 'String', 'source': None,
                              'description': 'S3 bucket for trail logs in DR'},
        },
    },
    # ── DR Readiness (Backup & Replication) ──
    'Backup Vaults': {
        'cfn_type': 'AWS::Backup::BackupVault',
        'id_field': 'BackupVaultName',
        'properties': {
            'BackupVaultName': 'BackupVaultName',
        },
        'params': {
            'EncryptionKeyArn': {'type': 'String', 'source': 'EncryptionKeyArn',
                                  'description': 'KMS key ARN for vault encryption in DR'},
        },
    },
    'Backup Plans': {
        'cfn_type': 'AWS::Backup::BackupPlan',
        'id_field': 'BackupPlanId',
        'properties': {
            'BackupPlanName': 'BackupPlanName',
        },
        'params': {},
        'note': 'Plan rules (schedule, lifecycle, copy actions) require bespoke generation from plan detail.',
    },
    'Backup Selections': {
        'cfn_type': 'AWS::Backup::BackupSelection',
        'id_field': 'SelectionId',
        'properties': {
            'SelectionName': 'SelectionName',
        },
        'params': {
            'BackupPlanId': {'type': 'String', 'source': 'BackupPlanId',
                              'description': 'Backup plan ID in DR'},
            'IamRoleArn': {'type': 'String', 'source': 'IamRoleArn',
                            'description': 'IAM role ARN for backup service'},
        },
    },
    'S3 Replication': {
        'cfn_type': 'AWS::S3::Bucket',
        'id_field': 'BucketName',
        'properties': {
            'ReplicationConfiguration': 'Rules',
        },
        'params': {},
        'note': 'CRR config lives on the source bucket. Captured for DR gap analysis.',
    },
    'EBS Snapshots': {
        'cfn_type': 'AWS::EC2::Snapshot',
        'id_field': 'SnapshotId',
        'properties': {
            'VolumeId': 'VolumeId',
            'VolumeSize': 'VolumeSize',
            'Encrypted': 'Encrypted',
            'Description': 'Description',
        },
        'params': {
            'KmsKeyId': {'type': 'String', 'source': 'KmsKeyId',
                          'description': 'KMS key for snapshot encryption in DR'},
        },
        'note': 'Snapshots must be copied cross-region for DR. DLM or AWS Backup automates this.',
    },
    'AMIs': {
        'cfn_type': 'AWS::EC2::Image',
        'id_field': 'ImageId',
        'properties': {
            'Name': 'Name',
            'Architecture': 'Architecture',
            'RootDeviceType': 'RootDeviceType',
            'VirtualizationType': 'VirtualizationType',
        },
        'params': {},
        'note': 'AMIs must be copied to DR region. Instance launches depend on AMI availability.',
    },
    'DLM Lifecycle Policies': {
        'cfn_type': 'AWS::DLM::LifecyclePolicy',
        'id_field': 'PolicyId',
        'properties': {
            'Description': 'Description',
            'State': 'State',
            'PolicyType': 'PolicyType',
        },
        'params': {},
        'note': 'Verify cross-region copy rules exist and cover all critical volumes.',
    },
}

# Resources that go to manual-steps.md (secrets, or no CFN path)
NO_CFN_SUPPORT = {
    'SSM Parameters',   # Often contain secrets — manual review needed
    'Secrets',          # Secrets Manager — values can't be exported
}

# Resources handled by bespoke generators — skip in generic/manual-steps routing
BESPOKE_HANDLED = {
    'Security Groups',       # generate_sg_template()
    'EC2 Instances',         # generate_compute_template()
    'RDS Instances',         # generate_data_template()
    'RDS DB Clusters',       # generate_data_template()
    'ElastiCache Clusters',  # generate_data_template()
    'Load Balancers',        # generate_network_template()
    'Target Groups',         # generate_network_template()
    'Listeners',             # generate_network_template()
    'Listener Rules',        # generate_network_template() — informational, actions reference TGs
    'Registered Targets',    # generate_network_template() — informational, target registration
}

# Assessment-only categories — captured for dr_assess.py gap analysis and
# enrichment of other templates, but do NOT generate their own IaC stacks.
# These are either backup/snapshot artifacts (inputs to restore, not deploy targets)
# or diagnostic data about existing configurations.
ASSESSMENT_ONLY = {
    # Backup/snapshot artifacts — inputs to restore-from operations
    'EBS Snapshots',         # Input: snapshot IDs for volume restore
    'AMIs',                  # Input: AMI IDs for instance launch (copied to DR)
    'FSx Backups',           # Input: backup IDs for FSx restore
    'Protected Resources',   # AWS Backup coverage list — gap analysis
    'EBS Volumes',           # Volume-to-instance mapping — snapshot assessment

    # Per-resource config status — feeds DR gap report, not deployable
    'S3 Versioning',         # Per-bucket versioning status
    'S3 Lifecycle',          # Per-bucket lifecycle rules
    'S3 Replication',        # Per-bucket CRR config (or absence thereof)
    'FSx Data Repository Associations',  # Lustre-to-S3 links

    # Platform/catalog data captured by auto-templates
    'List Stacks',           # CloudFormation stacks — we generate new ones, don't clone
    'List Roles',            # IAM roles — complex trust policies need manual review
    'List Trails',           # CloudTrail — typically managed by governance tooling
    'List Work Groups',      # Athena workgroups — default + platform
    'List Resolver Rules',   # Route53 Resolver — may be default rule only
    'List Registries',       # EventBridge schema registry
    'List Instances',        # SSO instances — management plane
    'Describe Db Clusters',  # DocumentDB/Neptune from auto-template (separate from RDS)
    'Get Lifecycle Policies', # DLM from auto-template (duplicate of hand-crafted)
}


def generate_generic_template(category: str, type_config: dict) -> dict:
    """Generate a reusable CFN template for a resource type.

    Returns a template with parameters for each instance-specific value
    and fixed properties from the type config.
    """
    cfn_type = type_config['cfn_type']
    properties = type_config.get('properties', {})
    params = type_config.get('params', {})

    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = f'IaC Blueprint — {category} ({cfn_type})'

    # Parameters section
    template['Parameters'] = OrderedDict()
    template['Parameters']['ResourceName'] = {
        'Type': 'String',
        'Description': f'Name/identifier for this {category} resource',
    }

    # Add parameters for each parameterized field
    for param_name, param_config in params.items():
        param_def = {
            'Type': param_config['type'],
        }
        if param_config.get('description'):
            param_def['Description'] = param_config['description']
        if param_config.get('source'):
            param_def['Description'] = param_def.get('Description', '') + \
                f" (from inventory field: {param_config['source']})"
        template['Parameters'][param_name] = param_def

    # Also add parameters for each fixed property (so they can be overridden)
    for cfn_prop, inv_field in properties.items():
        template['Parameters'][cfn_prop] = {
            'Type': 'String',
            'Description': f'{cfn_prop} (from inventory field: {inv_field})',
        }

    # Resources section — single resource using all parameters
    resource_props = OrderedDict()
    for cfn_prop in properties:
        resource_props[cfn_prop] = {'Ref': cfn_prop}
    for param_name in params:
        resource_props[param_name] = {'Ref': param_name}

    # Tags
    resource_props['Tags'] = [
        {'Key': 'Name', 'Value': {'Ref': 'ResourceName'}},
        {'Key': 'GeneratedBy', 'Value': 'iac_blueprint'},
    ]

    template['Resources'] = OrderedDict()
    template['Resources']['Resource'] = {
        'Type': cfn_type,
        'Properties': resource_props,
    }

    template['Outputs'] = OrderedDict()
    template['Outputs']['ResourceId'] = {
        'Value': {'Ref': 'Resource'},
        'Description': f'{category} resource ID',
    }

    return template


def generate_parameter_file(resource: dict, category: str,
                            type_config: dict) -> dict:
    """Generate a parameter file for a specific resource instance.

    Maps inventory config values to the template's parameter names.
    """
    config = resource.get('config', {})
    properties = type_config.get('properties', {})
    params_config = type_config.get('params', {})
    id_field = type_config.get('id_field', '')

    params = OrderedDict()
    params['ResourceName'] = resource.get('name', config.get(id_field, 'unnamed'))

    # Fixed properties — pull values from inventory
    for cfn_prop, inv_field in properties.items():
        val = config.get(inv_field, '')
        if val is not None and val != '':
            params[cfn_prop] = str(val) if not isinstance(val, (list, dict)) else val

    # Parameterized fields — pull from inventory or mark as REQUIRED
    for param_name, param_config in params_config.items():
        source = param_config.get('source')
        if source:
            val = config.get(source, '')
            if val is not None and val != '':
                params[param_name] = val
            else:
                params[param_name] = f'REQUIRED — provide {param_name}'
        else:
            params[param_name] = f'REQUIRED — provide {param_name}'

    return params


# ═══════════════════════════════════════════════════════════════════
# BESPOKE GENERATORS (complex resource types)
# ═══════════════════════════════════════════════════════════════════


def generate_sg_template(inventory: dict) -> dict:
    """Generate CFN template for all customer security groups.

    Reads every SG from the inventory, filters out excluded ones,
    and produces a CFN template with:
    - Each customer SG as a resource with its exact ingress/egress rules
    - Cross-SG references mapped to Ref (where both SGs are in scope)
    - CIDR-based rules preserved as-is (parameterized VPC CIDR)
    - Named for engineer convenience
    """
    all_sgs = inventory.get('resources', {}).get('Security Groups', [])

    # Separate included vs excluded
    include_rules = inventory.get('_include_rules', [])
    exclude_rules = inventory.get('_exclude_rules', [])
    customer_sgs = [sg for sg in all_sgs
                    if should_include_resource(sg, include_rules, exclude_rules)]
    excluded_sg_ids = {sg['resource_id'] for sg in all_sgs
                       if not should_include_resource(sg, include_rules, exclude_rules)}

    # Build a map of SG ID -> logical name for cross-references
    sg_id_to_logical = {}
    for sg in customer_sgs:
        sg_id = sg['config']['GroupId']
        sg_name = sg['config'].get('GroupName', sg_id)
        logical_id = safe_logical_id(sg_name)
        sg_id_to_logical[sg_id] = logical_id

    # Build template
    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = (
        'DR Security Groups — Auto-generated from primary region inventory. '
        f'Generated: {datetime.now(tz=timezone.utc).isoformat()}. '
        f'{len(customer_sgs)} included SGs (excluded {len(excluded_sg_ids)}).'
    )

    # Parameters
    template['Parameters'] = OrderedDict()
    template['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID',
    }
    template['Parameters']['VpcCidr'] = {
        'Type': 'String',
        'Default': '100.64.46.0/23',
        'Description': 'DR VPC CIDR block — adjust if DR uses different CIDR',
    }

    # Resources
    template['Resources'] = OrderedDict()

    for sg in customer_sgs:
        config = sg['config']
        sg_id = config['GroupId']
        sg_name = config.get('GroupName', 'unnamed')
        logical_id = sg_id_to_logical[sg_id]
        description = config.get('Description', f'DR copy of {sg_name}')

        # Build ingress rules
        ingress_rules = []
        for rule in config.get('IngressRules', []):
            ip_protocol = rule.get('IpProtocol', '-1')
            from_port = rule.get('FromPort', -1)
            to_port = rule.get('ToPort', -1)

            # CIDR-based rules
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                desc = ip_range.get('Description', '')
                ingress_entry = OrderedDict()
                ingress_entry['IpProtocol'] = cfn_str(ip_protocol)
                if from_port is not None and from_port != -1:
                    ingress_entry['FromPort'] = from_port
                if to_port is not None and to_port != -1:
                    ingress_entry['ToPort'] = to_port
                ingress_entry['CidrIp'] = cidr
                if desc:
                    ingress_entry['Description'] = desc
                ingress_rules.append(ingress_entry)

            # SG-to-SG rules
            for sg_pair in rule.get('UserIdGroupPairs', []):
                ref_sg_id = sg_pair.get('GroupId', '')
                desc = sg_pair.get('Description', '')
                ingress_entry = OrderedDict()
                ingress_entry['IpProtocol'] = cfn_str(ip_protocol)
                if from_port is not None and from_port != -1:
                    ingress_entry['FromPort'] = from_port
                if to_port is not None and to_port != -1:
                    ingress_entry['ToPort'] = to_port

                if ref_sg_id == sg_id:
                    # Self-referencing rule — use Ref to self
                    ingress_entry['SourceSecurityGroupId'] = {'Ref': logical_id}
                    if desc:
                        ingress_entry['Description'] = desc
                    ingress_rules.append(ingress_entry)
                elif ref_sg_id in sg_id_to_logical:
                    # Reference another customer SG via Ref
                    ingress_entry['SourceSecurityGroupId'] = {
                        'Ref': sg_id_to_logical[ref_sg_id]
                    }
                    if desc:
                        ingress_entry['Description'] = desc
                    ingress_rules.append(ingress_entry)
                elif ref_sg_id in excluded_sg_ids:
                    # Excluded SG — skip this rule entirely.
                    continue
                else:
                    # Unknown external SG — skip with a warning.
                    # These are SGs outside our inventory (other accounts, etc.)
                    print(f"    WARNING: SG {sg_name} has rule referencing unknown SG {ref_sg_id} — skipped")
                    continue

        # Build the SG resource — separate self-referencing rules
        # CFN can't have a SG reference itself in its own SecurityGroupIngress.
        # Those must be separate AWS::EC2::SecurityGroupIngress resources.
        self_ref_rules = [r for r in ingress_rules
                          if isinstance(r.get('SourceSecurityGroupId'), dict)
                          and r['SourceSecurityGroupId'].get('Ref') == logical_id]
        other_rules = [r for r in ingress_rules if r not in self_ref_rules]

        sg_resource = OrderedDict()
        sg_resource['Type'] = 'AWS::EC2::SecurityGroup'
        sg_resource['Properties'] = OrderedDict()
        sg_resource['Properties']['GroupDescription'] = description[:255]
        sg_resource['Properties']['GroupName'] = f'{sg_name}-DR'
        sg_resource['Properties']['VpcId'] = {'Ref': 'VpcId'}
        if other_rules:
            sg_resource['Properties']['SecurityGroupIngress'] = other_rules
        sg_resource['Properties']['Tags'] = [
            {'Key': 'Name', 'Value': f'{sg_name}-DR'},
            {'Key': 'SourceSG', 'Value': sg_id},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
        ]

        template['Resources'][logical_id] = sg_resource

        # Add self-referencing rules as separate resources
        for idx, self_rule in enumerate(self_ref_rules):
            self_ingress = OrderedDict()
            self_ingress['Type'] = 'AWS::EC2::SecurityGroupIngress'
            props = OrderedDict()
            props['GroupId'] = {'Ref': logical_id}
            props['IpProtocol'] = self_rule['IpProtocol']
            if 'FromPort' in self_rule:
                props['FromPort'] = self_rule['FromPort']
            if 'ToPort' in self_rule:
                props['ToPort'] = self_rule['ToPort']
            props['SourceSecurityGroupId'] = {'Ref': logical_id}
            if 'Description' in self_rule:
                props['Description'] = self_rule['Description']
            self_ingress['Properties'] = props
            template['Resources'][f'{logical_id}SelfRef{idx}'] = self_ingress

    # Outputs — export every SG ID for use by other templates
    template['Outputs'] = OrderedDict()
    for sg in customer_sgs:
        sg_id = sg['config']['GroupId']
        logical_id = sg_id_to_logical[sg_id]
        sg_name = sg['config'].get('GroupName', 'unnamed')
        template['Outputs'][f'{logical_id}Id'] = {
            'Value': {'Ref': logical_id},
            'Description': f'{sg_name} (source: {sg_id})',
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical_id}'}},
        }

    return template, sg_id_to_logical


def generate_compute_template(inventory: dict, sg_id_to_logical: dict) -> dict:
    """Generate CFN template for customer EC2 instances.

    Each instance gets its own AMI parameter. Security groups are
    referenced via Fn::ImportValue from the SG template.
    """
    all_instances = inventory.get('resources', {}).get('EC2 Instances', [])
    include_rules = inventory.get('_include_rules', [])
    exclude_rules = inventory.get('_exclude_rules', [])
    customer_instances = [i for i in all_instances
                          if should_include_resource(i, include_rules, exclude_rules)]

    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = (
        'DR Compute Tier — Auto-generated from primary region inventory. '
        f'{len(customer_instances)} customer instances.'
    )

    # Parameters
    template['Parameters'] = OrderedDict()
    template['Parameters']['SGStack'] = {
        'Type': 'String',
        'Default': 'dr-security-groups',
        'Description': 'Name of the security groups stack',
    }
    template['Parameters']['KeyPairName'] = {
        'Type': 'AWS::EC2::KeyPair::KeyName',
        'Description': 'EC2 key pair for instance access',
    }

    # Collect unique subnets used by customer instances
    subnets_used = set()
    for inst in customer_instances:
        subnet = inst['config'].get('SubnetId', '')
        if subnet:
            subnets_used.add(subnet)

    # Create a subnet parameter for each unique subnet
    subnet_param_map = {}
    for idx, subnet_id in enumerate(sorted(subnets_used), 1):
        param_name = f'Subnet{idx}'
        template['Parameters'][param_name] = {
            'Type': 'AWS::EC2::Subnet::Id',
            'Description': f'DR subnet replacing {subnet_id}',
        }
        subnet_param_map[subnet_id] = param_name

    # Per-instance AMI parameters
    for inst in customer_instances:
        name = inst.get('name', 'unnamed')
        clean_name = safe_logical_id(name)
        template['Parameters'][f'{clean_name}AmiId'] = {
            'Type': 'AWS::EC2::Image::Id',
            'Description': f'AMI for {name} (primary: {inst["config"].get("ImageId", "unknown")})',
        }

    # Resources
    template['Resources'] = OrderedDict()

    for inst in customer_instances:
        config = inst['config']
        name = inst.get('name', 'unnamed')
        logical_id = safe_logical_id(name)
        instance_type = config.get('InstanceType', 't3.medium')
        subnet_id = config.get('SubnetId', '')
        tags = config.get('Tags', {})

        # Map SGs to imports from the SG stack
        sg_refs = []
        for sg_id in config.get('SecurityGroups', []):
            if sg_id in sg_id_to_logical:
                sg_refs.append({
                    'Fn::ImportValue': {
                        'Fn::Sub': f'${{SGStack}}-{sg_id_to_logical[sg_id]}'
                    }
                })
            # Skip excluded SGs

        # Build instance resource
        instance_resource = OrderedDict()
        instance_resource['Type'] = 'AWS::EC2::Instance'
        props = OrderedDict()
        props['InstanceType'] = instance_type
        props['ImageId'] = {'Ref': f'{logical_id}AmiId'}
        props['KeyName'] = {'Ref': 'KeyPairName'}

        if subnet_id in subnet_param_map:
            props['SubnetId'] = {'Ref': subnet_param_map[subnet_id]}

        if sg_refs:
            props['SecurityGroupIds'] = sg_refs

        # Preserve important tags
        cfn_tags = [
            {'Key': 'Name', 'Value': name},
            {'Key': 'SourceInstance', 'Value': config.get('InstanceId', '')},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
        ]
        for key in ['Role', 'DomainJoined', 'OS', 'Backup', 'Zone',
                     'InstallRGSTools', 'InstallBESClient']:
            if key in tags:
                cfn_tags.append({'Key': key, 'Value': tags[key]})
        props['Tags'] = cfn_tags

        instance_resource['Properties'] = props
        template['Resources'][logical_id] = instance_resource

    # Outputs
    template['Outputs'] = OrderedDict()
    for inst in customer_instances:
        name = inst.get('name', 'unnamed')
        logical_id = safe_logical_id(name)
        template['Outputs'][f'{logical_id}Id'] = {
            'Value': {'Ref': logical_id},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical_id}'}},
        }

    return template


def generate_data_template(inventory: dict) -> dict:
    """Generate CFN template for RDS and ElastiCache.

    RDS instances are restored from snapshots (parameterized).
    ElastiCache clusters are created from configuration.
    """
    rds_instances = inventory.get('resources', {}).get('RDS Instances', [])
    cache_clusters = inventory.get('resources', {}).get('ElastiCache', [])

    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = (
        'DR Data Tier — Auto-generated. '
        f'{len(rds_instances)} RDS instances, {len(cache_clusters)} ElastiCache clusters.'
    )

    template['Parameters'] = OrderedDict()
    template['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID',
    }
    template['Parameters']['VpcCidr'] = {
        'Type': 'String',
        'Default': '100.64.46.0/23',
    }
    template['Parameters']['DataSubnet1'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Data subnet AZ1',
    }
    template['Parameters']['DataSubnet2'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Data subnet AZ2',
    }
    template['Parameters']['KmsKeyArn'] = {
        'Type': 'String',
        'Description': 'KMS key ARN for encryption (from foundation stack)',
    }

    # Snapshot parameters for each RDS instance
    for rds in rds_instances:
        db_id = rds['config']['DBInstanceIdentifier']
        param_name = safe_logical_id(db_id) + 'SnapshotId'
        template['Parameters'][param_name] = {
            'Type': 'String',
            'Description': f'Snapshot ID for {db_id} in DR region',
        }

    template['Resources'] = OrderedDict()

    # DB Subnet Group
    template['Resources']['DBSubnetGroup'] = {
        'Type': 'AWS::RDS::DBSubnetGroup',
        'Properties': {
            'DBSubnetGroupDescription': 'DR product database subnets',
            'SubnetIds': [
                {'Ref': 'DataSubnet1'},
                {'Ref': 'DataSubnet2'},
            ],
        },
    }

    # RDS Security Group
    template['Resources']['RdsSecurityGroup'] = {
        'Type': 'AWS::EC2::SecurityGroup',
        'Properties': {
            'GroupDescription': 'RDS access from product subnets',
            'GroupName': 'RdsSecurityGroup-DR',
            'VpcId': {'Ref': 'VpcId'},
            'SecurityGroupIngress': [{
                'IpProtocol': 'tcp',
                'FromPort': 3306,
                'ToPort': 3306,
                'CidrIp': {'Ref': 'VpcCidr'},
                'Description': 'MySQL from VPC',
            }],
        },
    }

    # RDS Instances
    for rds in rds_instances:
        config = rds['config']
        db_id = config['DBInstanceIdentifier']
        logical_id = safe_logical_id(db_id)
        snapshot_param = logical_id + 'SnapshotId'

        template['Resources'][logical_id] = {
            'Type': 'AWS::RDS::DBInstance',
            'Properties': OrderedDict([
                ('DBInstanceIdentifier', db_id),
                ('DBInstanceClass', config.get('DBInstanceClass', 'db.t3.medium')),
                ('Engine', config.get('Engine', 'mysql')),
                ('DBSnapshotIdentifier', {'Ref': snapshot_param}),
                ('DBSubnetGroupName', {'Ref': 'DBSubnetGroup'}),
                ('VPCSecurityGroups', [{'Ref': 'RdsSecurityGroup'}]),
                ('StorageEncrypted', True),
                ('KmsKeyId', {'Ref': 'KmsKeyArn'}),
                ('MultiAZ', False),
                ('PubliclyAccessible', False),
            ]),
        }

    # ElastiCache Subnet Group
    if cache_clusters:
        template['Resources']['CacheSubnetGroup'] = {
            'Type': 'AWS::ElastiCache::SubnetGroup',
            'Properties': {
                'Description': 'DR product cache subnets',
                'SubnetIds': [
                    {'Ref': 'DataSubnet1'},
                    {'Ref': 'DataSubnet2'},
                ],
            },
        }

        template['Resources']['CacheSecurityGroup'] = {
            'Type': 'AWS::EC2::SecurityGroup',
            'Properties': {
                'GroupDescription': 'ElastiCache access from product subnets',
                'GroupName': 'CacheSecurityGroup-DR',
                'VpcId': {'Ref': 'VpcId'},
                'SecurityGroupIngress': [{
                    'IpProtocol': 'tcp',
                    'FromPort': 6379,
                    'ToPort': 6379,
                    'CidrIp': {'Ref': 'VpcCidr'},
                    'Description': 'Redis/Valkey from VPC',
                }],
            },
        }

        # Deduplicate — group cache nodes into a replication group
        engines = set(c['config'].get('Engine', '') for c in cache_clusters)
        node_type = cache_clusters[0]['config'].get('CacheNodeType', 'cache.t3.medium')
        engine = cache_clusters[0]['config'].get('Engine', 'redis')

        template['Resources']['CacheCluster'] = {
            'Type': 'AWS::ElastiCache::ReplicationGroup',
            'Properties': OrderedDict([
                ('ReplicationGroupDescription', f'DR {engine} cluster'),
                ('Engine', engine),
                ('CacheNodeType', node_type),
                ('NumCacheClusters', len(cache_clusters)),
                ('CacheSubnetGroupName', {'Ref': 'CacheSubnetGroup'}),
                ('SecurityGroupIds', [{'Ref': 'CacheSecurityGroup'}]),
                ('AtRestEncryptionEnabled', True),
                ('TransitEncryptionEnabled', True),
                ('AutomaticFailoverEnabled', len(cache_clusters) > 1),
            ]),
        }

    # Outputs
    template['Outputs'] = OrderedDict()
    for rds in rds_instances:
        db_id = rds['config']['DBInstanceIdentifier']
        logical_id = safe_logical_id(db_id)
        template['Outputs'][f'{logical_id}Endpoint'] = {
            'Value': {'Fn::GetAtt': [logical_id, 'Endpoint.Address']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical_id}Endpoint'}},
        }
    template['Outputs']['RdsSgId'] = {
        'Value': {'Ref': 'RdsSecurityGroup'},
        'Export': {'Name': {'Fn::Sub': '${AWS::StackName}-RdsSgId'}},
    }

    return template


def generate_network_template(inventory: dict) -> dict:
    """Generate CFN template for load balancers, listeners, target groups.

    LBs, listeners, and TGs are created from inventory config.
    Target registrations reference the compute stack outputs.
    ACM cert ARNs are parameterized (from foundation stack).
    """
    all_lbs = inventory.get('resources', {}).get('Load Balancers', [])
    # Exclude GWLB (gateway LBs are infrastructure-managed)
    customer_lbs = [lb for lb in all_lbs
                    if lb['config'].get('Type', '') != 'gateway'
                    and should_include_resource(lb,
                        inventory.get('_include_rules', []),
                        inventory.get('_exclude_rules', []))]

    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = (
        'DR Network Tier — Auto-generated. '
        f'{len(customer_lbs)} load balancers with listeners and target groups.'
    )

    template['Parameters'] = OrderedDict()
    template['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
    }
    template['Parameters']['DmzSubnet1'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'DMZ/public subnet AZ1 for internet-facing LBs',
    }
    template['Parameters']['DmzSubnet2'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'DMZ/public subnet AZ2',
    }
    template['Parameters']['WildcardCertArn'] = {
        'Type': 'String',
        'Default': '',
        'Description': 'Wildcard ACM certificate ARN in DR region (leave empty to skip TLS listeners)',
    }

    template['Conditions'] = OrderedDict()
    template['Conditions']['HasCertificate'] = {
        'Fn::Not': [{'Fn::Equals': [{'Ref': 'WildcardCertArn'}, '']}]
    }
    template['Parameters']['ComputeStack'] = {
        'Type': 'String',
        'Default': 'dr-compute',
        'Description': 'Name of the compute tier stack',
    }

    template['Resources'] = OrderedDict()

    for lb in customer_lbs:
        config = lb['config']
        lb_name = config.get('LoadBalancerName', 'unnamed')
        lb_logical = safe_logical_id(lb_name)
        lb_type = config.get('Type', 'network')
        lb_scheme = config.get('Scheme', 'internet-facing')

        # LB resource
        lb_props = OrderedDict()
        lb_props['Name'] = lb_name
        lb_props['Type'] = lb_type
        lb_props['Scheme'] = lb_scheme
        lb_props['Subnets'] = [{'Ref': 'DmzSubnet1'}, {'Ref': 'DmzSubnet2'}]

        # ALBs need a security group
        if lb_type == 'application':
            sg_logical = f'{lb_logical}SG'
            template['Resources'][sg_logical] = {
                'Type': 'AWS::EC2::SecurityGroup',
                'Properties': {
                    'GroupDescription': f'SG for {lb_name}',
                    'VpcId': {'Ref': 'VpcId'},
                    'SecurityGroupIngress': [
                        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
                         'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS'},
                        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80,
                         'CidrIp': '0.0.0.0/0', 'Description': 'HTTP redirect'},
                    ],
                },
            }
            lb_props['SecurityGroups'] = [{'Ref': sg_logical}]

        template['Resources'][lb_logical] = {
            'Type': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
            'Properties': lb_props,
        }

        # Target Groups
        for tg in config.get('TargetGroups', []):
            tg_name = tg.get('TargetGroupName', 'unnamed')
            tg_logical = safe_logical_id(tg_name)
            tg_props = OrderedDict()
            tg_props['Name'] = tg_name
            tg_props['Protocol'] = tg.get('Protocol', 'TCP') or 'TCP'
            tg_props['Port'] = tg.get('Port', 443) or 443
            tg_props['VpcId'] = {'Ref': 'VpcId'}
            tg_props['TargetType'] = tg.get('TargetType', 'instance')

            # Health check
            hc = tg.get('HealthCheck', {})
            if hc.get('Protocol'):
                tg_props['HealthCheckProtocol'] = hc['Protocol']
            if hc.get('Path'):
                tg_props['HealthCheckPath'] = hc['Path']
            if hc.get('Interval'):
                tg_props['HealthCheckIntervalSeconds'] = hc['Interval']

            # Note: targets are NOT registered here — they reference
            # instance IDs that don't exist yet. Registration happens
            # after compute stack deploys, or via a separate step.

            template['Resources'][tg_logical] = {
                'Type': 'AWS::ElasticLoadBalancingV2::TargetGroup',
                'Properties': tg_props,
            }

        # Listeners
        for listener in config.get('Listeners', []):
            port = listener.get('Port', 443)
            protocol = listener.get('Protocol', 'TCP')
            ln_logical = f'{lb_logical}Listener{port}'

            ln_props = OrderedDict()
            ln_props['LoadBalancerArn'] = {'Ref': lb_logical}
            ln_props['Port'] = port
            ln_props['Protocol'] = protocol

            # TLS/HTTPS listeners need a certificate
            needs_cert = protocol in ('TLS', 'HTTPS')
            if needs_cert and listener.get('CertificateArn'):
                ln_props['Certificates'] = [
                    {'CertificateArn': {'Ref': 'WildcardCertArn'}}
                ]

            # Match listener to the correct target group by port.
            # Strategy: find a TG whose port matches the listener port,
            # or whose protocol matches. Fall back to first TG if no match.
            matched_tg = None
            tgs = config.get('TargetGroups', [])

            # First try: exact port match
            for tg in tgs:
                if tg.get('Port') == port:
                    matched_tg = tg
                    break

            # Second try: look at the listener's default action from inventory
            # The original listener had a default action pointing to a specific TG
            if not matched_tg:
                default_actions = listener.get('DefaultActions', [])
                for action in default_actions:
                    target_arn = action.get('TargetGroupArn', '')
                    # Match by TG ARN suffix (name)
                    for tg in tgs:
                        if tg.get('TargetGroupArn', '') == target_arn:
                            matched_tg = tg
                            break
                    if matched_tg:
                        break

            # Fall back to first TG
            if not matched_tg and tgs:
                matched_tg = tgs[0]

            # HTTP redirect for ALBs
            if protocol == 'HTTP' and lb_type == 'application':
                ln_props['DefaultActions'] = [{
                    'Type': 'redirect',
                    'RedirectConfig': {
                        'Protocol': 'HTTPS',
                        'Port': '443',
                        'StatusCode': 'HTTP_301',
                    },
                }]
            elif matched_tg:
                tg_logical = safe_logical_id(matched_tg.get('TargetGroupName', 'unnamed'))
                ln_props['DefaultActions'] = [{
                    'Type': 'forward',
                    'TargetGroupArn': {'Ref': tg_logical},
                }]
            else:
                # No TG available — skip this listener with a warning
                print(f"    WARNING: Listener {port}/{protocol} on {lb_name} has no target group — skipped")
                continue

            template['Resources'][ln_logical] = {
                'Type': 'AWS::ElasticLoadBalancingV2::Listener',
                'Properties': ln_props,
            }
            # TLS/HTTPS listeners only deploy if a certificate is provided
            if needs_cert:
                template['Resources'][ln_logical]['Condition'] = 'HasCertificate'

    # Outputs
    template['Outputs'] = OrderedDict()
    for lb in customer_lbs:
        lb_name = lb['config'].get('LoadBalancerName', 'unnamed')
        lb_logical = safe_logical_id(lb_name)
        template['Outputs'][f'{lb_logical}DnsName'] = {
            'Value': {'Fn::GetAtt': [lb_logical, 'DNSName']},
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{lb_logical}DnsName'}},
        }

    return template


def generate_serverless_template(inventory: dict) -> dict:
    """Generate CFN template for Lambda, Step Functions, EventBridge, API Gateway.

    Lambda functions get per-function parameters for code location (S3 bucket/key)
    since we can't embed code in CFN. The function configuration (runtime, memory,
    timeout, env vars, VPC config) is captured from the inventory.
    """
    lambdas = inventory.get('resources', {}).get('Lambda Functions', [])
    step_fns = inventory.get('resources', {}).get('Step Functions', [])
    eb_rules = inventory.get('resources', {}).get('EventBridge Rules', [])
    api_gws = inventory.get('resources', {}).get('API Gateways', [])

    # Filter using include/exclude rules
    include_rules = inventory.get('_include_rules', [])
    exclude_rules = inventory.get('_exclude_rules', [])
    lambdas = [r for r in lambdas if should_include_resource(r, include_rules, exclude_rules)]
    step_fns = [r for r in step_fns if should_include_resource(r, include_rules, exclude_rules)]
    eb_rules = [r for r in eb_rules if should_include_resource(r, include_rules, exclude_rules)]
    api_gws = [r for r in api_gws if should_include_resource(r, include_rules, exclude_rules)]

    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = (
        'DR Serverless Tier — Auto-generated. '
        f'{len(lambdas)} Lambda, {len(step_fns)} Step Functions, '
        f'{len(eb_rules)} EventBridge rules, {len(api_gws)} API Gateways.'
    )

    template['Parameters'] = OrderedDict()
    template['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID (for VPC-attached Lambdas)',
    }
    template['Parameters']['LambdaSubnet1'] = {
        'Type': 'String',
        'Default': '',
        'Description': 'Subnet for VPC-attached Lambdas (leave empty if none)',
    }
    template['Parameters']['LambdaSubnet2'] = {
        'Type': 'String',
        'Default': '',
        'Description': 'Second subnet for VPC-attached Lambdas',
    }
    template['Parameters']['LambdaCodeBucket'] = {
        'Type': 'String',
        'Description': 'S3 bucket containing Lambda deployment packages in DR region',
    }

    template['Resources'] = OrderedDict()
    template['Conditions'] = OrderedDict()

    # ─── Lambda Functions ───
    for fn in lambdas:
        config = fn['config']
        fn_name = config.get('FunctionName', 'unnamed')
        logical_id = safe_logical_id(fn_name)

        # Parameter for the S3 key of this function's code
        code_param = f'{logical_id}CodeKey'
        template['Parameters'][code_param] = {
            'Type': 'String',
            'Description': f'S3 key for {fn_name} deployment package',
        }

        # Build the function resource
        fn_props = OrderedDict()
        fn_props['FunctionName'] = fn_name
        fn_props['Runtime'] = config.get('Runtime', 'python3.12')
        fn_props['Handler'] = config.get('Handler', 'index.handler')
        fn_props['Role'] = config.get('Role', '')  # IAM role ARN — global, should work
        fn_props['MemorySize'] = config.get('MemorySize', 128)
        fn_props['Timeout'] = config.get('Timeout', 30)
        fn_props['Architectures'] = config.get('Architectures', ['x86_64'])
        fn_props['Code'] = {
            'S3Bucket': {'Ref': 'LambdaCodeBucket'},
            'S3Key': {'Ref': code_param},
        }

        # Environment variables — preserve but note region-specific values
        env_vars = config.get('Environment', {})
        if env_vars:
            fn_props['Environment'] = {'Variables': env_vars}

        # VPC config if the function was VPC-attached
        vpc_subnets = config.get('VpcSubnetIds', [])
        vpc_sgs = config.get('VpcSecurityGroupIds', [])
        if vpc_subnets:
            fn_props['VpcConfig'] = {
                'SubnetIds': [{'Ref': 'LambdaSubnet1'}, {'Ref': 'LambdaSubnet2'}],
                'SecurityGroupIds': vpc_sgs,  # May need remapping
            }

        fn_props['Tags'] = [
            {'Key': 'Name', 'Value': fn_name},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
        ]

        template['Resources'][logical_id] = {
            'Type': 'AWS::Lambda::Function',
            'Properties': fn_props,
        }

    # ─── Step Functions ───
    for sf in step_fns:
        config = sf['config']
        sf_name = config.get('Name', 'unnamed')
        logical_id = safe_logical_id(sf_name)

        # The definition contains ARNs that are region-specific.
        # We store it as-is — engineer must review and update ARNs.
        definition = config.get('Definition', '{}')

        template['Resources'][logical_id] = {
            'Type': 'AWS::StepFunctions::StateMachine',
            'Properties': OrderedDict([
                ('StateMachineName', sf_name),
                ('RoleArn', config.get('RoleArn', '')),
                ('StateMachineType', config.get('Type', 'STANDARD')),
                ('DefinitionString', definition),
                ('Tags', [
                    {'Key': 'Name', 'Value': sf_name},
                    {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
                    {'Key': 'WARNING', 'Value': 'Definition contains region-specific ARNs — review before deploying'},
                ]),
            ]),
        }

    # ─── EventBridge Rules ───
    for rule in eb_rules:
        config = rule['config']
        rule_name = config.get('Name', 'unnamed')
        logical_id = safe_logical_id(rule_name)

        rule_props = OrderedDict()
        rule_props['Name'] = rule_name
        rule_props['State'] = config.get('State', 'ENABLED')
        if config.get('ScheduleExpression'):
            rule_props['ScheduleExpression'] = config['ScheduleExpression']
        if config.get('EventPattern'):
            rule_props['EventPattern'] = config['EventPattern']
        if config.get('Description'):
            rule_props['Description'] = config['Description']

        template['Resources'][logical_id] = {
            'Type': 'AWS::Events::Rule',
            'Properties': rule_props,
        }

        # Targets — ARNs are region-specific, preserved as-is with a note
        targets = config.get('Targets', [])
        if targets:
            target_resources = []
            for t in targets:
                target_resources.append(OrderedDict([
                    ('Id', t.get('Id', '')),
                    ('Arn', t.get('Arn', '')),  # Region-specific — needs update
                ]))
                if t.get('RoleArn'):
                    target_resources[-1]['RoleArn'] = t['RoleArn']

            # CFN Events::Rule includes targets inline
            template['Resources'][logical_id]['Properties']['Targets'] = target_resources

    # ─── API Gateways ───
    for api in api_gws:
        config = api['config']
        api_name = config.get('Name', config.get('ApiId', 'unnamed'))
        logical_id = safe_logical_id(api_name)
        api_type = api.get('resource_type', '')

        if 'REST' in api_type:
            template['Resources'][logical_id] = {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': OrderedDict([
                    ('Name', api_name),
                    ('Description', config.get('Description', f'DR copy of {api_name}')),
                    ('EndpointConfiguration', config.get('EndpointConfiguration', {'Types': ['REGIONAL']})),
                    ('Tags', [
                        {'Key': 'Name', 'Value': api_name},
                        {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
                        {'Key': 'WARNING', 'Value': 'Resources/methods/integrations not included — deploy API definition separately'},
                    ]),
                ]),
            }
        elif 'HTTP' in api_type:
            template['Resources'][logical_id] = {
                'Type': 'AWS::ApiGatewayV2::Api',
                'Properties': OrderedDict([
                    ('Name', api_name),
                    ('ProtocolType', config.get('ProtocolType', 'HTTP')),
                    ('Description', config.get('Description', f'DR copy of {api_name}')),
                    ('Tags', {'Name': api_name, 'GeneratedBy': 'dr_template_generator'}),
                ]),
            }

    # Outputs
    template['Outputs'] = OrderedDict()
    for fn in lambdas:
        logical_id = safe_logical_id(fn['config'].get('FunctionName', 'unnamed'))
        template['Outputs'][f'{logical_id}Arn'] = {
            'Value': {'Fn::GetAtt': [logical_id, 'Arn']},
        }

    return template


def generate_supporting_template(inventory: dict) -> dict:
    """Generate CFN template for CloudWatch alarms, SNS, SQS, DynamoDB, ACM, WAF.

    These are supporting services that the application depends on.
    """
    alarms = inventory.get('resources', {}).get('CloudWatch Alarms', [])
    sns_topics = inventory.get('resources', {}).get('SNS Topics', [])
    sqs_queues = inventory.get('resources', {}).get('SQS Queues', [])
    dynamodb_tables = inventory.get('resources', {}).get('DynamoDB Tables', [])
    acm_certs = inventory.get('resources', {}).get('ACM Certificates', [])
    waf_acls = inventory.get('resources', {}).get('WAF Web ACLs', [])

    # Filter using include/exclude rules
    include_rules = inventory.get('_include_rules', [])
    exclude_rules = inventory.get('_exclude_rules', [])
    alarms = [r for r in alarms if should_include_resource(r, include_rules, exclude_rules)]
    sns_topics = [r for r in sns_topics if should_include_resource(r, include_rules, exclude_rules)]

    template = OrderedDict()
    template['AWSTemplateFormatVersion'] = '2010-09-09'
    template['Description'] = (
        'DR Supporting Services — Auto-generated. '
        f'{len(alarms)} alarms, {len(sns_topics)} SNS topics, '
        f'{len(sqs_queues)} SQS queues, {len(dynamodb_tables)} DynamoDB tables, '
        f'{len(acm_certs)} ACM certs, {len(waf_acls)} WAF ACLs.'
    )

    template['Parameters'] = OrderedDict()
    template['Parameters']['DomainName'] = {
        'Type': 'String',
        'Default': 'fd1.mspa.n-able.com',
        'Description': 'Domain name for ACM certificates',
    }
    template['Parameters']['HostedZoneId'] = {
        'Type': 'String',
        'Default': '',
        'Description': 'Route 53 hosted zone ID for DNS validation (leave empty to skip ACM)',
    }
    template['Parameters']['VpcId'] = {
        'Type': 'AWS::EC2::VPC::Id',
        'Description': 'DR VPC ID (for WAF associations)',
    }

    template['Resources'] = OrderedDict()

    # ─── ACM Certificates ───
    # Group by unique domain to avoid duplicate cert requests
    seen_domains = set()
    for cert in acm_certs:
        config = cert['config']
        domain = config.get('DomainName', '')
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        logical_id = safe_logical_id(domain.replace('*', 'wildcard'))

        cert_props = OrderedDict()
        cert_props['DomainName'] = domain
        sans = config.get('SubjectAlternativeNames', [])
        if sans and len(sans) > 1:
            cert_props['SubjectAlternativeNames'] = sans
        cert_props['ValidationMethod'] = 'DNS'
        # Only add hosted zone if provided
        cert_props['DomainValidationOptions'] = [{
            'DomainName': domain,
            'HostedZoneId': {'Ref': 'HostedZoneId'},
        }]
        cert_props['Tags'] = [
            {'Key': 'Name', 'Value': domain},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
        ]

        template['Resources'][logical_id] = {
            'Type': 'AWS::CertificateManager::Certificate',
            'Properties': cert_props,
        }

    # ─── SNS Topics ───
    for topic in sns_topics:
        config = topic['config']
        topic_name = config.get('TopicName', 'unnamed')
        logical_id = safe_logical_id(topic_name)

        topic_props = OrderedDict()
        topic_props['TopicName'] = topic_name
        if config.get('DisplayName'):
            topic_props['DisplayName'] = config['DisplayName']
        if config.get('KmsMasterKeyId'):
            topic_props['KmsMasterKeyId'] = config['KmsMasterKeyId']
        topic_props['Tags'] = [
            {'Key': 'Name', 'Value': topic_name},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
        ]

        template['Resources'][logical_id] = {
            'Type': 'AWS::SNS::Topic',
            'Properties': topic_props,
        }

        # Subscriptions
        for idx, sub in enumerate(config.get('Subscriptions', [])):
            if sub.get('SubscriptionArn', '').startswith('arn:'):
                sub_logical = f'{logical_id}Sub{idx}'
                sub_props = OrderedDict()
                sub_props['TopicArn'] = {'Ref': logical_id}
                sub_props['Protocol'] = sub.get('Protocol', 'email')
                sub_props['Endpoint'] = sub.get('Endpoint', '')
                template['Resources'][sub_logical] = {
                    'Type': 'AWS::SNS::Subscription',
                    'Properties': sub_props,
                }

    # ─── SQS Queues ───
    for queue in sqs_queues:
        config = queue['config']
        queue_name = config.get('QueueName', 'unnamed')
        logical_id = safe_logical_id(queue_name)

        queue_props = OrderedDict()
        queue_props['QueueName'] = queue_name
        if config.get('VisibilityTimeout'):
            queue_props['VisibilityTimeout'] = int(config['VisibilityTimeout'])
        if config.get('MessageRetentionPeriod'):
            queue_props['MessageRetentionPeriod'] = int(config['MessageRetentionPeriod'])
        if config.get('DelaySeconds'):
            queue_props['DelaySeconds'] = int(config['DelaySeconds'])
        if config.get('MaximumMessageSize'):
            queue_props['MaximumMessageSize'] = int(config['MaximumMessageSize'])
        if config.get('ReceiveMessageWaitTimeSeconds'):
            queue_props['ReceiveMessageWaitTimeSeconds'] = int(config['ReceiveMessageWaitTimeSeconds'])
        if config.get('FifoQueue') == 'true':
            queue_props['FifoQueue'] = True
        if config.get('ContentBasedDeduplication') == 'true':
            queue_props['ContentBasedDeduplication'] = True
        if config.get('KmsMasterKeyId'):
            queue_props['KmsMasterKeyId'] = config['KmsMasterKeyId']
        # DLQ redrive policy — ARN needs to reference the DR queue
        if config.get('DeadLetterTargetArn'):
            queue_props['Tags'] = [
                {'Key': 'WARNING', 'Value': f'Had DLQ in primary: {config["DeadLetterTargetArn"]}'},
            ]
        queue_props['Tags'] = queue_props.get('Tags', []) + [
            {'Key': 'Name', 'Value': queue_name},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
        ]

        template['Resources'][logical_id] = {
            'Type': 'AWS::SQS::Queue',
            'Properties': queue_props,
        }

    # ─── DynamoDB Tables ───
    for table in dynamodb_tables:
        config = table['config']
        table_name = config.get('TableName', 'unnamed')
        logical_id = safe_logical_id(table_name)

        table_props = OrderedDict()
        table_props['TableName'] = table_name
        table_props['KeySchema'] = config.get('KeySchema', [])
        table_props['AttributeDefinitions'] = config.get('AttributeDefinitions', [])

        billing = config.get('BillingMode', 'PAY_PER_REQUEST')
        table_props['BillingMode'] = billing

        gsis = config.get('GlobalSecondaryIndexes', [])
        if gsis:
            gsi_defs = []
            for gsi in gsis:
                gsi_def = OrderedDict()
                gsi_def['IndexName'] = gsi['IndexName']
                gsi_def['KeySchema'] = gsi['KeySchema']
                gsi_def['Projection'] = {'ProjectionType': 'ALL'}
                gsi_defs.append(gsi_def)
            table_props['GlobalSecondaryIndexes'] = gsi_defs

        table_props['Tags'] = [
            {'Key': 'Name', 'Value': table_name},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
        ]

        template['Resources'][logical_id] = {
            'Type': 'AWS::DynamoDB::Table',
            'Properties': table_props,
        }

    # ─── CloudWatch Alarms ───
    for alarm in alarms:
        config = alarm['config']
        alarm_name = config.get('AlarmName', 'unnamed')
        logical_id = safe_logical_id(alarm_name)

        alarm_props = OrderedDict()
        alarm_props['AlarmName'] = alarm_name
        if config.get('AlarmDescription'):
            alarm_props['AlarmDescription'] = config['AlarmDescription']
        alarm_props['Namespace'] = config.get('Namespace', '')
        alarm_props['MetricName'] = config.get('MetricName', '')
        alarm_props['Statistic'] = config.get('Statistic', 'Average')
        alarm_props['Period'] = config.get('Period', 300)
        alarm_props['EvaluationPeriods'] = config.get('EvaluationPeriods', 1)
        alarm_props['Threshold'] = config.get('Threshold', 0)
        alarm_props['ComparisonOperator'] = config.get('ComparisonOperator', 'GreaterThanThreshold')
        if config.get('TreatMissingData'):
            alarm_props['TreatMissingData'] = config['TreatMissingData']

        # Dimensions — instance IDs etc. are region-specific
        dims = config.get('Dimensions', [])
        if dims:
            alarm_props['Dimensions'] = [
                {'Name': d['Name'], 'Value': d['Value']}
                for d in dims
            ]

        # Actions — SNS ARNs are region-specific
        for action_key in ['AlarmActions', 'OKActions', 'InsufficientDataActions']:
            actions = config.get(action_key, [])
            if actions:
                alarm_props[action_key] = actions  # Engineer must update ARNs

        template['Resources'][logical_id] = {
            'Type': 'AWS::CloudWatch::Alarm',
            'Properties': alarm_props,
        }

    # ─── WAF Web ACLs ───
    for acl in waf_acls:
        config = acl['config']
        acl_name = config.get('Name', 'unnamed')
        logical_id = safe_logical_id(acl_name)

        acl_props = OrderedDict()
        acl_props['Name'] = acl_name
        acl_props['Scope'] = 'REGIONAL'
        acl_props['DefaultAction'] = config.get('DefaultAction', {'Allow': {}})

        # Rules — statements may be truncated in inventory, include what we have
        rules = config.get('Rules', [])
        if rules:
            cfn_rules = []
            for r in rules:
                cfn_rule = OrderedDict()
                cfn_rule['Name'] = r.get('Name', '')
                cfn_rule['Priority'] = r.get('Priority', 0)
                if r.get('Action'):
                    cfn_rule['Action'] = r['Action']
                # Statement was truncated in discovery — tag for review
                cfn_rule['VisibilityConfig'] = {
                    'SampledRequestsEnabled': True,
                    'CloudWatchMetricsEnabled': True,
                    'MetricName': r.get('Name', 'metric'),
                }
                cfn_rules.append(cfn_rule)
            acl_props['Rules'] = cfn_rules

        acl_props['VisibilityConfig'] = {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': acl_name,
        }
        acl_props['Tags'] = [
            {'Key': 'Name', 'Value': acl_name},
            {'Key': 'GeneratedBy', 'Value': 'dr_template_generator'},
            {'Key': 'WARNING', 'Value': 'WAF rule statements may be incomplete — review before deploying'},
        ]

        template['Resources'][logical_id] = {
            'Type': 'AWS::WAFv2::WebACL',
            'Properties': acl_props,
        }

    # Outputs
    template['Outputs'] = OrderedDict()
    for cert_domain in seen_domains:
        logical_id = safe_logical_id(cert_domain.replace('*', 'wildcard'))
        template['Outputs'][f'{logical_id}CertArn'] = {
            'Value': {'Ref': logical_id},
            'Description': f'ACM cert for {cert_domain}',
        }
    for topic in sns_topics:
        logical_id = safe_logical_id(topic['config'].get('TopicName', 'unnamed'))
        template['Outputs'][f'{logical_id}Arn'] = {
            'Value': {'Ref': logical_id},
        }

    return template


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def write_template(template: dict, filepath: str):
    """Write a CFN template as YAML with a header comment."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"# Auto-generated by iac_blueprint.py\n")
        f.write(f"# Generated: {datetime.now(tz=timezone.utc).isoformat()}\n")
        f.write(f"# Review and adjust parameters before deploying.\n")
        f.write(f"# ─────────────────────────────────────────────\n\n")
        yaml.dump(dict(template), f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False)
    print(f"  Written: {filepath}")


def write_template_docs(template: dict, filepath: str, description: str,
                        dependencies: List[str] = None):
    """Write a .md documentation file for a CFN template."""
    with open(filepath, 'w', encoding='utf-8') as f:
        name = os.path.basename(filepath).replace('.md', '.yaml')
        f.write(f"# {name}\n\n")
        f.write(f"{description}\n\n")

        if dependencies:
            f.write("## Dependencies\n\n")
            f.write("Deploy these stacks first:\n")
            for dep in dependencies:
                f.write(f"- `{dep}`\n")
            f.write("\n")

        params = template.get('Parameters', {})
        if params:
            f.write("## Parameters\n\n")
            f.write("| Parameter | Type | Required | Description |\n")
            f.write("|-----------|------|----------|-------------|\n")
            for pname, pconfig in params.items():
                ptype = pconfig.get('Type', 'String')
                has_default = 'Default' in pconfig
                required = "No" if has_default else "**Yes**"
                desc = pconfig.get('Description', '')
                default = pconfig.get('Default', '')
                if has_default and default != '':
                    desc += f" (default: `{default}`)"
                f.write(f"| `{pname}` | {ptype} | {required} | {desc} |\n")
            f.write("\n")

        resources = template.get('Resources', {})
        if resources:
            f.write("## Resources Created\n\n")
            f.write(f"| Logical ID | Type |\n")
            f.write(f"|------------|------|\n")
            for rid, rconfig in resources.items():
                rtype = rconfig.get('Type', 'Unknown')
                f.write(f"| `{rid}` | `{rtype}` |\n")
            f.write(f"\n**Total: {len(resources)} resources**\n")

    print(f"  Docs:    {filepath}")


def write_manual_steps(manual_resources: List[dict], filepath: str):
    """Write manual-steps.md listing resources that can't be CFN-managed."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Manual Steps Required\n\n")
        f.write("These resources were inventoried but cannot be fully reproduced\n")
        f.write("via CloudFormation. Manual action is required.\n\n")

        if not manual_resources:
            f.write("*No manual steps identified.*\n")
            return

        # Group by category
        from collections import defaultdict
        by_category = defaultdict(list)
        for r in manual_resources:
            by_category[r.get('category', 'Other')].append(r)

        for category, resources in sorted(by_category.items()):
            f.write(f"## {category}\n\n")
            for r in resources:
                f.write(f"- **{r.get('name', 'unnamed')}**")
                if r.get('arn'):
                    f.write(f" (`{r['arn']}`)")
                f.write(f"\n  - {r.get('reason', 'No CFN support or requires manual configuration')}\n")
            f.write("\n")

    print(f"  Manual:  {filepath}")


def find_inventory_file(input_dir: str) -> Optional[str]:
    """Find the inventory YAML file in a run directory."""
    import glob
    pattern = os.path.join(input_dir, 'inventory-*.yaml')
    matches = glob.glob(pattern)
    if matches:
        return matches[0]
    return None


def main():
    parser = argparse.ArgumentParser(
        description='IaC Blueprint — Generate CloudFormation templates from inventory.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 iac_blueprint.py --input output/acme-prod/us-east-1/20260505-151053/
  python3 iac_blueprint.py --input output/acme-prod/us-east-1/20260505-151053/ --mode dr

Filter files (optional, placed in the input directory):
  include.yaml — force-include resources matching tag patterns
  exclude.yaml — skip resources matching tag patterns
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

    # Find inventory file
    inventory_path = find_inventory_file(input_dir)
    if not inventory_path:
        print(f"ERROR: No inventory-*.yaml found in {input_dir}")
        sys.exit(1)

    # Load inventory
    print(f"Loading inventory: {inventory_path}")
    with open(inventory_path, 'r', encoding='utf-8') as f:
        inventory = yaml.safe_load(f)

    region = inventory.get('metadata', {}).get('region', 'unknown')
    account = inventory.get('metadata', {}).get('account_id', 'unknown')
    print(f"Account: {account}, Region: {region}")
    print(f"Mode: {args.mode}")

    # Load filter files from input directory
    include_path = os.path.join(input_dir, 'include.yaml')
    exclude_path = os.path.join(input_dir, 'exclude.yaml')
    include_rules = load_filter_file(include_path)
    exclude_rules = load_filter_file(exclude_path)

    if include_rules:
        print(f"Include filter: {len(include_rules)} rules from {include_path}")
    if exclude_rules:
        print(f"Exclude filter: {len(exclude_rules)} rules from {exclude_path}")
    if not include_rules and not exclude_rules:
        print("No filter files — including all resources")

    # Store filters in inventory for generators to access
    inventory['_include_rules'] = include_rules
    inventory['_exclude_rules'] = exclude_rules

    # Output directory inside the run
    output_dir = os.path.join(input_dir, 'iac-templates')
    os.makedirs(output_dir, exist_ok=True)

    # Count resources (applying filters)
    print(f"\nResource breakdown (after filtering):")
    total_included = 0
    total_excluded = 0
    for category, resources in inventory.get('resources', {}).items():
        included = [r for r in resources
                    if should_include_resource(r, include_rules, exclude_rules)]
        excluded_count = len(resources) - len(included)
        if included:
            print(f"  {category:40s} {len(included):5d} included"
                  f"{f' ({excluded_count} excluded)' if excluded_count else ''}")
            total_included += len(included)
        total_excluded += excluded_count
    print(f"\n  Total: {total_included} included, {total_excluded} excluded")

    # Generate templates
    print(f"\nGenerating templates in {output_dir}/...")

    # Track resources that can't be CFN-managed
    manual_resources = []

    # ── Generic template+params generation ──
    # For each category in the inventory that has a CFN_TYPE_MAP entry,
    # generate one template (shared) and one parameter file per resource.
    templates_dir = os.path.join(output_dir, 'templates')
    params_dir = os.path.join(output_dir, 'params')
    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(params_dir, exist_ok=True)

    deploy_commands = []  # For orchestration README

    for category, resources in inventory.get('resources', {}).items():
        if category.startswith('_'):
            continue

        # Filter resources
        included = [r for r in resources
                    if should_include_resource(r, include_rules, exclude_rules)]
        if not included:
            continue

        # Check if this category goes to manual-steps
        if category in NO_CFN_SUPPORT:
            for r in included:
                manual_resources.append({
                    'name': r.get('name', 'unnamed'),
                    'arn': r.get('config', {}).get('Arn', r.get('resource_id', '')),
                    'category': category,
                    'reason': f'{category} — values contain secrets or require manual configuration',
                })
            continue

        # Skip categories handled by bespoke generators (SGs, compute, data, network)
        if category in BESPOKE_HANDLED:
            continue

        # Skip assessment-only categories (snapshots, backups, diagnostic data)
        if category in ASSESSMENT_ONLY:
            continue

        # Check if we have a CFN type mapping
        if category not in CFN_TYPE_MAP:
            # No mapping — add to manual steps with a note
            for r in included:
                manual_resources.append({
                    'name': r.get('name', 'unnamed'),
                    'arn': r.get('config', {}).get('Arn', r.get('resource_id', '')),
                    'category': category,
                    'reason': f'No CFN type mapping defined for {category} — add to CFN_TYPE_MAP to enable',
                })
            continue

        type_config = CFN_TYPE_MAP[category]
        cfn_type = type_config['cfn_type']

        # Generate the shared template for this resource type
        safe_category = re.sub(r'[^a-zA-Z0-9]', '-', category).lower().strip('-')
        template_filename = f'{safe_category}.yaml'
        template = generate_generic_template(category, type_config)
        template_path = os.path.join(templates_dir, template_filename)
        write_template(template, template_path)

        # Generate documentation for this template
        doc_path = os.path.join(templates_dir, f'{safe_category}.md')
        write_template_docs(template, doc_path,
                            f'{category} — {cfn_type}. '
                            f'One template, {len(included)} parameter files.',
                            dependencies=[])

        # Generate parameter files for each resource instance
        category_params_dir = os.path.join(params_dir, safe_category)
        os.makedirs(category_params_dir, exist_ok=True)

        for r in included:
            name = r.get('name', r.get('resource_id', 'unnamed'))
            safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)[:60]
            param_file = generate_parameter_file(r, category, type_config)

            param_filepath = os.path.join(category_params_dir, f'{safe_name}.json')
            with open(param_filepath, 'w', encoding='utf-8') as f:
                import json
                json.dump(param_file, f, indent=2, default=str)

            # Build deploy command
            stack_name = f'iac-{safe_category}-{safe_name}'[:128]
            deploy_commands.append({
                'category': category,
                'stack_name': stack_name,
                'template': f'templates/{template_filename}',
                'params': f'params/{safe_category}/{safe_name}.json',
                'resource_name': name,
            })

        print(f"  {category:40s} 1 template, {len(included)} param files")

    # ── Bespoke generators for complex types ──
    # Security Groups need cross-reference resolution
    all_sgs = inventory.get('resources', {}).get('Security Groups', [])
    if all_sgs:
        sg_included = [sg for sg in all_sgs
                       if should_include_resource(sg, include_rules, exclude_rules)]
        if sg_included:
            sg_template, sg_id_map = generate_sg_template(inventory)
            write_template(sg_template, os.path.join(templates_dir, 'security-groups.yaml'))
            write_template_docs(sg_template, os.path.join(templates_dir, 'security-groups.md'),
                                'Security Groups — Cross-SG references resolved via Ref. '
                                'Deploy this as a single stack (not per-resource).',
                                dependencies=[])
            print(f"  {'Security Groups (bespoke)':40s} 1 consolidated template")

    # ── Write manual steps ──
    write_manual_steps(manual_resources, os.path.join(output_dir, 'manual-steps.md'))

    # ── Write orchestration README ──
    orchestration_path = os.path.join(output_dir, 'DEPLOY.md')
    with open(orchestration_path, 'w', encoding='utf-8') as f:
        f.write("# Deployment Orchestration\n\n")
        f.write(f"Generated: {datetime.now(tz=timezone.utc).isoformat()}\n")
        f.write(f"Source: {inventory_path}\n")
        f.write(f"Account: {account} | Region: {region}\n\n")
        f.write("Deploy in dependency order:\\n\\n")
        f.write("| Phase | Category | Reason |\\n")
        f.write("|-------|----------|--------|\\n")
        f.write("| 1 | VPCs | Foundation |\\n")
        f.write("| 2 | Subnets, Route Tables | Network topology |\\n")
        f.write("| 3 | Security Groups | Referenced by all resources |\\n")
        f.write("| 4 | NAT Gateways, VPC Endpoints, Directories | Network + identity |\\n")
        f.write("| 5 | KMS Keys | Encryption (before data tier) |\\n")
        f.write("| 6 | RDS, ElastiCache, DynamoDB, S3 | Data tier |\\n")
        f.write("| 7 | EC2, ASG, ECS, EKS | Compute |\\n")
        f.write("| 8 | Load Balancers, Target Groups | Traffic routing |\\n")
        f.write("| 9 | Lambda, Step Functions, EventBridge, API GW | Serverless |\\n")
        f.write("| 10 | ACM, WAF, Route53, SNS, SQS, CloudWatch | Supporting |\\n")
        f.write("\\n---\\n\\n")
        f.write("## Security Groups (consolidated stack)\\n\\n```bash\\n")
        f.write("aws cloudformation deploy \\\\\\n")
        f.write("  --template-file templates/security-groups.yaml \\\\\\n")
        f.write("  --stack-name iac-security-groups \\\\\\n")
        f.write("  --parameter-overrides VpcId=<VPC_ID> VpcCidr=<CIDR>\\n```\\n\\n")


        # Group deploy commands by category
        from collections import defaultdict
        by_category = defaultdict(list)
        for cmd in deploy_commands:
            by_category[cmd['category']].append(cmd)

        DEPLOY_ORDER = [
            'VPCs', 'Subnets', 'Route Tables', 'NAT Gateways', 'VPC Endpoints',
            'Directories', 'KMS Keys', 'RDS Instances', 'ElastiCache Clusters',
            'DynamoDB Tables', 'S3 Buckets', 'EC2 Instances', 'Auto Scaling Groups',
            'ECS Clusters', 'ECS Services', 'EKS Clusters', 'Classic Load Balancers',
            'Load Balancers', 'Target Groups', 'Lambda Functions', 'Step Functions',
            'EventBridge Rules', 'API Gateways', 'ACM Certificates', 'WAF Web ACLs',
            'Hosted Zones', 'SNS Topics', 'SQS Queues', 'CloudWatch Alarms',
        ]
        ordered_cats = [c for c in DEPLOY_ORDER if c in by_category] + \
                       [c for c in by_category if c not in DEPLOY_ORDER]
        for cat in ordered_cats:
            cmds = by_category[cat]
            f.write(f"## {cat} ({len(cmds)} resources)\n\n")
            for cmd in cmds:
                f.write(f"### {cmd['resource_name']}\n\n")
                f.write("```bash\n")
                f.write(f"aws cloudformation deploy \\\n")
                f.write(f"  --template-file {cmd['template']} \\\n")
                f.write(f"  --stack-name {cmd['stack_name']} \\\n")
                f.write(f"  --parameter-overrides file://{cmd['params']}\n")
                f.write("```\n\n")

    print(f"  {'Orchestration':40s} DEPLOY.md")

    print(f"\nDone. Output in {output_dir}/")
    print(f"  templates/  — Shared CFN templates (one per resource type)")
    print(f"  params/     — Per-resource parameter files")
    print(f"  DEPLOY.md   — Orchestration commands in deployment order")
    if manual_resources:
        print(f"  manual-steps.md — {len(manual_resources)} resources requiring manual action")


if __name__ == "__main__":
    main()
