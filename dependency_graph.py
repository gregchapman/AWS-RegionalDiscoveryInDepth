#!/usr/bin/env python3
"""
Dependency Graph — Graph-driven deployment group partitioning.

Input:  Inventory dict (from deep_discover.py) + CATEGORY_TO_CFN_TYPE mapping
Output: Ordered list of deployment groups, each containing resources assigned
        to a single CloudFormation stack.

The graph is built from:
  1. CFN schema property references (SubnetId references a Subnet, etc.)
  2. Known ordering patterns (VPC → Subnet → SG → Compute)
  3. AD/Directory boot-order detection
  4. LB → Listener → TG → Target chain

Partitioning respects:
  - CFN resource limit (500 per stack, we target 200 for sanity)
  - Logical affinity (all SGs together, all subnets together)
  - Dependency ordering (no group deploys before its dependencies)

Usage:
    from dependency_graph import build_deployment_plan
    plan = build_deployment_plan(inventory, region='us-gov-west-1')
    for group in plan.groups:
        print(group.name, len(group.resources))
"""

import os
import sys
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field

from cfn_immutables import CATEGORY_TO_CFN_TYPE


# ═══════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ResourceNode:
    """A single resource in the dependency graph."""
    resource_id: str
    name: str
    category: str
    cfn_type: str
    config: dict
    tier: str = ''          # assigned during partitioning
    group_name: str = ''    # assigned during partitioning


@dataclass
class DeploymentGroup:
    """A set of resources that deploy together as one CFN stack."""
    name: str
    order: int
    resources: List[ResourceNode] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    pre_steps: List[str] = field(default_factory=list)
    post_steps: List[str] = field(default_factory=list)
    description: str = ''

    @property
    def cfn_types(self) -> Set[str]:
        return {r.cfn_type for r in self.resources}

    @property
    def categories(self) -> Set[str]:
        return {r.category for r in self.resources}


@dataclass
class DeploymentPlan:
    """The complete ordered deployment plan."""
    groups: List[DeploymentGroup] = field(default_factory=list)
    account_id: str = ''
    region: str = ''
    skipped_categories: Set[str] = field(default_factory=set)
    unmapped_categories: Set[str] = field(default_factory=set)

    def group_by_name(self, name: str) -> Optional[DeploymentGroup]:
        for g in self.groups:
            if g.name == name:
                return g
        return None


# ═══════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════

# Maximum resources per CFN stack (hard limit 500, we cap lower)
MAX_RESOURCES_PER_GROUP = 200

# Categories that are assessment-only — not deployable resources
ASSESSMENT_ONLY = {
    'EBS Snapshots', 'AMIs', 'FSx Backups', 'Protected Resources',
    'EBS Volumes', 'S3 Versioning', 'S3 Lifecycle', 'S3 Replication',
    'FSx Data Repository Associations', 'List Stacks', 'List Roles',
    'List Trails', 'List Work Groups', 'List Resolver Rules',
    'List Registries', 'List Instances', 'Describe Db Clusters',
    'Get Lifecycle Policies', 'Backup Vaults', 'Backup Plans',
    'Backup Selections',
}

# Categories requiring manual handling (secrets can't be exported via CFN)
MANUAL_ONLY = {'SSM Parameters', 'Secrets'}

# Known tier ordering — defines which logical tiers must deploy before others.
# Resources are assigned to tiers by category, then tiers are ordered.
# Within a tier, resources deploy as one group (unless split for size).
TIER_ORDER = [
    'foundation',       # VPC, Subnets, Route Tables, DHCP, Internet GW
    'security',         # Security Groups (cross-refs resolved via Ref)
    'encryption',       # KMS keys (must exist before encrypted resources)
    'directories',      # AD/Directory Service (must be healthy before AD-joined)
    'data',             # RDS, Aurora, ElastiCache, FSx
    'dc_compute',       # Domain Controllers (boot before other compute)
    'compute',          # EC2 instances (non-DC)
    'containers',       # ECS, EKS
    'network',          # LBs, Listeners, Target Groups
    'serverless',       # Lambda, EventBridge, Step Functions
    'dns',              # Route53, hosted zones
    'supporting',       # VPC Endpoints, ACM, SNS, CloudWatch, WAF
    'connectivity',     # TGW, VPN, Customer Gateways, Peering
]


# Map each inventory category to its logical tier.
# Categories not listed here get 'supporting' as default.
CATEGORY_TO_TIER = {
    # Foundation
    'VPCs': 'foundation',
    'Subnets': 'foundation',
    'Route Tables': 'foundation',
    'DHCP Options': 'foundation',
    'NAT Gateways': 'foundation',

    # Security
    'Security Groups': 'security',

    # Encryption
    'KMS Keys': 'encryption',

    # Directories
    'Directories': 'directories',

    # Data
    'RDS DB Clusters': 'data',
    'RDS Instances': 'data',
    'RDS DB Subnet Groups': 'data',
    'RDS Parameter Groups': 'data',
    'RDS Cluster Parameter Groups': 'data',
    'RDS Option Groups': 'data',
    'ElastiCache Clusters': 'data',
    'ElastiCache Replication Groups': 'data',
    'FSx File Systems': 'data',
    'DynamoDB Tables': 'data',

    # Compute (DCs detected dynamically, split out during partitioning)
    'EC2 Instances': 'compute',
    'Auto Scaling Groups': 'compute',

    # Containers
    'ECS Clusters': 'containers',
    'ECS Services': 'containers',
    'EKS Clusters': 'containers',

    # Network / Load Balancing
    'Load Balancers': 'network',
    'Target Groups': 'network',
    'Listeners': 'network',
    'Listener Rules': 'network',

    # Serverless
    'Lambda Functions': 'serverless',
    'EventBridge Rules': 'serverless',

    # DNS
    'Hosted Zones': 'dns',

    # Supporting
    'VPC Endpoints': 'supporting',
    'ACM Certificates': 'supporting',
    'SNS Topics': 'supporting',
    'SQS Queues': 'supporting',
    'CloudWatch Alarms': 'supporting',
    'WAF Web ACLs': 'supporting',
    'S3 Buckets': 'supporting',

    # Connectivity
    'Transit Gateways': 'connectivity',
    'Transit Gateway Attachments': 'connectivity',
    'Customer Gateways': 'connectivity',
    'VPN Connections': 'connectivity',
    'VPC Peering Connections': 'connectivity',
}


# ═══════════════════════════════════════════════════════════════════
# EDGE DERIVATION — known dependency patterns
#
# These are the ordering rules the graph uses beyond what the CFN
# schema can tell us. They encode deployment-time dependencies:
# "resource A must exist and be healthy before resource B can deploy."
# ═══════════════════════════════════════════════════════════════════

# Tier-level dependency edges: tier A must deploy before tier B.
# Expressed as (dependency, dependent) pairs.
TIER_EDGES = [
    ('foundation', 'security'),
    ('foundation', 'encryption'),
    ('foundation', 'connectivity'),
    ('security', 'encryption'),
    ('security', 'directories'),
    ('security', 'data'),
    ('security', 'dc_compute'),
    ('security', 'compute'),
    ('security', 'containers'),
    ('security', 'network'),
    ('security', 'serverless'),
    ('security', 'supporting'),
    ('encryption', 'data'),
    ('encryption', 'compute'),
    ('encryption', 'dc_compute'),
    ('directories', 'dc_compute'),
    ('directories', 'data'),        # FSx AD-join needs directory
    ('dc_compute', 'compute'),      # DCs healthy before domain-joined compute
    ('dc_compute', 'data'),         # FSx AD-join needs DCs healthy
    ('foundation', 'data'),
    ('foundation', 'dc_compute'),
    ('foundation', 'compute'),
    ('foundation', 'network'),
    ('foundation', 'serverless'),
    ('foundation', 'dns'),
    ('foundation', 'supporting'),
    ('compute', 'network'),         # Targets must exist before LB wiring
    ('dc_compute', 'network'),
    ('containers', 'network'),
    ('network', 'dns'),             # DNS records point to LB endpoints
]


# ═══════════════════════════════════════════════════════════════════
# DC DETECTION
# ═══════════════════════════════════════════════════════════════════

def is_domain_controller(resource: dict) -> bool:
    """Detect if an EC2 instance is a Domain Controller.

    Uses tag-based detection (CCPM standard: Role=DC) and name heuristics.
    """
    config = resource.get('config', {})
    tags = config.get('Tags', {})
    name = resource.get('name', '').lower()

    # Tag-based (most reliable)
    if tags.get('Role', '').upper() == 'DC':
        return True

    # Name-based heuristics
    if any(pattern in name for pattern in ['/dc1', '/dc2', '-dc1', '-dc2',
                                            'dc01', 'dc02', 'domctrl']):
        return True

    return False


# ═══════════════════════════════════════════════════════════════════
# SHARED TGW DETECTION
# ═══════════════════════════════════════════════════════════════════

def is_shared_resource(resource: dict, account_id: str) -> bool:
    """Detect if a resource is owned by another account (shared via RAM).

    Shared resources cannot be recreated — they're excluded from IaC.
    """
    config = resource.get('config', {})
    owner = str(config.get('OwnerId', ''))
    if owner and owner != str(account_id) and owner != '':
        return True
    return False


# ═══════════════════════════════════════════════════════════════════
# GRAPH BUILDING
# ═══════════════════════════════════════════════════════════════════

def _assign_tier(category: str, resource: dict) -> str:
    """Assign a resource to its deployment tier.

    Special case: EC2 instances detected as DCs go to 'dc_compute'.
    """
    if category == 'EC2 Instances' and is_domain_controller(resource):
        return 'dc_compute'

    return CATEGORY_TO_TIER.get(category, 'supporting')


def _build_resource_nodes(inventory: dict,
                          account_id: str) -> Tuple[List[ResourceNode],
                                                     Set[str], Set[str]]:
    """Convert inventory into ResourceNode list.

    Returns:
        (nodes, skipped_categories, unmapped_categories)
    """
    resources = inventory.get('resources', {})
    nodes = []
    skipped = set()
    unmapped = set()

    for category, items in resources.items():
        # Skip assessment-only and manual categories
        if category in ASSESSMENT_ONLY or category in MANUAL_ONLY:
            skipped.add(category)
            continue

        # Check if we have a CFN type mapping
        cfn_type = CATEGORY_TO_CFN_TYPE.get(category, '')

        if not cfn_type:
            # No mapping — still include in graph for schema-driven generation
            # if we can derive a CFN type later. For now, track as unmapped.
            unmapped.add(category)
            continue

        for item in items:
            # Skip shared resources (owned by another account)
            if is_shared_resource(item, account_id):
                continue

            tier = _assign_tier(category, item)

            node = ResourceNode(
                resource_id=item.get('resource_id', ''),
                name=item.get('name', ''),
                category=category,
                cfn_type=cfn_type,
                config=item.get('config', {}),
                tier=tier,
            )
            nodes.append(node)

    return nodes, skipped, unmapped


# ═══════════════════════════════════════════════════════════════════
# PARTITIONING — Group resources into deployment stacks
# ═══════════════════════════════════════════════════════════════════

def _partition_into_groups(nodes: List[ResourceNode]) -> List[DeploymentGroup]:
    """Partition resource nodes into ordered deployment groups.

    Strategy:
      1. Group nodes by tier
      2. Order tiers using TIER_ORDER
      3. Within a tier, split into multiple groups if > MAX_RESOURCES_PER_GROUP
      4. Compute dependencies between groups from TIER_EDGES

    Returns ordered list of DeploymentGroup objects.
    """
    # Group by tier
    tier_nodes: Dict[str, List[ResourceNode]] = defaultdict(list)
    for node in nodes:
        tier_nodes[node.tier].append(node)

    # Build groups in tier order
    groups = []
    order_counter = 0

    for tier in TIER_ORDER:
        tier_resources = tier_nodes.get(tier, [])
        if not tier_resources:
            continue

        # Split into sub-groups if too large
        chunks = _split_tier(tier, tier_resources)

        for idx, chunk in enumerate(chunks):
            suffix = f'-{idx + 1}' if len(chunks) > 1 else ''
            group_name = f'{tier}{suffix}'

            # Determine dependencies from TIER_EDGES
            deps = []
            for dep_tier, dependent_tier in TIER_EDGES:
                if dependent_tier == tier and dep_tier in tier_nodes:
                    # Find all groups from the dependency tier
                    for g in groups:
                        if g.name.startswith(dep_tier):
                            deps.append(g.name)

            # Assign group to each resource
            for node in chunk:
                node.group_name = group_name

            group = DeploymentGroup(
                name=group_name,
                order=order_counter,
                resources=chunk,
                depends_on=sorted(set(deps)),
                description=_tier_description(tier, chunk),
            )

            # Add pre/post steps for special tiers
            if tier == 'dc_compute':
                group.post_steps = [
                    'Wait for DC instances to pass both status checks (2-5 min)',
                    'Verify AD health: dcdiag /s:localhost via SSM',
                    'Confirm DNS resolution from DC private IPs',
                ]
            elif tier == 'network':
                group.post_steps = [
                    'Register targets with Target Groups (new instance IDs/IPs)',
                    'Verify health checks pass on all target groups',
                ]
            elif tier == 'data':
                group.pre_steps = [
                    'Ensure cross-region snapshot/backup copies are available',
                    'Verify KMS keys exist in DR region for encrypted resources',
                ]
                group.post_steps = [
                    'Verify database connectivity from compute tier',
                ]
            elif tier == 'foundation':
                group.pre_steps = [
                    'Confirm target region AZ availability',
                    'Verify CIDR ranges do not conflict with existing VPCs',
                ]

            groups.append(group)
            order_counter += 1

    return groups


def _split_tier(tier: str, resources: List[ResourceNode]) -> List[List[ResourceNode]]:
    """Split a tier's resources into chunks if exceeding MAX_RESOURCES_PER_GROUP.

    Splitting strategy varies by tier:
      - compute: split by subnet/AZ for geographic affinity
      - security: keep all SGs together (cross-refs need Ref)
      - data: split by engine/service type
      - default: split by category, then arbitrary chunks
    """
    if len(resources) <= MAX_RESOURCES_PER_GROUP:
        return [resources]

    if tier == 'security':
        # SGs should stay together for cross-ref resolution
        # If > 200 SGs, split alphabetically (rare)
        chunks = []
        for i in range(0, len(resources), MAX_RESOURCES_PER_GROUP):
            chunks.append(resources[i:i + MAX_RESOURCES_PER_GROUP])
        return chunks

    if tier == 'compute' or tier == 'dc_compute':
        # Split by subnet for geographic affinity
        by_subnet: Dict[str, List[ResourceNode]] = defaultdict(list)
        for r in resources:
            subnet = r.config.get('SubnetId', 'unknown')
            by_subnet[subnet].append(r)

        chunks = []
        current_chunk = []
        for subnet_id in sorted(by_subnet.keys()):
            subnet_resources = by_subnet[subnet_id]
            if (len(current_chunk) + len(subnet_resources)
                    > MAX_RESOURCES_PER_GROUP):
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = subnet_resources[:]
            else:
                current_chunk.extend(subnet_resources)
        if current_chunk:
            chunks.append(current_chunk)
        return chunks if chunks else [resources]

    # Default: split by category first, then arbitrary
    by_category: Dict[str, List[ResourceNode]] = defaultdict(list)
    for r in resources:
        by_category[r.category].append(r)

    chunks = []
    current_chunk = []
    for cat in sorted(by_category.keys()):
        cat_resources = by_category[cat]
        if (len(current_chunk) + len(cat_resources)
                > MAX_RESOURCES_PER_GROUP):
            if current_chunk:
                chunks.append(current_chunk)
            # If single category exceeds limit, split it
            if len(cat_resources) > MAX_RESOURCES_PER_GROUP:
                for i in range(0, len(cat_resources), MAX_RESOURCES_PER_GROUP):
                    chunks.append(cat_resources[i:i + MAX_RESOURCES_PER_GROUP])
            else:
                current_chunk = cat_resources[:]
        else:
            current_chunk.extend(cat_resources)
    if current_chunk:
        chunks.append(current_chunk)
    return chunks if chunks else [resources]


def _tier_description(tier: str, resources: List[ResourceNode]) -> str:
    """Generate a human-readable description for a deployment group."""
    categories = defaultdict(int)
    for r in resources:
        categories[r.category] += 1

    parts = [f'{count} {cat}' for cat, count in
             sorted(categories.items(), key=lambda x: -x[1])]
    summary = ', '.join(parts[:4])
    if len(parts) > 4:
        summary += f' (+{len(parts) - 4} more)'

    tier_labels = {
        'foundation': 'Foundation — VPC, Subnets, Routing, NAT',
        'security': 'Security Groups — cross-references resolved via Ref',
        'encryption': 'Encryption — KMS keys for encrypted resources',
        'directories': 'Directory Services — AD/domain infrastructure',
        'data': 'Data Tier — databases, caches, file systems',
        'dc_compute': 'Domain Controllers — deploy and verify before compute',
        'compute': 'Compute — EC2 instances',
        'containers': 'Containers — ECS/EKS clusters and services',
        'network': 'Network — Load Balancers, Listeners, Target Groups',
        'serverless': 'Serverless — Lambda, EventBridge',
        'dns': 'DNS — Route53 hosted zones and records',
        'supporting': 'Supporting — VPC Endpoints, ACM, SNS, CloudWatch',
        'connectivity': 'Connectivity — Transit Gateways, VPN, Peering',
    }

    label = tier_labels.get(tier, tier.title())
    return f'{label}. {summary}.'


# ═══════════════════════════════════════════════════════════════════
# CROSS-GROUP REFERENCE DETECTION
#
# After partitioning, determine which resource IDs need to be
# exported by one group and imported by another.
# ═══════════════════════════════════════════════════════════════════

# Config fields that reference other resources by ID
REFERENCE_FIELDS = {
    'VpcId', 'SubnetId', 'GroupId', 'SecurityGroups',
    'SubnetIds', 'SecurityGroupIds', 'KmsKeyId', 'KmsKeyArn',
    'TargetGroupArn', 'LoadBalancerArn', 'LoadBalancerArns',
    'CustomerGatewayId', 'TransitGatewayId', 'VpnGatewayId',
    'DBSubnetGroupName', 'DBParameterGroupName',
    'DBClusterParameterGroupName', 'OptionGroupName',
    'DBClusterIdentifier', 'DirectoryId',
}


def compute_cross_group_refs(plan: DeploymentPlan) -> Dict[str, Set[str]]:
    """Determine which resource IDs must be exported by each group.

    Returns: {group_name: set of resource_ids that must be !ImportValue'd}
    """
    # Build index: resource_id -> group_name
    id_to_group: Dict[str, str] = {}
    for group in plan.groups:
        for node in group.resources:
            id_to_group[node.resource_id] = group.name

    # For each resource, check if its config references a resource in a
    # different group
    exports_needed: Dict[str, Set[str]] = defaultdict(set)

    for group in plan.groups:
        for node in group.resources:
            _scan_refs(node.config, node.group_name,
                       id_to_group, exports_needed)

    return dict(exports_needed)


def _scan_refs(config: dict, current_group: str,
               id_to_group: Dict[str, str],
               exports_needed: Dict[str, Set[str]]):
    """Recursively scan config for resource ID references."""
    for key, value in config.items():
        if key == 'Tags':
            continue
        if isinstance(value, str):
            if value in id_to_group and id_to_group[value] != current_group:
                exports_needed[id_to_group[value]].add(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    if (item in id_to_group and
                            id_to_group[item] != current_group):
                        exports_needed[id_to_group[item]].add(item)
                elif isinstance(item, dict):
                    _scan_refs(item, current_group, id_to_group,
                               exports_needed)
        elif isinstance(value, dict):
            _scan_refs(value, current_group, id_to_group, exports_needed)


# ═══════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════

def build_deployment_plan(inventory: dict,
                          region: str = '') -> DeploymentPlan:
    """Build a complete deployment plan from inventory.

    This is the main entry point. Takes raw inventory from
    deep_discover.py and produces an ordered deployment plan
    with resources grouped, ordered, and annotated.

    Args:
        inventory: dict from deep_discover.py YAML output
        region: AWS region (for display/metadata)

    Returns:
        DeploymentPlan with ordered groups and metadata
    """
    meta = inventory.get('metadata', {})
    account_id = meta.get('account_id', '')
    effective_region = region or meta.get('region', '')

    # Build resource nodes
    nodes, skipped, unmapped = _build_resource_nodes(inventory, account_id)

    # Partition into deployment groups
    groups = _partition_into_groups(nodes)

    plan = DeploymentPlan(
        groups=groups,
        account_id=account_id,
        region=effective_region,
        skipped_categories=skipped,
        unmapped_categories=unmapped,
    )

    return plan


def print_plan_summary(plan: DeploymentPlan):
    """Print a human-readable summary of the deployment plan."""
    total = sum(len(g.resources) for g in plan.groups)
    print(f"\nDeployment Plan — {plan.region} (account {plan.account_id})")
    print(f"{'═' * 60}")
    print(f"  Groups: {len(plan.groups)}")
    print(f"  Total resources: {total}")
    print()

    print(f"  {'#':<4} {'Group':<20} {'Resources':<12} {'Dependencies'}")
    print(f"  {'─' * 56}")
    for g in plan.groups:
        deps = ', '.join(g.depends_on[:3])
        if len(g.depends_on) > 3:
            deps += f' (+{len(g.depends_on) - 3})'
        print(f"  {g.order:<4} {g.name:<20} {len(g.resources):<12} {deps}")

    if plan.skipped_categories:
        print(f"\n  Skipped (assessment/manual): "
              f"{', '.join(sorted(plan.skipped_categories)[:5])}")
        if len(plan.skipped_categories) > 5:
            print(f"    (+{len(plan.skipped_categories) - 5} more)")

    if plan.unmapped_categories:
        print(f"\n  Unmapped (no CFN type): "
              f"{', '.join(sorted(plan.unmapped_categories))}")

    print(f"{'═' * 60}")


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import argparse
    import yaml
    import glob

    parser = argparse.ArgumentParser(
        description='Dependency Graph — Build deployment plan from inventory.')
    parser.add_argument('--input', required=True,
                        help='Path to inventory YAML or run directory')
    args = parser.parse_args()

    # Find inventory file
    input_path = args.input
    if os.path.isdir(input_path):
        matches = glob.glob(os.path.join(input_path, 'inventory-*.yaml'))
        if not matches:
            print(f"ERROR: No inventory-*.yaml found in {input_path}")
            sys.exit(1)
        input_path = matches[0]

    with open(input_path, 'r') as f:
        inventory = yaml.safe_load(f)

    plan = build_deployment_plan(inventory)
    print_plan_summary(plan)

    # Show cross-group references
    refs = compute_cross_group_refs(plan)
    if refs:
        print(f"\nCross-group exports needed:")
        for group_name, ids in sorted(refs.items()):
            print(f"  {group_name}: {len(ids)} exports")
