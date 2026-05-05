#!/usr/bin/env python3
"""
Graph Discovery — Audience-driven visualization of AWS inventory.

Reads the YAML/JSON inventory produced by deep_discover.py and renders
it as structured markdown tailored to a specific audience. No AWS API
calls — pure data transformation.

Audiences:
    executive    — Abstract, function-grouped, no IDs. Presentation-ready.
    engineering  — Full detail, topology, security posture, anomalies.
    operations   — Recovery-focused, dependency chains, DR notes.

Usage:
    python3 graph_discover.py --input output/inventory-us-gov-west-1.yaml --audience executive
    python3 graph_discover.py --input output/inventory-us-gov-west-1.yaml --audience engineering
    python3 graph_discover.py --input output/inventory-us-gov-west-1.yaml --audience operations
"""

import yaml
import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


# ═══════════════════════════════════════════════════════════════════
# RESOURCE CLASSIFICATION
#
# Every resource gets classified into a tier and a functional group.
# This drives how it's rendered for each audience.
# ═══════════════════════════════════════════════════════════════════

# Tier 1: Workload — things that run your application
# Tier 2: Routing  — things that direct traffic
# Tier 3: Boundary — things that contain other things
# Tier 4: Attached — properties of other resources (SGs, certs, keys)
# Tier 5: Platform — logging, monitoring, compliance (not app traffic)

CATEGORY_TIERS = {
    # Tier 1 — Workload
    'EC2 Instances':                  ('workload', 'compute'),
    'RDS Instances':                  ('workload', 'database'),
    'ElastiCache Clusters':           ('workload', 'cache'),
    'ElastiCache Replication Groups': ('workload', 'cache'),
    'Lambda Functions':               ('workload', 'serverless'),

    # Tier 2 — Routing
    'Load Balancers':         ('routing', 'load_balancing'),
    'Classic Load Balancers': ('routing', 'load_balancing'),
    'Target Groups':          ('routing', 'load_balancing'),
    'NAT Gateways':       ('routing', 'network'),
    'VPC Endpoints':      ('routing', 'network'),
    'Hosted Zones':       ('routing', 'dns'),
    'Transit Gateways':   ('routing', 'network'),
    'Transit Gateway Attachments': ('routing', 'network'),
    'VPC Peering Connections': ('routing', 'network'),

    # Tier 3 — Boundary
    'VPCs':          ('boundary', 'network'),
    'Subnets':       ('boundary', 'network'),
    'Route Tables':  ('boundary', 'network'),

    # Tier 4 — Attached
    'Security Groups':   ('attached', 'security'),
    'ACM Certificates':  ('attached', 'security'),
    'KMS Keys':          ('attached', 'encryption'),
    'SSM Parameters':    ('attached', 'config'),
    'Secrets':           ('attached', 'config'),

    # Tier 5 — Platform
    'CloudWatch Alarms':  ('platform', 'monitoring'),
    'SNS Topics':         ('platform', 'notifications'),
    'WAF Web ACLs':       ('platform', 'security'),
    'EventBridge Rules':  ('platform', 'automation'),
    'S3 Buckets':         ('platform', 'storage'),
}

DEFAULT_TIER = ('platform', 'other')


def classify(category: str) -> Tuple[str, str]:
    """Return (tier, functional_group) for a resource category."""
    return CATEGORY_TIERS.get(category, DEFAULT_TIER)


# ═══════════════════════════════════════════════════════════════════
# INVENTORY ANALYSIS
#
# Build a structured model from the flat inventory. This model is
# what the audience renderers consume.
# ═══════════════════════════════════════════════════════════════════

class InventoryModel:
    """Analyzed inventory with relationships and classifications."""

    def __init__(self, inventory: dict):
        self.meta = inventory.get('metadata', {})
        self.raw_resources = inventory.get('resources', {})

        # Separate known (classified) resources from noise
        # Only categories in CATEGORY_TIERS are "known" — everything else
        # is auto-generated catalog data we don't want in diagrams.
        self.known_categories = {
            cat: res for cat, res in self.raw_resources.items()
            if cat in CATEGORY_TIERS
        }
        self.noise_categories = {
            cat: res for cat, res in self.raw_resources.items()
            if cat not in CATEGORY_TIERS
        }

        # Flat list of all KNOWN resources with their category
        self.all_resources = []
        for category, resources in self.known_categories.items():
            for res in resources:
                res['_category'] = category
                tier, group = classify(category)
                res['_tier'] = tier
                res['_group'] = group
                self.all_resources.append(res)

        # Index by resource_id for relationship lookups
        self.by_id = {}
        for res in self.all_resources:
            rid = res.get('resource_id', '')
            if rid:
                self.by_id[rid] = res

        # Build relationship graph
        self._build_relationships()

        # Detect anomalies
        self.anomalies = self._detect_anomalies()

    def _build_relationships(self):
        """Build parent/child and reference relationships."""
        self.children = defaultdict(list)   # parent_id -> [child resources]
        self.references = defaultdict(list)  # source_id -> [(target_id, rel_type)]

        for res in self.all_resources:
            rid = res.get('resource_id', '')
            config = res.get('config', {})

            # VPC containment (v2 uses VpcId, classic ELB uses VPCId)
            vpc_id = config.get('VpcId', '') or config.get('VPCId', '')
            if vpc_id and vpc_id != rid and vpc_id in self.by_id:
                self.children[vpc_id].append(res)

            # Subnet containment
            subnet_id = config.get('SubnetId', '')
            if subnet_id and subnet_id != rid and subnet_id in self.by_id:
                self.children[subnet_id].append(res)

            # SG references
            sgs = config.get('GroupId', config.get('SecurityGroups', []))
            if isinstance(sgs, list):
                for sg in sgs:
                    if isinstance(sg, str) and sg in self.by_id:
                        self.references[rid].append((sg, 'security_group'))

            # Subnet list references (LBs, etc.)
            subnet_ids = config.get('SubnetIds', [])
            if isinstance(subnet_ids, list):
                for sid in subnet_ids:
                    if isinstance(sid, str) and sid in self.by_id:
                        self.references[rid].append((sid, 'subnet'))

    def _detect_anomalies(self) -> List[dict]:
        """Detect potential misconfigurations and noteworthy patterns."""
        anomalies = []

        for res in self.all_resources:
            config = res.get('config', {})
            category = res.get('_category', '')
            name = res.get('name', '')

            # Lambda not in VPC
            if category == 'Lambda Functions':
                vpc_subnets = config.get('SubnetIds', [])
                vpc_sgs = config.get('SecurityGroupIds', [])
                if not vpc_subnets and not vpc_sgs:
                    anomalies.append({
                        'severity': 'info',
                        'resource': name,
                        'resource_id': res.get('resource_id', ''),
                        'issue': 'Lambda function is NOT attached to a VPC — '
                                 'runs in AWS public network space',
                        'category': 'network_boundary',
                    })

            # SG with 0.0.0.0/0 ingress
            if category == 'Security Groups':
                for rule in config.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        if cidr == '0.0.0.0/0':
                            port = rule.get('FromPort', 'all')
                            anomalies.append({
                                'severity': 'warning',
                                'resource': name,
                                'resource_id': res.get('resource_id', ''),
                                'issue': f'SG allows inbound from 0.0.0.0/0 '
                                         f'on port {port}',
                                'category': 'exposure',
                            })

            # EC2 with public IP
            if category == 'EC2 Instances':
                pub_ip = config.get('PublicIpAddress', '')
                if pub_ip and pub_ip != '' and pub_ip != 'None':
                    anomalies.append({
                        'severity': 'info',
                        'resource': name,
                        'resource_id': res.get('resource_id', ''),
                        'issue': f'Instance has public IP: {pub_ip}',
                        'category': 'exposure',
                    })

            # RDS publicly accessible
            if category == 'RDS Instances':
                if config.get('PubliclyAccessible', False):
                    anomalies.append({
                        'severity': 'critical',
                        'resource': name,
                        'resource_id': res.get('resource_id', ''),
                        'issue': 'RDS instance is publicly accessible',
                        'category': 'exposure',
                    })

                # RDS not encrypted
                if not config.get('StorageEncrypted', False):
                    anomalies.append({
                        'severity': 'warning',
                        'resource': name,
                        'resource_id': res.get('resource_id', ''),
                        'issue': 'RDS storage is NOT encrypted',
                        'category': 'encryption',
                    })

            # RDS no backups
            if category == 'RDS Instances':
                retention = config.get('BackupRetentionPeriod', 0)
                if retention == 0:
                    anomalies.append({
                        'severity': 'warning',
                        'resource': name,
                        'resource_id': res.get('resource_id', ''),
                        'issue': 'RDS backup retention is 0 days',
                        'category': 'resilience',
                    })

        return anomalies

    def by_tier(self, tier: str) -> List[dict]:
        return [r for r in self.all_resources if r['_tier'] == tier]

    def by_group(self, group: str) -> List[dict]:
        return [r for r in self.all_resources if r['_group'] == group]

    def by_category(self, category: str) -> List[dict]:
        return self.known_categories.get(category, [])

    def vpcs(self) -> List[dict]:
        return self.by_category('VPCs')

    def instances_in_vpc(self, vpc_id: str) -> List[dict]:
        return [r for r in self.by_category('EC2 Instances')
                if r.get('config', {}).get('VpcId') == vpc_id]

    def subnets_in_vpc(self, vpc_id: str) -> List[dict]:
        return [r for r in self.by_category('Subnets')
                if r.get('config', {}).get('VpcId') == vpc_id]

    def lbs_in_vpc(self, vpc_id: str) -> List[dict]:
        v2 = [r for r in self.by_category('Load Balancers')
              if r.get('config', {}).get('VpcId') == vpc_id]
        classic = [r for r in self.by_category('Classic Load Balancers')
                   if r.get('config', {}).get('VPCId') == vpc_id]
        return v2 + classic

    def rds_instances(self) -> List[dict]:
        return self.by_category('RDS Instances')

    def rds_in_vpc(self, vpc_id: str) -> List[dict]:
        """Return RDS instances that belong to a specific VPC.
        Cross-references the RDS subnet group subnets with the subnet
        inventory to determine VPC membership.
        """
        # Build a map of subnet_id -> vpc_id from our subnet inventory
        subnet_to_vpc = {}
        for sn in self.by_category('Subnets'):
            sid = sn.get('resource_id', '')
            vid = sn.get('config', {}).get('VpcId', '')
            if sid and vid:
                subnet_to_vpc[sid] = vid

        # For each RDS instance, check its VPC security groups or subnet group
        # RDS VpcSecurityGroups reference SG IDs — we can map SG -> VPC
        sg_to_vpc = {}
        for sg in self.by_category('Security Groups'):
            sgid = sg.get('resource_id', '')
            vid = sg.get('config', {}).get('VpcId', '')
            if sgid and vid:
                sg_to_vpc[sgid] = vid

        results = []
        for db in self.rds_instances():
            cfg = db.get('config', {})
            # Try SG-based VPC detection
            db_sgs = cfg.get('VpcSecurityGroupId', cfg.get('VpcSecurityGroups', []))
            if isinstance(db_sgs, list):
                for sg_id in db_sgs:
                    if isinstance(sg_id, str) and sg_id in sg_to_vpc:
                        if sg_to_vpc[sg_id] == vpc_id:
                            results.append(db)
                            break
                        break  # Found the VPC, just not this one
        return results

    def lambda_functions(self) -> List[dict]:
        return self.by_category('Lambda Functions')

    def resource_counts(self) -> Dict[str, int]:
        return {cat: len(res) for cat, res in self.known_categories.items()}


# ═══════════════════════════════════════════════════════════════════
# MERMAID TOPOLOGY DIAGRAM
#
# Generates a curated Mermaid diagram showing only workload topology:
# Internet → LBs → Compute → Data, grouped inside VPC/subnet boundaries.
# Attached resources (SGs, certs) shown as annotations, not nodes.
# ═══════════════════════════════════════════════════════════════════

def render_mermaid_topology(model: InventoryModel, detailed: bool = False) -> str:
    """Build a curated Mermaid topology diagram.

    Args:
        model: InventoryModel
        detailed: if True, include instance IDs and IPs (engineering).
                  if False, abstract names only (executive).
    """
    lines = []
    w = lines.append

    w("```mermaid")
    w("graph TD")

    # Internet entry point
    w('  Internet(("🌐 Internet"))')
    w("")

    # Internet-facing LBs
    v2_lbs = model.by_category('Load Balancers')
    classic_lbs = model.by_category('Classic Load Balancers')
    lbs = v2_lbs + classic_lbs
    internet_lbs = [lb for lb in lbs
                    if lb.get('config', {}).get('Scheme') == 'internet-facing']
    internal_lbs = [lb for lb in lbs
                    if lb.get('config', {}).get('Scheme') != 'internet-facing']

    for lb in internet_lbs:
        name = lb.get('name', '')
        is_classic = lb.get('_category', '') == 'Classic Load Balancers'
        lb_type = lb.get('config', {}).get('Type', 'LB')
        short = name[:30] if len(name) > 30 else name
        node_id = _safe_mermaid_id(name)
        if is_classic:
            icon = "CLB"
        else:
            icon = "ALB" if lb_type == 'application' else "NLB"
        w(f'  Internet --> {node_id}["{icon}: {short}"]')

    w("")

    # VPCs as subgraphs
    vpcs = model.vpcs()
    for vpc in vpcs:
        vpc_id = vpc.get('resource_id', '')
        vpc_name = vpc.get('name', vpc_id)
        cidr = vpc.get('config', {}).get('CidrBlock', '')
        safe_vpc = _safe_mermaid_id(vpc_id)

        # Skip default VPC if there's a named one
        if vpc.get('config', {}).get('IsDefault') and len(vpcs) > 1:
            continue

        label = f"{vpc_name}" if not detailed else f"{vpc_name} ({cidr})"
        w(f'  subgraph {safe_vpc}["{label}"]')

        # Internal LBs in this VPC
        for lb in internal_lbs:
            lb_vpc = lb.get('config', {}).get('VpcId') or lb.get('config', {}).get('VPCId', '')
            if lb_vpc == vpc_id:
                name = lb.get('name', '')
                short = name[:30] if len(name) > 30 else name
                node_id = _safe_mermaid_id(name)
                is_classic = lb.get('_category', '') == 'Classic Load Balancers'
                lb_type = lb.get('config', {}).get('Type', 'LB')
                if is_classic:
                    icon = "CLB"
                else:
                    icon = "ALB" if lb_type == 'application' else "NLB"
                w(f'    {node_id}["{icon}: {short}"]')

        # EC2 instances in this VPC
        instances = model.instances_in_vpc(vpc_id)
        if instances:
            w(f'    subgraph {safe_vpc}_compute["Compute"]')
            for inst in instances:
                name = inst.get('name', '')
                iid = _safe_mermaid_id(inst.get('resource_id', name))
                if detailed:
                    ip = inst.get('config', {}).get('PrivateIpAddress', '')
                    itype = inst.get('config', {}).get('InstanceType', '')
                    label = f"{name}\\n{itype} | {ip}"
                else:
                    label = name
                w(f'      {iid}["{label}"]')
            w(f'    end')

        # RDS in this VPC (RDS doesn't have VpcId directly, but we show them)
        # We'll put RDS at VPC level since they're in the VPC via subnet groups
        rds = model.rds_instances()
        if rds:
            w(f'    subgraph {safe_vpc}_data["Data Tier"]')
            for db in rds:
                name = db.get('name', '')
                did = _safe_mermaid_id(name)
                cfg = db.get('config', {})
                if detailed:
                    engine = f"{cfg.get('Engine', '')} {cfg.get('EngineVersion', '')}"
                    label = f"{name}\\n{engine}"
                else:
                    label = name
                w(f'      {did}[("{label}")]')
            w(f'    end')

        # ElastiCache
        cache = model.by_category('ElastiCache Clusters')
        if cache:
            for c in cache:
                name = c.get('name', '')
                cid = _safe_mermaid_id(name)
                engine = c.get('config', {}).get('Engine', 'cache')
                nodes = c.get('config', {}).get('NumCacheNodes', '?')
                if detailed:
                    label = f"{name}\\n{engine} ({nodes} nodes)"
                else:
                    label = f"{engine} cache ({nodes} nodes)"
                w(f'    {cid}[("{label}")]')

        w(f'  end')
        w("")

    # Lambda outside VPC
    lambdas_no_vpc = [l for l in model.lambda_functions()
                      if not l.get('config', {}).get('SubnetIds')]
    if lambdas_no_vpc:
        w('  subgraph aws_public["AWS Public (outside VPC)"]')
        for lf in lambdas_no_vpc:
            name = lf.get('name', '')
            short = name[:35] if len(name) > 35 else name
            lid = _safe_mermaid_id(name)
            w(f'    {lid}["λ {short}"]')
        w('  end')
        w("")

    # Draw traffic flow edges: LBs → instances
    # We can't perfectly map TG→instance from inventory alone,
    # so we connect LBs to all instances in the same VPC
    for vpc in vpcs:
        vpc_id = vpc.get('resource_id', '')
        if vpc.get('config', {}).get('IsDefault') and len(vpcs) > 1:
            continue
        vpc_lbs = [lb for lb in lbs
                   if (lb.get('config', {}).get('VpcId') or
                       lb.get('config', {}).get('VPCId', '')) == vpc_id]
        vpc_instances = model.instances_in_vpc(vpc_id)

        for lb in vpc_lbs:
            lb_node = _safe_mermaid_id(lb.get('name', ''))
            for inst in vpc_instances:
                inst_node = _safe_mermaid_id(inst.get('resource_id',
                                                       inst.get('name', '')))
                w(f'  {lb_node} --> {inst_node}')

        # Instances → RDS
        rds = model.rds_instances()
        for inst in vpc_instances:
            inst_node = _safe_mermaid_id(inst.get('resource_id',
                                                   inst.get('name', '')))
            for db in rds:
                db_node = _safe_mermaid_id(db.get('name', ''))
                w(f'  {inst_node} --> {db_node}')

    # Styling
    w("")
    w("  classDef lb fill:#8C4FFF,stroke:#232F3E,color:white")
    w("  classDef compute fill:#ED7100,stroke:#232F3E,color:white")
    w("  classDef data fill:#C925D1,stroke:#232F3E,color:white")
    w("  classDef lambda fill:#ED7100,stroke:#232F3E,color:white")

    # Apply styles
    for lb in lbs:
        w(f"  class {_safe_mermaid_id(lb.get('name', ''))} lb")
    for inst in model.by_category('EC2 Instances'):
        w(f"  class {_safe_mermaid_id(inst.get('resource_id', inst.get('name', '')))} compute")
    for db in model.rds_instances():
        w(f"  class {_safe_mermaid_id(db.get('name', ''))} data")
    for c in model.by_category('ElastiCache Clusters'):
        w(f"  class {_safe_mermaid_id(c.get('name', ''))} data")
    for lf in lambdas_no_vpc:
        w(f"  class {_safe_mermaid_id(lf.get('name', ''))} lambda")

    w("```")
    return '\n'.join(lines)


def _safe_mermaid_id(name: str) -> str:
    """Convert a resource name/ID to a safe Mermaid node ID."""
    import re
    safe = re.sub(r'[^a-zA-Z0-9]', '_', str(name))
    if safe and safe[0].isdigit():
        safe = 'n_' + safe
    return safe or 'unknown'


# ═══════════════════════════════════════════════════════════════════
# DRAW.IO XML WRITER (CONTAINMENT MODEL)
#
# Generates a native .drawio file with:
#   - VPC as a parent container (swimlane)
#   - Subnets as child containers grouped by AZ
#   - Instances inside their subnets
#   - LBs at the top (traffic entry tier)
#   - RDS/cache at the bottom (data tier)
#   - Directional arrows for traffic flow
#   - Lambdas outside VPC in a separate group
#   - AWS Architecture Icons from mxgraph stencils
# ═══════════════════════════════════════════════════════════════════

def render_drawio(model: InventoryModel, filepath: str):
    """Write a draw.io XML file with containment-based layout."""
    import xml.etree.ElementTree as ET

    # ── Styles ──
    VPC_STYLE = (
        'points=[[0,0],[0.25,0],[0.5,0],[0.75,0],[1,0],[1,0.25],[1,0.5],[1,0.75],'
        '[1,1],[0.75,1],[0.5,1],[0.25,1],[0,1],[0,0.75],[0,0.5],[0,0.25]];'
        'outlineConnect=0;gradientColor=none;html=1;whiteSpace=wrap;fontSize=12;'
        'fontStyle=1;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_vpc2;'
        'strokeColor=#8C4FFF;fillColor=none;verticalAlign=top;align=left;'
        'spacingLeft=30;fontColor=#AAB7B8;dashed=0;container=1;pointerEvents=0;'
        'collapsible=0;recursiveResize=0;'
    )
    SUBNET_STYLE = (
        'points=[[0,0],[0.25,0],[0.5,0],[0.75,0],[1,0],[1,0.25],[1,0.5],[1,0.75],'
        '[1,1],[0.75,1],[0.5,1],[0.25,1],[0,1],[0,0.75],[0,0.5],[0,0.25]];'
        'outlineConnect=0;gradientColor=none;html=1;whiteSpace=wrap;fontSize=11;'
        'fontStyle=0;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_subnet;'
        'strokeColor=#7AA116;fillColor=none;verticalAlign=top;align=left;'
        'spacingLeft=30;fontColor=#AAB7B8;dashed=0;container=1;pointerEvents=0;'
        'collapsible=0;recursiveResize=0;'
    )
    TIER_STYLE = (
        'fillColor=none;strokeColor=#5A6C86;dashed=1;verticalAlign=top;'
        'fontStyle=1;fontColor=#5A6C86;whiteSpace=wrap;html=1;container=1;'
        'collapsible=0;recursiveResize=0;'
    )
    EC2_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#ED7100;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.ec2_instance;'
    )
    RDS_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#C925D1;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.rds_instance;'
    )
    CACHE_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#C925D1;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elasticache;'
    )
    ALB_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#8C4FFF;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.application_load_balancer;'
    )
    NLB_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#8C4FFF;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.network_load_balancer;'
    )
    CLB_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#8C4FFF;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.classic_load_balancer;'
    )
    LAMBDA_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#ED7100;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.lambda_function;'
    )
    NAT_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#8C4FFF;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.nat_gateway;'
    )
    INTERNET_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#232F3E;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=12;fontStyle=1;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.internet_gateway;'
    )
    EDGE_STYLE = (
        'edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;'
        'jettySize=auto;html=1;strokeColor=#545B64;strokeWidth=2;'
        'endArrow=blockThin;endFill=1;'
    )
    S = 60  # shape size

    # ── Build XML ──
    root = ET.Element('mxGraphModel')
    for attr, val in [('dx', '1800'), ('dy', '1200'), ('grid', '1'),
                       ('gridSize', '10'), ('guides', '1'), ('tooltips', '1'),
                       ('connect', '1'), ('arrows', '1'), ('fold', '1'),
                       ('page', '1'), ('pageScale', '1'), ('pageWidth', '1600'),
                       ('pageHeight', '1200'), ('math', '0'), ('shadow', '0')]:
        root.set(attr, val)

    graph_root = ET.SubElement(root, 'root')
    ET.SubElement(graph_root, 'mxCell', id='0')
    ET.SubElement(graph_root, 'mxCell', id='1', parent='0')

    cid = [100]  # mutable counter
    id_map = {}  # resource_id -> cell_id string

    def next_id():
        cid[0] += 1
        return str(cid[0])

    def add_cell(parent_id, value, style, x, y, w, h, **extra):
        cell_id = next_id()
        attrs = {'id': cell_id, 'value': value, 'style': style,
                 'vertex': '1', 'parent': parent_id}
        attrs.update(extra)
        cell = ET.SubElement(graph_root, 'mxCell', **attrs)
        geo = ET.SubElement(cell, 'mxGeometry', x=str(x), y=str(y),
                            width=str(w), height=str(h))
        geo.set('as', 'geometry')
        return cell_id

    def add_edge(source_id, target_id, label=''):
        eid = next_id()
        edge = ET.SubElement(graph_root, 'mxCell',
                             id=eid, value=label, style=EDGE_STYLE,
                             edge='1', parent='1',
                             source=source_id, target=target_id)
        geo = ET.SubElement(edge, 'mxGeometry', relative='1')
        geo.set('as', 'geometry')

    # ── Internet gateway ──
    inet_id = add_cell('1', 'Internet', INTERNET_STYLE, 700, 20, S, S)

    # ── Region label ──
    region = model.meta.get('region', 'unknown')
    account = model.meta.get('account_id', '')
    REGION_STYLE = (
        'points=[[0,0],[0.25,0],[0.5,0],[0.75,0],[1,0],[1,0.25],[1,0.5],[1,0.75],'
        '[1,1],[0.75,1],[0.5,1],[0.25,1],[0,1],[0,0.75],[0,0.5],[0,0.25]];'
        'outlineConnect=0;gradientColor=none;html=1;whiteSpace=wrap;fontSize=12;'
        'fontStyle=1;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_region;'
        'strokeColor=#00A4A6;fillColor=none;verticalAlign=top;align=left;'
        'spacingLeft=30;fontColor=#147EBA;dashed=1;container=1;pointerEvents=0;'
        'collapsible=0;recursiveResize=0;'
    )
    AZ_STYLE = (
        'fillColor=#E6F2FF;strokeColor=#147EBA;dashed=1;verticalAlign=top;'
        'fontStyle=1;fontColor=#147EBA;whiteSpace=wrap;html=1;fontSize=11;'
        'container=1;collapsible=0;recursiveResize=0;rounded=1;'
    )

    # ── Process each VPC ──
    vpc_y = 120
    max_vpc_w = 800  # Track widest VPC for right-side label placement
    for vpc in model.vpcs():
        vpc_rid = vpc.get('resource_id', '')
        vpc_cfg = vpc.get('config', {})
        vpc_name = vpc.get('name', vpc_rid)
        cidr = vpc_cfg.get('CidrBlock', '')

        # Skip default VPC if there's a named one and it has no instances
        if vpc_cfg.get('IsDefault') and len(model.vpcs()) > 1:
            if not model.instances_in_vpc(vpc_rid):
                continue

        instances = model.instances_in_vpc(vpc_rid)
        subnets = model.subnets_in_vpc(vpc_rid)
        lbs = model.lbs_in_vpc(vpc_rid)
        nats = [n for n in model.by_category('NAT Gateways')
                if n.get('config', {}).get('VpcId') == vpc_rid]

        # Group instances by AZ
        from collections import defaultdict as _dd
        az_instances = _dd(list)
        for inst in instances:
            az = inst.get('config', {}).get('AvailabilityZone', 'unknown')
            az_instances[az].append(inst)
        sorted_azs = sorted(az_instances.keys())

        # Initial VPC container — calculate sizes FIRST
        num_lbs = len(lbs)
        AZ_W = 200

        # ── Build subnet map: subnet_id → subnet resource ──
        subnet_map = {}  # subnet_id -> subnet resource
        for sn in subnets:
            subnet_map[sn.get('resource_id', '')] = sn

        # ── Determine which subnets are public (LB subnets) ──
        # Collect all subnet IDs referenced by LBs
        lb_subnet_ids = set()
        for lb in lbs:
            lb_cfg = lb.get('config', {})
            lb_subs = lb_cfg.get('Subnets', [])
            if isinstance(lb_subs, list):
                lb_subnet_ids.update(lb_subs)

        # Group subnets by AZ, split into public and private
        az_public_subnets = _dd(list)   # az -> [subnet resources]
        az_private_subnets = _dd(list)  # az -> [subnet resources]
        for sn in subnets:
            cfg = sn.get('config', {})
            az = cfg.get('AvailabilityZone', 'unknown')
            is_public = cfg.get('MapPublicIpOnLaunch', False)
            if is_public:
                az_public_subnets[az].append(sn)
            else:
                az_private_subnets[az].append(sn)

        # ── Group instances by AZ and subnet ──
        az_subnet_instances = _dd(lambda: _dd(list))  # az -> subnet_id -> [instances]
        for inst in instances:
            cfg = inst.get('config', {})
            az = cfg.get('AvailabilityZone', 'unknown')
            sn_id = cfg.get('SubnetId', 'unknown')
            az_subnet_instances[az][sn_id].append(inst)

        # ── LB placement will happen after VPC cell is created ──

        # ── Also collect VPC-attached Lambdas for this VPC ──
        vpc_lambdas = []
        for lf in model.lambda_functions():
            lf_cfg = lf.get('config', {})
            lf_subnets = lf_cfg.get('SubnetIds', [])
            if isinstance(lf_subnets, list) and lf_subnets:
                for sn_id in lf_subnets:
                    for sn in subnets:
                        if sn.get('resource_id', '') == sn_id:
                            vpc_lambdas.append(lf)
                            az = sn.get('config', {}).get('AvailabilityZone', 'unknown')
                            lf['_resolved_az'] = az
                            lf['_resolved_subnet'] = sn_id
                            break
                    else:
                        continue
                    break

        # ── Recalculate AZs ──
        # Include AZs from instances, lambdas, and LB subnets
        all_azs = set(az_instances.keys())
        for lf in vpc_lambdas:
            all_azs.add(lf.get('_resolved_az', 'unknown'))
        for sn_id in lb_subnet_ids:
            if sn_id in subnet_map:
                az = subnet_map[sn_id].get('config', {}).get('AvailabilityZone', '')
                if az:
                    all_azs.add(az)
        sorted_azs = sorted(all_azs)

        # ── Calculate sizes ──
        # Max items in any single AZ (instances + lambdas in private subnets)
        max_private_per_az = max(
            (len(az_instances.get(az, [])) for az in sorted_azs), default=0)
        max_lambda_per_az = max(
            (sum(1 for lf in vpc_lambdas if lf.get('_resolved_az') == az)
             for az in sorted_azs), default=0)
        max_items_per_az = max_private_per_az + max_lambda_per_az

        # Public subnet tier height (for LB subnet containers)
        has_public_tier = bool(lb_subnet_ids)
        PUBLIC_TIER_H = 100 if has_public_tier else 0

        # Private tier height based on instance count
        PRIVATE_TIER_H = max(max_items_per_az * 90 + 60, 160)

        AZ_H = PUBLIC_TIER_H + PRIVATE_TIER_H + 40
        AZ_W = 200

        # Recalculate VPC dimensions
        num_azs = max(len(sorted_azs), 1)
        lb_row_h = 120 if lbs else 0
        vpc_w = max(800, num_azs * (AZ_W + 20) + 200)
        vpc_w = min(vpc_w, 1800)
        max_vpc_w = max(max_vpc_w, vpc_w)

        DATA_PER_ROW = 5
        rds_in_this_vpc = model.rds_in_vpc(vpc_rid)
        cache_items = model.by_category('ElastiCache Clusters')
        total_data = len(rds_in_this_vpc) + len(cache_items)
        data_rows = max((total_data + DATA_PER_ROW - 1) // DATA_PER_ROW, 0)
        data_row_h = data_rows * 100 + 40 if total_data > 0 else 0

        vpc_h = lb_row_h + AZ_H + 60 + data_row_h + 40

        # NOW create the VPC cell with correct dimensions
        vpc_id = add_cell('1',
                          f'{vpc_name}<br><font style="font-size:10px">{cidr} | {region}</font>',
                          VPC_STYLE, 50, vpc_y, vpc_w, vpc_h)
        id_map[vpc_rid] = vpc_id

        # ── LB placement: inside VPC at top, spanning AZs ──
        lb_ids = []
        lb_y = 30
        for i, lb in enumerate(lbs):
            lb_name = lb.get('name', '')
            lb_cfg = lb.get('config', {})
            lb_cat = lb.get('_category', '')
            is_classic = lb_cat == 'Classic Load Balancers'

            if is_classic:
                style = CLB_STYLE
            else:
                lb_type = lb_cfg.get('Type', 'network')
                style = ALB_STYLE if lb_type == 'application' else NLB_STYLE

            short = lb_name[:25] if len(lb_name) > 25 else lb_name
            scheme = lb_cfg.get('Scheme', '')

            lid = add_cell(vpc_id, short, style,
                           30 + i * 140, lb_y, S, S)
            lb_ids.append(lid)
            id_map[lb.get('resource_id', lb_name)] = lid

            if scheme == 'internet-facing':
                add_edge(inet_id, lid)

        # ── AZ containers with subnet tiers ──
        az_y = lb_row_h + 20
        inst_ids = []
        public_subnet_cell_ids = {}  # subnet_id -> cell_id (for LB edges)

        for az_idx, az_name in enumerate(sorted_azs):
            az_x = 20 + az_idx * (AZ_W + 20)
            az_label = f'{az_name}'

            az_id = add_cell(vpc_id, az_label, AZ_STYLE,
                             az_x, az_y, AZ_W, AZ_H)

            inner_y = 30

            # ── Public subnet tier (if this AZ has public subnets used by LBs) ──
            if has_public_tier:
                az_pub_subs = [sn for sn in az_public_subnets.get(az_name, [])
                               if sn.get('resource_id', '') in lb_subnet_ids]
                if az_pub_subs:
                    # Show the public subnet as a small labeled container
                    pub_sn = az_pub_subs[0]  # Primary public subnet
                    pub_name = pub_sn.get('name', 'public')
                    pub_cidr = pub_sn.get('config', {}).get('CidrBlock', '')
                    pub_label = f'{pub_name[:15]}<br><font style="font-size:8px">{pub_cidr}</font>'
                    pub_cell = add_cell(az_id, pub_label, SUBNET_STYLE,
                                        10, inner_y, AZ_W - 20, PUBLIC_TIER_H - 10)
                    public_subnet_cell_ids[pub_sn.get('resource_id', '')] = pub_cell
                inner_y += PUBLIC_TIER_H

            # ── Private subnet tier (instances) ──
            az_insts = az_instances.get(az_name, [])
            for inst_idx, inst in enumerate(az_insts):
                name = inst.get('name', '')
                cfg = inst.get('config', {})
                itype = cfg.get('InstanceType', '')
                ip = cfg.get('PrivateIpAddress', '')
                short_name = name[:20] if len(name) > 20 else name
                label = f'{short_name}<br><font style="font-size:9px">{itype} | {ip}</font>'

                iid = add_cell(az_id, label, EC2_STYLE,
                               (AZ_W - S) // 2, inner_y + inst_idx * 90, S, S)
                inst_ids.append(iid)
                id_map[inst.get('resource_id', name)] = iid

            # VPC-attached Lambdas in this AZ
            az_lfs = [lf for lf in vpc_lambdas if lf.get('_resolved_az') == az_name]
            offset = len(az_insts) * 90
            for lf_idx, lf in enumerate(az_lfs):
                lf_name = lf.get('name', '')
                short = lf_name[:20] if len(lf_name) > 20 else lf_name
                lf_id = add_cell(az_id, short, LAMBDA_STYLE,
                                 (AZ_W - S) // 2, inner_y + offset + lf_idx * 90, S, S)
                id_map[lf.get('resource_id', lf_name)] = lf_id

        # ── LB → public subnet edges (showing AZ spanning) ──
        # LBs are VPC children, subnets are AZ grandchildren — same
        # parent-into-child direction as Internet→CLB which renders fine.
        for lb in lbs:
            lb_cfg = lb.get('config', {})
            lb_subs = lb_cfg.get('Subnets', [])
            lb_rid = lb.get('resource_id', lb.get('name', ''))
            lb_cell = id_map.get(lb_rid)
            if lb_cell and isinstance(lb_subs, list):
                for sn_id in lb_subs:
                    if sn_id in public_subnet_cell_ids:
                        add_edge(lb_cell, public_subnet_cell_ids[sn_id])

        # ── Data tier (bottom of VPC) ──
        # RDS instances that belong to this VPC (matched via SG→VPC)
        rds = model.rds_in_vpc(vpc_rid)
        cache = model.by_category('ElastiCache Clusters')
        data_y = az_y + AZ_H + 20
        data_ids = []
        DATA_PER_ROW = 5

        for i, db in enumerate(rds):
            name = db.get('name', '')
            cfg = db.get('config', {})
            engine = cfg.get('Engine', '')
            label = f'{name}<br><font style="font-size:9px">{engine}</font>'
            col = i % DATA_PER_ROW
            row = i // DATA_PER_ROW
            did = add_cell(vpc_id, label, RDS_STYLE,
                           30 + col * 160, data_y + row * 100, S, S)
            data_ids.append(did)
            id_map[db.get('resource_id', name)] = did

        for i, c in enumerate(cache):
            name = c.get('name', '')
            engine = c.get('config', {}).get('Engine', 'cache')
            label = f'{name}<br><font style="font-size:9px">{engine}</font>'
            idx = len(rds) + i
            col = idx % DATA_PER_ROW
            row = idx // DATA_PER_ROW
            cid_val = add_cell(vpc_id, label, CACHE_STYLE,
                               30 + col * 160, data_y + row * 100, S, S)
            data_ids.append(cid_val)
            id_map[c.get('resource_id', name)] = cid_val

        # Representative edges: first instance in each AZ → data stores
        # DISABLED: edges between nested cells and VPC-level cells cause
        # draw.io to displace icons. Spatial proximity communicates the
        # relationship (data tier is at the bottom of the VPC).
        # for iid in shown_inst_ids:
        #     for did in data_ids:
        #         add_edge(iid, did)

        # NAT Gateways
        for i, nat in enumerate(nats):
            name = nat.get('name', 'NAT')
            add_cell(vpc_id, name, NAT_STYLE,
                     vpc_w - 100, 30 + i * 80, S, S)

        vpc_y += vpc_h + 60

    # ── Transit Gateways (between VPCs) ──
    TGW_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#8C4FFF;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.transit_gateway;'
    )
    tgws = model.by_category('Transit Gateways')
    tgw_attachments = model.by_category('Transit Gateway Attachments')
    if tgws:
        tgw_y = vpc_y
        for i, tgw in enumerate(tgws):
            name = tgw.get('name', tgw.get('resource_id', 'TGW'))
            tgw_state = tgw.get('config', {}).get('State', '')
            label = f'{name}<br><font style="font-size:9px">{tgw_state}</font>'
            tgw_cell_id = add_cell('1', label, TGW_STYLE,
                                   300 + i * 200, tgw_y, S, S)
            id_map[tgw.get('resource_id', '')] = tgw_cell_id

        # Draw attachment edges: TGW ↔ VPC (or labeled line for remote)
        REMOTE_EDGE_STYLE = (
            'edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;'
            'jettySize=auto;html=1;strokeColor=#8C4FFF;strokeWidth=2;'
            'dashed=1;endArrow=blockThin;endFill=1;'
        )
        REMOTE_LABEL_STYLE = (
            'text;html=1;align=center;verticalAlign=middle;resizable=0;'
            'points=[];autosize=1;strokeColor=#8C4FFF;fillColor=#E6E0F8;'
            'fontColor=#5A3E8E;fontSize=10;rounded=1;arcSize=20;'
        )
        tgw_remote_x = max_vpc_w + 150  # Right side of diagram
        tgw_remote_y = tgw_y
        for att in tgw_attachments:
            att_cfg = att.get('config', {})
            tgw_id = att_cfg.get('TransitGatewayId', '')
            resource_id = att_cfg.get('ResourceId', '')
            resource_type = att_cfg.get('ResourceType', '')
            resource_owner = att_cfg.get('ResourceOwnerId', '')
            att_name = att.get('name', att.get('resource_id', ''))

            if tgw_id in id_map and resource_id in id_map:
                # Both sides are in our inventory — solid edge (same nesting level)
                add_edge(id_map[tgw_id], id_map[resource_id])
            elif tgw_id in id_map:
                # TGW is local but the attached resource is in another
                # region or account — draw a labeled dashed line to the right
                detail_parts = [resource_type]
                if resource_id:
                    detail_parts.append(resource_id[:25])
                if resource_owner:
                    detail_parts.append(f'acct:{resource_owner}')
                detail = ' | '.join(detail_parts)

                remote_cell = add_cell(
                    '1',
                    f'{att_name}<br><font style="font-size:9px">{detail}</font>',
                    REMOTE_LABEL_STYLE, tgw_remote_x, tgw_remote_y, 280, 40)
                eid = next_id()
                edge = ET.SubElement(graph_root, 'mxCell',
                                     id=eid, value='',
                                     style=REMOTE_EDGE_STYLE,
                                     edge='1', parent='1',
                                     source=id_map[tgw_id],
                                     target=remote_cell)
                geo = ET.SubElement(edge, 'mxGeometry', relative='1')
                geo.set('as', 'geometry')
                tgw_remote_y += 60

        vpc_y = tgw_y + 140

    # ── VPC Peering Connections ──
    PCX_STYLE = (
        'outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#8C4FFF;'
        'strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;'
        'align=center;html=1;fontSize=11;fontStyle=0;aspect=fixed;pointerEvents=1;'
        'shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.peering;'
    )
    PCX_EDGE_STYLE = (
        'edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;'
        'jettySize=auto;html=1;strokeColor=#8C4FFF;strokeWidth=2;'
        'dashed=1;endArrow=none;'
    )
    peerings = model.by_category('VPC Peering Connections')
    # Place remote peering labels to the right of the VPC they connect to
    pcx_remote_x = 0  # Will be set to max_vpc_w + margin
    pcx_remote_y = 120  # Start at top of diagram, offset per item
    for pcx in peerings:
        cfg = pcx.get('config', {})
        pcx_id = pcx.get('resource_id', '')
        name = pcx.get('name', pcx_id)
        status = cfg.get('Code', cfg.get('Status', ''))

        # With collision-safe keys from discover_operation:
        # RequesterVpcInfo.VpcId → RequesterVpcInfo_VpcId
        # AccepterVpcInfo.VpcId → AccepterVpcInfo_VpcId
        req_vpc_id = cfg.get('RequesterVpcInfo_VpcId', cfg.get('VpcId', ''))
        acc_vpc_id = cfg.get('AccepterVpcInfo_VpcId', '')
        req_region = cfg.get('RequesterVpcInfo_Region', cfg.get('Region', ''))
        acc_region = cfg.get('AccepterVpcInfo_Region', '')

        # Fallback for inventories generated before collision-safe keys
        if not acc_vpc_id:
            for k, v in cfg.items():
                if isinstance(v, str) and v.startswith('vpc-') and v != req_vpc_id:
                    acc_vpc_id = v
                    break

        # Draw peering as edges between VPCs (if both are in our inventory)
        if req_vpc_id in id_map and acc_vpc_id in id_map:
            eid = next_id()
            edge = ET.SubElement(graph_root, 'mxCell',
                                 id=eid, value=f'Peering: {name}',
                                 style=PCX_EDGE_STYLE,
                                 edge='1', parent='1',
                                 source=id_map[req_vpc_id],
                                 target=id_map[acc_vpc_id])
            geo = ET.SubElement(edge, 'mxGeometry', relative='1')
            geo.set('as', 'geometry')
        elif req_vpc_id in id_map or acc_vpc_id in id_map:
            # One side is in our inventory, the other is external
            local_vpc = req_vpc_id if req_vpc_id in id_map else acc_vpc_id
            remote_vpc = acc_vpc_id if local_vpc == req_vpc_id else req_vpc_id
            remote_region = acc_region if local_vpc == req_vpc_id else req_region
            remote_owner = cfg.get('AccepterVpcInfo_OwnerId', '') if local_vpc == req_vpc_id \
                else cfg.get('RequesterVpcInfo_OwnerId', cfg.get('OwnerId', ''))

            detail_parts = []
            if remote_region:
                detail_parts.append(remote_region)
            if remote_owner:
                detail_parts.append(f'acct:{remote_owner}')
            if remote_vpc:
                detail_parts.append(remote_vpc)
            detail = ' | '.join(detail_parts) if detail_parts else 'cross-account/region'

            # Place to the RIGHT of the diagram (east-west layout)
            REMOTE_LABEL_STYLE = (
                'text;html=1;align=center;verticalAlign=middle;resizable=0;'
                'points=[];autosize=1;strokeColor=#8C4FFF;fillColor=#E6E0F8;'
                'fontColor=#5A3E8E;fontSize=10;rounded=1;arcSize=20;'
            )
            # Position remote labels to the right, stacked vertically
            if pcx_remote_x == 0:
                pcx_remote_x = max_vpc_w + 150  # Right of the widest VPC
            remote_cell = add_cell('1',
                                   f'Peering: {name}<br><font style="font-size:9px">{detail}</font>',
                                   REMOTE_LABEL_STYLE,
                                   pcx_remote_x, pcx_remote_y, 280, 40)
            eid = next_id()
            edge = ET.SubElement(graph_root, 'mxCell',
                                 id=eid, value='',
                                 style=PCX_EDGE_STYLE,
                                 edge='1', parent='1',
                                 source=id_map[local_vpc],
                                 target=remote_cell)
            geo = ET.SubElement(edge, 'mxGeometry', relative='1')
            geo.set('as', 'geometry')
            pcx_remote_y += 80

    # ── Lambdas outside VPC ──
    # Collect all Lambda resource_ids that were placed inside a VPC
    placed_lambda_ids = set()
    for vpc in model.vpcs():
        vpc_rid = vpc.get('resource_id', '')
        vpc_cfg = vpc.get('config', {})
        if vpc_cfg.get('IsDefault') and len(model.vpcs()) > 1:
            if not model.instances_in_vpc(vpc_rid):
                continue
        subnets = model.subnets_in_vpc(vpc_rid)
        subnet_ids_in_vpc = {sn.get('resource_id', '') for sn in subnets}
        for lf in model.lambda_functions():
            lf_subnets = lf.get('config', {}).get('SubnetIds', [])
            if isinstance(lf_subnets, list):
                for sn_id in lf_subnets:
                    if sn_id in subnet_ids_in_vpc:
                        placed_lambda_ids.add(lf.get('resource_id', ''))
                        break

    lambdas_no_vpc = [l for l in model.lambda_functions()
                      if l.get('resource_id', '') not in placed_lambda_ids
                      and not l.get('config', {}).get('SubnetIds')]
    if lambdas_no_vpc:
        aws_pub_y = vpc_y + 20
        num_rows = (len(lambdas_no_vpc) + 3) // 4  # 4 per row
        pub_h = num_rows * 100 + 60
        pub_id = add_cell('1', 'AWS Public (outside VPC)',
                          TIER_STYLE, 50, aws_pub_y, 700, pub_h)
        for i, lf in enumerate(lambdas_no_vpc):
            name = lf.get('name', '')
            short = name[:30] if len(name) > 30 else name
            add_cell(pub_id, short, LAMBDA_STYLE,
                     30 + (i % 4) * 150, 40 + (i // 4) * 90, S, S)

    # ── Write XML ──
    tree = ET.ElementTree(root)
    # ET.indent requires Python 3.9+; skip pretty-printing on older versions
    if hasattr(ET, 'indent'):
        ET.indent(tree, space='  ')
    tree.write(filepath, encoding='unicode', xml_declaration=False)
    print(f"  ✓ draw.io        → {filepath}")


# ═══════════════════════════════════════════════════════════════════
# EXECUTIVE AUDIENCE
# ═══════════════════════════════════════════════════════════════════

def render_executive(model: InventoryModel) -> str:
    """Render an executive-level architecture overview.

    No resource IDs, no instance types. Grouped by function.
    Highlights HA, encryption, DR readiness.
    """
    lines = []
    meta = model.meta
    w = lines.append

    w(f"# Infrastructure Overview")
    w(f"")
    w(f"**Account:** {meta.get('account_id', 'N/A')}  ")
    w(f"**Region:** {meta.get('region', 'N/A')}  ")
    w(f"**Inventory Date:** {meta.get('scan_date', 'N/A')}  ")
    w("")

    # Summary counts by functional area
    counts = model.resource_counts()
    total = sum(counts.values())
    w(f"**Total Resources Inventoried:** {total}")
    if model.noise_categories:
        noise_total = sum(len(r) for r in model.noise_categories.values())
        w(f"  *(plus {noise_total} AWS platform/catalog items not shown)*")
    w("")

    # ── Topology Diagram ──
    w("## Architecture Topology")
    w("")
    w(render_mermaid_topology(model, detailed=False))
    w("")

    # ── Compute ──
    instances = model.by_category('EC2 Instances')
    if instances:
        # Group by apparent function (from name patterns)
        ha_pairs = defaultdict(list)
        standalone = []
        for inst in instances:
            name = inst.get('name', '')
            # Detect HA pairs: Name-1a/Name-1b or Name-1/Name-2
            base = name
            for suffix in ['-1a', '-1b', '-1', '-2', '_1a', '_1b']:
                if name.lower().endswith(suffix):
                    base = name[:len(name) - len(suffix)]
                    break
            if base != name:
                ha_pairs[base].append(inst)
            else:
                standalone.append(inst)

        w("## Compute Tier")
        w("")
        if ha_pairs:
            w("| Application | Servers | High Availability |")
            w("|-------------|:-------:|:-----------------:|")
            for base, members in sorted(ha_pairs.items()):
                ha = "✅ HA" if len(members) >= 2 else "⚠️ Single"
                w(f"| {base} | {len(members)} | {ha} |")
        if standalone:
            for inst in standalone:
                name = inst.get('name', 'unnamed')
                w(f"| {name} | 1 | ⚠️ Single |")
        w("")

    # ── Database ──
    rds = model.rds_instances()
    cache = model.by_category('ElastiCache Clusters')
    if rds or cache:
        w("## Data Tier")
        w("")
        if rds:
            w("| Database | Engine | Encrypted | Multi-AZ | Backups |")
            w("|----------|--------|:---------:|:--------:|:-------:|")
            for db in rds:
                cfg = db.get('config', {})
                name = db.get('name', '')
                engine = f"{cfg.get('Engine', '?')} {cfg.get('EngineVersion', '')}"
                encrypted = "✅" if cfg.get('StorageEncrypted') else "❌"
                multi_az = "✅" if cfg.get('MultiAZ') else "❌"
                retention = cfg.get('BackupRetentionPeriod', 0)
                backups = f"✅ {retention}d" if retention > 0 else "❌ None"
                w(f"| {name} | {engine} | {encrypted} | {multi_az} | {backups} |")
            w("")

        if cache:
            w(f"**Caching:** {len(cache)} ElastiCache node(s) deployed")
            w("")

    # ── Networking ──
    v2_lbs = model.by_category('Load Balancers')
    classic_lbs = model.by_category('Classic Load Balancers')
    all_lbs = v2_lbs + classic_lbs
    if all_lbs:
        w("## Network Tier")
        w("")
        w(f"**Load Balancers:** {len(all_lbs)}")
        albs = [lb for lb in v2_lbs if lb.get('config', {}).get('Type') == 'application']
        nlbs = [lb for lb in v2_lbs if lb.get('config', {}).get('Type') == 'network']
        if albs:
            w(f"  - {len(albs)} Application Load Balancer(s) — HTTP/HTTPS routing")
        if nlbs:
            w(f"  - {len(nlbs)} Network Load Balancer(s) — TCP/TLS passthrough")
        if classic_lbs:
            w(f"  - {len(classic_lbs)} Classic Load Balancer(s) — legacy TCP/HTTP")
        w("")

    # ── Security ──
    sgs = model.by_category('Security Groups')
    certs = model.by_category('ACM Certificates')
    waf = model.by_category('WAF Web ACLs')
    kms = model.by_category('KMS Keys')
    w("## Security Posture")
    w("")
    w(f"| Control | Count | Status |")
    w(f"|---------|:-----:|--------|")
    if sgs:
        w(f"| Security Groups | {len(sgs)} | Active |")
    if certs:
        w(f"| TLS Certificates | {len(certs)} | Managed (ACM) |")
    if waf:
        w(f"| Web Application Firewall | {len(waf)} | Active |")
    if kms:
        w(f"| Encryption Keys | {len(kms)} | Customer-managed |")
    secrets = model.by_category('Secrets')
    if secrets:
        w(f"| Secrets (credentials) | {len(secrets)} | Secrets Manager |")

    # Encryption summary
    rds_encrypted = sum(1 for db in rds if db.get('config', {}).get('StorageEncrypted'))
    if rds:
        status = "✅ All encrypted" if rds_encrypted == len(rds) else f"⚠️ {rds_encrypted}/{len(rds)} encrypted"
        w(f"| Database Encryption | {len(rds)} DBs | {status} |")
    w("")

    # ── Anomalies (executive-relevant only) ──
    critical = [a for a in model.anomalies if a['severity'] in ('critical', 'warning')]
    if critical:
        w("## ⚠️ Items Requiring Attention")
        w("")
        for a in critical:
            icon = "🔴" if a['severity'] == 'critical' else "🟡"
            w(f"- {icon} **{a['resource']}**: {a['issue']}")
        w("")

    # ── Serverless ──
    lambdas = model.lambda_functions()
    if lambdas:
        vpc_attached = sum(1 for l in lambdas
                          if l.get('config', {}).get('SubnetIds'))
        w("## Serverless")
        w("")
        w(f"**Lambda Functions:** {len(lambdas)} "
          f"({vpc_attached} VPC-attached, "
          f"{len(lambdas) - vpc_attached} public)")
        w("")

    # ── Platform ──
    alarms = model.by_category('CloudWatch Alarms')
    sns = model.by_category('SNS Topics')
    s3 = model.by_category('S3 Buckets')
    w("## Platform Services")
    w("")
    if alarms:
        w(f"- **Monitoring:** {len(alarms)} CloudWatch alarm(s)")
    if sns:
        w(f"- **Notifications:** {len(sns)} SNS topic(s)")
    if s3:
        w(f"- **Storage:** {len(s3)} S3 bucket(s)")
    w("")

    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════
# ENGINEERING AUDIENCE
# ═══════════════════════════════════════════════════════════════════

def render_engineering(model: InventoryModel) -> str:
    """Render an engineering-level architecture view.

    Full detail: resource names, IDs, instance types, subnet placement.
    Three sections: Network Topology, Security Posture, Data Flow.
    Anomalies flagged inline.
    """
    lines = []
    meta = model.meta
    w = lines.append

    w(f"# Engineering Architecture — {meta.get('region', '')}")
    w(f"")
    w(f"Account: `{meta.get('account_id', '')}`  ")
    w(f"Region: `{meta.get('region', '')}`  ")
    w(f"Scanned: {meta.get('scan_date', '')}  ")
    w("")

    # ════════════════════════════════════════════
    # SECTION 1: NETWORK TOPOLOGY
    # ════════════════════════════════════════════
    w("## 1. Network Topology")
    w("")
    w("### Visual Overview")
    w("")
    w(render_mermaid_topology(model, detailed=True))
    w("")
    w("### Detailed Breakdown")
    w("")

    vpcs = model.vpcs()
    for vpc in vpcs:
        vpc_id = vpc.get('resource_id', '')
        vpc_cfg = vpc.get('config', {})
        vpc_name = vpc.get('name', vpc_id)
        cidr = vpc_cfg.get('CidrBlock', '?')

        w(f"### VPC: {vpc_name} (`{vpc_id}`, {cidr})")
        w("")

        # Subnets grouped by AZ
        subnets = model.subnets_in_vpc(vpc_id)
        az_groups = defaultdict(list)
        for sn in subnets:
            az = sn.get('config', {}).get('AvailabilityZone', 'unknown')
            az_groups[az].append(sn)

        if az_groups:
            for az in sorted(az_groups.keys()):
                w(f"**{az}:**")
                for sn in az_groups[az]:
                    sn_name = sn.get('name', sn.get('resource_id', ''))
                    sn_cidr = sn.get('config', {}).get('CidrBlock', '')
                    public = "public" if sn.get('config', {}).get('MapPublicIpOnLaunch') else "private"
                    w(f"  - `{sn.get('resource_id', '')}` {sn_name} ({sn_cidr}, {public})")
                w("")

        # Load Balancers in this VPC
        lbs = model.lbs_in_vpc(vpc_id)
        if lbs:
            w("#### Traffic Entry Points")
            w("")
            for lb in lbs:
                lb_cfg = lb.get('config', {})
                lb_name = lb.get('name', '')
                is_classic = lb.get('_category', '') == 'Classic Load Balancers'
                if is_classic:
                    lb_type = 'classic'
                else:
                    lb_type = lb_cfg.get('Type', '?')
                scheme = lb_cfg.get('Scheme', '?')
                state = lb_cfg.get('Code', lb_cfg.get('State', ''))
                if isinstance(state, dict):
                    state = state.get('Code', '')

                icon = "🌐" if scheme == 'internet-facing' else "🔒"
                w(f"**{icon} {lb_name}** ({lb_type}, {scheme})")

                # Find target groups for this LB
                lb_arn = lb_cfg.get('LoadBalancerArn', '')
                tgs = model.by_category('Target Groups')
                # We can't directly link TG to LB from inventory alone,
                # so list all TGs (they're in the same VPC context)
                w("")

            w("")

        # EC2 Instances in this VPC
        instances = model.instances_in_vpc(vpc_id)
        if instances:
            w("#### Compute Instances")
            w("")
            w("| Name | ID | Type | Subnet | Private IP | State | Tags |")
            w("|------|-----|------|--------|------------|-------|------|")
            for inst in sorted(instances, key=lambda x: x.get('name', '')):
                cfg = inst.get('config', {})
                name = inst.get('name', '')
                iid = cfg.get('InstanceId', inst.get('resource_id', ''))
                itype = cfg.get('InstanceType', '')
                subnet = cfg.get('SubnetId', '')
                ip = cfg.get('PrivateIpAddress', '')
                state = cfg.get('Name', cfg.get('State', ''))
                if isinstance(state, dict):
                    state = state.get('Name', '')
                # Key tags
                tags = cfg.get('Tags', {})
                tag_str = ', '.join(f"{k}={v}" for k, v in tags.items()
                                   if k in ('Role', 'OS', 'Zone', 'Backup',
                                            'JoinDomain', 'DomainJoined'))
                w(f"| {name} | `{iid}` | {itype} | `{subnet[:15]}…` | {ip} | {state} | {tag_str} |")
            w("")

    # Resources OUTSIDE any VPC
    lambdas_no_vpc = [l for l in model.lambda_functions()
                      if not l.get('config', {}).get('SubnetIds')]
    if lambdas_no_vpc:
        w("### ⚠️ Resources Outside VPC (AWS Public Network)")
        w("")
        for lf in lambdas_no_vpc:
            cfg = lf.get('config', {})
            w(f"- **Lambda:** {lf.get('name', '')} "
              f"(runtime: {cfg.get('Runtime', '?')}, "
              f"memory: {cfg.get('MemorySize', '?')}MB)")
        w("")

    # ════════════════════════════════════════════
    # SECTION 2: SECURITY POSTURE
    # ════════════════════════════════════════════
    w("## 2. Security Posture")
    w("")

    # Internet-facing resources
    v2_lbs = model.by_category('Load Balancers')
    classic_lbs = model.by_category('Classic Load Balancers')
    all_lbs = v2_lbs + classic_lbs
    internet_facing = [lb for lb in all_lbs
                       if lb.get('config', {}).get('Scheme') == 'internet-facing']
    if internet_facing:
        w("### Internet-Facing Resources")
        w("")
        for lb in internet_facing:
            name = lb.get('name', '')
            is_classic = lb.get('_category', '') == 'Classic Load Balancers'
            if is_classic:
                lb_type = 'classic'
            else:
                lb_type = lb.get('config', {}).get('Type', '')
            w(f"- **{name}** ({lb_type})")
        w("")

    # SG analysis
    sgs = model.by_category('Security Groups')
    open_sgs = []
    for sg in sgs:
        cfg = sg.get('config', {})
        for rule in cfg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    port = rule.get('FromPort', 'all')
                    proto = rule.get('IpProtocol', 'all')
                    open_sgs.append({
                        'sg': sg.get('name', ''),
                        'sg_id': sg.get('resource_id', ''),
                        'port': port,
                        'protocol': proto,
                    })

    if open_sgs:
        w("### Security Groups with Public Access (0.0.0.0/0)")
        w("")
        w("| Security Group | ID | Port | Protocol |")
        w("|---------------|-----|------|----------|")
        for entry in open_sgs:
            w(f"| {entry['sg']} | `{entry['sg_id']}` | {entry['port']} | {entry['protocol']} |")
        w("")

    # Encryption status
    w("### Encryption Status")
    w("")
    rds = model.rds_instances()
    for db in rds:
        cfg = db.get('config', {})
        enc = "✅ Encrypted" if cfg.get('StorageEncrypted') else "❌ NOT encrypted"
        kms = cfg.get('KmsKeyId', 'default')
        if kms and len(kms) > 40:
            kms = kms[:37] + '...'
        w(f"- **{db.get('name', '')}**: {enc} (KMS: `{kms}`)")

    cache = model.by_category('ElastiCache Clusters')
    for c in cache:
        cfg = c.get('config', {})
        at_rest = "✅" if cfg.get('AtRestEncryptionEnabled') else "❌"
        in_transit = "✅" if cfg.get('TransitEncryptionEnabled') else "❌"
        w(f"- **{c.get('name', '')}**: at-rest {at_rest}, in-transit {in_transit}")
    w("")

    # ════════════════════════════════════════════
    # SECTION 3: DATA FLOW
    # ════════════════════════════════════════════
    w("## 3. Data Flow")
    w("")

    # Persistent data stores
    if rds:
        w("### Persistent Data")
        w("")
        for db in rds:
            cfg = db.get('config', {})
            w(f"**{db.get('name', '')}** "
              f"({cfg.get('Engine', '')} {cfg.get('EngineVersion', '')}, "
              f"{cfg.get('DBInstanceClass', '')})")
            w(f"  - Endpoint: `{cfg.get('Address', cfg.get('Endpoint', ''))}`")
            w(f"  - Storage: {cfg.get('AllocatedStorage', '?')} GB, "
              f"{cfg.get('StorageType', '?')}")
            retention = cfg.get('BackupRetentionPeriod', 0)
            w(f"  - Backups: {retention} day retention")
            w("")

    # S3 buckets
    s3 = model.by_category('S3 Buckets')
    if s3:
        w("### Object Storage")
        w("")
        for bucket in s3:
            w(f"- `{bucket.get('name', '')}`")
        w("")

    # ════════════════════════════════════════════
    # SECTION 4: CROSS-REGION DEPENDENCIES
    # ════════════════════════════════════════════
    cross_region_items = []

    # VPC Peering with remote region
    peerings = model.by_category('VPC Peering Connections')
    for pcx in peerings:
        cfg = pcx.get('config', {})
        req_region = cfg.get('RequesterVpcInfo_Region', cfg.get('Region', ''))
        acc_region = cfg.get('AccepterVpcInfo_Region', '')
        scan_region = meta.get('region', '')
        remote_region = ''
        if req_region and req_region != scan_region:
            remote_region = req_region
        elif acc_region and acc_region != scan_region:
            remote_region = acc_region
        if remote_region:
            cross_region_items.append(
                f"- **VPC Peering:** {pcx.get('name', pcx.get('resource_id', ''))} "
                f"→ {remote_region}")

    # TGW attachments referencing resources not in our inventory
    tgw_attachments = model.by_category('Transit Gateway Attachments')
    for att in tgw_attachments:
        att_cfg = att.get('config', {})
        resource_id = att_cfg.get('ResourceId', '')
        resource_type = att_cfg.get('ResourceType', '')
        if resource_id and resource_id not in model.by_id:
            owner = att_cfg.get('ResourceOwnerId', '')
            cross_region_items.append(
                f"- **TGW Attachment:** {att.get('name', att.get('resource_id', ''))} "
                f"→ {resource_type} `{resource_id}`"
                f"{f' (acct: {owner})' if owner else ''}")

    # RDS cross-region read replicas
    for db in rds:
        cfg = db.get('config', {})
        source = cfg.get('ReadReplicaSourceDBInstanceIdentifier', '')
        replicas = cfg.get('ReadReplicaDBInstanceIdentifiers', [])
        if source and source not in model.by_id:
            cross_region_items.append(
                f"- **RDS Replica:** {db.get('name', '')} "
                f"← source `{source}` (likely cross-region)")
        if isinstance(replicas, list):
            for rep in replicas:
                if rep and rep not in model.by_id:
                    cross_region_items.append(
                        f"- **RDS Replica:** {db.get('name', '')} "
                        f"→ replica `{rep}` (likely cross-region)")

    if cross_region_items:
        w("## 4. Cross-Region Dependencies")
        w("")
        w("*These resources reference endpoints outside this region's scan. "
          "Run discovery in the remote region for full topology.*")
        w("")
        for item in cross_region_items:
            w(item)
        w("")

    # ════════════════════════════════════════════
    # SECTION 5: ANOMALIES & FINDINGS
    # ════════════════════════════════════════════
    if model.anomalies:
        section_num = 5 if cross_region_items else 4
        w(f"## {section_num}. Findings & Anomalies")
        w("")
        severity_icons = {
            'critical': '🔴',
            'warning': '🟡',
            'info': '🔵',
        }
        # Group by category
        by_cat = defaultdict(list)
        for a in model.anomalies:
            by_cat[a['category']].append(a)

        for cat, items in sorted(by_cat.items()):
            w(f"### {cat.replace('_', ' ').title()}")
            w("")
            for a in items:
                icon = severity_icons.get(a['severity'], '⚪')
                w(f"- {icon} **{a['resource']}** (`{a['resource_id']}`): "
                  f"{a['issue']}")
            w("")

    # ════════════════════════════════════════════
    # FINAL SECTION: RESOURCE SUMMARY
    # ════════════════════════════════════════════
    w("## Resource Summary")
    w("")
    w("| Category | Count | Tier |")
    w("|----------|:-----:|------|")
    for category, resources in sorted(model.known_categories.items()):
        tier, group = classify(category)
        w(f"| {category} | {len(resources)} | {tier} |")
    w("")
    w(f"**Total: {sum(len(r) for r in model.known_categories.values())} resources**")

    if model.noise_categories:
        noise_total = sum(len(r) for r in model.noise_categories.values())
        w(f"\n*{len(model.noise_categories)} additional AWS catalog/platform categories "
          f"({noise_total} items) excluded from this view.*")
    w("")

    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════
# OPERATIONS AUDIENCE
# ═══════════════════════════════════════════════════════════════════

def render_operations(model: InventoryModel) -> str:
    """Render an operations-focused view.

    Instance IDs, IPs, key pairs, dependency chains.
    DR notes per resource. Recovery priority ordering.
    """
    lines = []
    meta = model.meta
    w = lines.append

    w(f"# Operations Reference — {meta.get('region', '')}")
    w(f"")
    w(f"Account: `{meta.get('account_id', '')}`  ")
    w(f"Region: `{meta.get('region', '')}`  ")
    w(f"Scanned: {meta.get('scan_date', '')}  ")
    w("")

    # ── Recovery Priority 1: Data Tier ──
    w("## Priority 1: Data Tier (recover first)")
    w("")
    rds = model.rds_instances()
    for db in rds:
        cfg = db.get('config', {})
        w(f"### {db.get('name', '')}")
        w(f"- **ID:** `{db.get('resource_id', '')}`")
        w(f"- **Engine:** {cfg.get('Engine', '')} {cfg.get('EngineVersion', '')}")
        w(f"- **Class:** {cfg.get('DBInstanceClass', '')}")
        w(f"- **Endpoint:** `{cfg.get('Address', '')}`:{cfg.get('Port', '')}")
        w(f"- **Encrypted:** {cfg.get('StorageEncrypted', False)}")
        w(f"- **Multi-AZ:** {cfg.get('MultiAZ', False)}")
        w(f"- **Backup Retention:** {cfg.get('BackupRetentionPeriod', 0)} days")
        dr = db.get('dr_note', '')
        if dr:
            w(f"- **DR Note:** {dr}")
        w("")

    cache = model.by_category('ElastiCache Clusters')
    for c in cache:
        cfg = c.get('config', {})
        w(f"### {c.get('name', '')}")
        w(f"- **Engine:** {cfg.get('Engine', '')} {cfg.get('EngineVersion', '')}")
        w(f"- **Node Type:** {cfg.get('CacheNodeType', '')}")
        w(f"- **Nodes:** {cfg.get('NumCacheNodes', '')}")
        dr = c.get('dr_note', '')
        if dr:
            w(f"- **DR Note:** {dr}")
        w("")

    # ── Recovery Priority 2: Compute Tier ──
    w("## Priority 2: Compute Tier")
    w("")
    instances = model.by_category('EC2 Instances')
    for inst in sorted(instances, key=lambda x: x.get('name', '')):
        cfg = inst.get('config', {})
        tags = cfg.get('Tags', {})
        w(f"### {inst.get('name', '')}")
        w(f"- **Instance ID:** `{cfg.get('InstanceId', inst.get('resource_id', ''))}`")
        w(f"- **Type:** {cfg.get('InstanceType', '')}")
        w(f"- **AMI:** `{cfg.get('ImageId', '')}`")
        w(f"- **Private IP:** {cfg.get('PrivateIpAddress', '')}")
        w(f"- **Subnet:** `{cfg.get('SubnetId', '')}`")
        w(f"- **Key Pair:** {cfg.get('KeyName', 'none')}")
        w(f"- **AZ:** {cfg.get('AvailabilityZone', '')}")
        role = tags.get('Role', '')
        if role:
            w(f"- **Role:** {role}")
        dr = inst.get('dr_note', '')
        if dr:
            w(f"- **DR Note:** {dr}")
        w("")

    # ── Recovery Priority 3: Network Tier ──
    w("## Priority 3: Network & Routing")
    w("")
    v2_lbs = model.by_category('Load Balancers')
    classic_lbs = model.by_category('Classic Load Balancers')
    all_lbs = v2_lbs + classic_lbs
    for lb in all_lbs:
        cfg = lb.get('config', {})
        is_classic = lb.get('_category', '') == 'Classic Load Balancers'
        if is_classic:
            lb_type = 'classic'
        else:
            lb_type = cfg.get('Type', '')
        w(f"- **{lb.get('name', '')}** ({lb_type}, "
          f"{cfg.get('Scheme', '')})")
    w("")

    # ── Cross-Region Dependencies ──
    cross_region_items = []

    peerings = model.by_category('VPC Peering Connections')
    scan_region = meta.get('region', '')
    for pcx in peerings:
        cfg = pcx.get('config', {})
        req_region = cfg.get('RequesterVpcInfo_Region', cfg.get('Region', ''))
        acc_region = cfg.get('AccepterVpcInfo_Region', '')
        remote_region = ''
        if req_region and req_region != scan_region:
            remote_region = req_region
        elif acc_region and acc_region != scan_region:
            remote_region = acc_region
        if remote_region:
            cross_region_items.append(
                f"- **VPC Peering:** {pcx.get('name', pcx.get('resource_id', ''))} "
                f"→ {remote_region}")

    tgw_attachments = model.by_category('Transit Gateway Attachments')
    for att in tgw_attachments:
        att_cfg = att.get('config', {})
        resource_id = att_cfg.get('ResourceId', '')
        resource_type = att_cfg.get('ResourceType', '')
        if resource_id and resource_id not in model.by_id:
            owner = att_cfg.get('ResourceOwnerId', '')
            cross_region_items.append(
                f"- **TGW Attachment:** {att.get('name', att.get('resource_id', ''))} "
                f"→ {resource_type} `{resource_id}`"
                f"{f' (acct: {owner})' if owner else ''}")

    for db in rds:
        cfg = db.get('config', {})
        source = cfg.get('ReadReplicaSourceDBInstanceIdentifier', '')
        replicas = cfg.get('ReadReplicaDBInstanceIdentifiers', [])
        if source and source not in model.by_id:
            cross_region_items.append(
                f"- **RDS Replica:** {db.get('name', '')} "
                f"← source `{source}` (likely cross-region)")
        if isinstance(replicas, list):
            for rep in replicas:
                if rep and rep not in model.by_id:
                    cross_region_items.append(
                        f"- **RDS Replica:** {db.get('name', '')} "
                        f"→ replica `{rep}` (likely cross-region)")

    if cross_region_items:
        w("## Cross-Region Dependencies")
        w("")
        w("*Resources referencing endpoints outside this region. "
          "DR plans must account for these dependencies.*")
        w("")
        for item in cross_region_items:
            w(item)
        w("")

    # ── Monitoring Coverage ──
    w("## Monitoring Coverage")
    w("")
    alarms = model.by_category('CloudWatch Alarms')
    if alarms:
        w(f"**{len(alarms)} CloudWatch Alarm(s):**")
        w("")
        for alarm in alarms:
            cfg = alarm.get('config', {})
            w(f"- {alarm.get('name', '')} "
              f"({cfg.get('MetricName', '')} {cfg.get('ComparisonOperator', '')} "
              f"{cfg.get('Threshold', '')})")
        w("")
    else:
        w("⚠️ **No CloudWatch alarms configured.**")
        w("")

    # ── Anomalies ──
    if model.anomalies:
        w("## Operational Findings")
        w("")
        for a in model.anomalies:
            icon = {'critical': '🔴', 'warning': '🟡', 'info': '🔵'}.get(
                a['severity'], '⚪')
            w(f"- {icon} **{a['resource']}**: {a['issue']}")
        w("")

    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

RENDERERS = {
    'executive': render_executive,
    'engineering': render_engineering,
    'operations': render_operations,
}


def main():
    parser = argparse.ArgumentParser(
        description='Graph Discovery — Audience-driven AWS architecture views.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Audiences:
  executive    Abstract overview, no IDs. For leadership presentations.
  engineering  Full detail with topology, security, anomalies.
  operations   Recovery-focused with IDs, IPs, DR notes.

Examples:
  python3 graph_discover.py --input output/inventory-us-gov-west-1.yaml --audience executive
  python3 graph_discover.py --input output/inventory-us-gov-west-1.yaml --audience engineering
  python3 graph_discover.py --input output/inventory-us-gov-west-1.yaml --audience all
        """,
    )
    parser.add_argument('--input', required=True,
                        help='Path to inventory YAML or JSON from deep_discover.py')
    parser.add_argument('--audience', default='all',
                        choices=['executive', 'engineering', 'operations', 'all'],
                        help='Target audience (default: all)')
    parser.add_argument('--output', default='',
                        help='Output directory (default: same as input)')
    args = parser.parse_args()

    # Load inventory
    input_path = args.input
    if input_path.endswith('.json'):
        with open(input_path, 'r') as f:
            inventory = json.load(f)
    else:
        with open(input_path, 'r') as f:
            inventory = yaml.safe_load(f)

    if not inventory or 'resources' not in inventory:
        print(f"ERROR: No resources found in {input_path}")
        sys.exit(1)

    # Build model
    model = InventoryModel(inventory)
    region = model.meta.get('region', 'unknown')

    total = len(model.all_resources)
    print(f"Loaded {total} resources from {input_path}")
    print(f"Anomalies detected: {len(model.anomalies)}")

    # Determine output directory
    output_dir = args.output or os.path.dirname(os.path.abspath(input_path))
    os.makedirs(output_dir, exist_ok=True)

    # Render
    audiences = list(RENDERERS.keys()) if args.audience == 'all' else [args.audience]

    for audience in audiences:
        renderer = RENDERERS[audience]
        content = renderer(model)
        filename = f"architecture-{audience}-{region}.md"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w', newline='\n') as f:
            f.write(content)
        print(f"  ✓ {audience:15s} → {filepath}")

    # Always generate the draw.io diagram
    drawio_path = os.path.join(output_dir, f"architecture-{region}.drawio")
    render_drawio(model, drawio_path)

    print(f"\nDone. {len(audiences)} markdown view(s) + 1 draw.io diagram generated.")


if __name__ == "__main__":
    main()
