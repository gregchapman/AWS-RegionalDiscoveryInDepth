#!/usr/bin/env python3
"""
IaC Blueprint v3 — Graph-Driven DR Template Generator

Reads the YAML inventory produced by deep_discover.py and generates
CloudFormation templates grouped into deployment stacks determined by
a dependency graph. No hardcoded tier structure — the number and
contents of output stacks are derived from analyzing the resources.

Architecture:
  1. Load inventory
  2. Build dependency graph (dependency_graph.py)
  3. Partition into deployment groups
  4. For each group:
     - If bespoke handler exists (SGs, LBs) → use it
     - Otherwise → schema-driven generation (schema_template_generator.py)
  5. Generate DEPLOY.md from graph ordering
  6. Generate manual-steps.md for non-CFN resources

Bespoke handlers are retained for:
  - Security Groups: cross-SG references need !Ref within same template,
    self-referencing rules need separate SecurityGroupIngress resources
  - Load Balancers: Listener→TG→Target action wiring, forward config
    with multiple TGs, and conditional TLS certificate handling

Everything else goes through the generic schema-driven path.

Usage:
    python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730/
    python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730/ --mode dr
    python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730/ --v1
"""

import yaml
import os
import sys
import re
import glob
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import OrderedDict, defaultdict

from dependency_graph import (
    build_deployment_plan, compute_cross_group_refs,
    print_plan_summary, DeploymentPlan, DeploymentGroup,
    ResourceNode, ASSESSMENT_ONLY, MANUAL_ONLY,
)
from schema_template_generator import (
    generate_resource_block, generate_group_template,
    safe_logical_id, ResourceBlock,
)


# ═══════════════════════════════════════════════════════════════════
# YAML helpers
# ═══════════════════════════════════════════════════════════════════

def ordered_dict_representer(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items())

yaml.add_representer(OrderedDict, ordered_dict_representer)


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
    """Write a YAML parameter file with inline comments."""
    comments = comments or {}
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Parameter file — fill in DR-region values before deploying.\n")
        f.write("# Source values shown in comments for reference.\n")
        f.write("# Fields marked IMMUTABLE cannot be changed after creation.\n")
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
# BESPOKE HANDLER: SECURITY GROUPS
#
# SGs need special handling because:
#   1. Cross-SG references must use !Ref (same template)
#   2. Self-referencing rules need separate SecurityGroupIngress resources
#   3. Excluded/infrastructure SGs must not be referenced
# ═══════════════════════════════════════════════════════════════════

def generate_security_groups_bespoke(resources: List[ResourceNode],
                                     foundation_stack: str = 'foundationStack',
                                     ) -> Tuple[OrderedDict, OrderedDict, Dict]:
    """Generate the security groups template with cross-ref resolution."""

    # Build SG ID -> logical name map
    sg_id_to_logical = {}
    for node in resources:
        sg_id = node.config.get('GroupId', node.resource_id)
        sg_name = node.config.get('GroupName', sg_id)
        sg_id_to_logical[sg_id] = safe_logical_id(sg_name)

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Security Groups — {len(resources)} SGs with cross-references '
        f'resolved via Ref.'
    )
    t['Parameters'] = OrderedDict()
    t['Parameters'][foundation_stack] = {
        'Type': 'String', 'Default': 'dr-foundation',
        'Description': 'Name of the foundation stack (provides VpcId)',
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
                    # Self-reference — separate resource
                    entry['SourceSecurityGroupId'] = {'Ref': logical}
                    if sg_pair.get('Description'):
                        entry['Description'] = sg_pair['Description']
                    self_ref_rules.append(entry)
                elif ref_sg_id in sg_id_to_logical:
                    # Cross-SG reference within same template
                    entry['SourceSecurityGroupId'] = {
                        'Ref': sg_id_to_logical[ref_sg_id]}
                    if sg_pair.get('Description'):
                        entry['Description'] = sg_pair['Description']
                    ingress_rules.append(entry)

        sg_resource = OrderedDict()
        sg_resource['Type'] = 'AWS::EC2::SecurityGroup'
        sg_resource['Properties'] = OrderedDict([
            ('GroupDescription', description),
            ('GroupName', f'{sg_name}-DR'),
            ('VpcId', {'Fn::ImportValue': {
                'Fn::Sub': f'${{{foundation_stack}}}-VpcId'}}),
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

        # Output — export SG ID
        t['Outputs'][f'{logical}Id'] = {
            'Value': {'Fn::GetAtt': [logical, 'GroupId']},
            'Description': f'{sg_name} (source: {sg_id})',
            'Export': {'Name': {'Fn::Sub': f'${{AWS::StackName}}-{logical}'}},
        }

    params = OrderedDict()
    comments = {}
    params[foundation_stack] = 'dr-foundation'
    comments[foundation_stack] = 'Stack name for foundation (VPC/Subnets)'

    return t, params, comments, sg_id_to_logical


# ═══════════════════════════════════════════════════════════════════
# BESPOKE HANDLER: LOAD BALANCERS / NETWORK TIER
#
# LBs need special handling because:
#   1. LB → Listener → TG → Target is an ordered chain
#   2. DefaultActions reference TGs by Ref (same template)
#   3. TLS listeners need conditional certificate handling
#   4. Gateway LBs are excluded (infrastructure-managed)
# ═══════════════════════════════════════════════════════════════════

def generate_network_bespoke(resources: List[ResourceNode],
                             inventory: dict,
                             sg_id_to_logical: Dict[str, str],
                             foundation_stack: str = 'foundationStack',
                             sg_stack: str = 'securityStack',
                             ) -> Tuple[OrderedDict, OrderedDict, Dict]:
    """Generate network tier template with LB/TG/Listener wiring."""

    # Separate resource types
    lbs = [r for r in resources if r.category == 'Load Balancers']
    tgs = [r for r in resources if r.category == 'Target Groups']
    listeners = [r for r in resources if r.category == 'Listeners']

    # Also pull listener/TG data from full inventory for cross-referencing
    all_resources = inventory.get('resources', {})
    all_tgs = all_resources.get('Target Groups', [])
    all_listeners = all_resources.get('Listeners', [])

    # Skip gateway LBs
    customer_lbs = [lb for lb in lbs
                    if lb.config.get('Type', '') != 'gateway']

    t = OrderedDict()
    t['AWSTemplateFormatVersion'] = '2010-09-09'
    t['Description'] = (
        f'DR Network Tier — {len(customer_lbs)} load balancers '
        f'with listeners and target groups.'
    )
    t['Parameters'] = OrderedDict()
    t['Parameters'][foundation_stack] = {
        'Type': 'String', 'Default': 'dr-foundation'}
    t['Parameters'][sg_stack] = {
        'Type': 'String', 'Default': 'dr-security'}
    t['Parameters']['LBSubnet1'] = {
        'Type': 'AWS::EC2::Subnet::Id',
        'Description': 'Subnet AZ1 for load balancers',
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

    # Maps for wiring
    tg_arn_to_name = {}
    for tg_item in all_tgs:
        arn = tg_item.get('config', {}).get('TargetGroupArn', '')
        name = tg_item.get('config', {}).get('TargetGroupName', '')
        tg_arn_to_name[arn] = name

    lb_arn_to_name = {}
    for lb in customer_lbs:
        arn = lb.config.get('LoadBalancerArn', '')
        lb_arn_to_name[arn] = lb.config.get('LoadBalancerName', '')

    # ── Load Balancers ──
    for lb in customer_lbs:
        lc = lb.config
        lb_name = lc.get('LoadBalancerName', 'unnamed')
        lb_logical = safe_logical_id(lb_name)

        lb_props = OrderedDict()
        lb_props['Name'] = lb_name
        lb_props['Type'] = lc.get('Type', 'network')
        lb_props['Scheme'] = lc.get('Scheme', 'internet-facing')
        lb_props['Subnets'] = [{'Ref': 'LBSubnet1'}, {'Ref': 'LBSubnet2'}]
        lb_props['IpAddressType'] = lc.get('IpAddressType', 'ipv4')

        sg_refs = []
        for sg_id in (lc.get('SecurityGroups') or []):
            if isinstance(sg_id, str) and sg_id in sg_id_to_logical:
                sg_refs.append({'Fn::ImportValue': {
                    'Fn::Sub': f'${{{sg_stack}}}-{sg_id_to_logical[sg_id]}'}})
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
            'Export': {'Name': {
                'Fn::Sub': f'${{AWS::StackName}}-{lb_logical}DnsName'}},
        }

    # ── Target Groups ──
    for tg_item in all_tgs:
        tc = tg_item.get('config', {})
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
        tg_props['VpcId'] = {'Fn::ImportValue': {
            'Fn::Sub': f'${{{foundation_stack}}}-VpcId'}}
        tg_props['TargetType'] = tc.get('TargetType', 'instance')
        tg_props['HealthCheckEnabled'] = tc.get('HealthCheckEnabled', True)
        tg_props['HealthCheckProtocol'] = tc.get('HealthCheckProtocol', 'TCP')
        if tc.get('HealthCheckPath'):
            tg_props['HealthCheckPath'] = tc['HealthCheckPath']
        tg_props['HealthCheckIntervalSeconds'] = tc.get(
            'HealthCheckIntervalSeconds', 30)
        tg_props['HealthyThresholdCount'] = tc.get('HealthyThresholdCount', 5)
        tg_props['UnhealthyThresholdCount'] = tc.get(
            'UnhealthyThresholdCount', 2)
        tg_props['Tags'] = [
            {'Key': 'Name', 'Value': tg_name},
            {'Key': 'SourceTGArn', 'Value': tc.get('TargetGroupArn', '')},
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
            ln_props['Certificates'] = [
                {'CertificateArn': {'Ref': 'CertificateArn'}}]
        if lc.get('SslPolicy'):
            ln_props['SslPolicy'] = lc['SslPolicy']

        # Default action — forward to target group
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

        if 'DefaultActions' not in ln_props:
            # Try ForwardConfig
            if default_actions:
                fc = default_actions[0].get('ForwardConfig', {})
                tg_list = fc.get('TargetGroups', [])
                if tg_list:
                    tg_arn = tg_list[0].get('TargetGroupArn', '')
                    tg_name = tg_arn_to_name.get(tg_arn, '')
                    if tg_name:
                        ln_props['DefaultActions'] = [{
                            'Type': 'forward',
                            'TargetGroupArn': {
                                'Ref': safe_logical_id(tg_name)},
                        }]

        if 'DefaultActions' not in ln_props:
            continue  # Skip unresolvable listeners

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
# TIERS THAT USE BESPOKE HANDLERS
# ═══════════════════════════════════════════════════════════════════

BESPOKE_TIERS = {'security', 'network'}


# ═══════════════════════════════════════════════════════════════════
# DEPLOY.md GENERATOR
# ═══════════════════════════════════════════════════════════════════

def generate_deploy_guide(plan: DeploymentPlan, output_dir: str,
                          files_written: List[str]):
    """Write DEPLOY.md from the deployment plan."""
    meta_region = plan.region
    meta_account = plan.account_id
    filepath = os.path.join(output_dir, 'DEPLOY.md')

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# DR Deployment Guide\n\n")
        f.write(f"**Source Account:** {meta_account}\n")
        f.write(f"**Source Region:** {meta_region}\n")
        f.write(f"**Generated:** {datetime.now(tz=timezone.utc).isoformat()}\n")
        f.write(f"**Generator:** iac_blueprint.py v3 (graph-driven)\n\n")
        f.write("---\n\n")

        f.write("## Pre-Deployment Checklist\n\n")
        f.write("- [ ] Copy customer-owned AMIs to DR region\n")
        f.write("- [ ] Copy latest EBS snapshots to DR region\n")
        f.write("- [ ] Copy FSx backups to DR region\n")
        f.write("- [ ] Copy RDS/Aurora snapshots to DR region\n")
        f.write("- [ ] Run `scripts/replicate-secrets.py`\n")
        f.write("- [ ] Run `scripts/replicate-parameters.py`\n")
        f.write("- [ ] Verify ACM certificate DNS validation\n")
        f.write("- [ ] Confirm VPN peer IPs reachable from DR region\n\n")

        f.write("## Deployment Order\n\n")
        f.write("Deploy each group in sequence. Wait for completion "
                "before proceeding to the next.\n\n")
        f.write("| # | Stack | Resources | Dependencies | "
                "Pre-Steps | Post-Steps |\n")
        f.write("|---|-------|:---------:|--------------|"
                "-----------|------------|\n")

        for g in plan.groups:
            deps = ', '.join(g.depends_on[:3]) or 'None'
            if len(g.depends_on) > 3:
                deps += f' +{len(g.depends_on) - 3}'
            pre = '; '.join(g.pre_steps[:2]) if g.pre_steps else '—'
            post = '; '.join(g.post_steps[:2]) if g.post_steps else '—'
            f.write(f"| {g.order} | `{g.name}` | {len(g.resources)} "
                    f"| {deps} | {pre} | {post} |\n")

        f.write("\n## Critical Notes\n\n")

        # DC boot order
        dc_group = plan.group_by_name('dc_compute')
        if dc_group:
            f.write("### Domain Controller Boot Order\n\n")
            f.write("**dc_compute must deploy and verify healthy BEFORE "
                    "compute or data (FSx).**\n\n")
            f.write("After deploying dc_compute:\n")
            f.write("1. Wait for instances to pass both status checks\n")
            f.write("2. Verify AD health via SSM: `dcdiag /s:localhost`\n")
            f.write("3. Then proceed with dependent stacks.\n\n")

        f.write("## Post-Deployment\n\n")
        f.write("- [ ] Register targets with Target Groups\n")
        f.write("- [ ] Update DHCP DNS to DR DC private IPs\n")
        f.write("- [ ] Verify DNS resolution\n")
        f.write("- [ ] Test application connectivity end-to-end\n")
        f.write("- [ ] Re-establish VPN tunnels\n")
        f.write("- [ ] Validate CloudWatch alarms\n")

    print(f"  Written: DEPLOY.md")


# ═══════════════════════════════════════════════════════════════════
# MANUAL STEPS
# ═══════════════════════════════════════════════════════════════════

def generate_manual_steps(inventory: dict, output_dir: str):
    """Write manual-steps.md for non-CFN resources."""
    resources = inventory.get('resources', {})
    manual_items = []

    for category in MANUAL_ONLY:
        items = resources.get(category, [])
        for r in items:
            manual_items.append({
                'category': category,
                'name': r.get('name', 'unnamed'),
            })

    filepath = os.path.join(output_dir, 'manual-steps.md')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Manual Steps Required\n\n")
        f.write("These resources require manual action — they cannot be "
                "reproduced via CloudFormation.\n\n")

        by_category = defaultdict(list)
        for item in manual_items:
            by_category[item['category']].append(item)

        for category in sorted(by_category.keys()):
            items = by_category[category]
            f.write(f"## {category} ({len(items)} items)\n\n")
            if category == 'Secrets':
                f.write("Run `scripts/replicate-secrets.py` to copy.\n\n")
            elif category == 'SSM Parameters':
                f.write("Run `scripts/replicate-parameters.py` to copy.\n\n")
            for item in items:
                f.write(f"- **{item['name']}**\n")
            f.write("\n")

    print(f"  Written: manual-steps.md ({len(manual_items)} items)")


# ═══════════════════════════════════════════════════════════════════
# SCHEMA CACHE INTEGRATION
# ═══════════════════════════════════════════════════════════════════

def _load_schemas(cfn_types: Set[str], region: str) -> Dict[str, dict]:
    """Try to load schemas for all CFN types. Graceful if unavailable."""
    try:
        from cfn_schema_cache import get_all_schemas_for_types
        return get_all_schemas_for_types(list(cfn_types), region)
    except Exception:
        return {}


# ═══════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def run_graph_driven(inventory: dict, output_dir: str, region: str):
    """Main graph-driven IaC generation pipeline.

    1. Build deployment plan from inventory
    2. For each group: use bespoke handler or schema-driven generation
    3. Write templates, params, DEPLOY.md
    """
    print(f"\n{'═' * 60}")
    print(f"IaC Blueprint v3 — Graph-Driven Generation")
    print(f"{'═' * 60}")

    # Step 1: Build deployment plan
    plan = build_deployment_plan(inventory, region=region)
    print_plan_summary(plan)

    if not plan.groups:
        print("ERROR: No deployment groups generated. Check inventory.")
        return

    # Step 2: Compute cross-group references
    cross_refs = compute_cross_group_refs(plan)

    # Build set of all resource IDs that are in OTHER groups (for each group)
    all_ids_by_group: Dict[str, Set[str]] = {}
    for group in plan.groups:
        own_ids = {r.resource_id for r in group.resources}
        other_ids = set()
        for other_group in plan.groups:
            if other_group.name != group.name:
                other_ids.update(r.resource_id for r in other_group.resources)
        all_ids_by_group[group.name] = other_ids

    # Step 3: Load schemas for all CFN types in the plan
    all_cfn_types = set()
    for group in plan.groups:
        all_cfn_types.update(r.cfn_type for r in group.resources)
    schemas = _load_schemas(all_cfn_types, region)
    if schemas:
        print(f"\n  Schemas loaded: {len(schemas)}/{len(all_cfn_types)} types")
    else:
        print(f"\n  Schemas: none available (using fallback mode)")

    # Step 4: Generate templates per group
    os.makedirs(output_dir, exist_ok=True)
    templates_dir = os.path.join(output_dir, 'templates')
    params_dir = os.path.join(output_dir, 'params')
    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(params_dir, exist_ok=True)

    files_written = []
    sg_id_to_logical = {}  # Populated by SG bespoke handler

    print(f"\n  Generating templates in {templates_dir}/...")

    for group in plan.groups:
        print(f"\n─── {group.name} ({len(group.resources)} resources) ───")

        filename = f'{group.order:02d}-{group.name}.yaml'
        params_filename = f'{group.order:02d}-{group.name}-params.yaml'
        template_path = os.path.join(templates_dir, filename)
        params_path = os.path.join(params_dir, params_filename)

        header = (
            f'DR {group.name} — {group.description}\n'
            f'Dependencies: {", ".join(group.depends_on) or "None"}\n'
            f'Generated: {datetime.now(tz=timezone.utc).isoformat()}'
        )

        if group.name.startswith('security') and group.resources:
            # Bespoke: Security Groups
            template, param_vals, param_comments, sg_map = (
                generate_security_groups_bespoke(group.resources))
            sg_id_to_logical.update(sg_map)
            write_template(template, template_path, header)
            write_params_yaml(param_vals, params_path, param_comments)

        elif group.name.startswith('network') and group.resources:
            # Bespoke: Load Balancers / Network
            template, param_vals, param_comments = (
                generate_network_bespoke(
                    group.resources, inventory, sg_id_to_logical))
            write_template(template, template_path, header)
            write_params_yaml(param_vals, params_path, param_comments)

        else:
            # Schema-driven generation (default path)
            cross_ids = all_ids_by_group.get(group.name, set())
            template, param_vals, param_comments = generate_group_template(
                group_name=group.name,
                resources=group.resources,
                region=region,
                cross_stack_ids=cross_ids,
                schemas=schemas,
                description=group.description,
                depends_on_stacks=group.depends_on,
            )
            write_template(template, template_path, header)
            write_params_yaml(param_vals, params_path, param_comments)

        files_written.append(filename)

    # Step 5: Generate DEPLOY.md and manual-steps.md
    print(f"\n─── Documentation ───")
    generate_deploy_guide(plan, output_dir, files_written)
    generate_manual_steps(inventory, output_dir)

    # Summary
    print(f"\n{'═' * 60}")
    print(f"Done. {len(files_written)} templates generated.")
    print(f"  Templates:  {templates_dir}/")
    print(f"  Params:     {params_dir}/")
    print(f"  Guide:      {output_dir}/DEPLOY.md")
    print(f"  Manual:     {output_dir}/manual-steps.md")
    if plan.unmapped_categories:
        print(f"\n  ⚠ Unmapped categories (no CFN type, not generated):")
        for cat in sorted(plan.unmapped_categories):
            print(f"    - {cat}")
    print(f"{'═' * 60}")


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def find_inventory_file(input_dir: str) -> Optional[str]:
    """Find the inventory YAML file in a run directory."""
    matches = glob.glob(os.path.join(input_dir, 'inventory-*.yaml'))
    return matches[0] if matches else None


def main():
    parser = argparse.ArgumentParser(
        description='IaC Blueprint v3 — Graph-driven DR template generation.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730/
  python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730/ --v1
        """,
    )
    parser.add_argument('--input', required=True,
                        help='Path to a discovery run directory')
    parser.add_argument('--mode', default='dr', choices=['import', 'dr'],
                        help='Generation mode: import (exact) or dr (parameterized)')
    parser.add_argument('--v1', action='store_true',
                        help='Use v1 tier-based generator (fallback)')
    args = parser.parse_args()

    # Fallback to v1 if requested
    if args.v1:
        print("Using v1 (tier-based) generator...")
        import iac_blueprint_v1
        sys.argv = ['iac_blueprint_v1.py', '--input', args.input,
                    '--mode', args.mode]
        iac_blueprint_v1.main()
        return

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

    # Output directory
    output_dir = os.path.join(input_dir, 'iac-templates')

    # Run graph-driven pipeline
    run_graph_driven(inventory, output_dir, region)


if __name__ == "__main__":
    main()
