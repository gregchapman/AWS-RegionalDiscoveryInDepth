#!/usr/bin/env python3
"""Quick smoke test for dependency_graph.py"""
from dependency_graph import (
    build_deployment_plan, DeploymentPlan, DeploymentGroup,
    ResourceNode, compute_cross_group_refs, print_plan_summary,
    TIER_ORDER, CATEGORY_TO_TIER, is_domain_controller
)

# Minimal fake inventory to validate the flow
fake_inventory = {
    'metadata': {
        'account_id': '048766100331',
        'region': 'us-gov-west-1',
    },
    'resources': {
        'VPCs': [
            {'resource_id': 'vpc-abc123', 'name': 'MainVPC',
             'config': {'VpcId': 'vpc-abc123', 'CidrBlock': '10.0.0.0/16',
                        'Tags': {'Name': 'MainVPC'}}}
        ],
        'Subnets': [
            {'resource_id': 'subnet-001', 'name': 'Private-A',
             'config': {'SubnetId': 'subnet-001', 'VpcId': 'vpc-abc123',
                        'CidrBlock': '10.0.1.0/24',
                        'AvailabilityZone': 'us-gov-west-1a',
                        'Tags': {'Name': 'Private-A'}}},
        ],
        'Security Groups': [
            {'resource_id': 'sg-001', 'name': 'WebSG',
             'config': {'GroupId': 'sg-001', 'VpcId': 'vpc-abc123',
                        'GroupName': 'WebSG', 'Tags': {}}},
        ],
        'EC2 Instances': [
            {'resource_id': 'i-dc001', 'name': 'primary/DC1',
             'config': {'InstanceId': 'i-dc001', 'SubnetId': 'subnet-001',
                        'InstanceType': 'm5.large', 'ImageId': 'ami-111',
                        'GroupId': ['sg-001'],
                        'Tags': {'Name': 'primary/DC1', 'Role': 'DC'}}},
            {'resource_id': 'i-app001', 'name': 'AppServer1',
             'config': {'InstanceId': 'i-app001', 'SubnetId': 'subnet-001',
                        'InstanceType': 't3.medium', 'ImageId': 'ami-222',
                        'GroupId': ['sg-001'],
                        'Tags': {'Name': 'AppServer1'}}},
        ],
        'KMS Keys': [
            {'resource_id': 'key-001', 'name': 'MyKey',
             'config': {'KeyId': 'key-001', 'Enabled': True,
                        'Tags': {}}},
        ],
        'Load Balancers': [
            {'resource_id': 'arn:nlb-001', 'name': 'NLB-Web',
             'config': {'LoadBalancerArn': 'arn:nlb-001',
                        'LoadBalancerName': 'NLB-Web',
                        'Type': 'network', 'Scheme': 'internal',
                        'VpcId': 'vpc-abc123', 'Tags': {}}},
        ],
        # Assessment-only should be skipped
        'EBS Snapshots': [
            {'resource_id': 'snap-001', 'name': 'snap',
             'config': {'Tags': {}}},
        ],
    },
}

plan = build_deployment_plan(fake_inventory)
print_plan_summary(plan)

# Validate structure
assert isinstance(plan, DeploymentPlan)
assert len(plan.groups) > 0
assert plan.account_id == '048766100331'
assert plan.region == 'us-gov-west-1'
assert 'EBS Snapshots' in plan.skipped_categories

# Validate DC detection
dc_group = plan.group_by_name('dc_compute')
compute_group = plan.group_by_name('compute')
assert dc_group is not None, "DC group should exist"
assert compute_group is not None, "Compute group should exist"
assert len(dc_group.resources) == 1
assert dc_group.resources[0].name == 'primary/DC1'
assert len(compute_group.resources) == 1
assert compute_group.resources[0].name == 'AppServer1'

# Validate ordering
group_names = [g.name for g in plan.groups]
assert group_names.index('foundation') < group_names.index('security')
assert group_names.index('security') < group_names.index('compute')
assert group_names.index('dc_compute') < group_names.index('compute')

# Validate cross-group refs
refs = compute_cross_group_refs(plan)
print(f"\nCross-group refs: {refs}")

print("\n✓ All assertions passed. dependency_graph.py is working.")

# ── Test schema_template_generator integration ──
from schema_template_generator import generate_group_template

compute_group = plan.group_by_name('compute')
template, param_values, param_comments = generate_group_template(
    group_name='compute',
    resources=compute_group.resources,
    region='us-gov-west-1',
    cross_stack_ids={'vpc-abc123', 'subnet-001', 'sg-001'},
    schemas={},  # no schemas in test
    description='DR Compute Tier',
    depends_on_stacks=['foundation', 'security'],
)

assert template['AWSTemplateFormatVersion'] == '2010-09-09'
assert 'AppServer1' in template['Resources']
assert 'foundationStack' in template['Parameters'] or 'securityStack' in template['Parameters']
print("\n✓ generate_group_template integration works.")

# ── Test full orchestrator ──
import os
import tempfile
import yaml as _yaml

# Write fake inventory to a temp dir and run the orchestrator
tmpdir = tempfile.mkdtemp(prefix='iac_test_')
inv_path = os.path.join(tmpdir, 'inventory-us-gov-west-1.yaml')
with open(inv_path, 'w') as f:
    _yaml.dump(fake_inventory, f)

from iac_blueprint import run_graph_driven
run_graph_driven(fake_inventory, os.path.join(tmpdir, 'iac-templates'),
                 'us-gov-west-1')

# Verify output files exist
import os
iac_dir = os.path.join(tmpdir, 'iac-templates')
templates_dir = os.path.join(iac_dir, 'templates')
params_dir = os.path.join(iac_dir, 'params')
assert os.path.isdir(templates_dir), "templates/ dir should exist"
assert os.path.isdir(params_dir), "params/ dir should exist"
assert os.path.isfile(os.path.join(iac_dir, 'DEPLOY.md')), "DEPLOY.md missing"

# Check that template files were created
import glob as _glob
templates = _glob.glob(os.path.join(templates_dir, '*.yaml'))
params = _glob.glob(os.path.join(params_dir, '*.yaml'))
print(f"\nTemplates generated: {len(templates)}")
for t in sorted(templates):
    print(f"  {os.path.basename(t)}")
print(f"Param files: {len(params)}")

assert len(templates) >= 4, f"Expected 4+ templates, got {len(templates)}"
assert len(params) >= 4, f"Expected 4+ param files, got {len(params)}"

# Verify SG template uses bespoke handler (has SecurityGroupIngress pattern)
sg_templates = [t for t in templates if 'security' in os.path.basename(t)]
assert len(sg_templates) > 0, "Security group template should exist"
with open(sg_templates[0]) as f:
    sg_content = f.read()
assert 'SecurityGroupIngress' in sg_content or 'GroupDescription' in sg_content

print("\n✓ Full orchestrator (iac_blueprint.py v3) works end-to-end.")

# Cleanup
import shutil
shutil.rmtree(tmpdir)
