#!/usr/bin/env python3
"""
IaC Blueprint v3 — Graph-Driven DR Template Generator

Reads inventory from deep_discover.py and produces operator-ready
CloudFormation templates grouped by dependency graph analysis.

Templates are self-contained and deployable via CloudFormation console
or CLI. Each template has typed parameters with source-value defaults,
proper cross-stack !ImportValue from named stack parameters, and
only deploy-relevant properties (no runtime state).

Usage:
    python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730/
    python3 iac_blueprint.py --input output/Instem/us-gov-west-1/20260730/ --v1
"""

import yaml
import os
import sys
import glob
import argparse
from datetime import datetime, timezone
from collections import OrderedDict, defaultdict

from dependency_graph import (
    build_deployment_plan, print_plan_summary,
    DeploymentPlan, MANUAL_ONLY,
)
from schema_template_generator import generate_group_template


# ═══════════════════════════════════════════════════════════════════
# YAML helpers
# ═══════════════════════════════════════════════════════════════════

def ordered_dict_representer(dumper, data):
    return dumper.represent_mapping('tag:yaml.org,2002:map', data.items())

yaml.add_representer(OrderedDict, ordered_dict_representer)


# ═══════════════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════════════

def write_template(template: dict, filepath: str, header: str = ''):
    """Write a CFN template as YAML with header comments."""
    with open(filepath, 'w', encoding='utf-8') as f:
        if header:
            for line in header.strip().split('\n'):
                f.write(f"# {line}\n")
            f.write('\n')
        yaml.dump(dict(template), f, default_flow_style=False,
                  allow_unicode=True, sort_keys=False, width=120)
    print(f"  Written: {os.path.basename(filepath)}")


def generate_deploy_guide(plan: DeploymentPlan, output_dir: str):
    """Write DEPLOY.md from the deployment plan."""
    filepath = os.path.join(output_dir, 'DEPLOY.md')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# DR Deployment Guide\n\n")
        f.write(f"**Source Account:** {plan.account_id}\n")
        f.write(f"**Source Region:** {plan.region}\n")
        f.write(f"**Generated:** {datetime.now(tz=timezone.utc).isoformat()}\n")
        f.write(f"**Generator:** iac_blueprint.py v3 (graph-driven)\n\n---\n\n")

        f.write("## Pre-Deployment Checklist\n\n")
        f.write("- [ ] Copy customer-owned AMIs to DR region\n")
        f.write("- [ ] Copy latest EBS snapshots / RDS snapshots to DR region\n")
        f.write("- [ ] Copy FSx backups to DR region\n")
        f.write("- [ ] Run `scripts/replicate-secrets.py`\n")
        f.write("- [ ] Run `scripts/replicate-parameters.py`\n")
        f.write("- [ ] Verify ACM certificate DNS validation\n")
        f.write("- [ ] Confirm VPN peer IPs reachable from DR\n\n")

        f.write("## Deployment Sequence\n\n")
        f.write("| # | Template | Description | Depends On |\n")
        f.write("|---|----------|-------------|------------|\n")
        for g in plan.groups:
            deps = ', '.join(g.depends_on[:4]) or 'None'
            if len(g.depends_on) > 4:
                deps += f' +{len(g.depends_on) - 4}'
            f.write(f"| {g.order} | `{g.order:02d}-{g.name}.yaml` "
                    f"| {len(g.resources)} resources | {deps} |\n")

        f.write("\n## Critical: Domain Controller Boot Order\n\n")
        dc = plan.group_by_name('dc_compute')
        if dc:
            f.write("**Deploy `dc_compute` and verify AD health BEFORE "
                    "deploying `compute` or `data` (FSx).**\n\n")
            f.write("1. Deploy dc_compute stack\n")
            f.write("2. Wait for instances to pass both status checks\n")
            f.write("3. Verify via SSM: `dcdiag /s:localhost`\n")
            f.write("4. Then proceed with remaining stacks\n\n")

        f.write("## Post-Deployment\n\n")
        f.write("- [ ] Register targets with Target Groups (new instance IDs)\n")
        f.write("- [ ] Update DHCP DNS to DR DC private IPs\n")
        f.write("- [ ] Verify DNS resolution from all instances\n")
        f.write("- [ ] Test application connectivity end-to-end\n")
        f.write("- [ ] Re-establish VPN tunnels\n")
    print(f"  Written: DEPLOY.md")


def generate_manual_steps(inventory: dict, output_dir: str):
    """Write manual-steps.md for non-CFN resources."""
    resources = inventory.get('resources', {})
    filepath = os.path.join(output_dir, 'manual-steps.md')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Manual Steps Required\n\n")
        f.write("These resources cannot be reproduced via CloudFormation.\n\n")
        for category in sorted(MANUAL_ONLY):
            items = resources.get(category, [])
            if not items:
                continue
            f.write(f"## {category} ({len(items)} items)\n\n")
            if category == 'Secrets':
                f.write("Run `scripts/replicate-secrets.py` to copy.\n\n")
            elif category == 'SSM Parameters':
                f.write("Run `scripts/replicate-parameters.py` to copy.\n\n")
            for item in items:
                f.write(f"- **{item.get('name', 'unnamed')}**\n")
            f.write("\n")
    print(f"  Written: manual-steps.md")


# ═══════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def run_graph_driven(inventory: dict, output_dir: str, region: str):
    """Main pipeline: graph → partition → generate templates."""

    print(f"\n{'═' * 60}")
    print(f"IaC Blueprint v3 — Graph-Driven Generation")
    print(f"{'═' * 60}")

    # Build deployment plan
    plan = build_deployment_plan(inventory, region=region)
    print_plan_summary(plan)

    if not plan.groups:
        print("ERROR: No deployment groups generated.")
        return

    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    templates_dir = os.path.join(output_dir, 'templates')
    os.makedirs(templates_dir, exist_ok=True)

    # Generate templates per group
    sg_id_to_logical = {}
    print(f"\n  Generating templates...")

    for group in plan.groups:
        filename = f'{group.order:02d}-{group.name}.yaml'
        filepath = os.path.join(templates_dir, filename)

        header = (
            f'DR {group.name} — {group.description}\n'
            f'Template: {filename}\n'
            f'Dependencies: {", ".join(group.depends_on) or "None"}\n'
            f'Generated: {datetime.now(tz=timezone.utc).isoformat()}\n'
            f'Deploy via: aws cloudformation create-stack --stack-name dr-{group.name} '
            f'--template-body file://{filename} --capabilities CAPABILITY_IAM'
        )

        template, sg_id_to_logical = generate_group_template(
            group, inventory, sg_id_to_logical)

        write_template(template, filepath, header)

    # Documentation
    print()
    generate_deploy_guide(plan, output_dir)
    generate_manual_steps(inventory, output_dir)

    # Summary
    print(f"\n{'═' * 60}")
    print(f"Done. {len(plan.groups)} templates in {templates_dir}/")
    print(f"  DEPLOY.md:       {output_dir}/DEPLOY.md")
    print(f"  manual-steps.md: {output_dir}/manual-steps.md")
    if plan.unmapped_categories:
        print(f"\n  Unmapped (no CFN type, not generated):")
        for cat in sorted(plan.unmapped_categories)[:10]:
            print(f"    - {cat}")
    print(f"{'═' * 60}")


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='IaC Blueprint v3 — Graph-driven DR template generation.')
    parser.add_argument('--input', required=True,
                        help='Path to a discovery run directory')
    parser.add_argument('--mode', default='dr', choices=['import', 'dr'],
                        help='Generation mode (default: dr)')
    parser.add_argument('--v1', action='store_true',
                        help='Use v1 tier-based generator (fallback)')
    args = parser.parse_args()

    if args.v1:
        print("Using v1 (tier-based) generator...")
        import iac_blueprint_v1
        sys.argv = ['iac_blueprint_v1.py', '--input', args.input, '--mode', args.mode]
        iac_blueprint_v1.main()
        return

    input_dir = os.path.abspath(args.input)
    if not os.path.isdir(input_dir):
        print(f"ERROR: Directory not found: {input_dir}")
        sys.exit(1)

    matches = glob.glob(os.path.join(input_dir, 'inventory-*.yaml'))
    if not matches:
        print(f"ERROR: No inventory-*.yaml in {input_dir}")
        sys.exit(1)

    inventory_path = matches[0]
    print(f"Loading: {inventory_path}")
    with open(inventory_path, 'r', encoding='utf-8') as f:
        inventory = yaml.safe_load(f)

    meta = inventory.get('metadata', {})
    region = meta.get('region', 'unknown')
    print(f"Account: {meta.get('account_id')}, Region: {region}")

    output_dir = os.path.join(input_dir, 'iac-templates')
    run_graph_driven(inventory, output_dir, region)


if __name__ == "__main__":
    main()
