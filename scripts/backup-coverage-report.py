#!/usr/bin/env python3
"""
backup-coverage-report.py

Reads an inventory YAML produced by deep_discover.py and generates a
focused AWS Backup coverage report in markdown.

Highlights:
  - Service opt-in status (which resource types are enabled for Backup)
  - Vault inventory (encryption, lock, recovery point counts)
  - Backup plans and their selections
  - Coverage gap analysis: resources that exist but have NO backup protection
  - Staleness check: protected resources where last backup is older than threshold

Usage:
    python3 backup-coverage-report.py --inventory path/to/inventory-us-gov-west-1.yaml
    python3 backup-coverage-report.py --inventory path/to/inventory-us-east-1.yaml --stale-hours 48
"""

import argparse
import os
import sys
import yaml
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set


# ═══════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate AWS Backup coverage report from discovery inventory."
    )
    parser.add_argument(
        "--inventory", required=True,
        help="Path to inventory YAML file (e.g., inventory-us-gov-west-1.yaml)"
    )
    parser.add_argument(
        "--stale-hours", type=int, default=25,
        help="Flag protected resources with last backup older than this (default: 25 hours)"
    )
    parser.add_argument(
        "--output", default=None,
        help="Output file path (default: backup-report-<region>.md in same directory)"
    )
    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════════
# INVENTORY PARSING
# ═══════════════════════════════════════════════════════════════════

# Resource types that SHOULD be backed up (backable resources)
BACKABLE_RESOURCE_TYPES = {
    'EC2 Instances': 'EC2',
    'RDS Instances': 'RDS',
    'RDS Clusters': 'Aurora',
    'EFS File Systems': 'EFS',
    'DynamoDB Tables': 'DynamoDB',
    'EBS Volumes': 'EBS',
    'FSx File Systems': 'FSx',
    'S3 Buckets': 'S3',
    'Neptune Clusters': 'Neptune',
    'DocumentDB Clusters': 'DocumentDB',
    'Redshift Clusters': 'Redshift',
}


def load_inventory(filepath: str) -> dict:
    """Load the inventory YAML."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def extract_section(resources: dict, section_name: str) -> List[dict]:
    """Extract a named section from the resources dict."""
    return resources.get(section_name, []) or []


def extract_metadata(inventory: dict) -> dict:
    """Extract metadata from inventory."""
    return inventory.get('metadata', {})


# ═══════════════════════════════════════════════════════════════════
# DATA EXTRACTION
# ═══════════════════════════════════════════════════════════════════

def get_region_settings(resources: dict) -> Optional[dict]:
    """Extract Backup region settings (opt-in preferences)."""
    items = extract_section(resources, 'Region Settings')
    if items:
        # The _response pattern puts everything in config
        config = items[0].get('config', {})
        return config
    return None


def get_vaults(resources: dict) -> List[dict]:
    """Extract Backup Vaults."""
    return extract_section(resources, 'Backup Vaults')


def get_plans(resources: dict) -> List[dict]:
    """Extract Backup Plans."""
    return extract_section(resources, 'Backup Plans')


def get_selections(resources: dict) -> List[dict]:
    """Extract Backup Selections."""
    return extract_section(resources, 'Backup Selections')


def get_protected_resources(resources: dict) -> List[dict]:
    """Extract Protected Resources."""
    return extract_section(resources, 'Protected Resources')


def get_backable_resources(resources: dict) -> Dict[str, List[dict]]:
    """Extract all resources that should potentially be backed up."""
    backable = {}
    for section_name, resource_type_label in BACKABLE_RESOURCE_TYPES.items():
        items = extract_section(resources, section_name)
        if items:
            backable[section_name] = items
    return backable


def build_protected_arn_set(protected_resources: List[dict]) -> Set[str]:
    """Build a set of ARNs that are actively protected by Backup."""
    arns = set()
    for res in protected_resources:
        config = res.get('config', {})
        arn = config.get('ResourceArn', '')
        if arn:
            arns.add(arn)
    return arns


# ═══════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_report(inventory: dict, stale_hours: int) -> str:
    """Generate the full markdown report."""
    metadata = extract_metadata(inventory)
    resources = inventory.get('resources', {})

    account_id = metadata.get('account_id', 'Unknown')
    region = metadata.get('region', 'Unknown')
    scan_date = metadata.get('scan_date', 'Unknown')

    lines = []
    lines.append(f"# AWS Backup Coverage Report")
    lines.append(f"")
    lines.append(f"**Account:** `{account_id}`  ")
    lines.append(f"**Region:** `{region}`  ")
    lines.append(f"**Scan Date:** {scan_date}  ")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # ── Section 1: Critical Warnings ──
    vaults = get_vaults(resources)
    plans = get_plans(resources)
    protected = get_protected_resources(resources)
    backable = get_backable_resources(resources)

    total_backable_count = sum(len(items) for items in backable.values())
    protected_arns = build_protected_arn_set(protected)

    warnings = []
    if not plans:
        warnings.append("NO BACKUP PLANS CONFIGURED — resources are NOT being backed up by AWS Backup")
    if not vaults:
        warnings.append("NO BACKUP VAULTS EXIST — AWS Backup has never been configured in this region")
    elif all(v.get('config', {}).get('NumberOfRecoveryPoints', 0) == 0 for v in vaults):
        warnings.append("ALL VAULTS ARE EMPTY — no recovery points exist (nothing has been backed up)")
    if total_backable_count > 0 and not protected:
        warnings.append(f"{total_backable_count} backable resources exist but NONE are protected by AWS Backup")

    if warnings:
        lines.append(f"## CRITICAL WARNINGS")
        lines.append(f"")
        for w in warnings:
            lines.append(f"- **{w}**")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

    # ── Section 2: Service Opt-In Status ──
    lines.append(f"## Service Opt-In Status")
    lines.append(f"")

    region_settings = get_region_settings(resources)
    if region_settings:
        opt_in = region_settings.get('ResourceTypeOptInPreference', {})
        mgmt_pref = region_settings.get('ResourceTypeManagementPreference', {})

        if opt_in:
            lines.append(f"Which resource types are enabled for AWS Backup in this region:")
            lines.append(f"")
            lines.append(f"| Resource Type | Opted In | Management Preference |")
            lines.append(f"|---------------|----------|----------------------|")
            for rtype in sorted(opt_in.keys()):
                opted = opt_in[rtype]
                mgmt = mgmt_pref.get(rtype, '-')
                icon = "Yes" if opted else "**NO**"
                mgmt_str = str(mgmt) if mgmt != '-' else '-'
                lines.append(f"| {rtype} | {icon} | {mgmt_str} |")
            lines.append(f"")

            not_opted = [k for k, v in opt_in.items() if not v]
            if not_opted:
                lines.append(f"**Services NOT opted in:** {', '.join(sorted(not_opted))}")
                lines.append(f"")
                lines.append(f"These resource types CANNOT be backed up by AWS Backup until opted in.")
                lines.append(f"")
        else:
            lines.append(f"Region settings returned but no opt-in preferences found.")
            lines.append(f"")
    else:
        lines.append(f"*Region settings not available in this inventory (run was before template update).*")
        lines.append(f"")
        lines.append(f"Re-run discovery with the updated `backup.yaml` template to capture opt-in status.")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # ── Section 3: Vault Summary ──
    lines.append(f"## Backup Vaults")
    lines.append(f"")

    if vaults:
        lines.append(f"| Vault Name | Recovery Points | Encrypted | Lock Config | Created |")
        lines.append(f"|------------|-----------------|-----------|-------------|---------|")
        for vault in vaults:
            config = vault.get('config', {})
            name = config.get('BackupVaultName', vault.get('name', 'Unknown'))
            rp_count = config.get('NumberOfRecoveryPoints', 0)
            enc_key = config.get('EncryptionKeyArn', '')
            encrypted = "Yes" if enc_key else "No"
            lock = config.get('LockConfiguration', '')
            lock_str = "Yes" if lock and lock != '' else "No"
            created = str(config.get('CreationDate', ''))[:10]
            rp_display = str(rp_count) if rp_count > 0 else "**0 (EMPTY)**"
            lines.append(f"| {name} | {rp_display} | {encrypted} | {lock_str} | {created} |")
        lines.append(f"")
    else:
        lines.append(f"**No backup vaults found.** AWS Backup has not been configured.")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # ── Section 4: Backup Plans ──
    lines.append(f"## Backup Plans")
    lines.append(f"")

    if plans:
        lines.append(f"| Plan Name | Plan ID | Last Execution | Created |")
        lines.append(f"|-----------|---------|----------------|---------|")
        for plan in plans:
            config = plan.get('config', {})
            name = config.get('BackupPlanName', plan.get('name', 'Unknown'))
            plan_id = config.get('BackupPlanId', '')
            last_exec = str(config.get('LastExecutionDate', 'Never'))[:19]
            created = str(config.get('CreationDate', ''))[:10]
            lines.append(f"| {name} | {plan_id} | {last_exec} | {created} |")
        lines.append(f"")

        # Show selections per plan
        selections = get_selections(resources)
        if selections:
            lines.append(f"### Plan Selections (Protected Resource Rules)")
            lines.append(f"")
            lines.append(f"| Selection Name | Plan ID | IAM Role |")
            lines.append(f"|----------------|---------|----------|")
            for sel in selections:
                config = sel.get('config', {})
                sel_name = config.get('SelectionName', sel.get('name', 'Unknown'))
                plan_id = config.get('BackupPlanId', '')
                role = config.get('IamRoleArn', '')
                # Shorten the role ARN for readability
                role_short = role.split('/')[-1] if '/' in role else role
                lines.append(f"| {sel_name} | {plan_id} | {role_short} |")
            lines.append(f"")
    else:
        lines.append(f"**No backup plans configured.** No automated backups are being taken by AWS Backup.")
        lines.append(f"")
        lines.append(f"This means:")
        lines.append(f"- No scheduled backups are running")
        lines.append(f"- No retention policies are enforced")
        lines.append(f"- No cross-region copy rules are active")
        lines.append(f"- Recovery from data loss would require manual snapshots (if any exist)")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # ── Section 5: Coverage Gap Analysis ──
    lines.append(f"## Coverage Gap Analysis")
    lines.append(f"")

    if not backable:
        lines.append(f"No backable resources (EC2, RDS, EBS, EFS, etc.) found in inventory.")
        lines.append(f"")
    else:
        lines.append(f"Resources that exist in the account but are **not protected** by AWS Backup:")
        lines.append(f"")

        total_unprotected = 0
        total_protected = 0

        for section_name, items in sorted(backable.items()):
            protected_count = 0
            unprotected_items = []

            for item in items:
                config = item.get('config', {})
                # Try to match against protected ARNs
                # The resource_id in inventory is usually the ARN
                resource_id = item.get('resource_id', '')
                resource_name = item.get('name', 'unnamed')

                # Also check common ARN fields in config
                arn = (config.get('InstanceArn', '') or
                       config.get('DBInstanceArn', '') or
                       config.get('DBClusterArn', '') or
                       config.get('FileSystemArn', '') or
                       config.get('VolumeArn', '') or
                       config.get('TableArn', '') or
                       config.get('BucketArn', '') or
                       resource_id)

                if arn in protected_arns:
                    protected_count += 1
                else:
                    unprotected_items.append({
                        'name': resource_name,
                        'id': resource_id,
                    })

            total_protected += protected_count
            total_unprotected += len(unprotected_items)

            if unprotected_items:
                lines.append(f"### {section_name} ({len(unprotected_items)} unprotected / {len(items)} total)")
                lines.append(f"")
                lines.append(f"| Resource Name | Resource ID |")
                lines.append(f"|---------------|-------------|")
                for item in unprotected_items:
                    # Truncate long ARNs for readability
                    display_id = item['id']
                    if len(display_id) > 80:
                        display_id = '...' + display_id[-60:]
                    lines.append(f"| {item['name']} | `{display_id}` |")
                lines.append(f"")
            elif items:
                lines.append(f"### {section_name} — All {len(items)} resources protected")
                lines.append(f"")

        lines.append(f"**Summary:** {total_protected} protected, "
                     f"{total_unprotected} unprotected out of "
                     f"{total_protected + total_unprotected} total backable resources")
        lines.append(f"")

        if total_unprotected > 0 and not plans:
            lines.append(f"Since no backup plans exist, ALL resources are effectively unprotected.")
            lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # ── Section 6: Staleness Check ──
    lines.append(f"## Backup Staleness Check")
    lines.append(f"")

    if protected:
        stale_threshold = datetime.now(timezone.utc) - timedelta(hours=stale_hours)
        stale_items = []

        for res in protected:
            config = res.get('config', {})
            last_backup_str = config.get('LastBackupTime', '')
            resource_arn = config.get('ResourceArn', '')
            resource_type = config.get('ResourceType', '')

            if last_backup_str:
                try:
                    # Handle ISO format datetime strings
                    last_backup = datetime.fromisoformat(
                        str(last_backup_str).replace('Z', '+00:00'))
                    if last_backup < stale_threshold:
                        hours_ago = int(
                            (datetime.now(timezone.utc) - last_backup).total_seconds() / 3600)
                        stale_items.append({
                            'arn': resource_arn,
                            'type': resource_type,
                            'last_backup': str(last_backup_str)[:19],
                            'hours_ago': hours_ago,
                        })
                except (ValueError, TypeError):
                    pass

        if stale_items:
            lines.append(f"Resources with last backup older than {stale_hours} hours:")
            lines.append(f"")
            lines.append(f"| Resource Type | Resource ARN | Last Backup | Hours Ago |")
            lines.append(f"|---------------|--------------|-------------|-----------|")
            for item in sorted(stale_items, key=lambda x: x['hours_ago'], reverse=True):
                arn_short = item['arn']
                if len(arn_short) > 70:
                    arn_short = '...' + arn_short[-55:]
                lines.append(f"| {item['type']} | `{arn_short}` | {item['last_backup']} | {item['hours_ago']}h |")
            lines.append(f"")
        else:
            lines.append(f"All protected resources have backups within the last {stale_hours} hours.")
            lines.append(f"")
    else:
        lines.append(f"No protected resources — staleness check not applicable.")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # ── Section 7: Recommendations ──
    lines.append(f"## Recommendations")
    lines.append(f"")

    if not plans:
        lines.append(f"1. **URGENT:** Create a backup plan with appropriate schedule and retention")
        lines.append(f"2. Assign all critical resources (EC2, RDS, EBS) to the plan via selections")
        lines.append(f"3. Configure cross-region copy rules for DR readiness")
        lines.append(f"4. Enable vault lock for compliance/immutability if required")
        lines.append(f"")
    else:
        if total_unprotected > 0:
            lines.append(f"1. Review unprotected resources above and add to backup selections")
            lines.append(f"2. Consider tag-based selections (e.g., `Backup: True`) for automatic coverage")
            lines.append(f"")
        if region_settings:
            opt_in = region_settings.get('ResourceTypeOptInPreference', {})
            not_opted = [k for k, v in opt_in.items() if not v]
            if not_opted:
                lines.append(f"3. Opt in additional services if they contain data: {', '.join(not_opted)}")
                lines.append(f"")

    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    args = parse_args()

    if not os.path.isfile(args.inventory):
        print(f"ERROR: Inventory file not found: {args.inventory}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading inventory: {args.inventory}")
    inventory = load_inventory(args.inventory)

    if not inventory or 'resources' not in inventory:
        print(f"ERROR: Invalid inventory format (no 'resources' key)", file=sys.stderr)
        sys.exit(1)

    print(f"Generating backup coverage report...")
    report = generate_report(inventory, args.stale_hours)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        inv_dir = os.path.dirname(os.path.abspath(args.inventory))
        inv_name = os.path.basename(args.inventory)
        # inventory-us-gov-west-1.yaml -> backup-report-us-gov-west-1.md
        region_part = inv_name.replace('inventory-', '').replace('.yaml', '').replace('.json', '')
        output_path = os.path.join(inv_dir, f"backup-report-{region_part}.md")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"Report written to: {output_path}")
    print()

    # Print a quick summary to stdout
    metadata = extract_metadata(inventory)
    resources = inventory.get('resources', {})
    vaults = get_vaults(resources)
    plans = get_plans(resources)
    protected = get_protected_resources(resources)

    print(f"  Account:    {metadata.get('account_id', '?')}")
    print(f"  Region:     {metadata.get('region', '?')}")
    print(f"  Vaults:     {len(vaults)}")
    print(f"  Plans:      {len(plans)}")
    print(f"  Protected:  {len(protected)} resources")

    if not plans:
        print(f"\n  *** NO BACKUP PLANS — RESOURCES ARE NOT PROTECTED ***")


if __name__ == "__main__":
    main()
