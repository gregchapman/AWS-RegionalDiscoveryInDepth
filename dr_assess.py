#!/usr/bin/env python3
"""
DR Readiness Assessment — Reads inventory and produces a gap report.

Analyzes the discovery output to identify:
- Resources without backup/replication coverage
- Boot-order dependencies (AD/DNS, FSx)
- Missing cross-region copies (AMIs, snapshots, S3, secrets)
- DLM/Backup coverage gaps
- Single points of failure

Usage:
    python3 dr_assess.py --input output/acme-prod/us-east-1/20260730-170126/
    python3 dr_assess.py --input output/acme-prod/us-east-1/20260730-170126/inventory-us-gov-west-1.yaml

Output:
    dr-gaps.md in the same directory as the inventory file
"""

import yaml
import os
import sys
import argparse
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Set, Any


def parse_args():
    parser = argparse.ArgumentParser(
        description='DR Readiness Assessment — identify recovery gaps from inventory.'
    )
    parser.add_argument('--input', required=True,
                        help='Path to inventory YAML file or run directory')
    return parser.parse_args()


def load_inventory(path: str) -> dict:
    """Load inventory from YAML file or find it in a run directory."""
    if os.path.isfile(path) and path.endswith('.yaml'):
        with open(path) as f:
            return yaml.safe_load(f)

    # It's a directory — find the inventory file
    if os.path.isdir(path):
        for fname in os.listdir(path):
            if fname.startswith('inventory-') and fname.endswith('.yaml'):
                with open(os.path.join(path, fname)) as f:
                    return yaml.safe_load(f)

    print(f"ERROR: Could not find inventory YAML in {path}", file=sys.stderr)
    sys.exit(1)


def get_resources(inventory: dict, category: str) -> List[dict]:
    """Get resources by category name."""
    return inventory.get('resources', {}).get(category, [])


# ═══════════════════════════════════════════════════════════════════
# ASSESSMENT CHECKS
# ═══════════════════════════════════════════════════════════════════

def assess_s3_replication(inventory: dict) -> List[str]:
    """Check S3 buckets for CRR and versioning gaps."""
    findings = []
    buckets = get_resources(inventory, 'S3 Buckets')
    versioning = get_resources(inventory, 'S3 Versioning')
    replication = get_resources(inventory, 'S3 Replication')

    # Build set of buckets with versioning enabled
    versioned_buckets = set()
    for v in versioning:
        cfg = v.get('config', {})
        if cfg.get('Status') == 'Enabled':
            bucket_name = cfg.get('BucketName', '')
            if bucket_name:
                versioned_buckets.add(bucket_name)

    # Build set of buckets with CRR
    replicated_buckets = set()
    for r in replication:
        bucket_name = r.get('config', {}).get('BucketName', '')
        if bucket_name:
            replicated_buckets.add(bucket_name)

    # Find gaps
    all_bucket_names = {b.get('config', {}).get('Name', b.get('name', ''))
                        for b in buckets}
    no_versioning = all_bucket_names - versioned_buckets
    no_replication = all_bucket_names - replicated_buckets

    if no_replication:
        findings.append(f"**{len(no_replication)} of {len(all_bucket_names)} S3 buckets have NO cross-region replication (CRR):**")
        for name in sorted(no_replication):
            v_status = "versioning enabled" if name in versioned_buckets else "NO versioning"
            findings.append(f"  - `{name}` ({v_status})")
        findings.append("")

    if no_versioning:
        findings.append(f"**{len(no_versioning)} buckets lack versioning** (required for CRR):")
        for name in sorted(no_versioning):
            findings.append(f"  - `{name}`")
        findings.append("")

    return findings


def assess_secrets_replication(inventory: dict) -> List[str]:
    """Check Secrets Manager for replication gaps."""
    findings = []
    secrets = get_resources(inventory, 'Secrets')

    unreplicated = []
    for secret in secrets:
        cfg = secret.get('config', {})
        name = cfg.get('Name', secret.get('name', ''))
        repl_status = cfg.get('ReplicationStatus', '')
        if not repl_status:
            unreplicated.append(name)

    if unreplicated:
        findings.append(f"**{len(unreplicated)} of {len(secrets)} secrets have NO cross-region replication:**")
        for name in sorted(unreplicated):
            findings.append(f"  - `{name}`")
        findings.append("")
        findings.append("*Action:* Run `scripts/replicate-secrets.py` to copy values to DR region.")
        findings.append("")

    return findings


def assess_backup_coverage(inventory: dict) -> List[str]:
    """Check AWS Backup coverage gaps."""
    findings = []
    vaults = get_resources(inventory, 'Backup Vaults')
    plans = get_resources(inventory, 'Backup Plans')
    protected = get_resources(inventory, 'Protected Resources')

    if not plans:
        findings.append("**No AWS Backup plans configured.**")
        findings.append("  The account has no automated backup schedule via AWS Backup.")
        findings.append("  All backup relies on DLM (snapshot automation) and FSx automatic backups.")
        findings.append("")
        findings.append("*Action:* Create a Backup plan with cross-region copy rules covering EC2, RDS, and FSx.")
        findings.append("")
    elif not protected:
        findings.append(f"**{len(plans)} Backup plan(s) exist but no protected resources found.**")
        findings.append("  Backup selections may not match any resources, or plans may be disabled.")
        findings.append("")

    return findings


def assess_ebs_snapshot_coverage(inventory: dict) -> List[str]:
    """Check EBS volume snapshot coverage and DLM gaps."""
    findings = []
    volumes = get_resources(inventory, 'EBS Volumes')
    snapshots = get_resources(inventory, 'EBS Snapshots')
    dlm_policies = get_resources(inventory, 'DLM Lifecycle Policies') or \
                   get_resources(inventory, 'Get Lifecycle Policies')

    # Build set of volume IDs that have at least one snapshot
    snapshotted_volumes = set()
    for snap in snapshots:
        vol_id = snap.get('config', {}).get('VolumeId', '')
        if vol_id:
            snapshotted_volumes.add(vol_id)

    # Volumes without any snapshot
    all_volume_ids = {v.get('config', {}).get('VolumeId', v.get('resource_id', ''))
                      for v in volumes}
    no_snapshot = all_volume_ids - snapshotted_volumes

    if no_snapshot:
        findings.append(f"**{len(no_snapshot)} of {len(all_volume_ids)} EBS volumes have NO snapshots:**")
        for vol_id in sorted(no_snapshot):
            # Find the volume to get its instance attachment
            for v in volumes:
                if v.get('resource_id', '') == vol_id:
                    attachments = v.get('config', {}).get('Attachments', [])
                    inst_id = ''
                    if isinstance(attachments, list) and attachments:
                        inst_id = attachments[0].get('InstanceId', '')
                    size = v.get('config', {}).get('Size', '')
                    findings.append(f"  - `{vol_id}` ({size}GB) attached to `{inst_id}`")
                    break
        findings.append("")

    # DLM coverage
    if not dlm_policies:
        findings.append("**No DLM Lifecycle Policies found.** Snapshot automation is absent.")
        findings.append("")
    elif len(dlm_policies) == 1:
        findings.append(f"**Only 1 DLM policy** managing {len(snapshots)} snapshots across {len(all_volume_ids)} volumes.")
        findings.append("  Verify tag-based targeting covers all critical volumes.")
        findings.append("")

    return findings


def assess_ami_coverage(inventory: dict) -> List[str]:
    """Check AMI availability for DR — instances using non-owned AMIs."""
    findings = []
    instances = get_resources(inventory, 'EC2 Instances')
    amis = get_resources(inventory, 'AMIs')

    # AMI IDs we own (in DR they'd need to be copied)
    owned_ami_ids = {a.get('config', {}).get('ImageId', a.get('resource_id', ''))
                     for a in amis}

    # AMIs used by instances
    used_ami_ids = defaultdict(list)
    for inst in instances:
        cfg = inst.get('config', {})
        ami_id = cfg.get('ImageId', '')
        if ami_id:
            used_ami_ids[ami_id].append(inst.get('name', inst.get('resource_id', '')))

    # AMIs used but not owned (marketplace/AWS AMIs)
    not_owned = {ami: insts for ami, insts in used_ami_ids.items()
                 if ami not in owned_ami_ids}

    if not_owned:
        findings.append(f"**{len(not_owned)} AMIs used by instances are NOT customer-owned** (marketplace/AWS):")
        findings.append("  These must be available in the DR region (re-subscribe or find equivalent).")
        for ami_id, insts in sorted(not_owned.items()):
            findings.append(f"  - `{ami_id}` used by: {', '.join(insts[:5])}"
                           + (f" (+{len(insts)-5} more)" if len(insts) > 5 else ""))
        findings.append("")

    if owned_ami_ids:
        findings.append(f"**{len(owned_ami_ids)} customer-owned AMIs** must be copied to DR region:")
        for ami_id in sorted(owned_ami_ids):
            name = ''
            for a in amis:
                if a.get('resource_id', '') == ami_id:
                    name = a.get('name', '')
                    break
            findings.append(f"  - `{ami_id}` ({name})")
        findings.append("")

    return findings


def assess_dns_dependencies(inventory: dict) -> List[str]:
    """Check for AD/DNS boot-order dependencies from DHCP options."""
    findings = []
    dhcp_options = get_resources(inventory, 'DHCP Options')

    for dhcp in dhcp_options:
        cfg = dhcp.get('config', {})
        dhcp_configs = cfg.get('DhcpConfigurations', [])
        for dc in dhcp_configs:
            key = dc.get('Key', '')
            values = dc.get('Values', [])
            if key == 'domain-name-servers':
                dns_ips = [v.get('Value', '') for v in values if v.get('Value', '')]
                if dns_ips and 'AmazonProvidedDNS' not in dns_ips:
                    findings.append(f"**DHCP Option Set `{cfg.get('DhcpOptionsId', '')}` uses custom DNS servers:**")
                    for ip in dns_ips:
                        findings.append(f"  - `{ip}` (EC2 Domain Controller)")
                    findings.append("")
                    findings.append("  **Boot-order dependency:** These DCs must be running before ANY other")
                    findings.append("  instance can resolve DNS. Deploy DCs first, verify AD health, then proceed.")
                    findings.append("")

                    # Find the domain name
                    for dc2 in dhcp_configs:
                        if dc2.get('Key') == 'domain-name':
                            domain_vals = [v.get('Value', '') for v in dc2.get('Values', [])]
                            if domain_vals:
                                findings.append(f"  AD Domain: `{domain_vals[0]}`")
                                findings.append("")
                    break

    return findings


def assess_fsx_dr(inventory: dict) -> List[str]:
    """Check FSx backup and DR readiness."""
    findings = []
    fsx_systems = get_resources(inventory, 'FSx File Systems')
    fsx_backups = get_resources(inventory, 'FSx Backups')

    if not fsx_systems:
        return findings

    for fs in fsx_systems:
        cfg = fs.get('config', {})
        fs_id = cfg.get('FileSystemId', '')
        fs_name = fs.get('name', fs_id)
        fs_type = cfg.get('FileSystemType', '')
        capacity = cfg.get('StorageCapacity', '')
        retention = cfg.get('AutomaticBackupRetentionDays', 0)
        domain = cfg.get('DomainName', '')

        # Count backups for this file system
        fs_backup_count = sum(1 for b in fsx_backups
                              if b.get('config', {}).get('FileSystemId', '') == fs_id
                              or b.get('config', {}).get('FileSystem', {}).get('FileSystemId', '') == fs_id)

        findings.append(f"**FSx File System `{fs_name}` ({fs_type}, {capacity}GB):**")
        findings.append(f"  - Backups in region: {fs_backup_count}")
        findings.append(f"  - Automatic backup retention: {retention} days")
        if domain:
            findings.append(f"  - AD Domain: `{domain}` (DCs must be up before FSx creation)")
        findings.append(f"  - Cross-region backup copies: **UNKNOWN** (check AWS Backup or manual copies)")
        findings.append("")
        findings.append("  *Action:* Verify cross-region backup copies exist. If not, configure AWS Backup")
        findings.append("  with a cross-region copy rule, or script `aws fsx copy-backup --source-region`.")
        findings.append("")

    return findings


def assess_ssm_parameters(inventory: dict) -> List[str]:
    """Check SSM Parameter Store replication."""
    findings = []
    params = get_resources(inventory, 'SSM Parameters')

    if params:
        findings.append(f"**{len(params)} SSM parameters** are region-specific and not replicated:")
        findings.append("  These must be manually copied to the DR region before deployment.")
        findings.append("")
        findings.append("  *Action:* Run `scripts/replicate-parameters.py` to copy all parameters to DR region.")
        findings.append("")

    return findings


def assess_vpn_connectivity(inventory: dict) -> List[str]:
    """Check VPN/TGW connectivity for DR considerations."""
    findings = []
    vpn_connections = get_resources(inventory, 'VPN Connections')
    customer_gateways = get_resources(inventory, 'Customer Gateways')
    tgws = get_resources(inventory, 'Transit Gateways')

    if vpn_connections:
        findings.append(f"**{len(vpn_connections)} VPN connection(s)** provide on-prem connectivity:")
        for vpn in vpn_connections:
            cfg = vpn.get('config', {})
            vpn_id = cfg.get('VpnConnectionId', vpn.get('resource_id', ''))
            tgw_id = cfg.get('TransitGatewayId', '')
            cgw_id = cfg.get('CustomerGatewayId', '')
            findings.append(f"  - `{vpn_id}` → TGW: `{tgw_id}`, CGW: `{cgw_id}`")
        findings.append("")
        findings.append("  *DR consideration:* VPN tunnels are region-specific. In DR, new VPN connections")
        findings.append("  must be established to the same on-prem endpoints (Customer Gateway IPs are reusable).")
        findings.append("")

    return findings


def assess_target_registration(inventory: dict) -> List[str]:
    """Identify target groups and their registration requirements for DR."""
    findings = []
    registered_targets = get_resources(inventory, 'Registered Targets')
    target_groups = get_resources(inventory, 'Target Groups')

    if registered_targets:
        # Group targets by TG ARN
        tg_targets = defaultdict(list)
        for rt in registered_targets:
            cfg = rt.get('config', {})
            tg_arn = cfg.get('TargetGroupArn', cfg.get('_parent_arn', ''))
            target_id = cfg.get('Id', '')
            port = cfg.get('Port', '')
            tg_targets[tg_arn].append(f"{target_id}:{port}")

        findings.append(f"**{len(registered_targets)} target registrations** across {len(tg_targets)} target groups:")
        findings.append("  After compute deploys in DR, targets must be re-registered with new IPs/instance IDs.")
        findings.append("")
        for tg_arn, targets in tg_targets.items():
            # Find TG name
            tg_name = tg_arn.split('/')[-2] if '/' in tg_arn else tg_arn[-30:]
            findings.append(f"  - `{tg_name}`: {', '.join(targets)}")
        findings.append("")

    return findings


# ═══════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════

def generate_report(inventory: dict) -> str:
    """Generate the full DR gap report."""
    meta = inventory.get('metadata', {})
    lines = []
    w = lines.append

    w("# DR Readiness Assessment")
    w("")
    w(f"**Account:** {meta.get('account_id', 'N/A')}")
    w(f"**Region:** {meta.get('region', 'N/A')}")
    w(f"**Inventory Date:** {meta.get('scan_date', 'N/A')}")
    w(f"**Assessment Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    w("")
    w("---")
    w("")

    # Run all assessments
    checks = [
        ("Critical: DNS/AD Boot-Order Dependencies", assess_dns_dependencies),
        ("Critical: S3 Replication & Versioning", assess_s3_replication),
        ("Critical: Secrets Manager Replication", assess_secrets_replication),
        ("Critical: AWS Backup Coverage", assess_backup_coverage),
        ("High: EBS Snapshot Coverage & DLM", assess_ebs_snapshot_coverage),
        ("High: AMI Availability for DR", assess_ami_coverage),
        ("High: FSx DR Readiness", assess_fsx_dr),
        ("Medium: SSM Parameter Store", assess_ssm_parameters),
        ("Medium: VPN/On-Prem Connectivity", assess_vpn_connectivity),
        ("Info: Target Group Registration", assess_target_registration),
    ]

    # Summary table
    w("## Summary")
    w("")
    w("| Severity | Check | Status |")
    w("|----------|-------|--------|")

    all_findings = {}
    for title, check_fn in checks:
        findings = check_fn(inventory)
        all_findings[title] = findings
        severity = title.split(':')[0].strip()
        check_name = title.split(':', 1)[1].strip()
        status = "GAP FOUND" if findings else "OK"
        icon = "🔴" if severity == "Critical" and findings else \
               "🟡" if severity == "High" and findings else \
               "🔵" if findings else "✅"
        w(f"| {icon} {severity} | {check_name} | {status} |")

    w("")
    w("---")
    w("")

    # Detailed findings
    w("## Detailed Findings")
    w("")

    for title, findings in all_findings.items():
        if findings:
            w(f"### {title}")
            w("")
            for line in findings:
                w(line)
            w("---")
            w("")

    # Recovery sequence
    w("## Recommended Recovery Sequence")
    w("")
    w("Based on the dependencies identified above:")
    w("")
    w("```")
    w("1. Pre-DR: Copy AMIs, snapshots, FSx backups to DR region")
    w("2. Pre-DR: Run replicate-secrets.py and replicate-parameters.py")
    w("3. Deploy: VPC, Subnets, Route Tables, DHCP Options")
    w("4. Deploy: Security Groups (bespoke template)")
    w("5. Deploy: NAT Gateways, VPC Endpoints")
    w("6. Deploy: KMS Keys (needed before encrypted resources)")
    w("7. Deploy: Domain Controllers (EC2) — WAIT FOR AD HEALTH")
    w("8. Deploy: FSx (restore from backup — requires AD)")
    w("9. Deploy: RDS (restore from snapshot)")
    w("10. Deploy: Remaining EC2 instances")
    w("11. Deploy: Load Balancers, Target Groups")
    w("12. Post-Deploy: Register targets with Target Groups")
    w("13. Post-Deploy: Verify DNS resolution, connectivity, app health")
    w("14. Post-Deploy: Re-establish VPN connections to on-prem")
    w("```")
    w("")

    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    args = parse_args()

    # Determine paths
    input_path = args.input
    if os.path.isdir(input_path):
        output_dir = input_path
    else:
        output_dir = os.path.dirname(input_path)

    # Load inventory
    print(f"Loading inventory from {input_path}...")
    inventory = load_inventory(input_path)

    resources = inventory.get('resources', {})
    total = sum(len(v) for v in resources.values())
    print(f"  {len(resources)} categories, {total} resources")

    # Generate report
    print("Running DR readiness assessment...")
    report = generate_report(inventory)

    # Write output
    output_path = os.path.join(output_dir, 'dr-gaps.md')
    with open(output_path, 'w') as f:
        f.write(report)

    print(f"\n  DR Gap Report: {output_path}")

    # Count gaps
    gap_count = report.count('GAP FOUND')
    ok_count = report.count('| OK |')
    print(f"  Results: {gap_count} gaps found, {ok_count} checks passed")
    print()


if __name__ == "__main__":
    main()
