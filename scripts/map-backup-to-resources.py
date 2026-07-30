#!/usr/bin/env python3
"""
DR Resource Mapper — Maps AWS Backup recovery points to AMI/Snapshot IDs.

Queries a cross-region backup vault in the DR region and resolves each
recovery point to the actual AMI or RDS snapshot needed for restore.
Resolves source-region EC2 instance Name tags for operator-friendly output.

Usage:
  python3 map-backup-to-resources.py --source-region us-gov-west-1 \
    --dr-region us-gov-east-1 --vault-name my-dr-vault

  python3 map-backup-to-resources.py --source-region us-gov-west-1 \
    --dr-region us-gov-east-1 --vault-name my-dr-vault --max-age-hours 48
"""

import json
import sys
import re
import argparse
from datetime import datetime, timedelta, timezone

import boto3


def parse_args():
    parser = argparse.ArgumentParser(
        description="Map AWS Backup recovery points to AMI/Snapshot IDs for DR restore."
    )
    parser.add_argument("--source-region", required=True,
                        help="Primary region where instances live (e.g., us-gov-west-1)")
    parser.add_argument("--dr-region", required=True,
                        help="DR region where backups are copied (e.g., us-gov-east-1)")
    parser.add_argument("--vault-name", required=True,
                        help="Name of the cross-region backup vault in the DR region")
    parser.add_argument("--max-age-hours", type=int, default=36,
                        help="Only include recovery points newer than this (default: 36)")
    parser.add_argument("--output", default="resource-mapping.txt",
                        help="Output filename (default: resource-mapping.txt)")
    return parser.parse_args()


def extract_resource_id(arn, resource_type):
    """Extract human-readable resource identifier from ARN."""
    if resource_type.upper() == "RDS":
        match = re.search(r":(db|cluster):([^:]+)$", arn)
        if match:
            return match.group(2)
    elif resource_type.upper() == "EC2":
        match = re.search(r"instance/([^/]+)$", arn)
        if match:
            return match.group(1)
    return arn.split(":")[-1].split("/")[-1]


def get_rds_snapshot(rds_client, db_identifier):
    """Get latest RDS snapshot for a DB instance."""
    try:
        resp = rds_client.describe_db_snapshots(DBInstanceIdentifier=db_identifier)
        snaps = resp.get("DBSnapshots", [])
        if snaps:
            snaps.sort(key=lambda s: s.get("SnapshotCreateTime"), reverse=True)
            return snaps[0].get("DBSnapshotIdentifier")
    except Exception as e:
        print(f"  -> ERROR: {e}", file=sys.stderr)
    return None


def get_ec2_ami(ec2_client, instance_id):
    """Get latest EC2 AMI for an instance using tag and description heuristics."""
    try:
        tag_keys = ["SourceInstance", "SourceAmi", "CopiedFrom", "OriginalAmi", "BackupSourceInstance"]
        for key in tag_keys:
            try:
                resp = ec2_client.describe_images(
                    Owners=["self"],
                    Filters=[{"Name": f"tag:{key}", "Values": [instance_id]}]
                )
            except Exception:
                resp = {"Images": []}
            images = resp.get("Images", [])
            if images:
                images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
                return images[0].get("ImageId")

        resp = ec2_client.describe_images(Owners=["self"])
        images = resp.get("Images", [])
        candidates = [img for img in images
                      if instance_id in (img.get("Description") or "")
                      or instance_id in (img.get("Name") or "")]
        if candidates:
            candidates.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
            return candidates[0].get("ImageId")

        candidates = []
        for img in images:
            for tag in img.get("Tags", []) or []:
                if instance_id in (tag.get("Value") or ""):
                    candidates.append(img)
                    break
        if candidates:
            candidates.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
            return candidates[0].get("ImageId")
    except Exception as e:
        print(f"  -> ERROR: {e}", file=sys.stderr)
    return None


def get_ec2_instance_name(ec2_client, instance_id):
    """Get the EC2 instance Name tag from the source region."""
    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        for reservation in resp.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                for tag in instance.get("Tags", []) or []:
                    if tag.get("Key") == "Name":
                        return tag.get("Value")
    except Exception:
        pass
    return None


def list_backup_recovery_points(backup_client, vault_name, max_age_hours):
    """List recovery points, filtering for EC2/RDS within max_age_hours."""
    paginator = backup_client.get_paginator("list_recovery_points_by_backup_vault")
    points = []
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

    try:
        for page in paginator.paginate(BackupVaultName=vault_name):
            for rp in page.get("RecoveryPoints", []):
                rtype = rp.get("ResourceType", "")
                arn = rp.get("ResourceArn", "")
                creation_date = rp.get("CreationDate")

                try:
                    if isinstance(creation_date, str):
                        cdate = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
                    else:
                        cdate = creation_date
                    if cdate < cutoff_time:
                        continue
                except Exception:
                    continue

                if rtype in ("EC2", "RDS") or "instance/" in arn or ":db:" in arn or ":cluster:" in arn:
                    points.append(rp)
    except Exception as e:
        print(f"ERROR: Could not list recovery points from vault '{vault_name}': {e}", file=sys.stderr)
        sys.exit(1)

    # Deduplicate — keep newest per ResourceArn
    deduped = {}
    for rp in points:
        arn = rp.get("ResourceArn", "")
        cdate = rp.get("CreationDate")
        try:
            cdt = cdate if not isinstance(cdate, str) else datetime.fromisoformat(cdate.replace("Z", "+00:00"))
        except Exception:
            cdt = datetime.fromtimestamp(0, tz=timezone.utc)
        existing = deduped.get(arn)
        if not existing or cdt > existing[1]:
            deduped[arn] = (rp, cdt)

    return [t[0] for t in deduped.values()]


def main():
    args = parse_args()

    print(f"\n{'='*70}")
    print(f"  DR Resource Mapper")
    print(f"  DR Region: {args.dr_region} | Vault: {args.vault_name}")
    print(f"  Max age: {args.max_age_hours} hours")
    print(f"{'='*70}\n")

    session = boto3.Session()
    backup_client = session.client("backup", region_name=args.dr_region)
    rds_client = session.client("rds", region_name=args.dr_region)
    ec2_client = session.client("ec2", region_name=args.dr_region)
    ec2_src_client = session.client("ec2", region_name=args.source_region)

    print(f"[1/2] Listing recovery points from vault '{args.vault_name}'...")
    print(f"      (filtering for last {args.max_age_hours} hours)")
    recovery_points = list_backup_recovery_points(backup_client, args.vault_name, args.max_age_hours)
    print(f"      Found {len(recovery_points)} EC2/RDS recovery points\n")

    if not recovery_points:
        print("No recovery points found. Check vault name, region, and age filter.", file=sys.stderr)
        sys.exit(1)

    print(f"[2/2] Mapping to AMI/Snapshot IDs in {args.dr_region}...\n")
    print(f"{'Type':<6} {'Resource':<32} {'AMI/Snapshot ID':<50} {'Instance Name'}")
    print(f"{'-'*6} {'-'*32} {'-'*50} {'-'*24}")

    mappings = []
    success_count = 0
    fail_count = 0

    for rp in recovery_points:
        arn = rp.get("ResourceArn", "")
        rtype = rp.get("ResourceType", "")
        resource_id = extract_resource_id(arn, rtype)
        resource_value = None
        instance_name = None

        if rtype.upper() == "RDS":
            resource_value = get_rds_snapshot(rds_client, resource_id)
        elif rtype.upper() == "EC2":
            resource_value = get_ec2_ami(ec2_client, resource_id)
            instance_name = get_ec2_instance_name(ec2_src_client, resource_id)

        if resource_value:
            success_count += 1
            name_col = instance_name or ""
            print(f"+ {rtype:<6} {resource_id:<32} {resource_value:<50} {name_col}")
            mappings.append({
                "ResourceType": rtype,
                "ResourceId": resource_id,
                "AMI_or_SnapshotId": resource_value,
                "InstanceName": instance_name,
            })
        else:
            fail_count += 1
            print(f"x {rtype:<6} {resource_id:<32} FAILED TO MAP")

    # Write output
    with open(args.output, "w") as f:
        f.write(f"DR Resource Mapping - {args.dr_region}\n")
        f.write(f"Vault: {args.vault_name}\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Recovery points within last {args.max_age_hours} hours\n\n")
        f.write(f"{'Type':<6} {'Resource':<32} {'AMI/Snapshot ID':<50} {'Instance Name'}\n")
        f.write(f"{'-'*6} {'-'*32} {'-'*50} {'-'*24}\n")
        for m in mappings:
            name = m.get("InstanceName") or ""
            f.write(f"{m['ResourceType']:<6} {m['ResourceId']:<32} {m['AMI_or_SnapshotId']:<50} {name}\n")
        f.write(f"\nSummary: {success_count} mapped, {fail_count} failed, {len(recovery_points)} total\n")

    print(f"\n{'-'*70}")
    print(f"Summary: {success_count} mapped, {fail_count} failed, {len(recovery_points)} total")
    print(f"Output: {args.output}")
    print(f"{'='*70}\n")

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
