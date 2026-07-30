#!/usr/bin/env python3
"""
sg-vpc-config-changes.py

Uses AWS Config to identify ingress/egress rule changes made to ALL security
groups in a specified VPC within a date/time window.

Auto-discovers all security groups in the target VPC.

Output formats:
  - Text (.txt)  - Human-readable report for review
  - CSV  (.csv)  - Spreadsheet-friendly for tracking/filtering
  - YAML (.yaml) - Structured data, handy for CloudFormation reference

Requirements:
  - boto3
  - pyyaml (pip install pyyaml)
  - AWS Config Recorder must be/have been enabled in the target region
  - IAM permissions: config:GetResourceConfigHistory, ec2:DescribeSecurityGroups

Usage:
  python3 sg-vpc-config-changes.py --vpc-id vpc-xxx --region us-gov-east-1 --start 2026-04-01 --end 2026-06-29
"""

import argparse
import boto3
import csv
import json
import yaml
from datetime import datetime, timezone

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Identify security group rule changes in a VPC via AWS Config."
    )
    parser.add_argument("--vpc-id", required=True, help="VPC ID to scan")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")
    return parser.parse_args()


args = parse_args()
VPC_ID = args.vpc_id
REGION = args.region
START_TIME = datetime.strptime(args.start, "%Y-%m-%d").replace(hour=0, minute=0, second=0, tzinfo=timezone.utc)
END_TIME = datetime.strptime(args.end, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
OUTPUT_BASE = f"sg-changes-{VPC_ID}-{args.start}-{args.end}"


# ============================================================================
# PREFLIGHT CHECK
# ============================================================================

def check_config_recorder():
    """Verify AWS Config Recorder is active in the target region."""
    client = boto3.client("config", region_name=REGION)
    try:
        resp = client.describe_configuration_recorder_status()
        statuses = resp.get("ConfigurationRecordersStatus", [])
        if not statuses:
            print(f"WARNING: No Config Recorder found in {REGION}. Results may be incomplete.")
            return
        for status in statuses:
            if not status.get("recording", False):
                print(f"WARNING: Config Recorder '{status.get('name', '')}' is NOT recording in {REGION}.")
            else:
                print(f"Config Recorder '{status.get('name', '')}' is active in {REGION}.")
    except Exception as e:
        print(f"WARNING: Could not verify Config Recorder status: {e}")


# ============================================================================
# AWS CLIENTS
# ============================================================================

def get_config_client():
    return boto3.client("config", region_name=REGION)


def get_ec2_client():
    return boto3.client("ec2", region_name=REGION)


# ============================================================================
# DISCOVERY
# ============================================================================

def discover_security_groups() -> list:
    """Enumerate all security groups in the target VPC."""
    ec2 = get_ec2_client()
    security_groups = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(
        Filters=[{"Name": "vpc-id", "Values": [VPC_ID]}]
    ):
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            name = sg.get("GroupName", "")
            tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
            display_name = tags.get("Name", name)
            security_groups.append({
                "sg_id": sg_id,
                "sg_name": display_name,
            })
    return security_groups


# ============================================================================
# CONFIG HISTORY
# ============================================================================

def get_config_history(sg_id: str) -> list:
    """Retrieve configuration history for a security group within the time window."""
    client = get_config_client()
    items = []

    # Cap end time to now if it's in the future - Config API rejects future times
    now = datetime.now(timezone.utc)
    effective_end = min(END_TIME, now)

    if START_TIME >= effective_end:
        print(f"    Warning: START_TIME is not before effective END_TIME ({effective_end}). Skipping.")
        return []

    try:
        paginator = client.get_paginator("get_resource_config_history")
        page_iterator = paginator.paginate(
            resourceType="AWS::EC2::SecurityGroup",
            resourceId=sg_id,
            laterTime=effective_end,
            earlierTime=START_TIME,
            chronologicalOrder="Forward",
        )
        for page in page_iterator:
            items.extend(page.get("configurationItems", []))
    except client.exceptions.ResourceNotDiscoveredException:
        print(f"    Skipped: Config has not discovered this resource.")
    except Exception as e:
        print(f"    Error fetching config history: {e}")

    return items


# ============================================================================
# RULE PARSING AND DIFFING
# ============================================================================

def parse_rules(config_json: str) -> tuple:
    """Parse ingress and egress rules from a configuration item's JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return [], []

    ingress = config.get("ipPermissions", [])
    egress = config.get("ipPermissionsEgress", [])
    return ingress, egress


def normalize_rule(rule: dict) -> dict:
    """Normalize a rule dict for consistent comparison."""
    return {
        "ipProtocol": rule.get("ipProtocol", ""),
        "fromPort": rule.get("fromPort", None),
        "toPort": rule.get("toPort", None),
        "ipv4Ranges": sorted(
            [r.get("cidrIp", "") for r in rule.get("ipv4Ranges", rule.get("ipRanges", []))],
        ),
        "ipv6Ranges": sorted(
            [r.get("cidrIpv6", "") for r in rule.get("ipv6Ranges", [])],
        ),
        "prefixListIds": sorted(
            [p.get("prefixListId", "") for p in rule.get("prefixListIds", [])],
        ),
        "userIdGroupPairs": sorted(
            [g.get("groupId", "") for g in rule.get("userIdGroupPairs", [])],
        ),
    }


def rules_to_set(rules: list) -> set:
    """Convert a list of rules to a set of frozen representations for diffing."""
    result = set()
    for rule in rules:
        nr = normalize_rule(rule)
        frozen = json.dumps(nr, sort_keys=True)
        result.add(frozen)
    return result


def format_rule_text(rule_json: str) -> str:
    """Format a normalized rule JSON into a human-readable string."""
    r = json.loads(rule_json)
    proto = r["ipProtocol"] if r["ipProtocol"] else "all"
    from_port = r["fromPort"]
    to_port = r["toPort"]

    if proto == "-1":
        port_str = "All traffic"
    elif from_port == to_port:
        port_str = f"{proto.upper()} port {from_port}"
    else:
        port_str = f"{proto.upper()} ports {from_port}-{to_port}"

    sources = []
    if r["ipv4Ranges"]:
        sources.extend(r["ipv4Ranges"])
    if r["ipv6Ranges"]:
        sources.extend(r["ipv6Ranges"])
    if r["prefixListIds"]:
        sources.extend([f"pl:{p}" for p in r["prefixListIds"]])
    if r["userIdGroupPairs"]:
        sources.extend([f"sg:{g}" for g in r["userIdGroupPairs"]])

    source_str = ", ".join(sources) if sources else "(no source)"
    return f"{port_str} <- {source_str}"


def rule_to_dict(rule_json: str) -> dict:
    """Convert a normalized rule JSON string to a clean dict for YAML/CSV output."""
    r = json.loads(rule_json)
    proto = r["ipProtocol"] if r["ipProtocol"] else "all"
    from_port = r["fromPort"]
    to_port = r["toPort"]

    sources = []
    if r["ipv4Ranges"]:
        sources.extend(r["ipv4Ranges"])
    if r["ipv6Ranges"]:
        sources.extend(r["ipv6Ranges"])
    if r["prefixListIds"]:
        sources.extend([f"pl:{p}" for p in r["prefixListIds"]])
    if r["userIdGroupPairs"]:
        sources.extend([f"sg:{g}" for g in r["userIdGroupPairs"]])

    result = {"protocol": proto}
    if proto != "-1":
        result["from_port"] = from_port
        result["to_port"] = to_port
    result["sources"] = sources
    return result


def diff_rules(old_rules: list, new_rules: list) -> tuple:
    """Return (added, removed) rule sets between two snapshots."""
    old_set = rules_to_set(old_rules)
    new_set = rules_to_set(new_rules)
    added = new_set - old_set
    removed = old_set - new_set
    return added, removed


# ============================================================================
# ANALYSIS
# ============================================================================

def analyze_sg(sg_id: str, sg_name: str) -> list:
    """Analyze a single security group. Returns list of change dicts."""
    print(f"  Fetching config history for {sg_id} ({sg_name})...")
    items = get_config_history(sg_id)

    if len(items) < 2:
        print(f"    Only {len(items)} config item(s) found - no changes to diff.")
        return []

    changes = []
    for i in range(1, len(items)):
        prev_item = items[i - 1]
        curr_item = items[i]

        prev_ingress, prev_egress = parse_rules(prev_item.get("configuration", "{}"))
        curr_ingress, curr_egress = parse_rules(curr_item.get("configuration", "{}"))

        ingress_added, ingress_removed = diff_rules(prev_ingress, curr_ingress)
        egress_added, egress_removed = diff_rules(prev_egress, curr_egress)

        if ingress_added or ingress_removed or egress_added or egress_removed:
            timestamp = curr_item.get("configurationItemCaptureTime", "unknown")
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            changes.append({
                "sg_id": sg_id,
                "sg_name": sg_name,
                "timestamp": str(timestamp),
                "ingress_added": sorted(ingress_added),
                "ingress_removed": sorted(ingress_removed),
                "egress_added": sorted(egress_added),
                "egress_removed": sorted(egress_removed),
            })

    if not changes:
        print(f"    No ingress/egress rule changes detected in window.")
    else:
        print(f"    Found {len(changes)} change event(s).")

    return changes


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

def write_text_report(all_changes: list, sg_count: int):
    """Write a human-readable text report."""
    lines = []
    lines.append("=" * 70)
    lines.append("SECURITY GROUP RULE CHANGES REPORT (VPC-WIDE)")
    lines.append("=" * 70)
    lines.append(f"Region:              {REGION}")
    lines.append(f"VPC:                 {VPC_ID}")
    lines.append(f"Window:              {START_TIME.strftime('%Y-%m-%d %H:%M')} to {END_TIME.strftime('%Y-%m-%d %H:%M')} UTC")
    lines.append(f"SGs in VPC:          {sg_count}")
    lines.append(f"SGs with Changes:    {len(set(c['sg_id'] for c in all_changes))}")
    lines.append(f"Total Change Events: {len(all_changes)}")
    lines.append("=" * 70)
    lines.append("")

    if not all_changes:
        lines.append("No ingress/egress rule changes detected for any security group.")
    else:
        current_sg = None
        for change in all_changes:
            if change["sg_id"] != current_sg:
                current_sg = change["sg_id"]
                lines.append("-" * 70)
                lines.append(f"  {change['sg_name']}  ({change['sg_id']})")
                lines.append("-" * 70)
                lines.append("")

            lines.append(f"  Change recorded: {change['timestamp']}")
            lines.append("")

            if change["ingress_added"]:
                lines.append("    INGRESS ADDED:")
                for rule in change["ingress_added"]:
                    lines.append(f"      + {format_rule_text(rule)}")
                lines.append("")

            if change["ingress_removed"]:
                lines.append("    INGRESS REMOVED:")
                for rule in change["ingress_removed"]:
                    lines.append(f"      - {format_rule_text(rule)}")
                lines.append("")

            if change["egress_added"]:
                lines.append("    EGRESS ADDED:")
                for rule in change["egress_added"]:
                    lines.append(f"      + {format_rule_text(rule)}")
                lines.append("")

            if change["egress_removed"]:
                lines.append("    EGRESS REMOVED:")
                for rule in change["egress_removed"]:
                    lines.append(f"      - {format_rule_text(rule)}")
                lines.append("")

            lines.append("")

    filename = f"{OUTPUT_BASE}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(lines))
    print(f"  Text report:  {filename}")


def write_csv_report(all_changes: list):
    """Write a CSV report - one row per rule change."""
    filename = f"{OUTPUT_BASE}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "sg_id",
            "sg_name",
            "timestamp",
            "direction",
            "action",
            "protocol",
            "from_port",
            "to_port",
            "sources",
        ])

        for change in all_changes:
            sg_id = change["sg_id"]
            sg_name = change["sg_name"]
            timestamp = change["timestamp"]

            for rule_json in change["ingress_added"]:
                r = rule_to_dict(rule_json)
                writer.writerow([
                    sg_id, sg_name, timestamp,
                    "ingress", "added",
                    r["protocol"],
                    r.get("from_port", ""),
                    r.get("to_port", ""),
                    "; ".join(r["sources"]),
                ])

            for rule_json in change["ingress_removed"]:
                r = rule_to_dict(rule_json)
                writer.writerow([
                    sg_id, sg_name, timestamp,
                    "ingress", "removed",
                    r["protocol"],
                    r.get("from_port", ""),
                    r.get("to_port", ""),
                    "; ".join(r["sources"]),
                ])

            for rule_json in change["egress_added"]:
                r = rule_to_dict(rule_json)
                writer.writerow([
                    sg_id, sg_name, timestamp,
                    "egress", "added",
                    r["protocol"],
                    r.get("from_port", ""),
                    r.get("to_port", ""),
                    "; ".join(r["sources"]),
                ])

            for rule_json in change["egress_removed"]:
                r = rule_to_dict(rule_json)
                writer.writerow([
                    sg_id, sg_name, timestamp,
                    "egress", "removed",
                    r["protocol"],
                    r.get("from_port", ""),
                    r.get("to_port", ""),
                    "; ".join(r["sources"]),
                ])

    print(f"  CSV report:   {filename}")


def write_yaml_report(all_changes: list):
    """Write a YAML report - structured for easy CloudFormation reference."""
    yaml_data = {
        "report": {
            "region": REGION,
            "vpc_id": VPC_ID,
            "window_start": START_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "window_end": END_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        "security_groups": [],
    }

    # Group changes by SG
    sg_changes = {}
    for change in all_changes:
        sg_id = change["sg_id"]
        if sg_id not in sg_changes:
            sg_changes[sg_id] = {
                "sg_id": sg_id,
                "sg_name": change["sg_name"],
                "changes": [],
            }

        change_entry = {
            "timestamp": change["timestamp"],
        }

        if change["ingress_added"]:
            change_entry["ingress_added"] = [rule_to_dict(r) for r in change["ingress_added"]]
        if change["ingress_removed"]:
            change_entry["ingress_removed"] = [rule_to_dict(r) for r in change["ingress_removed"]]
        if change["egress_added"]:
            change_entry["egress_added"] = [rule_to_dict(r) for r in change["egress_added"]]
        if change["egress_removed"]:
            change_entry["egress_removed"] = [rule_to_dict(r) for r in change["egress_removed"]]

        sg_changes[sg_id]["changes"].append(change_entry)

    yaml_data["security_groups"] = list(sg_changes.values())

    filename = f"{OUTPUT_BASE}.yaml"
    with open(filename, "w") as f:
        yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, width=120)
    print(f"  YAML report:  {filename}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    check_config_recorder()
    print()
    print("=" * 60)
    print("Security Group Config Change Report (VPC-Wide)")
    print(f"Region: {REGION}")
    print(f"VPC:    {VPC_ID}")
    print(f"Window: {START_TIME.isoformat()} to {END_TIME.isoformat()}")
    print("=" * 60)
    print()

    # Discover all security groups in the VPC
    print("Discovering security groups in VPC...")
    security_groups = discover_security_groups()
    print(f"  Found {len(security_groups)} security group(s)")
    for sg in security_groups:
        print(f"    {sg['sg_id']} - {sg['sg_name']}")
    print()

    # Analyze each SG
    all_changes = []
    for sg in security_groups:
        changes = analyze_sg(sg["sg_id"], sg["sg_name"])
        all_changes.extend(changes)

    print()
    print(f"Total change events found: {len(all_changes)}")
    print()

    # Write all three output formats
    print("Writing reports...")
    write_text_report(all_changes, len(security_groups))
    write_csv_report(all_changes)
    write_yaml_report(all_changes)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
