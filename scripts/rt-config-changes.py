#!/usr/bin/env python3
"""
rt-config-changes.py

Uses AWS Config to identify route changes made to route tables within a
specified VPC and date/time window. Enumerates all route tables for the
given VPC automatically.

Special handling: For routes involving specified enrichment prefixes,
the script enriches the output with the ENI ID (eni-xxx) and the subnet
the ENI is attached to.

Output formats:
  - Text (.txt)  - Human-readable report for review
  - CSV  (.csv)  - Spreadsheet-friendly for tracking/filtering
  - YAML (.yaml) - Structured data, handy for CloudFormation reference

Requirements:
  - boto3
  - pyyaml (pip install pyyaml)
  - AWS Config Recorder must be/have been enabled in the target region
  - IAM permissions:
      config:GetResourceConfigHistory
      ec2:DescribeRouteTables
      ec2:DescribeNetworkInterfaces

Usage:
  python3 rt-config-changes.py --vpc-id vpc-xxx --region us-gov-east-1 --start 2026-04-15 --end 2026-06-29
  python3 rt-config-changes.py --vpc-id vpc-xxx --region us-gov-east-1 --start 2026-04-15 --end 2026-06-29 --enrichment-prefixes "192.168.237.,192.168.238."
"""

import argparse
import boto3
import csv
import json
import yaml
from datetime import datetime, timezone
from typing import Optional

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Identify route table changes in a VPC via AWS Config."
    )
    parser.add_argument("--vpc-id", required=True, help="VPC ID to scan")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")
    parser.add_argument(
        "--enrichment-prefixes", default="",
        help="Comma-separated CIDR prefixes for ENI enrichment (e.g. '192.168.237.,192.168.238.')"
    )
    return parser.parse_args()


args = parse_args()
VPC_ID = args.vpc_id
REGION = args.region
START_TIME = datetime.strptime(args.start, "%Y-%m-%d").replace(hour=0, minute=0, second=0, tzinfo=timezone.utc)
END_TIME = datetime.strptime(args.end, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
ENRICHMENT_PREFIXES = [p.strip() for p in args.enrichment_prefixes.split(",") if p.strip()]
OUTPUT_BASE = f"rt-changes-{VPC_ID}-{args.start}-{args.end}"


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

def discover_route_tables() -> list:
    """Enumerate all route tables in the target VPC."""
    ec2 = get_ec2_client()
    route_tables = []
    paginator = ec2.get_paginator("describe_route_tables")
    for page in paginator.paginate(
        Filters=[{"Name": "vpc-id", "Values": [VPC_ID]}]
    ):
        for rt in page["RouteTables"]:
            rt_id = rt["RouteTableId"]
            tags = {t["Key"]: t["Value"] for t in rt.get("Tags", [])}
            name = tags.get("Name", "")
            # Collect associated subnets
            assoc_subnets = [
                a.get("SubnetId", "")
                for a in rt.get("Associations", [])
                if a.get("SubnetId")
            ]
            route_tables.append({
                "rt_id": rt_id,
                "rt_name": name,
                "associated_subnets": assoc_subnets,
            })
    return route_tables


# ============================================================================
# ENI ENRICHMENT
# ============================================================================

_eni_cache = {}


def get_eni_details(eni_id: str) -> dict:
    """Look up an ENI to get its subnet and description."""
    if eni_id in _eni_cache:
        return _eni_cache[eni_id]

    ec2 = get_ec2_client()
    try:
        resp = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        eni = resp["NetworkInterfaces"][0]
        details = {
            "eni_id": eni_id,
            "subnet_id": eni.get("SubnetId", "(unknown)"),
            "description": eni.get("Description", ""),
            "private_ip": eni.get("PrivateIpAddress", ""),
            "status": eni.get("Status", ""),
        }
    except Exception as e:
        details = {
            "eni_id": eni_id,
            "subnet_id": "(lookup failed)",
            "description": str(e),
            "private_ip": "",
            "status": "",
        }
    _eni_cache[eni_id] = details
    return details


def route_matches_enrichment_prefixes(route: dict) -> bool:
    """Check if a route's destination matches our prefixes of interest."""
    if not ENRICHMENT_PREFIXES:
        return False
    dest = route.get("destinationCidrBlock", "")
    for prefix in ENRICHMENT_PREFIXES:
        if dest.startswith(prefix):
            return True
    return False


def enrich_route(route: dict) -> dict:
    """If route targets an ENI and matches our prefixes, enrich with ENI details."""
    enrichment = {}
    # Routes targeting an ENI have networkInterfaceId
    eni_id = route.get("networkInterfaceId", "")
    if eni_id and route_matches_enrichment_prefixes(route):
        enrichment = get_eni_details(eni_id)
    return enrichment


# ============================================================================
# CONFIG HISTORY
# ============================================================================

def get_config_history(rt_id: str) -> list:
    """Retrieve configuration history for a route table within the time window."""
    client = get_config_client()
    items = []

    # Cap end time to now if it's in the future - Config API rejects future times
    now = datetime.now(timezone.utc)
    effective_end = min(END_TIME, now)

    if START_TIME >= effective_end:
        print(f"    Warning: START_TIME is not before effective END_TIME ({effective_end}). Skipping.")
        return []

    paginator = client.get_paginator("get_resource_config_history")
    page_iterator = paginator.paginate(
        resourceType="AWS::EC2::RouteTable",
        resourceId=rt_id,
        laterTime=effective_end,
        earlierTime=START_TIME,
        chronologicalOrder="Forward",
    )
    for page in page_iterator:
        items.extend(page.get("configurationItems", []))
    return items


# ============================================================================
# ROUTE PARSING AND DIFFING
# ============================================================================

def parse_routes(config_json: str) -> list:
    """Parse routes from a route table configuration item's JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return []
    return config.get("routeSet", config.get("routes", []))


def normalize_route(route: dict) -> dict:
    """Normalize a route for consistent comparison."""
    return {
        "destinationCidrBlock": route.get("destinationCidrBlock", ""),
        "destinationIpv6CidrBlock": route.get("destinationIpv6CidrBlock", ""),
        "destinationPrefixListId": route.get("destinationPrefixListId", ""),
        "gatewayId": route.get("gatewayId", ""),
        "natGatewayId": route.get("natGatewayId", ""),
        "networkInterfaceId": route.get("networkInterfaceId", ""),
        "transitGatewayId": route.get("transitGatewayId", ""),
        "vpcPeeringConnectionId": route.get("vpcPeeringConnectionId", ""),
        "instanceId": route.get("instanceId", ""),
        "state": route.get("state", ""),
    }


def routes_to_set(routes: list) -> set:
    """Convert a list of routes to a set of frozen representations for diffing."""
    result = set()
    for route in routes:
        nr = normalize_route(route)
        frozen = json.dumps(nr, sort_keys=True)
        result.add(frozen)
    return result


def diff_routes(old_routes: list, new_routes: list) -> tuple:
    """Return (added, removed) route sets between two snapshots."""
    old_set = routes_to_set(old_routes)
    new_set = routes_to_set(new_routes)
    added = new_set - old_set
    removed = old_set - new_set
    return added, removed


# ============================================================================
# FORMATTING HELPERS
# ============================================================================

def format_route_text(route_json: str, enrichment: dict = None) -> str:
    """Format a normalized route into a human-readable string."""
    r = json.loads(route_json)
    dest = r["destinationCidrBlock"] or r["destinationIpv6CidrBlock"] or r["destinationPrefixListId"] or "(no dest)"

    # Determine target
    target_parts = []
    if r["gatewayId"]:
        target_parts.append(f"gw:{r['gatewayId']}")
    if r["natGatewayId"]:
        target_parts.append(f"nat:{r['natGatewayId']}")
    if r["networkInterfaceId"]:
        target_parts.append(f"eni:{r['networkInterfaceId']}")
    if r["transitGatewayId"]:
        target_parts.append(f"tgw:{r['transitGatewayId']}")
    if r["vpcPeeringConnectionId"]:
        target_parts.append(f"pcx:{r['vpcPeeringConnectionId']}")
    if r["instanceId"]:
        target_parts.append(f"instance:{r['instanceId']}")

    target = ", ".join(target_parts) if target_parts else "local"
    state = r["state"]
    line = f"{dest} -> {target} [{state}]"

    if enrichment:
        line += f"  ** ENI: {enrichment['eni_id']} | Subnet: {enrichment['subnet_id']}"
        if enrichment.get("description"):
            line += f" | Desc: {enrichment['description']}"

    return line


def route_to_dict(route_json: str, enrichment: dict = None) -> dict:
    """Convert a normalized route JSON string to a clean dict for YAML/CSV output."""
    r = json.loads(route_json)
    dest = r["destinationCidrBlock"] or r["destinationIpv6CidrBlock"] or r["destinationPrefixListId"] or ""

    # Determine target type and value
    target_type = "local"
    target_id = ""
    if r["gatewayId"]:
        target_type = "gateway"
        target_id = r["gatewayId"]
    elif r["natGatewayId"]:
        target_type = "nat_gateway"
        target_id = r["natGatewayId"]
    elif r["networkInterfaceId"]:
        target_type = "network_interface"
        target_id = r["networkInterfaceId"]
    elif r["transitGatewayId"]:
        target_type = "transit_gateway"
        target_id = r["transitGatewayId"]
    elif r["vpcPeeringConnectionId"]:
        target_type = "vpc_peering"
        target_id = r["vpcPeeringConnectionId"]
    elif r["instanceId"]:
        target_type = "instance"
        target_id = r["instanceId"]

    result = {
        "destination": dest,
        "target_type": target_type,
        "target_id": target_id,
        "state": r["state"],
    }

    if enrichment:
        result["eni_id"] = enrichment["eni_id"]
        result["eni_subnet_id"] = enrichment["subnet_id"]
        result["eni_description"] = enrichment.get("description", "")
        result["eni_private_ip"] = enrichment.get("private_ip", "")

    return result


# ============================================================================
# ANALYSIS
# ============================================================================

def analyze_route_table(rt_info: dict) -> list:
    """Analyze a single route table. Returns list of change dicts."""
    rt_id = rt_info["rt_id"]
    rt_name = rt_info["rt_name"]
    print(f"  Fetching config history for {rt_id} ({rt_name})...")
    items = get_config_history(rt_id)

    if len(items) < 2:
        print(f"    Only {len(items)} config item(s) found - no changes to diff.")
        return []

    changes = []
    for i in range(1, len(items)):
        prev_item = items[i - 1]
        curr_item = items[i]

        prev_routes = parse_routes(prev_item.get("configuration", "{}"))
        curr_routes = parse_routes(curr_item.get("configuration", "{}"))

        routes_added, routes_removed = diff_routes(prev_routes, curr_routes)

        if routes_added or routes_removed:
            timestamp = curr_item.get("configurationItemCaptureTime", "unknown")
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            # Enrich routes that match our prefixes of interest
            added_enriched = []
            for route_json in sorted(routes_added):
                route_dict = json.loads(route_json)
                enrichment = enrich_route(route_dict)
                added_enriched.append({
                    "route_json": route_json,
                    "enrichment": enrichment,
                })

            removed_enriched = []
            for route_json in sorted(routes_removed):
                route_dict = json.loads(route_json)
                enrichment = enrich_route(route_dict)
                removed_enriched.append({
                    "route_json": route_json,
                    "enrichment": enrichment,
                })

            changes.append({
                "rt_id": rt_id,
                "rt_name": rt_name,
                "associated_subnets": rt_info["associated_subnets"],
                "timestamp": str(timestamp),
                "routes_added": added_enriched,
                "routes_removed": removed_enriched,
            })

    if not changes:
        print(f"    No route changes detected in window.")
    else:
        print(f"    Found {len(changes)} change event(s).")

    return changes


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

def write_text_report(all_changes: list, route_tables: list):
    """Write a human-readable text report."""
    lines = []
    lines.append("=" * 80)
    lines.append("ROUTE TABLE CHANGES REPORT")
    lines.append("=" * 80)
    lines.append(f"Region:                {REGION}")
    lines.append(f"VPC:                   {VPC_ID}")
    lines.append(f"Window:                {START_TIME.strftime('%Y-%m-%d %H:%M')} to {END_TIME.strftime('%Y-%m-%d %H:%M')} UTC")
    lines.append(f"Route Tables Found:    {len(route_tables)}")
    lines.append(f"RTs with Changes:      {len(set(c['rt_id'] for c in all_changes))}")
    lines.append(f"Total Change Events:   {len(all_changes)}")
    lines.append(f"Enrichment Prefixes:   {', '.join(ENRICHMENT_PREFIXES) if ENRICHMENT_PREFIXES else '(none)'}")
    lines.append("=" * 80)
    lines.append("")

    if not all_changes:
        lines.append("No route changes detected for any route table in the specified window.")
    else:
        current_rt = None
        for change in all_changes:
            if change["rt_id"] != current_rt:
                current_rt = change["rt_id"]
                lines.append("-" * 80)
                lines.append(f"  {change['rt_name']}  ({change['rt_id']})")
                if change["associated_subnets"]:
                    lines.append(f"  Associated subnets: {', '.join(change['associated_subnets'])}")
                lines.append("-" * 80)
                lines.append("")

            lines.append(f"  Change recorded: {change['timestamp']}")
            lines.append("")

            if change["routes_added"]:
                lines.append("    ROUTES ADDED:")
                for entry in change["routes_added"]:
                    enrichment = entry["enrichment"] if entry["enrichment"] else None
                    lines.append(f"      + {format_route_text(entry['route_json'], enrichment)}")
                lines.append("")

            if change["routes_removed"]:
                lines.append("    ROUTES REMOVED:")
                for entry in change["routes_removed"]:
                    enrichment = entry["enrichment"] if entry["enrichment"] else None
                    lines.append(f"      - {format_route_text(entry['route_json'], enrichment)}")
                lines.append("")

            lines.append("")

    filename = f"{OUTPUT_BASE}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(lines))
    print(f"  Text report:  {filename}")


def write_csv_report(all_changes: list):
    """Write a CSV report - one row per route change."""
    filename = f"{OUTPUT_BASE}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "rt_id",
            "rt_name",
            "associated_subnets",
            "timestamp",
            "action",
            "destination",
            "target_type",
            "target_id",
            "state",
            "eni_id",
            "eni_subnet_id",
            "eni_description",
            "eni_private_ip",
        ])

        for change in all_changes:
            rt_id = change["rt_id"]
            rt_name = change["rt_name"]
            assoc_subnets = "; ".join(change["associated_subnets"])
            timestamp = change["timestamp"]

            for entry in change["routes_added"]:
                r = route_to_dict(entry["route_json"], entry["enrichment"] or None)
                writer.writerow([
                    rt_id, rt_name, assoc_subnets, timestamp,
                    "added",
                    r["destination"],
                    r["target_type"],
                    r["target_id"],
                    r["state"],
                    r.get("eni_id", ""),
                    r.get("eni_subnet_id", ""),
                    r.get("eni_description", ""),
                    r.get("eni_private_ip", ""),
                ])

            for entry in change["routes_removed"]:
                r = route_to_dict(entry["route_json"], entry["enrichment"] or None)
                writer.writerow([
                    rt_id, rt_name, assoc_subnets, timestamp,
                    "removed",
                    r["destination"],
                    r["target_type"],
                    r["target_id"],
                    r["state"],
                    r.get("eni_id", ""),
                    r.get("eni_subnet_id", ""),
                    r.get("eni_description", ""),
                    r.get("eni_private_ip", ""),
                ])

    print(f"  CSV report:   {filename}")


def write_yaml_report(all_changes: list):
    """Write a YAML report - structured for CloudFormation reference."""
    yaml_data = {
        "report": {
            "region": REGION,
            "vpc_id": VPC_ID,
            "window_start": START_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "window_end": END_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "enrichment_prefixes": ENRICHMENT_PREFIXES,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        "route_tables": [],
    }

    # Group changes by route table
    rt_changes = {}
    for change in all_changes:
        rt_id = change["rt_id"]
        if rt_id not in rt_changes:
            rt_changes[rt_id] = {
                "rt_id": rt_id,
                "rt_name": change["rt_name"],
                "associated_subnets": change["associated_subnets"],
                "changes": [],
            }

        change_entry = {
            "timestamp": change["timestamp"],
        }

        if change["routes_added"]:
            change_entry["routes_added"] = [
                route_to_dict(e["route_json"], e["enrichment"] or None)
                for e in change["routes_added"]
            ]
        if change["routes_removed"]:
            change_entry["routes_removed"] = [
                route_to_dict(e["route_json"], e["enrichment"] or None)
                for e in change["routes_removed"]
            ]

        rt_changes[rt_id]["changes"].append(change_entry)

    yaml_data["route_tables"] = list(rt_changes.values())

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
    print("Route Table Config Change Report")
    print(f"Region: {REGION}")
    print(f"VPC:    {VPC_ID}")
    print(f"Window: {START_TIME.isoformat()} to {END_TIME.isoformat()}")
    print(f"Enrichment prefixes: {ENRICHMENT_PREFIXES if ENRICHMENT_PREFIXES else '(none)'}")
    print("=" * 60)
    print()

    # Discover route tables in the VPC
    print("Discovering route tables...")
    route_tables = discover_route_tables()
    print(f"  Found {len(route_tables)} route table(s) in {VPC_ID}")
    for rt in route_tables:
        subnets = ", ".join(rt["associated_subnets"]) if rt["associated_subnets"] else "(main/unassociated)"
        print(f"    {rt['rt_id']} - {rt['rt_name']} -> subnets: {subnets}")
    print()

    # Analyze each route table
    all_changes = []
    for rt_info in route_tables:
        changes = analyze_route_table(rt_info)
        all_changes.extend(changes)

    print()
    print(f"Total change events found: {len(all_changes)}")
    print()

    # Write all three output formats
    print("Writing reports...")
    write_text_report(all_changes, route_tables)
    write_csv_report(all_changes)
    write_yaml_report(all_changes)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
