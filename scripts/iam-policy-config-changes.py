#!/usr/bin/env python3
"""
iam-policy-config-changes.py

Uses AWS Config to identify changes to customer-managed IAM policies
and IAM roles within a specified date/time window.

Auto-discovers all customer-managed policies and roles in the account.
Diffs policy document versions to show statements added/removed/changed.
Diffs role configurations to show trust policy changes, attached/inline
policy changes, and metadata modifications.

Output formats:
  - Text (.txt)  - Human-readable report
  - CSV  (.csv)  - Spreadsheet-friendly
  - YAML (.yaml) - Structured data for CloudFormation reference

Requirements:
  - boto3
  - pyyaml (pip install pyyaml)
  - AWS Config Recorder must be/have been enabled in the target region
  - IAM permissions:
      config:GetResourceConfigHistory
      iam:ListPolicies
      iam:GetPolicyVersion
      iam:ListRoles

Usage:
  python3 iam-policy-config-changes.py --region us-gov-east-1 --region us-gov-west-1 --start 2026-06-10 --end 2026-06-29
"""

import argparse
import boto3
import csv
import json
import yaml
from datetime import datetime, timezone
from urllib.parse import unquote

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Identify IAM policy and role changes via AWS Config."
    )
    parser.add_argument(
        "--region", required=True, action="append",
        help="AWS region(s) to query Config from (can be specified multiple times)"
    )
    parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")
    return parser.parse_args()


args = parse_args()
REGIONS = args.region
START_TIME = datetime.strptime(args.start, "%Y-%m-%d").replace(hour=0, minute=0, second=0, tzinfo=timezone.utc)
END_TIME = datetime.strptime(args.end, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
OUTPUT_BASE = f"iam-changes-{args.start}-{args.end}"


# ============================================================================
# PREFLIGHT CHECK
# ============================================================================

def check_config_recorder():
    """Verify AWS Config Recorder is active in the target region(s)."""
    for region in REGIONS:
        client = boto3.client("config", region_name=region)
        try:
            resp = client.describe_configuration_recorder_status()
            statuses = resp.get("ConfigurationRecordersStatus", [])
            if not statuses:
                print(f"WARNING: No Config Recorder found in {region}. Results may be incomplete.")
                continue
            for status in statuses:
                if not status.get("recording", False):
                    print(f"WARNING: Config Recorder '{status.get('name', '')}' is NOT recording in {region}.")
                else:
                    print(f"Config Recorder '{status.get('name', '')}' is active in {region}.")
        except Exception as e:
            print(f"WARNING: Could not verify Config Recorder status in {region}: {e}")


# ============================================================================
# AWS CLIENTS
# ============================================================================

def get_config_client(region: str = None):
    return boto3.client("config", region_name=region or REGIONS[0])


def get_iam_client():
    return boto3.client("iam", region_name=REGIONS[0])


# ============================================================================
# DISCOVERY
# ============================================================================

def discover_customer_managed_policies() -> list:
    """Enumerate all customer-managed IAM policies."""
    iam = get_iam_client()
    policies = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            policies.append({
                "arn": policy["Arn"],
                "name": policy["PolicyName"],
                "policy_id": policy["PolicyId"],
                "path": policy.get("Path", "/"),
                "default_version": policy.get("DefaultVersionId", ""),
            })
    return policies


def discover_iam_roles() -> list:
    """Enumerate all IAM roles in the account (excluding service-linked)."""
    iam = get_iam_client()
    roles = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            roles.append({
                "arn": role["Arn"],
                "name": role["RoleName"],
                "role_id": role["RoleId"],
                "path": role.get("Path", "/"),
                "create_date": role.get("CreateDate", ""),
            })
    return roles


# ============================================================================
# CONFIG HISTORY
# ============================================================================

def get_config_history_for_resource(resource_type: str, resource_id: str) -> list:
    """Retrieve configuration history for any IAM resource within the time window.
    
    Queries all configured regions and deduplicates.
    """
    all_items = []

    now = datetime.now(timezone.utc)
    effective_end = min(END_TIME, now)

    if START_TIME >= effective_end:
        print(f"    Warning: START_TIME is not before effective END_TIME ({effective_end}). Skipping.")
        return []

    for region in REGIONS:
        client = get_config_client(region)
        try:
            paginator = client.get_paginator("get_resource_config_history")
            page_iterator = paginator.paginate(
                resourceType=resource_type,
                resourceId=resource_id,
                laterTime=effective_end,
                earlierTime=START_TIME,
                chronologicalOrder="Forward",
            )
            for page in page_iterator:
                all_items.extend(page.get("configurationItems", []))
        except client.exceptions.ResourceNotDiscoveredException:
            pass
        except Exception as e:
            print(f"    Error fetching config history from {region}: {e}")

    # Deduplicate
    seen = set()
    unique_items = []
    for item in all_items:
        capture_time = str(item.get("configurationItemCaptureTime", ""))
        config_hash = hash(item.get("configuration", ""))
        key = (capture_time, config_hash)
        if key not in seen:
            seen.add(key)
            unique_items.append(item)

    unique_items.sort(key=lambda x: str(x.get("configurationItemCaptureTime", "")))

    if not unique_items:
        print(f"    Skipped: Config has not discovered this resource in any region.")

    return unique_items


def get_config_history(policy_arn: str) -> list:
    """Retrieve configuration history for an IAM policy within the time window."""
    return get_config_history_for_resource("AWS::IAM::Policy", policy_arn)


# ============================================================================
# POLICY DOCUMENT PARSING AND DIFFING
# ============================================================================

def extract_policy_config(config_json: str) -> dict:
    """Extract relevant policy fields from config JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    result = {
        "policy_name": config.get("policyName", ""),
        "default_version_id": config.get("defaultVersionId", ""),
        "attachment_count": config.get("attachmentCount", 0),
        "description": config.get("description", ""),
    }

    policy_version_list = config.get("policyVersionList", [])
    default_version = config.get("defaultVersionId", "v1")

    doc = None
    for version in policy_version_list:
        if version.get("versionId") == default_version:
            raw_doc = version.get("document", "")
            if raw_doc:
                try:
                    decoded = unquote(raw_doc)
                    doc = json.loads(decoded)
                except (json.JSONDecodeError, TypeError):
                    try:
                        doc = json.loads(raw_doc)
                    except (json.JSONDecodeError, TypeError):
                        doc = None
            break

    result["policy_document"] = doc
    return result


def normalize_statement(stmt: dict) -> str:
    """Normalize a policy statement for comparison."""
    normalized = {
        "Effect": stmt.get("Effect", ""),
        "Action": sorted(stmt["Action"]) if isinstance(stmt.get("Action"), list) else [stmt.get("Action", "")],
        "Resource": sorted(stmt["Resource"]) if isinstance(stmt.get("Resource"), list) else [stmt.get("Resource", "")],
    }
    if "Condition" in stmt:
        normalized["Condition"] = stmt["Condition"]
    if "Sid" in stmt:
        normalized["Sid"] = stmt["Sid"]
    if "Principal" in stmt:
        normalized["Principal"] = stmt["Principal"]
    return json.dumps(normalized, sort_keys=True)


def diff_policy_documents(prev_doc: dict, curr_doc: dict) -> dict:
    """Diff two policy documents, returning added/removed/changed statements."""
    if prev_doc is None and curr_doc is None:
        return {}
    if prev_doc is None:
        prev_doc = {"Statement": []}
    if curr_doc is None:
        curr_doc = {"Statement": []}

    prev_stmts = prev_doc.get("Statement", [])
    curr_stmts = curr_doc.get("Statement", [])

    prev_set = set(normalize_statement(s) for s in prev_stmts)
    curr_set = set(normalize_statement(s) for s in curr_stmts)

    added = curr_set - prev_set
    removed = prev_set - curr_set

    result = {}
    if added:
        result["statements_added"] = [json.loads(s) for s in sorted(added)]
    if removed:
        result["statements_removed"] = [json.loads(s) for s in sorted(removed)]
    return result


def diff_policy(prev_json: str, curr_json: str) -> dict:
    """Full diff of policy configuration."""
    prev = extract_policy_config(prev_json)
    curr = extract_policy_config(curr_json)
    changes = {}

    for field in ["default_version_id", "attachment_count", "description"]:
        old_val = prev.get(field)
        new_val = curr.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}

    doc_diff = diff_policy_documents(
        prev.get("policy_document"),
        curr.get("policy_document"),
    )
    if doc_diff:
        changes.update(doc_diff)

    return changes


# ============================================================================
# ROLE CONFIGURATION PARSING AND DIFFING
# ============================================================================

def extract_role_config(config_json: str) -> dict:
    """Extract relevant role fields from Config JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    result = {
        "role_name": config.get("roleName", ""),
        "path": config.get("path", "/"),
        "max_session_duration": config.get("maxSessionDuration", 3600),
        "description": config.get("description", ""),
    }

    trust_doc = config.get("assumeRolePolicyDocument", "")
    if trust_doc:
        if isinstance(trust_doc, str):
            try:
                decoded = unquote(trust_doc)
                result["trust_policy"] = json.loads(decoded)
            except (json.JSONDecodeError, TypeError):
                try:
                    result["trust_policy"] = json.loads(trust_doc)
                except (json.JSONDecodeError, TypeError):
                    result["trust_policy"] = None
        elif isinstance(trust_doc, dict):
            result["trust_policy"] = trust_doc
        else:
            result["trust_policy"] = None
    else:
        result["trust_policy"] = None

    attached = config.get("attachedManagedPolicies", [])
    result["attached_policies"] = sorted(
        [p.get("policyArn", p.get("policyName", "")) for p in attached]
    ) if attached else []

    inline_policies = config.get("rolePolicyList", [])
    result["inline_policies"] = {}
    for inline in inline_policies:
        policy_name = inline.get("policyName", "")
        policy_doc = inline.get("policyDocument", "")
        if isinstance(policy_doc, str):
            try:
                decoded = unquote(policy_doc)
                result["inline_policies"][policy_name] = json.loads(decoded)
            except (json.JSONDecodeError, TypeError):
                try:
                    result["inline_policies"][policy_name] = json.loads(policy_doc)
                except (json.JSONDecodeError, TypeError):
                    result["inline_policies"][policy_name] = None
        elif isinstance(policy_doc, dict):
            result["inline_policies"][policy_name] = policy_doc
        else:
            result["inline_policies"][policy_name] = None

    instance_profiles = config.get("instanceProfileList", [])
    result["instance_profiles"] = sorted(
        [ip.get("instanceProfileName", "") for ip in instance_profiles]
    ) if instance_profiles else []

    return result


def diff_role_config(prev_json: str, curr_json: str) -> dict:
    """Full diff of role configuration between two Config snapshots."""
    prev = extract_role_config(prev_json)
    curr = extract_role_config(curr_json)
    changes = {}

    for field in ["description", "max_session_duration", "path"]:
        old_val = prev.get(field)
        new_val = curr.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}

    trust_diff = diff_policy_documents(
        prev.get("trust_policy"),
        curr.get("trust_policy"),
    )
    if trust_diff:
        renamed = {}
        if "statements_added" in trust_diff:
            renamed["trust_statements_added"] = trust_diff["statements_added"]
        if "statements_removed" in trust_diff:
            renamed["trust_statements_removed"] = trust_diff["statements_removed"]
        changes.update(renamed)

    prev_attached = set(prev.get("attached_policies", []))
    curr_attached = set(curr.get("attached_policies", []))
    policies_added = curr_attached - prev_attached
    policies_removed = prev_attached - curr_attached
    if policies_added:
        changes["managed_policies_attached"] = sorted(policies_added)
    if policies_removed:
        changes["managed_policies_detached"] = sorted(policies_removed)

    prev_inline = prev.get("inline_policies", {})
    curr_inline = curr.get("inline_policies", {})
    prev_inline_names = set(prev_inline.keys())
    curr_inline_names = set(curr_inline.keys())

    inline_added = curr_inline_names - prev_inline_names
    inline_removed = prev_inline_names - curr_inline_names
    inline_common = prev_inline_names & curr_inline_names

    if inline_added:
        changes["inline_policies_added"] = sorted(inline_added)
    if inline_removed:
        changes["inline_policies_removed"] = sorted(inline_removed)

    inline_modified = {}
    for name in sorted(inline_common):
        doc_diff = diff_policy_documents(prev_inline.get(name), curr_inline.get(name))
        if doc_diff:
            inline_modified[name] = doc_diff
    if inline_modified:
        changes["inline_policies_modified"] = inline_modified

    prev_profiles = set(prev.get("instance_profiles", []))
    curr_profiles = set(curr.get("instance_profiles", []))
    profiles_added = curr_profiles - prev_profiles
    profiles_removed = prev_profiles - curr_profiles
    if profiles_added:
        changes["instance_profiles_added"] = sorted(profiles_added)
    if profiles_removed:
        changes["instance_profiles_removed"] = sorted(profiles_removed)

    return changes


# ============================================================================
# ANALYSIS
# ============================================================================

def analyze_policy(policy: dict) -> list:
    """Analyze a single IAM policy. Returns list of change dicts."""
    policy_arn = policy["arn"]
    policy_name = policy["name"]
    policy_id = policy["policy_id"]
    print(f"  Fetching config history for {policy_name} ({policy_id})...")
    items = get_config_history(policy_id)

    if len(items) < 2:
        print(f"    Only {len(items)} config item(s) found - no changes to diff.")
        return []

    changes = []
    for i in range(1, len(items)):
        prev_item = items[i - 1]
        curr_item = items[i]

        diff = diff_policy(
            prev_item.get("configuration", "{}"),
            curr_item.get("configuration", "{}"),
        )

        if diff:
            timestamp = curr_item.get("configurationItemCaptureTime", "unknown")
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            changes.append({
                "policy_arn": policy_arn,
                "policy_name": policy_name,
                "policy_id": policy_id,
                "timestamp": str(timestamp),
                "changes": diff,
            })

    if not changes:
        print(f"    No policy changes detected in window.")
    else:
        print(f"    Found {len(changes)} change event(s).")

    return changes


def analyze_role(role: dict) -> list:
    """Analyze a single IAM role. Returns list of change dicts."""
    role_name = role["name"]
    role_id = role["role_id"]
    role_arn = role["arn"]
    print(f"  Fetching config history for role {role_name} ({role_id})...")
    items = get_config_history_for_resource("AWS::IAM::Role", role_name)

    if not items:
        print(f"    No config items found in window.")
        return []

    changes = []

    if len(items) == 1:
        item = items[0]
        status = item.get("configurationItemStatus", "")
        capture_time = item.get("configurationItemCaptureTime", "")

        if status == "ResourceDiscovered":
            timestamp = capture_time
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            curr_config = extract_role_config(item.get("configuration", "{}"))
            details = {"event": "role_created"}
            if curr_config.get("trust_policy"):
                details["trust_policy"] = curr_config["trust_policy"]
            if curr_config.get("attached_policies"):
                details["managed_policies_attached"] = curr_config["attached_policies"]
            if curr_config.get("inline_policies"):
                details["inline_policies_added"] = sorted(curr_config["inline_policies"].keys())
            if curr_config.get("instance_profiles"):
                details["instance_profiles"] = curr_config["instance_profiles"]

            changes.append({
                "role_arn": role_arn,
                "role_name": role_name,
                "role_id": role_id,
                "timestamp": str(timestamp),
                "changes": details,
            })
            print(f"    NEW ROLE detected (created in window).")
            return changes

        print(f"    Only 1 config item found (status: {status}) - no changes to diff.")
        return []

    for i in range(1, len(items)):
        prev_item = items[i - 1]
        curr_item = items[i]

        diff = diff_role_config(
            prev_item.get("configuration", "{}"),
            curr_item.get("configuration", "{}"),
        )

        if diff:
            timestamp = curr_item.get("configurationItemCaptureTime", "unknown")
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            changes.append({
                "role_arn": role_arn,
                "role_name": role_name,
                "role_id": role_id,
                "timestamp": str(timestamp),
                "changes": diff,
            })

    if not changes:
        print(f"    No role changes detected in window.")
    else:
        print(f"    Found {len(changes)} change event(s).")

    return changes


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

def format_statement(stmt: dict) -> str:
    """Format a policy statement for text display."""
    effect = stmt.get("Effect", "")
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    action_str = ", ".join(actions[:5])
    if len(actions) > 5:
        action_str += f" (+{len(actions) - 5} more)"
    resource_str = ", ".join(resources[:3])
    if len(resources) > 3:
        resource_str += f" (+{len(resources) - 3} more)"
    sid = stmt.get("Sid", "")
    sid_str = f"[{sid}] " if sid else ""
    return f"{sid_str}{effect}: {action_str} on {resource_str}"


def write_text_report(all_changes: list, policy_count: int, role_changes: list, role_count: int):
    """Write a human-readable text report."""
    lines = []
    lines.append("=" * 80)
    lines.append("IAM CUSTOMER-MANAGED POLICY & ROLE CHANGES REPORT")
    lines.append("=" * 80)
    lines.append(f"Region:                    {', '.join(REGIONS)} (all queried)")
    lines.append(f"Window:                    {START_TIME.strftime('%Y-%m-%d %H:%M')} to {END_TIME.strftime('%Y-%m-%d %H:%M')} UTC")
    lines.append(f"Customer Policies Found:   {policy_count}")
    lines.append(f"Policies with Changes:     {len(set(c['policy_arn'] for c in all_changes))}")
    lines.append(f"Total Policy Change Events:{len(all_changes)}")
    lines.append(f"IAM Roles Found:           {role_count}")
    lines.append(f"Roles with Changes:        {len(set(c['role_arn'] for c in role_changes))}")
    lines.append(f"Total Role Change Events:  {len(role_changes)}")
    lines.append("=" * 80)
    lines.append("")

    # Policy changes section
    lines.append("~" * 80)
    lines.append("  SECTION: CUSTOMER-MANAGED POLICY CHANGES")
    lines.append("~" * 80)
    lines.append("")

    if not all_changes:
        lines.append("No changes detected for any customer-managed policy in the specified window.")
    else:
        current_policy = None
        for change in all_changes:
            if change["policy_arn"] != current_policy:
                current_policy = change["policy_arn"]
                lines.append("-" * 80)
                lines.append(f"  {change['policy_name']}")
                lines.append(f"  {change['policy_arn']}")
                lines.append("-" * 80)
                lines.append("")

            lines.append(f"  Change recorded: {change['timestamp']}")
            lines.append("")

            for field, detail in change["changes"].items():
                if field == "statements_added":
                    lines.append("    STATEMENTS ADDED:")
                    for stmt in detail:
                        lines.append(f"      + {format_statement(stmt)}")
                    lines.append("")
                elif field == "statements_removed":
                    lines.append("    STATEMENTS REMOVED:")
                    for stmt in detail:
                        lines.append(f"      - {format_statement(stmt)}")
                    lines.append("")
                elif isinstance(detail, dict) and "old" in detail and "new" in detail:
                    lines.append(f"    {field}:")
                    lines.append(f"      old: {detail['old']}")
                    lines.append(f"      new: {detail['new']}")
                    lines.append("")

            lines.append("")

    # Role changes section
    lines.append("")
    lines.append("~" * 80)
    lines.append("  SECTION: IAM ROLE CHANGES")
    lines.append("~" * 80)
    lines.append("")

    if not role_changes:
        lines.append("No changes detected for any IAM role in the specified window.")
    else:
        current_role = None
        for change in role_changes:
            if change["role_arn"] != current_role:
                current_role = change["role_arn"]
                lines.append("-" * 80)
                lines.append(f"  {change['role_name']}")
                lines.append(f"  {change['role_arn']}")
                lines.append("-" * 80)
                lines.append("")

            lines.append(f"  Change recorded: {change['timestamp']}")
            lines.append("")

            for field, detail in change["changes"].items():
                if field == "event" and detail == "role_created":
                    lines.append("    *** NEW ROLE CREATED ***")
                    lines.append("")
                elif field == "trust_policy":
                    lines.append("    INITIAL TRUST POLICY:")
                    for stmt in detail.get("Statement", []):
                        lines.append(f"      {format_statement(stmt)}")
                    lines.append("")
                elif field == "trust_statements_added":
                    lines.append("    TRUST POLICY - STATEMENTS ADDED:")
                    for stmt in detail:
                        lines.append(f"      + {format_statement(stmt)}")
                    lines.append("")
                elif field == "trust_statements_removed":
                    lines.append("    TRUST POLICY - STATEMENTS REMOVED:")
                    for stmt in detail:
                        lines.append(f"      - {format_statement(stmt)}")
                    lines.append("")
                elif field == "managed_policies_attached":
                    lines.append("    MANAGED POLICIES ATTACHED:")
                    for p in detail:
                        lines.append(f"      + {p}")
                    lines.append("")
                elif field == "managed_policies_detached":
                    lines.append("    MANAGED POLICIES DETACHED:")
                    for p in detail:
                        lines.append(f"      - {p}")
                    lines.append("")
                elif field == "inline_policies_added":
                    lines.append("    INLINE POLICIES ADDED:")
                    for p in detail:
                        lines.append(f"      + {p}")
                    lines.append("")
                elif field == "inline_policies_removed":
                    lines.append("    INLINE POLICIES REMOVED:")
                    for p in detail:
                        lines.append(f"      - {p}")
                    lines.append("")
                elif field == "inline_policies_modified":
                    lines.append("    INLINE POLICIES MODIFIED:")
                    for name, doc_diff in detail.items():
                        lines.append(f"      Policy: {name}")
                        if "statements_added" in doc_diff:
                            for stmt in doc_diff["statements_added"]:
                                lines.append(f"        + {format_statement(stmt)}")
                        if "statements_removed" in doc_diff:
                            for stmt in doc_diff["statements_removed"]:
                                lines.append(f"        - {format_statement(stmt)}")
                    lines.append("")
                elif field == "instance_profiles_added":
                    lines.append("    INSTANCE PROFILES ADDED:")
                    for p in detail:
                        lines.append(f"      + {p}")
                    lines.append("")
                elif field == "instance_profiles_removed":
                    lines.append("    INSTANCE PROFILES REMOVED:")
                    for p in detail:
                        lines.append(f"      - {p}")
                    lines.append("")
                elif field == "instance_profiles":
                    lines.append("    INSTANCE PROFILES:")
                    for p in detail:
                        lines.append(f"      {p}")
                    lines.append("")
                elif isinstance(detail, dict) and "old" in detail and "new" in detail:
                    lines.append(f"    {field}:")
                    lines.append(f"      old: {detail['old']}")
                    lines.append(f"      new: {detail['new']}")
                    lines.append("")

            lines.append("")

    filename = f"{OUTPUT_BASE}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(lines))
    print(f"  Text report:  {filename}")


def write_csv_report(all_changes: list, role_changes: list):
    """Write a CSV report."""
    filename = f"{OUTPUT_BASE}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "resource_type",
            "resource_arn",
            "resource_name",
            "timestamp",
            "change_type",
            "field_or_sid",
            "effect",
            "actions",
            "resources",
            "old_value",
            "new_value",
        ])

        for change in all_changes:
            arn = change["policy_arn"]
            name = change["policy_name"]
            ts = change["timestamp"]

            for field, detail in change["changes"].items():
                if field == "statements_added":
                    for stmt in detail:
                        writer.writerow([
                            "Policy", arn, name, ts,
                            "statement_added",
                            stmt.get("Sid", ""),
                            stmt.get("Effect", ""),
                            "; ".join(stmt.get("Action", [])),
                            "; ".join(stmt.get("Resource", [])),
                            "", "",
                        ])
                elif field == "statements_removed":
                    for stmt in detail:
                        writer.writerow([
                            "Policy", arn, name, ts,
                            "statement_removed",
                            stmt.get("Sid", ""),
                            stmt.get("Effect", ""),
                            "; ".join(stmt.get("Action", [])),
                            "; ".join(stmt.get("Resource", [])),
                            "", "",
                        ])
                elif isinstance(detail, dict) and "old" in detail and "new" in detail:
                    writer.writerow([
                        "Policy", arn, name, ts,
                        "metadata_change",
                        field, "", "", "",
                        str(detail["old"]),
                        str(detail["new"]),
                    ])

        for change in role_changes:
            arn = change["role_arn"]
            name = change["role_name"]
            ts = change["timestamp"]

            for field, detail in change["changes"].items():
                if field == "event" and detail == "role_created":
                    writer.writerow([
                        "Role", arn, name, ts,
                        "role_created",
                        "", "", "", "", "",
                    ])
                elif field == "trust_statements_added":
                    for stmt in detail:
                        writer.writerow([
                            "Role", arn, name, ts,
                            "trust_statement_added",
                            stmt.get("Sid", ""),
                            stmt.get("Effect", ""),
                            "; ".join(stmt.get("Action", [])),
                            "; ".join(stmt.get("Resource", [])),
                            "", "",
                        ])
                elif field == "trust_statements_removed":
                    for stmt in detail:
                        writer.writerow([
                            "Role", arn, name, ts,
                            "trust_statement_removed",
                            stmt.get("Sid", ""),
                            stmt.get("Effect", ""),
                            "; ".join(stmt.get("Action", [])),
                            "; ".join(stmt.get("Resource", [])),
                            "", "",
                        ])
                elif field == "managed_policies_attached":
                    for p in detail:
                        writer.writerow([
                            "Role", arn, name, ts,
                            "managed_policy_attached",
                            p, "", "", "", "", "",
                        ])
                elif field == "managed_policies_detached":
                    for p in detail:
                        writer.writerow([
                            "Role", arn, name, ts,
                            "managed_policy_detached",
                            p, "", "", "", "", "",
                        ])
                elif field == "inline_policies_added":
                    for p in detail:
                        writer.writerow([
                            "Role", arn, name, ts,
                            "inline_policy_added",
                            p, "", "", "", "", "",
                        ])
                elif field == "inline_policies_removed":
                    for p in detail:
                        writer.writerow([
                            "Role", arn, name, ts,
                            "inline_policy_removed",
                            p, "", "", "", "", "",
                        ])
                elif field == "inline_policies_modified":
                    for pname, doc_diff in detail.items():
                        if "statements_added" in doc_diff:
                            for stmt in doc_diff["statements_added"]:
                                writer.writerow([
                                    "Role", arn, name, ts,
                                    "inline_statement_added",
                                    f"{pname}/{stmt.get('Sid', '')}",
                                    stmt.get("Effect", ""),
                                    "; ".join(stmt.get("Action", [])),
                                    "; ".join(stmt.get("Resource", [])),
                                    "", "",
                                ])
                        if "statements_removed" in doc_diff:
                            for stmt in doc_diff["statements_removed"]:
                                writer.writerow([
                                    "Role", arn, name, ts,
                                    "inline_statement_removed",
                                    f"{pname}/{stmt.get('Sid', '')}",
                                    stmt.get("Effect", ""),
                                    "; ".join(stmt.get("Action", [])),
                                    "; ".join(stmt.get("Resource", [])),
                                    "", "",
                                ])
                elif isinstance(detail, dict) and "old" in detail and "new" in detail:
                    writer.writerow([
                        "Role", arn, name, ts,
                        "metadata_change",
                        field, "", "", "",
                        str(detail["old"]),
                        str(detail["new"]),
                    ])

    print(f"  CSV report:   {filename}")


def write_yaml_report(all_changes: list, role_changes: list):
    """Write a YAML report."""
    yaml_data = {
        "report": {
            "regions": REGIONS,
            "window_start": START_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "window_end": END_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        "policies": [],
        "roles": [],
    }

    policy_changes = {}
    for change in all_changes:
        arn = change["policy_arn"]
        if arn not in policy_changes:
            policy_changes[arn] = {
                "policy_arn": arn,
                "policy_name": change["policy_name"],
                "changes": [],
            }
        policy_changes[arn]["changes"].append({
            "timestamp": change["timestamp"],
            "details": change["changes"],
        })

    yaml_data["policies"] = list(policy_changes.values())

    role_changes_grouped = {}
    for change in role_changes:
        arn = change["role_arn"]
        if arn not in role_changes_grouped:
            role_changes_grouped[arn] = {
                "role_arn": arn,
                "role_name": change["role_name"],
                "changes": [],
            }
        role_changes_grouped[arn]["changes"].append({
            "timestamp": change["timestamp"],
            "details": change["changes"],
        })

    yaml_data["roles"] = list(role_changes_grouped.values())

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
    print("IAM Customer-Managed Policy & Role Change Report")
    print(f"Regions: {', '.join(REGIONS)}")
    print(f"Window: {START_TIME.isoformat()} to {END_TIME.isoformat()}")
    print("=" * 60)
    print()

    # Discover customer-managed policies
    print("Discovering customer-managed IAM policies...")
    policies = discover_customer_managed_policies()
    print(f"  Found {len(policies)} customer-managed policy(ies)")
    for p in policies:
        print(f"    {p['name']} ({p['arn']})")
    print()

    # Analyze each policy
    all_changes = []
    for policy in policies:
        changes = analyze_policy(policy)
        all_changes.extend(changes)

    print()
    print(f"Total policy change events found: {len(all_changes)}")
    print()

    # Discover IAM roles
    print("Discovering IAM roles...")
    roles = discover_iam_roles()
    print(f"  Found {len(roles)} IAM role(s) (excluding service-linked)")
    for r in roles:
        print(f"    {r['name']} ({r['arn']})")
    print()

    # Analyze each role
    all_role_changes = []
    for role in roles:
        changes = analyze_role(role)
        all_role_changes.extend(changes)

    print()
    print(f"Total role change events found: {len(all_role_changes)}")
    print()

    # Write all three output formats
    print("Writing reports...")
    write_text_report(all_changes, len(policies), all_role_changes, len(roles))
    write_csv_report(all_changes, all_role_changes)
    write_yaml_report(all_changes, all_role_changes)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
