#!/usr/bin/env python3
"""
compute-config-changes.py

Uses AWS Config to identify changes to EC2 instances, ELBv2 load balancers,
ELBv2 target groups, and S3 buckets within a specified VPC and date/time window.

Auto-discovers all resources in the target VPC (EC2, ELB, TGs) and all S3
buckets in the account/region.

Tracks changes to:
  - EC2: security groups, subnet, instance type, state, IAM role, tags
  - ALB/NLB: listeners, scheme, security groups, subnets, attributes
  - Target Groups: registered targets, health check config, attributes
  - S3: bucket policy, versioning, encryption, logging, public access block,
        lifecycle rules, CORS, replication, tags

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
      ec2:DescribeInstances
      elasticloadbalancing:DescribeLoadBalancers
      elasticloadbalancing:DescribeTargetGroups
      s3:ListAllMyBuckets
      s3:GetBucketLocation

Usage:
  python3 compute-config-changes.py --vpc-id vpc-xxx --region us-gov-east-1 --start 2026-06-15 --end 2026-06-29
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
        description="Identify compute resource changes in a VPC via AWS Config."
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
S3_REGIONS = [REGION]
OUTPUT_BASE = f"compute-changes-{VPC_ID}-{args.start}-{args.end}"


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


def get_elbv2_client():
    return boto3.client("elbv2", region_name=REGION)


def get_s3_client(region: str = None):
    return boto3.client("s3", region_name=region or REGION)


# ============================================================================
# DISCOVERY
# ============================================================================

def discover_ec2_instances() -> list:
    """Find all EC2 instances in the target VPC."""
    ec2 = get_ec2_client()
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "vpc-id", "Values": [VPC_ID]}]
    ):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                inst_id = inst["InstanceId"]
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                name = tags.get("Name", "")
                instances.append({"id": inst_id, "name": name})
    return instances


def discover_load_balancers() -> list:
    """Find all ELBv2 load balancers in the target VPC."""
    elbv2 = get_elbv2_client()
    lbs = []
    paginator = elbv2.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page["LoadBalancers"]:
            if lb.get("VpcId") == VPC_ID:
                lbs.append({
                    "id": lb["LoadBalancerArn"].split("/")[-2] + "/" + lb["LoadBalancerArn"].split("/")[-1],
                    "arn": lb["LoadBalancerArn"],
                    "name": lb["LoadBalancerName"],
                    "type": lb["Type"],
                })
    return lbs


def discover_target_groups() -> list:
    """Find all ELBv2 target groups in the target VPC."""
    elbv2 = get_elbv2_client()
    tgs = []
    paginator = elbv2.get_paginator("describe_target_groups")
    for page in paginator.paginate():
        for tg in page["TargetGroups"]:
            if tg.get("VpcId") == VPC_ID:
                tgs.append({
                    "id": tg["TargetGroupArn"].split(":")[-1],
                    "arn": tg["TargetGroupArn"],
                    "name": tg["TargetGroupName"],
                })
    return tgs


def discover_listeners(load_balancers: list) -> list:
    """Find all ELBv2 listeners for the discovered load balancers."""
    elbv2 = get_elbv2_client()
    listeners = []
    for lb in load_balancers:
        try:
            paginator = elbv2.get_paginator("describe_listeners")
            for page in paginator.paginate(LoadBalancerArn=lb["arn"]):
                for listener in page["Listeners"]:
                    listeners.append({
                        "arn": listener["ListenerArn"],
                        "lb_name": lb["name"],
                        "port": listener.get("Port", ""),
                        "protocol": listener.get("Protocol", ""),
                    })
        except Exception as e:
            print(f"  Warning: Could not list listeners for {lb['name']}: {e}")
    return listeners


def discover_s3_buckets() -> list:
    """Find all S3 buckets in the account across all tracked regions."""
    s3 = get_s3_client()
    buckets = []
    seen_names = set()

    response = s3.list_buckets()
    for bucket in response.get("Buckets", []):
        bucket_name = bucket.get("BucketName") or bucket.get("Name", "")
        if not bucket_name or bucket_name in seen_names:
            continue
        try:
            loc = s3.get_bucket_location(Bucket=bucket_name)
            bucket_region = loc.get("LocationConstraint") or "us-east-1"
            if bucket_region in S3_REGIONS:
                seen_names.add(bucket_name)
                buckets.append({
                    "name": bucket_name,
                    "region": bucket_region,
                    "creation_date": bucket.get("CreationDate", ""),
                })
        except Exception:
            pass

    return buckets


# ============================================================================
# CONFIG HISTORY
# ============================================================================

def get_config_history(resource_type: str, resource_id: str, region: str = None) -> list:
    """Retrieve configuration history for a resource within the time window."""
    client = boto3.client("config", region_name=region or REGION)
    items = []

    now = datetime.now(timezone.utc)
    effective_end = min(END_TIME, now)

    if START_TIME >= effective_end:
        print(f"    Warning: START_TIME is not before effective END_TIME ({effective_end}). Skipping.")
        return []

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
            items.extend(page.get("configurationItems", []))
    except client.exceptions.ResourceNotDiscoveredException:
        print(f"    Skipped: Config has not discovered this resource (not recorded by Config Recorder).")
    except Exception as e:
        print(f"    Error fetching config history: {e}")

    return items


# ============================================================================
# EC2 DIFFING
# ============================================================================

EC2_FIELDS = [
    "instanceType", "subnetId", "vpcId", "imageId", "state",
    "iamInstanceProfile", "securityGroups", "tags",
    "privateIpAddress", "publicIpAddress", "keyName",
]


def extract_ec2_config(config_json: str) -> dict:
    """Extract relevant EC2 fields from config JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    extracted = {}
    for field in EC2_FIELDS:
        val = config.get(field)
        if field == "state":
            extracted[field] = val.get("name", "") if isinstance(val, dict) else str(val)
        elif field == "securityGroups":
            extracted[field] = sorted([sg.get("groupId", "") for sg in (val or [])])
        elif field == "iamInstanceProfile":
            extracted[field] = val.get("arn", "") if isinstance(val, dict) else str(val or "")
        elif field == "tags":
            extracted[field] = {t["key"]: t["value"] for t in (val or [])} if val else {}
        else:
            extracted[field] = str(val) if val else ""
    return extracted


def diff_ec2(prev_json: str, curr_json: str) -> dict:
    """Diff two EC2 configuration snapshots."""
    prev = extract_ec2_config(prev_json)
    curr = extract_ec2_config(curr_json)
    changes = {}
    for field in EC2_FIELDS:
        old_val = prev.get(field)
        new_val = curr.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}
    return changes


# ============================================================================
# ELBv2 DIFFING
# ============================================================================

ELB_FIELDS = [
    "scheme", "type", "state", "securityGroups", "availabilityZones",
    "ipAddressType",
]


def extract_elb_config(config_json: str) -> dict:
    """Extract relevant ELBv2 fields from config JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    extracted = {}
    for field in ELB_FIELDS:
        val = config.get(field)
        if field == "securityGroups":
            extracted[field] = sorted(val) if val else []
        elif field == "availabilityZones":
            extracted[field] = sorted([
                az.get("subnetId", "") for az in (val or [])
            ])
        elif field == "state":
            extracted[field] = val.get("code", "") if isinstance(val, dict) else str(val or "")
        else:
            extracted[field] = str(val) if val else ""
    return extracted


def diff_elb(prev_json: str, curr_json: str) -> dict:
    """Diff two ELBv2 configuration snapshots."""
    prev = extract_elb_config(prev_json)
    curr = extract_elb_config(curr_json)
    changes = {}
    for field in ELB_FIELDS:
        old_val = prev.get(field)
        new_val = curr.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}
    return changes


# ============================================================================
# LISTENER DIFFING
# ============================================================================

LISTENER_FIELDS = [
    "protocol", "port", "sslPolicy", "certificates", "defaultActions",
]


def extract_listener_config(config_json: str) -> dict:
    """Extract relevant listener fields from Config JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    extracted = {}
    extracted["protocol"] = str(config.get("protocol", config.get("Protocol", "")))
    extracted["port"] = str(config.get("port", config.get("Port", "")))
    extracted["sslPolicy"] = str(config.get("sslPolicy", config.get("SslPolicy", config.get("SSLPolicy", ""))))

    certs = config.get("certificates", config.get("Certificates", []))
    extracted["certificates"] = json.dumps(certs, sort_keys=True) if certs else ""

    actions = config.get("defaultActions", config.get("DefaultActions", []))
    extracted["defaultActions"] = json.dumps(actions, sort_keys=True) if actions else ""

    return extracted


def diff_listener(prev_json: str, curr_json: str) -> dict:
    """Diff two listener configuration snapshots."""
    prev = extract_listener_config(prev_json)
    curr = extract_listener_config(curr_json)
    changes = {}

    for field in LISTENER_FIELDS:
        old_val = prev.get(field)
        new_val = curr.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}

    return changes


# ============================================================================
# TARGET GROUP DIFFING
# ============================================================================

TG_FIELDS = [
    "targetType", "protocol", "port", "healthCheckProtocol",
    "healthCheckPort", "healthCheckPath", "healthCheckIntervalSeconds",
    "healthyThresholdCount", "unhealthyThresholdCount",
]


def extract_tg_config(config_json: str) -> dict:
    """Extract relevant target group fields from config JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    extracted = {}
    for field in TG_FIELDS:
        extracted[field] = str(config.get(field, ""))

    targets = config.get("targets", config.get("registeredTargets", []))
    extracted["targets"] = sorted(
        [json.dumps(t, sort_keys=True) for t in (targets or [])]
    )
    return extracted


def diff_tg(prev_json: str, curr_json: str) -> dict:
    """Diff two target group configuration snapshots."""
    prev = extract_tg_config(prev_json)
    curr = extract_tg_config(curr_json)
    changes = {}

    for field in TG_FIELDS:
        old_val = prev.get(field)
        new_val = curr.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}

    old_targets = set(prev.get("targets", []))
    new_targets = set(curr.get("targets", []))
    if old_targets != new_targets:
        changes["targets_added"] = sorted(new_targets - old_targets)
        changes["targets_removed"] = sorted(old_targets - new_targets)

    return changes


# ============================================================================
# S3 BUCKET DIFFING
# ============================================================================

S3_FIELDS = [
    "versioning", "encryption", "logging_enabled", "logging_target",
    "public_access_block", "bucket_policy", "lifecycle_rules",
    "cors_rules", "replication", "tags",
]


def extract_s3_config(config_json: str) -> dict:
    """Extract relevant S3 bucket fields from Config JSON."""
    try:
        config = json.loads(config_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    extracted = {}

    def _get_config_value(key_camel: str, key_pascal: str):
        val = config.get(key_pascal) or config.get(key_camel) or {}
        if isinstance(val, str):
            try:
                val = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                val = {}
        return val

    versioning = _get_config_value("versioningConfiguration", "BucketVersioningConfiguration")
    extracted["versioning"] = versioning.get("status", "Disabled") if versioning else "Disabled"

    encryption = _get_config_value("serverSideEncryptionConfiguration", "ServerSideEncryptionConfiguration")
    if encryption:
        rules = encryption.get("rules", [])
        enc_summary = []
        for rule in rules:
            sse = rule.get("applyServerSideEncryptionByDefault", {})
            enc_summary.append(sse.get("sseAlgorithm", "unknown"))
        extracted["encryption"] = ", ".join(enc_summary) if enc_summary else "None"
    else:
        extracted["encryption"] = "None"

    logging_config = _get_config_value("loggingConfiguration", "BucketLoggingConfiguration")
    extracted["logging_enabled"] = "Enabled" if logging_config.get("destinationBucketName") else "Disabled"
    extracted["logging_target"] = logging_config.get("destinationBucketName", "") if logging_config else ""

    pab = _get_config_value("publicAccessBlockConfiguration", "PublicAccessBlockConfiguration")
    if pab:
        extracted["public_access_block"] = {
            "blockPublicAcls": pab.get("blockPublicAcls", False),
            "ignorePublicAcls": pab.get("ignorePublicAcls", False),
            "blockPublicPolicy": pab.get("blockPublicPolicy", False),
            "restrictPublicBuckets": pab.get("restrictPublicBuckets", False),
        }
    else:
        extracted["public_access_block"] = "Not configured"

    bucket_policy = _get_config_value("bucketPolicy", "BucketPolicy")
    policy_text = bucket_policy.get("policyText") if isinstance(bucket_policy, dict) else None
    if policy_text:
        try:
            parsed = json.loads(policy_text) if isinstance(policy_text, str) else policy_text
            extracted["bucket_policy"] = json.dumps(parsed, sort_keys=True)
        except (json.JSONDecodeError, TypeError):
            extracted["bucket_policy"] = str(policy_text)
    else:
        extracted["bucket_policy"] = ""

    lifecycle = _get_config_value("lifecycleConfiguration", "BucketLifecycleConfiguration")
    rules = lifecycle.get("rules", []) if lifecycle else []
    extracted["lifecycle_rules"] = json.dumps(rules, sort_keys=True) if rules else ""

    cors = _get_config_value("corsConfiguration", "BucketCORSConfiguration")
    cors_rules = cors.get("corsRules", []) if cors else []
    extracted["cors_rules"] = json.dumps(cors_rules, sort_keys=True) if cors_rules else ""

    replication = _get_config_value("replicationConfiguration", "BucketReplicationConfiguration")
    if replication:
        extracted["replication"] = json.dumps(replication, sort_keys=True)
    else:
        extracted["replication"] = ""

    tags_raw = (
        config.get("BucketTaggingConfiguration")
        or config.get("bucketTaggingConfiguration")
        or config.get("tags")
        or {}
    )

    tag_dict = {}
    try:
        if isinstance(tags_raw, dict):
            tag_sets = tags_raw.get("tagSets", tags_raw.get("TagSets", []))
            if isinstance(tag_sets, list):
                for tag_set in tag_sets:
                    if isinstance(tag_set, dict):
                        inner_tags = tag_set.get("tags", tag_set.get("Tags", []))
                        if isinstance(inner_tags, list):
                            for t in inner_tags:
                                if isinstance(t, dict):
                                    k = t.get("key", t.get("Key", ""))
                                    v = t.get("value", t.get("Value", ""))
                                    tag_dict[k] = v
        elif isinstance(tags_raw, list):
            for t in tags_raw:
                if isinstance(t, dict):
                    k = t.get("key", t.get("Key", ""))
                    v = t.get("value", t.get("Value", ""))
                    tag_dict[k] = v
    except (TypeError, AttributeError):
        tag_dict = {}

    extracted["tags"] = tag_dict

    return extracted


def diff_s3(prev_json: str, curr_json: str) -> dict:
    """Diff two S3 bucket configuration snapshots."""
    prev = extract_s3_config(prev_json)
    curr = extract_s3_config(curr_json)
    changes = {}

    for field in S3_FIELDS:
        old_val = prev.get(field)
        new_val = curr.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}

    return changes


def analyze_s3_bucket(bucket_name: str, bucket_region: str = None) -> list:
    """Analyze a single S3 bucket. Detects new buckets and changes."""
    region_display = bucket_region or REGION
    print(f"  Fetching config history for bucket {bucket_name} (querying {region_display} Config)...")

    items = get_config_history("AWS::S3::Bucket", bucket_name, region=bucket_region)

    if not items:
        bucket_arn = f"arn:aws-us-gov:s3:::{bucket_name}"
        print(f"    No items by name, trying ARN: {bucket_arn}")
        items = get_config_history("AWS::S3::Bucket", bucket_arn, region=bucket_region)
        if items:
            print(f"    (Found {len(items)} item(s) via ARN lookup)")

    if not items:
        print(f"    No config items found in window.")
        return []

    print(f"    Found {len(items)} config item(s) to analyze.")

    changes = []

    if len(items) == 1:
        item = items[0]
        status = item.get("configurationItemStatus", "")

        if status == "ResourceDiscovered":
            timestamp = item.get("configurationItemCaptureTime", "unknown")
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            curr_config = extract_s3_config(_merge_config(item))
            details = {"event": "bucket_created"}
            if curr_config.get("versioning") != "Disabled":
                details["versioning"] = curr_config["versioning"]
            if curr_config.get("encryption") != "None":
                details["encryption"] = curr_config["encryption"]
            if curr_config.get("public_access_block") != "Not configured":
                details["public_access_block"] = curr_config["public_access_block"]
            if curr_config.get("logging_enabled") == "Enabled":
                details["logging_target"] = curr_config["logging_target"]
            if curr_config.get("bucket_policy"):
                details["has_bucket_policy"] = True
            if curr_config.get("tags"):
                details["tags"] = curr_config["tags"]

            changes.append({
                "resource_type": "S3 Bucket",
                "resource_id": bucket_name,
                "resource_name": bucket_name,
                "timestamp": str(timestamp),
                "changes": details,
            })
            print(f"    NEW BUCKET detected (created in window).")
            return changes

        print(f"    Only 1 config item found (status: {status}) - no changes to diff.")
        return []

    for i in range(1, len(items)):
        prev_item = items[i - 1]
        curr_item = items[i]

        diff = diff_s3(
            _merge_config(prev_item),
            _merge_config(curr_item),
        )

        if diff:
            timestamp = curr_item.get("configurationItemCaptureTime", "unknown")
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            changes.append({
                "resource_type": "S3 Bucket",
                "resource_id": bucket_name,
                "resource_name": bucket_name,
                "timestamp": str(timestamp),
                "changes": diff,
            })

    if not changes:
        print(f"    No S3 configuration changes detected in window.")
    else:
        print(f"    Found {len(changes)} change event(s).")

    return changes


# ============================================================================
# ANALYSIS
# ============================================================================

def _merge_config(config_item: dict) -> str:
    """Merge a Config item's configuration and supplementaryConfiguration."""
    config_str = config_item.get("configuration", "{}")
    try:
        config = json.loads(config_str) if isinstance(config_str, str) else config_str
    except (json.JSONDecodeError, TypeError):
        config = {}

    if not isinstance(config, dict):
        config = {}

    supp = config_item.get("supplementaryConfiguration", {})
    if isinstance(supp, str):
        try:
            supp = json.loads(supp)
        except (json.JSONDecodeError, TypeError):
            supp = {}

    if supp and isinstance(supp, dict):
        for key, value in supp.items():
            if isinstance(value, str):
                try:
                    config[key] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    config[key] = value
            else:
                config[key] = value

    return json.dumps(config)


def analyze_resource(resource_type: str, resource_id: str, resource_name: str,
                     diff_func, config_type_str: str) -> list:
    """Generic analysis for a Config-tracked resource."""
    print(f"  Fetching config history for {resource_id} ({resource_name})...")
    items = get_config_history(resource_type, resource_id)

    if len(items) < 2:
        print(f"    Only {len(items)} config item(s) found - no changes to diff.")
        return []

    changes = []
    for i in range(1, len(items)):
        prev_item = items[i - 1]
        curr_item = items[i]

        diff = diff_func(
            _merge_config(prev_item),
            _merge_config(curr_item),
        )

        if diff:
            timestamp = curr_item.get("configurationItemCaptureTime", "unknown")
            if hasattr(timestamp, "strftime"):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            changes.append({
                "resource_type": config_type_str,
                "resource_id": resource_id,
                "resource_name": resource_name,
                "timestamp": str(timestamp),
                "changes": diff,
            })

    if not changes:
        print(f"    No configuration changes detected in window.")
    else:
        print(f"    Found {len(changes)} change event(s).")

    return changes


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

def format_change_value(val) -> str:
    """Format a value for text display."""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    if isinstance(val, dict):
        return str(val)
    return str(val)


def write_text_report(all_changes: list, counts: dict):
    """Write a human-readable text report."""
    lines = []
    lines.append("=" * 80)
    lines.append("COMPUTE RESOURCE CHANGES REPORT")
    lines.append("=" * 80)
    lines.append(f"Region:                  {REGION}")
    lines.append(f"VPC:                     {VPC_ID}")
    lines.append(f"Window:                  {START_TIME.strftime('%Y-%m-%d %H:%M')} to {END_TIME.strftime('%Y-%m-%d %H:%M')} UTC")
    lines.append(f"EC2 Instances Found:     {counts['ec2']}")
    lines.append(f"Load Balancers Found:    {counts['elb']}")
    lines.append(f"Target Groups Found:     {counts['tg']}")
    lines.append(f"S3 Buckets Found:        {counts['s3']}")
    lines.append(f"Total Change Events:     {len(all_changes)}")
    lines.append("=" * 80)
    lines.append("")

    if not all_changes:
        lines.append("No configuration changes detected for any resource in the specified window.")
    else:
        current_resource = None
        for change in all_changes:
            resource_key = f"{change['resource_type']}:{change['resource_id']}"
            if resource_key != current_resource:
                current_resource = resource_key
                lines.append("-" * 80)
                lines.append(f"  [{change['resource_type']}] {change['resource_name']}  ({change['resource_id']})")
                lines.append("-" * 80)
                lines.append("")

            lines.append(f"  Change recorded: {change['timestamp']}")
            lines.append("")

            for field, detail in change["changes"].items():
                if field == "event" and detail == "bucket_created":
                    lines.append(f"    *** NEW S3 BUCKET CREATED ***")
                elif field in ("targets_added", "targets_removed"):
                    action = "ADDED" if "added" in field else "REMOVED"
                    lines.append(f"    Targets {action}:")
                    for t in detail:
                        lines.append(f"      {'+ ' if 'added' in field else '- '}{t}")
                elif isinstance(detail, dict) and "old" in detail and "new" in detail:
                    lines.append(f"    {field}:")
                    lines.append(f"      old: {format_change_value(detail['old'])}")
                    lines.append(f"      new: {format_change_value(detail['new'])}")
                else:
                    lines.append(f"    {field}: {format_change_value(detail)}")
            lines.append("")

    filename = f"{OUTPUT_BASE}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(lines))
    print(f"  Text report:  {filename}")


def write_csv_report(all_changes: list):
    """Write a CSV report - one row per field change."""
    filename = f"{OUTPUT_BASE}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "resource_type",
            "resource_id",
            "resource_name",
            "timestamp",
            "field",
            "old_value",
            "new_value",
        ])

        for change in all_changes:
            for field, detail in change["changes"].items():
                if field in ("targets_added", "targets_removed"):
                    action = "added" if "added" in field else "removed"
                    for t in detail:
                        writer.writerow([
                            change["resource_type"],
                            change["resource_id"],
                            change["resource_name"],
                            change["timestamp"],
                            f"target_{action}",
                            "" if action == "added" else t,
                            t if action == "added" else "",
                        ])
                elif isinstance(detail, dict) and "old" in detail and "new" in detail:
                    writer.writerow([
                        change["resource_type"],
                        change["resource_id"],
                        change["resource_name"],
                        change["timestamp"],
                        field,
                        format_change_value(detail["old"]),
                        format_change_value(detail["new"]),
                    ])

    print(f"  CSV report:   {filename}")


def write_yaml_report(all_changes: list):
    """Write a YAML report."""
    yaml_data = {
        "report": {
            "region": REGION,
            "vpc_id": VPC_ID,
            "window_start": START_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "window_end": END_TIME.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        "changes": [],
    }

    for change in all_changes:
        entry = {
            "resource_type": change["resource_type"],
            "resource_id": change["resource_id"],
            "resource_name": change["resource_name"],
            "timestamp": change["timestamp"],
            "fields_changed": {},
        }
        for field, detail in change["changes"].items():
            if isinstance(detail, dict) and "old" in detail and "new" in detail:
                entry["fields_changed"][field] = {
                    "old": detail["old"],
                    "new": detail["new"],
                }
            else:
                entry["fields_changed"][field] = detail
        yaml_data["changes"].append(entry)

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
    print("Compute Resource Config Change Report")
    print(f"Region: {REGION}")
    print(f"VPC:    {VPC_ID}")
    print(f"Window: {START_TIME.isoformat()} to {END_TIME.isoformat()}")
    print("=" * 60)
    print()

    # Discover resources
    print("Discovering EC2 instances...")
    ec2_instances = discover_ec2_instances()
    print(f"  Found {len(ec2_instances)} instance(s)")

    print("Discovering load balancers...")
    load_balancers = discover_load_balancers()
    print(f"  Found {len(load_balancers)} load balancer(s)")

    print("Discovering target groups...")
    target_groups = discover_target_groups()
    print(f"  Found {len(target_groups)} target group(s)")

    print(f"Discovering S3 buckets in {', '.join(S3_REGIONS)}...")
    s3_buckets = discover_s3_buckets()
    print(f"  Found {len(s3_buckets)} S3 bucket(s)")
    print()

    counts = {
        "ec2": len(ec2_instances),
        "elb": len(load_balancers),
        "listeners": 0,
        "tg": len(target_groups),
        "s3": len(s3_buckets),
    }

    all_changes = []

    # Analyze EC2 instances
    print("Analyzing EC2 instances...")
    for inst in ec2_instances:
        changes = analyze_resource(
            "AWS::EC2::Instance", inst["id"], inst["name"],
            diff_ec2, "EC2 Instance",
        )
        all_changes.extend(changes)

    # Analyze load balancers
    print("Analyzing load balancers...")
    for lb in load_balancers:
        changes = analyze_resource(
            "AWS::ElasticLoadBalancingV2::LoadBalancer", lb["arn"], lb["name"],
            diff_elb, f"ELBv2 ({lb['type']})",
        )
        all_changes.extend(changes)

    # Analyze listeners
    print("Discovering and analyzing listeners...")
    listeners = discover_listeners(load_balancers)
    counts["listeners"] = len(listeners)
    print(f"  Found {len(listeners)} listener(s)")
    for listener in listeners:
        display_name = f"{listener['lb_name']}:{listener['port']}/{listener['protocol']}"
        changes = analyze_resource(
            "AWS::ElasticLoadBalancingV2::Listener", listener["arn"], display_name,
            diff_listener, "Listener",
        )
        all_changes.extend(changes)

    # Analyze target groups
    print("Analyzing target groups...")
    for tg in target_groups:
        changes = analyze_resource(
            "AWS::ElasticLoadBalancingV2::TargetGroup", tg["arn"], tg["name"],
            diff_tg, "Target Group",
        )
        all_changes.extend(changes)

    # Analyze S3 buckets
    print("Analyzing S3 buckets...")
    for bucket in s3_buckets:
        changes = analyze_s3_bucket(bucket["name"], bucket_region=bucket.get("region"))
        all_changes.extend(changes)

    print()
    print(f"Total change events found: {len(all_changes)}")
    print()

    # Write all three output formats
    print("Writing reports...")
    write_text_report(all_changes, counts)
    write_csv_report(all_changes)
    write_yaml_report(all_changes)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
