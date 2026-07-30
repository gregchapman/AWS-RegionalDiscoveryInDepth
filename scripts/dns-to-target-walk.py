#!/usr/bin/env python3
"""
dns-to-target-walk.py

Walks the full path from DNS records through load balancers to target instances.
Outputs a hierarchical markdown report suitable for customer delivery.

DNS Record → Load Balancer → Security Groups → Listeners → Rules → Target Groups → Targets (health)

Usage:
  python3 dns-to-target-walk.py --zone-id Z0712928DILH42U83LKS --region us-gov-east-1
"""

import argparse
import boto3
import json
from datetime import datetime, timezone

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Walk DNS records through load balancers to target instances."
    )
    parser.add_argument("--zone-id", required=True, help="Route53 Hosted Zone ID")
    parser.add_argument("--region", required=True, help="AWS region (e.g., us-gov-east-1)")
    return parser.parse_args()


args = parse_args()
HOSTED_ZONE_ID = args.zone_id
REGION = args.region
OUTPUT_FILE = f"dns-to-target-{HOSTED_ZONE_ID}-report.md"

# ============================================================================
# AWS CLIENTS
# ============================================================================

r53 = boto3.client("route53")
elbv2 = boto3.client("elbv2", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)

# Caches
_lb_cache = {}
_sg_cache = {}
_instance_cache = {}


def get_dns_records():
    records = []
    paginator = r53.get_paginator("list_resource_record_sets")
    for page in paginator.paginate(HostedZoneId=HOSTED_ZONE_ID):
        for rr in page["ResourceRecordSets"]:
            if rr["Type"] not in ("A", "CNAME"):
                continue
            if rr["Name"].startswith("_"):
                continue
            records.append(rr)
    return records


def get_lb_by_dns(dns_name):
    dns_clean = dns_name.rstrip(".").replace("dualstack.", "")
    if dns_clean in _lb_cache:
        return _lb_cache[dns_clean]
    paginator = elbv2.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page["LoadBalancers"]:
            lb_dns = lb.get("DNSName", "")
            if not lb_dns:
                continue
            lb_dns = lb_dns.rstrip(".")
            _lb_cache[lb_dns] = lb
            if lb_dns == dns_clean:
                return lb
    _lb_cache[dns_clean] = None
    return None


def get_listeners(lb_arn):
    listeners = []
    paginator = elbv2.get_paginator("describe_listeners")
    for page in paginator.paginate(LoadBalancerArn=lb_arn):
        listeners.extend(page["Listeners"])
    return listeners


def get_rules(listener_arn):
    try:
        return elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    except Exception:
        return []


def get_target_group(tg_arn):
    try:
        resp = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])
        return resp["TargetGroups"][0] if resp["TargetGroups"] else None
    except Exception:
        return None


def get_target_health(tg_arn):
    try:
        return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    except Exception:
        return []


def get_security_group(sg_id):
    if sg_id in _sg_cache:
        return _sg_cache[sg_id]
    try:
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = resp["SecurityGroups"][0] if resp["SecurityGroups"] else None
    except Exception:
        sg = None
    _sg_cache[sg_id] = sg
    return sg


def get_instance_name(instance_id):
    if instance_id in _instance_cache:
        return _instance_cache[instance_id]
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        for res in resp["Reservations"]:
            for inst in res["Instances"]:
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                name = tags.get("Name", instance_id)
                _instance_cache[instance_id] = name
                return name
    except Exception:
        pass
    _instance_cache[instance_id] = instance_id
    return instance_id


def format_sg_rules(sg, direction="ingress"):
    lines = []
    rules = sg.get("IpPermissions" if direction == "ingress" else "IpPermissionsEgress", [])
    for rule in rules:
        protocol = rule.get("IpProtocol", "-1")
        if protocol == "-1":
            protocol = "ALL"
        from_port = rule.get("FromPort", "ALL")
        to_port = rule.get("ToPort", "ALL")
        port_str = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"

        sources = []
        for cidr in rule.get("IpRanges", []):
            desc = cidr.get("Description", "")
            sources.append(f"{cidr['CidrIp']}" + (f" ({desc})" if desc else ""))
        for sg_pair in rule.get("UserIdGroupPairs", []):
            desc = sg_pair.get("Description", "")
            sources.append(f"sg:{sg_pair.get('GroupId', '?')}" + (f" ({desc})" if desc else ""))
        for pl in rule.get("PrefixListIds", []):
            sources.append(f"pl:{pl.get('PrefixListId', '?')}")

        for source in sources:
            lines.append(f"{protocol}/{port_str} from {source}")
        if not sources:
            lines.append(f"{protocol}/{port_str} from (any)")
    return lines


def walk_record(record, lines):
    name = record["Name"].rstrip(".")
    rtype = record["Type"]

    if "AliasTarget" in record:
        target_dns = record["AliasTarget"]["DNSName"].rstrip(".")
        lines.append(f"### {name}")
        lines.append(f"- **Type:** A (ALIAS)")
        lines.append(f"- **Target:** `{target_dns}`")
    elif "ResourceRecords" in record:
        values = [rr["Value"] for rr in record["ResourceRecords"]]
        target_dns = values[0] if values else ""
        lines.append(f"### {name}")
        lines.append(f"- **Type:** {rtype}")
        lines.append(f"- **Target:** `{', '.join(values)}`")
    else:
        return

    lb = get_lb_by_dns(target_dns)
    if not lb:
        lines.append(f"- *(Target is not a load balancer in this region — may be a CNAME chain)*")
        lines.append("")
        lines.append("---")
        lines.append("")
        return

    lb_name = lb["LoadBalancerName"]
    lb_type = lb["Type"]
    lb_scheme = lb["Scheme"]
    lb_state = lb.get("State", {}).get("Code", "unknown")
    lb_arn = lb["LoadBalancerArn"]

    lines.append("")
    lines.append(f"#### Load Balancer: {lb_name}")
    lines.append(f"- **Type:** {lb_type} | **Scheme:** {lb_scheme} | **State:** {lb_state}")

    # Security groups
    sg_ids = lb.get("SecurityGroups", [])
    if sg_ids:
        lines.append("")
        lines.append("**Security Groups:**")
        for sg_id in sg_ids:
            sg = get_security_group(sg_id)
            if sg:
                sg_name = sg.get("GroupName", "")
                ingress_count = len(sg.get("IpPermissions", []))
                lines.append(f"- `{sg_name}` (`{sg_id}`) — {ingress_count} ingress rules")
                ingress_rules = format_sg_rules(sg, "ingress")
                for rule in ingress_rules[:10]:
                    lines.append(f"  - ALLOW `{rule}`")
                if len(ingress_rules) > 10:
                    lines.append(f"  - *... +{len(ingress_rules) - 10} more*")
            else:
                lines.append(f"- `{sg_id}` *(details unavailable)*")
    else:
        lines.append("- **Security Groups:** ⚠️ NONE ATTACHED")

    # Listeners
    listeners = get_listeners(lb_arn)
    lines.append("")
    lines.append(f"**Listeners ({len(listeners)}):**")
    lines.append("")

    for listener in sorted(listeners, key=lambda l: l.get("Port", 0)):
        port = listener.get("Port", "?")
        protocol = listener.get("Protocol", "?")
        ssl_policy = listener.get("SslPolicy", "")
        certs = listener.get("Certificates", [])
        listener_arn = listener["ListenerArn"]

        cert_info = ""
        if certs:
            cert_arn = certs[0].get("CertificateArn", "")
            cert_info = f" | Cert: `...{cert_arn[-20:]}`" if cert_arn else ""
        ssl_info = f" | SSL: `{ssl_policy}`" if ssl_policy else ""

        lines.append(f"**`{protocol}/{port}`**{ssl_info}{cert_info}")

        for action in listener.get("DefaultActions", []):
            action_type = action.get("Type", "?")

            if action_type == "forward":
                tg_arn = action.get("TargetGroupArn", "")
                if tg_arn:
                    tg = get_target_group(tg_arn)
                    if tg:
                        tg_name = tg.get("TargetGroupName", "?")
                        tg_proto = tg.get("Protocol", "?")
                        tg_port = tg.get("Port", "?")
                        tg_type = tg.get("TargetType", "?")
                        hc_proto = tg.get("HealthCheckProtocol", "")
                        hc_port = tg.get("HealthCheckPort", "")
                        hc_path = tg.get("HealthCheckPath", "")
                        hc_interval = tg.get("HealthCheckIntervalSeconds", "")

                        lines.append(f"- → **Target Group:** `{tg_name}` ({tg_proto}/{tg_port}, type: {tg_type})")
                        lines.append(f"  - Health Check: `{hc_proto}:{hc_port}{hc_path}` every {hc_interval}s")

                        health_list = get_target_health(tg_arn)
                        if health_list:
                            lines.append(f"  - **Targets:**")
                            for th in health_list:
                                tid = th.get("Target", {}).get("Id", "?")
                                tport = th.get("Target", {}).get("Port", "?")
                                state = th.get("TargetHealth", {}).get("State", "unknown")
                                reason = th.get("TargetHealth", {}).get("Reason", "")
                                desc = th.get("TargetHealth", {}).get("Description", "")

                                if tid.startswith("i-"):
                                    display = f"{get_instance_name(tid)} (`{tid}`)"
                                else:
                                    display = f"`{tid}`"

                                icon = "✅" if state == "healthy" else "❌" if state == "unhealthy" else "⚠️"
                                extra = f" — {reason}: {desc}" if reason else ""
                                lines.append(f"    - {icon} {display}:{tport} **[{state}]**{extra}")
                        else:
                            lines.append(f"  - Targets: *(none registered)*")

            elif action_type == "fixed-response":
                fc = action.get("FixedResponseConfig", {})
                lines.append(f"- → **Fixed Response:** `{fc.get('StatusCode', '?')}` ({fc.get('ContentType', '')})")

            elif action_type == "redirect":
                rc = action.get("RedirectConfig", {})
                lines.append(f"- → **Redirect:** `{rc.get('Protocol', '')}://{rc.get('Host', '')}{rc.get('Path', '')}` [{rc.get('StatusCode', '')}]")

        # Non-default rules
        rules = get_rules(listener_arn)
        non_default = [r for r in rules if not r.get("IsDefault", False)]
        if non_default:
            lines.append(f"")
            lines.append(f"  **Additional Rules ({len(non_default)}):**")
            for rule in non_default:
                priority = rule.get("Priority", "?")
                conditions = rule.get("Conditions", [])
                cond_strs = []
                for cond in conditions:
                    field = cond.get("Field", "")
                    values = cond.get("Values", [])
                    cond_strs.append(f"`{field}={','.join(values)}`")
                action_strs = []
                for ra in rule.get("Actions", []):
                    if ra["Type"] == "forward":
                        tg = get_target_group(ra.get("TargetGroupArn", ""))
                        action_strs.append(f"forward → `{tg['TargetGroupName'] if tg else '?'}`")
                    else:
                        action_strs.append(ra["Type"])
                lines.append(f"  - Priority {priority}: IF {' AND '.join(cond_strs)} THEN {', '.join(action_strs)}")

        lines.append("")

    lines.append("---")
    lines.append("")


def main():
    print("Fetching DNS records...")
    records = get_dns_records()
    print(f"  Found {len(records)} A/CNAME records")
    print()
    print("Walking each record through the load balancer stack...")
    print()

    lines = []
    lines.append(f"# DNS → Load Balancer → Target Walk Report")
    lines.append("")
    lines.append(f"**Zone:** `{HOSTED_ZONE_ID}`")
    lines.append(f"**Region:** `{REGION}`")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for record in sorted(records, key=lambda r: r["Name"]):
        walk_record(record, lines)

    report = "\n".join(lines)

    with open(OUTPUT_FILE, "w") as f:
        f.write(report)

    print(report)
    print()
    print(f"Report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
