#!/usr/bin/env python3
"""
Fix iac_blueprint.py:
1. Move SG bespoke output into templates/ (drop 01- prefix)
2. Update DEPLOY.md to specify correct dependency-ordered launch sequence
"""

filepath = '/home/greg/AWS-RegionalDiscoveryInDepth-repo/iac_blueprint.py'

with open(filepath, 'r') as f:
    content = f.read()

# 1. Fix SG output path: 01-security-groups.yaml -> templates/security-groups.yaml
content = content.replace(
    "os.path.join(output_dir, '01-security-groups.yaml')",
    "os.path.join(templates_dir, 'security-groups.yaml')"
)
content = content.replace(
    "os.path.join(output_dir, '01-security-groups.md')",
    "os.path.join(templates_dir, 'security-groups.md')"
)

# 2. Replace the DEPLOY.md generation with proper dependency ordering
old_deploy = """    # ── Write orchestration DEPLOY.md ──
    from collections import defaultdict as _dd2
    orchestration_path = os.path.join(output_dir, 'DEPLOY.md')
    with open(orchestration_path, 'w', encoding='utf-8') as f:
        f.write("# Deployment Orchestration\\n\\n")
        f.write(f"Source: {inventory_path}\\n")
        f.write(f"Account: {account} | Region: {region}\\n\\n")
        f.write("## Deployment Order\\n\\n")
        f.write("1. `01-security-groups.yaml` — Deploy first\\n")
        f.write("2. Per-resource stacks from `templates/` + `params/`\\n\\n")
        f.write("## Security Groups\\n\\n```bash\\n")
        f.write("aws cloudformation deploy \\\\\\n")
        f.write("  --template-file 01-security-groups.yaml \\\\\\n")
        f.write("  --stack-name iac-security-groups \\\\\\n")
        f.write("  --parameter-overrides VpcId=<VPC_ID> VpcCidr=<CIDR>\\n```\\n\\n")
        by_cat = _dd2(list)
        for cmd in deploy_commands:
            by_cat[cmd['category']].append(cmd)
        for cat, cmds in sorted(by_cat.items()):
            f.write(f"## {cat} ({len(cmds)})\\n\\n")
            for cmd in cmds:
                f.write(f"### {cmd['resource_name']}\\n```bash\\n")
                f.write(f"aws cloudformation deploy \\\\\\n")
                f.write(f"  --template-file {cmd['template']} \\\\\\n")
                f.write(f"  --stack-name {cmd['stack_name']} \\\\\\n")
                f.write(f"  --parameter-overrides file://{cmd['params']}\\n```\\n\\n")
    print(f"  {'DEPLOY.md':40s} orchestration guide")"""

new_deploy = """    # ── Write orchestration DEPLOY.md ──
    from collections import defaultdict as _dd2

    # Define deployment order by category (dependency chain)
    DEPLOY_ORDER = [
        'VPCs',
        'Subnets',
        'Route Tables',
        'Security Groups',
        'NAT Gateways',
        'VPC Endpoints',
        'Directories',
        'KMS Keys',
        'RDS Instances',
        'ElastiCache Clusters',
        'DynamoDB Tables',
        'EC2 Instances',
        'Auto Scaling Groups',
        'ECS Clusters',
        'ECS Services',
        'EKS Clusters',
        'Classic Load Balancers',
        'Load Balancers',
        'Target Groups',
        'Lambda Functions',
        'Step Functions',
        'EventBridge Rules',
        'API Gateways',
        'ACM Certificates',
        'WAF Web ACLs',
        'Hosted Zones',
        'SNS Topics',
        'SQS Queues',
        'CloudWatch Alarms',
        'S3 Buckets',
    ]

    orchestration_path = os.path.join(output_dir, 'DEPLOY.md')
    with open(orchestration_path, 'w', encoding='utf-8') as f:
        f.write("# Deployment Orchestration\\n\\n")
        f.write(f"Source: {inventory_path}\\n")
        f.write(f"Account: {account} | Region: {region}\\n\\n")
        f.write("## Deployment Order\\n\\n")
        f.write("Deploy in this sequence to satisfy dependencies:\\n\\n")
        f.write("| Phase | Category | Reason |\\n")
        f.write("|-------|----------|--------|\\n")
        f.write("| 1 | VPCs | Foundation — everything lives here |\\n")
        f.write("| 2 | Subnets, Route Tables | Network topology |\\n")
        f.write("| 3 | Security Groups | Referenced by all resources |\\n")
        f.write("| 4 | NAT Gateways, VPC Endpoints | Network services |\\n")
        f.write("| 5 | KMS Keys, Directories | Encryption + identity |\\n")
        f.write("| 6 | Data (RDS, ElastiCache, DynamoDB) | Stateful — restore first |\\n")
        f.write("| 7 | Compute (EC2, ASG, ECS, EKS) | Application tier |\\n")
        f.write("| 8 | Load Balancers, Target Groups | Traffic routing |\\n")
        f.write("| 9 | Serverless (Lambda, Step Functions, EventBridge) | Event-driven |\\n")
        f.write("| 10 | DNS, Certs, WAF, Monitoring | Supporting services |\\n")
        f.write("\\n---\\n\\n")

        # Group deploy commands by category
        by_cat = _dd2(list)
        for cmd in deploy_commands:
            by_cat[cmd['category']].append(cmd)

        # Security Groups (bespoke — consolidated stack)
        if sg_included:
            f.write("## Security Groups (consolidated stack)\\n\\n")
            f.write("```bash\\naws cloudformation deploy \\\\\\n")
            f.write("  --template-file templates/security-groups.yaml \\\\\\n")
            f.write("  --stack-name iac-security-groups \\\\\\n")
            f.write("  --parameter-overrides VpcId=<VPC_ID> VpcCidr=<CIDR>\\n```\\n\\n")

        # All other categories in dependency order
        for cat in DEPLOY_ORDER:
            if cat == 'Security Groups':
                continue  # Already handled above
            if cat not in by_cat:
                continue
            cmds = by_cat[cat]
            f.write(f"## {cat} ({len(cmds)} resources)\\n\\n")
            for cmd in cmds:
                f.write(f"### {cmd['resource_name']}\\n\\n```bash\\n")
                f.write(f"aws cloudformation deploy \\\\\\n")
                f.write(f"  --template-file {cmd['template']} \\\\\\n")
                f.write(f"  --stack-name {cmd['stack_name']} \\\\\\n")
                f.write(f"  --parameter-overrides file://{cmd['params']}\\n```\\n\\n")

        # Any categories not in DEPLOY_ORDER (catch-all)
        for cat, cmds in sorted(by_cat.items()):
            if cat in DEPLOY_ORDER or cat == 'Security Groups':
                continue
            f.write(f"## {cat} ({len(cmds)} resources)\\n\\n")
            for cmd in cmds:
                f.write(f"### {cmd['resource_name']}\\n\\n```bash\\n")
                f.write(f"aws cloudformation deploy \\\\\\n")
                f.write(f"  --template-file {cmd['template']} \\\\\\n")
                f.write(f"  --stack-name {cmd['stack_name']} \\\\\\n")
                f.write(f"  --parameter-overrides file://{cmd['params']}\\n```\\n\\n")

    print(f"  {'DEPLOY.md':40s} orchestration guide")"""

if old_deploy in content:
    content = content.replace(old_deploy, new_deploy)
    print("Replaced DEPLOY.md generation with dependency-ordered version")
else:
    print("WARNING: Could not find old DEPLOY.md block to replace")
    print("Searching for partial match...")
    if "1. `01-security-groups.yaml`" in content:
        print("Found partial - old deploy code exists but doesn't match exactly")
    else:
        print("Old deploy code not found at all")

with open(filepath, 'w') as f:
    f.write(content)

print("Done.")
