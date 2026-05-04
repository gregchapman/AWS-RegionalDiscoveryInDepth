#!/usr/bin/env python3
import yaml, sys

path = sys.argv[1] if len(sys.argv) > 1 else '/home/greg/DiscoveryInDepth/output/inventory-us-east-1.yaml'
with open(path) as f:
    inv = yaml.safe_load(f)

lambdas = inv.get('resources', {}).get('Lambda Functions', [])
vpc_count = 0
no_vpc_count = 0

print("=== VPC-Attached Lambdas ===")
for l in lambdas:
    cfg = l.get('config', {})
    subnets = cfg.get('SubnetIds', [])
    sgs = cfg.get('SecurityGroupIds', [])
    if subnets or sgs:
        vpc_count += 1
        print(f"  {l.get('name','?'):50s} subnets={subnets} sgs={sgs}")

print(f"\n=== Summary ===")
print(f"Total Lambdas: {len(lambdas)}")
print(f"VPC-attached:  {vpc_count}")
print(f"No VPC:        {len(lambdas) - vpc_count}")

# Also show first non-VPC lambda's full config to check field names
print(f"\n=== Sample non-VPC Lambda config keys ===")
for l in lambdas:
    cfg = l.get('config', {})
    if not cfg.get('SubnetIds') and not cfg.get('SecurityGroupIds'):
        print(f"  Name: {l.get('name','?')}")
        for k, v in cfg.items():
            if k != 'Tags':
                print(f"    {k}: {v}")
        break

print(f"\n=== Sample VPC Lambda config keys ===")
for l in lambdas:
    cfg = l.get('config', {})
    if cfg.get('SubnetIds') or cfg.get('SecurityGroupIds'):
        print(f"  Name: {l.get('name','?')}")
        for k, v in cfg.items():
            if k != 'Tags':
                print(f"    {k}: {v}")
        break
