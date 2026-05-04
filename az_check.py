#!/usr/bin/env python3
"""Quick check of AZ distribution in inventory."""
import yaml, sys

path = sys.argv[1] if len(sys.argv) > 1 else '/home/greg/DiscoveryInDepth/output/inventory-us-east-1.yaml'
with open(path) as f:
    inv = yaml.safe_load(f)

print("=== EC2 Instances ===")
for inst in inv.get('resources', {}).get('EC2 Instances', []):
    cfg = inst.get('config', {})
    name = inst.get('name', '?')
    az = cfg.get('AvailabilityZone', '?')
    subnet = cfg.get('SubnetId', '?')
    vpc = cfg.get('VpcId', '?')
    print(f"  {name:35s} AZ={az:15s} Subnet={subnet} VPC={vpc}")

print("\n=== VPCs ===")
for vpc in inv.get('resources', {}).get('VPCs', []):
    cfg = vpc.get('config', {})
    print(f"  {vpc.get('name', '?'):35s} {vpc.get('resource_id', '?')} CIDR={cfg.get('CidrBlock', '?')}")

print("\n=== Subnets by AZ ===")
from collections import defaultdict
az_map = defaultdict(list)
for sn in inv.get('resources', {}).get('Subnets', []):
    cfg = sn.get('config', {})
    az = cfg.get('AvailabilityZone', '?')
    az_map[az].append(f"{sn.get('name', sn.get('resource_id', '?'))} ({cfg.get('CidrBlock', '?')})")

for az in sorted(az_map.keys()):
    print(f"  {az}: {len(az_map[az])} subnets")
    for s in az_map[az]:
        print(f"    - {s}")
