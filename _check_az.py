#!/usr/bin/env python3
import yaml
from collections import Counter

with open('/home/greg/AWS-RegionalDiscoveryInDepth-repo/output/TG-TWDB-txwise/us-east-1/20260505-133309/inventory-us-east-1.yaml') as f:
    inv = yaml.safe_load(f)

instances = inv['resources'].get('EC2 Instances', [])
az_count = Counter()
for i in instances:
    az = i.get('config', {}).get('AvailabilityZone', '?')
    az_count[az] += 1
for az, count in sorted(az_count.items()):
    print(f'{az}: {count} instances')

# Check meso-master
for i in instances:
    if 'meso-master' in i.get('name', '').lower():
        cfg = i.get('config', {})
        print(f"\n{i['name']}: AZ={cfg.get('AvailabilityZone')}, Subnet={cfg.get('SubnetId')}")

# Check which AZ has only 1 instance (us-east-1d)
print("\nus-east-1d instances:")
for i in instances:
    cfg = i.get('config', {})
    if cfg.get('AvailabilityZone') == 'us-east-1d':
        print(f"  {i['name']}: Subnet={cfg.get('SubnetId')}, IP={cfg.get('PrivateIpAddress')}")
