#!/usr/bin/env python3
"""Run iac_blueprint v3 against real inventory and report results."""
import os
import sys
import yaml
import shutil

REPO = '/home/greg/AWS-RegionalDiscoveryInDepth-repo'
RUN_DIR = os.path.join(REPO, 'output/TXDOTAWS1/us-east-1/20260505-161430')
INV_FILE = os.path.join(RUN_DIR, 'inventory-us-east-1.yaml')

# Clean previous iac output
iac_dir = os.path.join(RUN_DIR, 'iac-templates')
if os.path.isdir(iac_dir):
    shutil.rmtree(iac_dir)

# Load inventory
print(f"Loading: {INV_FILE}")
with open(INV_FILE, 'r') as f:
    inventory = yaml.safe_load(f)

meta = inventory.get('metadata', {})
print(f"Account: {meta.get('account_id')}, Region: {meta.get('region')}")
print(f"Categories: {len(inventory.get('resources', {}))}")

# Import and run
sys.path.insert(0, REPO)
from iac_blueprint import run_graph_driven

try:
    run_graph_driven(inventory, iac_dir, meta.get('region', 'us-east-1'))
    print("\n\nSUCCESS")
except Exception as e:
    print(f"\n\nFAILED: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Verify output
templates_dir = os.path.join(iac_dir, 'templates')
params_dir = os.path.join(iac_dir, 'params')
if os.path.isdir(templates_dir):
    templates = [f for f in os.listdir(templates_dir) if f.endswith('.yaml')]
    print(f"\nTemplates: {len(templates)}")
    for t in sorted(templates):
        size = os.path.getsize(os.path.join(templates_dir, t))
        print(f"  {t} ({size//1024}KB)")
else:
    print("ERROR: No templates dir created")
    sys.exit(1)

if os.path.isdir(params_dir):
    params = [f for f in os.listdir(params_dir) if f.endswith('.yaml')]
    print(f"Param files: {len(params)}")

deploy = os.path.join(iac_dir, 'DEPLOY.md')
if os.path.isfile(deploy):
    print(f"DEPLOY.md: {os.path.getsize(deploy)} bytes")

print("\nDONE - All checks passed")
