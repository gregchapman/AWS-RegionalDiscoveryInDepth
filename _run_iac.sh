#!/bin/bash
cd /home/greg/AWS-RegionalDiscoveryInDepth-repo
INV="output/Instem/us-gov-west-1/20260731-170202"
rm -rf "$INV/iac-templates"
python3 iac_blueprint.py --input "$INV" 2>&1 | tail -25
echo "---"
echo "Templates:"
ls "$INV/iac-templates/templates/" 2>/dev/null
