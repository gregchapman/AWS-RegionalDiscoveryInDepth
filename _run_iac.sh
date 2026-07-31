#!/bin/bash
cd /home/greg/AWS-RegionalDiscoveryInDepth-repo
python3 iac_blueprint.py --input output/OAG-CS-FS/us-east-1/20260505-162759/ > /tmp/iac_run.log 2>&1
echo "EXIT_CODE=$?"
tail -30 /tmp/iac_run.log
