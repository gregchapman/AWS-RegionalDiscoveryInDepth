#!/usr/bin/env python3
"""
Replicate AWS Systems Manager Parameter Store parameters from source to destination region.

Copies all parameters (including SecureString values via WithDecryption)
to enable DR readiness.

Usage:
  python3 replicate-parameters.py --source-region us-gov-west-1 --dest-region us-gov-east-1
"""

import sys
import argparse
import boto3
from botocore.exceptions import ClientError


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replicate SSM Parameter Store parameters to a DR region."
    )
    parser.add_argument("--source-region", required=True,
                        help="Source region (e.g., us-gov-west-1)")
    parser.add_argument("--dest-region", required=True,
                        help="Destination/DR region (e.g., us-gov-east-1)")
    return parser.parse_args()


def list_parameters(client):
    """List all parameters in the region."""
    paginator = client.get_paginator("describe_parameters")
    parameters = []
    try:
        for page in paginator.paginate():
            parameters.extend(page.get("Parameters", []))
    except ClientError as e:
        print(f"ERROR: Could not list parameters: {e}", file=sys.stderr)
        sys.exit(1)
    return parameters


def get_parameter_value(client, param_name):
    """Get the parameter value from the source region."""
    try:
        resp = client.get_parameter(Name=param_name, WithDecryption=True)
        param = resp.get("Parameter", {})
        return {
            "Value": param.get("Value"),
            "Type": param.get("Type"),
            "Description": param.get("Description", ""),
        }
    except ClientError as e:
        print(f"  -> ERROR getting '{param_name}': {e}", file=sys.stderr)
    return None


def replicate_parameter(src_client, dst_client, param_name):
    """Replicate a single parameter to the destination region."""
    param_data = get_parameter_value(src_client, param_name)
    if param_data is None:
        return False

    try:
        put_args = {
            "Name": param_name,
            "Value": param_data["Value"],
            "Type": param_data["Type"],
            "Overwrite": True,
        }
        if param_data["Description"]:
            put_args["Description"] = param_data["Description"]

        dst_client.put_parameter(**put_args)
        print(f"  + {param_name} ({param_data['Type']})")
        return True
    except ClientError as e:
        print(f"  x Failed '{param_name}': {e}", file=sys.stderr)
        return False


def main():
    args = parse_args()

    print(f"\n{'='*70}")
    print(f"  Parameter Store Replication")
    print(f"  Source: {args.source_region} -> Destination: {args.dest_region}")
    print(f"{'='*70}\n")

    src_client = boto3.client("ssm", region_name=args.source_region)
    dst_client = boto3.client("ssm", region_name=args.dest_region)

    print(f"[1/2] Listing parameters in {args.source_region}...")
    parameters = list_parameters(src_client)
    print(f"      Found {len(parameters)} parameters\n")

    if not parameters:
        print("No parameters found. Nothing to replicate.")
        return

    print(f"[2/2] Replicating to {args.dest_region}...\n")
    success_count = 0
    fail_count = 0

    for param in parameters:
        if replicate_parameter(src_client, dst_client, param.get("Name")):
            success_count += 1
        else:
            fail_count += 1

    print(f"\n{'-'*70}")
    print(f"Summary: {success_count} replicated, {fail_count} failed, {len(parameters)} total")
    print(f"{'='*70}\n")

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
