#!/usr/bin/env python3
"""
Replicate AWS Secrets Manager secrets from source region to destination region.

Copies all secrets (values included) to enable DR readiness.
Handles name sanitization for secrets with invalid characters.

Usage:
  python3 replicate-secrets.py --source-region us-gov-west-1 --dest-region us-gov-east-1
"""

import json
import sys
import re
import argparse
import boto3
from botocore.exceptions import ClientError


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replicate Secrets Manager secrets to a DR region."
    )
    parser.add_argument("--source-region", required=True,
                        help="Source region (e.g., us-gov-west-1)")
    parser.add_argument("--dest-region", required=True,
                        help="Destination/DR region (e.g., us-gov-east-1)")
    return parser.parse_args()


def list_secrets(client):
    """List all secrets in the region."""
    paginator = client.get_paginator("list_secrets")
    secrets = []
    try:
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))
    except ClientError as e:
        print(f"ERROR: Could not list secrets: {e}", file=sys.stderr)
        sys.exit(1)
    return secrets


def sanitize_secret_name(secret_name):
    """Sanitize secret name — allowed: alphanumeric, /_+=.@-"""
    return re.sub(r"[^a-zA-Z0-9/_+=.@-]", "_", secret_name)


def get_secret_value(client, secret_name):
    """Get the secret value from the source region."""
    try:
        resp = client.get_secret_value(SecretId=secret_name)
        if "SecretString" in resp:
            return resp["SecretString"], "SecretString"
        elif "SecretBinary" in resp:
            return resp["SecretBinary"], "SecretBinary"
    except ClientError as e:
        print(f"  -> ERROR getting secret '{secret_name}': {e}", file=sys.stderr)
    return None, None


def replicate_secret(src_client, dst_client, secret_name, source_region):
    """Replicate a single secret to the destination region."""
    secret_value, value_type = get_secret_value(src_client, secret_name)
    if secret_value is None:
        return False, None

    dest_secret_name = sanitize_secret_name(secret_name)
    was_renamed = dest_secret_name != secret_name

    try:
        create_args = {
            "Name": dest_secret_name,
            "Description": f"Replicated from {source_region}",
        }
        if value_type == "SecretString":
            create_args["SecretString"] = secret_value
        elif value_type == "SecretBinary":
            create_args["SecretBinary"] = secret_value

        try:
            dst_client.create_secret(**create_args)
            label = f"{secret_name} -> {dest_secret_name}" if was_renamed else secret_name
            print(f"  + Created: {label}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceExistsException":
                update_args = {"SecretId": dest_secret_name}
                if value_type == "SecretString":
                    update_args["SecretString"] = secret_value
                elif value_type == "SecretBinary":
                    update_args["SecretBinary"] = secret_value
                dst_client.update_secret(**update_args)
                label = f"{secret_name} -> {dest_secret_name}" if was_renamed else secret_name
                print(f"  ~ Updated: {label}")
            else:
                raise
        return True, was_renamed
    except ClientError as e:
        print(f"  x Failed: '{secret_name}': {e}", file=sys.stderr)
        return False, was_renamed


def main():
    args = parse_args()

    print(f"\n{'='*70}")
    print(f"  Secrets Replication")
    print(f"  Source: {args.source_region} -> Destination: {args.dest_region}")
    print(f"{'='*70}\n")

    src_client = boto3.client("secretsmanager", region_name=args.source_region)
    dst_client = boto3.client("secretsmanager", region_name=args.dest_region)

    print(f"[1/2] Listing secrets in {args.source_region}...")
    secrets = list_secrets(src_client)
    print(f"      Found {len(secrets)} secrets\n")

    if not secrets:
        print("No secrets found. Nothing to replicate.")
        return

    print(f"[2/2] Replicating to {args.dest_region}...\n")
    success_count = 0
    fail_count = 0
    renamed = []

    for secret in secrets:
        secret_name = secret.get("Name")
        success, was_renamed = replicate_secret(
            src_client, dst_client, secret_name, args.source_region
        )
        if success:
            success_count += 1
            if was_renamed:
                renamed.append(secret_name)
        else:
            fail_count += 1

    print(f"\n{'-'*70}")
    print(f"Summary: {success_count} replicated, {fail_count} failed, {len(secrets)} total")
    if renamed:
        print(f"\nSanitized names (invalid chars replaced with _):")
        for name in renamed:
            print(f"  {name} -> {sanitize_secret_name(name)}")
    print(f"{'='*70}\n")

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
