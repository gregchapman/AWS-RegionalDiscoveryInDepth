#!/usr/bin/env python3
"""
CFN Schema Cache — Fetches and caches CloudFormation Resource Type Schemas.

Provides:
  - get_create_only_properties(cfn_type) -> list of immutable property paths
  - get_schema(cfn_type) -> full schema dict
  - build_cache(region) -> pre-fetch all schemas for mapped types

Schemas are cached to disk (~/.cfn-schemas/{region}/{type}.json) so we don't
hit the API repeatedly across runs. Cache is valid for 30 days.

Used by iac_blueprint.py to ensure generated templates and parameter files
include all immutable properties — either as set values or as REQUIRED
parameters with IMMUTABLE warnings.
"""

import boto3
import json
import os
import sys
import time
from typing import Dict, List, Optional, Set
from pathlib import Path


# Default cache location
CACHE_DIR = os.path.expanduser('~/.cfn-schemas')
CACHE_MAX_AGE_DAYS = 30


def _cache_path(region: str, type_name: str) -> str:
    """Get the filesystem path for a cached schema."""
    safe_name = type_name.replace('::', '_')
    return os.path.join(CACHE_DIR, region, f'{safe_name}.json')


def _is_cache_valid(filepath: str) -> bool:
    """Check if a cached schema file is still valid."""
    if not os.path.exists(filepath):
        return False
    age_seconds = time.time() - os.path.getmtime(filepath)
    return age_seconds < (CACHE_MAX_AGE_DAYS * 86400)


def fetch_schema(type_name: str, region: str = None,
                 cfn_client=None) -> Optional[dict]:
    """Fetch a CFN type schema, using cache if available.

    Args:
        type_name: e.g., 'AWS::EC2::Instance'
        region: AWS region (uses default if not specified)
        cfn_client: optional pre-created boto3 cloudformation client

    Returns:
        Parsed schema dict, or None if unavailable.
    """
    # Check cache first
    effective_region = region or boto3.Session().region_name or 'us-east-1'
    cache_file = _cache_path(effective_region, type_name)

    if _is_cache_valid(cache_file):
        with open(cache_file, 'r') as f:
            return json.load(f)

    # Fetch from API
    if cfn_client is None:
        session = boto3.Session(region_name=effective_region)
        cfn_client = session.client('cloudformation')

    try:
        response = cfn_client.describe_type(
            Type='RESOURCE',
            TypeName=type_name
        )
        schema_str = response.get('Schema', '{}')
        schema = json.loads(schema_str)

        # Cache it
        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
        with open(cache_file, 'w') as f:
            json.dump(schema, f, indent=2)

        return schema

    except Exception as e:
        # Type not available in this region — not an error for our purposes
        return None


def get_create_only_properties(type_name: str, region: str = None,
                               cfn_client=None) -> List[str]:
    """Get the immutable (create-only) properties for a CFN resource type.

    Returns property names like: ['Engine', 'StorageEncrypted', 'KmsKeyId']
    Nested properties returned as: ['WindowsConfiguration.DeploymentType']
    """
    schema = fetch_schema(type_name, region, cfn_client)
    if not schema:
        return []

    create_only = schema.get('createOnlyProperties', [])
    result = []
    for prop_path in create_only:
        # /properties/Engine -> Engine
        # /properties/WindowsConfiguration/DeploymentType -> WindowsConfiguration.DeploymentType
        clean = prop_path.replace('/properties/', '').replace('/', '.')
        result.append(clean)
    return sorted(result)


def get_all_schemas_for_types(type_names: List[str], region: str = None) -> Dict[str, dict]:
    """Batch-fetch schemas for multiple types. Uses cache aggressively."""
    effective_region = region or boto3.Session().region_name or 'us-east-1'
    session = boto3.Session(region_name=effective_region)
    cfn_client = session.client('cloudformation')

    results = {}
    for type_name in type_names:
        schema = fetch_schema(type_name, effective_region, cfn_client)
        if schema:
            results[type_name] = schema
    return results


def build_cache(region: str, type_names: List[str] = None):
    """Pre-fetch and cache schemas for all mapped types."""
    from cfn_immutables import CATEGORY_TO_CFN_TYPE

    if type_names is None:
        type_names = list(set(CATEGORY_TO_CFN_TYPE.values()))

    print(f"Building schema cache for {len(type_names)} types in {region}...")
    session = boto3.Session(region_name=region)
    cfn_client = session.client('cloudformation')

    success = 0
    for type_name in sorted(type_names):
        schema = fetch_schema(type_name, region, cfn_client)
        if schema:
            immutables = get_create_only_properties(type_name, region, cfn_client)
            print(f"  ✓ {type_name}: {len(immutables)} immutables")
            success += 1
        else:
            print(f"  ✗ {type_name}: not available")

    print(f"\nCached {success}/{len(type_names)} schemas in {CACHE_DIR}/{region}/")


# ═══════════════════════════════════════════════════════════════════
# IMMUTABLE PROPERTY ENFORCEMENT
#
# This is what iac_blueprint.py calls at template generation time.
# ═══════════════════════════════════════════════════════════════════

def get_immutable_params_for_resource(cfn_type: str, resource_config: dict,
                                      region: str = None) -> Dict[str, dict]:
    """For a resource about to be templated, identify immutable properties
    that are NOT present in the inventory config.

    Returns a dict of:
      {property_name: {
          'value': <from inventory or None>,
          'present_in_inventory': bool,
          'immutable': True,
          'description': str
      }}

    Used by iac_blueprint.py to force these into the parameter file
    with IMMUTABLE warnings if not captured.
    """
    immutables = get_create_only_properties(cfn_type, region)
    if not immutables:
        return {}

    result = {}
    for prop in immutables:
        # Try to find the value in resource_config
        # Handle dotted paths: WindowsConfiguration.DeploymentType
        parts = prop.split('.')
        value = resource_config
        found = True
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                found = False
                value = None
                break

        result[prop] = {
            'value': value if found else None,
            'present_in_inventory': found and value is not None,
            'immutable': True,
            'description': f'IMMUTABLE — cannot change after creation. CFN will REPLACE resource if wrong.',
        }

    return result


def validate_immutables_coverage(cfn_type: str, captured_fields: List[str],
                                  region: str = None) -> List[str]:
    """Quick check: which immutable properties are NOT in our captured fields?

    Returns list of missing immutable property names.
    """
    immutables = get_create_only_properties(cfn_type, region)
    missing = []
    for prop in immutables:
        # Simple check: is any part of this prop path in our fields?
        prop_lower = prop.lower()
        found = any(
            prop_lower in f.lower() or f.lower() in prop_lower
            for f in captured_fields
        )
        if not found:
            missing.append(prop)
    return missing


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Build CFN schema cache')
    parser.add_argument('--region', required=True, help='AWS region')
    args = parser.parse_args()
    build_cache(args.region)
