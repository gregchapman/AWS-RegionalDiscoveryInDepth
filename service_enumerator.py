#!/usr/bin/env python3
"""
AWS Service Enumerator — Dynamic resource discovery across all services.

Instead of hardcoding per-service API calls, this script:
1. Enumerates all services available in a region via boto3 SDK metadata
2. For each service, introspects the service model to find list/describe operations
3. Calls the most promising operation to detect if resources exist
4. Reports which services have resources and approximate counts

Uses concurrent.futures for parallel execution to stay within
temporary credential windows.

Usage:
    python3 service_enumerator.py                          # Default region
    python3 service_enumerator.py --region us-gov-east-1   # Specific region
    python3 service_enumerator.py --workers 30             # Adjust parallelism
    python3 service_enumerator.py --output results.yaml    # Save results

Design:
    No hardcoded per-service logic. Everything is derived from the boto3
    service model at runtime. The script discovers what's available,
    figures out how to list resources, and tries it.
"""

import boto3
import botocore
import json
import yaml
import os
import sys
import time
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Thread-safe print
print_lock = Lock()
def tprint(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)


# ═══════════════════════════════════════════════════════════════════
# CREDENTIAL PRE-CACHING
#
# When running with high parallelism, many threads hitting the IMDS
# or container credential endpoint simultaneously can overwhelm it.
# Pre-fetching credentials once and sharing them across threads avoids
# this contention entirely.
# ═══════════════════════════════════════════════════════════════════

_cached_credentials = None  # Set by enumerate_services() before threads launch


def _get_session(region: str):
    """Create a boto3 session using pre-cached credentials if available.
    
    Falls back to default credential chain if cache is empty.
    """
    if _cached_credentials:
        return boto3.Session(
            region_name=region,
            aws_access_key_id=_cached_credentials['AccessKeyId'],
            aws_secret_access_key=_cached_credentials['SecretAccessKey'],
            aws_session_token=_cached_credentials.get('SessionToken'),
        )
    return boto3.Session(region_name=region)


# Maximum retries for transient credential/connection errors
MAX_RETRIES = 3
RETRY_ERRORS = (
    'CredentialRetrievalError',
    'MetadataRetrievalError',
    'ConnectTimeoutError',
    'ReadTimeoutError',
    'ConnectionClosedError',
)


# ═══════════════════════════════════════════════════════════════════
# SERVICE INTROSPECTION
# ═══════════════════════════════════════════════════════════════════

# Operations that are known to require parameters and should be skipped.
# These are list/describe calls that can't be called with zero arguments.
SKIP_OPERATIONS = {
    'describe_db_log_files',        # Requires DBInstanceIdentifier
    'describe_db_snapshots',        # Works but returns thousands
    'describe_events',              # Requires SourceType
    'describe_pending_maintenance_actions',
    'list_tags_for_resource',       # Requires ResourceArn
    'get_bucket_location',          # Requires Bucket
    'describe_log_groups',          # Works but can be huge
    'describe_log_streams',         # Requires logGroupName
    'list_objects_v2',              # Requires Bucket
    'describe_alarms',              # Works but we handle it explicitly
}

# ═══════════════════════════════════════════════════════════════════
# SKIP SERVICES — Platform noise that exists in every AWS account.
#
# These services report "resources found" but are static AWS catalogs,
# reference data, or management-plane metadata — not customer workloads.
# Excluding them reduces inventory noise and keeps output focused on
# resources that matter for DR, compliance, and architecture review.
#
# To re-include a service for a specific run, use:
#   python3 service_enumerator.py --services artifact,health,...
# ═══════════════════════════════════════════════════════════════════
SKIP_SERVICES = {
    # Static catalogs — same content in every account
    'artifact',                     # AWS compliance reports (VPATs, SOC2, ISO)
    'translate',                    # Supported language list
    'elasticbeanstalk',             # Available platform versions
    'fis',                          # Fault Injection Simulator action catalog
    'pinpoint-sms-voice-v2',        # Country list for SMS notifications
    'health',                       # Health event type definitions
    'wellarchitected',              # Well-Architected lens catalog
    'grafana',                      # Managed Grafana version list
    'redshift-serverless',          # Redshift Serverless track catalog
    'polly',                        # Voice/lexicon catalog

    # Management-plane metadata — not customer workload resources
    'service-quotas',               # List of services with quotas
    'controlcatalog',               # Control Tower control catalog
    'controltower',                 # Control Tower baselines
    'appconfig',                    # Built-in extensions (AWS-managed)
    'resource-explorer-2',          # Default view (always exists)
    'launch-wizard',                # Launch Wizard metadata

    # Services with default resources in every account
    'keyspaces',                    # System keyspaces (system, system_schema, etc.)
    'memorydb',                     # Default "open-access" ACL
}

# Preferred operations per service — when multiple list ops exist,
# use the one most likely to give a meaningful resource count.
# Format: service_name -> operation_name
PREFERRED_OPS = {
    'ec2': 'describe_instances',
    's3': 'list_buckets',
    'rds': 'describe_db_instances',
    'lambda': 'list_functions',
    'dynamodb': 'list_tables',
    'elbv2': 'describe_load_balancers',
    'iam': 'list_roles',
    'cloudformation': 'list_stacks',
    'sns': 'list_topics',
    'sqs': 'list_queues',
    'secretsmanager': 'list_secrets',
    'ssm': 'describe_parameters',
    'kms': 'list_keys',
    'acm': 'list_certificates',
    'route53': 'list_hosted_zones',
    'elasticache': 'describe_cache_clusters',
    'stepfunctions': 'list_state_machines',
    'events': 'list_rules',
    'apigateway': 'get_rest_apis',
    'apigatewayv2': 'get_apis',
    'wafv2': 'list_web_acls',
    'cloudwatch': 'describe_alarms',
    'ecs': 'list_clusters',
    'eks': 'list_clusters',
    'ecr': 'describe_repositories',
    'codebuild': 'list_projects',
    'codecommit': 'list_repositories',
    'codepipeline': 'list_pipelines',
    'kinesis': 'list_streams',
    'firehose': 'list_delivery_streams',
    'glue': 'get_databases',
    'athena': 'list_work_groups',
    'redshift': 'describe_clusters',
    'elasticsearch': 'list_domain_names',
    'opensearch': 'list_domain_names',
    'efs': 'describe_file_systems',
    'fsx': 'describe_file_systems',
    'backup': 'list_backup_vaults',
    'cloudfront': 'list_distributions',
    'cloudtrail': 'describe_trails',
    'config': 'describe_configuration_recorders',
    'guardduty': 'list_detectors',
    'inspector2': 'list_findings',
    'macie2': 'list_classification_jobs',
    'securityhub': 'describe_hub',
    'transfer': 'list_servers',
    'datasync': 'list_tasks',
    'dms': 'describe_replication_instances',
    'mq': 'list_brokers',
    'mediaconvert': 'list_jobs',
    'sagemaker': 'list_notebook_instances',
    'cognito-idp': 'list_user_pools',
    'cognito-identity': 'list_identity_pools',
    'workspaces': 'describe_workspaces',
    'ds': 'describe_directories',
    'organizations': 'list_accounts',
    'ram': 'list_resources',
    'license-manager': 'list_received_licenses',
}


def find_list_operation(service_name: str, client) -> Optional[str]:
    """Find the best list/describe operation for a service.
    
    Strategy:
    1. Check PREFERRED_OPS for a known-good operation
    2. Introspect the service model for list_* or describe_* operations
    3. Pick the one most likely to enumerate top-level resources
    4. Skip operations that require parameters
    """
    # Check preferred ops first
    if service_name in PREFERRED_OPS:
        op = PREFERRED_OPS[service_name]
        # Verify it exists in this client
        if hasattr(client, op):
            return op
    
    # Introspect the service model
    try:
        operations = client.meta.service_model.operation_names
    except Exception:
        return None
    
    # Score operations — prefer list_ over describe_, prefer shorter names
    # (shorter names tend to be top-level resource enumerations)
    candidates = []
    for op in operations:
        # Convert from CamelCase API name to snake_case method name
        method_name = botocore.xform_name(op)
        
        if method_name in SKIP_OPERATIONS:
            continue
        
        if not hasattr(client, method_name):
            continue
        
        # Check if the operation requires parameters
        try:
            op_model = client.meta.service_model.operation_model(op)
            required = op_model.input_shape.required_members if op_model.input_shape else []
            if required:
                continue  # Skip ops that require parameters
        except Exception:
            continue
        
        # Score: list_ = 10, describe_ = 8, get_ = 5
        score = 0
        if method_name.startswith('list_'):
            score = 10
        elif method_name.startswith('describe_'):
            score = 8
        elif method_name.startswith('get_'):
            score = 5
        else:
            continue
        
        # Prefer shorter names (top-level resources)
        score -= len(method_name) * 0.01
        
        candidates.append((score, method_name))
    
    if not candidates:
        return None
    
    # Return highest-scoring operation
    candidates.sort(reverse=True)
    return candidates[0][1]


def count_resources_in_response(response: dict) -> int:
    """Estimate the number of resources in an API response.
    
    AWS responses vary wildly in structure. We look for the largest
    list in the response — that's usually the resource list.
    """
    if not isinstance(response, dict):
        return 0
    
    max_count = 0
    for key, value in response.items():
        # Skip metadata keys
        if key in ('ResponseMetadata', 'NextToken', 'nextToken',
                   'Marker', 'IsTruncated', 'NextMarker'):
            continue
        
        if isinstance(value, list):
            max_count = max(max_count, len(value))
        elif isinstance(value, dict):
            # Some responses nest the list one level deep
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    max_count = max(max_count, len(subvalue))
    
    return max_count


# ═══════════════════════════════════════════════════════════════════
# SERVICE PROBING
# ═══════════════════════════════════════════════════════════════════

def probe_service(service_name: str, region: str) -> Dict:
    """Probe a single AWS service for resources.
    
    Returns a dict with:
        service: service name
        status: 'found' | 'empty' | 'error' | 'no_list_op' | 'access_denied'
        operation: the API call used
        count: approximate resource count
        error: error message if any
        elapsed: time taken in seconds
    
    Retries up to MAX_RETRIES times on transient credential/connection errors.
    """
    start = time.time()
    result = {
        'service': service_name,
        'status': 'unknown',
        'operation': '',
        'count': 0,
        'error': '',
        'elapsed': 0,
    }

    for attempt in range(MAX_RETRIES):
        try:
            # Use pre-cached credentials to avoid IMDS contention
            session = _get_session(region)
            client = session.client(service_name)

            # Find the best list operation
            operation = find_list_operation(service_name, client)
            if not operation:
                result['status'] = 'no_list_op'
                result['elapsed'] = time.time() - start
                return result

            result['operation'] = operation

            # Call the operation
            method = getattr(client, operation)

            # Some operations need special kwargs
            kwargs = {}
            if service_name == 'wafv2' and operation == 'list_web_acls':
                kwargs['Scope'] = 'REGIONAL'
            if service_name == 'cognito-identity' and operation == 'list_identity_pools':
                kwargs['MaxResults'] = 10
            if service_name == 'cognito-idp' and operation == 'list_user_pools':
                kwargs['MaxResults'] = 10
            if service_name == 'ram' and operation == 'list_resources':
                kwargs['resourceOwner'] = 'SELF'
                kwargs['resourceType'] = 'ec2:Subnet'  # Just check one type

            response = method(**kwargs)

            # Count resources in the response
            count = count_resources_in_response(response)
            result['count'] = count
            result['status'] = 'found' if count > 0 else 'empty'
            break  # Success — exit retry loop

        except botocore.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ('AccessDeniedException', 'AccessDenied',
                              'UnauthorizedAccess', 'AuthorizationError'):
                result['status'] = 'access_denied'
                result['error'] = error_code
                break  # Not retryable
            elif error_code in ('UnrecognizedClientException',
                                'InvalidClientTokenId'):
                result['status'] = 'access_denied'
                result['error'] = 'Invalid credentials for this service'
                break  # Not retryable
            else:
                result['status'] = 'error'
                result['error'] = f'{error_code}: {str(e)[:200]}'
                break  # API errors are not retryable

        except botocore.exceptions.EndpointConnectionError:
            result['status'] = 'not_in_region'
            result['error'] = 'Endpoint not available in region'
            break  # Not retryable

        except botocore.exceptions.NoRegionError:
            result['status'] = 'error'
            result['error'] = 'No region specified'
            break  # Not retryable

        except Exception as e:
            error_name = type(e).__name__
            error_msg = str(e)[:200]

            # Check if this is a retryable credential/connection error
            is_retryable = any(err in error_name or err in error_msg
                               for err in RETRY_ERRORS)

            if is_retryable and attempt < MAX_RETRIES - 1:
                # Wait with exponential backoff before retry
                wait = (attempt + 1) * 2  # 2s, 4s
                tprint(f"    ⟳ {service_name}: credential/connection error, retrying in {wait}s "
                       f"(attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(wait)
                continue  # Retry

            # Final attempt failed or non-retryable error
            result['status'] = 'error'
            result['error'] = f'{error_name}: {error_msg}'
            break

    result['elapsed'] = round(time.time() - start, 2)
    return result


# ═══════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

def get_available_services(region: str) -> List[str]:
    """Get all services available via boto3 in a region.
    
    Uses boto3's session to enumerate services. This is SDK-level
    availability, not region-level — some services may not have
    endpoints in every region.
    """
    session = boto3.Session(region_name=region)
    return sorted(session.get_available_services())


def run_enumeration(region: str, max_workers: int = 20,
                    services_filter: List[str] = None) -> Dict:
    """Run parallel service enumeration.
    
    Args:
        region: AWS region to scan
        max_workers: thread pool size (default 20)
        services_filter: optional list of specific services to scan
    
    Returns:
        Full results dict with metadata and per-service results
    """
    start_time = time.time()
    
    # Get service list
    all_services = get_available_services(region)
    if services_filter:
        all_services = [s for s in all_services if s in services_filter]
    else:
        # Exclude platform noise services (static catalogs, default resources)
        skipped = [s for s in all_services if s in SKIP_SERVICES]
        all_services = [s for s in all_services if s not in SKIP_SERVICES]
        if skipped:
            tprint(f"  Skipping {len(skipped)} platform/catalog services (SKIP_SERVICES)")
    
    tprint(f"\n{'=' * 60}")
    tprint(f"AWS Service Enumerator — {region}")
    tprint(f"{'=' * 60}")
    tprint(f"Services to probe: {len(all_services)}")
    tprint(f"Workers: {max_workers}")
    tprint(f"{'=' * 60}\n")
    
    # Get account info
    try:
        sts = boto3.client('sts', region_name=region)
        identity = sts.get_caller_identity()
        account_id = identity['Account']
    except Exception:
        account_id = 'unknown'

    # Pre-cache credentials to avoid IMDS contention under high parallelism
    global _cached_credentials
    try:
        session = boto3.Session(region_name=region)
        credentials = session.get_credentials()
        if credentials:
            frozen = credentials.get_frozen_credentials()
            _cached_credentials = {
                'AccessKeyId': frozen.access_key,
                'SecretAccessKey': frozen.secret_key,
                'SessionToken': frozen.token,
            }
            tprint(f"  Credentials pre-cached for thread safety")
    except Exception as e:
        tprint(f"  WARNING: Could not pre-cache credentials ({e}). "
               f"Threads will fetch independently.")
        _cached_credentials = None
    
    results = {
        'metadata': {
            'account_id': account_id,
            'region': region,
            'scan_date': datetime.now(tz=timezone.utc).isoformat(),
            'services_probed': len(all_services),
            'workers': max_workers,
            'tool': 'service_enumerator.py',
        },
        'services_with_resources': [],
        'services_empty': [],
        'services_access_denied': [],
        'services_not_in_region': [],
        'services_error': [],
        'services_no_list_op': [],
        'all_results': [],
    }
    
    # Parallel probe
    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_service = {
            executor.submit(probe_service, svc, region): svc
            for svc in all_services
        }
        
        for future in as_completed(future_to_service):
            svc = future_to_service[future]
            completed += 1
            
            try:
                result = future.result()
            except Exception as e:
                result = {
                    'service': svc,
                    'status': 'error',
                    'operation': '',
                    'count': 0,
                    'error': str(e),
                    'elapsed': 0,
                }
            
            results['all_results'].append(result)
            
            # Categorize
            status = result['status']
            if status == 'found':
                results['services_with_resources'].append(result)
                tprint(f"  ✓ {svc:35s} {result['count']:5d} resources  ({result['operation']}, {result['elapsed']}s)")
            elif status == 'empty':
                results['services_empty'].append(result)
            elif status == 'access_denied':
                results['services_access_denied'].append(result)
            elif status == 'not_in_region':
                results['services_not_in_region'].append(result)
            elif status == 'no_list_op':
                results['services_no_list_op'].append(result)
            else:
                results['services_error'].append(result)
            
            # Progress indicator every 25 services
            if completed % 25 == 0:
                tprint(f"  ... {completed}/{len(all_services)} services probed")
    
    elapsed = round(time.time() - start_time, 1)
    results['metadata']['elapsed_seconds'] = elapsed
    
    # Sort results
    results['services_with_resources'].sort(key=lambda x: x['count'], reverse=True)
    results['all_results'].sort(key=lambda x: x['service'])
    
    # Summary
    tprint(f"\n{'=' * 60}")
    tprint(f"Results — {region} (account {account_id})")
    tprint(f"{'=' * 60}")
    tprint(f"  Services with resources:  {len(results['services_with_resources'])}")
    tprint(f"  Services empty:           {len(results['services_empty'])}")
    tprint(f"  Access denied:            {len(results['services_access_denied'])}")
    tprint(f"  Not in region:            {len(results['services_not_in_region'])}")
    tprint(f"  No list operation:        {len(results['services_no_list_op'])}")
    tprint(f"  Errors:                   {len(results['services_error'])}")
    tprint(f"  Total time:               {elapsed}s")
    tprint(f"{'=' * 60}")
    
    if results['services_with_resources']:
        tprint(f"\nServices with resources:")
        for r in results['services_with_resources']:
            tprint(f"  {r['service']:35s} {r['count']:5d}  ({r['operation']})")
    
    if results['services_access_denied']:
        tprint(f"\nAccess denied (may have resources but credentials lack permission):")
        for r in results['services_access_denied']:
            tprint(f"  {r['service']:35s} {r['error']}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='AWS Service Enumerator — Dynamic resource discovery across all services.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 service_enumerator.py                          # Default region, 20 workers
  python3 service_enumerator.py --region us-gov-east-1   # Specific region
  python3 service_enumerator.py --workers 30             # More parallelism
  python3 service_enumerator.py --output results.yaml    # Save results
  python3 service_enumerator.py --services ec2,s3,rds    # Specific services only
        """,
    )
    parser.add_argument('--region', default='us-gov-west-1',
                        help='AWS region to scan (default: us-gov-west-1)')
    parser.add_argument('--workers', type=int, default=20,
                        help='Thread pool size (default: 20)')
    parser.add_argument('--output', default='',
                        help='Output file path (YAML)')
    parser.add_argument('--services', default='',
                        help='Comma-separated list of specific services to scan')
    args = parser.parse_args()
    
    services_filter = [s.strip() for s in args.services.split(',') if s.strip()] or None
    
    results = run_enumeration(args.region, args.workers, services_filter)
    
    if args.output:
        with open(args.output, 'w', newline='\n') as f:
            yaml.dump(results, f, default_flow_style=False, sort_keys=False)
        tprint(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
