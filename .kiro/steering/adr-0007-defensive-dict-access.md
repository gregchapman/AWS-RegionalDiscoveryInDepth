---
inclusion: auto
---

# ADR-0007: Defensive Dict Access (.get() Everywhere, No Direct Key Access)

Date: 2026-07-31
Status: Accepted

## Context

AWS API responses and inventory config dicts are inherently unpredictable:
- Different API versions return different field sets
- Resources in different states omit fields (terminated instances lack IPs)
- GovCloud responses sometimes differ from commercial
- Discovery templates capture what's available; missing fields produce empty values
- Collision-safe keys from the discovery engine produce unexpected field names

Direct key access (`response['Key']`) or index access (`list[0]`) on AWS-derived
data will eventually produce `KeyError` or `IndexError` in production when a
resource has an unexpected shape.

## Decision

All dict access on AWS-derived data uses `.get('key', default)`. All list access
is guarded with length checks or conditional expressions. Specifically:

1. `config.get('FieldName', '')` — never `config['FieldName']`
2. Always iterate lists — never assume `list[0]` is the only item
3. `isinstance(value, list) and value` before iterating
4. `isinstance(value, str) and value.startswith('prefix-')` before treating as ID
5. When a response could contain multiple items, iterate all of them
6. Expect pagination on every AWS API call that returns a list of resources

For pagination: the discovery engine (`deep_discover.py`) uses boto3 paginators
by default. Templates mark `paginator: true`. The engine falls back to single
calls only for APIs that are explicitly not pageable. `service_enumerator.py`
is the one exception — it probes for existence (first page only, intentionally).

For list processing: if a query returns multiple VPCs, process all of them.
If DHCP has multiple DNS servers, emit all of them. The response dimension
is never guaranteed — treat every list as potentially multi-element.

## Consequences

- Code is slightly more verbose but never crashes on missing data
- Empty/missing fields produce empty output (visible in templates) rather than
  stack traces (invisible until someone runs the pipeline)
- The operator sees a blank parameter rather than the pipeline failing silently
- Code reviews should flag any bare `dict['key']` or `list[idx]` on config data
