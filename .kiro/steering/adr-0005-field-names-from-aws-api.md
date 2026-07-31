---
inclusion: auto
---

# ADR-0005: Field Names Taken from AWS API Response (Not Normalized)

Date: 2026-07-31
Status: Accepted

## Context

The discovery engine (`deep_discover.py`) stores resource config using field names
from the raw AWS API response. This means:
- EC2 subnet is `SubnetId_SubnetId` (collision-safe from `Placement.SubnetId` vs
  `NetworkInterfaces[].SubnetId`)
- SG rules are `IpPermissions` (not `IngressRules`)
- RDS SGs are `VpcSecurityGroupId` (not `VpcSecurityGroups`)
- DHCP options are `DhcpConfigurations[].Key/Values` (not flat `domain-name`)
- SNS topics have `TopicArn` (not `TopicName`)
- FSx Windows config is `WindowsConfiguration_DeploymentType` (flattened with underscore)

The IaC generator must match these exact field names or produce empty output.

## Decision

The IaC generators use the field names as they exist in the inventory, with
helper functions (like `_get_subnet_id()`) to handle collision-safe variants.
We do NOT normalize field names in a preprocessing step — that would add
complexity and another place for bugs.

When adding a new generator or modifying an existing one:
1. Always check the actual inventory YAML for the resource type
2. Use `grep` or `Select-String` to find the exact field name
3. Never assume a field name matches the CFN property name

## Consequences

- Generators must be tested against real inventory data (not synthetic)
- The `_get_subnet_id()` pattern (try multiple field variants) is the model
  for handling collision-safe keys
- Adding a new resource type to the generator requires verifying field names
  against at least one real customer's inventory output
- This is a source of bugs if not verified — as proven by the IpPermissions,
  DHCP, and SNS issues found during Instem testing
