# Operational Scripts

Standalone utilities for DR preparation and post-implementation assessment.
These complement the main discovery pipeline — run them independently as
needed during recovery prep, DR testing, or change auditing.

All scripts use `boto3` and are designed for AWS CloudShell or any
environment with valid credentials. No customer-specific values are
hardcoded — everything is passed via CLI arguments.

## Prerequisites

- Python 3.8+
- `boto3` (included in CloudShell)
- `pyyaml` (`pip install pyyaml`) — required by config-change scripts
- Valid AWS credentials with appropriate permissions

## Scripts by Category

### DR Preparation (run before or during recovery)

| Script | Purpose | Key Arguments |
|--------|---------|---------------|
| `replicate-secrets.py` | Copy all Secrets Manager secrets to DR region | `--source-region`, `--dest-region` |
| `replicate-parameters.py` | Copy all SSM parameters to DR region | `--source-region`, `--dest-region` |
| `map-backup-to-resources.py` | Map Backup recovery points to AMI/Snapshot IDs | `--source-region`, `--dr-region`, `--vault-name` |

### Verification (run after deployment or during DR test)

| Script | Purpose | Key Arguments |
|--------|---------|---------------|
| `map-all-internet-facing-resources.py` | Trace Internet → LB → EC2 → RDS paths | `--region` |
| `dns-to-target-walk.py` | Walk DNS records through LBs to targets with health | `--zone-id`, `--region` |

### Post-Implementation Assessment (config change auditing)

| Script | Purpose | Key Arguments |
|--------|---------|---------------|
| `sg-vpc-config-changes.py` | SG rule changes in a VPC within a time window | `--vpc-id`, `--region`, `--start`, `--end` |
| `rt-config-changes.py` | Route table changes in a VPC | `--vpc-id`, `--region`, `--start`, `--end` |
| `compute-config-changes.py` | EC2, ELB, Target Group, S3 changes in a VPC | `--vpc-id`, `--region`, `--start`, `--end` |
| `iam-policy-config-changes.py` | IAM policy and role changes (account-wide) | `--region`, `--start`, `--end` |

## Usage Examples

### Replicate secrets and parameters before a DR test

```bash
python3 scripts/replicate-secrets.py \
  --source-region us-gov-west-1 --dest-region us-gov-east-1

python3 scripts/replicate-parameters.py \
  --source-region us-gov-west-1 --dest-region us-gov-east-1
```

### Map backup recovery points to AMIs for restore

```bash
python3 scripts/map-backup-to-resources.py \
  --source-region us-gov-west-1 \
  --dr-region us-gov-east-1 \
  --vault-name my-cross-region-vault \
  --max-age-hours 48
```

### Verify traffic paths after DR deployment

```bash
python3 scripts/map-all-internet-facing-resources.py --region us-gov-east-1

python3 scripts/dns-to-target-walk.py \
  --zone-id Z0712928DILH42U83LKS --region us-gov-east-1
```

### Audit changes after a maintenance window

```bash
python3 scripts/sg-vpc-config-changes.py \
  --vpc-id vpc-008f52970d488679a --region us-gov-west-1 \
  --start 2026-07-01 --end 2026-07-15

python3 scripts/rt-config-changes.py \
  --vpc-id vpc-008f52970d488679a --region us-gov-west-1 \
  --start 2026-07-01 --end 2026-07-15 \
  --enrichment-prefixes "192.168.237.,192.168.238."

python3 scripts/compute-config-changes.py \
  --vpc-id vpc-008f52970d488679a --region us-gov-west-1 \
  --start 2026-07-01 --end 2026-07-15

python3 scripts/iam-policy-config-changes.py \
  --region us-gov-west-1 --region us-gov-east-1 \
  --start 2026-07-01 --end 2026-07-15
```

## Config Change Scripts — Important Notes

The four config-change scripts (`sg-vpc-*`, `rt-*`, `compute-*`, `iam-*`)
depend on **AWS Config Recorder** being enabled during the time window.
Each script performs a preflight check and warns if Config is not active.

If Config was not recording during the window of interest, the scripts
will return no results — this is not an error, it means there is no
recorded history to diff against.

**Output formats:** Each config-change script produces three files:
- `.txt` — Human-readable report
- `.csv` — Spreadsheet-friendly (Excel, Sheets)
- `.yaml` — Structured data for automation or CloudFormation reference

Output filenames include the VPC ID and date range for safe repeated use:
`sg-changes-vpc-008f52970d488679a-2026-07-01-2026-07-15.txt`

## Adapting to Different Environments

All scripts work in both commercial and GovCloud regions. Just change
the `--region` argument:
- GovCloud: `us-gov-west-1`, `us-gov-east-1`
- Commercial: `us-east-1`, `us-west-2`, etc.

No code edits needed. The scripts are environment-agnostic by design.
