# Recovery Guide — From Inventory to Running Environment

This document covers the second half of the workflow: you've run the tool,
you have output. Now what?

## The Big Picture

The tool produces a complete inventory and IaC templates. Recovery from
that output follows this sequence:

```
1. Assess    — What do we have? What's missing? What are the dependencies?
2. Plan      — What order do things deploy in? What needs manual action?
3. Prepare   — Copy snapshots/AMIs/backups to DR region, gather credentials
4. Execute   — Deploy stacks in order, run manual steps, validate
5. Verify    — Smoke test, DNS cutover, connectivity checks
```

## Navigating the Output

After a run you have this tree:

```
output/<label>/<region>/<timestamp>/
├── inventory-<region>.yaml        ← The source of truth. Everything discovered.
├── summary.txt                    ← Quick resource counts per category
├── iac-templates/
│   ├── DEPLOY.md                  ← Stack deployment commands in order
│   ├── manual-steps.md            ← Things that can't be automated
│   ├── templates/*.yaml           ← One CFN template per resource type
│   └── params/*/*.json            ← One param file per resource instance
├── architecture-operations-*.md   ← Recovery-focused view (start here)
└── architecture-engineering-*.md  ← Full technical detail
```

**Start here:** `architecture-operations-<region>.md` — it's organized by
recovery priority and calls out dependency chains and DR notes.

## Step 1: Assess — What Do We Have?

### Quick Scan

Open `summary.txt` for resource counts. Anything with zero that you
expected? That's a discovery gap — check if a template exists.

### Identify the Boot Order Dependencies

Search the inventory for DHCP Option Sets and check `DhcpConfigurations`:

```yaml
# If you see domain-name-servers pointing to private IPs (not AmazonProvidedDNS):
DhcpConfigurations:
  - Key: domain-name-servers
    Values:
      - Value: 100.64.41.125
      - Value: 100.64.41.142
```

Those IPs are Domain Controllers. **Everything depends on them.**

Boot order for AD-dependent environments:
```
VPC → Subnets → Route Tables → Security Groups
    → NAT Gateways → Domain Controllers (EC2)
    → FSx (AD-joined) → RDS → Other EC2 instances
```

### Check for DR Gaps

Look for these red flags in the inventory:

| Gap | Where to Look | What It Means |
|-----|---------------|---------------|
| No S3 CRR | `S3 Replication` category empty or missing buckets | Bucket data won't be in DR region |
| No AWS Backup | `Backup Plans` category empty | No automated backup/copy schedule |
| Secrets not replicated | `Secrets` → `ReplicationStatus` field empty | Secrets must be manually recreated |
| FSx no cross-region backup | `FSx Backups` → check for cross-region copies | File system data trapped in source region |
| Snapshots not copied | `EBS Snapshots` → all in one region | Volume data not available for DR restore |
| AMIs not copied | `AMIs` → all in one region | Can't launch instances in DR |
| DLM gaps | Compare `EBS Volumes` list against `DLM Lifecycle Policies` tags | Volumes without snapshot automation |

### Understand What's Not Automated

Open `manual-steps.md`. Ignore the "noise" entries (Health Event Types,
service catalog items). Focus on entries that represent actual workload
resources without CFN mappings.

Common items that legitimately need manual steps:
- **SSM Parameters** — may contain secrets, need manual review
- **Secrets Manager secrets** — values aren't exported, must be recreated
- **Custom resource configurations** — things the tool doesn't model yet

## Step 2: Plan — Deployment Order

### Use DEPLOY.md

`iac-templates/DEPLOY.md` contains the exact `aws cloudformation deploy`
commands in the correct order. The order matters:

1. **Foundation** — VPCs, Subnets, Route Tables, DHCP Options
2. **Security** — Security Groups (bespoke template with cross-references)
3. **Network** — NAT Gateways, VPC Endpoints, TGW, VPN
4. **Identity** — Directories, KMS Keys
5. **Data** — RDS, ElastiCache, DynamoDB, FSx (restore from backup)
6. **Compute** — EC2, ASGs, ECS, EKS
7. **Routing** — Load Balancers, Target Groups, Listeners
8. **Serverless** — Lambda, Step Functions, EventBridge Rules
9. **DNS** — Route 53 (or DHCP Option Set update to point to new DC IPs)
10. **Monitoring** — CloudWatch Alarms, SNS Topics

### Parameter Files Need Updating

The param files in `params/` contain values from the source region.
Before deploying to DR, you **must** update:

- `SubnetId` → new subnet IDs in DR region
- `VpcId` → new VPC ID
- `SecurityGroupIds` → new SG IDs
- `ImageId` → AMI ID after cross-region copy
- `KmsKeyId` → KMS key ARN in DR region
- `CertificateArn` → ACM cert ARN in DR region (re-issue or import)
- `DBSnapshotIdentifier` → snapshot ID after cross-region copy
- `BackupId` → FSx backup ID after cross-region copy

These are marked as parameters (not hardcoded properties) specifically
so they can be swapped for DR values without editing the template itself.

### The Gotcha List

Things that bite you during recovery if you don't plan for them:

1. **AD/DNS dependency** — If DHCP options point to DC IPs, those DCs
   must be the first EC2 instances launched. Nothing else can resolve
   DNS until they're up and have promoted/restored AD.

2. **Security Group circular references** — SG A references SG B and
   SG B references SG A. The bespoke SG template handles this with a
   two-phase approach (create empty, then add rules), but you need to
   deploy it before anything that references those SGs.

3. **ACM certificates** — Can't be copied cross-region. Must re-request
   or import in DR region. DNS validation records need to be accessible.

4. **KMS keys** — Region-specific. Any resource encrypted with a CMK
   needs a new key in DR. Cross-region snapshot copies re-encrypt with
   the DR key automatically, but you need the key to exist first.

5. **Elastic IPs** — Specific IPs don't transfer. Anything hardcoded to
   an EIP (firewall rules at partners, DNS records) needs updating.

6. **FSx AD join** — The file system creation will fail if it can't
   reach the domain controllers. DCs must be healthy and the domain
   functional before FSx creation begins.

7. **RDS Parameter Groups** — Must exist before the DB instance that
   references them. Deploy parameter groups first, then instances.

8. **Load Balancer idle timeout / attributes** — Not captured in the
   basic config. Check source LB attributes if you have custom values.

9. **Lambda code packages** — The S3 bucket holding the deployment
   package must exist in DR. If using CRR on code buckets, it's
   automatic. Otherwise, you need to copy packages manually.

10. **Target Group registration** — New instance IDs must be registered
    after compute comes up. The IaC templates create the TGs but can't
    register targets that don't exist yet.

## Step 3: Prepare — Pre-DR Actions

Before you can execute recovery, these assets must exist in the DR region:

### Cross-Region Copies Needed

```bash
# Copy AMIs to DR region
aws ec2 copy-image --source-region us-gov-west-1 \
  --source-image-id ami-xxxxxxxx --region us-gov-east-1 \
  --name "DR copy of <name>"

# Copy EBS snapshots to DR region
aws ec2 copy-snapshot --source-region us-gov-west-1 \
  --source-snapshot-id snap-xxxxxxxx --region us-gov-east-1

# Copy FSx backup to DR region
aws fsx copy-backup --source-region us-gov-west-1 \
  --source-backup-id backup-xxxxxxxx --region us-gov-east-1

# Copy RDS snapshot to DR region
aws rds copy-db-snapshot --source-region us-gov-west-1 \
  --source-db-snapshot-identifier <arn> --region us-gov-east-1 \
  --target-db-snapshot-identifier dr-copy-<name>
```

If AWS Backup is configured with cross-region copy rules, these happen
automatically. If not (common gap), you must script or manually copy.

### Credentials and Secrets

- Retrieve secret values from Secrets Manager and store securely for
  manual recreation in DR
- Export SSM Parameter Store values (non-SecureString can be scripted;
  SecureString values need the source KMS key or manual re-entry)
- Gather AD admin credentials for domain controller promotion
- Collect any third-party API keys, certificates, license files

### KMS Keys

Create matching KMS keys in the DR region before deploying encrypted
resources. Record the new key ARNs for use in parameter files.

## Step 4: Execute — Deploy

Follow `DEPLOY.md` commands in order. For each stack:

1. Review the parameter file — confirm DR values are correct
2. Deploy the stack
3. Wait for CREATE_COMPLETE
4. Note any new resource IDs needed by downstream stacks

### After Compute Is Up

- Register EC2 instances with Target Groups
- Verify AD join for domain-joined instances
- Confirm DNS resolution is working (nslookup against DC IPs)
- Start application services in dependency order

## Step 5: Verify

### Connectivity Checks

- [ ] VPC routing — can instances reach each other?
- [ ] NAT Gateway — can private instances reach the internet?
- [ ] VPC Endpoints — can instances reach AWS services?
- [ ] Security Groups — are the right ports open?
- [ ] DNS — does name resolution work for internal and external names?
- [ ] TGW/VPN — is cross-VPC or on-prem connectivity working?

### Application Checks

- [ ] Database connectivity from compute tier
- [ ] FSx mount and file access
- [ ] Load balancer health checks passing
- [ ] Application endpoints responding
- [ ] Monitoring and alerting active (CloudWatch alarms, SNS)

### DR-Specific Validation

- [ ] RPO met — is the data as recent as required?
- [ ] RTO tracking — how long did recovery take?
- [ ] DNS cutover ready — can we point traffic to the DR environment?
- [ ] Runbook gaps — what wasn't covered that we discovered during execution?

## Common Scenarios

### "The account has no AWS Backup, no S3 CRR, and relies on DLM"

This means:
- EBS snapshots may exist but only in the source region
- S3 data is not replicated — if the source region is gone, data is gone
- No automated cross-region copy of anything

**Action:** Before the next DR test or real event, implement:
1. AWS Backup with cross-region copy rules for EBS, RDS, FSx
2. S3 CRR for buckets containing application data and code packages
3. Scheduled AMI copies (or use AWS Backup for EC2)

### "DNS is entirely via AD DCs in EC2"

This means:
- The DHCP Option Set points to EC2 instance IPs for DNS
- No AmazonProvidedDNS fallback
- DCs are the first thing that must come up

**Action:**
1. Ensure DC AMIs are copied cross-region (or have a restore-from-snapshot plan)
2. Deploy DCs first, wait for AD health, then proceed with other resources
3. Update the DHCP Option Set in DR to point to new DC IPs
4. Consider adding AmazonProvidedDNS as a fallback (if AD DNS forwarding allows)

### "FSx for Windows is present"

This means:
- File system data must be restored from a backup in the DR region
- AD must be healthy before FSx can be created (domain join requirement)
- Storage capacity and throughput must match production

**Action:**
1. Ensure FSx backups are being copied cross-region (AWS Backup or manual)
2. In DR: deploy DCs → wait for domain → create FSx from backup
3. Update DHCP/DNS before FSx creation (FSx needs to resolve the domain)

## Reading the Inventory YAML

### Structure

```yaml
metadata:
  account_id: "048766100331"
  region: us-gov-west-1
  scan_date: "2026-07-29T20:07:20Z"
resources:
  EC2 Instances:
    - resource_key: "inst:i-0abc123"
      resource_type: EC2 Instances
      resource_id: "i-0abc123"
      name: "web-server-1a"
      dr_note: "Instance IDs change in DR..."
      config:
        InstanceId: "i-0abc123"
        ImageId: "ami-xxxxxxxx"
        # ... all captured fields
        Tags:
          Name: "web-server-1a"
          Environment: "production"
```

### Key Fields

- `dr_note` — Read these. They call out service-specific gotchas.
- `config.Tags` — Use tags to identify what's managed by other tools
  (CloudFormation, Terraform, CCPM) vs. what's manually provisioned.
- `resource_key` — Unique identifier in the format `prefix:id`. Use for
  cross-referencing between categories.

### Filtering Noise

The inventory captures everything, including AWS service catalog data
(Health Event Types, Artifact Reports, pricing info). These are captured
because the auto-template generator discovers any service with resources.

To focus on workload resources, look at these categories:
- EC2 Instances, Auto Scaling Groups
- RDS Instances, RDS DB Clusters, ElastiCache
- Load Balancers, Target Groups, Listeners
- Lambda Functions, ECS/EKS
- S3 Buckets, FSx File Systems
- VPCs, Subnets, Security Groups, Route Tables
- Secrets, SSM Parameters, KMS Keys

Ignore these (service catalog / platform noise):
- Describe Event Types, Describe Affected Entities
- List Service Level Objectives, Get Service
- Describe Trusted Advisor Checks
- Anything from `health`, `artifact`, `servicecatalog`, `support`
