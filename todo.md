# Discovery In-Depth — TODO

## Cross-Region Replication Detection

The template engine currently handles single list/describe operations per service. Detecting cross-region replication requires per-resource follow-up calls, which the engine doesn't support yet.

### Services needing per-resource secondary calls
- **S3 Buckets** — `get_bucket_replication` per bucket (throws `ReplicationConfigurationNotFoundError` if not configured, needs per-bucket error handling)
- **DynamoDB** — `describe_table` per table returns `Replicas[]` with region info

### Services with standalone list operations (easier)
- **Aurora Global Databases** — `describe_global_clusters` returns cluster members and their regions
- **ElastiCache Global Datastores** — `describe_global_replication_groups` returns member regions

### What's needed
1. Add a `secondary_calls` concept to the template engine in `deep_discover.py` — after the primary list operation, make per-resource follow-up API calls and merge results into the resource config
2. Handle per-resource errors gracefully (e.g., S3 buckets without replication)
3. Surface replication status in draw.io diagrams and audience views
4. Add replication targets to the Cross-Region Dependencies sections in engineering and operations views

### Already done
- RDS cross-region read replicas — `ReadReplicaSourceDBInstanceIdentifier` and `ReadReplicaDBInstanceIdentifiers` are captured from the existing `describe_db_instances` response (no secondary call needed)
