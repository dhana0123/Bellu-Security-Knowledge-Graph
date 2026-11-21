# Operations

Applies to the AWS host created by `infra/` and the Compose stack in `deploy/`.
Commands marked (planned) belong to later tasks and are not wired yet.

## Sizing and Neo4j memory

Default host: `t4g.large` (ARM64, 2 vCPU, 8 GB RAM). The stack must stay at or
below RAM minus 1 GB (7 GB on the default host).

| Part | Setting (8 GB) | Reason |
| --- | --- | --- |
| Neo4j heap | 2 GiB, initial equals maximum | No resize pauses. Inside the required 1 to 2 GB |
| Neo4j page cache | 2500m | Inside the required 2 to 3 GB |
| Neo4j container limit | 5632m | Heap + page cache + about 1 GiB for metaspace, thread stacks, direct buffers, Lucene |
| Transaction memory cap | `dbms.memory.transaction.total.max` = 1g | A runaway query fails instead of killing the JVM |
| Worker | 768m, `GOMEMLIMIT=600MiB` | Batches of at most 10,000 records |
| API | 384m, `GOMEMLIMIT=300MiB` | |
| Total | 6784 MiB (6.6 GiB) | Below the 7 GiB ceiling |

For a 16 GB host (`t4g.xlarge` or `m7g.xlarge`) append `deploy/.env.16gb` to
`deploy/.env`: heap 4g, page cache 6g, `NEO4J_MEM_LIMIT=11g`. The page cache is
small for a graph that may reach several GB, so the first full-text and
statistics queries can run cold. Record the measured values below after the
sample and full builds.

| Measurement | Sample build | Full build |
| --- | --- | --- |
| Date | 2026-11-21 | 2026-11-21 |
| Peak Neo4j heap | not measured (2 GiB fixed) | not measured (2 GiB fixed) |
| Peak container memory (neo4j / worker / api) | 2.5 GiB / 90 MiB / 30 MiB | 4.6 GiB / 90 MiB / 34 MiB (Neo4j limit 5.5 GiB) |
| Store size on disk | under 1 GB | 8.9 GB on /data |
| Stats query time | under 1 s | 12.0 s cold, cached 5 min |
| Out-of-memory kills | none | none |

## Create the infrastructure

The application never creates AWS resources. The operator runs Terraform from
`infra/` with their own credentials, and confirms the plan first.

```
cd infra
terraform init
terraform plan  -var 'api_allowed_cidrs=["203.0.113.0/24"]' -var operator_cidr=203.0.113.7/32 \
                -var repo_url=https://example.com/bskg.git
terraform apply   # after reviewing the plan
terraform destroy # removes the instance, volume, and Elastic IP
```

`t4g` instances run in unlimited CPU credit mode by default (`cpu_credits`), so
the long full build does not throttle. Set `cpu_credits=standard` to avoid the
extra cost at the price of a slower build.

The instance role carries no policy: no S3 and no static AWS keys on the host.
IMDSv2 is required with hop limit 1, so containers cannot reach the metadata
service. Ports 7687 and 7474 are never opened or published.

## Start the stack

On the host, as user `ubuntu`:

```
cd /opt/bskg/deploy
cp .env.example .env      # fill NEO4J_PASSWORD and BSKG_CURSOR_SECRET
docker compose build
docker compose up -d
```

The worker runs the build queue on an empty volume without further commands:
`migrate`, `cwe`, `nvd-catch-up`, `exploitdb`. `buildState` reports the running
job (`migrating`, `loading_cwe`, `nvd_catch_up`, `loading_exploits`) and
`ready` when the queue is complete.

### Sample build first

Set `BSKG_SAMPLE_LIMIT=1000` in `.env` before the first start. The queue loads
the full CWE catalog, the first 1000 NVD records, and the matching Exploit-DB
rows, then reports `ready` and starts no daily schedule. Run `bskg validate`
and inspect the result. To continue to the full build on the same graph, empty
`BSKG_SAMPLE_LIMIT` and run `docker compose up -d` again: CWE stays, NVD and
Exploit-DB run again. `BSKG_SAMPLE_ORDER=latest` makes the sample take the most
recent N NVD records instead of the first N; changing it re-runs NVD and
Exploit-DB. A full graph cannot be reduced to a sample; run
`bskg reset --confirm` (planned) first.

## API keys (planned)

```
docker compose exec bskg-worker /bskg apikey create bellu-code
docker compose exec bskg-worker /bskg apikey revoke bellu-code
```

The key is printed once. Send it in the `Authorization` header. Outside a
private network, put TLS in front of the API: set `BSKG_API_TLS_CERT_FILE` and
`BSKG_API_TLS_KEY_FILE`, or use a host-level reverse proxy.

## Failed jobs

A job is retried 3 times after the first attempt, waiting 5, 10, and 20 seconds.
Then the queue stops and keeps the `buildState` of the failed job. The API keeps
running. A failed `migrate` job makes the worker exit with status 1 and name the
migration version; Compose restarts it.

1. Read the cause: `docker compose logs bskg-worker` and `bskg sync status` (planned).
2. Fix it (network, credentials, disk space).
3. `docker compose restart bskg-worker`. Jobs that succeeded are skipped; the
   failed job starts again.

A job that reports `job not implemented` belongs to a source adapter that is not
built yet.

## Validate

```
docker compose exec bskg-worker /bskg validate --out /tmp/validation-report.json
```

Exit status 0 means every check passed. The check set grows with task 9.4.

## Backups

EBS snapshots of the data volume (tag `bskg-backup=true`) are taken daily by AWS
Data Lifecycle Manager at 03:30 UTC. `snapshot_retain_count` (default 3) sets
how many are kept. BSKG has no backup code.

Restore:

1. Create a volume from a snapshot in the instance's availability zone.
2. Stop the stack: `docker compose down`.
3. Detach the current data volume, attach the restored volume as `/dev/sdf`,
   and mount it at `/data` (the filesystem is XFS; see `/etc/fstab`).
4. `docker compose up -d`. The worker finds the jobs done and starts no job.

S3 is a possible future backup target and is not used today.
