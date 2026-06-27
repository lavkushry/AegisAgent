# Gateway performance tuning guide (TASK-0075)

Operator-facing guide to the gateway's tunable knobs — what each one does,
its default, when to change it, and what to watch after changing it. For
the underlying measurements and methodology these defaults were chosen
against, see [`performance-baseline.md`](performance-baseline.md).

All settings below are read once at startup (env vars), logged at `info`
level on boot, and require a restart to change.

## 1. Database connection pool

| Env var | Default | Notes |
|---|---|---|
| `AEGIS_DB_MAX_CONNECTIONS` | `5` | SQLite max pool connections (`lib/storage/src/db/mod.rs`). |
| `DATABASE_URL` | `sqlite://aegis.db` | `sqlite://...` or (with the `postgres` feature) a Postgres URL. |

Not configurable via env (intentional, baked-in safe defaults — see
[`sqlite_usage.md`](../.claude/rules/sqlite_usage.md)):
- **WAL journal mode** — readers don't block writers.
- **`busy_timeout` = 5s** — a writer waiting on the SQLite write lock retries
  for up to 5s before erroring, instead of failing instantly under brief
  write contention.
- **`synchronous = NORMAL`** — balances durability and write throughput;
  safe under WAL (only loses the most recent transaction on an OS crash,
  never corrupts the file).

**When to raise `AEGIS_DB_MAX_CONNECTIONS`:** SQLite's single-writer model
means raising this mostly helps *read* concurrency, not write throughput —
see "SQLite throughput ceiling" in `performance-baseline.md` for the
measured ceiling and the path to scaling past it (read replicas / Postgres).
Watch `db_query` tracing spans (added for #900) and the pool-health sampler
log line (`AEGIS_POOL_HEALTH_SAMPLE_INTERVAL_SECS`, below) for "pool over 80%
busy" warnings before increasing this.

## 2. In-memory caches

Each cache is a bounded LRU; setting capacity to `0` disables it (every
lookup falls through to the DB).

| Env var | Default | Cache |
|---|---|---|
| `AEGIS_SKILL_CACHE_CAPACITY` | `1024` | Registered skill-action metadata (#899) — avoids a DB read on every `/v1/authorize` call to resolve a tool/action's risk/mutates_state/default_decision. |
| `AEGIS_MCP_SERVER_CACHE_CAPACITY` | `1024` | MCP server records (#1337). |
| `AEGIS_MCP_TOOL_CACHE_CAPACITY` | `1024` | MCP tool records (#1337). |
| `AEGIS_CANONICAL_HASH_CACHE_CAPACITY` | `1024` | JCS-1 canonical action hashes. |
| `AEGIS_REPLAY_NONCE_CACHE_CAPACITY` | `10000` | Opt-in `/v1/authorize` replay-protection nonces (#1306). |
| `AEGIS_RISK_WEIGHTS_CACHE_TTL_SECS` | `60` | TTL (not size) — per-tenant composite-risk-score weights; invalidated immediately on `PUT /v1/tenants/risk-weights`, so this TTL only bounds staleness for instances that *don't* see the invalidation (e.g. before #1210's shared-state work lands). |

**Sizing rule of thumb:** the skill/MCP-server/MCP-tool caches should be
sized to comfortably exceed the number of distinct tool/action and MCP
server/tool pairs a tenant actually calls — there's no benefit to
over-provisioning beyond that working set, and each entry is small (a
handful of `String`s + scalars), so erring high costs little memory.

## 3. Rate limiting and quotas

| Env var | Default | Notes |
|---|---|---|
| `AEGIS_RATE_LIMIT_CAPACITY` | `100` | Token-bucket burst capacity, per agent token. |
| `AEGIS_RATE_LIMIT_REFILL_RATE` | `10` | Tokens/second refill. |
| `AEGIS_QUOTA_LIMIT` | `0` (disabled) | Max requests per `AEGIS_QUOTA_WINDOW_SECS` window, per agent. |
| `AEGIS_QUOTA_WINDOW_SECS` | `86400` | Quota window (default 24h). |
| `AEGIS_APPROVAL_CALLBACK_IP_LIMIT` | `10` | Per-source-IP token bucket for `POST /v1/approvals/:id/{approve,reject,edit}` (#1307); refills at `limit / 60` tokens/sec. |
| `AEGIS_APPROVAL_ATTEMPT_LIMIT` / `AEGIS_APPROVAL_ATTEMPT_WINDOW_SECS` | `5` / `3600` | Max failed (4xx) approval-callback attempts per `approval_id` per window (#1307). |

**Load-testing against the gateway?** Set
`AEGIS_RATE_LIMIT_CAPACITY`/`AEGIS_RATE_LIMIT_REFILL_RATE` very high first —
the built-in limiter will otherwise cap your measured throughput well below
the gateway's actual ceiling (`performance-baseline.md`'s sustained-throughput
test calls this out explicitly).

## 4. HTTP-level limits

| Env var | Default | Notes |
|---|---|---|
| `AEGIS_MAX_BODY_LIMIT_BYTES` | `1048576` (1MB) | Request body size cap. |
| `AEGIS_REQUEST_TIMEOUT_SECS` | `30` | Global per-request timeout. |
| `AEGIS_MAX_CONCURRENT_REQUESTS` | `1000` | Load-shed threshold (#911) — requests beyond this get `503` instead of queuing indefinitely. |

Lower `AEGIS_MAX_CONCURRENT_REQUESTS` if the DB pool (above) is the actual
bottleneck — letting more requests queue past the point the pool can drain
them just trades a fast `503` for a slow timeout.

## 5. Audit-event batching (#1315)

Audit events are buffered and flushed in batches rather than one write per
request — see [`audit_batch.rs`](../lib/storage/src/audit_batch.rs).

| Env var | Default | Notes |
|---|---|---|
| `AEGIS_AUDIT_BATCH_SIZE` | `100` | Flush early once this many events are buffered. |
| `AEGIS_AUDIT_BATCH_FLUSH_MS` | `500` | Otherwise flush on this timer. |

Raising `AEGIS_AUDIT_BATCH_SIZE` trades a few hundred ms of audit-event
visibility lag for fewer, larger DB writes under high request volume.

## 6. Background jobs

All gated on `is_leader` in multi-instance deployments (#1149) — only the
elected leader runs these, so raising instance count doesn't multiply job
load.

| Env var | Default | Job |
|---|---|---|
| `AEGIS_LEADER_ELECTION_INTERVAL_SECS` | `5` | Leader-election heartbeat. |
| `AEGIS_LEADER_LEASE_SECS` | `20` | Leader lease duration. |
| `AEGIS_RECEIPT_INTEGRITY_INTERVAL_SECS` | `3600` | Full receipt-chain integrity check, all tenants (#0107). |
| `AEGIS_AUDIT_ARCHIVAL_INTERVAL_SECS` / `AEGIS_AUDIT_RETENTION_DAYS` | `86400` / `90` | Archive old `audit_events` rows (#0106). |
| `AEGIS_APPROVAL_CLEANUP_INTERVAL_SECS` / `AEGIS_APPROVAL_RETENTION_DAYS` | `86400` / `30` | Delete stale decided/expired approvals (#0105). |
| `AEGIS_VACUUM_INTERVAL_SECS` | `86400` | `VACUUM` to reclaim space from the above deletes (#0061). |
| `AEGIS_POOL_HEALTH_SAMPLE_INTERVAL_SECS` | `30` | Sample DB pool acquire latency; warns when the pool is over 80% busy (REL-004, #1150). |
| `AEGIS_HEARTBEAT_FLUSH_INTERVAL_SECS` | `30` | Agent heartbeat debounce flush. |

The receipt-integrity check (`AEGIS_RECEIPT_INTEGRITY_INTERVAL_SECS`) scans
every tenant's full hash chain — on a large `action_receipts` table this is
the most expensive background job. If it starts contending with foreground
traffic, raise the interval before touching anything else here.

## 7. Re-measuring after a change

- `cargo bench --bench authorize_benchmark -p gateway` — in-process p50/p95/p99 for the hot `/v1/authorize` path (criterion; CI regression-gates this at >20%, see `performance-baseline.md`'s "CI regression gate").
- `cargo bench --bench audit_batch_benchmark -p gateway` — audit-batch flush throughput.
- The vegeta HTTP load-test commands under "Sustained-throughput load test" in `performance-baseline.md` for end-to-end, real-network numbers.

Change one knob at a time and re-run the relevant benchmark — these settings
interact (e.g. a bigger DB pool doesn't help if the rate limiter caps load
well below the pool's capacity first).
