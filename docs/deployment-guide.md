# Deployment Guide

Production deployment reference for the AegisAgent gateway: Docker Compose, Kubernetes (Helm), and bare metal, plus an environment variable reference, a production checklist, and capacity planning grounded in measured benchmarks.

This page assumes you've already read [`docs/getting-started.md`](getting-started.md) or [`docs/quickstart.md`](quickstart.md) for the zero-setup demo. It's about running the gateway as a real, long-lived service.

## 1. Docker Compose

The repo ships two compose files:

- **`docker-compose.yml`** — the base gateway service. Starts with an empty database; you seed it yourself (`bash scripts/seed-demo.sh`), which is what CI's "Docker Compose E2E" job does.
- **`docker-compose.dev.yml`** — `include:`s the base file and layers on a one-shot `seed-demo` service that runs `scripts/seed-demo-dev.sh` automatically once the gateway reports healthy. Use this for local development.

```bash
# Production-leaning: empty DB, seed yourself (or skip seeding entirely)
docker compose up --build -d
bash scripts/seed-demo.sh   # optional — demo agents/tools/decisions

# Local dev: auto-seeded
docker compose -f docker-compose.dev.yml up --build
```

Both compose files run the gateway image built from [`src/Dockerfile`](../src/Dockerfile) — a multi-stage build that lands on `gcr.io/distroless/cc-debian12:nonroot` (no shell, no package manager, runs as uid/gid 65532). The base file's `init-data-dir` service is a one-shot `busybox` container that `chmod`s the bind-mounted `./data` directory before the gateway starts, since the host-side directory is created under your local user, not uid 65532.

For a real deployment, replace the bind mounts with named volumes and put a reverse proxy (or `AEGIS_TLS_CERT`/`AEGIS_TLS_KEY`, see §4) in front for TLS — `network_mode: host` in the shipped compose files is a local-dev convenience, not a production-hardening choice.

## 2. Kubernetes (Helm)

```bash
helm install aegis helm/aegis-gateway/ \
  --set image.repository=<your-registry>/aegis-gateway \
  --set image.tag=<your-tag>
```

The chart (`helm/aegis-gateway/`, #1206) ships Deployment, Service, ConfigMap (Cedar policy bundle), Secret, ServiceMonitor, NetworkPolicy, PodDisruptionBudget, HPA, ServiceAccount, and PVC templates. Read `helm/aegis-gateway/values.yaml` top to bottom before deploying — in particular:

- **`replicaCount: 1` / `autoscaling.enabled: false` by default.** The relational backend is SQLite + WAL (single writer) until the PostgreSQL backend (#1194) ships — see §6 below for the measured ceiling this implies. Don't raise `replicaCount` past 1 against the default `ReadWriteOnce` PVC.
- **`secret.create: false` by default.** Set `secret.create=true` with `secret.jwtSecret`/`secret.policySigningKey`/`secret.githubWebhookSecret` via `--set` or a values override file (never commit real secret values), or pre-create a Secret matching `secret.existingSecret` yourself.
- **`networkPolicy.enabled: true` by default**, restricting ingress to pods labeled `aegis-client: "true"`. Add your ingress controller / SDK-running namespaces via `networkPolicy.allowedNamespaceSelectors`/`allowedPodSelectors`.
- **`serviceMonitor.enabled: false` by default** — turn on if you run prometheus-operator; the chart self-suppresses the template if the `monitoring.coreos.com/v1` CRD isn't present in-cluster.
- **Cedar policy hot-reload is on by default** (`AEGIS_POLICY_HOT_RELOAD=true`). A `helm upgrade --set cedarPolicy="$(cat my-policy.cedar)"` updates the ConfigMap; kubelet refreshes the mounted file, and the gateway's filesystem watcher (#883) picks it up live without a pod restart.

Verify the rollout:

```bash
kubectl rollout status deployment/aegis-aegis-gateway
kubectl port-forward svc/aegis-aegis-gateway 8080:8080
curl http://127.0.0.1:8080/health
```

## 3. Bare metal

```bash
# Build a release binary
cargo build --release --manifest-path src/Cargo.toml
# binary lands at target/release/gateway (repo-root target/ — src/ is a
# workspace member, not its own workspace; see the root Cargo.toml)

# Run directly
CEDAR_POLICY_PATH=policies.cedar \
DATABASE_URL=sqlite://aegis.db \
AEGIS_BIND_ADDR=0.0.0.0:8080 \
./target/release/gateway
```

For a long-lived service, run it under `systemd`:

```ini
# /etc/systemd/system/aegis-gateway.service
[Unit]
Description=AegisAgent gateway
After=network.target

[Service]
Type=simple
User=aegis
WorkingDirectory=/opt/aegis
Environment=DATABASE_URL=sqlite:///opt/aegis/data/aegis.db
Environment=CEDAR_POLICY_PATH=/opt/aegis/policies.cedar
Environment=AEGIS_BIND_ADDR=0.0.0.0:8080
EnvironmentFile=-/etc/aegis/aegis.env
ExecStart=/opt/aegis/gateway
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/aegis/data

[Install]
WantedBy=multi-user.target
```

Put secret-bearing env vars (`AEGIS_JWT_SECRET`, `AEGIS_POLICY_SIGNING_KEY`, etc.) in `/etc/aegis/aegis.env` with `0600` permissions owned by the `aegis` user, not directly in the unit file (unit files are world-readable via `systemctl cat`).

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-gateway
journalctl -u aegis-gateway -f
```

## 4. Environment variable reference

All variables are optional unless noted; the gateway runs with secure, fail-closed defaults when unset.

### Core / networking

| Variable | Default | Description |
| --- | --- | --- |
| `AEGIS_BIND_ADDR` | `127.0.0.1:8080` | REST listener. Set to `0.0.0.0:8080` in containers so the Service/proxy can reach the pod. |
| `AEGIS_GRPC_BIND_ADDR` | `127.0.0.1:6334` | gRPC listener. |
| `AEGIS_TLS_CERT` / `AEGIS_TLS_KEY` | unset | PEM cert/key paths. Both must be set together to enable TLS (same-port HTTP→HTTPS detection); either alone falls back to plain HTTP with a warning. |
| `AEGIS_CORS_ORIGINS` | unset (no CORS headers — most restrictive) | Comma-separated allowed origins. |
| `AEGIS_MAX_BODY_LIMIT_BYTES` | `1048576` (1 MiB) | Request body size cap. |
| `AEGIS_REQUEST_TIMEOUT_SECS` | `30` | Global per-request timeout. |
| `AEGIS_MAX_CONCURRENT_REQUESTS` | `1000` | Load-shed ceiling; requests beyond this get an immediate `503` instead of queuing. |

### Database

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite://aegis.db` | SQLite connection string. |
| `AEGIS_DB_MAX_CONNECTIONS` | `5` | SQLite connection pool size. |
| `AEGIS_DB_IDLE_TIMEOUT_SECS` | `30` | Pool idle-connection timeout. |
| `AEGIS_DB_ACQUIRE_TIMEOUT_SECS` | `5` | Pool acquire timeout. |
| `AEGIS_DB_ENCRYPTION_KEY` | unset | Enables `PRAGMA key` (SQLCipher). Requires the gateway binary to be built with `--features sqlcipher` — fails closed at startup otherwise. |

### Authentication & policy

| Variable | Default | Description |
| --- | --- | --- |
| `AEGIS_JWT_REQUIRED` | `false` | When `true`, every request must carry a valid JWT and `AEGIS_JWT_SECRET` must be set (startup error otherwise). |
| `AEGIS_JWT_SECRET` | unset | HMAC secret(s) for JWT validation; comma-separated for zero-downtime rotation (`"new,old"`). |
| `AEGIS_MTLS_CA_CERT` | unset | Enables mTLS — clients must present a cert signed by this CA. Requires TLS to also be configured. |
| `AEGIS_MTLS_CRL_PATH` | unset | CRL file for mTLS revocation checks (only used if `AEGIS_MTLS_CA_CERT` is set). |
| `CEDAR_POLICY_PATH` | `policies.cedar` | Path to the Cedar policy file. |
| `AEGIS_POLICY_HOT_RELOAD` | `false` | Watches `CEDAR_POLICY_PATH` for changes and reloads automatically. |
| `AEGIS_POLICY_SIGNING_KEY` | unset | Ed25519 verifying key for `POST /v1/policies/bundles`. Unset → that endpoint always returns `501`. |

### Observability

| Variable | Default | Description |
| --- | --- | --- |
| `RUST_LOG` | `info,gateway=debug,sqlx=info` | Standard `tracing` filter syntax. |
| `AEGIS_OTLP_ENDPOINT` | unset | Enables OTLP/HTTP export for both traces and the `authorize_latency_seconds` histogram / hash-mismatch and provenance-denial counters. Entirely inert when unset. |
| `AEGIS_SPLUNK_HEC_URL` / `AEGIS_SPLUNK_HEC_TOKEN` | unset | Both required to enable Splunk HTTP Event Collector export of audit events. |
| `AEGIS_SPLUNK_HEC_BATCH_INTERVAL_SECS` | `30` | Splunk export batch interval. |
| `AEGIS_BUILD_HASH` | unset | Surfaced for build/version attribution in logs; set by CI/release tooling. |

### Webhooks & integrations

| Variable | Default | Description |
| --- | --- | --- |
| `AEGIS_GITHUB_WEBHOOK_SECRET` | unset | HMAC secret to verify `X-Hub-Signature-256` on `POST /v1/ingest` (`source: github_webhook`). Unset → signature check skipped. |
| `AEGIS_GITHUB_APP_TOKEN` | unset | Enables GitHub PR deny-comments and "Aegis Security Gate" check runs. |
| `AEGIS_SLACK_SIGNING_SECRET` | unset | HMAC secret to verify `X-Slack-Signature`. Unset → `POST /v1/callbacks/slack` refuses all requests with `404`. |
| `AEGIS_ADMISSION_WEBHOOK_URL` | unset | Pre-authorize admission webhook endpoint. |
| `AEGIS_ADMISSION_WEBHOOK_TIMEOUT_SECS` | `5` | Admission webhook call timeout. |
| `AEGIS_ADMISSION_WEBHOOK_FAIL_OPEN` | `true` (any value other than `"false"`/`"0"` counts as enabled) | Whether an unreachable admission webhook allows or blocks the action. |
| `AEGIS_WEBHOOK_URL` / `AEGIS_WEBHOOK_SECRET` | unset | SOC alert notification webhook + its HMAC signing secret. |
| `AEGIS_WEBHOOK_FAILURE_THRESHOLD` | `5` | Consecutive delivery failures before the circuit breaker opens. |
| `AEGIS_WEBHOOK_COOLDOWN_SECS` | `30` | Circuit-breaker cooldown before retrying. |

### Qdrant / semantic indexing

| Variable | Default | Description |
| --- | --- | --- |
| `AEGIS_QDRANT_URL` | unset | Enables the semantic-indexing exporter. Unset → no Qdrant client constructed at all. |
| `AEGIS_QDRANT_API_KEY` | unset | Qdrant auth. |
| `AEGIS_QDRANT_COLLECTION` | `aegis_audit_events` | Target collection name. |
| `AEGIS_EMBEDDING_STRATEGY` | `api` | `api` (HTTP embedding endpoint) or `local` (requires the `local-embeddings`/`fastembed` Cargo feature). |
| `AEGIS_EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model name. |
| `AEGIS_EMBEDDING_URL` | `https://api.openai.com/v1/embeddings` | API-strategy embedding endpoint. |
| `AEGIS_EMBEDDING_KEY` | unset | API-strategy embedding auth key. |
| `AEGIS_EMBEDDING_DIMENSION` | `1536` | Vector dimension. |

### Rate limiting, quotas & caches

| Variable | Default | Description |
| --- | --- | --- |
| `AEGIS_RATE_LIMIT_CAPACITY` | `100` | Per-agent token-bucket capacity. |
| `AEGIS_RATE_LIMIT_REFILL_RATE` | `10` | Tokens/sec refill. |
| `AEGIS_QUOTA_LIMIT` | `0` (disabled) | Per-agent request quota. |
| `AEGIS_QUOTA_WINDOW_SECS` | `86400` (24h) | Quota window. |
| `AEGIS_APPROVAL_CALLBACK_IP_LIMIT` | `10` | Per-IP rate limit on approval-decision callbacks. |
| `AEGIS_APPROVAL_ATTEMPT_LIMIT` | `5` | Max failed (4xx) attempts per `approval_id`. |
| `AEGIS_APPROVAL_ATTEMPT_WINDOW_SECS` | `3600` | Window for the above. |
| `AEGIS_SKILL_CACHE_CAPACITY` | `1024` | Registered-action metadata LRU cache size; `0` disables. |
| `AEGIS_REPLAY_NONCE_CACHE_CAPACITY` | `10000` | Replay-protection nonce dedup cache size; `0` disables replay rejection. |
| `AEGIS_RISK_WEIGHTS_CACHE_TTL_SECS` | `60` | TTL for the per-tenant risk-weights cache. |

### Maintenance jobs (leader-elected)

These only run on whichever gateway instance wins the SQLite advisory-lock leader election (safe with multiple replicas sharing one DB — though see §6 on why multiple replicas aren't currently recommended).

| Variable | Default | Description |
| --- | --- | --- |
| `AEGIS_LEADER_ELECTION_INTERVAL_SECS` | `5` | Leader-election tick interval. |
| `AEGIS_LEADER_LEASE_SECS` | `20` | Leader lease duration. |
| `AEGIS_AUDIT_ARCHIVAL_INTERVAL_SECS` | `86400` | How often old `audit_events` rows move to the archive table. |
| `AEGIS_AUDIT_RETENTION_DAYS` | `90` | Live-table retention before archival. |
| `AEGIS_APPROVAL_CLEANUP_INTERVAL_SECS` | `86400` | How often stale approvals are deleted. |
| `AEGIS_APPROVAL_RETENTION_DAYS` | `30` | Approval retention before cleanup. |
| `AEGIS_VACUUM_INTERVAL_SECS` | `86400` | `VACUUM` interval (reclaims space from the deletes above). |
| `AEGIS_RECEIPT_INTEGRITY_INTERVAL_SECS` | `3600` | Receipt-chain integrity check interval. |
| `AEGIS_POOL_HEALTH_SAMPLE_INTERVAL_SECS` | `30` | DB pool acquire-latency sampling interval. |
| `AEGIS_HEARTBEAT_FLUSH_INTERVAL_SECS` | `30` | Agent `last_seen_at` heartbeat flush interval. |
| `AEGIS_AUDIT_BATCH_SIZE` | `100` | Rows buffered before a batched `audit_events` flush. |
| `AEGIS_AUDIT_BATCH_FLUSH_MS` | `500` | Max time before a partial batch flushes anyway. |
| `AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS` | `3600` | SOC incident-correlation dedup window. |
| `AEGIS_SOC_AUTONOMY_LEVEL` | unset | Per-tenant SOC response autonomy override. |
| `AEGIS_BACKUP_DIR` | `backups` | Directory for `POST /v1/admin/backup` output. |
| `AEGIS_DRAIN_TIMEOUT_SECS` | `10` | Graceful-shutdown drain timeout for the in-flight event sink. |
| `AEGIS_DEFERRED_WRITE_DRAIN_TIMEOUT_SECS` | `5` | Graceful-shutdown drain timeout for fire-and-forget background writes (best-effort; a slow drain doesn't hold up shutdown indefinitely). |
| `AEGIS_RECEIPT_SIGNING_KEY` | unset | Optional signing key for receipt signatures. |
| `AEGIS_NARRATOR` | unset | Enables Claude-backed SOC incident narration when set. |

> For the full, always-current source of truth, grep `AEGIS_` in `src/src/main.rs` and `lib/` — this table is maintained by hand and may lag a brand-new env var by one release.

## 5. Production checklist

- [ ] **TLS**: set `AEGIS_TLS_CERT`/`AEGIS_TLS_KEY`, or terminate TLS at a reverse proxy / Kubernetes ingress in front of the gateway. Plain HTTP is fine for `127.0.0.1`-bound local dev only.
- [ ] **Secrets**: set `AEGIS_JWT_REQUIRED=true` with a real `AEGIS_JWT_SECRET` (not `default_secret`) before exposing the gateway beyond localhost. Set `AEGIS_POLICY_SIGNING_KEY` if you intend to use signed policy bundles. Never commit secret values — use your platform's secret store (Kubernetes `Secret`, systemd `EnvironmentFile`, etc.).
- [ ] **Database encryption at rest**: if required by your compliance posture, build with `--features sqlcipher` and set `AEGIS_DB_ENCRYPTION_KEY` — the gateway fails closed at startup if the key is set without the matching build feature.
- [ ] **Monitoring**: point `AEGIS_OTLP_ENDPOINT` at your collector for traces + metrics, or scrape `/metrics` (Prometheus text) directly — bound on the same listener, not separately exposed. Wire up the Helm chart's `ServiceMonitor` if you run prometheus-operator.
- [ ] **Health probes**: `/livez`, `/readyz`, `/startupz` are already wired into the Helm chart's Deployment; if deploying elsewhere, point your orchestrator's liveness/readiness checks at them directly rather than `/health` (which does a DB round-trip and is heavier).
- [ ] **Backups**: schedule `POST /v1/admin/backup`, which writes a consistent point-in-time copy via SQLite's `VACUUM INTO` (safe against a live database, no downtime) into `AEGIS_BACKUP_DIR`. See [Runbook: Backup and Restore](runbooks/backup-and-restore.md) for the restore procedure — there is no restore API, only a documented manual procedure.
- [ ] **CORS**: leave `AEGIS_CORS_ORIGINS` unset (no CORS headers) unless a browser-based dashboard or client genuinely needs cross-origin access; set it to an explicit allowlist, never a wildcard, if you do.
- [ ] **Rate limits & quotas**: the defaults (`AEGIS_RATE_LIMIT_CAPACITY=100`, refill `10`/s) are tuned for development. Size them per-agent based on your actual expected call volume before going live.

## 6. Capacity planning

Don't size for "N agents" or "M events/sec" in the abstract — size for the one thing that actually bottlenecks `/v1/authorize`: **SQLite's single-writer serialization**, measured in [`docs/performance-baseline.md`](performance-baseline.md#sustained-throughput-load-test-1398):

| Constant-rate load | Sustained throughput | p50 | p95 | p99 | Errors |
| --- | --- | --- | --- | --- | --- |
| 100 req/s offered | 92 req/s | 3.2 ms | 4.0 ms | 5.7 ms | 0 |
| 150 req/s offered | 128 req/s | 3.0 ms | 4.0 ms | 5.4 ms | 1 (0.01%) |
| 200 req/s offered | 141 req/s | 3.1 ms | 4.6 ms | 9.6 ms | 1 (0.01%) |
| 1,000 req/s offered | 364 req/s | 5.0 s | 26.6 s | 29.9 s | 30,701 (51%) |

**Practical reading**: on hardware comparable to the benchmark (Intel Xeon Gold 6230R, 15 GiB RAM), a single gateway instance sustains **~130–150 `/v1/authorize` req/s** with excellent latency. Past that, requests queue behind SQLite's write lock faster than the two synchronous writes per request (`decisions` + `audit_events`) can drain, and latency falls off a cliff rather than degrading gracefully — plan capacity with headroom below that ceiling, not up to it.

This is a property of the storage backend, not of CPU/memory/replica count — adding more gateway replicas in front of the *same* SQLite file does not raise this ceiling (they'd all serialize on the same WAL writer lock), which is why the Helm chart defaults to `replicaCount: 1`. If your expected load is within the ~100 req/s range, a single instance sized at the chart's default `resources` (100m/128Mi requests, 500m/512Mi limits) is sufficient headroom. If you need materially more throughput, the PostgreSQL backend (#1194) is the tracked path to MVCC-based concurrent writers and is the right point to revisit both `replicaCount` and the HPA — not before.
