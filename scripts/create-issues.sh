#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# create-issues.sh — Batch-create Kubernetes-grade GitHub issues for AegisAgent
# ──────────────────────────────────────────────────────────────────────────────
#
# Usage:  bash scripts/create-issues.sh
#
# Creates 81 issues across 12 categories. Each issue gets:
#   - A descriptive title with category prefix
#   - Labels for category, priority, and component
#   - Full description with context, rationale, and acceptance criteria
#
# Requires: gh CLI authenticated (gh auth login)
# Rate limit: 1-second delay between issues to avoid GitHub API throttling
#
set -euo pipefail

REPO="lavkushry/AegisAgent"
CREATED=0
FAILED=0
LOG="scripts/issues-created.log"

: > "$LOG"  # truncate log

create_issue() {
  local title="$1"
  local labels="$2"
  local body="$3"

  echo "Creating: $title"
  local result
  if result=$(gh issue create \
    --repo "$REPO" \
    --title "$title" \
    --label "$labels" \
    --body "$body" 2>&1); then
    echo "  ✅ $result"
    echo "$result | $title" >> "$LOG"
    CREATED=$((CREATED + 1))
  else
    echo "  ❌ FAILED: $result"
    echo "FAILED | $title | $result" >> "$LOG"
    FAILED=$((FAILED + 1))
  fi
  sleep 1  # rate-limit
}

# First, ensure required labels exist via the API
echo "=== Creating labels (if missing) ==="
for label_spec in \
  "priority/P0:B60205:Security-critical, fix immediately" \
  "priority/P1:FF9900:High priority, blocks production" \
  "priority/P2:FBCA04:Medium priority, needed for robustness" \
  "priority/P3:0E8A16:Low priority, polish" \
  "bug:D73A4A:Something isn't working" \
  "security:B60205:Security vulnerability or hardening" \
  "enhancement:A2EEEF:New feature or improvement" \
  "reliability:C5DEF5:Reliability and resilience" \
  "observability:BFD4F2:Metrics, logging, tracing" \
  "testing:BFDADC:Test coverage and quality" \
  "ci:E4E669:CI/CD pipeline" \
  "sdk-python:3572A5:Python SDK" \
  "sdk-typescript:2B7489:TypeScript SDK" \
  "soc:7057FF:SOC Plane" \
  "database:006B75:Database and migrations" \
  "documentation:0075CA:Documentation" \
  "api:1D76DB:API design and hardening" \
  "developer-experience:C2E0C6:Developer experience" \
  "production:5319E7:Production readiness" \
  "compliance:EDEDED:Compliance and audit" \
  "performance:F9D0C4:Performance optimization" \
  "tenant-isolation:B60205:Multi-tenant isolation"; do
  IFS=':' read -r name color desc <<< "$label_spec"
  gh api repos/"$REPO"/labels \
    --method POST \
    --field "name=$name" \
    --field "color=$color" \
    --field "description=$desc" \
    --silent 2>/dev/null || true
done
echo "Labels ready."
echo ""

echo "=== Creating 81 Issues ==="
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 1: SECURITY CRITICAL (P0 + P1)
# ─────────────────────────────────────────────────────────────────────────────

echo "── Security Critical ──"

create_issue \
  "[BUG-001] JWT secret defaults to hardcoded 'default_secret' when AEGIS_JWT_SECRET unset" \
  "bug,security,priority/P0" \
  "## Bug Description

\`validate_jwt()\` in \`routes.rs:240\` falls back to \`\"default_secret\"\` when \`AEGIS_JWT_SECRET\` is not set:

\`\`\`rust
let secret = std::env::var(\"AEGIS_JWT_SECRET\").unwrap_or_else(|_| \"default_secret\".to_string());
\`\`\`

Any attacker who knows this default (it's in source code) can forge arbitrary tenant JWT tokens.

## Impact
- **Severity:** Critical
- **Attack:** Any external actor can mint valid JWTs for any tenant
- **Data at risk:** Complete tenant data exposure

## Fix
Refuse to start if \`AEGIS_JWT_SECRET\` is not set and \`AEGIS_JWT_REQUIRED=true\`, or return \`None\` (auth fails closed) when the secret is the default.

## Acceptance Criteria
- [ ] Gateway panics on startup if \`AEGIS_JWT_REQUIRED=true\` and \`AEGIS_JWT_SECRET\` is unset
- [ ] Gateway logs a WARNING on startup if using the default secret
- [ ] Unit test: JWT signed with \`default_secret\` is rejected when a real secret is configured"

create_issue \
  "[BUG-002] Tenant auth falls back to 'tenant_123' for non-JWT tokens — cross-tenant leakage" \
  "bug,security,priority/P0,tenant-isolation" \
  "## Bug Description

In \`routes.rs:299-303\`, when JWT validation fails and \`AEGIS_JWT_REQUIRED\` is not \`true\`:

\`\`\`rust
let tenant_id = if token.starts_with(\"tenant_\") {
    token.to_string()
} else {
    \"tenant_123\".to_string()  // ← ALL unauthenticated requests share this tenant
};
\`\`\`

ALL unauthenticated requests land on \`tenant_123\`, creating cross-tenant data leakage.

## Impact
- **Severity:** Critical
- **CWE:** CWE-284 (Improper Access Control)
- **Data at risk:** Any data stored under tenant_123

## Fix
Return 401 Unauthorized instead of falling back to a hardcoded tenant.

## Acceptance Criteria
- [ ] Requests with invalid JWT return 401, not 200 with tenant_123
- [ ] No hardcoded tenant_id fallback in production code
- [ ] Integration test: invalid Bearer token → 401"

create_issue \
  "[BUG-003] Missing X-Aegis-Tenant-ID header defaults to 'tenant_123' — tenant isolation bypass" \
  "bug,security,priority/P0,tenant-isolation" \
  "## Bug Description

\`get_runtime_tenant_from_headers()\` in \`routes.rs:309-317\` defaults to \`tenant_123\` when the tenant header is missing:

\`\`\`rust
.unwrap_or_else(|| \"tenant_123\".to_string())
\`\`\`

Combined with BUG-002, unauthenticated requests without headers operate on tenant_123's data.

## Fix
Return 400 Bad Request when \`X-Aegis-Tenant-ID\` is missing on endpoints that use this function, or derive tenant_id exclusively from the JWT claim.

## Acceptance Criteria
- [ ] Missing tenant header → 400 (not silent fallback)
- [ ] Tenant ID derived from JWT when available (JWT claim takes precedence)
- [ ] Test: request without tenant header returns 400"

create_issue \
  "[BUG-004] RateLimiter/QuotaManager panic on poisoned mutex" \
  "bug,reliability,priority/P1" \
  "## Bug Description

\`RateLimiter::check_rate_limit()\` and \`QuotaManager::check_quota()\` use \`lock().unwrap()\` (routes.rs:54, routes.rs:98). If any thread panics while holding the lock, all subsequent calls panic — crashing every request.

## Fix
Use \`.lock().unwrap_or_else(|e| e.into_inner())\` or switch to \`parking_lot::Mutex\` (never poisons).

## Acceptance Criteria
- [ ] No \`.lock().unwrap()\` in production (non-test) code paths
- [ ] Poisoned mutex does not crash the gateway
- [ ] Clippy custom lint to prevent future \`.lock().unwrap()\` usage"

create_issue \
  "[BUG-005] PolicyEngine RwLock panics on poison — blocks all authorization" \
  "bug,reliability,priority/P1,security" \
  "## Bug Description

\`PolicyEngine\` uses \`RwLock::read().unwrap()\` / \`write().unwrap()\` in \`policy.rs:42,57,86,102-108\`. A panic during Cedar evaluation poisons the lock, making every subsequent \`authorize()\` call panic. The gateway becomes completely unusable.

## Fix
Switch to \`parking_lot::RwLock\` (never poisons) or handle poisoned locks with \`.unwrap_or_else()\`.

## Acceptance Criteria
- [ ] No \`RwLock::unwrap()\` in production code
- [ ] Gateway continues to serve after a Cedar evaluation panic
- [ ] Test: simulated panic in policy evaluation → gateway recovers"

create_issue \
  "[SEC-001] ensure_tenant_exists auto-creates tenants on any request" \
  "security,priority/P1,tenant-isolation" \
  "## Security Issue

\`ensure_tenant_exists()\` in \`routes.rs:319-324\` auto-creates a tenant row with plan \`developer\` for ANY request with a new tenant ID. An attacker can create thousands of phantom tenants.

## Fix
Remove auto-creation. Require explicit tenant provisioning via \`POST /v1/tenants\` (admin-only). Reject requests for non-existent tenants with 404.

## Acceptance Criteria
- [ ] Requests for non-existent tenants return 404
- [ ] Tenants can only be created via the admin endpoint
- [ ] Test: request with unknown tenant_id → 404 (not auto-created)"

create_issue \
  "[SEC-002] Agent tokens stored in plaintext in SQLite" \
  "security,priority/P1,database" \
  "## Security Issue

\`agent_token\` is stored as cleartext in the \`agents\` table. A database file exfiltration exposes all agent credentials. Kubernetes stores all secrets encrypted at rest.

## Fix
Store \`SHA-256(agent_token)\` and compare hashes on lookup. Return the raw token only on initial registration (show-once pattern). Alternatively, integrate with a secrets manager.

## Acceptance Criteria
- [ ] \`agent_token\` column stores a hash, not cleartext
- [ ] Token is returned in cleartext only on \`POST /v1/agents/register\` response
- [ ] Existing tokens migrated on next startup
- [ ] Test: reading agent record does not reveal the raw token"

create_issue \
  "[SEC-003] Webhook notifications not signed — receiver cannot verify authenticity" \
  "security,priority/P2,soc" \
  "## Security Issue

\`WebhookSink::notify()\` POSTs to the webhook URL without any signature. The receiver cannot verify the message came from AegisAgent (spoofable).

## Fix
Add HMAC-SHA256 signing: \`X-Aegis-Signature: sha256=<hmac>\` header using a configurable \`AEGIS_WEBHOOK_SECRET\` env var. Same pattern as GitHub/Slack webhook signatures.

## Acceptance Criteria
- [ ] Webhook POSTs include \`X-Aegis-Signature\` header when \`AEGIS_WEBHOOK_SECRET\` is set
- [ ] Signature is HMAC-SHA256 over the raw JSON body
- [ ] Test: signature verification round-trip"

create_issue \
  "[SEC-004] Log redaction misses secrets in nested JSON and URL query parameters" \
  "security,priority/P1" \
  "## Security Issue

\`redact_secrets()\` in \`main.rs\` uses character-by-character scanning for \`Bearer\`, \`agent_token\`, and \`api_key\`. It misses:
- Secrets in URL query parameters (\`?token=xxx\`)
- Secrets in deeply nested JSON
- Other secret patterns (\`password\`, \`secret_key\`, \`authorization\`)

## Fix
Expand the redaction patterns and consider using a structured approach (parse JSON, redact known fields) rather than regex-on-string.

## Acceptance Criteria
- [ ] \`password\`, \`secret_key\`, \`client_secret\` patterns also redacted
- [ ] URL query parameter values for sensitive keys are redacted
- [ ] Tests for each new pattern"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 2: API HARDENING
# ─────────────────────────────────────────────────────────────────────────────

echo "── API Hardening ──"

create_issue \
  "[API-001] Implement API versioning strategy (v1 → v2 migration path)" \
  "enhancement,api,priority/P1" \
  "## Feature Request

Kubernetes has a strict alpha → beta → stable API versioning. AegisAgent has only \`/v1/\`. We need:

1. API versioning strategy document
2. Deprecation headers (\`Sunset\`, \`Deprecation\`)
3. Content negotiation (\`Accept: application/vnd.aegis.v2+json\`)
4. Version-specific routing infrastructure

## Acceptance Criteria
- [ ] Versioning strategy documented in \`docs/api-versioning.md\`
- [ ] Deprecated endpoints return \`Sunset\` header
- [ ] Router supports \`/v2/\` prefix alongside \`/v1/\`"

create_issue \
  "[API-002] Add ETag/If-None-Match caching for GET endpoints" \
  "enhancement,api,performance,priority/P2" \
  "## Feature Request

All GET endpoints re-query the DB on every request. Add ETag-based conditional responses for frequently polled endpoints: \`/v1/alerts\`, \`/v1/incidents\`, \`/v1/soc/summary\`, \`/v1/agents\`.

## Acceptance Criteria
- [ ] GET responses include \`ETag\` header (hash of response body)
- [ ] Requests with matching \`If-None-Match\` return 304 Not Modified
- [ ] Bandwidth savings measurable in benchmarks"

create_issue \
  "[API-003] Implement cursor-based pagination for all list endpoints" \
  "enhancement,api,priority/P2" \
  "## Feature Request

Current LIMIT/OFFSET pagination degrades at high offsets. Implement Kubernetes-style cursor-based pagination with \`continue\` tokens for: \`/v1/decisions\`, \`/v1/receipts\`, \`/v1/audit/events\`, \`/v1/alerts\`, \`/v1/incidents\`.

## Acceptance Criteria
- [ ] List endpoints accept \`?cursor=<token>\` parameter
- [ ] Response includes \`next_cursor\` field when more results exist
- [ ] Performance is constant regardless of offset depth
- [ ] Backwards-compatible (LIMIT/OFFSET still works)"

create_issue \
  "[API-004] Add admission webhooks — pluggable pre-authorize hooks" \
  "enhancement,api,priority/P2" \
  "## Feature Request

Kubernetes has MutatingAdmissionWebhook and ValidatingAdmissionWebhook. AegisAgent should support optional pre-authorize webhooks allowing external systems to mutate or reject requests before Cedar evaluation.

## Acceptance Criteria
- [ ] \`AEGIS_ADMISSION_WEBHOOK_URL\` env var for the webhook endpoint
- [ ] Pre-authorize webhook called with the AuthorizeRequest body
- [ ] Webhook can return: pass, reject (with reason), or mutate (modify parameters)
- [ ] Timeout: 5s, fail-open configurable to fail-closed"

create_issue \
  "[API-005] Standardize error response format across all endpoints" \
  "enhancement,api,priority/P2,developer-experience" \
  "## Feature Request

Error responses are inconsistent (\`{\"error\": \"...\"}\` vs structured). Adopt a Kubernetes-style structured error response:

\`\`\`json
{
  \"kind\": \"Status\",
  \"apiVersion\": \"v1\",
  \"status\": \"Failure\",
  \"message\": \"agent not found\",
  \"reason\": \"NotFound\",
  \"details\": {\"name\": \"agent-123\"},
  \"code\": 404
}
\`\`\`

## Acceptance Criteria
- [ ] All error responses follow the standard format
- [ ] Error reasons are from a defined enum (NotFound, Unauthorized, Forbidden, Conflict, etc.)
- [ ] OpenAPI spec updated with error response schemas"

create_issue \
  "[API-006] Add field-based filtering (fieldSelector) for list endpoints" \
  "enhancement,api,priority/P3" \
  "## Feature Request

Add Kubernetes-style field-based filtering: \`GET /v1/agents?status=active\`, \`GET /v1/incidents?kind=deny_storm&severity=high\`, \`GET /v1/decisions?decision=deny\`.

## Acceptance Criteria
- [ ] List endpoints support query parameter filtering
- [ ] Filters are SQL-parameterized (no injection)
- [ ] Invalid filter fields return 400 with list of valid fields"

create_issue \
  "[API-007] Add watch mode for list endpoints (Server-Sent Events)" \
  "enhancement,api,priority/P3" \
  "## Feature Request

Kubernetes has \`?watch=true\` for streaming updates. Add \`?watch=true\` on \`/v1/alerts\` and \`/v1/incidents\` using SSE as a REST alternative to the WebSocket stream.

## Acceptance Criteria
- [ ] \`GET /v1/alerts?watch=true\` streams new alerts as SSE events
- [ ] \`Content-Type: text/event-stream\` response
- [ ] Connection kept alive with heartbeat pings"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 3: RELIABILITY & RESILIENCE
# ─────────────────────────────────────────────────────────────────────────────

echo "── Reliability & Resilience ──"

create_issue \
  "[REL-001] Add circuit breaker for webhook notifications" \
  "enhancement,reliability,priority/P1,soc" \
  "## Feature Request

If the Slack webhook is consistently failing, each event still spawns a task that times out after 5s. Under load, this creates thousands of zombie tasks.

## Fix
Add a circuit breaker pattern: trip after N consecutive failures (default 5), enter half-open after cooldown (default 60s), close on first success.

## Acceptance Criteria
- [ ] Circuit breaker trips after configurable consecutive failures
- [ ] Tripped circuit rejects immediately (no task spawn)
- [ ] Half-open state allows one probe request
- [ ] Prometheus counter: \`aegis_webhook_circuit_breaker_trips_total\`"

create_issue \
  "[REL-002] Graceful shutdown must drain the SOC event channel" \
  "bug,reliability,priority/P1" \
  "## Bug Description

On SIGTERM, the gateway shuts down HTTP but the \`events::drain\` task is not explicitly awaited. Events in the mpsc channel may be lost (data loss).

## Fix
On shutdown signal:
1. Close the sender half of the mpsc channel
2. Await the drain task until the channel is empty (with 10s timeout)
3. Log the number of events drained during shutdown

## Acceptance Criteria
- [ ] Graceful shutdown drains remaining events from the channel
- [ ] Drain has a configurable timeout (default 10s)
- [ ] Log message: \"Drained N events during shutdown\"
- [ ] Test: events emitted before shutdown are persisted"

create_issue \
  "[REL-003] Add leader election for background jobs (multi-instance safety)" \
  "enhancement,reliability,priority/P2" \
  "## Feature Request

Running multiple gateway instances means multiple background jobs (receipt integrity, audit archival, approval cleanup) compete on the same DB rows.

## Fix
Add SQLite advisory lock-based leader election. Only the leader instance runs background jobs. On leader failure, another instance acquires the lock.

## Acceptance Criteria
- [ ] Only one instance runs background jobs at a time
- [ ] Leadership is acquired via SQLite advisory lock
- [ ] Leadership transfer on instance failure within 30s
- [ ] Non-leader instances log \"standby\" status"

create_issue \
  "[REL-004] Add connection pool exhaustion monitoring and alerts" \
  "enhancement,reliability,observability,priority/P2" \
  "## Feature Request

The SQLite pool has fixed \`max_connections=5\`. Under burst load, requests fail silently. Add Prometheus metrics for pool health.

## Acceptance Criteria
- [ ] Metrics: \`db_pool_connections_active\`, \`db_pool_connections_idle\`, \`db_pool_acquire_wait_seconds\`
- [ ] Alert threshold: log warning when >80% connections busy
- [ ] Exposed on \`GET /metrics\`"

create_issue \
  "[REL-005] Add retry with exponential backoff for transient DB errors" \
  "enhancement,reliability,database,priority/P2" \
  "## Feature Request

Transient \`SQLITE_BUSY\` errors under write contention can fail a request. Add a retry wrapper with exponential backoff for write operations.

## Acceptance Criteria
- [ ] Write operations retry up to 3 times on SQLITE_BUSY
- [ ] Backoff: 1ms → 2ms → 4ms (configurable)
- [ ] Retry attempts logged at DEBUG level
- [ ] Non-retryable errors propagate immediately"

create_issue \
  "[REL-006] Add liveness checks for background tasks (drain, jobs)" \
  "enhancement,reliability,priority/P2" \
  "## Feature Request

\`/health\` only checks DB connectivity. If the drain task panics or a background job deadlocks, the gateway reports healthy but is partially broken.

## Acceptance Criteria
- [ ] Add \`/livez\` endpoint that checks: drain task alive, background jobs alive
- [ ] Add \`/readyz\` endpoint that checks: DB connected, migrations applied
- [ ] Failed liveness → 503 with details of which component is unhealthy"

create_issue \
  "[REL-007] Add CatchPanic Tower layer for handler panic recovery" \
  "enhancement,reliability,priority/P2" \
  "## Feature Request

An unhandled panic in an Axum handler drops the connection. Add Tower's CatchPanic layer so panics return 500 with a structured error instead of dropping the TCP connection.

## Acceptance Criteria
- [ ] Handler panics return 500 JSON response (not connection drop)
- [ ] Panic backtrace logged at ERROR level
- [ ] Prometheus counter: \`aegis_handler_panics_total\`"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 4: OBSERVABILITY & MONITORING
# ─────────────────────────────────────────────────────────────────────────────

echo "── Observability & Monitoring ──"

create_issue \
  "[OBS-001] Add Prometheus histogram for authorize latency (p50/p95/p99)" \
  "enhancement,observability,priority/P1" \
  "## Feature Request

\`latency_ms\` is stored per-decision but not exposed as a Prometheus metric. Add \`aegis_authorize_duration_seconds\` histogram for Grafana dashboards.

## Acceptance Criteria
- [ ] \`aegis_authorize_duration_seconds\` histogram exposed on \`/metrics\`
- [ ] Buckets: 5ms, 10ms, 25ms, 50ms, 75ms, 100ms, 250ms, 500ms, 1s
- [ ] Grafana dashboard JSON template included"

create_issue \
  "[OBS-002] Add counter metrics for decisions, alerts, and incidents" \
  "enhancement,observability,priority/P1" \
  "## Feature Request

Only 2 security counters are exposed. Add comprehensive counters:
- \`aegis_decisions_total{decision=\"allow|deny|require_approval\"}\`
- \`aegis_alerts_total{rule=\"...\", severity=\"...\"}\`
- \`aegis_incidents_total{kind=\"...\"}\`
- \`aegis_events_emitted_total\`
- \`aegis_events_dropped_total\`

## Acceptance Criteria
- [ ] All counters exposed on \`/metrics\` in Prometheus format
- [ ] Labels are safe (no tenant/agent PII)
- [ ] Counters survive hot-path performance budget (<75ms)"

create_issue \
  "[OBS-003] Add distributed tracing with OpenTelemetry" \
  "enhancement,observability,priority/P2" \
  "## Feature Request

Add \`tracing-opentelemetry\` spans for: authorize evaluation, Cedar policy check, DB query, receipt hash computation, approval creation. Export via OTLP.

## Acceptance Criteria
- [ ] \`AEGIS_OTLP_ENDPOINT\` env var to enable OTel export
- [ ] Spans: \`authorize\`, \`cedar_evaluate\`, \`db_query\`, \`receipt_hash\`, \`approval_create\`
- [ ] Trace ID propagated from SDK via \`traceparent\` header"

create_issue \
  "[OBS-004] Add audit trail for admin operations (freeze, quarantine, delete)" \
  "enhancement,observability,compliance,priority/P2" \
  "## Feature Request

Admin operations (freeze_agent, quarantine_server, close_incident, delete_tenant) are not logged to the audit trail. Kubernetes logs all admin actions.

## Acceptance Criteria
- [ ] Every state-changing admin endpoint emits an \`admin_action\` audit event
- [ ] Audit event includes: who (operator ID), what (action), when, target
- [ ] Admin audit events appear in \`GET /v1/audit/events?event_type=admin_action\`"

create_issue \
  "[OBS-005] Add SOC metrics: MTTD (mean-time-to-detect) and MTTR (mean-time-to-respond)" \
  "enhancement,observability,soc,priority/P2" \
  "## Feature Request

Track: time from event occurrence to alert creation (MTTD), time from incident open to incident close (MTTR). Expose as Prometheus gauges.

## Acceptance Criteria
- [ ] \`aegis_soc_mttd_seconds\` gauge (rolling average)
- [ ] \`aegis_soc_mttr_seconds\` gauge (rolling average)
- [ ] Values computed from actual alert/incident timestamps"

create_issue \
  "[OBS-006] Emit audit events for configuration changes" \
  "enhancement,observability,priority/P2" \
  "## Feature Request

Policy reloads, Cedar file changes, and env var changes are not tracked. Add \`config_change\` events to the audit trail.

## Acceptance Criteria
- [ ] \`POST /v1/policies/reload\` emits a \`config_change\` audit event
- [ ] \`POST /v1/policies\` emits a \`policy_created\` audit event
- [ ] Configuration change events include before/after state where safe"

create_issue \
  "[OBS-007] Add Tokio runtime metrics endpoint (/debug/runtime)" \
  "enhancement,observability,performance,priority/P3" \
  "## Feature Request

Kubernetes exposes /debug/pprof. Add Tokio runtime metrics (active tasks, task poll count, scheduler idle time) via \`tokio-metrics\` crate.

## Acceptance Criteria
- [ ] \`GET /debug/runtime\` returns Tokio runtime stats (JSON)
- [ ] Only accessible on 127.0.0.1 (same as /metrics)
- [ ] Includes: active task count, total polls, scheduler utilization"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 5: TESTING MATURITY
# ─────────────────────────────────────────────────────────────────────────────

echo "── Testing Maturity ──"

create_issue \
  "[TEST-001] Add end-to-end integration test for full SOC pipeline" \
  "testing,soc,priority/P1" \
  "## Feature Request

Each SOC phase is unit-tested in isolation, but no test verifies the full pipeline: authorize → AseEvent → detector → correlator → alert persisted → incident persisted → notification sent.

## Acceptance Criteria
- [ ] Single test exercises: emit event → detect → correlate → persist → notify
- [ ] Verify alert appears in \`soc_alerts\` table
- [ ] Verify incident appears in \`soc_incidents\` table
- [ ] Verify notification was dispatched (mock sink)"

create_issue \
  "[TEST-002] Add fuzz testing for canonicalize_json and canonical_action_string" \
  "testing,security,priority/P1" \
  "## Feature Request

The canonicalization scheme is the foundation of the fail-closed guarantee. Fuzz it to find edge cases.

## Acceptance Criteria
- [ ] \`cargo-fuzz\` target for \`canonicalize_json\` with arbitrary JSON input
- [ ] \`cargo-fuzz\` target for \`canonical_action_string\` with arbitrary AuthorizeToolCall
- [ ] Run for minimum 1 hour in CI without crashes
- [ ] Any found edge cases added as regression tests"

create_issue \
  "[TEST-003] Add property-based tests for receipt chain integrity" \
  "testing,priority/P2" \
  "## Feature Request

Use \`proptest\` to generate random receipt chains and verify: every valid chain passes verification, and every tampered chain fails.

## Acceptance Criteria
- [ ] Property: ∀ chain: verify_chain(build(chain)) == Ok
- [ ] Property: ∀ tampered: verify_chain(tamper(chain)) == Err
- [ ] Minimum 1000 cases per property"

create_issue \
  "[TEST-004] Add chaos/fault-injection tests for DB failures" \
  "testing,reliability,priority/P2" \
  "## Feature Request

Verify the gateway degrades gracefully when: DB unreachable, DB read-only, pool exhausted, WAL corrupted.

## Acceptance Criteria
- [ ] Test: DB unreachable → /health returns 503, authorize returns 500
- [ ] Test: pool exhausted → requests timeout gracefully (not panic)
- [ ] Test: corrupted WAL → gateway detects and logs error"

create_issue \
  "[TEST-005] Add load test framework (k6 / criterion benchmarks)" \
  "testing,performance,priority/P2" \
  "## Feature Request

Establish baseline performance: target p50 <10ms, p99 <75ms for /v1/authorize.

## Acceptance Criteria
- [ ] \`cargo bench\` (criterion) for canonicalization and receipt hashing
- [ ] k6 or vegeta script for HTTP load testing
- [ ] Baseline recorded in \`docs/performance-baseline.md\`
- [ ] CI fails if p99 regresses by >20%"

create_issue \
  "[TEST-006] Add mutation testing to measure test quality" \
  "testing,priority/P3" \
  "## Feature Request

Use \`cargo-mutants\` to measure mutation test coverage. Target >80% kill rate on security-critical modules.

## Acceptance Criteria
- [ ] \`cargo-mutants\` configured for \`detect.rs\`, \`correlate.rs\`, \`policy.rs\`, \`sign.rs\`
- [ ] Mutation kill rate >80% on each module
- [ ] Results tracked in CI (informational, not blocking)"

create_issue \
  "[TEST-007] Add cross-tenant isolation stress test" \
  "testing,security,tenant-isolation,priority/P1" \
  "## Feature Request

Create 100 tenants concurrently, each with agents, decisions, approvals, and receipts. Verify no tenant can read another's data through any API endpoint.

## Acceptance Criteria
- [ ] 100 tenants created in parallel
- [ ] Each tenant's data is only visible to that tenant
- [ ] All list endpoints tested for cross-tenant leakage
- [ ] Test runs in CI on every PR"

create_issue \
  "[TEST-008] Add approval race condition stress test (50 concurrent consumes)" \
  "testing,priority/P2" \
  "## Feature Request

50 concurrent \`consume_approval\` calls for the same approval_id. Exactly one must succeed, 49 must fail. Verify receipt chain is not forked.

## Acceptance Criteria
- [ ] 50 concurrent consume requests
- [ ] Exactly 1 returns 200
- [ ] 49 return 409 Conflict
- [ ] Receipt chain has exactly 1 new entry (no fork)"

create_issue \
  "[TEST-009] Add WebSocket live stream integration test" \
  "testing,soc,priority/P2" \
  "## Feature Request

Connect a WebSocket client, trigger authorize events, verify events arrive on the stream with correct tenant scoping.

## Acceptance Criteria
- [ ] WebSocket client connects to \`/v1/ws/events\`
- [ ] Authorize events appear on the stream within 100ms
- [ ] Tenant A client does NOT see tenant B events"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 6: CI/CD PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

echo "── CI/CD Pipeline ──"

create_issue \
  "[CI-001] Make cargo audit a blocking CI check (not continue-on-error)" \
  "ci,security,priority/P1" \
  "## Bug/Enhancement

\`ci.yml:193\` has \`continue-on-error: true\` and \`cargo audit || true\`. Known CVEs pass silently.

## Fix
Make \`cargo audit\` blocking. Use \`--ignore RUSTSEC-XXXX\` only for explicitly acknowledged advisories.

## Acceptance Criteria
- [ ] \`cargo audit\` failure blocks the CI
- [ ] \`pip-audit\` failure blocks the CI
- [ ] Known false positives documented and \`--ignore\`d"

create_issue \
  "[CI-002] Add SAST scanning (semgrep / custom clippy rules)" \
  "ci,security,priority/P1" \
  "## Feature Request

Add static analysis for: SQL injection (raw string SQL), hardcoded secrets, unsafe unwrap in production code, unredacted logging.

## Acceptance Criteria
- [ ] semgrep or equivalent runs on every PR
- [ ] Custom rules for AegisAgent security patterns
- [ ] Blocking on high-severity findings"

create_issue \
  "[CI-003] Add SBOM generation and container image signing (cosign)" \
  "ci,compliance,priority/P2" \
  "## Feature Request

Kubernetes signs every release artifact. Add \`syft\` for SBOM, \`cosign\` for container image signing, SLSA provenance attestation.

## Acceptance Criteria
- [ ] SBOM generated on every release (SPDX format)
- [ ] Docker image signed with cosign
- [ ] SLSA Level 2+ provenance attestation"

create_issue \
  "[CI-004] Add code coverage gate (minimum threshold)" \
  "ci,testing,priority/P2" \
  "## Feature Request

Add coverage tracking with a minimum threshold. Fail CI if coverage drops.

## Acceptance Criteria
- [ ] \`cargo-llvm-cov\` or \`tarpaulin\` for Rust (threshold: 70%)
- [ ] \`coverage.py\` for Python SDK (threshold: 75%)
- [ ] Coverage report in PR comments"

create_issue \
  "[CI-005] Add dependency license checker (cargo-deny)" \
  "ci,compliance,priority/P2" \
  "## Feature Request

Block GPL and other incompatible licenses from entering the dependency tree.

## Acceptance Criteria
- [ ] \`cargo-deny\` configured in \`deny.toml\`
- [ ] Disallowed licenses: GPL, AGPL
- [ ] Blocking in CI on violations"

create_issue \
  "[CI-006] Add release automation (semantic versioning + changelog)" \
  "ci,priority/P3" \
  "## Feature Request

Add \`release-please\` or \`conventional-commits\` for automatic changelog generation, version bumps, and GitHub Releases.

## Acceptance Criteria
- [ ] Commits follow conventional-commits format
- [ ] Changelog auto-generated from commit messages
- [ ] GitHub Release created automatically on version bump"

create_issue \
  "[CI-007] Add container image vulnerability scanning (Trivy)" \
  "ci,security,priority/P2" \
  "## Feature Request

Scan the gateway Docker image for OS-level and library CVEs on every build.

## Acceptance Criteria
- [ ] Trivy or Grype scan on every Docker build
- [ ] Critical/High findings block merge
- [ ] Scan results uploaded as GitHub Security Advisory"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 7: SDK COMPLETENESS
# ─────────────────────────────────────────────────────────────────────────────

echo "── SDK Completeness ──"

create_issue \
  "[SDK-001] Add list_alerts() and list_incidents() to Python SDK" \
  "enhancement,sdk-python,soc,priority/P1" \
  "## Feature Request

The gateway has \`GET /v1/alerts\` and \`GET /v1/incidents\` but the Python SDK has no methods to call them. SOC automation scripts need these.

## Acceptance Criteria
- [ ] \`client.list_alerts(limit, offset, severity, rule)\` → list
- [ ] \`client.list_incidents(limit, offset, kind, status)\` → list
- [ ] Both sync and async client versions
- [ ] Unit tests with mocked responses"

create_issue \
  "[SDK-002] Add get_soc_summary() to Python SDK" \
  "enhancement,sdk-python,soc,priority/P2" \
  "## Feature Request

\`GET /v1/soc/summary\` returns aggregate counts. Expose as \`client.get_soc_summary()\`.

## Acceptance Criteria
- [ ] \`client.get_soc_summary()\` returns SocSummary dict
- [ ] Both sync and async versions
- [ ] Unit test with mocked response"

create_issue \
  "[SDK-003] Add close_incident() and narrate_incident() to Python SDK" \
  "enhancement,sdk-python,soc,priority/P2" \
  "## Feature Request

Expose \`POST /v1/incidents/:id/close\` and \`GET /v1/incidents/:id/narrate\` in the Python SDK.

## Acceptance Criteria
- [ ] \`client.close_incident(incident_id)\` → bool
- [ ] \`client.narrate_incident(incident_id)\` → str (RCA narrative)
- [ ] Both sync and async versions"

create_issue \
  "[SDK-004] Add @async_protect_tool decorator for asyncio frameworks" \
  "enhancement,sdk-python,priority/P2" \
  "## Feature Request

\`@protect_tool\` is synchronous. Add \`@async_protect_tool\` for async frameworks (FastAPI, asyncio agents).

## Acceptance Criteria
- [ ] \`@async_protect_tool\` decorator for async functions
- [ ] Uses AsyncAegisClient internally
- [ ] Same fail-closed guarantee as sync version
- [ ] Tests with asyncio event loop"

create_issue \
  "[SDK-005] Add exponential backoff to approval polling" \
  "enhancement,sdk-python,reliability,priority/P2" \
  "## Feature Request

Approval polling currently uses a fixed interval. Add exponential backoff: 2s → 4s → 8s → 16s → 30s cap.

## Acceptance Criteria
- [ ] Backoff starts at 2s, doubles each iteration, caps at 30s
- [ ] Configurable via \`poll_backoff_factor\` parameter
- [ ] Total timeout still configurable (default 5 minutes)"

create_issue \
  "[SDK-006] TypeScript SDK: add client methods parity with Python SDK" \
  "enhancement,sdk-typescript,priority/P2" \
  "## Feature Request

The TS SDK has canon corpus tests but lacks: protectTool decorator, approval polling, SOC operations, management methods.

## Acceptance Criteria
- [ ] \`AegisClient\` class with authorize, approve, reject, consume
- [ ] \`protectTool\` decorator equivalent
- [ ] SOC methods: listAlerts, listIncidents, getSocSummary
- [ ] All methods fully typed"

create_issue \
  "[SDK-007] Go SDK: add client methods parity with Python SDK" \
  "enhancement,priority/P3" \
  "## Feature Request

The Go SDK has canon corpus tests but lacks client methods. Add full client.

## Acceptance Criteria
- [ ] \`aegis.Client\` with Authorize, FreezeAgent, ListAlerts
- [ ] Context-based cancellation (Go idiomatic)
- [ ] Canon byte-parity maintained"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 8: SOC PLANE COMPLETION
# ─────────────────────────────────────────────────────────────────────────────

echo "── SOC Plane Completion ──"

create_issue \
  "[SOC-001] Implement Response Engine auto-dispatch (Phase 4 completion)" \
  "enhancement,soc,priority/P1" \
  "## Feature Request

Correlation fires incidents but nothing auto-responds. Wire:
- \`deny_storm\` → auto-freeze agent
- \`data_exfil_pattern\` → auto-freeze + critical notify
- \`trust_escalation\` → require_approval for all future actions
- \`runaway\` → throttle/freeze agent

## Implementation
New module: \`respond.rs\` — deterministic verdict → action mapping, called from \`events::drain\` after \`correlator.observe()\`.

## Acceptance Criteria
- [ ] deny_storm incident → agent frozen automatically
- [ ] data_exfil_pattern → agent frozen + critical webhook
- [ ] Response action logged as audit event
- [ ] Configurable: auto-respond can be disabled per-tenant"

create_issue \
  "[SOC-002] Add configurable SOC response autonomy levels (L0–L4)" \
  "enhancement,soc,priority/P2" \
  "## Feature Request

L0=log only, L1=notify, L2=notify+recommend, L3=auto-respond+notify, L4=auto-respond+silent. Configurable per-tenant via env or DB.

## Acceptance Criteria
- [ ] \`AEGIS_SOC_AUTONOMY_LEVEL\` env var (default L1)
- [ ] Per-tenant override via \`tenants.soc_autonomy_level\` column
- [ ] L0: only log, no notify, no auto-respond
- [ ] L3: auto-freeze on deny_storm + notify"

create_issue \
  "[SOC-003] Add YAML-driven detection rules (replace hardcoded Rust)" \
  "enhancement,soc,priority/P2" \
  "## Feature Request

Detection rules are hardcoded Rust functions. Add a YAML rule DSL loaded from DB/config so operators can add custom rules without recompiling.

## Acceptance Criteria
- [ ] \`detection_rules\` DB table (see migration issue #934)
- [ ] YAML rule format: \`condition\` (field match), \`severity\`, \`summary_template\`
- [ ] Rules loaded on startup and cacheable
- [ ] Existing hardcoded rules migrated to YAML format"

create_issue \
  "[SOC-004] Add agentless ingestion endpoint (POST /v1/ingest)" \
  "enhancement,soc,priority/P2" \
  "## Feature Request

Accept external event sources (GitHub webhooks, OpenAI traces, LangSmith spans) and normalize them into AseEvents.

## Acceptance Criteria
- [ ] \`POST /v1/ingest\` accepts generic event payloads
- [ ] Normalizers for: GitHub webhook events, OpenAI API logs
- [ ] Normalized events feed into the same detect → correlate pipeline
- [ ] Tenant-scoped, authenticated"

create_issue \
  "[SOC-005] Add incident deduplication (suppress repeat incidents for same pattern)" \
  "enhancement,soc,priority/P2" \
  "## Feature Request

If a deny_storm fires and the agent keeps denying, the correlator creates new incidents after window eviction. Merge into existing open incident instead.

## Acceptance Criteria
- [ ] On incident creation, check for existing open incident with same (tenant, agent, kind)
- [ ] If found: update source_event_ids (append), bump timestamp, do NOT create new row
- [ ] Deduplication window: configurable (default 1 hour)"

create_issue \
  "[SOC-006] Add evidence pack export (GET /v1/incidents/:id/evidence-pack)" \
  "enhancement,soc,compliance,priority/P2" \
  "## Feature Request

Bundle incident + linked alerts + linked receipts + linked audit events + RCA narrative into a downloadable ZIP for SOC 2 / EU AI Act Article 14 compliance.

## Acceptance Criteria
- [ ] \`GET /v1/incidents/:id/evidence-pack\` returns ZIP file
- [ ] Contains: incident.json, alerts.json, receipts.json, audit_events.json, rca_narrative.md
- [ ] All data tenant-scoped (no cross-tenant leakage)
- [ ] ZIP is streaming (doesn't buffer entire pack in memory)"

create_issue \
  "[SOC-007] Add behavioral baselining for agents (anomaly detection)" \
  "enhancement,soc,priority/P3" \
  "## Feature Request

Track per-agent behavioral norms (tool calls/hour, action distribution). Fire anomaly alerts when an agent deviates (Law 1 compliant: statistical threshold, not ML scoring).

## Acceptance Criteria
- [ ] Per-agent baseline computed from rolling 7-day window
- [ ] Anomaly fires when: action rate >3σ above baseline, or new tool never used before
- [ ] Deterministic threshold (no ML, no tunable weights)
- [ ] Agent baseline stored in DB, not in-memory"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 9: DATA INTEGRITY & DATABASE
# ─────────────────────────────────────────────────────────────────────────────

echo "── Data Integrity & Database ──"

create_issue \
  "[DB-001] Migrate to sqlx versioned migration system" \
  "enhancement,database,priority/P1" \
  "## Feature Request

Schema changes are inline CREATE TABLE + manual PRAGMA checks. Migrate to \`sqlx migrate\` with numbered migration files in \`gateway/migrations/\`.

## Acceptance Criteria
- [ ] All schemas moved to \`gateway/migrations/NNNNNN_description.sql\`
- [ ] \`sqlx migrate run\` replaces \`run_migrations()\`
- [ ] Migration state tracked in \`_sqlx_migrations\` table
- [ ] Existing databases upgrade seamlessly"

create_issue \
  "[DB-002] Add database encryption at rest (SQLCipher support)" \
  "enhancement,security,database,priority/P2" \
  "## Feature Request

SQLite stores data in plaintext. Add SQLCipher support behind a compile-time feature flag.

## Acceptance Criteria
- [ ] \`--features sqlcipher\` enables encrypted database
- [ ] Encryption key via \`AEGIS_DB_ENCRYPTION_KEY\` env var
- [ ] Unencrypted databases can be migrated to encrypted
- [ ] Performance impact documented"

create_issue \
  "[DB-003] Add soft-delete across all tenant-owned tables" \
  "enhancement,database,priority/P2" \
  "## Feature Request

Add \`deleted_at\` column and filter on \`deleted_at IS NULL\` in all queries. Hard deletes only via GDPR erasure endpoint.

## Acceptance Criteria
- [ ] \`deleted_at\` column added to: agents, skills, mcp_servers, policies
- [ ] All queries filter on \`deleted_at IS NULL\`
- [ ] \`DELETE\` endpoints set \`deleted_at\` instead of removing rows
- [ ] GDPR \`DELETE /v1/tenants/:id\` still does hard delete"

create_issue \
  "[DB-004] Add PostgreSQL backend support (feature flag)" \
  "enhancement,database,priority/P2" \
  "## Feature Request

SQLite limits the gateway to a single node. Add PostgreSQL support behind \`--features postgres\`.

## Acceptance Criteria
- [ ] All queries work on both SQLite and PostgreSQL
- [ ] \`DATABASE_URL=postgres://...\` activates PostgreSQL mode
- [ ] Migrations work on both backends
- [ ] CI tests both backends"

create_issue \
  "[DB-005] Add schema version tracking and compatibility checks" \
  "enhancement,database,priority/P2" \
  "## Feature Request

If a newer binary runs against an older DB, results are undefined. Add a \`schema_version\` table and check on startup.

## Acceptance Criteria
- [ ] \`schema_meta\` table with \`version\` column
- [ ] Gateway checks version on startup
- [ ] Version mismatch: refuse to start with clear error message
- [ ] Migration bumps the version automatically"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 10: DOCUMENTATION
# ─────────────────────────────────────────────────────────────────────────────

echo "── Documentation ──"

create_issue \
  "[DOC-001] Update SOC design doc to reflect actual implementation state" \
  "documentation,priority/P1" \
  "## Bug

AegisAgent_Agent_SOC_Design.md §28 says Phases 0–3 are 'to build' when they're all implemented. This misleads contributors.

## Acceptance Criteria
- [ ] SOC design doc updated: Phases 0–3+5+6 marked as ✅ DONE
- [ ] ROADMAP.md updated to reflect actual progress
- [ ] Remaining work (Phase 4 response engine, Phase 7 ingestion) clearly marked"

create_issue \
  "[DOC-002] Add architecture decision records (ADRs)" \
  "documentation,priority/P2" \
  "## Feature Request

Add \`docs/adr/\` with ADR templates for major design decisions: Why Cedar over OPA? Why SQLite first? Why Ed25519? Why JCS-1?

## Acceptance Criteria
- [ ] ADR template in \`docs/adr/template.md\`
- [ ] Minimum 5 ADRs for existing decisions
- [ ] New ADRs required for future architectural changes"

create_issue \
  "[DOC-003] Add rendered API reference documentation (Redoc/Scalar)" \
  "documentation,api,developer-experience,priority/P2" \
  "## Feature Request

The gateway serves \`/v1/openapi.json\` but there's no rendered docs. Add Redoc or Scalar rendering to GitHub Pages.

## Acceptance Criteria
- [ ] API docs rendered at \`https://lavkushry.github.io/AegisAgent/api/\`
- [ ] Auto-updated from OpenAPI spec on each merge to main
- [ ] All endpoints documented with examples"

create_issue \
  "[DOC-004] Add operational runbooks for SOC procedures" \
  "documentation,priority/P2" \
  "## Feature Request

Runbooks for: responding to deny_storm, investigating data_exfil, rotating agent tokens, restoring from backup, verifying receipt chains.

## Acceptance Criteria
- [ ] \`docs/runbooks/\` directory with markdown runbooks
- [ ] Each runbook: symptoms, investigation steps, remediation steps, verification
- [ ] Minimum 5 runbooks for the most common SOC scenarios"

create_issue \
  "[DOC-005] Add formal threat model document" \
  "documentation,security,priority/P2" \
  "## Feature Request

Create a STRIDE-based threat model covering: confused-deputy, approve-then-swap, MCP supply-chain, trust-escalation probe, replay attack, cross-tenant access.

## Acceptance Criteria
- [ ] \`docs/threat-model.md\` with STRIDE analysis
- [ ] Each threat: description, impact, likelihood, existing mitigations, residual risk
- [ ] Reviewed by SecurityAuditorAgent persona"

create_issue \
  "[DOC-006] Add CONTRIBUTING.md with coding standards" \
  "documentation,priority/P3" \
  "## Feature Request

Add contributor guide: commit conventions, PR checklist, test expectations, security review requirements, and the Four Design Laws.

## Acceptance Criteria
- [ ] \`CONTRIBUTING.md\` with: setup guide, coding standards, PR template
- [ ] Four Design Laws prominently documented
- [ ] Security review requirements for changes to: canonicalization, approval, trust, receipts"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 11: DEVELOPER EXPERIENCE
# ─────────────────────────────────────────────────────────────────────────────

echo "── Developer Experience ──"

create_issue \
  "[DX-001] Add unified 'aegis' CLI tool (kubectl equivalent)" \
  "enhancement,developer-experience,priority/P2" \
  "## Feature Request

Kubernetes has \`kubectl\`. AegisAgent needs \`aegis\` with subcommands: \`aegis status\`, \`aegis freeze-agent\`, \`aegis verify-receipts\`, \`aegis export-audit\`, \`aegis soc-summary\`.

## Acceptance Criteria
- [ ] \`aegis\` CLI installable via \`pip install aegisagent\`
- [ ] Subcommands: status, freeze-agent, unfreeze-agent, verify-receipts, export-audit, soc-summary
- [ ] Colorized output with table formatting
- [ ] \`--format json\` option for scripting"

create_issue \
  "[DX-002] Add docker-compose.dev.yml with seeded demo data" \
  "enhancement,developer-experience,priority/P2" \
  "## Feature Request

\`docker compose up\` starts with empty DB. Add dev compose that auto-seeds: demo tenant, agents, policies, and triggers a simulated attack.

## Acceptance Criteria
- [ ] \`docker compose -f docker-compose.dev.yml up\` starts gateway + seeds data
- [ ] Demo includes: 2 tenants, 3 agents, policies, simulated deny_storm
- [ ] SOC dashboard data visible immediately after startup"

create_issue \
  "[DX-003] Add Makefile for common workflows" \
  "enhancement,developer-experience,priority/P3" \
  "## Feature Request

Add: \`make test\`, \`make lint\`, \`make build\`, \`make docker\`, \`make bench\`, \`make seed\`, \`make demo\`, \`make clean\`.

## Acceptance Criteria
- [ ] Makefile in project root
- [ ] All targets documented with \`make help\`
- [ ] \`make ci\` runs the full CI pipeline locally"

create_issue \
  "[DX-004] Add pre-commit hooks (rustfmt, clippy, black, secret scanning)" \
  "enhancement,developer-experience,priority/P3" \
  "## Feature Request

Prevent CI failures by catching issues locally with pre-commit hooks.

## Acceptance Criteria
- [ ] \`.pre-commit-config.yaml\` with hooks for: cargo fmt, cargo clippy, black, detect-secrets
- [ ] \`make setup\` installs pre-commit hooks
- [ ] README documents how to set up the dev environment"

# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY 12: PRODUCTION READINESS
# ─────────────────────────────────────────────────────────────────────────────

echo "── Production Readiness ──"

create_issue \
  "[PROD-001] Add Helm chart for Kubernetes deployment" \
  "enhancement,production,priority/P2" \
  "## Feature Request

Add \`helm/aegis-gateway/\` with: Deployment, Service, ConfigMap, Secret, ServiceMonitor, NetworkPolicy, PodDisruptionBudget, HPA.

## Acceptance Criteria
- [ ] \`helm install aegis helm/aegis-gateway/\` deploys a working gateway
- [ ] Configurable: replicas, resources, env vars, secrets
- [ ] ServiceMonitor for Prometheus scraping
- [ ] NetworkPolicy restricts ingress to known sources"

create_issue \
  "[PROD-002] Add multi-stage Dockerfile with distroless base image" \
  "enhancement,production,security,priority/P2" \
  "## Feature Request

Use multi-stage build: \`rust:bookworm\` for build → \`gcr.io/distroless/cc-debian12\` for runtime (~25MB final image).

## Acceptance Criteria
- [ ] Multi-stage Dockerfile with distroless runtime
- [ ] Final image <50MB
- [ ] No shell, no package manager in runtime image
- [ ] Non-root user"

create_issue \
  "[PROD-003] Add Kubernetes-native health check endpoints (/readyz, /livez)" \
  "enhancement,production,priority/P2" \
  "## Feature Request

Separate readiness, liveness, and startup probes (Kubernetes convention).

## Acceptance Criteria
- [ ] \`/livez\` — process alive + drain task alive
- [ ] \`/readyz\` — DB connected + migrations applied
- [ ] \`/startupz\` — initialization complete (for slow startups)
- [ ] Each returns 200 OK or 503 with details"

create_issue \
  "[PROD-004] Add native TLS support (rustls)" \
  "enhancement,production,security,priority/P2" \
  "## Feature Request

The gateway binds plain HTTP. Add optional native TLS via \`AEGIS_TLS_CERT\` + \`AEGIS_TLS_KEY\` env vars.

## Acceptance Criteria
- [ ] TLS enabled when both env vars are set
- [ ] Uses rustls (no OpenSSL dependency)
- [ ] Auto-redirect HTTP → HTTPS when TLS is enabled
- [ ] Minimum TLS 1.2"

create_issue \
  "[PROD-005] Add horizontal scaling support (shared state)" \
  "enhancement,production,priority/P3" \
  "## Feature Request

In-memory state (RateLimiter, QuotaManager, SkillActionCache, Correlator) is per-process. For horizontal scaling, move to shared state.

## Acceptance Criteria
- [ ] Rate limits backed by Redis (when \`REDIS_URL\` is set)
- [ ] Correlation windows backed by PostgreSQL (when PG backend)
- [ ] Skill cache backed by Redis
- [ ] Single-instance mode still works with in-memory state"

create_issue \
  "[PROD-006] Add zero-downtime secret rotation support" \
  "enhancement,production,security,priority/P3" \
  "## Feature Request

Rotating \`AEGIS_JWT_SECRET\` or \`AEGIS_RECEIPT_SIGNING_KEY\` requires a restart. Support multiple keys for zero-downtime rotation.

## Acceptance Criteria
- [ ] \`AEGIS_JWT_SECRET\` supports comma-separated list (sign with first, verify with all)
- [ ] \`AEGIS_RECEIPT_SIGNING_KEY\` supports key ID for multi-key verification
- [ ] Old key can be removed after rotation window
- [ ] Documented rotation procedure in runbook"

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════"
echo "  DONE: Created $CREATED issues, $FAILED failed"
echo "  Log: $LOG"
echo "═══════════════════════════════════════════════"
