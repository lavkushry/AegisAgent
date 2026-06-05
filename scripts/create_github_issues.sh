#!/usr/bin/env bash
# AegisAgent — Bulk GitHub Issue Creator
# Creates all 92 PRs/Issues from the enterprise breakdown
# Prerequisites: gh auth login (GitHub CLI must be authenticated)
# Usage: bash scripts/create_github_issues.sh

set -e
REPO="lavkushry/AegisAgent"

echo "🛡️  AegisAgent — Creating GitHub Issues (92 PRs across 10 tracks)"
echo "   Repo: $REPO"
echo ""

create_issue() {
  local TITLE="$1"; local LABELS="$2"; local MILESTONE="$3"; local BODY="$4"
  echo "  Creating: $TITLE"
  gh issue create \
    --repo "$REPO" \
    --title "$TITLE" \
    --label "$LABELS" \
    --body "$BODY" 2>/dev/null || echo "    ⚠️  Skipped: $TITLE"
}

# ── Ensure labels exist ────────────────────────────────────────────────────────
echo "🏷️  Creating labels..."
for LABEL in p0 p1 p2 p3 rust python typescript go soc ci security docs frontend integration \
  blocker canonicalization approval-integrity receipt trust-provenance multi-tenant mcp slack otel \
  async compliance pentest correlation incident response analytics concurrency rate-limit privacy \
  release packaging observability langchain openai resilience audit testing dx supply-chain sbom \
  helm k8s gateway sdk demo positioning api openapi ml rca ingestion baselining rag memory \
  clickhouse backend notify detection nextjs sql-injection cedar policy secret-scanning microsoft \
  pipeline splunk datadog pagerduty github github-actions marketing test eu-ai-act soc2 \
  threat-model responsive onboarding soc-console dependabot automation e2e docker; do
  gh label create "$LABEL" --color "$(printf '%06X' $((RANDOM * RANDOM % 16777215)))" --repo "$REPO" 2>/dev/null || true
done
echo "   ✅ Labels ready"
echo ""

# ── TRACK 1: RUST GATEWAY ─────────────────────────────────────────────────────
echo "🦀 TRACK 1: Rust Gateway (PR-001 to PR-012)"

create_issue "PR-001 · [Gateway] Verify Rust compilation and make all existing tests green" \
  "rust,p0,blocker,gateway" "Q3 2026" \
"## Context
\`CLAUDE.md\` states several gateway features are written but NOT yet compiled.

## Tasks
- [ ] \`cargo check --manifest-path gateway/Cargo.toml\` — fix all errors
- [ ] \`cargo test --manifest-path gateway/Cargo.toml\` — all tests pass
- [ ] \`cargo fmt --manifest-path gateway/Cargo.toml -- --check\`
- [ ] \`cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings\`

## Acceptance Criteria
- \`cargo test\` exits 0
- \`cargo clippy\` exits 0 with \`-D warnings\`
- CI green

**Track:** TRACK-1 | **Priority:** P0 | **Team:** @team-gateway"

create_issue "PR-002 · [Gateway] Emit verifiable action receipts on every /v1/authorize decision" \
  "rust,p0,receipt,integrity,gateway" "Q3 2026" \
"## Tasks
- [ ] Create \`action_receipts\` table migration in \`db.rs\`
- [ ] Implement \`db::emit_action_receipt()\` with hash chaining to last tenant receipt
- [ ] Call from \`routes::authorize\` on every decision
- [ ] Implement \`GET /v1/receipts/:id/verify\` → returns \`{ verified: bool }\`
- [ ] Unit test: \`authorize_emits_verifiable_receipt\`

**Depends on:** PR-001 | **Priority:** P0"

create_issue "PR-003 · [Gateway] Single-use approval consume (replay defense T-A3)" \
  "rust,p0,approval-integrity,security,gateway" "Q3 2026" \
"## Tasks
- [ ] Add \`consumed_at TIMESTAMP\` column to \`approvals\`
- [ ] Atomic \`db::consume_approval()\` — returns AlreadyConsumed if set
- [ ] \`POST /v1/approvals/:id/consume\` → 200 first call, 409 repeat
- [ ] Test: \`consume_is_single_use\`
- [ ] Test: expired approval → 409

**Depends on:** PR-001 | **Priority:** P0"

create_issue "PR-004 · [Gateway] Enforce approval expiry at gateway level" \
  "rust,p0,approval-integrity,gateway" "Q3 2026" \
"## Tasks
- [ ] \`GET /v1/approvals/:id\` → \`{\"status\": \"EXPIRED\"}\` for stale approvals
- [ ] \`POST /v1/approvals/:id/approve\` → 409 if expired
- [ ] Test: \`expired_approval_is_reported_and_cannot_be_approved\`
- [ ] Configurable \`APPROVAL_TTL_SECONDS\` (default 300)

**Depends on:** PR-001 | **Priority:** P0"

create_issue "PR-005 · [Gateway] Cross-language action_hash corpus test (Rust ↔ Python byte equality)" \
  "rust,p0,canonicalization,test,gateway" "Q3 2026" \
"## Tasks
- [ ] Load \`tests/canonical_action_vectors.json\` in Rust test
- [ ] Test: \`canonical_action_matches_shared_corpus\`
- [ ] Test: \`receipt_chain_matches_shared_corpus\`
- [ ] CI fails on any vector hash divergence

**Depends on:** PR-001 | **Priority:** P0"

create_issue "PR-006 · [Gateway] Race-safe receipt chain head selection via SQLite transaction" \
  "rust,p1,receipt,concurrency,gateway" "Q3 2026" \
"## Tasks
- [ ] Wrap chain-head SELECT + INSERT in BEGIN IMMEDIATE transaction
- [ ] Concurrent test: 50 parallel authorize calls → no duplicate prev_hash
- [ ] Benchmark: <5ms overhead at p99

**Depends on:** PR-002 | **Priority:** P1"

create_issue "PR-007 · [Gateway] Approval edit must re-hash + re-evaluate before granting" \
  "rust,p0,approval-integrity,gateway" "Q3 2026" \
"## Tasks
- [ ] \`POST /v1/approvals/:id/edit\` recomputes action_hash, calls Cedar again
- [ ] Re-eval deny → 403
- [ ] Stores new action_hash on approval row
- [ ] Emits tamper-attempt receipt

**Depends on:** PR-001, PR-002 | **Priority:** P0"

create_issue "PR-008 · [Gateway] Audit all DB queries for tenant_id binding" \
  "rust,p0,security,multi-tenant,gateway" "Q3 2026" \
"## Tasks
- [ ] All tenant-owned queries: WHERE tenant_id = ?
- [ ] Zero string-interpolated SQL
- [ ] Cross-tenant leakage tests pass (empty result with wrong tenant_id)
- [ ] Document in SECURITY.md

**Depends on:** PR-001 | **Priority:** P0"

create_issue "PR-009 · [Gateway] OpenTelemetry metrics: approval_hash_mismatch_total, provenance_denials_total" \
  "rust,p1,observability,otel,gateway" "Q4 2026" \
"## Tasks
- [ ] Add opentelemetry + opentelemetry-otlp crates
- [ ] Instrument /v1/authorize with counters
- [ ] Expose /metrics Prometheus endpoint

**Depends on:** PR-001 | **Priority:** P1"

create_issue "PR-010 · [Gateway] Async Agent Security Event (ASE) emitter via tokio::mpsc" \
  "rust,p1,soc,async,gateway" "Q4 2026" \
"## Context
Phase 0: non-blocking ASE emission. Must NOT add latency to <75ms inline path.

## Tasks
- [ ] Define AseEvent struct
- [ ] Background Tokio task draining mpsc::Receiver<AseEvent>
- [ ] Non-blocking try_send from authorize handler
- [ ] Drop gracefully when channel full
- [ ] Test: 100 authorize calls → 100 ASE events emitted

**Depends on:** PR-001, PR-002 | **Priority:** P1"

create_issue "PR-011 · [Gateway] Per-tenant rate limiting on /v1/authorize" \
  "rust,p2,security,rate-limit,gateway" "2027 H1" \
"**Priority:** P2 | governor crate, 100 req/s default, 429 + Retry-After"

create_issue "PR-012 · [Gateway] Redact secrets from logs and receipts" \
  "rust,p0,security,privacy,gateway" "Q3 2026" \
"## Tasks
- [ ] Audit all tracing::info!/warn!/error! calls — redact secrets
- [ ] Receipts: store SHA-256(payload) not raw for sensitive params
- [ ] REDACTED_FIELDS env var
- [ ] Test: log with secret → [REDACTED]

**Depends on:** PR-001 | **Priority:** P0"

# ── TRACK 2: PYTHON SDK ───────────────────────────────────────────────────────
echo "🐍 TRACK 2: Python SDK (PR-013 to PR-022)"

create_issue "PR-013 · [Python SDK] Achieve 100% branch coverage on all SDK modules" \
  "python,p0,test" "Q3 2026" \
"- [ ] coverage run -m pytest sdk-python/tests/
- [ ] Cover decorator.py error paths
- [ ] Cover canon.py non-finite float rejection
- [ ] cover verify_receipts.py CLI
- [ ] coverage report --fail-under=100

**Priority:** P0"

create_issue "PR-014 · [Python SDK] Add async/await support for @protect_tool decorator" \
  "python,p1,async,sdk" "Q4 2026" \
"**Depends on:** PR-013 | **Priority:** P1 | Detect coroutine via asyncio.iscoroutinefunction, use asyncio.sleep for polling"

create_issue "PR-015 · [Python SDK] Receipt batch export / SOC 2 evidence pack" \
  "python,p1,receipt,compliance" "Q4 2026" \
"aegisagent.receipts.export_evidence_pack() + aegis-export-receipts CLI | **Priority:** P1"

create_issue "PR-016 · [Python SDK] Trust level classifier integration API" \
  "python,p1,trust-provenance" "Q4 2026" \
"Classifiers may only tighten, never loosen. AegisClient.set_trust_classifier(fn). ClassifierViolationError on loosen attempt. | **Priority:** P1"

create_issue "PR-017 · [Python SDK] Slack approval callback with signature verification" \
  "python,p1,slack,approval" "Q3 2026" \
"Verify X-Slack-Signature HMAC-SHA256. Invalid sig → 403. | **Priority:** P1"

create_issue "PR-018 · [Python SDK] Package and publish to PyPI (pip install aegisagent)" \
  "python,p1,release,packaging" "Q4 2026" "**Priority:** P1"

create_issue "PR-019 · [Python SDK] LangChain tool wrapper for @protect_tool" \
  "python,p2,integration,langchain" "Q4 2026" "**Priority:** P2"

create_issue "PR-020 · [Python SDK] OpenAI function-calling integration" \
  "python,p2,integration,openai" "Q4 2026" "**Depends on:** PR-019 | **Priority:** P2"

create_issue "PR-021 · [Python SDK] Exponential backoff + jitter for approval polling" \
  "python,p1,resilience" "Q3 2026" \
"0.5s→30s, ±20% jitter, configurable max_poll_duration, ApprovalTimeoutError | **Depends on:** PR-013 | **Priority:** P1"

create_issue "PR-022 · [Python SDK] Structured audit log export (JSON-L, CSV) from SDK" \
  "python,p2,audit,compliance" "Q4 2026" "aegis-audit-export CLI | **Priority:** P2"

# ── TRACK 3: TYPESCRIPT SDK ───────────────────────────────────────────────────
echo "📘 TRACK 3: TypeScript SDK (PR-023 to PR-030)"

create_issue "PR-023 · [TS SDK] Complete aegis-jcs-1 canonicalization — byte-identical to Python/Rust" \
  "typescript,p0,canonicalization" "Q4 2026" \
"Load canonical_action_vectors.json in Jest. All vectors pass byte-equality. | **Priority:** P0"

create_issue "PR-024 · [TS SDK] Implement protectTool() wrapper with fail-closed approval" \
  "typescript,p0,sdk,approval-integrity" "Q4 2026" \
"Fail closed: AegisGatewayUnavailableError + AegisHashMismatchError. 6 fail-closed scenario tests. | **Depends on:** PR-023 | **Priority:** P0"

create_issue "PR-025 · [TS SDK] AegisClient class with full API surface" \
  "typescript,p1,sdk" "Q4 2026" \
"Native fetch (Node 18+), TypeScript strict mode, full type exports. | **Depends on:** PR-024 | **Priority:** P1"

create_issue "PR-026 · [TS SDK] Publish @aegisagent/sdk to npm" \
  "typescript,p1,release" "Q4 2026" "**Depends on:** PR-025 | **Priority:** P1"

create_issue "PR-027 · [TS SDK] Receipt chain verifier + CLI (npx aegis-verify-receipts)" \
  "typescript,p1,receipt" "Q4 2026" "**Depends on:** PR-025 | **Priority:** P1"

create_issue "PR-028 · [TS SDK] Jest mock client for unit testing" \
  "typescript,p2,testing,dx" "Q4 2026" "**Depends on:** PR-025 | **Priority:** P2"

create_issue "PR-029 · [TS SDK] Next.js example app using protectTool" \
  "typescript,p2,demo,nextjs" "Q4 2026" "**Depends on:** PR-025 | **Priority:** P2"

create_issue "PR-030 · [TS SDK] AsyncIterator-based approval polling stream" \
  "typescript,p2,async" "Q4 2026" "**Depends on:** PR-025 | **Priority:** P2"

# ── TRACK 4: GO SDK ───────────────────────────────────────────────────────────
echo "🔵 TRACK 4: Go SDK (PR-031 to PR-036)"

create_issue "PR-031 · [Go SDK] Initialize Go SDK module with aegis-jcs-1 canonicalization" \
  "go,p1,sdk,canonicalization" "Q4 2026" \
"sdk-go/go.mod + canon.go. Test against canonical_action_vectors.json. | **Priority:** P1"

create_issue "PR-032 · [Go SDK] AegisClient with full HTTP API surface" \
  "go,p1,sdk" "Q4 2026" "**Depends on:** PR-031 | **Priority:** P1"

create_issue "PR-033 · [Go SDK] ProtectFunc() wrapper with fail-closed approval flow" \
  "go,p1,sdk" "Q4 2026" "**Depends on:** PR-032 | **Priority:** P1"

create_issue "PR-034 · [Go SDK] Receipt chain verifier" \
  "go,p2,receipt" "Q4 2026" "**Depends on:** PR-033 | **Priority:** P2"

create_issue "PR-035 · [Go SDK] GitHub Actions workflow example using Go SDK" \
  "go,p2,github-actions,demo" "2027 H1" "**Depends on:** PR-033 | **Priority:** P2"

create_issue "PR-036 · [Go SDK] Tag and publish Go module (pkg.go.dev)" \
  "go,p2,release" "Q4 2026" "**Depends on:** PR-034 | **Priority:** P2"

# ── TRACK 5: SOC PIPELINE ─────────────────────────────────────────────────────
echo "🔍 TRACK 5: Agent SOC Pipeline (PR-037 to PR-048)"

create_issue "PR-037 · [SOC] ASE event sink: write to Postgres/ClickHouse" \
  "soc,p1,analytics,backend" "Q4 2026" \
"Background drain → bulk-insert ase_events. ASE_SINK_DSN env var. Test: 1000 events, none lost. | **Depends on:** PR-010 | **Priority:** P1"

create_issue "PR-038 · [SOC] Phase 1: Deterministic YAML detection rule engine" \
  "soc,p1,detection" "Q4 2026" \
"3 built-in rules: confused_deputy, mcp_drift, approval_tamper. Cedar decides. No LLM. | **Depends on:** PR-037 | **Priority:** P1"

create_issue "PR-039 · [SOC] Incident data model with evidence_receipts" \
  "soc,p1,incident" "Q4 2026" \
"incidents table, POST /v1/incidents, GET /v1/incidents/:id/timeline | **Depends on:** PR-038 | **Priority:** P1"

create_issue "PR-040 · [SOC] Phase 2: Slack notification sink for deny + approval events" \
  "soc,p1,slack,notify" "Q4 2026" \
"SLACK_WEBHOOK_URL env var. Test: mock Slack → correct payload on deny. | **Depends on:** PR-038 | **Priority:** P1"

create_issue "PR-041 · [SOC] Phase 3: Correlation rule — deny storm detection (frequency window)" \
  "soc,p2,correlation" "2027 H1" \
">10 denies from same agent in 60s → incident. Sliding-window counter. | **Depends on:** PR-039 | **Priority:** P2"

create_issue "PR-042 · [SOC] Phase 3: Sequence rule — read sensitive + egress pattern" \
  "soc,p2,correlation" "2027 H1" "**Depends on:** PR-039 | **Priority:** P2"

create_issue "PR-043 · [SOC] Phase 4: Response API — POST /v1/agents/:id/freeze" \
  "soc,p1,response" "2027 H1" \
"agents.status column. Freeze → all subsequent authorize calls deny. | **Depends on:** PR-001 | **Priority:** P1"

create_issue "PR-044 · [SOC] Phase 4: Response API — POST /v1/mcp/servers/:key/quarantine" \
  "soc,p1,response,mcp" "2027 H1" "**Depends on:** PR-043 | **Priority:** P1"

create_issue "PR-045 · [SOC] Phase 5: ClickHouse sink for live decision feed" \
  "soc,p2,clickhouse,analytics" "2027 H2" "**Depends on:** PR-037 | **Priority:** P2"

create_issue "PR-046 · [SOC] Phase 6: Sandboxed LLM RCA narrator for closed incidents" \
  "soc,p3,ml,rca" "2027 H2" \
"One sandboxed LLM. No tools. No enforcement. Summarises closed incidents only. The ONLY LLM in the SOC. | **Priority:** P3"

create_issue "PR-047 · [SOC] Phase 7: Agentless GitHub webhook ingestion" \
  "soc,p2,ingestion,github" "2027 H2" "**Depends on:** PR-038 | **Priority:** P2"

create_issue "PR-048 · [SOC] Phase 7: Behavioural baselining for anomaly surface" \
  "soc,p3,ml,baselining" "2027 H2" "**Depends on:** PR-047 | **Priority:** P3"

# ── TRACK 6: CI/CD ────────────────────────────────────────────────────────────
echo "⚙️  TRACK 6: CI/CD & DevOps (PR-049 to PR-056)"

create_issue "PR-049 · [CI] Rust test matrix: stable + beta + MSRV (1.75)" \
  "ci,rust,p1" "Q3 2026" "rust-toolchain.toml pin + Cargo cache | **Priority:** P1"

create_issue "PR-050 · [CI] Python test matrix: 3.9, 3.10, 3.11, 3.12" \
  "ci,python,p1" "Q3 2026" "**Priority:** P1"

create_issue "PR-051 · [CI] Add TypeScript SDK test gate to CI pipeline" \
  "ci,typescript,p1" "Q4 2026" "**Depends on:** PR-023 | **Priority:** P1"

create_issue "PR-052 · [CI] Byte-equality gate: all SDKs must match canonical_action_vectors.json" \
  "ci,p0,canonicalization" "Q3 2026" \
"corpus-check CI job comparing Rust + Python + TS computed hashes. Blocks merge on any divergence. | **Depends on:** PR-005, PR-023, PR-031 | **Priority:** P0"

create_issue "PR-053 · [CI] End-to-end Docker Compose integration test in CI" \
  "ci,p1,e2e,docker" "Q3 2026" \
"docker compose up → health check → seed → attack demo → assert blocked message | **Priority:** P1"

create_issue "PR-054 · [CI] Generate SBOM (CycloneDX) on every release" \
  "ci,p2,sbom,supply-chain" "Q4 2026" "**Priority:** P2"

create_issue "PR-055 · [CI] Auto-merge Dependabot patch updates after CI green" \
  "ci,p2,dependabot,automation" "Q4 2026" "**Priority:** P2"

create_issue "PR-056 · [Ops] Helm chart for production gateway deployment" \
  "helm,p2,k8s" "2027 H1" \
"Chart.yaml, values.yaml, deployment.yaml, service.yaml, ingress.yaml. helm lint passes. | **Priority:** P2"

# ── TRACK 7: SECURITY ─────────────────────────────────────────────────────────
echo "🔒 TRACK 7: Security Audit (PR-057 to PR-063)"

create_issue "PR-057 · [Security] Refresh threat model after approval-integrity feature additions" \
  "security,p0,threat-model" "Q3 2026" \
"Add: receipt chain race (T-R1), ASE overflow (T-R2), ClickHouse injection (T-R3) | **Priority:** P0"

create_issue "PR-058 · [Security] SQL injection audit: verify 100% parameterized queries" \
  "security,p0,sql-injection" "Q3 2026" \
"grep for unparameterized SQL. Fuzz tenant_id with SQL metacharacters. Zero findings. | **Priority:** P0"

create_issue "PR-059 · [Security] Cedar policy audit: verify fail-closed for all agent/tool combos" \
  "security,p0,cedar,policy" "Q3 2026" \
"Unknown agent/tool/MCP → deny. mutates_state=true + untrusted_external → deny always. | **Priority:** P0"

create_issue "PR-060 · [Security] Secret scanning: ensure no hardcoded secrets in codebase" \
  "security,p0,secret-scanning" "Q3 2026" \
"Run gitleaks over full git history. Fix findings. Add pre-commit hook. CI gate. | **Priority:** P0"

create_issue "PR-061 · [Security] Pen test: approve-then-swap attack must fail" \
  "security,p0,pentest,approval-integrity" "Q3 2026" \
"3 scenarios: hash mismatch block, wrong approval ID, replay (409). Document in docs/pen-test-approval-integrity-2026.md | **Priority:** P0"

create_issue "PR-062 · [Security] MCP manifest trust audit: unknown tool deny + drift detection" \
  "security,p1,mcp" "Q4 2026" "**Priority:** P1"

create_issue "PR-063 · [Security] EU AI Act Article 14 compliance review of receipt evidence format" \
  "security,p1,compliance,eu-ai-act" "Q4 2026 (deadline 2026-08-02)" \
"Map receipt fields to Article 14. Legal review. Publish compliance guide. | **Priority:** P1"

# ── TRACK 8: DOCS ─────────────────────────────────────────────────────────────
echo "📚 TRACK 8: Docs & DX (PR-064 to PR-072)"

create_issue "PR-064 · [Docs] Record quickstart screencast (2-minute demo)" \
  "docs,p2,dx" "Q4 2026" "clone → compose up → seed → attack demo → audit events | **Priority:** P2"

create_issue "PR-065 · [Docs] Write the flagship approve-then-swap-blocked demo guide" \
  "docs,p0,demo,positioning" "Q3 2026" \
"The positioning proof. Step-by-step guide with code. Publish to docs/approve-then-swap-demo.md | **Priority:** P0"

create_issue "PR-066 · [Docs] OpenAPI 3.1 spec for all gateway endpoints" \
  "docs,p1,api,openapi" "Q4 2026" "docs/openapi.yaml + Swagger UI at /api-docs | **Priority:** P1"

create_issue "PR-067 · [Docs] Python SDK API reference (autodoc from docstrings)" \
  "docs,p1,python" "Q4 2026" "**Priority:** P1"

create_issue "PR-068 · [Docs] Write trust-provenance explainer with 6-level diagram" \
  "docs,p1,trust-provenance" "Q3 2026" "**Priority:** P1"

create_issue "PR-069 · [Docs] Update CONTRIBUTING.md with Go SDK + TS SDK development setup" \
  "docs,p2" "Q4 2026" "**Priority:** P2"

create_issue "PR-070 · [Docs] Write approval integrity blog post" \
  "docs,p2,marketing" "Q4 2026" "**Priority:** P2"

create_issue "PR-071 · [Docs] SOC 2 evidence export guide using action receipts" \
  "docs,p1,compliance,soc2" "Q4 2026" "**Priority:** P1"

create_issue "PR-072 · [Docs] Automate CHANGELOG.md from conventional commits" \
  "docs,p2,automation" "Q4 2026" "**Priority:** P2"

# ── TRACK 9: DASHBOARD ────────────────────────────────────────────────────────
echo "🖥️  TRACK 9: Dashboard / SOC Console UI (PR-073 to PR-082)"

create_issue "PR-073 · [UI] Live decision feed: real-time authorize event stream" \
  "frontend,p1,soc-console" "2027 H2" \
"SSE endpoint + EventSource frontend. Row color: green=allow, red=deny, amber=pending | **Priority:** P1"

create_issue "PR-074 · [UI] Incident timeline view with evidence receipt links" \
  "frontend,p1,incident" "2027 H1" "**Depends on:** PR-039 | **Priority:** P1"

create_issue "PR-075 · [UI] Agent risk scoreboard with deny rate and anomaly flags" \
  "frontend,p1,soc-console" "2027 H2" "**Depends on:** PR-041 | **Priority:** P1"

create_issue "PR-076 · [UI] Receipt integrity viewer: verify chain + display tamper status" \
  "frontend,p1,receipt" "2027 H1" "**Depends on:** PR-002 | **Priority:** P1"

create_issue "PR-077 · [UI] Human approval queue with one-click approve/reject/edit" \
  "frontend,p0,approval" "Q4 2026" \
"List pending approvals, action details, countdown timer showing expiry | **Priority:** P0"

create_issue "PR-078 · [UI] MCP server manifest viewer with drift indicators" \
  "frontend,p2,mcp" "Q4 2026" "**Priority:** P2"

create_issue "PR-079 · [UI] Dark/light mode toggle with system preference detection" \
  "frontend,p2" "Q4 2026" "**Priority:** P2"

create_issue "PR-080 · [UI] Mobile-responsive SOC console layout" \
  "frontend,p2,responsive" "2027 H1" "**Priority:** P2"

create_issue "PR-081 · [UI] Full-text search + filter for audit event log" \
  "frontend,p2,audit" "2027 H1" "**Priority:** P2"

create_issue "PR-082 · [UI] New tenant onboarding wizard" \
  "frontend,p2,onboarding,dx" "2027 H1" "**Priority:** P2"

# ── TRACK 10: INTEGRATIONS ────────────────────────────────────────────────────
echo "🔌 TRACK 10: Integrations (PR-083 to PR-092)"

create_issue "PR-083 · [Integration] GitHub App: PR comment/check for approval actions" \
  "integration,p1,github" "Q4 2026" \
"PR comment + /approve slash command + CI check update | **Priority:** P1"

create_issue "PR-084 · [Integration] Layer-on adapter: Microsoft Agent Governance Toolkit" \
  "integration,p1,microsoft" "2027 H1" "**Priority:** P1"

create_issue "PR-085 · [Integration] Layer-on adapter: MintMCP" \
  "integration,p1,mcp" "2027 H1" "**Priority:** P1"

create_issue "PR-086 · [Integration] Layer-on adapter: Pipelock" \
  "integration,p2,pipeline" "2027 H1" "**Priority:** P2"

create_issue "PR-087 · [Integration] OpenTelemetry exporter: emit audit events as OTel spans" \
  "integration,p1,otel,observability" "Q4 2026" "**Depends on:** PR-009 | **Priority:** P1"

create_issue "PR-088 · [Integration] Splunk webhook export of audit events" \
  "integration,p2,splunk" "2027 H1" "**Priority:** P2"

create_issue "PR-089 · [Integration] Datadog metrics + APM integration" \
  "integration,p2,datadog" "2027 H1" "**Priority:** P2"

create_issue "PR-090 · [Integration] PagerDuty alert integration for critical SOC incidents" \
  "integration,p2,pagerduty" "2027 H1" "**Priority:** P2"

create_issue "PR-091 · [Integration] MCP manifest signing + drift detection" \
  "integration,p1,mcp,security" "Q4 2026" "**Priority:** P1"

create_issue "PR-092 · [Integration] Memory/RAG provenance tracking + receipts (AgentPoison defense)" \
  "integration,p2,rag,memory" "2027 H2" "**Priority:** P2"

echo ""
echo "✅ Done! 92 GitHub Issues created on $REPO"
echo "   View at: https://github.com/$REPO/issues"
