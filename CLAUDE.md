# AegisAgent — Coding-Agent Context (`CLAUDE.md`)

Minimal, current context to work in this repo. For *why* the product is shaped this way, read **[`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md)** (source of truth) — don't re-derive it.

## What AegisAgent is (June 2026)

The **integrity layer for AI agent actions** — open, self-hostable, framework-neutral. The generic gateway loop (intercept → policy → allow/deny → audit → approval) is commodity (free Microsoft toolkit + OSS + SaaS), so it is **table stakes here**. The two defensible differentiators are:

1. **Approval integrity** — the human approval is bound to a SHA-256 hash of the *frozen exact action*; the SDK **fails closed** if a different/edited/expired action would execute (defeats approve-then-swap, replay, render-vs-bytes).
2. **Deterministic trust-provenance gating** — authorization is gated on the *source trust level* of the triggering content (6 levels), not a text score (confused-deputy defense). Plus **verifiable, hash-chained action receipts** as compliance evidence (SOC 2 / EU AI Act Art. 14).

> Motto: **Make the approval trustworthy. Trust the source, not the text.**

## Current status

**Python SDK — 182 tests, fully verified on `main`:**
- `action_hash` canonicalization unified as scheme **`aegis-jcs-1`** in `sdk-python/aegisagent/canon.py`; SDK fails closed on hash mismatch, on approval expiry, **and if it cannot atomically consume a single-use approval** (replay defense).
- Verifiable receipts: format + reference verifier (`aegisagent/receipts.py`), CLI (`aegis-verify-receipts`), shared corpus (`tests/receipt_chain_vectors.json`).
- Async client (`AegisAsyncClient`) + `async_protect_tool` decorator.
- CLI tools: `aegis-status`, `aegis-freeze-agent`, `aegis-export-audit`.
- Evidence packs, webhook handler, structured JSON logging.
- End-to-end demo `examples/integrity_demo.py`.

**Go SDK — full parity, verified on `main`:**
- `aegis-jcs-1` canonicalizer (`canon/canon.go`), `aegis.Client`, `aegis.Protect`, receipt verifier.
- Cross-language byte-parity CI gate.

**TypeScript SDK — full parity, verified on `main`:**
- `aegis-jcs-1` canonicalizer (`src/canon.ts`), `AegisClient`, `protect()`.
- `tsc --noEmit` build + `node --test` suite + cross-language corpus CI gate.

**Rust gateway — 499 tests, verified on `main`:**
- Cross-language `action_hash` corpus test (`canonical_action_matches_shared_corpus`).
- Gateway-side approval expiry (`get_approval` → `EXPIRED`; `approve_approval` → 409).
- Receipt-hash parity lock (`receipt_chain_matches_shared_corpus`).
- **Receipt emission**: `action_receipts` table + `emit_action_receipt` on every decision + `GET /v1/receipts/:id/verify` + optional Ed25519 signing (`sign.rs`).
- **Single-use approvals (replay T-A3)**: `consumed_at` column + atomic `db::consume_approval` + `POST /v1/approvals/:id/consume`.
- **Agent SOC (Phases 0-3, 5, 6)**: async event stream (`events.rs`), detection rules (`detect.rs`), correlation engine + incidents (`correlate.rs`), notify sink with HMAC-SHA256 signing + circuit breaker (`notify.rs`), RCA narrator (`narrate.rs`), SQLite event indexer + `/v1/ws/events` live feed + `/v1/soc/summary`.
- **YAML detection rule DSL** (`rule_dsl.rs`, #1282): `Detector` is now YAML-driven — the original hardcoded rules (`confused_deputy_block`, `approval_required_surface`, `critical_deny`, `replay_attempt`, `mcp_manifest_drift`) are an embedded default `YamlRule` set (`rule_dsl::default_rules()`). `events::drain` loads each tenant's enabled custom rules fresh from `detection_rules` per event (out-of-band, Law 3) and evaluates them alongside the defaults, deduping alerts by rule name. `GET /v1/soc/rules` (effective rules, tagged `source: "default"|"custom"`), `POST /v1/soc/rules` (validated create/update, 400 on invalid condition/severity), `POST /v1/soc/rules/reload` (documented no-op — rules are always fresh).
- **Phase 4 — Response Engine** (`respond.rs`): `freeze`/`revoke`/`quarantine` APIs + auto-dispatch responder with configurable autonomy levels (`L0`-`L4`).
- **Agentless ingestion** (`ingest.rs`): `POST /v1/ingest` for GitHub webhooks, OpenAI traces.
- **Behavioral baselining** (`baseline.rs`): per-agent action frequency baselines with anomaly detection.
- **Kubernetes probes**: `/livez`, `/readyz`, `/startupz`.
- **Composite risk score** (`risk.rs`, #1289): advisory `composite_risk_score` (0-100) on every `/v1/authorize` response and `decisions` row — base risk + environment/context-trust/MCP penalties + anomaly score - approval credit; per-tenant weight overrides via `GET|PUT /v1/tenants/risk-weights` (env-configured defaults otherwise). Display/audit metadata only — never gates `decision` (Law 1).
- **Evidence graph schema** (`graph.rs`, #1271): `EvidenceGraph { nodes: Vec<GraphNode>, edges: Vec<GraphEdge> }` — `GraphNode` (`id`/`group: NodeType`/`label`/`timestamp`/`metadata`) and `GraphEdge` (`from`/`to`/`label: EdgeType`/`timestamp`) serialize directly to vis.js Network's expected field names. `NodeType` covers `agent|run|tool_call|decision|approval|receipt|incident|mcp_server|policy`; `EdgeType` covers `triggered_by|executed|decided|approved|produced|linked_to`.
- **Evidence graph query API** (`routes.rs`, #1272): `GET /v1/graph/run/:run_id`, `GET /v1/graph/incident/:incident_id`, `GET /v1/graph/agent/:agent_id?depth=N` build an `EvidenceGraph` at query time via the shared `add_decision_subgraph` helper (tool_call -[decided]-> decision, plus run/agent linkage, and at `depth>=2` approval/receipt and `depth>=3` matched-policy nodes; `depth` clamped `[1,5]`, default 3). All three are tenant-scoped, read-only, and 404 (not 500) for missing/cross-tenant root entities — Law 1 unaffected.
- **Audit-writer chaos hardening** (#1399): `write_decision_and_audit` retries `db::insert_decision` via `db::retry_on_busy` on transient `SQLITE_BUSY`/`SQLITE_LOCKED` before treating the audit write as failed. `db::init_db_with_busy_timeout` (parameterised variant for tests) lets a chaos test hold a real SQLite writer lock and verify: high-risk action denied with `audit_writer_unavailable` + `audit_writer_unhealthy=true` while locked; `audit_writer_unhealthy` resets to `false` and normal decisions resume once the lock clears (AC3 + AC5 of #1299/#1399).
- **Tenant isolation stress tests** (#1402): `tenant_isolation_audit_events_alerts_incidents_and_decision_by_id` seeds two independent tenants and asserts `GET /v1/audit/events`, `GET /v1/alerts`, `GET /v1/incidents`, and `GET /v1/decisions/:id` all respect tenant boundaries — no cross-tenant row leakage and a cross-tenant decision ID yields 404.
- **GitHub App webhook receiver** (#1381): `POST /v1/webhooks/github` — dedicated endpoint accepting native GitHub event payloads (`pull_request`, `issues`, `issue_comment`) with mandatory HMAC-SHA256 `X-Hub-Signature-256` verification (fail-closed: 401 when `AEGIS_GITHUB_WEBHOOK_SECRET` is not set), tenant scoping via `X-Aegis-Tenant-ID`, and SOC pipeline integration. Unsupported event types return `202 ignored`. 21 new unit + integration tests.
- **Event schema versioning** (`events.rs`, #1387): `AseEvent` gains `schema_version: u32` (default 1, `#[serde(default)]`). Old serialized events without the field deserialize to v1 (forward-compatible). All ~17 construction sites updated. 5 new tests covering new/legacy/round-trip/future-version paths.
- **HMAC-SHA256 request signing** (#1403): optional `signing_key` on agents — when set, every `POST /v1/authorize` must carry `X-Aegis-Request-Signature: sha256=<hmac-hex>`; gateway verifies with constant-time `Mac::verify_slice` (401 on missing/invalid). `authorize_action` switched from `Json<>` to `Bytes` extractor. Migration `0011_agent_signing_key.sql`. 9 new gateway tests + 5 Python + 3 Go + 3 TypeScript tests.
- **Agent environment restrictions** (#1391): optional `allowed_environments` list on agents — when set, any `/v1/authorize` call from an environment not in the list is denied 403 FORBIDDEN before Cedar evaluation (confused-deputy / cross-env exploitation defense). `None` / empty = unrestricted (backwards-compatible). Migration `0012_agent_allowed_environments.sql`. 3 new gateway tests.
- **Agent-to-tool permission bindings** (#1390): optional explicit tool allow-list per agent — if any bindings exist, tools not in the list are denied 403 FORBIDDEN before Cedar evaluation (fail-closed). No bindings = unrestricted (backwards-compatible). `GET|POST /v1/agents/:id/permissions`, `DELETE /v1/agents/:id/permissions/:tool_key`. Migration `0013_agent_tool_permissions.sql`. 5 new gateway tests.
- **Cedar `@decision("quarantine")` annotation** (#1386): Cedar policies can emit `@decision("quarantine")` on any permit rule to immediately quarantine the agent after the call is recorded. `authorize_action` runs `set_agent_status → quarantined` and fires an `agent_quarantined` SOC event (Law 3, out-of-band). Subsequent calls auto-denied via `get_agent_by_token` filter. Canary-endpoint example policy in both `policies.cedar` and `gateway/policies.cedar`. `POST /v1/agents/:id/restore` reactivates quarantined agents. 5 new gateway tests (2 policy, 3 routes).
- **Action normalization layer** (#1384): `normalize_policy_identifier` added to `policy.rs` applies percent-decode → NFC → trim → lowercase before building Cedar entity UIDs, closing a bypass where `GitHub`/`Merge_Pull_Request` built a UID that didn't match Cedar policies targeting the canonical lowercase form. `normalize_tool_identifier` in `routes.rs` updated to also trim surrounding whitespace. 10 new tests (4 policy unit + 1 policy Cedar integration, 4 routes unit + 1 routes Cedar integration).
- **`redact` decision type** (#1385): Cedar policies can emit `@decision("redact") @redact_fields("field1,field2")` to allow a tool call but return a `redacted_fields` list; `authorize_action` passes the list through `AuthorizeResponse`; `AseEvent` records it for audit. `protect_tool` decorator (sync + async) strips listed kwargs before executing the tool (sets value to `"[REDACTED]"`). Severity: `quarantine > require_approval > redact > allow`. Example canary policy in both `policies.cedar` files. 4 new gateway tests (2 policy, 2 routes) + 3 Python SDK tests.
- Hashed agent tokens (SHA-256), tenant validation (404 for non-existent), graceful shutdown with SOC channel drain, `CatchPanic` layer, `schema_meta` version tracking.

**Next:** real SOC Console UI (today: `/v1/soc/summary` + WebSocket feed, no dashboard), PostgreSQL backend, Kubernetes/Helm packaging.

Baseline: Rust Axum gateway, SQLite/SQLx (tenant-scoped), Cedar policy pack (`policies.cedar` ≡ `gateway/policies.cedar`, incl. deterministic trust-provenance rules), MCP Gateway Lite, audit events, 3-SDK parity.

## Commands

```bash
# Gateway (Rust)
cargo check  --manifest-path gateway/Cargo.toml
cargo test   --manifest-path gateway/Cargo.toml        # 499 tests
cargo fmt    --manifest-path gateway/Cargo.toml -- --check
cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings
CEDAR_POLICY_PATH=policies.cedar cargo run --manifest-path gateway/Cargo.toml   # binds 127.0.0.1:8080

# SDK + demos (Python)
python3 -m pip install -e sdk-python/
python3 -m unittest discover -s sdk-python/tests       # 179 tests
python3 examples/integrity_demo.py                     # zero-setup wedge demo
aegis-verify-receipts <receipts.json>                  # or: python3 -m aegisagent.verify_receipts <f>
aegis-status --gateway http://127.0.0.1:8080           # gateway health + agent summary
aegis-freeze-agent --gateway http://127.0.0.1:8080 --agent <id>
aegis-export-audit --gateway http://127.0.0.1:8080 --output audit.json

# Go SDK
cd sdk-go && go test ./...

# TypeScript SDK
cd sdk-typescript && npm ci && npx tsc --noEmit && npm test

# Local stack
docker compose up --build && bash scripts/seed-demo.sh && python3 examples/github-attack-demo.py
```

## API endpoints (contract)

**Core:** `GET /health` · `GET /livez` · `GET /readyz` · `GET /startupz` · `POST /v1/agents/register` · `POST /v1/tools` · `GET|POST /v1/mcp/servers` (GET lists servers with `status` + pinned `manifest_hash`) · `GET|POST /v1/mcp/servers/:server_key/tools` · `POST .../tools/:tool_key/approve|disable` · `POST /v1/authorize` (returns `decision`, `action_hash`, approval info; optional `request_id` makes the call idempotent — a repeat with the same `(agent, request_id)` replays the original decision/approval instead of re-evaluating; optional `callback: {"url": "...", "secret": "..."}` registers a webhook for the resulting approval — stored as `callback_url` + `sha256(secret)` `callback_secret_hash`, plaintext secret never persisted) · `GET /v1/approvals/:id` (returns `status`, bound `action_hash`; `EXPIRED` for stale pending) · `POST /v1/approvals/:id/approve|reject|edit` · `POST /v1/approvals/:id/consume` (single-use; 409 if already used/expired) · `GET /v1/runs/:id/timeline` · `GET /v1/audit/events` · `GET /v1/receipts/:id/verify` (recomputes receipt hash; returns `verified`).

**Management & query API** (tenant-scoped, paginated): `GET /v1/agents` · `GET|PATCH|DELETE /v1/agents/:id` · `POST /v1/agents/:id/freeze|unfreeze|revoke` (freeze accepts optional `{"reason": "..."}`, recorded as `agents.frozen_reason`; agents also track `last_seen_at` heartbeat and `quarantined_at`) · `POST /v1/agents/:id/restore` (#1386, reactivates a quarantined agent to `status=active`; clears `quarantined_at`) · `GET|POST /v1/agents/:id/permissions` (#1390, agent-to-tool bindings; no rows = unrestricted) · `DELETE /v1/agents/:id/permissions/:tool_key` (#1390) · `GET /v1/decisions` (filter `agent_id`,`decision`) · `GET /v1/decisions/:id` · `GET /v1/approvals` (list pending; `EXPIRED` for stale) · `GET /v1/receipts` · `GET /v1/receipts/:id` · `POST /v1/receipts/verify-chain` · `GET|POST /v1/policies` · `PUT|DELETE /v1/policies/:id` · `POST /v1/policies/reload` · `GET|PUT /v1/tenants/risk-weights` (#1289, advisory composite-risk-score weight overrides; falls back to `AEGIS_RISK_*` env defaults) · `GET|POST /v1/tenants` · `GET /v1/tenants/:id` · `GET /v1/tenants/:id/export` (GDPR data-portability bundle) · `GET|PUT /v1/mcp/servers/:server_key` · `POST /v1/mcp/servers/:server_key/quarantine|restore` · `GET /v1/stats` · `GET /v1/openapi.json` · `GET /v1/version` · `GET /v1/ws/events` (WebSocket live SOC stream). **SOC:** `GET /v1/alerts` · `GET /v1/incidents` · `GET /v1/incidents/:id` · `POST /v1/incidents/:id/close` · `GET /v1/incidents/:id/narrate` · `GET /v1/soc/summary` · `GET|POST /v1/soc/rules` (#1282, effective YAML detection rules = embedded defaults + tenant custom, tagged `source: "default"|"custom"`; `POST` validates and 400s on an invalid condition/severity) · `POST /v1/soc/rules/reload` (documented no-op — rules are always loaded fresh) · `POST /v1/ingest` (SOC-004, agentless ingestion: `{"source": "github_webhook"|"openai_trace", "payload": {...}}`, normalizes and feeds the same detect→correlate→respond pipeline as `/v1/authorize`) · `POST /v1/webhooks/github` (#1381, dedicated GitHub App webhook receiver: raw GitHub event body, `X-GitHub-Event` header, mandatory HMAC-SHA256 `X-Hub-Signature-256`, `X-Aegis-Tenant-ID`; fail-closed — 401 when `AEGIS_GITHUB_WEBHOOK_SECRET` not set; supported events: `pull_request.opened`, `pull_request.merged`, `issues.opened`, `issue_comment.created`; unsupported events → `202 ignored`). **Evidence graph (#1272):** `GET /v1/graph/run/:run_id` · `GET /v1/graph/incident/:incident_id` · `GET /v1/graph/agent/:agent_id?depth=N` (`depth` 1-5, default 3) — all return `EvidenceGraph { nodes, edges }` (#1271 vis.js-compatible shape), tenant-scoped, 404 for missing/cross-tenant root entity.

## Critical invariants (do not weaken)

- **Canonicalization `aegis-jcs-1` MUST stay byte-identical across SDK and gateway** (keys sorted by Unicode code point, compact separators, **raw UTF-8 / no `\uXXXX`**, reject non-finite floats). Locked by `tests/canonical_action_vectors.json` + `tests/receipt_chain_vectors.json`. A divergence silently breaks the fail-closed guarantee — never change hashing without bumping the scheme + CI byte-equality.
- **Fail closed:** unknown agent/tool/MCP server/MCP tool → deny; critical → deny; high-risk → require approval. SDK refuses to execute on hash mismatch, expired approval, or unreachable gateway (mutating/high-risk).
- **Approval integrity:** every approval binds to the original `action_hash`; edits re-hash + re-evaluate; expiry enforced (SDK + gateway); never re-decide a decided approval; **single-use** — atomically consumed before execution (no replay).
- **Trust-provenance is deterministic:** classifiers may only *tighten* a label, never loosen it. Mutating action + `untrusted_external`/`malicious_suspected` → deny.
- **Multi-tenant isolation:** every tenant-owned query binds/filters `tenant_id`; parameterized SQLx only (no string interpolation).
- **Local binding** `127.0.0.1` for dev/test; **redact** secrets from logs/receipts (store hashes, not payloads); no `.unwrap()`/`.expect()` in production paths.

## Where things live

- `gateway/src/`: `routes.rs` (handlers, canonicalization, approval integrity, receipt helpers), `db.rs` (tenant-scoped SQLx, migrations), `policy.rs` (Cedar), `models.rs`, `main.rs` (lifecycle, redaction, K8s probes), `events.rs` (async SOC event emitter), `detect.rs` (detection rules), `correlate.rs` (correlation engine + incidents), `notify.rs` (webhook + Slack notifications, HMAC signing, circuit breaker), `respond.rs` (response engine, autonomy levels), `ingest.rs` (agentless ingestion), `baseline.rs` (behavioral baselining), `narrate.rs` (RCA narrator), `jobs.rs` (background jobs: cleanup, archival, chain verification), `metrics.rs` (database size/row monitoring), `sign.rs` (Ed25519 receipt signing). `gateway/policies.cedar` (keep ≡ root `policies.cedar`).
- `sdk-python/aegisagent/`: `canon.py` (scheme), `decorator.py` (`@protect_tool`, fail-closed + expiry), `client.py` (sync + async clients), `receipts.py` (verifier), `verify_receipts.py` (CLI), `accumulator.py` (receipt accumulation), `evidence.py` (evidence packs), `webhooks.py` (webhook/Slack handler), `logging.py` (structured JSON), `cli.py` (CLI tools).
- `sdk-go/`: `canon/canon.go` (scheme), `aegis/client.go`, `aegis/protect.go`, `aegis/receipts.go`.
- `sdk-typescript/src/`: `canon.ts` (scheme), `client.ts`, `protect.ts`.
- Strategy docs in `docs/` were re-anchored 2026-06-02 on the integrity wedge; `docs/action-receipt-spec.md` is the open receipt format.

## How to continue

Use TDD (RED → GREEN). Spend effort on the **two integrity primitives + receipts** (the moat); don't reinvent the commodity gateway loop. After Rust edits, run `cargo test/fmt/clippy`; **don't stack unverified Rust** — get the branch green first. `.clauderules`/`.cursorrules` are harness-generated (regenerate via `scripts/setup_agent_harness.sh`, don't hand-edit). Persona scopes: `AGENTS.md`.
