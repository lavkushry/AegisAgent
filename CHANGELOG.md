# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [Unreleased]

### Added

- **Canonicalization scheme `aegis-jcs-1`** shared byte-identically between the
  Python SDK, Go SDK, TypeScript SDK, and the Rust gateway, locked by shared test
  corpora (`tests/canonical_action_vectors.json`, `tests/receipt_chain_vectors.json`)
  and a 4-language CI gate.
- **Approval integrity**: action-hash binding with fail-closed SDK enforcement,
  approval expiry (SDK + gateway), and single-use approval consumption
  (`consumed_at` guard + `POST /v1/approvals/:id/consume`) to defeat replay.
- **Verifiable action receipts**: open hash-chained receipt format
  (`docs/action-receipt-spec.md`), Python reference verifier (`aegisagent.receipts`),
  `aegis-verify-receipts` CLI, gateway emission, `GET /v1/receipts/:id/verify`,
  and optional **Ed25519 receipt signing** with `sign.rs`.
- **Deterministic trust-provenance gating**: 6-level model in the default Cedar
  policy pack; classifiers may only tighten a label, never loosen it.
- **Go SDK** (`sdk-go/`): `aegis-jcs-1` canonicalizer, `aegis.Client`,
  `aegis.Protect`, receipt chain verifier — full parity with the Python reference,
  cross-language corpus CI gate.
- **TypeScript SDK** (`sdk-typescript/`): `aegis-jcs-1` canonicalizer,
  `AegisClient`, `protect()`, strict `tsc` build, `node --test` suite,
  cross-language corpus CI gate — full parity.
- **Agent SOC — Phase 0**: async Agent Security Event emitter (`events.rs`),
  non-blocking `tokio::mpsc` channel drained by background task.
- **Agent SOC — Phase 1**: deterministic detection rules (`detect.rs`), single-event
  matches for confused-deputy, MCP drift, approval tamper.
- **Agent SOC — Phase 2**: notify sink (`notify.rs`) — Slack / webhook consumer on
  deny + approval events, with **HMAC-SHA256 webhook signatures** and a
  **circuit breaker** for transient failures.
- **Agent SOC — Phase 3**: correlation engine + incidents (`correlate.rs`) — frequency,
  sequence, and time-window correlation rules (deny-storm, read-sensitive → egress,
  runaway-agent); incident model with `evidence_receipts`.
- **Agent SOC — Phase 4**: response engine (`respond.rs`) — manual
  `freeze`/`revoke`/`quarantine` APIs + **auto-dispatch responder** with configurable
  autonomy levels (`L0`-`L4`) via `AEGIS_SOC_AUTONOMY_LEVEL` env var and per-tenant
  `tenants.soc_autonomy_level` override.
- **Agent SOC — Phase 5**: SQLite event indexer + `/v1/ws/events` WebSocket live
  feed + `/v1/soc/summary` SOC overview endpoint.
- **Agent SOC — Phase 6**: RCA narrator (`narrate.rs`) — sandboxed LLM that
  summarises closed incidents as markdown reports; no path to enforcement.
- **Agentless ingestion** (`ingest.rs`): `POST /v1/ingest` accepting
  `github_webhook` and `openai_trace` sources, normalizing into the same
  detect→correlate→respond pipeline.
- **Behavioral baselining** (`baseline.rs`): per-agent action frequency baselines
  with anomaly detection, feeding the correlation engine.
- **Kubernetes probes**: `/livez` (liveness, no I/O), `/readyz` (readiness, pings
  DB), `/startupz` (startup probe) (#1225).
- **Schema meta table** (`schema_meta`) and startup version check (#1228).
- **Hashed agent tokens**: agent tokens stored as SHA-256 hashes, not plaintext
  (#1137).
- **Tenant validation**: reject requests for non-existent tenants with 404 (#1136).
- **Graceful shutdown**: drain SOC event channel before exit (#1148).
- **CatchPanic layer**: handler panic recovery to prevent process crash (#1222).
- **Retry with backoff**: transient `SQLITE_BUSY` retry wrapper (#1223).
- **Approval callback columns**: `callback_url` + `callback_secret_hash` on
  approvals (#1231).
- **Python SDK — async client**: `AegisAsyncClient` with `httpx` backend and
  `async_protect_tool` decorator.
- **Python SDK — CLI tools**: `aegis-status`, `aegis-freeze-agent`,
  `aegis-export-audit` entry points.
- **Python SDK — SOC client methods**: `get_soc_summary()`, `list_alerts()`,
  `list_incidents()`, `close_incident()`, `narrate_incident()`.
- **Python SDK — evidence packs**: `create_evidence_pack()` for bundling receipts.
- **Python SDK — webhook handler**: `WebhookHandler` + `verify_slack_signature()`.
- **Python SDK — structured logging**: `StructuredJSONFormatter`.
- Self-contained, zero-setup integrity demo (`examples/integrity_demo.py`).
- OSS project scaffolding: MIT `LICENSE`, `CODE_OF_CONDUCT.md`, issue/PR
  templates, Dependabot, and hardened CI.
- **CI matrix**: Rust (stable + beta + MSRV 1.88), Python (3.9–3.12), Go SDK,
  TypeScript SDK, cross-language corpus byte-equality gate, Docker Compose E2E,
  blocking dependency audits (cargo-audit + pip-audit) (#1170).
- **MkDocs Material docs site**: auto-deployed to GitHub Pages on push to `main`.

### Changed

- **sqlx 0.7.4 → 0.8.6**: resolves RUSTSEC-2024-0363 (binary protocol
  truncation/overflow) and drops the unmaintained `paste` dependency (#1170).
- Repositioned from "Agent Action Firewall" to the **integrity layer for AI
  agent actions** (see `docs/AegisAgent_Gap_Reassessment_2026-06.md`).
- Documentation re-anchored on the integrity + provenance + verifiable-evidence
  wedge.
- Seed script (`scripts/seed-demo.sh`) creates the demo tenant before registering
  agents (#1233).
- Notify env-var tests serialized to fix CI flakiness (#1232).

### Fixed

- **BUG-001, BUG-002, BUG-003**: auth and tenant isolation vulnerabilities (#1212).
- **BUG-004, BUG-005**: lock poisoning panics in policy and events modules (#1213).
- `edit_approval` re-hashes edited call and rejects if already decided (#1121).
- Python SDK `close_incident()` / `narrate_incident()` implementation restored (#1237).

### Security

- Fail-closed defaults across unknown agent/tool/MCP server/MCP tool, on hash
  mismatch, on expired/consumed approvals, and on gateway unreachability for
  mutating/high-risk actions.
- Multi-tenant isolation enforced with tenant-scoped, parameterized SQL only.
- **Log redaction**: recursive JSON redaction + URL query parameter redaction for
  sensitive fields (#1219).
- **Webhook signatures**: HMAC-SHA256 on all outbound webhook notifications (#1218).
- **Hashed agent tokens**: tokens stored as SHA-256 hashes, never plaintext (#1217).
- SQLite foreign key constraints enforced on every connection (#1125).
- 100-tenant cross-tenant isolation stress test (#1221).
- 50-concurrent `consume_approval` stress test (#1220).

### Tests

- Gateway: 53 Rust tests covering authorization decisions, approval lifecycle,
  receipt verification, tenant isolation, concurrent consume stress, WebSocket
  tenant scoping, and cross-language corpus parity.
- Python SDK: 174 tests across 10 test modules covering canonicalization, approvals,
  receipts, async client, webhooks, and scaling.
- Go SDK: corpus vector tests (`TestCanonicalActionVectors`, `TestReceiptChainVectors`),
  client tests, protect tests, receipt verifier tests.
- TypeScript SDK: `tsc --noEmit` build + `node --test` corpus parity suite.

[Unreleased]: https://github.com/lavkushry/AegisAgent/commits/main
