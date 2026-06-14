# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [Unreleased]

### Added

- **TASK-0088 (#934): `detection_rules` table + management API**. New
  migration `0008_detection_rules.sql` adds a tenant-scoped, indexed table
  (`rule_key`, `name`, `severity`, `condition`, `summary_template`,
  `enabled`) managed via `POST/GET /v1/detection_rules` (upsert by
  `(tenant_id, rule_key)`) and `DELETE /v1/detection_rules/:id`. This is the
  additive first step ("the migration issue") referenced by SOC-003 (#1186):
  loading these rows as a YAML-driven detection DSL that replaces the
  hardcoded Rust functions in `detect.rs` (`confused_deputy_block`,
  `approval_required_surface`, etc.) is deferred as separate, larger-scope
  work.
- **Tenant-managed API keys** (TASK-0093, #939): new `api_keys` table
  (`gateway/migrations/0007_api_keys.sql`) plus management endpoints
  `POST /v1/api_keys` (returns the plaintext key exactly once;
  `sha256(key)` is the only thing persisted, mirroring
  `agents.agent_token`), `GET /v1/api_keys`, and
  `POST /v1/api_keys/:id/revoke`. This is an additive first step; wiring
  `api_keys` into the `TenantId` extractor's authentication path (replacing
  the `tenant_<id>` bearer-token heuristic) is deferred as a separate
  cross-cutting security task.
- **Fuzz testing for `aegis-jcs-1` canonicalization** (TEST-002, #1162): the
  canonicalization logic was extracted into a new `aegis-canon` crate
  (`gateway/canon/`), shared by the gateway (via path dependency, delegated
  from `routes::canonicalize_json`/`canonical_action_string`) and two new
  `cargo-fuzz` targets in `gateway/fuzz/` — `canonicalize_json` (arbitrary
  JSON) and `canonical_value_string` (arbitrary `AuthorizeToolCall`-shaped
  input). A 60s smoke run gates PRs (`canon-fuzz` job in `ci.yml`); a nightly
  workflow (`canon-fuzz.yml`) runs each target for 1 hour.
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
- **SOC incident deduplication (SOC-005)**: repeat incidents for the same
  `(tenant_id, agent_id, kind)` within a configurable window (default 1 hour,
  `AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS`) are merged into the existing open
  `soc_incidents` row (`db::upsert_soc_incident`) instead of creating a new
  one — `source_event_ids` are unioned and `summary`/`opened_at` are bumped to
  the latest occurrence, suppressing duplicate Phase 2 incident notifications.
- Self-contained, zero-setup integrity demo (`examples/integrity_demo.py`).
- OSS project scaffolding: MIT `LICENSE`, `CODE_OF_CONDUCT.md`, issue/PR
  templates, Dependabot, and hardened CI.
- **CI matrix**: Rust (stable + beta + MSRV 1.88), Python (3.9–3.12), Go SDK,
  TypeScript SDK, cross-language corpus byte-equality gate, Docker Compose E2E,
  blocking dependency audits (cargo-audit + pip-audit) (#1170).
- **MkDocs Material docs site**: auto-deployed to GitHub Pages on push to `main`.
- **End-to-end SOC pipeline test** (TEST-001, #1161): a single test feeds
  events through the full Phase 0-3/5 pipeline (emit → detect → correlate →
  persist → notify), asserting a `confused_deputy_block` alert and a
  `deny_storm` incident are persisted to `soc_alerts`/`soc_incidents` and a
  HIGH notification is delivered to a mock webhook sink.
- **DB-001 (#1191): versioned `sqlx` migrations**. New `gateway/migrations/`
  directory (starting with `0001_baseline.sql`, the full current schema written
  with `IF NOT EXISTS`) applied via `sqlx::migrate!("./migrations")`, tracked in
  `_sqlx_migrations`. The legacy ad-hoc inline schema bootstrap
  (`db::bootstrap_legacy_schema`, formerly `run_migrations`) still runs first on
  every startup for backward compatibility with pre-existing databases, so the
  baseline migration is a no-op there too. All future schema changes ship as new
  numbered files via `sqlx migrate add`.
- **DB-007 (#932): `mcp_servers.last_discovery_at`**. New migration
  `0002_mcp_servers_last_discovery_at.sql` adds a nullable timestamp column,
  stamped via `db::touch_mcp_server_discovery` on every
  `POST /v1/mcp/servers/:server_key/tools` discovery call, surfaced on
  `McpServerRecord`/`GET /v1/mcp/servers` so operators can see manifest
  staleness alongside `manifest_hash`.
- **TASK-0089 (#935): `agent_risk_scores` table**. New migration
  `0005_agent_risk_scores.sql` adds a tenant-scoped, indexed table that
  records one row per `/v1/authorize` decision via
  `db::insert_agent_risk_score`, capturing the computed risk score and reason
  linked to the originating `decisions` row. Gives operators a per-agent risk
  trend over time instead of only the latest decision's score.
- **TASK-0090 (#936): `mcp_manifest_snapshots` table**. New migration
  `0003_mcp_manifest_snapshots.sql` adds a tenant-scoped, indexed table that
  records one row per `POST /v1/mcp/servers/:server_key/tools` discovery call,
  capturing the computed `mcp-manifest-1` hash and the raw discovered tool list
  via `db::insert_mcp_manifest_snapshot`. Gives operators an audit trail to diff
  against when investigating an `mcp_manifest_drift` alert.

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

- **#1301: Audit event missing decision_id linkage**. `audit_events` (and
  its `audit_events_archive` counterpart) gained nullable `decision_id` and
  `approval_id` columns (migration `0009_audit_events_decision_linkage.sql`,
  plus a new `idx_audit_events_tenant_decision` index), so operators and
  compliance can correlate the full audit trail for a single authorization
  decision or approval. Every decision-related audit event
  (`tool_call_intercepted`, etc.) now carries its `decision_id`, and every
  approval-lifecycle event (`approval_created`, `approval_decided`,
  `tamper_attempt`) carries both `approval_id` and the originating
  `decision_id`. `GET /v1/audit/events` accepts an optional `?decision_id=`
  filter (tenant-scoped, parameterized `(? IS NULL OR decision_id = ?)`).
- **#1299: High-risk action allowed when audit writer is unavailable**. The
  `/v1/authorize` decision path could return `allow`/`require_approval` for a
  mutating or high-risk action even when the audit trail for that decision
  could not be persisted — violating the fail-closed law "audit unavailable
  → do not execute critical action." The gateway now health-checks the SOC
  event stream (`EventSink::has_capacity`) before the main decision write: if
  the channel is full, or if `write_decision_and_audit` fails (e.g. SQLite
  write error), a mutating or non-`"low"`-risk action is denied with
  `reason` containing `audit_writer_unavailable` and
  `matched_policies: ["audit_writer_unavailable"]`. Read-only, low-risk
  actions instead degrade gracefully — they are still allowed, with a warning
  logged, since they have no destructive side effect to gate. A new
  `AppState.audit_writer_unhealthy` flag tracks the most recent DB-write
  outcome and is now surfaced on `GET /readyz` as `"audit_writer": "up"|"down"`.
- **#1336: MCP manifest-drift severity classification + diff**. Re-discovering
  an MCP server's tool manifest used to fire a single hardcoded
  `"high"`-severity `mcp_manifest_drift` alert on *any* hash change. The
  gateway now diffs the new manifest against the most recent prior
  `mcp_manifest_snapshots` row (`classify_manifest_drift` in `routes.rs`) and
  classifies the change as `tool_added`/`tool_removed` (high),
  `tool_modified` — e.g. a new optional parameter on an existing tool's
  `input_schema` (medium), or `metadata_changed` — name/description only
  (low). The classification and a tool-key-only diff are carried in the
  `AseEvent.reason`/`risk_score`, and `detect::mcp_manifest_drift` derives the
  SOC alert severity from `risk_score` instead of a flat `"high"`. Adding a
  parameter to an existing tool now still triggers drift, but as a
  medium-severity alert rather than being indistinguishable from a brand-new
  or removed tool.
- **BUG-001, BUG-002, BUG-003**: auth and tenant isolation vulnerabilities (#1212).
- **BUG-004, BUG-005**: lock poisoning panics in policy and events modules (#1213).
- `edit_approval` re-hashes edited call and rejects if already decided (#1121).
- Python SDK `close_incident()` / `narrate_incident()` implementation restored (#1237).
- **Build regression**: the #939/#1261 merge to `main` referenced
  `db::create_api_key`, `db::list_api_keys`, `db::revoke_api_key`, and an
  `ApiKeyRecord` model from `routes.rs` without adding them, and never wired
  `/v1/api_keys` (`GET`/`POST`) or `/v1/api_keys/:id/revoke` into the router —
  leaving `main` unable to compile. Adds the missing tenant-scoped,
  parameterized `db.rs` functions and `ApiKeyRecord`, wires the routes,
  documents them in `GET /v1/openapi.json`, and adds
  `test_api_key_crud_route` covering create/list/revoke/revoke-again/list.

- **#1335: MCP tool/server identifier normalization**. `/v1/authorize`
  resolved the `mcp:` server prefix and looked up `mcp_servers`/`mcp_tools`
  rows using the caller-supplied `tool`/`action` strings verbatim. A request
  with a different letter case (`MCP:github-mcp`), percent-encoding
  (`mcp%3Agithub-mcp`, `create%5Fissue`), or other Unicode form for the same
  identifier would make `mcp_server_key_from_tool` miss the `mcp:` prefix
  entirely, **skipping the deny-by-default "unknown MCP server/tool" checks**
  and falling through to the generic Cedar policy evaluation. `routes.rs` now
  normalizes (`normalize_tool_identifier`: percent-decode, Unicode NFC,
  lowercase) the `tool`/`action` identifiers once before any MCP/skill-action
  lookup; the `action_hash`/canonicalized payload still uses the original,
  un-normalized values. Adds
  `authorize_denies_unknown_mcp_tool_with_encoded_or_cased_identifier` and
  `authorize_allows_approved_mcp_tool_with_encoded_or_cased_identifier`.

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
- `GET /v1/audit/events` tenant-isolation and 100-row cap test (#1006).
- `GET /v1/runs/:id/timeline` chronological-order and run-scoping test (#1005).
- `discover_mcp_tools` registers a `skills`/`skill_actions` row per discovered
  MCP tool, with `default_decision`/`approval_required`/`risk`/`mutates_state`
  derived from the manifest, retrievable via `db::get_skill_action` (#998).
- `aegis-jcs-1` canonicalization sorts object keys independently at every
  nesting level, verified 3 levels deep (#1001).
- `POST /v1/receipts/verify-chain` verifies a clean 1000-entry receipt chain
  end-to-end and detects tampering with an entry in the middle of the chain
  (#1003).

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
