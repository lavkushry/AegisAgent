# AegisAgent Phased PR Plan

**Status:** implementation roadmap  
**Date:** 2026-06-28  
**Principle:** precise phased build, not a giant messy PR

---

## 1. Executive summary

AegisAgent should not jump straight into implementation of a giant runtime daemon. The next world-class version requires a deliberate sequence:

1. Preserve and harden the current integrity primitives.
2. Add data models and APIs for runtime control and evidence.
3. Add the node sensor as a separate runtime data-plane binary.
4. Add disposable cage runner.
5. Add egress proxy.
6. Add tool broker.
7. Add prompt/model/tool lineage.
8. Add SOC evidence graph and UI.
9. Production harden.

The highest-risk architectural mistake would be putting untrusted execution into `aegis-gateway`. Do not do that.

---

## 2. Phase 0 — Current repo gap analysis

### 2.1 Files read and assessed

Active root (current production layout — a Cargo workspace):

- `Cargo.toml` (workspace), `src/Cargo.toml`
- `src/src/main.rs`, `src/src/lib.rs`
- `src/src/routes/mod.rs`, `authorize.rs`, `authorize_canon.rs`,
  `authorize_decision.rs`, `authorize_receipts.rs`, `approval.rs`,
  `receipts.rs`, `soc.rs`, `mcp.rs`, `tenant.rs`, `policy.rs`, `webhooks.rs`,
  `graph.rs`, `agents.rs`, `dashboard.rs`
- `lib/api/*`, `lib/common/*`, `lib/storage/*` (incl.
  `migrations/`, `migrations_postgres/`, `db/*.rs`, `sqlite.rs`, `traits.rs`),
  `lib/policy/*`, `lib/soc/*`, `src/canon/*`
- `policies.cedar` (+ `src/policies.cedar`, `lib/policy/policies.cedar`,
  Helm copy — kept byte-identical)
- `sdk-python/*`, `sdk-typescript/*`, `sdk-go/*`, `ui/*`, `mcp-gateway-lite/*`
- `tests/canonical_action_vectors.json`, `tests/receipt_chain_vectors.json`
- `docker-compose.yml`, `helm/*`, `.github/workflows/*`
- `README.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CLAUDE.md`,
  `AGENTS.md`, `docs/*` (incl. `production-hardening.md`)

> Note: an earlier draft of this plan described the workspace as
> `.worktrees/ci-pipeline/*` "reference material" with a single `gateway/` crate
> as the active root. That is **stale** — the workspace is now the active root.
> Any remaining `gateway/` directory is a non-member legacy leftover.

### 2.2 What is already in the right place

- Axum/Tokio Rust gateway foundation.
- SQLx with parameterized SQLite queries.
- `tenant_id` present on current tenant-owned tables.
- Cedar policy engine with fail-closed baseline.
- Deterministic policy direction using source trust.
- Agent registration and token-based authorization.
- Tool action registry.
- MCP server/tool registration, discovery, approve/disable, unknown-tool denial.
- Approval workflow with action hash binding concept.
- SDK fail-closed behavior for denial, approval hash mismatch, expiry, and consume failure.
- Canonicalization corpus shared between Python and Rust tests.
- Receipt chain concept and Python verifier.
- Gateway receipt emission and `/v1/receipts/:id/verify` in active gateway.
- Audit event timeline by run.
- CI for Rust/Python basics.
- Existing docs correctly emphasize approval integrity, provenance gating, and receipts.

### 2.3 Already resolved (not gaps anymore)

Items earlier drafts listed as gaps that are now done on `main`:

- ✅ Root Cargo workspace (`src` + `src/canon` + `lib/{common,api,storage,policy,soc}`).
- ✅ Production Postgres mode + `migrations_postgres/` (SQLx versioned migrations).
- ✅ TypeScript SDK, Go SDK, and Next.js UI all active.
- ✅ Receipt-chain append is transaction-safe under concurrent writers
  (`append_action_receipt_atomic`).
- ✅ Fail-closed durable receipts for protected actions (a protected decision
  returns 500 if its receipt cannot be durably written) + inline receipt identity.
- ✅ Receipt range/head verification (`POST /v1/receipts/verify-range`,
  `GET /v1/receipts/chain-head`) in addition to single + chain verify.
- ✅ JWT-required production mode, public-bind fail-closed startup, and
  admin/metrics/debug endpoint auth gating.
- ✅ DB-backed, multi-instance-safe replay-nonce store (`AEGIS_REPLAY_STORE=db`).
- ✅ Structured `POST /v1/soc/query`; SOC events carry `EventEvidence` linkage.
- ✅ Substantial CI matrix (fmt/clippy/tests/coverage/fuzz/bench/SDK-parity/
  Docker E2E/SAST/secret-scan/container-scan).

### 2.4 Remaining critical gaps (the runtime data plane)

These are the real targets of this plan:

- No `aegis-node-sensor` (runtime sensor daemon + durable local queue).
- No `aegis-cage-runner` (sandboxed executor for unknown/anonymous agents).
- No `aegis-egress-proxy` (network choke point, deny-by-default).
- No `aegis-tool-broker` (credential isolation / authorized action execution).
- No standalone `aegis-mcp-gateway` runtime proxy (current root has MCP
  governance only).
- No runtime-event ingest schema/API (`runtime_events`, prompt/model/tool events).
- No signed gateway→sensor control-command protocol.
- No first-class ban system; no first-class quarantine system.
- No prompt/model capture schema/API or prompt-to-action lineage.
- No receipt Merkle/checkpoint proof (`GET /v1/receipts/:id/proof` deferred).
- No anonymous-agent sandbox enforcement; no egress deny-by-default enforcement.

### 2.5 What is wrongly placed or risky (current state)

- `src/src/routes/authorize.rs` is large (decision pipeline + admission +
  approval-create + receipt + several test modules); keep extracting helpers as
  it grows, but it is already modularized far beyond the old monolith.
- A legacy non-member `gateway/` directory may still exist at root; it should be
  removed or clearly archived so it is never mistaken for the source of truth.
- Gateway must not grow into a fat daemon: the sensor/cage/egress/broker must
  ship as separate binaries (a new `runtime/` workspace area), never inside the
  gateway process.
- Prompt/model/runtime security claims must never exceed the actual choke points
  the deployment enforces (see HLD §5).
- LLM output must remain advisory only — never gate enforcement.

---

## 3. Phase 1 — HLD/LLD/runtime data-plane docs

**Goal:** establish clear architecture and prevent chaotic implementation.

### PR 1.1 — World-class architecture docs

Files:

- `docs/AegisAgent_World_Class_HLD.md`
- `docs/AegisAgent_World_Class_LLD.md`
- `docs/AegisAgent_Runtime_Data_Plane.md`
- `docs/AegisAgent_Agent_Cage.md`
- `docs/AegisAgent_Control_Command_Protocol.md`
- `docs/AegisAgent_Phased_PR_Plan.md`

Acceptance:

- Defines control plane vs runtime data plane separation.
- Lists all choke points.
- Defines current gaps honestly.
- Defines data/API/event/control/receipt models.
- Produces phased PR plan.
- No runtime implementation added.

Tests:

- Docs-only; no code tests required.

---

## 4. Phase 2 — Control-plane data models

**Goal:** add core storage and API contracts for runtime control without sensor/cage implementation.

### PR 2.1 — Workspace and API model extraction

Files:

- root `Cargo.toml`
- `crates/aegis-common`
- `crates/aegis-api`
- minimal migration of shared models from `gateway/src/models.rs`

Acceptance:

- Existing gateway behavior unchanged.
- Existing tests pass.
- API structs for runtime events, commands, bans, quarantine, runs, receipts exist.
- No route behavior changes yet.

Tests:

- existing Rust/Python tests
- model serialization tests

### PR 2.2 — Storage migrations and traits

Files:

- `crates/aegis-storage`
- migrations for SQLite
- Postgres feature scaffold

Tables:

- `agent_runs`
- `agent_sandboxes`
- `runtime_events`
- `control_commands`
- `control_action_results`
- `agent_bans`
- `quarantine_records`
- `receipt_checkpoints`
- `sensor_nodes`
- `sensor_heartbeats`

Acceptance:

- All tenant tables include `tenant_id`.
- SQL is parameterized.
- Existing gateway can still use SQLite.
- Migration tests prove tables and indexes exist.

Tests:

- migration smoke tests
- tenant-isolation query tests

### PR 2.3 — Runtime event ingest APIs

Routes:

- `POST /v1/ingest/runtime-events`
- `GET /v1/runtime/events`
- `GET /v1/runtime/runs/:id/events`

Acceptance:

- Schema validation.
- Dedupe by `(tenant_id, event_id)`.
- Batch ingest supports partial duplicate success.
- No raw secrets in known sensitive fields.

Tests:

- event dedupe
- tenant isolation
- batch ingest
- invalid schema rejected

### PR 2.4 — Control command APIs and signing library

Routes:

- `POST /v1/control/commands`
- `GET /v1/control/commands/:id`
- `POST /v1/control/commands/:id/ack`

Acceptance:

- Commands are canonicalized and signed.
- ACK/NACK stored tenant-scoped.
- No actual local execution yet.
- Receipt emitted for command result where configured.

Tests:

- signature vector tests
- invalid ACK tenant rejected
- command idempotency

### PR 2.5 — Ban and quarantine APIs

Routes:

- `POST /v1/bans`
- `GET /v1/bans`
- `GET /v1/bans/:id`
- `POST /v1/bans/:id/revoke`
- `GET /v1/quarantine`
- `GET /v1/quarantine/:id`
- `POST /v1/quarantine/:id/release`
- `POST /v1/quarantine/:id/delete`

Acceptance:

- Every ban/unban/quarantine/release requires actor and reason.
- Receipts and SOC/audit events emitted.
- Authorization path checks active bans/quarantine before allow/approval.

Tests:

- banned agent cannot authorize
- quarantined agent cannot call tools
- tenant isolation
- receipt emitted

### PR 2.6 — Receipt hardening

Acceptance:

- Receipt append uses transaction-safe chain head.
- Protected action fails closed on receipt write failure.
- Chain head endpoint exists.
- Verify-chain and verify-range design stubs or APIs added.

Tests:

- concurrent receipt append
- receipt write failure blocks protected action
- chain verification

---

## 5. Phase 3 — `aegis-node-sensor` skeleton

**Goal:** runtime data plane starts as a separate binary with safe defaults.

### PR 3.1 — Sensor crate and config

Files:

- `bins/aegis-node-sensor`
- config structs
- identity file handling
- CLI flags

Acceptance:

- Starts and validates config.
- No root-only behavior required yet.
- Structured logs.

Tests:

- config parsing
- invalid config fails closed

### PR 3.2 — Registration and heartbeat

APIs:

- `POST /v1/sensors/register`
- `POST /v1/sensors/:id/heartbeat`

Acceptance:

- Sensor registers and receives config.
- Heartbeat updates sensor status.
- Tenant isolation enforced.

Tests:

- registration
- heartbeat
- wrong tenant rejected

### PR 3.3 — Durable local queue

Acceptance:

- Append-only spool with critical/normal lanes.
- Checksums detect corruption.
- ACK-based compaction.

Tests:

- append/replay
- corruption recovery
- disk budget behavior

### PR 3.4 — Event shipper

Acceptance:

- Ships events to gateway ingest.
- Retries with exponential backoff.
- Gateway down buffers.
- Duplicate event IDs idempotent.

Tests:

- gateway down observe mode buffers
- sensor restart replays queue
- duplicate event ID idempotent

### PR 3.5 — Signed command receiver

Acceptance:

- Polls commands.
- Verifies signatures, tenant, expiry, nonce.
- Executes mock `kill_run` handler.
- ACK/NACKs result.

Tests:

- invalid signature rejected
- expired command rejected
- replay rejected
- ACK stored

### PR 3.6 — Sensor modes

Acceptance:

- Observe/enforce/lockdown state machine.
- Local gateway-down behavior implemented for mock actions.

Tests:

- observe buffers
- enforce blocks controlled action when policy unavailable
- lockdown pauses/kills mock unknown run

---

## 6. Phase 4 — `aegis-cage-runner` skeleton

**Goal:** disposable sandbox executor for unknown agents.

### PR 4.1 — Cage runner crate and runtime trait

Acceptance:

- `SandboxRuntime` trait.
- `SandboxSpec` validation.
- Forbidden mount validation.

Tests:

- no Docker socket
- no host FS by default
- no raw credential env

### PR 4.2 — Docker runtime first implementation

Acceptance:

- start/status/kill simple container.
- isolated temp workspace.
- resource limits best effort.
- read-only root option.

Tests:

- start/kill container
- workspace isolation
- timeout kills run

### PR 4.3 — Gateway cage run APIs

Routes:

- `POST /v1/agent-cage/runs`
- `GET /v1/agent-cage/runs`
- `GET /v1/agent-cage/runs/:id`
- control routes for pause/resume/kill/quarantine

Acceptance:

- Gateway creates run record.
- Gateway sends signed command.
- Sensor/cage mock can execute.

Tests:

- anonymous run start
- kill command execution
- quarantine workspace record

### PR 4.4 — Runtime event emission

Acceptance:

- cage emits `agent_run_started`, `process_started`, `process_exited`, `agent_run_finished`.
- events link to run/sandbox IDs.

Tests:

- timeline contains cage events

---

## 7. Phase 5 — Egress proxy

**Goal:** network choke point.

### PR 5.1 — Egress policy crate

Acceptance:

- domain suffix trie
- CIDR matching
- deny-by-default option
- per-run and per-tenant rules

Tests:

- allowlist domains
- blocklist domains
- CIDR matching
- suffix false-positive safety

### PR 5.2 — Egress check API

Routes:

- `POST /v1/egress/check`
- `GET /v1/egress/events`
- `POST /v1/egress/block`
- `POST /v1/egress/unblock`

Acceptance:

- Fast ban/quarantine/rule check.
- Blocked egress emits event and receipt.

Tests:

- unknown egress block
- high-risk allowed egress receipt
- tenant isolation

### PR 5.3 — Proxy binary skeleton

Acceptance:

- HTTP CONNECT/HTTP proxy first.
- DNS/HTTP/SNI metadata where possible.
- Large upload detection hook.

Tests:

- allowed request forwards
- blocked request denied
- event emitted

---

## 8. Phase 6 — Tool broker

**Goal:** credential and tool/API execution choke point.

### PR 6.1 — Tool broker core

Acceptance:

- connector trait
- canonical action hashing
- credential reference abstraction
- no raw credentials in logs/events

Tests:

- canonical action hash
- redaction

### PR 6.2 — Gateway broker APIs

Routes:

- `POST /v1/tool-broker/execute`
- `GET /v1/tool-broker/tools`
- enable/disable routes

Acceptance:

- Broker calls gateway authorization.
- Approval consume required when needed.
- Receipt emitted before success.

Tests:

- known tool allow
- require approval
- wrong approval hash blocks
- receipt required

### PR 6.3 — Initial connectors

Connectors:

- GitHub mock/real app mode
- HTTP
- filesystem scoped workspace
- shell scoped cage command

Acceptance:

- anonymous agent never receives raw credentials.
- broker returns sanitized output.

Tests:

- GitHub write requires approval
- credential not in cage env/logs/events

---

## 9. Phase 7 — Prompt/model/tool capture

**Goal:** prompt/model lineage where Aegis owns a choke point.

### PR 7.1 — Prompt and model schemas/APIs

Routes:

- `POST /v1/ingest/prompt-events`
- `POST /v1/ingest/model-calls`

Acceptance:

- Stores prompt hash, redacted preview, model/provider, role, trust, run/trace links.
- Raw prompt storage disabled by default.

Tests:

- prompt hashing
- redaction
- tenant isolation

### PR 7.2 — SDK capture

Acceptance:

- Python SDK can emit prompt/model/tool events when configured.
- Known-agent flow links prompt/model/tool/action hash.

Tests:

- no raw sensitive prompt by default
- lineage IDs preserved

### PR 7.3 — LLM gateway adapter

Acceptance:

- proxy captures model call metadata.
- response hash and token metadata stored.

Tests:

- model_call_started/finished events
- failure redaction

---

## 10. Phase 8 — SOC/evidence graph

**Goal:** receipt-backed investigation experience.

### PR 8.1 — Timeline DAG APIs

Routes:

- `GET /v1/runtime/runs/:id/graph`
- `GET /v1/agent-cage/runs/:id/timeline`

Acceptance:

- Graph nodes/edges for prompt/model/tool/runtime/receipt.
- Cursor pagination for large graphs.

Tests:

- prompt-to-action lineage
- receipt linkage

### PR 8.2 — Incident correlation

Acceptance:

- Detection rules for secret access + egress block + control action.
- Incidents created with evidence edges.

Tests:

- SOC incident created
- evidence graph links required nodes

### PR 8.3 — Evidence export

Acceptance:

- Evidence pack includes events, receipts, checkpoints, graph manifest, redaction manifest.
- Export action emits receipt.

Tests:

- evidence pack export
- receipt chain verifies

---

## 11. Phase 9 — Console UI

**Goal:** SOC/approval/control UI that demonstrates the product.

### PR 9.1 — Active root UI scaffold

Pages:

- Overview
- Explore
- Approvals
- Incidents
- Receipts
- Settings

Acceptance:

- Connects to active gateway.
- Auth token configuration.
- Lists approvals/receipts/incidents.

Tests:

- component smoke tests
- Playwright happy path if feasible

### PR 9.2 — Runtime pages

Pages:

- Agents
- Agent Cage Runs
- Runtime Timeline
- Prompt Timeline
- Model Calls
- Tool Calls
- Egress Events

Acceptance:

- Handles 100k events with virtualization or pagination.

### PR 9.3 — Control pages

Pages:

- Ban Center
- Quarantine Center
- MCP Security
- Policy Center
- Evidence Graph

Acceptance:

- Destructive actions require reason.
- UI calls control APIs and shows command/receipt status.

---

## 12. Phase 10 — Production hardening

### PR 10.1 — Auth and admin hardening

Acceptance:

- JWT/OIDC for console/admin APIs.
- Agent tokens hashed.
- Bootstrap lock.
- Public admin route tests.

### PR 10.2 — Postgres production mode

Acceptance:

- Postgres migrations.
- SQLite remains local/dev.
- Tenant isolation tests.

### PR 10.3 — TLS/mTLS

Acceptance:

- mTLS for sensor/gateway optional but supported.
- TLS config validated.

### PR 10.4 — Metrics and OTel

Acceptance:

- OpenTelemetry traces for DB/policy/receipt/event ingest.
- Prometheus metrics for queues, decisions, receipts, commands.

### PR 10.5 — Deployment

Acceptance:

- Docker Compose for local full stack.
- Helm chart for gateway/sensor/cage/proxy/broker/MCP/console.
- Health/readiness checks.

### PR 10.6 — Supply chain and security CI

Acceptance:

- dependency audit blocks except accepted ignores
- SBOM
- container image signing
- secret scanning
- license policy

---

## 13. Cross-phase tests required

### Unit

- canonical action hashing
- prompt hashing/redaction
- receipt hashing
- policy decisions
- ban matching
- egress matching
- command signature verification
- event deduplication
- local spool corruption recovery

### Integration

- known agent allow
- known agent require approval
- approval edit approve consume
- wrong approval hash does not burn approval
- anonymous agent run start
- runtime event ingest
- secret access detection
- unknown egress block
- kill command execution
- ban fingerprint prevents rerun
- quarantine workspace
- receipt emitted for control action
- SOC incident created
- evidence graph links prompt/model/tool/runtime/receipt

### Concurrency

- concurrent receipt append
- concurrent approval consume
- concurrent runtime event ingestion
- concurrent command ACK
- concurrent ban cache invalidation
- multi-sensor event ordering

### Security

- tenant A cannot see tenant B data
- tenant A cannot control tenant B agent
- invalid command signature rejected
- expired command rejected
- replayed command rejected
- raw secret redaction
- banned agent cannot authorize
- quarantined agent cannot call tools
- public admin route rejected
- JWT required in production

### Failure

- gateway down in observe mode buffers
- gateway down in enforce mode blocks
- gateway down in lockdown mode pauses/kills
- DB unavailable for protected action fails closed
- receipt write failure blocks protected action
- sensor restart replays local queue
- duplicate event ID is idempotent

### E2E demo

Malicious anonymous agent path:

1. receives prompt
2. calls model
3. tries to read `.env`
4. tries to install package
5. tries GitHub write through broker
6. tries POST to unknown domain
7. Aegis captures prompt/model metadata
8. detects secret/package behavior
9. blocks egress
10. requires approval for GitHub write
11. kills/pauses run
12. quarantines workspace
13. bans fingerprint if configured
14. emits receipts
15. creates incident
16. shows timeline/UI
17. exports evidence pack
18. verifies receipt chain

---

## 14. PR hygiene rules

- One architecture slice per PR.
- Do not combine refactors with behavior changes.
- No hidden worktree wholesale merges.
- Every new table has tenant isolation tests.
- Every protected action has receipt tests.
- Every queue has bounds and backpressure behavior.
- Every destructive control requires actor and reason.
- Every new binary has a minimal security model in docs.
- Every route has typed request/response models.
- Every external effect has idempotency guidance.

---

## 15. Exact next recommended PR

**Next PR:** Phase 1 docs-only PR.

Title:

```text
docs: define world-class AegisAgent control plane and runtime data plane architecture
```

Files:

- `docs/AegisAgent_World_Class_HLD.md`
- `docs/AegisAgent_World_Class_LLD.md`
- `docs/AegisAgent_Runtime_Data_Plane.md`
- `docs/AegisAgent_Agent_Cage.md`
- `docs/AegisAgent_Control_Command_Protocol.md`
- `docs/AegisAgent_Phased_PR_Plan.md`

Why this PR first:

- It creates the shared blueprint.
- It prevents a fat daemon implementation.
- It codifies choke points and honest limitations.
- It gives the team a sequenced path from the current MVP to a runtime control plane.

Validation:

- Docs review by architecture/security/backend/ops.
- No code tests required.
- Optional: run existing CI to prove docs did not affect code.

After that, the next code PR should be **Phase 2.1: workspace and API model extraction**, keeping behavior unchanged and preserving the active gateway tests.
