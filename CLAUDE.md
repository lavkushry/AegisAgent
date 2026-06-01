# AegisAgent Developer Context (`CLAUDE.md`)

This guide is the active coding-agent context for AegisAgent. It captures current project status, launch commands, endpoint contracts, and security rules.

---

## 0. Current Project Status

AegisAgent MVP is now past basic skeleton stage and has the following implemented pieces:

- Rust Axum gateway with SQLite/SQLx persistence and Cedar policy evaluation.
- Tenant-scoped agent registry, tool registry, approval records, audit events, MCP server/tool records, and decision records.
- Default Cedar policy pack in `policies.cedar` and `gateway/policies.cedar`.
- MCP Gateway Lite: register server, discover manifest, approve/disable tools, deny unknown/unapproved MCP tools, and log MCP calls.
- Python SDK with `AegisClient` and `@protect_tool` decorator.
- Approval action-hash integrity: approvals return and persist `action_hash`; SDK fails closed if approval/status hashes mismatch.
- Docker Compose local gateway startup, seed script, GitHub attack demo, CI workflow, security policy, contribution guide, roadmap, and dashboard mock.

Remaining high-priority gaps after this update:

- Real Slack callback signature verification and approver role lookup.
- TypeScript SDK.
- Runtime MCP proxy execution path beyond authorization/manifest governance.
- Policy bundle versioning/dry-run and dashboard implementation.
- Demo video/hosted sandbox.

---

## 1. Build, Run, and Harness Commands

### Local Docker Quickstart

```bash
docker compose up --build
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```

Healthcheck:

```bash
curl http://127.0.0.1:8080/health
```

### Agent Context Harness (ECC-Style)

- **Initialize Developer Profile:** `bash scripts/setup_agent_harness.sh --profile developer`
- **Initialize Auditor Profile:** `bash scripts/setup_agent_harness.sh --profile auditor`
- **Initialize Architect Profile:** `bash scripts/setup_agent_harness.sh --profile architect`
- **Initialize Ops Profile:** `bash scripts/setup_agent_harness.sh --profile ops`
- **Initialize All Profiles:** `bash scripts/setup_agent_harness.sh --all`
- **Clean Harness Configuration:** `bash scripts/setup_agent_harness.sh --clean`

### Gateway (Rust + Axum + SQLx + SQLite)

- **Check code compiles:** `cargo check --manifest-path gateway/Cargo.toml`
- **Build debug binary:** `cargo build --manifest-path gateway/Cargo.toml`
- **Build production release:** `cargo build --release --manifest-path gateway/Cargo.toml`
- **Run the local gateway from repo root:** `CEDAR_POLICY_PATH=policies.cedar cargo run --manifest-path gateway/Cargo.toml`
- **Run package-local tests:** `cargo test --manifest-path gateway/Cargo.toml`

### SDK (Python)

- **Install in developer mode:** `python3 -m pip install -e sdk-python/`
- **Run SDK tests:** `python3 -m unittest discover -s sdk-python/tests`
- **Run attack demo:** `python3 examples/github-attack-demo.py`

---

## 2. Test Execution Commands

### Gateway Tests (Rust)

- **Run all tests:** `cargo test --manifest-path gateway/Cargo.toml`
- **Run specific test:** `cargo test --manifest-path gateway/Cargo.toml -- <test_name>`

### SDK & Demo Tests (Python)

- **Run all tests:** `python3 -m unittest discover -s sdk-python/tests`
- **Syntax check examples/scripts:** `python3 -m py_compile examples/github-attack-demo.py examples/mock_server.py`
- **Demo seed script syntax:** `bash -n scripts/seed-demo.sh`

---

## 3. Formatting and Linting

### Rust (Gateway)

- **Check formatting:** `cargo fmt --manifest-path gateway/Cargo.toml -- --check`
- **Apply formatting:** `cargo fmt --manifest-path gateway/Cargo.toml`
- **Run linter:** `cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings`

### Python (SDK & Examples)

- **Check formatting:** `black --check sdk-python/ examples/`
- **Apply formatting:** `black sdk-python/ examples/`
- **Run linter:** `flake8 sdk-python/ examples/`

---

## 4. API Endpoints & Contract Scopes

Every service component must align with these API endpoint contracts:

- `GET /health` - Gateway healthcheck.
- `POST /v1/agents/register` - Registers agent profiles and returns agent tokens.
- `POST /v1/tools` - Registers static tools and action metadata.
- `POST /v1/mcp/servers` - Registers MCP servers.
- `GET /v1/mcp/servers/:server_key/tools` - Shows MCP tool manifest.
- `POST /v1/mcp/servers/:server_key/tools` - Discovers/upserts MCP tool manifest entries.
- `POST /v1/mcp/servers/:server_key/tools/:tool_key/approve` - Approves an MCP tool.
- `POST /v1/mcp/servers/:server_key/tools/:tool_key/disable` - Disables an MCP tool.
- `POST /v1/authorize` - Intercepts and authorizes tool actions.
- `GET /v1/approvals/:id` - Retrieves pending approval status and `action_hash`.
- `POST /v1/approvals/:id/approve` - Approves a frozen action.
- `POST /v1/approvals/:id/reject` - Rejects a frozen action.
- `POST /v1/approvals/:id/edit` - Submits edited parameters for re-evaluation/execution.
- `GET /v1/runs/:id/timeline` - Retrieves chronological investigation run timelines.
- `GET /v1/audit/events` - Retrieves recent audit event logs.

---

## 5. Performance and SLO Requirements

All implementations should target these service level objectives:

- **Authorization API Latency:** p95 < 150 ms.
- **Policy Evaluation Latency:** p95 < 75 ms.
- **Approval Notification Delivery:** p95 < 5 seconds.
- **MCP Proxy Latency Overhead:** p95 < 250 ms.
- **Audit durability:** 99.9% enqueue success.

---

## 6. Coding Guidelines & Best Practices

### Secure Defaults (FAIL-CLOSED)

- **Unidentified Requests:** Deny unknown agents, unknown tools, unknown MCP servers, and unknown MCP tools by default.
- **Mutating Risk Actions:** Critical actions require approval unless explicit policy denies them; untrusted context mutations are denied.
- **Approval Integrity:** Every approval must bind to the original SHA-256 action hash. SDKs must fail closed on missing/mismatched hashes.
- **Signature Verification:** Verify signature tokens on all external approval callbacks (Slack/Teams/dashboard integrations).
- **Secret Redaction:** Strip passwords, API keys, and JWT tokens from traces, demo output, and audit logs.

### Multi-Tenant Isolation (CRITICAL)

- **Tenant Context Partitioning:** Every database read, write, update, and join over tenant-owned data must bind/filter by verified `tenant_id`.
- **No Cross-Tenant Queries:** Avoid SQL that omits `tenant_id` unless it is dedicated privileged maintenance code.
- **SQLx Parameter Binding:** Use parameterized SQL only; never interpolate user input into SQL strings.

### Policy Pack Rules

- Keep root `policies.cedar` and `gateway/policies.cedar` synchronized.
- Cedar implicit deny is the deny-all baseline.
- Avoid broad `permit(principal, action, resource)` rules unless constrained by context/resource checks.
- Add tests for every new allow, deny, and require_approval path.

### OpenTelemetry Instrumentation

- Wrap critical gateway handlers, policy evaluations, and DB operations in Rust `tracing` spans where practical.
- Python SDK should propagate trace context in authorization requests as SDK support matures.

### Rust Style & Idioms

- Use Tokio (`#[tokio::main]`) and Axum handlers.
- Avoid `.unwrap()`/`.expect()` in production paths; map errors to HTTP status codes.
- Use `SqlitePool` with WAL mode and busy timeout.

---

## 7. MVP Launch Checklist Snapshot

### P0 Complete

- Root `policies.cedar` default pack.
- Docker Compose local gateway startup.
- Python SDK `@protect_tool` decorator.
- GitHub attack demo script.
- Idempotent seed script.
- README quickstart.

### P1 Mostly Complete

- `SECURITY.md`.
- `CONTRIBUTING.md`.
- GitHub Actions CI.
- `ROADMAP.md`.
- `docs/dashboard-mock.html`.

### P1 Pending

- 90-second recorded demo video/link.
