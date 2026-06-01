# AegisAgent Developer Context (`CLAUDE.md`)

This guide outlines build, test, and style guidelines for working on the AegisAgent codebase. Follow these rules to ensure consistency and correct execution.

---

## 1. Build, Run, and Harness Commands

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
- **Run the local gateway server:** `cargo run --manifest-path gateway/Cargo.toml`

### SDK (Python)
- **Install in developer mode:** `pip install -e sdk-python/`
- **Verify package dependencies:** `pip check`

---

## 2. Test Execution Commands

### Gateway Tests (Rust)
- **Run all tests:** `cargo test --manifest-path gateway/Cargo.toml`
- **Run specific test:** `cargo test --manifest-path gateway/Cargo.toml -- <test_name>`

### SDK & Integration Tests (Python)
- **Run all tests:** `python -m unittest discover -s sdk-python`
- **Run the integration mock server test:** `python examples/mock_server.py`

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

Every service component must align with the following standard API endpoint contracts:
- `POST /v1/agents/register` - Registers agent profiles.
- `POST /v1/tools` - Registers static tools.
- `POST /v1/mcp/servers` - Registers MCP servers.
- `POST /v1/authorize` - Intercepts and authorizes tool actions.
- `GET /v1/approvals/:id` - Retrieves state for pending approval requests.
- `POST /v1/approvals/:id/approve` - Approves a frozen action.
- `POST /v1/approvals/:id/reject` - Rejects a frozen action.
- `POST /v1/approvals/:id/edit` - Submits edited parameters for re-evaluation.
- `GET /v1/runs/:id/timeline` - Retrieves chronological investigation run timelines.
- `GET /v1/audit/events` - Retrieves system-wide audit event logs.

---

## 5. Performance and SLO Requirements

All implementations must meet these service level objectives (SLOs) under load:
- **Authorization API Latency:** p95 < 150 ms (Rust gateway logic must evaluate in < 1.5ms to bypass TCP/DB overhead).
- **Policy Evaluation Latency:** p95 < 75 ms (Cedar in-process evaluation).
- **Approval Notification Delivery:** p95 < 5 seconds.
- **MCP Proxy Latency Overhead:** p95 < 250 ms.
- **Audit durabilty:** 99.9% enqueue success.

---

## 6. Coding Guidelines & Best Practices

### Secure Defaults (FAIL-CLOSED)
- **Unidentified Requests:** Deny unknown agents, unknown tools, unknown MCP servers, and unknown MCP tools by default.
- **Mutating Risk Actions:** Critical actions must be denied by default, and high-risk actions must require approval.
- **Signature Verification:** Verify signature tokens on all approval callbacks (e.g. Slack/dashboard integrations).
- **Secret Redaction:** Strip out any passwords, API keys, or JWT tokens from trace payloads and audit logs.

### Multi-Tenant Isolation (CRITICAL)
- **Tenant Context Partitioning:** AegisAgent is a multi-tenant platform. **Every single database read, write, update, or join must be bound to a verified `tenant_id`.**
- **No Cross-Tenant Queries:** Never write SQL queries that omit the `tenant_id` filter unless doing system-wide maintenance (which must be isolated in dedicated, privileged admin modules).
- **SQLx Parameter Binding:** Always pass `tenant_id` as the parameter to SQL queries, and enforce `UUID` validation.

### OpenTelemetry Instrumentation
- **Telemetry-native Spans:** All gateway handlers, policy evaluations, and database query executions must be wrapped in `tracing::info_span!` or `tracing::span!` from the Rust `tracing` crate.
- **Trace Context Propagation:** The Python SDK decorator must propagate the OpenTelemetry context (`traceparent` header) during authorization requests.

### Rust Style & Idioms
- **Async Runtime:** Use Tokio (`#[tokio::main]`) and Axum handlers.
- **Error Handling:** Avoid `.unwrap()` and `.expect()`. Use `?` propagates, map errors to custom HTTP status codes.
- **Database Pooling:** Use `SqlitePool` from SQLx. Ensure WAL (Write-Ahead Logging) mode and busy timeout are configured on database initialization.
