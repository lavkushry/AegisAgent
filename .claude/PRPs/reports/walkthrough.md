# AegisAgent Project Status Walkthrough

This report summarizes the current repository context after the MVP launch-readiness update.

---

## Current MVP Capabilities

### Gateway

- Rust Axum gateway with local `127.0.0.1:8080` binding.
- SQLite via SQLx with WAL mode and tenant-scoped data model.
- Cedar policy evaluation from `policies.cedar`/`gateway/policies.cedar`.
- Endpoints for agent registration, static tool registration, authorization, approvals, audit timeline, and MCP Gateway Lite.

### Policy Pack

The default policy pack includes:

1. Cedar implicit deny baseline.
2. Permit read-only/non-mutating actions.
3. Require approval for `github.merge_pull_request` into `main`.
4. Require approval for mutating actions after `semi_trusted_customer` context.
5. Forbid mutating actions after `untrusted_external`, `malicious_suspected`, or `unknown` context.

### MCP Gateway Lite

Implemented controls:

- Register MCP server.
- Discover/upsert MCP tools.
- Show tool manifest.
- Approve/disable MCP tools.
- Deny unknown/unapproved MCP tools by default.
- Audit MCP discovery, status changes, and tool-call attempts.

### Approval Integrity

- Approval records persist `original_call_hash`.
- Authorization responses include approval `action_hash`.
- Approval status responses include `action_hash`.
- Python SDK verifies approval response/status hashes and fails closed on mismatch.

### Python SDK

- `AegisClient` registers agents and calls `/v1/authorize`.
- `@protect_tool` intercepts tool calls, handles allow/deny/require_approval, supports edited approvals, and verifies action hashes.
- SDK tests cover allow, deny, edited approval, and hash mismatch fail-closed behavior.

### Local Launch Assets

- `docker-compose.yml` and `gateway/Dockerfile` for local gateway startup.
- `scripts/seed-demo.sh` for idempotent demo data registration.
- `examples/github-attack-demo.py` for malicious issue → blocked merge demo.
- `README.md` with five-step quickstart.

### Repository Credibility Assets

- `SECURITY.md`
- `CONTRIBUTING.md`
- `ROADMAP.md`
- `.github/workflows/ci.yml`
- `docs/dashboard-mock.html`

---

## Workspace Layout Highlights

```text
AegisAgent/
├── policies.cedar                 # root default policy pack for local/Docker runs
├── docker-compose.yml              # local gateway quickstart
├── gateway/
│   ├── Dockerfile
│   ├── policies.cedar              # package-local policy pack for cargo tests/runs
│   └── src/
├── sdk-python/
│   └── aegisagent/
├── examples/
│   ├── github-attack-demo.py
│   └── mock_server.py
├── scripts/
│   ├── seed-demo.sh
│   └── setup_agent_harness.sh
├── docs/
│   └── dashboard-mock.html
├── .github/workflows/ci.yml
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── ROADMAP.md
├── AGENTS.md
└── CLAUDE.md
```

---

## Validation Commands

Use these for the current baseline:

```bash
cargo test --manifest-path gateway/Cargo.toml
python3 -m unittest discover -s sdk-python/tests
python3 -m py_compile examples/github-attack-demo.py examples/mock_server.py
bash -n scripts/seed-demo.sh
docker compose config
```

---

## Remaining Priority Work

1. Implement real Slack approval callbacks with signature verification and approver-group validation.
2. Add TypeScript SDK parity.
3. Add MCP manifest signing/drift detection.
4. Build runtime MCP proxy execution path.
5. Add OpenTelemetry traceparent propagation from SDK to gateway.
6. Add audit redaction and payload capture controls.
7. Record/link a 90-second demo video.
