# Implementation Plan: MVP Launch Readiness and Project Context Refresh

This plan supersedes the earlier skill-only integration plan. The skill runbooks and harness updates are complete; the active focus is MVP launch readiness for the AegisAgent gateway, Python SDK, policies, local demo, and repository trust assets.

---

## Current Implemented Baseline

- Rust Axum gateway with SQLite/SQLx migrations and Cedar Policy evaluation.
- Tenant-scoped agent, tool, MCP server/tool, decision, approval, and audit records.
- Python SDK with `AegisClient` and `@protect_tool`.
- Approval polling with SHA-256 action-hash integrity checks.
- MCP Gateway Lite controls: server registration, tool discovery, manifest display, approve/disable, unknown-tool denial, and audit logging.
- Default Cedar policy pack in both `policies.cedar` and `gateway/policies.cedar`.
- Local Docker Compose startup, seed script, and GitHub prompt-injection attack demo.
- Repository trust assets: `SECURITY.md`, `CONTRIBUTING.md`, `ROADMAP.md`, CI workflow, and dashboard mock.

---

## P0 MVP Launch Tasks

1. **Default policy pack**
   - Root `policies.cedar` exists.
   - Gateway package policy file is synchronized.
   - Starter controls: implicit deny baseline, allow read-only, require approval for main merge, require approval for semi-trusted mutation, deny untrusted mutation.

2. **Docker Compose quickstart**
   - `docker-compose.yml` builds/runs the gateway.
   - `gateway/Dockerfile` provides release container and curl healthcheck.
   - Gateway uses `CEDAR_POLICY_PATH=/app/policies.cedar` and SQLite at `/data/aegis.db`.

3. **Python SDK decorator**
   - `@protect_tool` calls `/v1/authorize`.
   - Deny and unexpected decisions fail closed.
   - Approval responses and approval-status polls verify `action_hash`.

4. **Attack demo**
   - `examples/github-attack-demo.py` simulates malicious public issue content followed by a blocked merge.
   - Prints the audit endpoint URL and recent audit event summary.

5. **Seed script**
   - `scripts/seed-demo.sh` is idempotent and registers demo agent, GitHub tool actions, and demo MCP manifest.

6. **README quickstart**
   - Five-step copy-paste flow: clone, compose up, seed, run demo, inspect audit.

---

## P1 Credibility Tasks

- `SECURITY.md`: responsible disclosure policy and secure-development expectations.
- `CONTRIBUTING.md`: test/lint commands and policy contribution rules.
- `.github/workflows/ci.yml`: Rust format/clippy/tests and Python SDK tests.
- `ROADMAP.md`: Q3/Q4/post-MVP plan.
- `docs/dashboard-mock.html`: static audit timeline dashboard mock.
- Demo video remains pending outside code changes.

---

## Remaining Engineering Priorities

1. Slack approval callback signature verification and approver-group authorization.
2. TypeScript SDK parity with Python SDK.
3. MCP manifest signing and drift detection.
4. Runtime MCP proxy execution path.
5. OpenTelemetry traceparent propagation in Python SDK requests.
6. Audit payload redaction and configurable capture levels.
7. GitHub App/PR comment integration.

---

## Verification Plan

Run before handing off changes:

```bash
cargo test --manifest-path gateway/Cargo.toml
python3 -m unittest discover -s sdk-python/tests
python3 -m py_compile examples/github-attack-demo.py examples/mock_server.py
bash -n scripts/seed-demo.sh
docker compose config
```

Optional when Docker daemon is available:

```bash
docker compose up --build
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```
