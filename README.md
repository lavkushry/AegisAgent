# AegisAgent

[![CI configured](https://img.shields.io/badge/CI-configured-blue)](.github/workflows/ci.yml)

AegisAgent is an **Agent Action Firewall** for AI agents and MCP tools. It sits between an agent runtime and external actions, evaluates Cedar policies, pauses risky actions for approval, denies untrusted mutations, and writes audit events.

## Current MVP Status

| Area | Status |
| --- | --- |
| Rust gateway | Implemented with Axum, SQLite/SQLx, Cedar policy loading, healthcheck, audit and approval endpoints |
| Python SDK | Implemented `AegisClient` and `@protect_tool` with fail-closed deny/approval handling and approval action-hash verification |
| Default policy pack | Implemented at `policies.cedar` and `gateway/policies.cedar` |
| MCP Gateway Lite | Implemented server registration, tool discovery/manifest, approve/disable controls, unknown-tool deny, and MCP audit events |
| Local demo | Implemented `scripts/seed-demo.sh` and `examples/github-attack-demo.py` |
| Launch docs | Added quickstart, security policy, contribution guide, roadmap, CI, and dashboard mock |

## 5-Step Quickstart

> Requirements: Docker with Compose, `python3`, and `bash`.
>
> The compose setup uses host networking so the gateway still binds to `127.0.0.1:8080` as required by the security rules.

### 1. Clone and enter the repository

```bash
git clone https://github.com/example/aegisagent.git
cd AegisAgent
```

### 2. Start the local gateway

```bash
docker compose up --build
```

Expected health output in another terminal:

```bash
curl http://127.0.0.1:8080/health
# healthy
```

### 3. Seed demo data

```bash
bash scripts/seed-demo.sh
```

Expected output:

```text
==> Gateway is healthy
==> Registering demo agent (coding-agent-prod)
==> Registering mock GitHub tool actions
==> Registering demo MCP server and manifest
==> Demo seed complete. Run: python3 examples/github-attack-demo.py
```

### 4. Run the GitHub prompt-injection attack demo

```bash
python3 examples/github-attack-demo.py
```

Expected output includes:

```text
AegisAgent blocked the malicious merge attempt
Audit URL: http://127.0.0.1:8080/v1/audit/events
Expected outcome: blocked mutation after untrusted external context.
```

### 5. Inspect audit events

```bash
curl -H "Authorization: Bearer tenant_123" \
  http://127.0.0.1:8080/v1/audit/events
```

## Default Policy Pack

The default Cedar policy pack lives in both:

- `policies.cedar` for local/Docker gateway runs from the repository root.
- `gateway/policies.cedar` for gateway package tests and direct package runs.

Starter behavior:

1. Cedar implicit deny is the deny-all baseline.
2. Read-only actions are allowed.
3. `github.merge_pull_request` into `main` requires platform approval.
4. Mutations after semi-trusted customer context require security review.
5. Mutations after untrusted, suspicious, or unknown context are denied.

## Key API Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Local healthcheck |
| `POST /v1/agents/register` | Register or retrieve an agent token |
| `POST /v1/tools` | Register static tool actions |
| `POST /v1/mcp/servers` | Register MCP servers |
| `GET/POST /v1/mcp/servers/:server_key/tools` | Show/discover MCP tools |
| `POST /v1/mcp/servers/:server_key/tools/:tool_key/approve` | Approve an MCP tool |
| `POST /v1/mcp/servers/:server_key/tools/:tool_key/disable` | Disable an MCP tool |
| `POST /v1/authorize` | Authorize an intercepted tool call |
| `GET /v1/approvals/:id` | Poll approval status |
| `POST /v1/approvals/:id/approve` | Approve a paused action |
| `POST /v1/approvals/:id/reject` | Reject a paused action |
| `POST /v1/approvals/:id/edit` | Approve with edited parameters |
| `GET /v1/audit/events` | View recent audit events |
| `GET /v1/runs/:id/timeline` | View run-specific audit timeline |

## Development Validation

```bash
cargo test --manifest-path gateway/Cargo.toml
python3 -m unittest discover -s sdk-python/tests
```

Optional checks:

```bash
cargo fmt --manifest-path gateway/Cargo.toml -- --check
cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings
```

## Project Docs

- `CLAUDE.md` — agent/developer commands, security rules, and API contracts.
- `AGENTS.md` — persona boundaries for Architect, Developer, SecurityAuditor, and Ops agents.
- `SECURITY.md` — vulnerability disclosure and secure development expectations.
- `CONTRIBUTING.md` — local development and contribution rules.
- `ROADMAP.md` — MVP and post-MVP roadmap.
- `docs/dashboard-mock.html` — static audit timeline/dashboard mock.
