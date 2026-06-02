# AegisAgent

[![CI configured](https://img.shields.io/badge/CI-configured-blue)](.github/workflows/ci.yml)

AegisAgent is the **integrity layer for AI agent actions** — open, self-hostable, and framework-neutral. It sits between an agent runtime and external actions and does two things that the now-commodity gateway market decides but does **not prove**:

1. **Provable approvals.** Every high-risk action is frozen and SHA-256 hashed; the human approval is bound to that exact action, and the SDK **fails closed** if a different action is about to execute. *An approval is valid for exactly one action* — defeating approve-then-swap, replay, and render-vs-bytes ("approval manipulation," OWASP Agentic Top 10).
2. **Deterministic trust-provenance gating.** Authorization is gated on *where the triggering content came from* (six trust levels), not a probabilistic text score. A mutating action triggered by untrusted external content is denied/escalated regardless of how benign the text looks — the confused-deputy defense at the policy layer.

Every protected action emits a verifiable, hash-chained **action receipt** suitable as SOC 2 / EU AI Act Article 14 evidence. AegisAgent runs standalone **or layers onto** an existing gateway (e.g. Microsoft Agent Governance Toolkit, MintMCP, Pipelock).

> **Make the approval trustworthy. Trust the source, not the text.**

> ℹ️ **Positioning context (June 2026):** the generic "intercept → policy → allow/deny → audit → approval" loop is now commodity, including free OSS. AegisAgent deliberately competes only on *integrity + provenance + verifiable evidence*. See [`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md) for the full competitor analysis and rationale.

## Current MVP Status

| Area | Status |
| --- | --- |
| Rust gateway | Implemented with Axum, SQLite/SQLx, Cedar policy loading, healthcheck, audit and approval endpoints |
| Python SDK | Implemented `AegisClient` and `@protect_tool` with **fail-closed** deny/approval handling and **approval action-hash verification** (the core integrity primitive) |
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

## No-setup integrity demo

To see the three integrity guarantees without running the gateway (pure Python, no network):

```bash
python3 examples/integrity_demo.py
```

It demonstrates: (1) a deterministic **provenance gate** denying an untrusted-triggered mutation, (2) **approve-then-swap** failing closed on an `action_hash` mismatch, and (3) **verifiable receipts** detecting tampering. Auditors can verify receipts independently with `aegis-verify-receipts <receipts.json>`.

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

> 📌 The strategy docs in `docs/` were re-anchored on 2026-06-02 from the original "Agent Action Firewall" framing to the **integrity-layer** positioning above. Start with the reassessment doc.

- [`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md) — **source of truth**: June-2026 competitor matrix, the real gap, and repositioning.
- `docs/AegisAgent_PRD.md` — product requirements (integrity primitives as headline features).
- `docs/AegisAgent_GTM_Document.md` — positioning, ICP, pricing, competitive landscape.
- `docs/# AegisAgent — In-Depth Technical D.md` — architecture (Approval Integrity Engine, Trust-Provenance Gate, Verifiable Receipts).
- `docs/AegisAgent_Threat_Model.md` — foregrounds approval manipulation, confused-deputy, and evidence tampering.
- `docs/# AegisAgent — Deep Agent Workflow.md`, `docs/# AegisAgent — Depth Vision Document.md`, `docs/# AegisAgent — Deep Market Gap Anal.md`, `docs/# AegisAgent — In-Depth Problem Def.md`, `docs/AegisAgent_Operational_Design.md`, `docs/AgentGuard_Product_Research.md`.
- `CLAUDE.md` — agent/developer commands, security rules, and API contracts.
- `AGENTS.md` — persona boundaries for Architect, Developer, SecurityAuditor, and Ops agents.
- `SECURITY.md` — vulnerability disclosure and secure development expectations.
- `CONTRIBUTING.md` — local development and contribution rules.
- `ROADMAP.md` — MVP and post-MVP roadmap.
- `docs/dashboard-mock.html` — static audit timeline/dashboard mock.
