---
title: Current vs Roadmap
description: Clear public status of what AegisAgent supports today and what is planned.
---

# Current vs Roadmap

This page is intentionally direct.

AegisAgent has a working **known-agent integrity MVP** on `main`. The full AI Agent Security Control Plane (unknown-agent runtime isolation + multi-replica production ops) is **partially built** — binaries and APIs exist for several data-plane pieces, but the end-to-end enforcement loop is not complete.

Do **not** claim runtime control over unknown agents until the cage execution loop, sensor collectors, and forced egress path are connected and tested.

For the detailed capability matrix, see [Implementation_Status.md](Implementation_Status.md).

---

## Short version

### Available today (known-agent integrity)

AegisAgent protects **known agents** that integrate through the SDK/gateway.

Strongest current capabilities:

- action authorization before protected tool execution
- deterministic source-trust policy (Cedar)
- approval integrity with exact `action_hash`
- fail-closed SDK verification (Python/Go/TS)
- verifiable hash-chained receipts + verification APIs/CLI
- audit / SOC events, incidents, SOC query API
- MCP Gateway Lite (registry, drift, optional Ed25519 manifest signing)
- prompt/model lineage ingest + Python SDK capture + LLM gateway adapter
- investigation evidence export (events, receipts, checkpoints, graph + redaction manifests, self-receipt)
- compliance evidence pack ZIP
- local Docker Compose demo (gateway + optional sensor/egress)

### Partial (built, not end-to-end production)

- **Node sensor** — binary, register/heartbeat, command poll, shipper; not full process/fs/net collectors
- **Egress proxy** — binary + Helm; not forced for all caged traffic by default
- **Tool broker** — gateway routes + connector libs; not a standalone mandatory binary
- **Agent cage runner** — binary + claim/execute loop; compose profile `cage` + Helm; host Docker security review + hardened create; Docker e2e script/CI (finish + kill) shipped; forced egress still open
- **Console UI** — Bun SPA (`ui-next/`) with full panel suite (approvals, integrity, charts, evidence graph); missing cage/ban/quarantine product pages
- **Deploy** — gateway + sensor + egress + cage + llm-gateway Helm; single-writer SQLite default
- **Postgres** — feature + migrations exist; not the default HA production path

### Roadmap / not done

- cage forced egress + sensor host enforce (P0; Docker finish/kill e2e done)
- sensor real telemetry + host enforce (P0)
- forced egress for unknown agents (P0)
- Postgres multi-replica GA (#1194) (P1)
- OIDC/SAML for console/admin (P1)
- full Phase 9 console (cage, ban/quarantine centers, runtime timelines) (P2)

---

## Capability table

| Capability | Status | What it means |
|---|---:|---|
| Rust gateway | Available today | Axum gateway for authorization, approvals, receipts, audit, MCP Lite, broker routes, runtime control APIs. |
| Python SDK | Available today | `@protect_tool` fails closed on hash mismatch / expired approval / unreachable gateway for high-risk paths; prompt/model emit opt-in. |
| Cedar policy engine | Available today | Deterministic policy decisions for protected action requests. |
| Source-trust gating | Available today | Untrusted external context treated differently from trusted internal. |
| Canonical action hashing | Available today | `aegis-jcs-1` byte-identical across languages. |
| Approval workflow | Available today | Pause, approve, reject, edit, consume; hash-bound. |
| Action receipts | Available today | Hash-chained evidence; optional Ed25519/KMS signing. |
| Receipt verification | Available today | HTTP + Python/Go/TS SDK verifiers; shared `receipt_chain_vectors.json` corpus. |
| MCP Gateway Lite | Available today | Register/discover/pin/drift; optional manifest signature verify. |
| Prompt/model capture | Available today | Ingest APIs + Python SDK + LLM reverse-proxy adapter. |
| Evidence graph | Available today | `/v1/graph/*` for run/incident/agent lineage; console `decision-graph` panel. |
| Investigation evidence export | Available today | `POST /v1/evidence/export` + Integrity UI export. |
| SOC query / incidents | Available today | Async detect/correlate + query API + schema-driven UI. |
| TypeScript SDK | Available today | Canon + protect + client + receipt chain verifier (shared corpus). |
| Go SDK | Partial | Core path shipped; prompt/model emit parity TBD. |
| Full web console | Partial | Bun SPA panel suite shipped; cage/ban/quarantine pages incomplete. |
| Node sensor | Partial | Skeleton binary + packaging; collectors/enforce incomplete. |
| Agent cage runner | Partial | Binary + DockerRuntime + compose + Helm; Docker security review + create hardening + finish/kill e2e done; forced egress open. |
| Egress proxy | Partial | Binary + packaging; not default-forced for cages. |
| Tool broker | Partial | In-gateway execute path; no standalone broker service. |
| Signed control commands | Partial | Issue + sensor poll path; full host enforce incomplete. |
| Ban / quarantine centers | Partial | Stores/APIs; not every choke point + full UI. |
| Postgres production mode | Roadmap / partial | Code path exists; SQLite single-writer is still the default deploy. |
| Full Kubernetes multi-replica | Roadmap | Blocked on Postgres GA + broader Helm surface. |

---

## What you should demo today

Use the current MVP demo:

```bash
docker compose up --build -d
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```

The demo shows:

```text
Untrusted GitHub issue
  → protected GitHub merge action
  → deterministic policy check
  → blocked / approval-bound before execution
  → audit / receipt evidence available
```

See [Quickstart](quickstart.md) and [Demo: malicious GitHub issue](demo-github-attack.md).

---

## What not to claim yet

Do not claim that the current `main` already provides:

- full EDR-like runtime control on arbitrary hosts
- automatic process kill/quarantine for agents that never call the SDK
- default network egress blocking for all agent traffic
- raw credential isolation for every tool path
- complete unknown-agent sandboxing (cage executor not on main)
- multi-replica production Kubernetes on SQLite
- full enterprise SOC console with OIDC

Those remain target architecture goals or incomplete waves (see Implementation Status).

---

## The product direction

AegisAgent is moving toward this architecture:

```text
Control Plane (gateway) — largely shipped
  + Runtime Sensor — skeleton shipped
  + Agent Cage — lib shipped, executor WIP
  + Egress Proxy — binary shipped, force-path WIP
  + Tool Broker — gateway path shipped
  + LLM choke point — adapter shipped
  + Integrity-anchored SOC + evidence export — largely shipped
```

Integrity motto remains: **make the approval trustworthy; trust the source, not the text.**
