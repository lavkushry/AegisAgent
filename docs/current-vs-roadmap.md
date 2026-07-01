---
title: Current vs Roadmap
description: Clear public status of what AegisAgent supports today and what is planned.
---

# Current vs Roadmap

This page is intentionally direct.

AegisAgent has a working MVP, but the full AI Agent Security Control Plane is a roadmap.

The project should not claim runtime control over unknown agents until the runtime data-plane components exist and are connected to real choke points.

---

## Short version

## Available today

AegisAgent currently protects known agents that integrate through the SDK/gateway.

The strongest current capabilities are:

- action authorization before protected tool execution
- deterministic source-trust policy
- approval integrity with exact `action_hash`
- fail-closed SDK verification
- verifiable receipts
- audit events
- MCP Gateway Lite governance primitives
- local Docker Compose demo

## Roadmap

The target system adds runtime control for unknown or non-cooperative agents:

- node sensor
- agent cage runner
- egress proxy
- tool broker
- signed control commands
- ban/quarantine system
- prompt/model/tool/runtime timeline
- SOC evidence graph and console

---

## Capability table

| Capability | Status | What it means |
|---|---:|---|
| Rust gateway | Available today | Local Axum gateway for authorization, approvals, receipts, audit, and MCP Lite governance. |
| Python SDK | Available today | `@protect_tool` can wrap known-agent tool functions and fail closed if authorization or approval verification fails. |
| Cedar policy engine | Available today | Deterministic policy decisions for protected action requests. |
| Source-trust gating | Available today | Policy can treat untrusted external context differently from trusted internal context. |
| Canonical action hashing | Available today | Exact actions are canonicalized and hashed for approval integrity. |
| Approval workflow | Available today | Risky actions can be paused, approved, rejected, edited, and consumed. |
| Approval hash binding | Available today | Approval is bound to the exact action hash, reducing approve-then-swap risk. |
| Action receipts | Available today | Protected decisions can emit hash-chained evidence receipts. |
| Receipt verification endpoint/CLI | Available today | Receipts can be recomputed and checked for tampering. |
| Audit events | Available today | Recent protected decisions can be inspected through API endpoints. |
| MCP Gateway Lite | Available today | MCP server/tool registration, discovery, approval/disable controls, unknown-tool denial, and MCP audit events. |
| GitHub attack demo | Available today | Demonstrates blocking a high-risk merge action triggered by untrusted external content. |
| TypeScript SDK | Partial / planned | Repository has SDK direction, but public docs should treat Python as the primary working demo path. |
| Go SDK | Partial / planned | Repository has SDK direction, but it is not the main demo path yet. |
| Full web console | Roadmap | A production console should show approvals, agents, incidents, receipts, timelines, bans, quarantine, and evidence graph. |
| Node sensor | Roadmap | Runtime daemon/DaemonSet/sidecar to observe agent process, file, network, and control events. |
| Agent cage runner | Roadmap | Disposable sandbox runner for unknown agents with filesystem, network, credential, and resource isolation. |
| Egress proxy | Roadmap | Network choke point for allow/block rules, DNS/HTTP metadata, exfil hooks, and egress receipts. |
| Tool broker | Roadmap | Credential-owning broker that executes/proxies actions after AegisAgent authorization. |
| Signed control commands | Roadmap | Gateway-to-sensor command protocol for pause, kill, quarantine, ban, policy update, and evidence collection. |
| Ban center | Roadmap | First-class bans for agents, fingerprints, tools, MCP servers, destinations, prompts, and behavior signatures. |
| Quarantine center | Roadmap | Preserve and isolate risky agents, workspaces, files, tools, credentials, destinations, and prompt lineage. |
| Prompt/model capture timeline | Roadmap | Capture prompt/model metadata where there is a real choke point, with hashes/redaction instead of raw sensitive prompts by default. |
| Runtime timeline | Roadmap | Process, file, shell, network, secret access, package install, browser, and control events linked by run/trace IDs. |
| Evidence graph | Roadmap | Link prompt, model, tool, runtime, approval, receipt, ban, quarantine, and incident evidence. |
| Postgres production mode | Roadmap | SQLite remains the local/dev path; production architecture should support Postgres. |
| Kubernetes/Helm production deployment | Roadmap | Target deployment model includes gateway, sensors, cage runner, egress proxy, tool broker, console, metrics, and storage. |

---

## What you should demo today

Use the current MVP demo:

```bash
docker compose up --build
bash scripts/seed-demo.sh
python3 examples/github-attack-demo.py
```

The demo shows:

```text
Untrusted GitHub issue
  → protected GitHub merge action
  → deterministic policy check
  → blocked before execution
  → audit evidence available
```

See [Quickstart](quickstart.md) and [Demo: malicious GitHub issue](demo-github-attack.md).

---

## What not to claim yet

Do not claim that the current MVP already provides:

- full EDR-like runtime control
- process kill/quarantine enforcement
- default network egress blocking
- raw credential isolation for all tools
- full SOC console
- complete unknown-agent sandboxing
- production-ready Kubernetes deployment
- magic protection for agents that bypass every AegisAgent choke point

Those are target architecture goals.

---

## The product direction

AegisAgent is moving toward this architecture:

```text
Control Plane
  + Runtime Sensor
  + Agent Cage
  + Egress Proxy
  + Tool Broker
  + MCP Gateway
  + Receipt-backed SOC Evidence
```

The architecture principle is strict:

> Do not put untrusted agent execution inside the gateway.

The gateway is the central control plane. Runtime enforcement should happen through separate data-plane components.

---

## Why this distinction matters

Security products lose trust when they overclaim.

AegisAgent's honest boundary is:

> If an action passes through AegisAgent, AegisAgent can control and prove the decision. If an action bypasses every AegisAgent choke point, the architecture must isolate, block, or treat that agent as hostile through runtime controls.

That is the difference between a demo gateway and a real AI agent security control plane.

---

## Read next

- [Core concepts](concepts.md)
- [Quickstart](quickstart.md)
- [World-Class HLD](AegisAgent_World_Class_HLD.md)
- [Phased PR Plan](AegisAgent_Phased_PR_Plan.md)
