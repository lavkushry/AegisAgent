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

- **Node sensor** — binary, register/heartbeat, command poll, shipper, host ProcessEnforcer (real kill/pause/resume for registered PIDs), real process/net/fs/secret collectors (`AEGIS_RUN_ID` auto-discovery -> enforcer registration); now proven against a real Linux host (`tests/real_host_integration.rs`: real `/proc`, real signal-killed child, real established TCP socket, real open file descriptor, real secret-shaped env var) rather than only synthetic `/proc` trees; soaked by `scripts/sensor-soak.sh` (nightly CI + PR smoke: sustained workload, signed-kill round-trips, gateway outage, bounded RSS/fd/spool-disk assertions); extended production-deployment soak still pending
- **Egress proxy** — binary + Helm; not forced for all caged traffic by default
- **Tool broker** — standalone `aegis-tool-broker` binary exists and is the only execution path when configured (gateway no longer links the connector-execution crate in production); no mandatory-force-path enforcement yet, no scoped per-run agent tokens
- **Agent cage runner** — binary + claim/execute loop; compose profile `cage` + Helm; host Docker security review + hardened create flags shipped (`docs/AegisAgent_Cage_Docker_Security.md`); full Docker e2e done (`cage-docker-e2e.sh` + `cage-wave-a-e2e.sh`, both CI-wired)
- **Console UI** — Bun SPA (`ui-next/`) with full panel suite (approvals, integrity, charts, evidence graph) plus cage runs / ban / quarantine / egress / evidence-graph / policy / prompt-timeline / model-calls product pages — Phase 9.2/9.3 complete
- **Deploy** — gateway + sensor + egress + cage + llm-gateway + tool-broker Helm; single-writer SQLite default
- **Postgres** — feature + migrations exist; read/write pool split with replica failover, DB-backed replay store, cross-replica correlation windows, and a live `postgres-integration` CI job now exercise it against a real Postgres instance (not just compile-checked) — but not the default HA production path; real cross-instance failover/load validation still pending
- **OIDC console login** — self-service login/link flow (`src/src/oidc.rs`, `routes/oidc.rs`), gated on `AEGIS_OIDC_*` + `AEGIS_JWT_SECRET`, fails closed for unrecognized identities (no auto-provisioning); single-IdP-per-gateway, no SAML, no per-SSO-user attribution/revocation
- **v2 event primitives** — cache-padded SPSC, safe sealed-page, append-only published-prefix, and failure-atomic single-page admission code are `current` in `lib/event`. The volatile composite uses cancelable permits, page-before-ring Release publication, commit-delayed claims, must-use frame leases, and explicit clean/faulted/orphan terminal checks. Test sources include safe differential oracles, native stress, shipping-algorithm Loom, Miri-oriented lifetime cases, defined ASan/TSan CI lanes, and zero-allocation admission/claim checks. The code is unwired, carries no production or `shadow` traffic or protected evidence, is not `qualified`, and makes no performance claim. The production Thread-Per-Core event fabric remains `target`.

### Roadmap / not done

- transparent / netns forced egress (no raw-socket bypass) (P0 residual after proxy-env force)
- Postgres multi-replica GA (#1194) (P1) — remaining: real cross-instance failover/replication-lag validation, load validation, default Helm bundling
- SAML, multi-IdP, and per-SSO-user attribution/revocation for console login (P1)

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
| Evidence graph | Available today | `/v1/graph/*` for run/incident/agent lineage; console `decision-graph` panel + standalone `/dashboard/graph` page. |
| Investigation evidence export | Available today | `POST /v1/evidence/export` + Integrity UI export. |
| SOC query / incidents | Available today | Async detect/correlate + query API + schema-driven UI. |
| TypeScript SDK | Available today | Canon + protect + client + receipt chain verifier (shared corpus). |
| Go SDK | Partial | Core path shipped; prompt/model emit parity TBD. |
| Full web console | Available today | Bun SPA panel suite + cage runs / ban / quarantine / egress / evidence-graph / policy / prompt-timeline / model-calls pages shipped (Phase 9.2/9.3 complete). |
| Node sensor | Partial | Binary + packaging; real process/net/fs/secret collectors + host enforce, unit-tested, proven against a real Linux host (`tests/real_host_integration.rs`), and soaked in CI (`scripts/sensor-soak.sh`, nightly); extended production-deployment soak pending. |
| Agent cage runner | Partial | Binary + DockerRuntime + compose + Helm; Docker security review + create hardening done; full Docker e2e done (`cage-docker-e2e.sh` + `cage-wave-a-e2e.sh`, CI-wired). |
| Egress proxy | Partial | Binary + packaging; not default-forced for cages. |
| Tool broker | Partial | Standalone `aegis-tool-broker` binary + HTTP contract; gateway owns approval/receipts, broker owns credential resolution + connector execution; no mandatory force path, no scoped tokens. |
| Signed control commands | Partial | Issue + sensor poll + host PID enforce + auto PID discovery (`AEGIS_RUN_ID` process collector); real-host kill proven (`tests/real_host_integration.rs`) and exercised repeatedly by the CI soak; extended production-deployment soak pending. |
| Ban / quarantine centers | Partial | Stores/APIs; not every choke point + full UI. |
| Postgres production mode | Roadmap / partial | Code path now CI-validated against a live Postgres instance (was compile-check only); SQLite single-writer is still the default deploy. |
| Full Kubernetes multi-replica | Roadmap | Blocked on Postgres GA + broader Helm surface. |
| Thread-Per-Core event fabric | `current` prototypes / `target` fabric | Isolated SPSC, safe sealed-page, append-only published-prefix, and single-page volatile admission prototypes exist. The composite validates before reservation, publishes the page before the ring, withholds tail advancement until a validated frame lease commits, and makes clean/faulted/orphan termination explicit. Test sources include safe differential oracles, native stress, shipping-algorithm Loom, Miri-oriented lifetime cases, defined ASan/TSan CI lanes, and zero-allocation checks. Production carries no protected evidence, is neither `shadow` nor `qualified`, and has no performance result. Blockers: formal ADR acceptance/security review, green hosted sanitizer artifacts, UBSan support, authenticated registry, bounded page rotation/outstanding pages, WAL durability/replay, generation reuse/epochs, NUMA-owner reclamation, priority lanes, production shadow wiring, release-artifact rollback, and qualification. |

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
- full enterprise SSO (SAML, RBAC, multi-IdP) — a beta self-service OIDC login/link flow exists (single IdP, no per-user attribution/revocation), see Implementation Status
- production Thread-Per-Core ingestion, HCMT storage, or qualified million-event throughput; only unwired event primitives are `current`

Those remain target architecture goals or incomplete waves (see Implementation Status).

---

## The product direction

AegisAgent is moving toward this architecture:

```text
Control Plane (gateway) — largely shipped
  + Runtime Sensor — skeleton shipped
  + Agent Cage — lib shipped, executor WIP
  + Egress Proxy — binary shipped, force-path WIP
  + Tool Broker — standalone binary shipped (Phase 1); force path + scoped tokens remain
  + LLM choke point — adapter shipped
  + Integrity-anchored SOC + evidence export — largely shipped
```

Integrity motto remains: **make the approval trustworthy; trust the source, not the text.**
