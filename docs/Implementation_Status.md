# Implementation Status

**One sentence:** the honest ledger of what AegisAgent ships today versus what is designed on the roadmap — if a capability isn't Implemented here, do not document, demo, or sell it as shipped.

**Legend — status values:** Implemented · Partial · Planned · Missing (design references inside other columns may still use ✅/🟡/📐 shorthand)  
**Production-readiness:** prod = hardened & exercised · beta = works, sharp edges · design = paper only  
**Verified against:** `origin/main` after console panel suite #1821–#1830 and TS receipt corpus gate — 2026-07-10.

> **How to read this for production:**  
> - **Known-agent integrity gateway** (authorize → policy → approval → receipt → SOC) is largely **prod**.  
> - **Unknown-agent runtime control** (cage execution loop + real sensor telemetry + forced egress) is **not** production-complete.  
> - **Multi-replica K8s** requires Postgres GA (#1194); Helm defaults remain `replicaCount: 1`.

| Capability | Status | Current files | Missing pieces | Related issues | Test coverage | Prod-ready | Next PR |
|---|---|---|---|---|---|---|---|
| Gateway authorize | Implemented | `src/src/routes/authorize.rs`, `authorize_decision.rs`, `authorize_canon.rs` | — | #1305–#1313 | unit + integration + bench + fuzz (canon) | prod | perf follow-ups |
| Policy engine (Cedar) | Implemented | `lib/policy/src/cedar.rs`, `policies.cedar`, `src/src/policy_watcher.rs` | — | #883, #1280 | unit + policy eval | prod | — |
| Trust provenance (6 levels, tighten-only) | Implemented | `lib/policy/src/trust_chain.rs`, ingest labeling | broader channel connectors | — | unit | prod | more ingest sources |
| Approval lifecycle (create/approve/reject/TTL) | Implemented | `src/src/routes/approval.rs`, `lib/storage/src/db/approvals.rs` | — | #1307 | unit + integration | prod | — |
| Approval edit lifecycle (re-hash + re-evaluate) | Implemented | `routes/approval.rs`, migration `0024_approval_effective_call_hash.sql` | — | — | integration | prod | — |
| Approval consume (single-use, atomic) | Implemented | `routes/approval.rs`, SDK consume paths | — | — | integration + SDK | prod | — |
| Receipt chain (append, per-tenant prev-hash) | Implemented | `routes/authorize_receipts.rs`, `lib/storage/src/db/receipts.rs` | — | concurrent append ✅ | vectors + bench | prod | — |
| Receipt verification (single/range/chain/head) | Implemented | `routes/receipts.rs`, Python/Go/TS verifiers + `tests/receipt_chain_vectors.json` | — | — | integration + CLI + 4-lang corpus | prod | — |
| Receipt signing (Ed25519, optional) | Implemented | `src/src/sign.rs`, `src/src/kms_receipt_signer.rs`, migration `0020_*` | default KMS path / rotation runbook automation | — | unit | beta | ops runbook |
| Evidence pack (compliance #1298) | Implemented | `GET /v1/compliance/evidence-pack` (`routes/tenant.rs`) | — | #1298 | integration | beta | — |
| Investigation evidence export (Phase 8.3) | Implemented | `POST /v1/evidence/export` (`routes/evidence_export.rs`), `receipt_checkpoints` (`0044` / PG `0029`); console Integrity + `receipt-integrity` panel | — | #1795, #1826 | unit + Playwright mock | beta | — |
| Evidence graph | Implemented | `src/src/graph.rs`, `/v1/graph/*` | richer edges when producers emit prompt/model/runtime consistently | #1272 | unit + integration | beta | producer coverage |
| SOC events pipeline (async) | Implemented | `lib/soc/src/events.rs`, `ingest.rs`, `detect.rs` | — | — | unit + integration | prod | — |
| Incidents (correlate, narrate, close) | Implemented | `lib/soc/src/correlate.rs`, `narrate.rs`, `routes/soc.rs` | — | — | unit + integration | prod | — |
| SOC query API | Implemented | `POST /v1/soc/query`, `lib/soc/src/query.rs`, runtime_events storage | — | #1623, #1674/#1680/#1682/#1688 | route + storage + UI | prod | — |
| Tenant isolation | Implemented | every `lib/storage/src/db/*` binds `tenant_id`; `TenantId` extractor | continuous audit | — | isolation tests | prod | audit on every storage PR |
| Auth: bearer/JWT, rotation, admin bootstrap | Implemented | JWT required gates, admin key, public-bind fail-closed | **OIDC/SAML** for console humans 📐 | #1211 | unit + integration | prod (JWT) | OIDC (Phase 10.1) |
| Agent mTLS identity | Implemented | `src/src/mtls.rs`, migration `0021_agent_mtls_cn.sql` | — | #1310 | integration | beta | — |
| MCP gateway (registry, discovery, pin, drift, optional Ed25519 sign) | Implemented | `routes/mcp.rs`, `lib/soc/src/mcp_inspect.rs`, migration `0043_mcp_server_manifest_signing_key.sql` | standalone MCP proxy binary 📐 | #1793, #1336 | unit + integration | prod (lite) | proxy-mode |
| Tool permissions (per-agent) | Implemented | migration `0013_agent_tool_permissions.sql`, `routes/agents.rs` | — | — | integration | prod | — |
| SDK Python | Implemented | `sdk-python/aegisagent/*` incl. prompt capture emit | — | #1776 | unit + parity vectors | prod | — |
| SDK TypeScript | Implemented | `sdk-typescript/src/*` (canon, client, protect, **receipts**) | — | [sdk-parity-status.md](sdk-parity-status.md) | unit + shared corpus | prod | — |
| SDK Go | Implemented | `sdk-go/{canon,aegis}/` | prompt/model emit parity | [sdk-parity-status.md](sdk-parity-status.md) | unit + parity vectors | beta | capture parity |
| UI: approvals | Implemented | `ui-next/…/approvals` + `approval-card` panel | — | #1824 | bun test + Playwright | beta | — |
| UI: receipts/integrity | Implemented | `ui-next` Integrity page + `provable-timeline` / `receipt-integrity` panels | — | #1825–#1826 | bun test + Playwright | beta | — |
| UI: panel framework + system catalog | Implemented | `ui-next/src/panels/*`, 10 system boards, charts + decision-graph | — | #1815–#1830 | bun test + E2E mock suite | beta | — |
| UI: incidents/SOC | Implemented | overview/fleet/incidents system boards + `decision-graph` | richer incident drill-down | #1828 | bun test + Playwright | beta | incident detail |
| UI: agent-cage console | Implemented | `ui-next/…/runs` (list + pause/resume/kill/quarantine), `/runs/:id` (timeline + runtime events), `/bans`, `/quarantine`, `/egress`, `/graph`, `/policies` | Prompt Timeline / Model Calls pages (backend has no query API yet, ingest-only) | Phased PR plan §11 (PR 9.2/9.3) | bun test | beta | prompt/model query API |
| Agent runs registry (cage control-plane API) | Partial | `lib/storage/src/db/agent_runs.rs`, migration `0026`; `routes/runtime.rs` (`/v1/agent-cage/runs` + controls) | claim/heartbeat/lease APIs + executor not on main (WIP branch) | #1681 | route + storage | beta | cage execution PR |
| Runtime events ingest + timeline | Partial | `POST /v1/ingest/runtime-events`, `list/query` ASE APIs | rich producers (process/fs/net) on sensor | #1681 | storage + route | beta | sensor collectors |
| Control commands (signed kill/pause/quarantine) | Partial | store + protocol + gateway issue routes; sensor poll/verify + **host ProcessEnforcer** (SIGTERM/STOP/CONT for registered PIDs); cage-runner Docker kill path | auto PID discovery/collectors; grace_period from command payload | Phased PR plan §5 | storage + sensor unit (real child kill) | beta | collectors |
| Ban system (first-class store) | Partial | `lib/storage/src/db/agent_bans.rs`, migration `0029` | enforcement at every choke point + sensor prop | #1678 | storage | beta | preflight wire-up |
| Quarantine records | Partial | `lib/storage/src/db/quarantine.rs`, migration `0030`; agent-status quarantine | workspace/sandbox quarantine (needs cage) | #1679 | storage | beta | cage integration |
| Node sensor | Partial | `bins/aegis-node-sensor` (main, spool, shipper, command_receiver), Dockerfile, Helm, compose | **real** process/fs/network/secret collectors; full local enforce | Phased PR plan §5 | unit | beta (skeleton) | collectors + e2e |
| Agent cage runner | Partial | binary + DockerRuntime + Dockerfile + compose `cage` + Helm; claim lifecycle smoke; host-Docker review + hardened create; `scripts/cage-docker-e2e.sh` + CI job (quick finish + signed kill against real Docker) | sensor↔runner IPC; forced egress netns; product “untrusted→incident” narrative e2e | Phased PR plan §6 | unit (lib) + claim lifecycle + cage-docker-e2e + helm lint | beta (local/k8s) | forced egress + sensor enforce |
| Egress proxy | Partial | `bins/aegis-egress-proxy` binary + Dockerfile + Helm + compose; `POST /v1/egress/check` | forced cage netns integration; always-on path | Phased PR plan §7 | unit + proxy tests | beta | cage net integration |
| Tool broker | Partial | `routes/broker.rs`, `lib/tool-broker-core`, `lib/tool-broker-connectors` | standalone broker binary; mandatory path for privileged tools | Phased PR plan §8 | unit + route | beta | binary + force-path |
| Prompt capture | Implemented | `POST /v1/ingest/prompt-events` (`routes/prompt_capture.rs`), Python SDK emit | Go/TS emit; UI timeline | #1775/#1776 | unit + SDK | beta | UI + SDK parity |
| Model call capture | Implemented | `POST /v1/ingest/model-calls`; `bins/aegis-llm-gateway` (Phase 7.3) | Dockerfile/Helm/compose for LLM gateway; broader provider adapters | #1775/#1776/#1794 | unit + gateway tests | beta | packaging + adapters |
| Runtime timeline (UI) | Implemented | APIs: `GET /v1/runtime/runs/:id/events`, `GET /v1/runs/:id/timeline`; `provable-timeline` panel (receipts); `ui-next/…/runs/:id` run-detail page renders both | prompt/model timeline pages (backend ingest-only, no query API) | Phase 9.2 | route + bun test | beta | prompt/model query API |
| Deployment (Compose/Helm) | Partial | gateway + sensor + egress-proxy + cage-runner + llm-gateway charts/images; compose full (+ `cage` profile) | broker + UI Helm; multi-replica | #1206, #1297/#1790 | helm lint + e2e | beta (single-writer) | Postgres + multi-replica |
| Postgres production mode | Partial | `features = postgres`, `migrations_postgres/*` (29 files) | full parity ops path, multi-replica validation, default Helm | #1194 | migration + feature tests | design→beta | Postgres GA |
| CI / testing / supply chain | Implemented | `.github/workflows/*` (fmt/clippy/tests/coverage/deny; release cosign/SLSA/SBOM) | — | #1172, #1174, #1792 | — | prod | — |

## Pre-production remaining work (priority waves)

Living checklist (detail also in [`.claude/PRPs/tasks/task.md`](../.claude/PRPs/tasks/task.md)):

### Wave A — P0 unknown-agent control (blocks full control-plane claim)

1. ~~Cage-runner binary + packaging + Helm~~ **Done**; ~~claim-path smoke~~ **Done**; ~~host Docker security review + sandbox create hardening~~ **Done** (`docs/AegisAgent_Cage_Docker_Security.md`); **remaining:** full Docker e2e  

2. Gateway claim/heartbeat/lease APIs — present (`/v1/agent-cage/runs/:id/{claim,heartbeat,status}`)  
3. ~~Sensor host enforce kill/pause/resume/quarantine~~ **Done** (`process_enforcer` + command_receiver); **remaining:** process collectors that `register_run`  

4. E2E: untrusted agent → cage → egress deny → control action → receipt/incident (Docker)  

### Wave B — P1 production ops (blocks multi-tenant HA claim)

5. Postgres as supported production backend + multi-replica validation (#1194)  
6. Helm/Docker packaging: broker (+ UI if split); ~~cage + llm-gateway~~ **Done**
7. OIDC for console/admin **or** documented JWT-only enterprise limitation  
8. Operator runbook gates: `JWT_REQUIRED`, admin key, `REPLAY_STORE=db`, TLS, backups  

### Wave C — P2 product surface / honesty

9. ~~UI Phase 9.2–9.3 (cage runs, ban/quarantine centers, runtime timelines)~~ **Done** — `ui-next` `/runs`, `/runs/:id`, `/bans`, `/quarantine`, `/egress`, `/graph`, `/policies`; remaining: prompt/model timeline pages once backend gets a query API  
10. ~~TypeScript receipt chain verifier parity~~ **Done** (`sdk-typescript/src/receipts.ts` + shared corpus; CI `ts-canon` runs canon + receipts)  
11. Keep this matrix + `current-vs-roadmap.md` in lockstep with landing PRs  
12. Branch merge-or-close pass (~80 remote branches)  

## What you may claim today

| Claim | Allowed? |
|---|---|
| Known-agent integrity (SDK authorize / approval hash / fail-closed / receipts) | **Yes** |
| Integrity-anchored SOC on gateway evidence | **Mostly yes** (beta UI) |
| Unknown-agent sandbox + forced egress + host kill | **Partial** — soft force + narrative e2e; transparent netns residual |
| Multi-replica production K8s | **No** until Postgres GA |
| Full enterprise SOC console + OIDC | **No** until Wave B/C |

## How to update this matrix

1. When a PR lands that changes any row, update **Status / Current files / Next PR** in the same PR.  
2. Never move a row to Implemented without naming the file paths and tests that make it true.  
3. `scripts/validate-docs.mjs` checks that required capability labels still appear — keep those substrings stable.  

## Related docs

[Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) · [AegisAgent_Phased_PR_Plan.md](AegisAgent_Phased_PR_Plan.md) · [current-vs-roadmap.md](current-vs-roadmap.md) · [feature_history.md](feature_history.md) · [sdk-parity-status.md](sdk-parity-status.md) · [production-hardening.md](production-hardening.md)
