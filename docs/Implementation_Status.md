# Implementation Status

**One sentence:** the honest ledger of what AegisAgent ships today versus what is designed on the roadmap — if a capability isn't Implemented here, do not document, demo, or sell it as shipped.

**Legend — status values:** Implemented · Partial · Planned · Missing (design references inside other columns may still use ✅/🟡/📐 shorthand)  
**Production-readiness:** prod = hardened & exercised · beta = works, sharp edges · design = paper only  
**Verified against:** `origin/main` after console panel suite #1821–#1830 and TS receipt corpus gate — 2026-07-10.

> **How to read this for production:**  
> - **Known-agent integrity gateway** (authorize → policy → approval → receipt → SOC) is largely **prod**.  
> - **Unknown-agent runtime control** (cage execution loop + real sensor telemetry + forced egress) is **not** production-complete.  
> - **Multi-replica K8s** requires Postgres GA (#1194); Helm defaults remain `replicaCount: 1`.

## v2 architecture migration ledger

This ledger uses the canonical `current`, `shadow`, `target`, and `qualified`
vocabulary from [architecture.md](architecture.md). The larger v1 capability
matrix below retains its historical release labels until it is migrated as a
separate documentation change.

| Artifact | Status | Evidence in this checkout | Authority / traffic | Remaining gates |
|---|---|---|---|---|
| Unwired SPSC, slab-page, published-prefix, and single-page admission prototypes | current | `lib/event/`; ring FIFO/full/wrap/drop/layout plus cancelable permits and commit-delayed claims; safe sealed and short-trace differential oracles; packed page publication; page-before-ring admission; must-use frame leases; clean/faulted/orphan terminal checks; native stress; shipping-algorithm Loom; Miri-oriented borrow/drop tests; ASan/TSan CI lanes defined; zero-allocation append/resolve and admission/claim checks; ADR-0006 through ADR-0009 | No production or `shadow` traffic; cannot carry protected evidence; volatile admission is not a receipt or durability acknowledgement; no performance claim | Formal ADR acceptance/security review, green hosted sanitizer artifacts, UBSan support, authenticated registry, bounded page rotation/outstanding pages + generation reuse (ADR-0010 Proposed with an unwired prototype; in-place slot reuse still required before shadow), WAL durability/replay, epochs for any multi-reader future, NUMA-owner reclamation, priority lanes, production shadow wiring, release-artifact rollback, qualification |
| Thread-per-core reactor | target | `ARCHITECTURE.md`, `docs/LLD.md` | None | runtime ADR, core-affinity/io_uring implementation, migration and benchmark gates |
| HCMT telemetry store | target | `ARCHITECTURE.md`, `docs/LLD.md` | None; SQL remains authoritative/current | WAL/segment ADR, recovery corpus, dual write, shadow equality, qualification |

No v2 component is `qualified` in this checkout. The SPSC, slab-page,
published-prefix, and single-page admission prototypes being `current` means
only that their isolated, unwired code and listed tests are present. The
production event fabric remains `target`, is neither `shadow` nor `qualified`,
and is not production-authoritative.

| Capability | Status | Current files | Missing pieces | Related issues | Test coverage | Prod-ready | Next PR |
|---|---|---|---|---|---|---|---|
| Gateway authorize | Implemented | Thin adapters: `routes/authorize.rs` + `authorize_service.rs` + `decision_runtime.rs`; evaluation in `lib/decision` (`run_authorize_pipeline`) | reactor snapshots / control-store cutover (later weeks) | #1305–#1313, Week-3 typed service | unit + pipeline e2e mocks + equality corpus + bench + fuzz (canon) | prod | perf follow-ups |
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
| Auth: bearer/JWT, rotation, admin bootstrap | Implemented | JWT required gates, admin key, public-bind fail-closed | full RBAC/admin-role distinction | #1211 | unit + integration | prod (JWT) | — |
| OIDC console login | Partial | `src/src/oidc.rs` (discovery/PKCE/ID-token verify via `openidconnect`), `routes/oidc.rs` (`GET /v1/auth/oidc/login`, `POST /v1/oidc/link/start`, `GET /v1/auth/oidc/callback`), `oidc_identities` self-service link table (no auto-provisioning — an unrecognized identity fails closed); gated on `AEGIS_OIDC_*` + `AEGIS_JWT_SECRET`; flow-state cookie HMAC-signed | SAML; per-SSO-user attribution/revocation (minted JWT carries only tenant authority, like any other bearer token); single-IdP-per-gateway | roadmap "OIDC/SAML for console/admin" | unit + route (incl. a forged-cookie cross-tenant-linking regression test) | beta | SAML, multi-IdP, session revocation |
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
| UI: agent-cage console | Implemented | `ui-next/…/runs` (list + pause/resume/kill/quarantine), `/runs/:id` (decision timeline, runtime events, prompt timeline, model calls), `/bans`, `/quarantine`, `/egress`, `/graph`, `/policies` | — | Phased PR plan §11 (PR 9.2/9.3) | bun test + Playwright (`mocked-phase9-control-pages.spec.ts`) | beta | — |
| Agent runs registry (cage control-plane API) | Partial | `lib/storage/src/db/agent_runs.rs`, migration `0026`; `routes/runtime.rs` (`/v1/agent-cage/runs` + controls) | claim/heartbeat/lease APIs + executor not on main (WIP branch) | #1681 | route + storage | beta | cage execution PR |
| Runtime events ingest + timeline | Partial | `POST /v1/ingest/runtime-events`, `list/query` ASE APIs | rich producers (process/fs/net) on sensor | #1681 | storage + route | beta | sensor collectors |
| Control commands (signed kill/pause/quarantine) | Partial | store + protocol + gateway issue routes; sensor poll/verify + **host ProcessEnforcer** (SIGTERM/STOP/CONT for registered PIDs); cage-runner Docker kill path | auto PID discovery/collectors; grace_period from command payload | Phased PR plan §5 | storage + sensor unit (real child kill) | beta | collectors |
| Ban system (first-class store) | Implemented | `lib/storage/src/db/agent_bans.rs`, migration `0029`; enforced at every choke point: `POST /v1/authorize` (agent + tool bans → durable deterministic deny via `write_decision_and_audit`), `POST /v1/broker/execute` (tool ban → 403 before approval consumption), `POST /v1/agent-cage/runs` create + claim (agent ban → 403; claim re-checks so a ban created after registration still blocks start), `POST /v1/egress/check` (destination ban, pre-existing); sensor prop: `POST /v1/bans` with `target_type=agent` issues signed `kill_run` control commands for the agent's active runs (`list_active_agent_runs_for_agent`) | `image_digest` bans enforced at cage run create + claim (`image_digest_ban_denial`, re-checked at claim so a ban created after registration still blocks start); `fingerprint`/`prompt_hash` target types stored but not consulted — `fingerprint` has no carrier at any choke point today (mTLS yields CN only; needs a wire field, i.e. a protobuf-first contract change), `prompt_hash` only appears at telemetry ingest where blocking would destroy evidence (enforcement belongs to SOC auto-response, a separate design) | #1678 | storage + route (authorize/broker/runtime/control/egress) | beta | remaining target types |
| Quarantine records | Partial | `lib/storage/src/db/quarantine.rs`, migration `0030`; agent-status quarantine; `quarantine_records` enforced at `POST /v1/authorize` (agent), `POST /v1/broker/execute` (tool), cage run create + claim (agent + run), egress (run/sandbox/agent, pre-existing) | workspace/sandbox evidence-freeze semantics (needs cage) | #1679 | storage + route | beta | cage integration |
| Node sensor | Implemented | `bins/aegis-node-sensor` (main, spool, shipper, command_receiver); real `process`/`net`/`fs`/`secret` collectors (`AEGIS_RUN_ID`-tagged process discovery -> `ProcessEnforcer` registration + `network_connection`/filesystem/secret-signal runtime events), all polled from the main loop; Dockerfile, Helm, compose; `tests/real_host_integration.rs` proves `scan_host_aegis_processes`/`ProcessCollector`/`NetCollector`/`FsCollector`/`SecretCollector` against a real Linux host's actual `/proc`, a real signal-killed child, a real established TCP socket, a real open file descriptor, and a real secret-shaped env var (name reported, value never leaves the host) -- not the synthetic `/proc` tempdir fixtures the module unit tests use; `scripts/sensor-soak.sh` + CI `sensor-soak.yml` (nightly 15-min + dispatchable multi-hour + PR smoke) soak the real sensor on the runner's real `/proc` under continuous collector workload, signed-kill round-trips, and a mid-soak gateway outage, asserting bounded RSS/fds/spool disk, zero panics, full spool drain, and unattended recovery; steady-state spool compaction (`compact_if_reclaimable`, wired into the ship tick) keeps lane files from growing without bound on long-lived hosts | extended-duration soak on a production-grade deployment (the nightly CI soak runs on a CI runner, not a production host under production load) | Phased PR plan §5 | unit (89 tests) + 5 real-host integration tests + nightly CI soak | beta | production-deployment soak |
| Agent cage runner | Partial | binary + DockerRuntime + Dockerfile + compose `cage` + Helm; claim lifecycle smoke; host-Docker review + hardened create; `scripts/cage-docker-e2e.sh` + CI job (quick finish + signed kill against real Docker) | sensor↔runner IPC; forced egress netns; product “untrusted→incident” narrative e2e | Phased PR plan §6 | unit (lib) + claim lifecycle + cage-docker-e2e + helm lint | beta (local/k8s) | forced egress + sensor enforce |
| Egress proxy | Partial | `bins/aegis-egress-proxy` binary + Dockerfile + Helm + compose; `POST /v1/egress/check` | forced cage netns integration; always-on path | Phased PR plan §7 | unit + proxy tests | beta | cage net integration |
| Tool broker | Partial | `routes/broker.rs` (owns tool CRUD, action-hash, approval consume, receipts), `lib/tool-broker-core` (shared types), `bins/aegis-tool-broker` (Phase 1: standalone connector-execution binary the gateway calls over HTTP with a service-to-service bearer token; gateway no longer links `lib/tool-broker-connectors` in production) | mandatory force path for privileged tools; per-run scoped agent tokens; reversed agent→broker→gateway topology | Phased PR plan §8 | unit (aegis-tool-broker) + route (mock-HTTP-broker) | beta | force-path + scoped tokens |
| Prompt capture | Implemented | `POST /v1/ingest/prompt-events`, `GET .../prompt-events` (`routes/prompt_capture.rs`), Python SDK emit, `ui-next` Prompt Timeline section | Go/TS emit | #1775/#1776 | unit + SDK + bun test | beta | SDK parity |
| Model call capture | Implemented | `POST /v1/ingest/model-calls`, `GET .../model-calls`; `bins/aegis-llm-gateway` (Phase 7.3); `ui-next` Model Calls section | Dockerfile/Helm/compose for LLM gateway; broader provider adapters | #1775/#1776/#1794 | unit + gateway tests + bun test | beta | packaging + adapters |
| Runtime timeline (UI) | Implemented | APIs: `GET /v1/runtime/runs/:id/events`, `GET /v1/runs/:id/timeline`, `GET /v1/runtime/runs/:id/{prompt-events,model-calls}`; `provable-timeline` panel (receipts); `ui-next/…/runs/:id` run-detail page renders all four | — | Phase 9.2 | route + storage + bun test | beta | — |
| Deployment (Compose/Helm) | Partial | gateway + sensor + egress-proxy + cage-runner + llm-gateway + tool-broker charts/images; compose full (+ `cage` profile) | UI Helm; multi-replica | #1206, #1297/#1790 | helm lint + e2e | beta (single-writer) | Postgres + multi-replica |
| Postgres production mode | Partial | `features = postgres`, `migrations_postgres/*` (31 files); read/write pool split with replica failover (#914); DB-backed replay store + cross-replica correlation windows (#1210); `helm/aegis-gateway` fail-closed multi-replica guard + `values-production.yaml`; live `postgres-integration` CI job (`lib/storage/tests/postgres_smoke.rs`) against a real `postgres:16` service, replacing compile-only checking | real cross-instance failover/replication-lag validation, load validation, default Helm bundling | #1194 | postgres-integration CI job (tenant CRUD + health_check + replica routing against live Postgres) | beta | failover/load validation, Postgres GA |
| CI / testing / supply chain | Implemented | `.github/workflows/*` (fmt/clippy/tests/coverage/deny; release cosign/SLSA/SBOM) | — | #1172, #1174, #1792 | — | prod | — |

## Pre-production remaining work (priority waves)

Living checklist (detail also in [`.claude/PRPs/tasks/task.md`](../.claude/PRPs/tasks/task.md)):

### Wave A — P0 unknown-agent control (blocks full control-plane claim)

1. ~~Cage-runner binary + packaging + Helm~~ **Done**; ~~claim-path smoke~~ **Done**; ~~host Docker security review + sandbox create hardening~~ **Done** (`docs/AegisAgent_Cage_Docker_Security.md`); ~~full Docker e2e~~ **Done** — `scripts/cage-docker-e2e.sh`, CI job `cage-docker-e2e`  

2. Gateway claim/heartbeat/lease APIs — present (`/v1/agent-cage/runs/:id/{claim,heartbeat,status}`)  
3. ~~Sensor host enforce kill/pause/resume/quarantine~~ **Done** (`process_enforcer` + command_receiver); ~~process collectors that `register_run`~~ **Done** (`process_collector.rs` discovers `AEGIS_RUN_ID`-tagged host processes and registers them; `net`/`fs`/`secret` collectors alongside it, all polled from `main.rs`'s loop); ~~live-host proof~~ **Done** — `bins/aegis-node-sensor/tests/real_host_integration.rs` runs every collector against a real Linux host's actual `/proc`/sockets/files (verified against a real `rust:1.96-bookworm` container, not just the synthetic `/proc` tempdir fixtures the module unit tests use); ~~soak harness~~ **Done** — `scripts/sensor-soak.sh` + `sensor-soak.yml` (nightly / dispatch / PR smoke): sustained collector workload, periodic signed-kill round-trips, mid-soak gateway outage, bounded RSS/fd/spool-disk + drain + zero-panic assertions; landing it surfaced and fixed a real steady-state defect (spool lane files were never compacted outside the over-budget drop path, so disk grew without bound on a healthy long-lived host — `compact_if_reclaimable` now runs after ship ticks); **remaining:** extended-duration soak on a production-grade deployment  

4. ~~E2E: untrusted agent → cage → egress deny → control action → receipt/incident (Docker)~~ **Done** — `scripts/cage-wave-a-e2e.sh` (#1840), CI-wired as job `cage-wave-a-e2e`: `root_trust_level=untrusted_external` cage run, egress routed through `aegis-egress-proxy --gateway-url` (the real fail-closed `POST /v1/egress/check` path) so a durable deny event + `ActionReceiptRecord` is asserted via `GET /v1/egress/events`, then a signed kill control command. Landing this e2e surfaced a real pre-existing bug: a forced-egress sandbox's `--internal` Docker bridge has **no route to the host at all** (not just no internet), so `host.docker.internal` never actually worked for reaching a host-run proxy, in any environment — fixed by having `aegis-cage-runner` join the proxy as a **sidecar container** to each sandbox's dedicated bridge (`egress_proxy_container` config, `docker network connect`, proxy addressed by container name) instead. Verified with a real-Docker regression test (`docker_runtime::forced_egress_sandbox_reaches_the_sidecar_proxy_container`) and the CI job itself.  

### Wave B — P1 production ops (blocks multi-tenant HA claim)

5. Postgres as supported production backend + multi-replica validation (#1194)  
6. Helm/Docker packaging: broker (+ UI if split); ~~cage + llm-gateway~~ **Done**
7. ~~OIDC for console/admin~~ **Done (beta)** — self-service login/link flow (`src/src/oidc.rs`, `routes/oidc.rs`); **remaining:** SAML, per-SSO-user attribution/revocation, multi-IdP  
8. ~~Operator runbook gates~~ **Done (beta)** — `JWT_REQUIRED`+bind was already fail-closed (`assert_bind_security`); startup now also *warns* (not fail-closed — these have legitimate reasons to be absent, e.g. TLS terminated at a reverse proxy) on a non-loopback bind missing admin key / `REPLAY_STORE=db` / TLS (`warn_on_incomplete_production_hardening`, `src/src/main.rs`); **remaining:** backups has no runtime-observable "is it actually scheduled" signal, stays a doc-only runbook item (`docs/deployment-guide.md`)  

### Wave C — P2 product surface / honesty

9. ~~UI Phase 9.2–9.3 (cage runs, ban/quarantine centers, runtime timelines)~~ **Done** — `ui-next` `/runs`, `/runs/:id` (decision timeline, runtime events, prompt timeline, model calls), `/bans`, `/quarantine`, `/egress`, `/graph`, `/policies`  
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
