# Implementation Status

**One sentence:** the honest ledger of what AegisAgent ships today versus what is designed on the roadmap — if a capability isn't Implemented here, do not document, demo, or sell it as shipped.

**Legend — status values:** Implemented · Partial · Planned · Missing (design references inside other columns may still use ✅/🟡/📐 shorthand)
**Production-readiness:** prod = hardened & exercised · beta = works, sharp edges · design = paper only
**Verified against:** committed HEAD of this branch lineage (PRs #1678–#1682 era), 2026-07-02. The route layer for the runtime data plane is under active revision — re-verify `src/src/routes/runtime.rs` before deep-linking.

| Capability | Status | Current files | Missing pieces | Related issues | Test coverage | Prod-ready | Next PR |
|---|---|---|---|---|---|---|---|
| Gateway authorize | Implemented | `src/src/routes/authorize.rs`, `authorize_decision.rs`, `authorize_canon.rs` | — | #1305–#1313 (hardening done) | unit + integration + bench + fuzz (canon) | prod | perf follow-ups (#899 seq.) |
| Policy engine (Cedar) | Implemented | `lib/policy/src/cedar.rs`, `policies.cedar`, `src/src/policy_watcher.rs` | — | #883 (hot reload), #1280 (signed bundles) | unit + policy eval tests | prod | — |
| Trust provenance (6 levels, tighten-only) | Implemented | `lib/policy/src/trust_chain.rs`, ingest labeling in `routes/mod.rs` | broader channel connectors | — | unit | prod | more ingestion sources |
| Approval lifecycle (create/approve/reject/TTL) | Implemented | `src/src/routes/approval.rs`, `lib/storage/src/db/approvals.rs` | — | #1307 (brute-force guards) | unit + integration | prod | — |
| Approval edit lifecycle (re-hash + re-evaluate) | Implemented | `routes/approval.rs`, migration `0024_approval_effective_call_hash.sql` | — | — | integration | prod | — |
| Approval consume (single-use, atomic) | Implemented | `routes/approval.rs`, SDK consume paths | — | — | integration + SDK tests | prod | — |
| Receipt chain (append, per-tenant prev-hash) | Implemented | `routes/authorize_receipts.rs`, `lib/storage/src/db/receipts.rs`, `compute_receipt_hash` in `routes/mod.rs` | — | tx-safe concurrent append ✅ | vectors (`tests/receipt_chain_vectors.json`) + bench | prod | — |
| Receipt verification (single/range/chain/head) | Implemented | `routes/receipts.rs`, `sdk-python/aegisagent/verify_receipts.py` | — | — | integration + CLI tests | prod | — |
| Receipt signing (Ed25519, optional) | Implemented | `src/src/sign.rs`, migration `0020_receipt_signer_key_id.sql` | KMS/HSM integration | — | unit | beta | key-rotation runbook automation |
| Evidence pack | Implemented | `GET /v1/compliance/evidence-pack` (`routes/mod.rs`) | richer pack formats | — | integration | beta | — |
| Evidence graph | Implemented | `src/src/graph.rs`, `lib/api/src/graph.rs`, `/v1/graph/*` | deeper lineage once prompt capture lands | — | unit + integration | beta | — |
| SOC events pipeline (async) | Implemented | `lib/soc/src/events.rs`, `lib/soc/src/ingest.rs`, `detect.rs` | — | — | unit + integration | prod | — |
| Incidents (correlate, narrate, close) | Implemented | `lib/soc/src/correlate.rs`, `narrate.rs`, `routes/soc.rs` | — | — | unit + integration | prod | — |
| SOC query API | Implemented | `lib/soc/src/query.rs`, `POST /v1/soc/query` | — | #1674/#1680/#1682 (ASE queries + hardening) | unit (hardened on active branch) | prod | in review on `fix/1674-…` |
| Tenant isolation | Implemented | every `lib/storage/src/db/*` query binds `tenant_id`; `TenantId` extractor | — | audited recurrently | isolation tests | prod | continuous audit |
| Auth: bearer/JWT, rotation, admin bootstrap | Implemented | `routes/mod.rs` (`validate_jwt`, `jwt_secret_candidates`) | OIDC provider integration 📐 | #1211 (rotation) | unit + integration | prod | OIDC |
| Agent mTLS identity | Implemented | `src/src/mtls.rs`, migration `0021_agent_mtls_cn.sql` | — | #1310 | integration | beta | — |
| MCP gateway (registry, discovery, manifest pinning, drift) | Implemented | `src/src/routes/mcp.rs`, `lib/soc/src/mcp_inspect.rs`, migrations 0002–0003 | standalone MCP proxy binary 📐 | #1336, #1337 | unit + integration | prod (lite) | proxy-mode design |
| Tool permissions (per-agent) | Implemented | migration `0013_agent_tool_permissions.sql`, `routes/agents.rs` | — | — | integration | prod | — |
| SDK Python | Implemented | `sdk-python/aegisagent/*` (187 tests) | — | — | unit + parity vectors | prod | — |
| SDK TypeScript | Implemented | `sdk-typescript/src/*` | feature parity gaps — see [sdk-parity-status.md](sdk-parity-status.md) | — | unit + parity vectors | beta | parity items |
| SDK Go | Implemented | `sdk-go/{canon,aegis}/` | parity gaps — see [sdk-parity-status.md](sdk-parity-status.md) | — | unit + parity vectors | beta | parity items |
| UI: approvals | Implemented | `ui/src/dashboards/system/approvals.ts`, panels | — | — | vitest + Playwright e2e | beta | — |
| UI: receipts/integrity | Implemented | `ui/src/datasources/receipt*.ts`, `dashboards/system/integrity.ts` | — | — | vitest | beta | — |
| UI: incidents/SOC | Implemented | `ui/src/datasources/socQuery.ts`, `dashboards/system/overview.ts`, `fleet.ts` | dedicated incident drill-down page | — | vitest | beta | incident view |
| UI: agent-cage console | Planned | — | everything (Phase 9) | Phased PR plan §11 | — | design | after cage APIs stabilize |
| Agent runs registry (cage control-plane API) | Partial | `lib/storage/src/db/agent_runs.rs`, migration 0026; routes in `src/src/routes/runtime.rs` at HEAD (#1681) | route layer being reorganized on active branch; no executor | #1681 | route + storage tests | beta | stabilize routes |
| Runtime events ingest + timeline | Partial | `lib/storage/src/db/runtime_events.rs`, migration 0027; `POST /v1/ingest/runtime-events` at HEAD | producers (sensor) don't exist yet | #1681 | storage + route tests | beta | sensor skeleton |
| Control commands (signed kill/pause/quarantine) | Partial | store: `lib/storage/src/db/control_commands.rs`, migration 0028; protocol: [AegisAgent_Control_Command_Protocol.md](AegisAgent_Control_Command_Protocol.md) | signing, dispatch/poll routes, ACK path, sensor verifier | Phased PR plan §5 | storage tests only | design→beta | command dispatch API |
| Ban system (first-class store) | Partial | `lib/storage/src/db/agent_bans.rs`, migration 0029 (#1678) | enforcement wiring beyond agent-status checks; sensor propagation | #1678 | storage tests | beta | wire into preflight |
| Quarantine records | Partial | `lib/storage/src/db/quarantine.rs`, migration 0030 (#1679); agent-status quarantine ✅ (`respond.rs`) | workspace/sandbox quarantine (needs cage) | #1679 | storage tests | beta | — |
| Node sensor | Planned | design: [components/Node_Sensor.md](components/Node_Sensor.md), [AegisAgent_Runtime_Data_Plane.md](AegisAgent_Runtime_Data_Plane.md) | the binary (Phase 3) | Phased PR plan §5 | — | design | `aegis-node-sensor` skeleton |
| Agent cage runner | Planned | design: [AegisAgent_Agent_Cage.md](AegisAgent_Agent_Cage.md) | the binary (Phase 4: Docker-first sandbox) | Phased PR plan §6 | — | design | after sensor |
| Egress proxy | Planned | design: [components/Egress_Proxy.md](components/Egress_Proxy.md) | the proxy (Phase 5) | Phased PR plan §7 | — | design | after cage |
| Tool broker | Planned | design: [components/Tool_Broker.md](components/Tool_Broker.md) | the service (Phase 6) | Phased PR plan §8 | — | design | after egress |
| Prompt capture | Planned | untrusted-content ingest ✅ (`POST /v1/ingest`); full prompt/model capture is Phase 7 | prompt/model event schema + SDK capture | Phased PR plan §9 | ingest tests | design | Phase 7 |
| Model call capture | Planned | — | everything (Phase 7) | Phased PR plan §9 | — | design | Phase 7 |
| Runtime timeline (UI) | Partial | API: `GET /v1/runtime/runs/:id/events`, `GET /v1/runs/:id/timeline` | console visualization | — | route tests | beta | UI panel |
| Deployment (Compose/Helm) | Implemented | `docker-compose*.yml`, `helm/aegis-gateway/` | multi-replica needs Postgres (#1194) | #1206 | helm lint + e2e stack | prod (single-writer) | Postgres GA |
| CI / testing / supply chain | Implemented | `.github/workflows/*` (fmt/clippy/tests/coverage/fuzz/mutation/SAST/scans; cosign+SLSA+SBOM) | — | #1172, #1174 | — | prod | — |

## How to update this matrix

1. When a PR lands that changes any row, update **Status / Current files / Next PR** in the same PR.
2. Never move a row to ✅ without naming the file paths and tests that make it true.
3. `scripts/validate-docs.mjs` checks that every capability row above still exists — extend the list there when adding rows.

## Related docs

[Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) · [AegisAgent_Phased_PR_Plan.md](AegisAgent_Phased_PR_Plan.md) · [current-vs-roadmap.md](current-vs-roadmap.md) · [feature_history.md](feature_history.md) · [sdk-parity-status.md](sdk-parity-status.md)
