# AegisAgent Issue Backlog Execution Plan

**Date:** 2026-06-29  
**Repo:** `lavkushry/AegisAgent`  
**Planning scope:** all currently open GitHub issues plus current CI/PR health observed during triage.  
**Execution rule:** one issue → one focused branch → one focused PR → tests/docs/validation → merge → next issue.

This file is a planning artifact only. It does not authorize broad implementation or bulk closure.

## Current repository and CI state

- Local checkout was behind `origin/main` during triage. Remote `origin/main` head: `65603e7 feat(storage): add runtime_events idempotent ingest substrate (Phase 2.2) (#1660)`.
- Latest `main` CI run `28374459544` is failing only in **Dashboard E2E (Playwright)**. Gateway, SDK, coverage, audit, Docker Compose E2E, and corpus byte-equality jobs passed on that run.
- Open PR #1592 (`ongoing Changes`, branch `fix/mcp-unknown-tool-fail-closed`) is failing gateway, Python 3.12, PR-title, and Dashboard E2E checks. It should not be merged until isolated, retitled, rebased, and fixed.
- PR #1658 (`fix(ui): hydrate dashboard assets under gateway mount`) is merged. It fixed static asset prefixing but did not resolve the latest Dashboard E2E pointer-interception failure.

## Architecture summary

AegisAgent is an AI Agent Security Control Plane with a Qdrant-inspired layered Rust workspace:

```text
aegis-common  -> base errors/metrics/crypto
aegis-api     -> protobuf source of truth + REST/OpenAPI models
aegis-storage -> StorageBackend trait + SQLite/Postgres implementations
aegis-policy  -> Cedar/trust/risk logic, no storage dependency
aegis-soc     -> detection/correlation/response over storage/api/common
src/ gateway  -> thin Axum + tonic adapters and server wiring
ui/ console   -> Next.js SOC Console over gateway APIs only
SDKs          -> Python, TypeScript, Go fail-closed action wrappers
```

Architecture invariants to preserve:

- `src/` route handlers and gRPC impls stay thin: parse → service call → respond.
- API types start in `lib/api/proto/*.proto`; REST mirrors live in `lib/api`.
- DB access goes through `StorageBackend`; no raw `SqlitePool` in handlers/business logic.
- Policy decisions are deterministic; risk scores are advisory only.
- Approval integrity binds exact canonical action bytes to `action_hash`.
- Receipt/evidence paths fail closed and remain tenant scoped.
- UI never bypasses the gateway, never shows raw secrets, and must treat unknown verification as non-green.

## HLD/LLD alignment summary

The repo is directionally aligned with the target HLD/LLD:

- Workspace layout, crate dependency direction, REST route layer, gRPC server, and protobuf layout are present.
- Approval integrity exists with frozen action hashes, edit endpoint semantics, consume endpoint, and SDK fail-closed patterns.
- Hash-chained receipts, verification endpoints, evidence export, SOC alerts/incidents, active response, MCP governance, and dashboard mount exist in current code.
- UI has a real foundation: AppShell, ControlsBar, Zustand state, datasource registry, dashboard schema, PanelRuntime, panel registry, ApprovalCard, ProvableTimeline, ReceiptIntegrity, and tests.
- Runtime data-plane target docs now include Agent Cage / node sensor / egress proxy / tool broker / MCP gateway concepts, but not all are implemented as deployable services yet.

Key gaps:

- CI is currently red on Dashboard E2E.
- Open UI roadmap issues still represent substantial productionization work.
- Some backend dependency issues may already be partially or fully implemented and need verification/regression tests before closure.
- OpenAPI parity has no automated check.
- `docs/ARCHITECTURE.md` and `docs/architecture.md` are both tracked, creating case-sensitive/case-insensitive checkout risk.

## Dependency graph / waves

```text
Wave 0: Restore green main CI
  -> Dashboard E2E failure on main
  -> stale/open PR #1592 must not merge while red

Wave 1: P0 security/integrity/control correctness
  -> #1637 dangerous UI confirmations
  -> #1631 receipt integrity viewer/export
  -> #1630 active response endpoint verification
  -> #1616 approval card/queue completion
  -> #1619 provable timeline verification
  -> #922 SQLx compile-time query migration plan/slices

Wave 2: P0 SOC console foundation and core surfaces
  -> #1608 meta tracking
  -> #1611 datasource layer
  -> #1614 overview dashboard
  -> #1618 incidents
  -> #1621 explore
  -> #1623 SOC query endpoint verification/closure
  -> #1625 detections/rules split
  -> #1628 agents fleet

Wave 3: P1 correctness/API/reliability
  -> #1601 gateway audit backlog
  -> #1140 API versioning
  -> #1318 Postgres pooling
  -> #900 instrumentation
  -> #904 receipt append batching
  -> #914 read replicas
  -> #1615 SSE/live feed
  -> #1622 AQL parser/autocomplete
  -> #1626 alerting UI
  -> #1629 MCP registry/drift
  -> #1635 settings
  -> #1638 E2E coverage expansion

Wave 4: P2 hardening/features/performance
  -> #1604, #1605, #1607, #1142, #1277, #1297, #1311, #1317, #1337, #1389, #1392, #1393
  -> #1624, #1627, #1633, #1634, #1639

Wave 5: P3/future/docs/epics
  -> #1640, #1210, #1394, #1395, #1396, #1397
```

## Open issue execution table

| Order | Issue | Title | Area | Severity | Depends on | Affected files | Expected tests | PR size | Risk | HLD/LLD update |
|---:|---:|---|---|---|---|---|---|---|---|---|
| 0 | CI | Restore green `main` Dashboard E2E | CI / UI | P0 | none | `e2e/tests/*`, `ui/src/chrome/*`, `ui/src/components/*`, `src/src/routes/dashboard.rs` | `cd ui && npm run build`, `cd ui && npm run lint`, `cd e2e && npx playwright test ...`, relevant CI rerun | S | Medium | No |
| 1 | #1637 | [Bug/UI] Add confirmation and audit reason prompts for all dangerous console actions | UI / security | P0 | CI green | `ui/src/components/primitives/ConfirmDialog.tsx`, action panels/tabs, `ui/src/app/api.ts` | Vitest component/API flow tests; E2E critical destructive action smoke | M | High | No |
| 2 | #1631 | [UI/U6] Build Receipt Integrity Viewer with chain browse, range verify, and evidence export | UI / receipts | P0 | #1611, CI green | `ui/src/components/ReceiptsTab.tsx`, `ui/src/panels/differentiators/ReceiptIntegrity.tsx`, `ui/src/datasources/receipt.ts` | receipt normalization/range/export tests; E2E receipt verify/export | M | High | No |
| 3 | #1630 | [Backend Dependency] Complete Active Response endpoints for freeze/revoke/quarantine and audit receipts | backend / SOC / control | P0 | CI green | `src/src/routes/agents.rs`, `src/src/routes/mcp.rs`, `lib/storage/*`, `lib/api/proto/*`, `src/src/grpc.rs` | REST + gRPC contract, tenant isolation, audit/receipt negative tests | M | High | Maybe |
| 4 | #1616 | [UI/U1] Build Approval Queue and ApprovalCard differentiator panel | UI / approval | P0 | #1637 | `ui/src/panels/differentiators/ApprovalCard.tsx`, `ui/src/dashboards/system/approvals.ts`, `ui/src/app/api.ts` | Approval payload/edit/role-gate/reason tests; E2E approval read-only and approve/reject | M | High | No |
| 5 | #1619 | [UI/U2] Implement ProvableTimeline panel with one-click chain verification | UI / receipts / SOC | P0 | #1611, #1631 | `ui/src/panels/differentiators/ProvableTimeline.tsx`, `ui/src/datasources/receipt.ts` | chain verified/broken/unknown tests; incident timeline E2E | M | High | No |
| 6 | #922 | [TASK-0076] Migrate to SQLx compile-time checked queries | storage | P0 | CI green | `lib/storage/src/db/*`, migrations, CI env | `cargo sqlx prepare --workspace` if adopted; storage integration tests | L / split | High | Yes |
| 7 | #1608 | [UI Roadmap] Build production AegisAgent SOC Console... | UI / SOC | P0 | child issue progress | `ui/**`, docs | meta verification only | N/A | Medium | No |
| 8 | #1611 | [UI/U0] Complete datasource layer... | UI / SOC | P0 | CI green | `ui/src/datasources/*`, `ui/src/app/api.ts`, `ui/src/panels/PanelRuntime.tsx` | datasource fallback, tenant header, stream parser, receipt tests | M | Medium | No |
| 9 | #1614 | [UI/U1] Build production SOC Overview dashboard-as-code | UI / SOC | P0 | #1611 | `ui/src/dashboards/system/overview.ts`, `ui/src/components/OverviewTab.tsx` | dashboard render/drilldown tests; E2E overview stats | M | Medium | No |
| 10 | #1618 | [UI/U2] Build Incidents list and Incident Detail as provable investigation workflow | UI / SOC | P0 | #1611, #1619, #1631 | `ui/src/components/IncidentsTab.tsx`, `ui/src/dashboards/system/*`, graph/timeline panels | incidents list/detail/timeline tests; E2E incident drilldown | M | Medium | No |
| 11 | #1621 | [UI/U3] Build Kibana-style Explore / Discover page for Agent Security Events | UI / SOC | P0 | #1611, #1622, #1623 | `ui/src/components/ExploreTab.tsx`, `ui/src/components/filters/*`, `ui/src/datasources/socQuery.ts` | AQL/filter/row-inspector/redaction tests; E2E explore filter | L / split | Medium | No |
| 12 | #1623 | [Backend Dependency] Add `POST /v1/soc/query` for Explore and dashboard panels | backend / SOC | P0 | CI green | `src/src/routes/soc.rs`, `lib/soc/*`, `lib/storage/src/db/soc.rs`, `lib/api/proto/soc.proto`, OpenAPI | structured query, tenant isolation, SQL injection negative, REST/gRPC parity | M | High | Maybe |
| 13 | #1625 | [UI/U4] Split DetectionsTab into Detections page and Rules page | UI / SOC | P0 | #1611 | `ui/src/components/DetectionsTab.tsx`, new rule/detection components | component tests; E2E rules/backtest smoke | M | Medium | No |
| 14 | #1628 | [UI/U5] Build Agents Fleet dashboard and per-agent detail page | UI / SOC | P0 | #1630, #1637 | `ui/src/dashboards/system/fleet.ts`, `ui/src/panels/standard/AgentTablePanel.tsx`, agent components | role-gate/control tests; E2E freeze/unfreeze when safe | M | High | No |
| 15 | #1601 | [Gateway Audit] Production robustness review and bug backlog | backend / security | P1 | CI green | broad gateway files per sub-issue | split into focused regression tests | L / split | High | Maybe |
| 16 | #1140 | [API-001] Implement API versioning strategy (v1 → v2 migration path) | backend / API | P1 | OpenAPI parity baseline | `src/src/main.rs`, `src/src/routes/openapi.rs`, docs/api | version headers, routing compatibility tests | M | Medium | Yes |
| 17 | #1318 | [PERFORMANCE] Add connection pooling for PostgreSQL backend | storage / infra | P1 | Postgres backend readiness | `lib/storage/*`, config, docs | Postgres integration tests if feature-enabled | M | Medium | Maybe |
| 18 | #900 | [TASK-0054] Add database query timing instrumentation (tracing spans) | infra / storage | P1 | none | `lib/storage/src/db/*`, `lib/common/src/metrics*` | tracing/metrics unit tests where possible | M | Low | No |
| 19 | #904 | [TASK-0058] Optimize receipt chain append (batch INSERT) | receipts / perf | P1 | receipt tests green | `lib/storage/src/db/receipts.rs`, `lib/storage/src/audit_batch.rs` | receipt chain integrity + concurrency tests | M | High | Maybe |
| 20 | #914 | [TASK-0068] Add read replica support for query endpoints | infra / storage | P1 | #1142 pagination, storage abstraction | config, `lib/storage/*`, query routes | read/write split tests; failover behavior | L | High | Yes |
| 21 | #1615 | [UI/U1] Implement SSE live feed and live badges with polling fallback | UI / backend dependency | P1 | #1611 | `ui/src/datasources/stream.ts`, hooks, chrome badges | stream parser/reconnect/fallback tests | M | Medium | No |
| 22 | #1622 | [UI/U3] Implement AQL parser/autocomplete and safe query builder | UI / security | P1 | #1611 | `ui/src/datasources/aql/*`, Explore components | parser/AST/url serialization tests | M | Medium | No |
| 23 | #1626 | [UI/U4] Build deterministic alerting UI... | UI / SOC | P1 | #1625, #1627 | detections/rules/settings UI | component tests; backend-missing states | M | Medium | No |
| 24 | #1629 | [UI/U5] Build MCP Servers registry, manifest drift, and quarantine workflow | UI / MCP | P1 | #1630, #1637 | `ui/src/components/McpTab.tsx`, MCP datasources/panels | quarantine/restore confirm tests; drift state tests | M | High | No |
| 25 | #1635 | [UI/U6] Build Settings for tenants, RBAC, notification config, retention, and console preferences | UI / SOC | P1 | #1637 | `ui/src/components/SettingsTab.tsx`, store/runtime config | secret redaction, demo/prod auth tests | M | Medium | No |
| 26 | #1638 | [UI/Quality] Add end-to-end UI test coverage for core SOC workflows | UI / CI | P1 | CI green, core screens stable | `e2e/tests/*`, fixtures/helpers | deterministic Playwright flows | M | Medium | No |
| 27 | #1604 | [Hardening] No per-agent-token brute-force/lockout protection on /v1/authorize auth failures | tenant/auth / security | P2 | gateway audit decomposition | auth middleware, storage counters/config | rate-limit/lockout negative tests | M | High | Maybe |
| 28 | #1605 | [Audit] No SSRF guard exists for approval callback_url before the planned callback dispatcher ships | approval / security | P2 | callback dispatcher scope | approval routes/models, callback client | SSRF allow/deny unit tests | S | High | Maybe |
| 29 | #1607 | [Audit] Verify OpenAPI spec stays in sync with actual Axum routes | backend / CI | P2 | CI green | `src/src/routes/openapi.rs`, CI workflow, scripts | route/spec parity test | M | Medium | No |
| 30 | #1142 | [API-003] Implement cursor-based pagination for all list endpoints | backend / API | P2 | API versioning decisions | routes, storage list methods, OpenAPI, SDKs/UI | pagination contract + tenant tests | L / split | Medium | Maybe |
| 31 | #1277 | [FEATURE] Slack App: Approver Group Validation | approval / integration | P2 | approval identity model | Slack callback routes, policy/storage | signature + group auth tests | M | High | Maybe |
| 32 | #1297 | [EPIC] Enterprise Production Readiness | infra / docs | P2 | security hardening waves | broad | checklist/sub-issues | L / split | Medium | Yes |
| 33 | #1311 | [SECURITY] Add KMS-backed receipt signing | receipts / security | P2 | receipt signing abstraction | `src/src/sign.rs`, config, receipt models | KMS mocked signing/verification tests | L | High | Yes |
| 34 | #1317 | [PERFORMANCE] Dashboard: virtualized table rendering for 10k+ rows | UI / performance | P2 | #1611, #1621 | table panels, Explore tables | large fixture render/perf smoke | M | Medium | No |
| 35 | #1337 | [PERFORMANCE] Profile and optimize MCP gateway proxy latency | MCP / perf | P2 | MCP proxy baseline | MCP routes/storage/policy | benchmark + regression tests | M | Medium | Maybe |
| 36 | #1389 | [EPIC] Build Agent Identity and Permission Governance | tenant/auth / identity | P2 | API/version/auth decisions | agents, permissions, docs | split into child issues | L / split | High | Yes |
| 37 | #1392 | [EPIC] Build SOC Intelligence Plane (AI Investigation Agents) | SOC | P2 | deterministic SOC + evidence complete | `lib/soc/*`, UI incidents, docs | sandbox/LLM non-enforcement tests | L / split | High | Yes |
| 38 | #1393 | [FEATURE] Build Triage Agent (Auto-Prioritize Alerts) | SOC automation | P2 | #1392 | `lib/soc/*`, docs | advisory-only tests | M | Medium | Yes |
| 39 | #1624 | [UI/U3] Add saved searches and drilldowns across Explore, Incidents, Agents, Receipts | UI / SOC | P2 | #1621 | Explore/drilldown hooks/state | URL persistence/drilldown tests | M | Medium | No |
| 40 | #1627 | [Backend Dependency] Complete alerting settings APIs for contact points, policies, silences | backend / SOC | P2 | alerting model | routes/storage/proto/OpenAPI | CRUD, redaction, audit tests | M | Medium | Maybe |
| 41 | #1633 | [UI/U6] Build Analytics dashboards for SOC metrics and product success metrics | UI / analytics | P2 | #1611, #1623 | dashboard schemas/panels | dashboard render/drilldown tests | M | Low | No |
| 42 | #1634 | [UI/U6] Build in-app dashboard editor as capstone, reusing DashboardSchema | UI / dashboards | P2 | dashboard framework stable | dashboard editor components, backend deps | schema validation/editor tests | L | Medium | Maybe |
| 43 | #1639 | [UI/Quality] Add mock data mode / Storybook-like component harness for SOC panels | UI / quality | P2 | design system stable | UI harness route/components | harness guard/component states | M | Low | No |
| 44 | #1640 | [Cleanup] docs/ARCHITECTURE.md and docs/architecture.md are two git-tracked files differing only by case | docs / CI | P3 | CI green | docs paths, links, possibly git mv | link checks / docs build | S | Medium | Yes |
| 45 | #1210 | [PROD-005] Add horizontal scaling support (shared state) | infra | P3 | storage/control abstractions | storage/config/deploy docs | multi-instance tests if feasible | L | High | Yes |
| 46 | #1394 | [FEATURE] Build Policy Advisor Agent (Recommend Policy Changes) | policy / SOC automation | P3 | #1392 | `lib/soc/*`, policy docs/UI | recommendation advisory tests | L / split | Medium | Yes |
| 47 | #1395 | [FEATURE] Build Threat Hunter Agent (Proactive Anomaly Search) | SOC automation | P3 | #1392 | `lib/soc/*`, query APIs/UI | non-enforcement and sandbox tests | L / split | Medium | Yes |
| 48 | #1396 | [EPIC] Build Prompt-Injection Detection Layer | prompt defense | P3 | provenance/detection architecture | `lib/soc/*`, policy, docs | deterministic gating tests | L / split | Medium | Yes |
| 49 | #1397 | [EPIC] Build Memory/RAG Poisoning Detection | prompt defense | P3 | #1396 | `lib/soc/*`, docs | detection tests | L / split | Medium | Yes |

## Recommended first PR

**Target:** restore green `main` CI by fixing Dashboard E2E pointer interception.

This is a CI work item rather than an existing numbered issue. Because the user rule says one issue per PR, create a focused issue first if none exists, e.g.:

```text
Title: [CI/UI] Restore Dashboard E2E after production console shell overlay regression
Labels: area/ui, kind/bug, priority/P0
```

Then implement:

- Branch: `fix/<new-issue-number>-dashboard-e2e-pointer-interception`
- PR title: `fix(issue-<new-issue-number>): restore dashboard e2e navigation`
- Likely root cause: the E2E helper attempts to click `Apply Config`, but production dashboard content/panels intercept pointer events during/after configuration UI rendering. The fix should stabilize the UI interaction contract, not weaken the test.
- Likely files:
  - `e2e/tests/helpers.ts`
  - `e2e/tests/dashboard-shell.spec.ts`
  - `ui/src/components/ConfigBar.tsx` or `ui/src/chrome/ControlsBar.tsx`
  - possibly `ui/src/chrome/AppShell.tsx`
- Tests/validation:
  - `cd ui && npm run lint`
  - `cd ui && npm run test`
  - `cd ui && npm run build`
  - `cd e2e && npx playwright test tests/dashboard-shell.spec.ts --project=chromium`
  - rerun or observe GitHub Actions Dashboard E2E.

## First PR implementation plan

1. Sync local branch to `origin/main` after preserving unrelated local/untracked files.
2. Create or identify a dedicated issue for the failing Dashboard E2E if no open issue exists.
3. Create `fix/<issue-number>-dashboard-e2e-pointer-interception`.
4. Reproduce locally with the exact E2E command against the Docker-served dashboard.
5. Inspect the failing screenshot/trace to determine whether the bug is:
   - an actual UI overlay/z-index/pointer-events issue, or
   - a brittle test selector/helper using a hidden/stale `Apply Config` button.
6. Apply the smallest correct fix:
   - Prefer making the configuration control accessible and non-overlapped.
   - Use stable labels/test IDs only if the UI behavior is already correct.
   - Do not force-click through a real overlay bug.
7. Add/adjust E2E assertions so future regressions fail with a precise cause.
8. Run UI unit tests/build/lint and targeted Playwright.
9. Open PR with root cause, solution, commands, CI run link, risk/rollback notes.
10. Merge only after required checks pass, then proceed to #1637.

