# UI Guide — the SOC Console

**One sentence:** the console is a schema-driven Bun SPA (`ui-next/`) served by the gateway at `/dashboard`, where dashboards are data, panels render frames, and every pixel maps to a `/v1` API.

> **Status:** Implemented / beta. Core dashboards, approvals, receipts, incidents, agent controls, runs, bans, quarantine, egress, graph, and policies exist. Prompt/model query timelines and richer incident drill-down remain incomplete.

## Overview

The console is the operator surface for evidence-backed investigation and response. It visualizes deterministic gateway state; it does not make authorization decisions and must never turn missing, stale, or advisory data into apparent permission.

## Why This Exists

Security teams need one tenant-scoped place to review exact approvals, verify receipts, correlate incidents, explore evidence, and issue controlled containment. Generic dashboards do not understand action hashes, source trust, receipt chains, or the difference between gateway status and runtime force-path enforcement.

> **Production tree:** `ui-next/` only (Bun + Vite + React 19). Binding contracts: [Console_UI_Bun_Contracts.md](./Console_UI_Bun_Contracts.md).

Hands-on onboarding: [onboarding/For_Frontend_Engineer.md](../onboarding/For_Frontend_Engineer.md). Design system: [AegisAgent_SOC_Console_Design_System.md](../AegisAgent_SOC_Console_Design_System.md). UX model: [AegisAgent_SOC_UI_Design.md](../AegisAgent_SOC_UI_Design.md).

## 1. App architecture

```mermaid
flowchart LR
    subgraph ui[ui-next/src]
        APP[app/: store · runtimeConfig · providers]
        CHROME[chrome/: shell + nav]
        DASH[dashboards/: schema · editor · system/*]
        DS[datasources/: gatewayEntity · socQuery · frame · aql · stream]
        PAN[panels/: PanelRuntime · standard/ · differentiators/]
        FEAT[features/: Approvals · Integrity · Explore · Agents · …]
        DSGN[design-system/tokens · hooks · lib]
    end
    DASH --> PAN
    DS -->|DataFrame| PAN
    APP --> DS
    FEAT --> DS
    GW[(Gateway /v1 + SSE/WS)] --> DS
```

Build output `ui-next/dist` is served by the gateway (`src/src/routes/dashboard.rs` — `/dashboard`, `/dashboard/*path`). Same-origin auth; no CORS gymnastics.

## 2. The dashboard schema

Dashboards conform to `ui-next/src/dashboards/schema.ts`: metadata + time range + layout rows of panels. Each panel is a `PanelDefinition` (`type`, `datasourceId`, optional `entity` / `snapshot` / `aggregate` / `options` / `drilldowns`).

Built-in **system templates** (copy-only in the editor; reserved UIDs) live in `ui-next/src/dashboards/system/`:

| UID | Board | Notable panels |
|---|---|---|
| `overview` | Tenant posture now | stats, **timeseries**, **heatmap**, **agent-risk-map**, feeds |
| `fleet` | Agent workforce | **agent-risk-map**, agent table |
| `integrity` | Receipt chain | **receipt-integrity**, **provable-timeline** |
| `approvals` | HITL queue | **approval-card** |
| `incidents` | SOC cases | table + **decision-graph** (latest case) |
| `detections` | Triggered alerts | tables / stats |
| `mcp` | MCP registry | tables / status |
| `rules` | Detection rules | tables |
| `alerting` | Webhook subscriptions | tables |
| `explore` | Explore template | AQL-oriented layout |

Tenant-editable boards: `GET/POST /v1/soc/dashboards`, `GET/PUT/DELETE /v1/soc/dashboards/:uid` (Phase D editor).

## 3. Datasources → frames → panels

Datasources (registered in `datasources/registry.ts`) normalize into **frames** (`frame.ts`). **Panels never fetch list data themselves** — `PanelRuntime` builds a `QueryRequest` and passes a `DataFrame` (differentiator panels may call mutation/verify/export helpers with operator context).

| Datasource | Role |
|---|---|
| `gateway-entity` | REST entities + snapshots (`tenant-stats`, `soc-summary`, `agent-scoreboard`, …) |
| `soc-query` | `POST /v1/soc/query` — `count_over_time` / `count_by` (absolute time tokens) |
| stream helpers | SSE/WS live tail (ControlsBar / feed) |
| `aql/` | Explore compile/autocomplete → structured filters |

### Panel registry (complete allowlist)

Registered in `ui-next/src/panels/registry.ts` (types in `panels/types.ts`). Zero chart-library dependency for v1 charts (pure SVG).

**Standard** (`panels/standard/`):

| Type | Renders |
|---|---|
| `stat` | Single number + optional thresholds |
| `table` | Columnar frame (badges for decision/trust/hash) |
| `timeseries` | SVG series from `count_over_time` (`bucket`/`count`) |
| `heatmap` | SVG categorical intensity from `count_by` (`value`/`count`) |
| `status` | Health / state chips |
| `feed` | Live-ish event list |
| `note` | Static markdown-ish body (no fetch) |

**Differentiators / fleet** (`panels/differentiators/`):

| Type | Renders | Primary APIs |
|---|---|---|
| `approval-card` ★ | Frozen action + `action_hash` + Approve/Reject | `/v1/approvals`, approve/reject |
| `provable-timeline` ★ | Receipt rows + per-row Verify | `/v1/receipts`, `…/verify` |
| `receipt-integrity` ★ | Chain summary + Verify range + evidence ZIPs | `verify-range`, `/v1/evidence/export`, compliance pack |
| `agent-risk-map` | Ranked 24h composite risk (advisory only) | `GET /v1/agents/risk-scoreboard` |
| `decision-graph` | Layered evidence graph SVG | `GET /v1/graph/{incident\|agent\|run}/:id` |

PR trail for charts + differentiators: **#1821–#1828**.

## 4. State, auth, tenancy

`app/store.ts` (client state) + `lib/http/client.ts` (fetch) + `app/runtimeConfig.ts`. Auth is the same bearer token as the API. Gateway enforces tenant scoping via `X-Aegis-Tenant-ID` — the UI never “filters tenants” client-side for isolation. Fail-closed: empty tenant blocks `/v1` calls.

## 5. Feature surfaces → backend APIs

| UI surface | Backing APIs |
|---|---|
| Approvals review | `GET /v1/approvals`, `POST /v1/approvals/:id/{approve,reject,edit}` |
| Integrity / receipts | `GET /v1/receipts*`, verify / verify-range, evidence packs |
| Incidents / graph | `GET /v1/incidents[/:id]`, `GET /v1/graph/incident/:id`, evidence-pack ZIP |
| Fleet / agent actions | `GET /v1/agents`, freeze/unfreeze/revoke/restore, risk-scoreboard |
| Explore | AQL → decisions / `POST /v1/soc/query` |
| Overview analytics | `POST /v1/soc/query` (`count_over_time`, `count_by`), snapshots |
| Live stream | ControlsBar stream subscription (gateway SSE/WS) |
| Tenant dashboards | `/v1/soc/dashboards` |

## 6. Runtime surfaces and remaining UI

The console ships `/runs`, `/runs/:id`, `/bans`, `/quarantine`, `/egress`, `/graph`, and `/policies`, including run controls and runtime-event/receipt timelines. These UI controls do not upgrade partial backend force paths into complete containment. Prompt/model timeline pages await backend query APIs; incident detail can become richer.

North-star chart libs (uPlot / ECharts / TanStack virtual table) stay swappable behind the panel registry — not required for the current SVG v1.

## 7. Testing

- Unit: `cd ui-next && bun test` (Bun test runner; colocated `*.test.ts`)
- Typecheck / lint: `bun run typecheck`, `bun run lint` (oxlint)
- E2E: Playwright in `e2e/` (`dashboard-*.spec.ts`, `mocked-soc-workflows.spec.ts`) against gateway + mock fixtures

## Example

```bash
cd ui-next
bun install --frozen-lockfile
bun test
bun run typecheck
bun run build
```

Then run Playwright against the selected gateway bundle. Verify empty/loading/error/unauthorized states as well as populated fixtures.

## Security

Production tokens are not persisted in browser storage. Tenant scope is enforced by the gateway, not client filtering. Escape attacker-controlled content, redact secrets, preserve exact action/hash display, label scores as advisory, confirm containment targets, and represent partial/runtime-unavailable state explicitly.

## Operations

Monitor asset/version mismatch, API errors, WebSocket/SSE reconnects, stale data, frontend exceptions, and containment mutation failures. The UI must degrade to clear unavailable states; analysts retain API/CLI/runbook paths. Rebuild `ui-next/dist` and verify `AEGIS_UI_BUNDLE`/`AEGIS_UI_DIST` when a deployed change does not appear.

## 8. Related docs

[Console_UI_Bun_Contracts.md](./Console_UI_Bun_Contracts.md) · [onboarding/For_Frontend_Engineer.md](../onboarding/For_Frontend_Engineer.md) · [AegisAgent_SOC_UI_Design.md](../AegisAgent_SOC_UI_Design.md) · [evidence-graph.md](../evidence-graph.md) · [api-reference.md](../api-reference.md) · `ui-next/README.md`
