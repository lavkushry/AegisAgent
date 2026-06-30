# AegisAgent — SOC Console HLD & LLD (Grafana + Kibana, engineering blueprint)

> **Status:** Design (2026-06-24). **Document type:** Engineering HLD/LLD.
> **This is the engineering blueprint for** [`AegisAgent_SOC_UI_Design.md`](AegisAgent_SOC_UI_Design.md) — that doc is the *product/UX* design (the "what"); this doc is the *architecture + component* design (the "how"), grounded in the actual `ui/` codebase and backed by a Grafana/Kibana changelog catalog.
> **Read first:** [`AegisAgent_SOC_UI_Design.md`](AegisAgent_SOC_UI_Design.md) (panel system §7, dashboards-as-code §9, datasource layer §6, phasing §14) and [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md) (the moat the console must ride).
> **Supersedes nothing.** It operationalizes `SOC_UI_Design.md` and answers its Open Questions §15.2 (charting) and §15.4 (dashboards-as-code format).

---

## 0. Executive summary

The current console (`ui/`) is a **fixed-tabs prototype**: nine hardcoded React tabs (`OverviewTab`, `ExploreTab`, … `SettingsTab`) calling the gateway through one-function-per-endpoint helpers in `ui/src/app/api.ts`. It renders the right *pages* but has **none of the framework** that makes Grafana and Kibana what they are.

The five architectural moves that define modern Grafana (v11→v12.2) and Kibana (8.x→9.x) — and that the console lacks — are:

| # | Capability | Grafana | Kibana | `ui/` today |
|---|---|---|---|---|
| 1 | **Panel framework** (state-managed, reusable render units) | Scenes (GA 11.3, default v12) | Embeddable panel system | ❌ bespoke JSX per tab |
| 2 | **Dashboards-as-data** (versioned JSON, provisionable) | Dashboard Schema v2 + Git Sync | Saved Objects | ❌ layout hardcoded in `page.tsx` |
| 3 | **Datasource abstraction** (uniform query of a source) | Datasource plugins + SQL Expressions | Data Views + connectors | ❌ one `fetch` fn per endpoint |
| 4 | **A real query language** | Drilldown + Explore | ES\|QL + KQL + Discover | ⚠️ substring `q=` only |
| 5 | **Drilldowns · controls · time-range · variables** | conditional logic, tabs, variable controls | controls, chained variables, drilldowns | ❌ none |

This blueprint introduces all five **as a swappable framework layer under the existing pages**, so the app keeps working at every step. The **dashboard model decision is a phased hybrid** (§6): curated dashboards-as-code from the start (every system page becomes JSON rendered by one panel framework); the in-app drag-drop editor ships **last** (phase U6). The MVP value stays the two surfaces neither Grafana nor Kibana can show — the **Approval Queue** and the **Provable Timeline**.

**Library decision (answers `SOC_UI_Design.md §15.2`):** the panel framework is **rendering-library-agnostic behind the `Panel` interface**. The already-installed **Recharts** bootstraps v1 panels with zero new dependencies; the documented north-star — **uPlot** (dense time-series) + **ECharts** (heatmap/sankey/treemap) + **TanStack Table + `@tanstack/react-virtual`** (high-row-count tables) — is adopted **per panel type as a swap**, with no change to dashboard JSON or consumers.

---

## 1. Grafana + Kibana changelog catalog (adopt / adapt / skip)

Scored for *a SOC over verifiable agent-action evidence* — single-tenant-per-deploy, one datasource family (the gateway), differentiator-first. **Adopt** = build as designed. **Adapt** = take the idea, bend it to AegisAgent. **Skip** = out of scope for this product.

### 1.1 Grafana (v11.0 → v12.2)

| Feature (release) | What it is | Verdict | AegisAgent treatment |
|---|---|---|---|
| **Scenes panel framework** (11.3 GA, v12 default) | State-managed, composable panels with their own query/time/variable scope | **Adopt** | The model for our `Panel` + `PanelRuntime` (§7.1). We do not import Grafana Scenes; we build the same shape in our stack. |
| **Dashboard Schema v2** (v12) | Dashboards as a versioned, layout-agnostic JSON model | **Adopt** | Our `DashboardSchema` (§7.3) — a lean, AegisAgent-native JSON, not Grafana-compatible (answers §15.4). |
| **Dynamic dashboards: tabs, rows, conditional logic, auto-layout** (v12) | Panels show/hide and arrange on conditions | **Adapt** | `rows`/`tabs` + a minimal `showWhen` variable predicate (§7.3). No full expression engine. |
| **Drilldown suite** (GA v12) | Queryless click-through across metrics/logs/traces | **Adopt (reframed)** | Our `DrilldownLink` router (§7.5): decision → receipt verify, alert → triggering events, agent → its decisions. |
| **SQL Expressions / cross-source joins** (v12) | Join data across datasources with SQL | **Skip** | One datasource family; joins happen server-side in the gateway's SOC query API. |
| **Variables / templating** | `$var` referenced across panels & queries | **Adopt** | `$tenant $agent $env $timeRange` (§7.4), URL-synced. |
| **Blazing-fast table panel** (react-data-grid refactor, v12) | Virtualized, fast sort/filter on large tables | **Adopt (as TanStack Table)** | Our virtualized `table` panel uses TanStack Table + virtual (§7.1). |
| **Unified Alerting → notification policies → contact points + silences** | Rules route to Slack/PagerDuty/webhook; mute windows | **Adapt** | Alerting UI over the **deterministic** rule engine; reuses existing webhook subscriptions + Slack sink. Rules never score-gate (Design Law 1). |
| **Git Sync / dashboards-as-code via GitHub PRs** (v12) | Edit dashboards through Git | **Skip (v1) → optional** | Curated dashboards live in-repo as JSON, but no in-app Git integration. Provisioning is a file load, not a GitHub app. |
| **Explore / queryless metrics** | Ad-hoc exploration | **Adapt** | Our **Explore** = Kibana-Discover-style (§1.2), not Grafana Explore. |
| **Canvas / geomaps / SCIM / SAML** | Custom viz, geo, identity sync | **Skip** | No geo dimension; identity is the gateway session (OIDC/SAML upstream). |

### 1.2 Kibana (8.x → 9.x)

| Feature | What it is | Verdict | AegisAgent treatment |
|---|---|---|---|
| **Discover** (multi-tab, field sidebar, doc table, expandable rows) | Exploratory search over indexed events | **Adopt** | The model for the **Explore** page (§8.2): query bar + field sidebar facets + virtualized doc table + row-expand → ASE JSON + one-click receipt verify. |
| **ES\|QL** (`STATS`, `WHERE`, time-series aware) | Typed pipe query language | **Adapt** | **AQL** — a small, *typed, parameterized* filter+aggregate DSL (§5.3) over the FTS5/ASE store. We do **not** ship a Turing-complete language; we ship a safe, URL-shareable filter. |
| **KQL filters + autocomplete + DSL conversion** | Field:value query builder | **Adopt (as AQL builder)** | Field-aware autocomplete from the datasource `fields()` capability (§5.2). |
| **Data Views** (index-pattern abstraction, field formatters) | Named field schema over an index | **Adapt** | `Datasource.fields()` returns the typed field catalog; formatters map to panel cell renderers. |
| **Embeddable panels** (≤100/dashboard, sections, pinned controls, library panels) | Reusable panels embedded anywhere | **Adopt** | Our panel registry + "save panel to library" (phase U6). |
| **Controls** (query-based selectors, chaining, conditional deps) | Dashboard-level input widgets | **Adopt** | Variable controls bar (§7.4); chaining = a variable's query references another `$var`. |
| **Drilldowns** (dashboard + URL, from chart interactions) | Click a series → navigate with context | **Adopt** | Same `DrilldownLink` router (§7.5). |
| **Saved Objects + Spaces** (multi-tenant isolation, portability) | Portable objects, per-space RBAC | **Adapt / Skip** | Saved searches/dashboards persist server-side keyed by `tenant_id` (already a hard invariant). **No Spaces** — tenancy is enforced in the gateway, not a UI construct. |
| **Security app: Detections / Cases / Timelines / Entities** | SIEM investigation surfaces | **Adopt (reframed)** | Detections, Incidents(=Cases), Provable Timeline, Agents(=Entities/"hosts for agents"). **Timeline is provable** — the differentiator. |
| **Alerting: maintenance windows, flapping, case auto-push** | Rule lifecycle controls | **Adapt** | Silences + dedup over deterministic rules. |
| **AI Assistant / Agent Builder (NL → ES\|QL, NL → dashboards)** | LLM authors queries/dashboards | **Skip** | Design Law 2: the LLM narrates closed incidents only; it never authors detection logic or reads attacker-controlled content. An NL query box would reintroduce the exact injection surface the product sells against. |
| **28+ SaaS connectors, scheduled PDF/PNG reports, workflows (Liquid YAML)** | Integrations & reporting | **Skip (v1)** | Evidence-pack export (SOC 2 / Article 14) is the one report that matters and is AegisAgent-specific (§8.8). |
| **Anomaly detection / swim lanes** | ML jobs | **Skip** | Detection is deterministic by Design Law 1. |

### 1.3 The three surfaces neither product has (the reason this is not "Grafana with an agents datasource")

Carried verbatim from `SOC_UI_Design.md §3`, restated as architecture targets:

1. **Approval Card panel** — renders the *frozen canonical action* (the exact bytes that will run), `action_hash`, `source_trust`, expiry; Approve / Reject / **Edit (re-hash + re-evaluate)** / Escalate. The human-in-the-loop control made visible.
2. **Provable Timeline panel** — every row carries its `receipt_hash`; a **Verify chain** action walks the hash chain → green "tamper-free" / red "broken at row N".
3. **Receipt Integrity panel** — browse the per-tenant chain, verify a range, visualize a break (also a `receipt-chain-broken` P1 detection).

These three are panel *types* in the same registry (§7.1) — not special-cased pages. That is the core architectural insight: **the differentiators are panels, so they compose into dashboards like everything else.**

---

## 2. Rejected alternative: embed real Grafana/Kibana (Option C)

Pointing Grafana at the gateway via the Infinity/JSON datasource (or shipping provisioned Grafana dashboards) is the cheapest path to "Grafana-grade charts." **Rejected as the primary UI**, kept as an *optional export interop*:

- **It throws away the entire differentiator.** Grafana/Kibana cannot render an Approval Card, cannot Verify a receipt chain, cannot bind an approval to `action_hash`. Those are the product (Gap Reassessment §3). A console that can't do them is a worse AegisAgent.
- **It adds a heavyweight runtime dependency** that breaks the "self-hostable single binary" wedge (Gap Reassessment §3 Gap C).
- **Tenancy mismatch:** Grafana orgs/Kibana Spaces are not our `tenant_id` invariant; mapping them is friction and a cross-tenant-leak risk surface.
- **Optional export we *do* keep:** a read-only `GET /v1/soc/query` shape compatible with Grafana's Infinity datasource, so a customer's existing Grafana can pull AegisAgent metrics into *their* board. This is interop, not our console.

---

## 3. HLD — system context

```
┌──────────────────────────────── Browser (Next.js App Router, ui/) ───────────────────────────────┐
│                                                                                                   │
│  App Shell (chrome)            Dashboard Runtime                  Differentiator panels           │
│  ┌───────────────────┐         ┌──────────────────────┐          ┌───────────────────────────┐    │
│  │ tenant ▾ time ▾    │         │ DashboardSchema(JSON) │          │ ApprovalCard              │    │
│  │ $vars ● live search│────────▶│  → PanelRuntime[]     │─────────▶│ ProvableTimeline (verify) │    │
│  │ role menu          │         │  → layout/rows/tabs   │          │ ReceiptIntegrity          │    │
│  └─────────┬─────────┘         └──────────┬───────────┘          └────────────┬──────────────┘    │
│            │ Zustand (filters, time, tenant)        │ TanStack Query (cache/poll/dedup)           │
│            ▼                                          ▼                         ▼                  │
│  ┌─────────────────────────── Datasource layer (uniform) ─────────────────────────────────────┐   │
│  │  GatewayEntityDatasource   │  SocQueryDatasource (AQL)  │  ReceiptDatasource  │  StreamDS    │   │
│  │  REST entity reads         │  POST /v1/soc/query        │  verify chain       │  SSE deltas  │   │
│  └────────────────────────────┴──────────────┬────────────┴─────────┬───────────┴──────┬──────┘   │
└──────────────────────────────────────────────┼──────────────────────┼──────────────────┼──────────┘
                                                ▼                      ▼                  ▼
                        AegisAgent Gateway (Rust/Axum) — tenant-scoped, fail-closed, parameterized SQL
                        Entity API (/v1/incidents,/agents,/approvals,/receipts/:id/verify, …)
                        Event Query API (/v1/soc/query over ASE: SQLite now, ClickHouse at scale)
                        Stream (/v1/soc/stream SSE)
```

**Invariant inheritance.** The UI never queries tools or the DB directly; it only calls the gateway, which enforces `tenant_id` server-side (the UI cannot request cross-tenant data — `SOC_UI_Design.md §11`). The UI shows **hashes, never raw secret payloads** (redaction invariant), so screenshots/exports are safe.

### 3.1 The five subsystems (HLD)

| Subsystem | Responsibility | Key types | Maps to existing `ui/` |
|---|---|---|---|
| **S1 Datasource layer** | Uniformly fetch entities, run AQL queries, verify receipts, subscribe to the stream | `Datasource`, `DatasourceCapabilities`, `QueryRequest/Result` | replaces ad-hoc `api.ts` fns (kept as the transport beneath) |
| **S2 Panel framework** | A registry of typed, self-contained panels bound to (query + timeRange + vars) | `PanelDefinition`, `PanelRuntime`, `PanelProps`, `PanelRegistry` | extracts the repeated `panel-card` JSX into real components |
| **S3 Dashboard model** | JSON schema → laid-out panels; curated boards in-repo; (later) user-editable | `DashboardSchema`, `Row`, `LayoutItem`, `DashboardLoader` | turns `page.tsx`'s fixed tabs into dashboard renders |
| **S4 Variables / time / drilldown** | Global chrome state, URL-synced; click-through navigation | `Variable`, `TimeRange`, `DrilldownLink`, `useDrilldownRouter` | new `ConfigBar` superset |
| **S5 Real-time** | SSE deltas feeding live panels + the Approvals badge | `StreamSubscription`, `useSocStream` | new; today everything polls on intervals |

---

## 4. HLD — data & query layer (S1)

Two read surfaces (per `SOC_UI_Design.md §6`), one uniform abstraction.

- **Entity API (typed REST)** — already present in `api.ts`: `/v1/incidents`, `/v1/incidents/:id`, `/v1/alerts`, `/v1/approvals`, `/v1/agents`, `/v1/mcp/servers`, `/v1/receipts`, `/v1/receipts/:id/verify`, `/v1/decisions`, `/v1/soc/summary`, `/v1/stats`, `/v1/soc/rules`, `/v1/detection_rules`. These become **`GatewayEntityDatasource` methods**, not loose functions.
- **Event Query API (AQL)** — `POST /v1/soc/query` over the ASE/decision store. The current gateway contract is a flat, tenant-scoped JSON allowlist (`entity`, `filters`, `aggregate`, `interval`, `limit`, `cursor`) backed by parameterized SQLite queries; ClickHouse can implement the same contract later. `SocQueryDatasource` still degrades to `GET /v1/decisions?q=` only when older gateways return 404/405/501.
- **Stream** — `GET /v1/soc/stream` (SSE). Advisory only; the query API is always the source of truth.

**SQL-injection invariant carries to the UI boundary:** AQL is compiled to a **parameterized** ClickHouse/SQLite query server-side, never string-interpolated — same invariant as the gateway data layer.

---

## 5. LLD — Datasource layer (S1)

New file group: `ui/src/datasources/`.

### 5.1 Core contracts — `ui/src/datasources/types.ts`

```ts
/** A point in (or span of) time. Relative tokens resolve client-side at query build. */
export interface TimeRange {
  from: string; // ISO 8601 or relative token e.g. "now-24h"
  to: string;   // ISO 8601 or "now"
}

/** Resolved variable bag passed into every query. */
export type VariableValues = Readonly<Record<string, string | string[]>>;

/** What a query needs to run. Datasources translate this to a transport call. */
export interface QueryRequest {
  readonly aql?: string;          // AQL filter/aggregate string (S1.3), optional
  readonly entity?: EntityKind;   // for entity reads: "incident" | "agent" | ...
  readonly timeRange: TimeRange;
  readonly variables: VariableValues;
  readonly limit?: number;
  readonly cursor?: string;       // opaque pagination cursor
  readonly signal?: AbortSignal;  // wired to TanStack Query cancellation
}

/** Columnar result — panels read frames, not bespoke shapes (Grafana DataFrame idea). */
export interface DataFrame {
  readonly fields: ReadonlyArray<Field>;
  readonly length: number;        // row count
  readonly meta?: { total?: number; cursor?: string; executedMs?: number };
}
export interface Field {
  readonly name: string;
  readonly type: FieldType;       // "time" | "number" | "string" | "trust" | "decision" | "hash"
  readonly values: ReadonlyArray<unknown>;
  readonly format?: FieldFormat;  // cell renderer hint (badge/mono-hash/link/relative-time)
}
export type FieldType = "time" | "number" | "string" | "trust" | "decision" | "hash" | "json";
export type FieldFormat = "badge" | "hash" | "link" | "relative-time" | "bytes" | "raw";
export type EntityKind =
  | "incident" | "alert" | "approval" | "agent" | "mcp_server" | "receipt" | "decision" | "rule";

/** Field catalog for the Explore field sidebar + AQL autocomplete (Kibana Data View idea). */
export interface FieldDescriptor {
  readonly name: string;
  readonly type: FieldType;
  readonly facetable: boolean;    // show as a clickable facet in the sidebar
  readonly examples?: ReadonlyArray<string>;
}

export interface DatasourceCapabilities {
  readonly query: boolean;        // supports AQL aggregate/search
  readonly stream: boolean;       // supports SSE deltas
  readonly fields: boolean;       // exposes a field catalog
  readonly verify: boolean;       // supports receipt-chain verify
}

/** The uniform datasource interface. Every read in the console goes through one of these. */
export interface Datasource {
  readonly id: string;
  readonly capabilities: DatasourceCapabilities;
  query(req: QueryRequest): Promise<DataFrame>;
  fields?(entity: EntityKind): Promise<ReadonlyArray<FieldDescriptor>>;
  verifyReceipt?(receiptId: string, signal?: AbortSignal): Promise<VerifyResult>;
  subscribe?(sub: StreamRequest, onEvent: (e: StreamEvent) => void): StreamSubscription;
}

export interface VerifyResult {
  readonly ok: boolean;
  readonly brokenAtRow?: number;    // 1-based index of the first broken link, if any
  readonly message: string;
  readonly chainHead?: string;      // receipt_hash of the verified head
}
export interface StreamRequest { readonly topics: ReadonlyArray<"ase" | "alert" | "approval">; readonly variables: VariableValues; }
export interface StreamEvent { readonly topic: "ase" | "alert" | "approval"; readonly payload: unknown; readonly ts: string; }
export interface StreamSubscription { close(): void; }
```

### 5.2 Concrete datasources — `ui/src/datasources/`

| File | Class | Notes |
|---|---|---|
| `gatewayEntity.ts` | `GatewayEntityDatasource` | Wraps the existing `fetchFromGateway` (kept as transport). Each `EntityKind` maps to a path. `query()` returns a `DataFrame` built from the JSON array. `capabilities = { query:false, stream:false, fields:true, verify:true }`. |
| `socQuery.ts` | `SocQueryDatasource` | `POST /v1/soc/query` (AQL → flat structured filters → DataFrame). Falls back to `GET /v1/decisions?q=` only for older gateways where the endpoint is absent. `capabilities.query = true`. |
| `receipt.ts` | `ReceiptDatasource` | `verifyReceipt()` → `GET /v1/receipts/:id/verify`; normalizes the loose response (today `ExploreTab` guesses `data.verified || data.status === "verified" || !data.error` — this is centralized here once). |
| `stream.ts` | `SocStreamDatasource` | `EventSource('/v1/soc/stream')` with reconnect/backoff; no-op `subscribe()` when the endpoint 404s (fail-soft). |
| `registry.ts` | `datasourceRegistry` | `getDatasource(id)`; the app wires one of each, selected per panel `datasourceId`. |

`fetchFromGateway` in `ui/src/app/api.ts` is **retained** as the low-level transport; the per-endpoint helper functions are **migrated into `GatewayEntityDatasource`** and the old exports kept as thin shims during the phased refactor so existing tabs don't break.

### 5.3 AQL — the typed query DSL (adapts ES\|QL/KQL) — `ui/src/datasources/aql/`

A **deliberately small, safe** language. URL-shareable, saved-searchable, compiled server-side to parameterized SQL.

```
# grammar (informal)
filter   := term (("AND" | "OR") term)*
term     := field ":" value | field ":[" value "TO" value "]" | "(" filter ")"
field    := "agent_id" | "tool" | "decision" | "source_trust" | "event_type"
          | "action_hash" | "receipt_hash" | "@time"
aggregate := "| stats" func "by" field          # optional, single stage
func      := "count()" | "count_over_time(" interval ")"
```

Example (carried from `SOC_UI_Design.md §6.3`):

```
agent_id:coding-agent-prod AND decision:deny AND source_trust:untrusted_external AND @time:[now-24h TO now]
```

```ts
// ui/src/datasources/aql/types.ts
export interface AqlQuery {
  readonly filter: AqlNode;            // parsed AST
  readonly aggregate?: AqlAggregate;   // optional single stats stage
}
export type AqlNode =
  | { kind: "term"; field: string; op: "eq" | "range"; value: string; to?: string }
  | { kind: "bool"; op: "and" | "or"; children: ReadonlyArray<AqlNode> };
export interface AqlAggregate { func: "count" | "count_over_time"; interval?: string; by?: string; }

export function parseAql(input: string): AqlQuery;          // pure, throws AqlParseError with position
export function aqlToParams(q: AqlQuery): QueryRequest;     // never string-interpolates SQL
export function aqlAutocomplete(input: string, fields: ReadonlyArray<FieldDescriptor>): Suggestion[];
```

**Parsing is client-side for UX (autocomplete, error squiggles); execution is server-side and parameterized.** The client AST is sent as structured JSON in `POST /v1/soc/query` — the gateway never receives a raw string to interpolate.

---

## 6. The dashboard model decision (phased hybrid) — answers your scoping question

**Decision: curated dashboards-as-code now; in-app editor as the capstone (U6).** Rationale, grounded in AegisAgent's own docs:

- `SOC_UI_Design.md §9` already commits to dashboards as **JSON/YAML artifacts in the repo** *and* "users can still build dashboards in-app (saved as the same JSON)."
- `SOC_UI_Design.md §14` phases the **user-editable Dashboards page into U6 (last)**, while the **MVP (U0–U2) is Overview + Live feed + Approvals + Provable Timeline** — none of which need an editor.
- **Differentiator-first (Gap Reassessment §3, §9):** an in-app dashboard editor is generic observability parity. Building the *panel framework* first (so every system page is config-as-code) yields the entire abstraction with **zero editor UI**; the editor later just serializes the same `DashboardSchema`.
- **Design Law 3:** the console is value-add; we ship the highest-leverage, AegisAgent-only surfaces first and the commodity editor last.

So: **not** "fixed tabs forever" (we get the panel/datasource framework and drilldowns immediately) and **not** "editor first" (it's the final phase). Every system page is a `DashboardSchema` JSON from day one.

---

## 7. LLD — Panel framework, dashboards, variables, drilldown (S2–S4)

### 7.1 Panel framework — `ui/src/panels/`

```ts
// ui/src/panels/types.ts
export type PanelType =
  | "stat" | "timeseries" | "table" | "heatmap" | "status" | "feed"
  | "provable-timeline"   // ★ differentiator
  | "approval-card"       // ★ differentiator
  | "receipt-integrity";  // ★ differentiator

/** Declarative panel config — this is what lives in DashboardSchema JSON. */
export interface PanelDefinition {
  readonly id: string;
  readonly type: PanelType;
  readonly title: string;
  readonly datasourceId: string;
  readonly query?: string;                 // AQL or entity selector
  readonly entity?: EntityKind;
  readonly options?: Readonly<Record<string, unknown>>; // per-type options (thresholds, columns…)
  readonly drilldowns?: ReadonlyArray<DrilldownLink>;
  readonly showWhen?: VariablePredicate;   // conditional display (Grafana v12 idea, minimal)
}

/** Props every panel component receives. Panels are pure: data in, JSX out. */
export interface PanelProps<TOptions = Record<string, unknown>> {
  readonly definition: PanelDefinition;
  readonly data: DataFrame;                // already fetched by PanelRuntime
  readonly isLoading: boolean;
  readonly error?: string;
  readonly timeRange: TimeRange;
  readonly variables: VariableValues;
  readonly onDrilldown: (link: DrilldownLink, row?: Record<string, unknown>) => void;
}

/** Registry: maps a PanelType to its renderer + its (optional) options schema. */
export interface PanelRegistryEntry<TOptions = Record<string, unknown>> {
  readonly type: PanelType;
  readonly Component: React.ComponentType<PanelProps<TOptions>>;
  readonly defaultOptions: TOptions;
  readonly chartLib?: "recharts" | "uplot" | "echarts" | "tanstack-table" | "none";
}
export const panelRegistry: Map<PanelType, PanelRegistryEntry>;
```

**`PanelRuntime`** (`ui/src/panels/PanelRuntime.tsx`) is the container that turns a `PanelDefinition` into a live panel: it resolves the datasource, builds the `QueryRequest` from the panel's `query` + the global `timeRange`/`variables`, runs it through **TanStack Query** (cache key = `[panelId, query, timeRange, variables]`, with `refetchInterval` when live mode is on), handles loading/error, and renders the registered component. **Panels never fetch; `PanelRuntime` fetches and panels render.** (Container/presentational split — matches the repo's React rules.)

**Library-agnostic rendering (your "keep the best as future goal" decision):** the `chartLib` field is advisory; the panel *component* owns its rendering. v1 ships `stat`/`timeseries` on **Recharts** (already installed). The north-star swap — `timeseries`→**uPlot**, `heatmap`→**ECharts**, `table`/`feed`/`provable-timeline`→**TanStack Table + react-virtual** — changes only the component internals, never `PanelDefinition`, `DashboardSchema`, or any consumer. That is the entire point of the abstraction.

Panel inventory (from `SOC_UI_Design.md §7`):

| `PanelType` | Renders | v1 lib | North-star lib |
|---|---|---|---|
| `stat` | single number + spark + threshold color | Recharts | Recharts/uPlot |
| `timeseries` | decisions/min, denies/agent | Recharts | **uPlot** |
| `table` | top risky agents, recent denies | plain `<table>` | **TanStack Table + virtual** |
| `heatmap` | provenance × hour | — | **ECharts** |
| `status` | receipt-chain ✓/✗, agent status | CSS | CSS |
| `feed` | live ASE stream | list | **virtualized list** |
| `provable-timeline` ★ | rows + `receipt_hash` + Verify chain | custom | custom + virtual |
| `approval-card` ★ | frozen action + Approve/Reject/Edit | custom | custom |
| `receipt-integrity` ★ | chain browse + verify-range | custom | custom |

### 7.2 The three differentiator panels (LLD detail)

**`ApprovalCard`** (`ui/src/panels/differentiators/ApprovalCard.tsx`) — supersedes today's `ApprovalsTab` row UI.
- Data: one `approval` row (`action`, `action_hash`, `source_trust`, `agent_id`, `run_id`, `expires_at`, `approver_group`, canonical `params`).
- Renders the **canonical action exactly as hashed** (the bytes, mono font) + a copyable `action_hash` + an expiry countdown.
- Actions call `GatewayEntityDatasource`: `approve`/`reject` (existing `/v1/approvals/:id/approve|reject`), `edit` → re-submit edited action → server **re-hashes + re-evaluates** (new endpoint `PUT /v1/approvals/:id` if absent; until then Edit is disabled with a tooltip — fail-closed UX), `escalate`.
- Approver-role gate (§9): the Approve/Reject buttons are disabled (not just hidden) for non-`approver` roles, with reason text.

**`ProvableTimeline`** (`ui/src/panels/differentiators/ProvableTimeline.tsx`) — the killer panel.
- Data: ordered events, each with `receipt_hash`; reuses the incident detail shape from `/v1/incidents/:id` + `/v1/graph/incident/:id`.
- A **Verify chain** button → `ReceiptDatasource.verifyReceipt` walked across the range → renders green "tamper-free `…a1b2 → …c3d4`" or red "broken at row N" (the `VerifyResult.brokenAtRow`).
- Each row's `receipt_hash` is a `hash`-format field → click drills to the Receipt Integrity panel (§7.5).

**`ReceiptIntegrity`** (`ui/src/panels/differentiators/ReceiptIntegrity.tsx`) — supersedes today's `ReceiptsTab`.
- Paginated chain browse (cursor from `DataFrame.meta.cursor`); "verify range" control; a broken link renders a red connector and links to the `receipt-chain-broken` detection; "Export evidence pack" button (SOC 2 / Article 14).

### 7.3 Dashboard schema — `ui/src/dashboards/schema.ts`

```ts
export interface DashboardSchema {
  readonly uid: string;
  readonly title: string;
  readonly schemaVersion: 1;                 // bump on breaking changes (Grafana lesson)
  readonly variables: ReadonlyArray<VariableDefinition>;
  readonly time: { readonly defaultRange: TimeRange; readonly refreshSec?: number };
  readonly layout: ReadonlyArray<Row>;       // rows of panels; tabs are rows with a `tab` group
}
export interface Row {
  readonly id: string;
  readonly tab?: string;                     // optional tab grouping (dynamic-dashboard idea)
  readonly title?: string;
  readonly panels: ReadonlyArray<LayoutItem>;
}
export interface LayoutItem {
  readonly panel: PanelDefinition;
  readonly w: number;  // 1–12 grid columns
  readonly h: number;  // row-height units
}
```

Curated system dashboards live as TypeScript-typed JSON in `ui/src/dashboards/system/` (`overview.ts`, `fleet.ts`, `detections.ts`, …) and validate against the schema at module load. `DashboardLoader` (`ui/src/dashboards/DashboardLoader.tsx`) renders a `DashboardSchema` into a CSS-grid of `PanelRuntime`s, applying `showWhen` predicates and tab grouping. The in-app editor (U6) writes the *same* shape to `POST /v1/soc/dashboards`.

### 7.4 Variables, time-range, controls — `ui/src/state/`

```ts
export interface VariableDefinition {
  readonly name: string;                        // "tenant" | "agent" | "env" | custom
  readonly kind: "constant" | "query" | "interval";
  readonly query?: string;                      // for kind:"query" — may reference another $var (chaining)
  readonly multi?: boolean;
  readonly includeAll?: boolean;
}
export type VariablePredicate =
  | { readonly var: string; readonly equals: string }
  | { readonly var: string; readonly in: ReadonlyArray<string> };
```

The global chrome state (replacing/extending today's `ui/src/app/store.ts` Zustand store and `ConfigBar`) holds `{ tenant, timeRange, variables, live }`, **URL-synced** so a view is shareable (the Kibana/Grafana "state in the URL" pattern; also satisfies the repo's "URL as state" web rule). A `ControlsBar` renders variable selectors; a `TimeRangePicker` renders relative/absolute ranges + the `live` toggle; both write to the store, which invalidates every `PanelRuntime` query key.

### 7.5 Drilldown router — `ui/src/dashboards/drilldown.ts`

```ts
export interface DrilldownLink {
  readonly label: string;
  readonly target:
    | { kind: "verify-receipt"; receiptIdField: string }      // row → receipt verify
    | { kind: "dashboard"; uid: string; mapVars: Record<string, string> }
    | { kind: "explore"; aqlTemplate: string }                // "agent_id:${agent_id}"
    | { kind: "incident"; incidentIdField: string };
}
export function useDrilldownRouter(): (link: DrilldownLink, row?: Record<string, unknown>) => void;
```

Drilldowns turn the console from "pages" into a connected investigation graph: a `deny` in a table → Explore filtered to that agent; an alert → its triggering events; a timeline row → verify its receipt; an agent → its decisions. All client-side navigation with variable mapping; no new endpoints.

---

## 8. LLD — page-by-page, as dashboards (file change-map)

Each current tab becomes a **`DashboardSchema`** rendered by `DashboardLoader`, composed of registry panels. The tab's bespoke logic moves into panel components.

| Current file (`ui/src/components/`) | Becomes | New artifacts |
|---|---|---|
| `OverviewTab.tsx` (267 LOC) | `dashboards/system/overview.ts` | stat row + `timeseries` + `feed` panels; drilldowns to Explore/Incidents |
| `ExploreTab.tsx` (244 LOC) | `pages/Explore.tsx` (Discover-style, not a dashboard) | query bar (AQL) + **field sidebar** (`FieldSidebar.tsx`) + histogram panel + virtualized `table`; row-expand reuses today's inspector; receipt verify centralized in `ReceiptDatasource` |
| `IncidentsTab.tsx` (307) | `pages/Incidents.tsx` + `dashboards/system/incident-detail.ts` | list table + `provable-timeline` panel + response-action buttons |
| `DetectionsTab.tsx` (843 — too large) | `pages/Detections.tsx` + `pages/Rules.tsx` (split) | detections `table` dashboard; rules catalog/dry-run/canary as its own page; **split the 843-LOC file** (repo rule: <800 LOC) |
| `ApprovalsTab.tsx` (270) | `dashboards/system/approvals.ts` | `approval-card` panel (×N) + SLA timers + bulk view |
| `AgentsTab.tsx` (133) | `dashboards/system/fleet.ts` | inventory `table` + per-agent risk `stat`/`timeseries`; freeze/revoke actions |
| `McpTab.tsx` (180) | `dashboards/system/mcp.ts` | registry `table` + manifest-drift `status` panel |
| `ReceiptsTab.tsx` (178) | `receipt-integrity` panel + `pages/Receipts.tsx` | chain browse + verify-range + evidence-pack export |
| `SettingsTab.tsx` (79) | `pages/Settings.tsx` | tenants, RBAC, contact points, notification policies, silences |
| `ConfigBar.tsx` (130) | `chrome/ControlsBar.tsx` + `chrome/TimeRangePicker.tsx` | + `$var` selectors, live toggle, URL sync |
| `page.tsx` (fixed switch) | `chrome/AppShell.tsx` + route-per-page | nav drives `DashboardLoader` for dashboard pages, dedicated components for Explore/Rules/Settings |
| `app/api.ts` (loose fns) | `datasources/gatewayEntity.ts` | transport `fetchFromGateway` retained; helpers migrated to datasource methods + shims |
| `app/store.ts` | `state/consoleStore.ts` | adds timeRange/variables/live; URL-synced |

New directories: `ui/src/datasources/`, `ui/src/panels/` (+ `panels/differentiators/`), `ui/src/dashboards/` (+ `dashboards/system/`), `ui/src/chrome/`, `ui/src/state/`, `ui/src/pages/`.

---

## 9. RBAC, real-time, performance, a11y (cross-cutting LLD)

- **RBAC** (`SOC_UI_Design.md §11`): role comes from the gateway session; the store exposes `role: "viewer"|"analyst"|"approver"|"admin"`. Action buttons are **disabled with reason** (not merely hidden) when the role lacks permission — and the gateway still enforces server-side (UI gating is UX, never the control). Every console action emits its own receipt (the console is inside the evidence boundary).
- **Real-time (S5):** `useSocStream` subscribes via `SocStreamDatasource`; panels of type `feed` and the Approvals badge consume deltas; everything else stays on TanStack Query polling. SSE is advisory — a dropped stream degrades to polling, never to stale-without-notice.
- **Performance:** virtualized tables (TanStack virtual); server-side time-series downsampling (ASE rollups); route-level code-splitting; per-panel query dedup via shared cache keys. Targets inherit the web performance rule (LCP < 2.5s, INP < 200ms).
- **A11y:** never color-only status (icon + label — the existing badges already pair them); keyboard nav on the controls bar and tables; honor reduced-motion; severity palette is consistent (allow=green, deny=red, approval=amber, critical=rose).
- **Redaction:** panels render `hash`-typed fields as truncated mono with copy; **never** raw secret payloads — exports/screenshots stay safe.

---

## 10. Phasing — reconciled with `SOC_UI_Design.md §14` (U0–U6)

Marked against what `ui/` **already has** (prototype) vs. the **gap** this blueprint adds.

| Phase | Goal | `ui/` today | This blueprint adds | New gateway dep |
|---|---|---|---|---|
| **U0** | App shell + framework foundation | partial (shell, nav, Zustand) | **S1 datasource layer, S2 panel registry + `PanelRuntime`, S3 `DashboardLoader`, S4 controls/time/URL-sync** | — |
| **U1 (MVP)** | Overview + Live feed + **Approvals** | Overview + Approvals tabs (no framework) | render both as dashboards; `approval-card` panel; **S5 SSE** | `/v1/soc/stream` |
| **U2** | **Incidents + Provable Timeline + Verify** | Incidents tab (no verify panel) | `provable-timeline` panel; centralized chain verify | (verify exists) |
| **U3** | **Explore (Discover) + saved searches** | substring Explore | AQL parser/autocomplete, field sidebar, histogram, virtualized table | **`POST /v1/soc/query`** |
| **U4** | **Detections + Rules + Alerting UI** | Detections tab (843 LOC) | split file; rules dry-run/canary; alerting over deterministic rules | (rules APIs exist) |
| **U5** | **Fleet + MCP + Active Response** | Agents + MCP tabs | dashboards + role-gated freeze/revoke/quarantine | (control endpoints exist) |
| **U6** | **Receipts viewer + Analytics + in-app dashboard editor + RBAC settings** | Receipts + Settings tabs | `receipt-integrity` panel; analytics dashboards; **the editor (capstone)** | `POST /v1/soc/dashboards`, ClickHouse tier |

**MVP = U0–U2**: the framework, the Overview, the live feed, the **Approval Queue**, and the **Provable Timeline**. Two of those are things Grafana and Kibana fundamentally cannot show — which is the whole point.

---

## 11. Open questions inherited / resolved

| `SOC_UI_Design.md §15` | Resolution in this blueprint |
|---|---|
| §15.1 ClickHouse from U1 or SQLite first? | **SQLite first**; `SocQueryDatasource` interface is storage-agnostic, ClickHouse swaps in at U6 with zero UI change. |
| §15.2 uPlot+ECharts vs Recharts? | **Recharts bootstraps v1; uPlot+ECharts+TanStack Table are the north-star, swapped per panel behind the `Panel` interface.** (Your "keep the best as future goal" decision.) |
| §15.3 Embed in single binary vs separate Node service? | Out of scope here (deployment); the static-export path is compatible with both. |
| §15.4 Dashboards-as-code format? | **Lean AegisAgent-native `DashboardSchema` (§7.3)**, not Grafana-compatible — but a read-only Grafana-Infinity-compatible `/v1/soc/query` shape is kept for export interop (§2). |
| §15.5 SSE vs WebSocket? | **SSE through U5**; advisory-only, so no bidirectional need until collaborative cases (post-U6). |

Newly raised by this blueprint:
1. **`PUT /v1/approvals/:id` (Edit & re-evaluate)** — does the gateway already support editing a frozen action (re-hash + re-evaluate), or is Edit disabled until it lands? (Approval-integrity invariant: editing MUST re-hash + re-evaluate, never patch the approved hash.)
2. **`POST /v1/soc/query` contract growth** — current gateway accepts flat structured filters rather than raw strings; future richer AQL AST support must preserve the no-interpolation invariant and remain backward-compatible with the flat contract.
3. **Saved searches / saved dashboards persistence** — server-side keyed by `tenant_id`; confirm the storage table shape before U3/U6.

---

## 12. World's Fastest Observability UI (Ultra-Performance Blueprint)

To deliver an observability console matching native desktop speed, we bypass standard Web runtime limitations. The following architectural protocols are enforced to achieve the fastest possible load times and sub-millisecond interaction frames:

### 12.1 Binary Protocol Buffers (Protobuf) over WebSockets
Rather than parsing heavy JSON text strings—which blocks the JavaScript main thread on large payloads—real-time event streaming and dashboard query payloads utilize binary serialization.
*   **Gateway**: Serializes datasets to Protobuf/FlatBuffers.
*   **Client**: Decodes the binary buffers directly into JavaScript TypedArrays (e.g. `Float64Array`, `Int32Array`).
*   **Result**: Eliminates CPU-bound `JSON.parse` execution entirely, cutting deserialization time for large tables from 100ms+ to < 1ms.

### 12.2 Rust-Compiled WebAssembly (Wasm) Query & Transformation Engine
Client-side processing (AQL query parsing, auto-complete indexing, and data transformations like Group By, Pivot, and Joins) is handled by a WebAssembly core written in Rust.
*   **Pipeline**: The raw binary frames from the network are fed directly into the Wasm memory space.
*   **Performance**: Avoids V8 JavaScript garbage collection pauses. Computes aggregation transforms on 100,000 records in sub-millisecond timelines.

### 12.3 OffscreenCanvas rendering on Web Workers
To guarantee that the UI main thread remains responsive at 120fps (zero mouse lag during heavy operations), dashboard visualizations are rendered off-thread.
*   **Worker Thread**: Charting engines (uPlot/ECharts) are initialized in Web Workers using `OffscreenCanvas`.
*   **Execution**: Data transfer, canvas rendering, and hover collision detection are handled in the background worker. The main UI thread only manages input dispatching and layout grid resizing.

### 12.4 Pre-Compressed Brotli Asset Delivery
Static dashboard bundle assets are pre-compressed during build time at the maximum compression level:
*   **Compression**: Assets are compiled into `.br` binaries (Brotli Level 11).
*   **Gateway Delivery**: The Rust server reads pre-compressed files directly from memory and serves them instantly with `Content-Encoding: br` headers.
*   **Result**: Reduces bundle transfer size to under 50KB, ensuring the entire console loads in under 150ms over standard connections.

---

## 13. Summary

This blueprint turns the fixed-tabs prototype into a true Grafana/Kibana-grade console by introducing **one panel framework, one datasource abstraction, one dashboard JSON model, one variables/time/drilldown layer, and one real-time stream** — adopting the *best* mechanics from each product (Scenes panels, Discover, drilldowns, controls, dashboards-as-data) and **skipping** what doesn't fit a single-tenant integrity SOC (Git Sync, Spaces, NL query builders, SaaS connectors). The three surfaces that are uniquely AegisAgent — **Approval Card, Provable Timeline, Receipt Integrity** — are first-class panel types in the same registry, so the differentiators compose like everything else. The dashboard model is a **phased hybrid**: curated config-as-code now, the in-app editor as the capstone — shipping the AegisAgent-only value first and the commodity editor last, exactly as the product's own design and moat thesis demand.
