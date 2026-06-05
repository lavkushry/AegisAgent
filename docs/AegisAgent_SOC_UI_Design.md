# AegisAgent — SOC Console UI Design (Kibana + Grafana model)

> **Status:** Design (2026-06-05). The L5 Presentation layer of [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md) §26, planned in depth.
> **Read first:** the SOC design doc (the data model + APIs this UI consumes). **Visual seed:** [`dashboard-mock.html`](dashboard-mock.html).
>
> Goal: build the **SOC Console** — the Grafana-for-dashboards + Kibana-for-investigation experience, **plus the three surfaces neither has**: the human **approval queue**, the **provable (hash-chained) incident timeline**, and the **receipt-integrity viewer**. It is a console over *verifiable agent-action evidence*, not a generic log explorer.

---

## 1. How Grafana and Kibana actually work (and the split we adopt)

The two tools solve two halves of a SOC. We take the best of each.

**Grafana = dashboards + metrics + alerting, as code.**
- **Panels on a grid** (time series, stat, gauge, table, heatmap, logs) composed into **dashboards**.
- **Data sources** are pluggable; panels issue queries to them.
- **Variables / templating** (`$tenant`, `$agent`, `$env`) + a global **time-range picker** + auto-refresh.
- **Explore** mode for ad-hoc querying.
- **Unified Alerting**: rules → notification policies → contact points (Slack/PagerDuty/webhook) + **silences**.
- **Provisioning as code**: dashboards/datasources are JSON/YAML, version-controlled.
- **Orgs/teams/RBAC** for multi-tenancy.

**Kibana = explore + SIEM investigation.**
- **Discover**: a query bar (KQL), a **field sidebar**, a **document table**, expandable raw documents, time picker, **saved searches**.
- **Lens/TSVB/Vega** visualizations → **Dashboards**.
- **Security app**: **Detections** (alert list), **Cases** (incident management), **Timelines** (drag events into an investigation), entities (hosts/users).
- **Spaces** for tenant separation; **saved objects** for portability.

**Our split:**
```
Grafana model  →  Dashboards (Overview, Fleet, Detection metrics) + Alerting UI + dashboards-as-code + variables
Kibana model   →  Explore (ASE search) + Detections + Cases(Incidents) + Timeline(investigation)
AegisAgent-only →  Approval Queue · Provable Timeline (receipt verify) · Receipt Integrity Viewer
```

---

## 2. What we borrow vs. what is uniquely ours

| Capability | Grafana | Kibana | AegisAgent SOC Console |
|---|---|---|---|
| Dashboards (panels on grid) | ✓ core | ✓ | ✓ Grafana-style, **dashboards-as-code** |
| Ad-hoc explore | Explore | Discover | **Explore** — ASE event search (query bar + field sidebar + doc table) |
| Time-series viz | ✓ core | Lens/TSVB | ✓ (uPlot/ECharts panels) |
| Variables / templating | ✓ | controls | `$tenant $agent $env $timeRange` |
| Alerting (rules→routing→silence) | Unified Alerting | Alerting/Watcher | ✓ but rules are **deterministic** (never text-score gated) |
| Detections / Cases / Timeline | — | Security app | ✓ Incident = Case; **Timeline is PROVABLE** |
| Pluggable data | data sources | data views | ASE store (ClickHouse/SQLite) + gateway SOC API |
| Provisioning as code | ✓ | saved objects | dashboards + detection rules as JSON/YAML |
| RBAC / multi-tenant | orgs/teams | spaces | **tenant-scoped (hard invariant), roles: admin/analyst/approver/viewer** |
| **Human approval queue** | ✗ | ✗ | **✓ unique — the human-in-the-loop** |
| **Provable hash-chained timeline** | ✗ | ✗ | **✓ unique — one-click receipt-chain verify** |
| **Receipt integrity viewer** | ✗ | ✗ | **✓ unique — tamper detection as a view** |

The bottom three rows are why this is not "Grafana with an agents data source" — they ride the receipt + provenance spine (Design Law 4) and are the product.

---

## 3. The three surfaces neither Kibana nor Grafana has

1. **Approval Queue + Approval Card.** Pending `require_approval` decisions. The card renders the **canonical action** (the exact bytes that will run), its `action_hash`, `source_trust` label, requesting agent, and the diff if edited. Actions: Approve / Reject / **Edit** (re-hashes + re-evaluates) / Escalate. Signature-verified; approver role enforced. *This is the human-in-the-loop control — the reason an approval is trustworthy.*
2. **Provable Incident Timeline.** A Kibana-style timeline where **every row carries its `receipt_hash`**, and a **Verify** button walks the chain (`GET /v1/receipts/:id/verify` / chain verify) → green "tamper-free" or red "broken at row N." Turns an investigation from "here are some logs" into "here is cryptographic proof."
3. **Receipt Integrity Viewer.** Browse the per-tenant hash chain; verify a range; visualize a break. A chain break is also surfaced as a P1 detection (`receipt-chain-broken`).

---

## 4. Technology stack (actionable)

| Concern | Choice | Why |
|---|---|---|
| Framework | **Next.js (App Router) + React + TypeScript** | Already the chosen dashboard stack; server components for data, client for interactivity; matches the TS SDK direction |
| Styling | **Tailwind CSS + shadcn/ui (Radix)** | Fast, accessible primitives; dark-first theme (matches the mock) |
| Data fetching | **TanStack Query** | Caching, polling, background refetch, request dedup |
| Big tables | **TanStack Table + virtualization** (`@tanstack/react-virtual`) | Event/Discover tables are high-row-count |
| Time-series charts | **uPlot** (dense series) + **ECharts** (rich panels) | uPlot is Grafana-class fast; ECharts for heatmaps/sankey/treemap |
| Live feed | **SSE (EventSource)** → WebSocket later | One-way decision/approval stream; simplest reliable real-time |
| UI state | **Zustand** (filters, time range, selected tenant) | Lightweight, no boilerplate |
| Auth | **OIDC/SAML** via the gateway session | Matches enterprise deployment doc |
| Packaging | Static export or Node server behind the gateway | Self-hostable single binary can embed it |

**Data path:** the UI never queries tools directly. It calls the **gateway SOC API** (REST) for incidents/alerts/approvals/receipts, and a **query endpoint** over the **ASE event store** (ClickHouse at scale, SQLite for single-binary) for Explore/dashboards. All requests carry the tenant context; the gateway enforces tenant scoping server-side (the UI never sees another tenant's data).

---

## 5. Information architecture (navigation)

```
AegisAgent SOC Console
├── Overview            (Grafana-style home dashboard — fleet health at a glance)
├── Explore             (Kibana Discover — search the ASE event stream)
├── Detections          (firing alerts list + rule health)
│   └── Rules           (deterministic rule catalog: view/dry-run/canary/version)
├── Incidents           (Kibana Cases — correlated, with PROVABLE timelines)
│   └── Incident detail (timeline + evidence receipts + RCA + response actions)
├── Approvals           (★ the queue — pending human-in-the-loop decisions)
├── Agents (Fleet)      (inventory + per-agent risk, runs, tools, MCP, status)
├── MCP Servers         (registry, manifest pins, drift status)
├── Receipts            (★ integrity viewer — chain browse + verify)
├── Dashboards          (custom Grafana-style boards, dashboards-as-code)
├── Analytics           (trends: decisions, provenance mix, MTTD/MTTC, top risk)
├── Policies            (Cedar bundles: view/dry-run/version)
└── Settings            (tenants, RBAC, contact points, notification policies, retention)
```

Global chrome (every page): **tenant selector** · **time-range picker** · **template variables** (`$agent`, `$env`) · **live/refresh toggle** · global search · user/role menu.

---

## 6. Data & query layer

### 6.1 Two read surfaces
- **Entity API (REST, gateway):** `GET /v1/incidents`, `/v1/incidents/:id`, `/v1/alerts`, `/v1/approvals`, `/v1/agents`, `/v1/receipts/:id/verify`, `/v1/runs/:id/timeline`. Typed client generated from an OpenAPI spec.
- **Event query API (Explore/dashboards):** a `POST /v1/soc/query` over the ASE store — filter (`agent_id`, `tool`, `decision`, `source_trust`, `event_type`, time range), aggregate (count over time, group-by), paginate. Backed by ClickHouse (fast `denies per agent per minute`) or SQLite for single-binary.

### 6.2 Real-time
`GET /v1/soc/stream` (SSE): pushes new ASEs, new alerts, and approval-queue changes. The Overview live feed, the Approvals badge, and incident updates subscribe. Backpressure: the stream is advisory UI sugar; the source of truth is always the query API.

### 6.3 Query model (Kibana-flavored, but typed)
A simple filter DSL in the URL (shareable/saved-searchable):
```
agent_id:coding-agent-prod AND decision:deny AND source_trust:untrusted_external AND @time:[now-24h TO now]
```
Compiled to a parameterized ClickHouse/SQLite query server-side (never string-interpolated — same SQL-injection invariant as the gateway).

---

## 7. The panel system (Grafana-style, reusable)

Every dashboard is composed of typed **panels** bound to a query + a time range + variables:

| Panel | Use |
|---|---|
| **Stat** | single number + spark + threshold color (protected actions, denies, open incidents, MTTC) |
| **Time series** | decisions/min by type, denies by agent, detections by rule (uPlot) |
| **Table** | top risky agents, recent denies, pending approvals (virtualized) |
| **Heatmap** | provenance × hour, detection density |
| **Status** | receipt-chain status (verified/broken), agent statuses |
| **Logs/Feed** | live ASE stream (Kibana-Discover-lite) |
| **Provable timeline** | the unique panel — rows + receipt_hash + verify |
| **Approval card** | the unique panel — canonical action + approve/reject/edit |

Panels are configured by JSON → **dashboards-as-code** (§9). The same panel components render both the fixed system dashboards and user-built ones.

---

## 8. Page-by-page

### 8.1 Overview (Grafana home)
Stat row: protected actions · blocked · pending approvals · open incidents · detections (24h) · **receipt chain: ✓ verified** · MTTC. Time-series: decisions/min by type; denies by agent. Live feed (right rail). One open-incident callout if any. (The current [`dashboard-mock.html`](dashboard-mock.html) is the seed for this page.)

### 8.2 Explore (Kibana Discover for agent actions)
Query bar + **field sidebar** (clickable facets: `decision`, `source_trust`, `tool`, `agent_id`, `event_type`) + histogram over time + **document table**. Expand a row → full ASE JSON + linked `action_hash`/`receipt_hash` (one click to verify) + "open in timeline." Save as a named search; pin to a dashboard.

### 8.3 Detections & Rules
- **Detections:** firing alerts (rule_id, level 0–15, ATLAS/OWASP tag, agent, time), filter/group, drill to the triggering events.
- **Rules:** the **deterministic** catalog (atomic + correlation). View YAML, **dry-run** against recent events, **canary** in `log_only`, version history. *No "AI rule builder"* — rules are code (Design Laws 1–2; Operational Design §4.5). A rule that would gate on a score is rejected in review.

### 8.4 Incidents (Kibana Cases) + Incident detail
List: severity, status, agent, detections, first/last seen. Detail = the **provable timeline** (§3.2): ordered events each with `receipt_hash`, a **Verify chain** button, `evidence_receipts[]`, the RCA narrative (clearly labeled LLM-drafted, analyst-reviewed), and **Response actions** (freeze/revoke/quarantine — deterministic, confirm dialog, audited).

### 8.5 Approvals (★ the queue)
The human-in-the-loop. Cards for pending `require_approval`: canonical action (rendered exactly as hashed), `action_hash`, `source_trust`, requesting agent/run, expiry countdown, approver group. Approve / Reject / **Edit** (re-hash + re-evaluate) / Escalate. Signature-verified; SLA timers; bulk view for leads. *This screen is the product's trust story made visible.*

### 8.6 Agents (Fleet)
Inventory (like Kibana SIEM "hosts," for agents): owner, env, framework, model, risk tier, **status (active/frozen/revoked/quarantined)**, connected tools/MCP, recent runs, risk trend, open alerts, approval history. Per-agent **freeze/revoke** with confirm.

### 8.7 MCP Servers
Registry, transport, trust level, **manifest pin + drift status**; quarantine action; per-tool approval state.

### 8.8 Receipts (★ integrity viewer)
Browse the per-tenant chain (paginated), verify a selected range, visualize a break (red link), export an evidence pack (SOC 2 / Article 14). A break → links to the `receipt-chain-broken` detection.

### 8.9 Analytics · Policies · Settings
Analytics: provenance mix over time, decision rates, MTTD/MTTC, top-risk agents, detection coverage vs ATLAS/OWASP. Policies: Cedar bundles (view/dry-run/version). Settings: tenants, **RBAC**, contact points (Slack/PagerDuty/webhook), notification policies, silences, retention.

---

## 9. Dashboards-as-code & provisioning (Grafana's best idea)

Dashboards and detection rules are **JSON/YAML artifacts** in the repo, not just DB rows:
```json
{ "uid": "overview", "title": "SOC Overview", "variables": ["tenant","env","timeRange"],
  "panels": [
    { "type": "stat", "title": "Blocked (24h)", "query": "decision:deny", "thresholds": [10,25] },
    { "type": "timeseries", "title": "Decisions/min", "query": "group:decision over @time" }
  ] }
```
Benefits: version control, review, reproducible installs, ship curated boards in OSS. Users can still build dashboards in-app (saved as the same JSON).

---

## 10. Alerting UI (Grafana Unified Alerting, deterministic core)

- **Rules** (deterministic, §8.3) → **Notification policies** (route by tenant/severity/agent) → **Contact points** (Slack, PagerDuty, webhook, email).
- **Silences** (mute a noisy rule/agent for a window) + **alert grouping/dedup** (deny-storms collapse to one).
- Rule health view (firing/normal/error), last-evaluated, throughput. **Active Response** mapping is shown read-only per rule (what containment fires) and is reversible/audited.

---

## 11. RBAC & multi-tenancy (hard invariant)

- **Every view, query, and SSE stream is tenant-scoped server-side.** The UI cannot request cross-tenant data; the gateway enforces `tenant_id` (same invariant as the data layer). Tenant selector only lists tenants the user is entitled to.
- **Roles:** `viewer` (read), `analyst` (investigate, silence, ack), `approver` (act on the approval queue — separation of duties from the agent owner), `admin` (rules, RBAC, settings). Critical Active-Response (revoke) can require two-person confirm.
- **Audit:** every console action (approve, freeze, silence, rule edit) emits its own receipt — the console is itself inside the evidence boundary.

---

## 12. Design system, theming, performance, a11y

- **Dark-first** (the mock palette: slate/`#0f172a`), light theme optional; severity colors consistent (allow=green, deny=red, approval=amber, critical=rose).
- **Performance:** virtualized tables; time-series downsampled server-side (ClickHouse `toStartOfMinute` rollups); SSE for deltas not full reloads; route-level code splitting; ClickHouse for all aggregations.
- **A11y:** Radix primitives (keyboard, focus, ARIA); never color-only status (icon + label); honor reduced-motion.
- **Redaction in the UI:** the console shows hashes, never raw secret payloads (the store holds hashes — Design Law 4 / redaction invariant), so screenshots/exports are safe.

---

## 13. Wireframes (key screens)

**Overview**
```
┌ SOC Console  [tenant ▾] [env ▾] [last 24h ▾] [● live] [search] [user ▾] ┐
│ [Protected 128] [Blocked 7] [Pending 3] [Incidents 1] [Detections 12] [Chain ✓] [MTTC 8s] │
│ ┌ Decisions / min ───────────────┐  ┌ Live feed ───────────────┐ │
│ │  ▁▂▅▇▅▃▂  allow/deny/approval   │  │ 12:04 ⛔ merge blocked    │ │
│ └────────────────────────────────┘  │ 12:03 ⏸ approval created  │ │
│ ┌ Denies by agent (table) ───────┐  │ 12:03 ✓ read_issue       │ │
│ │ coding-agent-prod   5  ▇▇▇▇▇    │  │ 12:03 ⚠ MCP drift        │ │
└──┴────────────────────────────────┴──┴──────────────────────────┴─┘
```

**Incident detail — provable timeline**
```
┌ inc_01J  Prompt injection → high-risk action   [critical] [contained] [Verify chain ✓] ┐
│ 10:02 ✓ read_issue #391 (public)                    trust=untrusted_external  rcpt …a1b2 │
│ 10:03 ⛨ AEG-1002 confused-deputy-mutation (L12)     ATLAS AML.T0051                       │
│ 10:05 ⛔ merge → main  forbid-untrusted-mutation                              rcpt …c3d4 │
│ 10:05 ⛔ approve-then-swap → SDK fail-closed (T-A1)                           rcpt …c3d4 │
│ 10:05 🛡 Active Response: agent FROZEN · Slack #agent-security                 contained │
│ 10:06 📝 RCA (LLM-drafted, reviewed): untrusted issue carried hijack instr.             │
│ [Evidence: …a1b2 → …c3d4  ✓ tamper-free]   [Freeze ▾] [Revoke] [Reopen] [Export pack]   │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

**Approval card**
```
┌ Approval required · expires 04:52 ────────────────────────────────┐
│ agent coding-agent-prod   group platform-leads   trust untrusted  │
│ action: github.merge_pull_request → payments-service/main         │
│ action_hash: sha256:9af1…   (you approve EXACTLY these bytes)      │
│ params: { base_branch: "main", pr_number: 482 }                   │
│ [ Approve ]  [ Reject ]  [ Edit & re-evaluate ]  [ Escalate ]     │
└───────────────────────────────────────────────────────────────────┘
```

---

## 14. Build phases (the UI is SOC Phase 5; ship vertically)

| Step | Screens | Depends on |
|---|---|---|
| **U0** | App shell: nav, tenant/time/var chrome, auth, design system, dark theme | gateway session + 1 read API |
| **U1 (MVP)** | **Overview** + **Live feed** + **Approvals queue** | event stream + approvals API (highest value; 1 unique surface) |
| **U2** | **Incidents** + **provable timeline** + Verify | correlation engine + receipts verify (the killer demo) |
| **U3** | **Explore** (Discover) + saved searches | `POST /v1/soc/query` over ASE store |
| **U4** | **Detections + Rules** (dry-run/canary) + **Alerting UI** | rule engine + contact points |
| **U5** | **Fleet/Agents** + **MCP** + Active-Response buttons | control endpoints (freeze/revoke/quarantine) |
| **U6** | **Receipts viewer** + **Analytics** + dashboards-as-code + RBAC settings | ClickHouse tier |

MVP = U0–U2: an Overview, a live feed, the **approval queue**, and a **provable incident timeline**. Two of those four are things Grafana and Kibana fundamentally cannot show — which is the whole point.

---

## 15. Open questions

1. ClickHouse from U1, or start on SQLite and add it at U3/U6 when aggregation pain is real?
2. Charting: commit to uPlot+ECharts, or start with Recharts for speed and swap hot panels later?
3. Embed the console in the single binary (static export served by the Rust gateway) for the self-hosted wedge, vs. a separate Node service for SaaS — or both?
4. Dashboards-as-code format: invent a lean JSON, or adopt a Grafana-compatible subset so users can import existing boards?
5. Real-time: SSE sufficient through U5, or do we need bidirectional WebSocket earlier (e.g., collaborative incident cases)?
