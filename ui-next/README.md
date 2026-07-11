# AegisAgent Console — `ui-next` (Bun rewrite)

SPA rewrite of the SOC console. **Bun** is the package manager and test runner; **Vite + React 19** produce a static build served by the gateway at `/dashboard/`.

## Theme (product of record)

| Mode | When |
|---|---|
| **Dark SOC** (default) | Operators / 24×7 console — indigo brand, reserved severity & trust ramps |
| Light | Daytime, print, evidence export |
| OLED | True black wall / NOC displays |

Tokens live in `src/design-system/tokens.css` (see `docs/AegisAgent_SOC_Console_Design_System.md`). Do **not** adopt stock shadcn/Material skins — semantic tokens only.

## Commands

```bash
# from ui-next/
bun install
bun test
bun run build     # → dist/ with base /dashboard/
bun run dev       # Vite on :3000, proxies /v1 to gateway
```

Demo local Docker:

```bash
VITE_AEGIS_DEMO_MODE=true VITE_AEGIS_GATEWAY_URL=http://127.0.0.1:8080 bun run dev
```

## Contracts

See [`docs/components/Console_UI_Bun_Contracts.md`](../docs/components/Console_UI_Bun_Contracts.md).

- Fail-closed: no `/v1` call without tenant (`X-Aegis-Tenant-ID`)
- CSRF: `X-CSRF-Token` from gateway-injected meta when present
- Production: bearer not persisted in `localStorage`
- Single tree: this package is the production console (Phase E cutover)

## Phase status

| Phase | Status |
|---|---|
| 0 Contracts freeze | Done |
| 1 Scaffold + Settings + Overview + Dark SOC shell | Done |
| 2 Approvals / Integrity / Explore port | Done |
| 3 Fleet / Incidents / MCP / edit / evidence export | Done |
| 4 Gateway cutover + Docker/CI + Playwright P0 | Done |
| A AQL + DataFrame | Done |
| B PanelRuntime + schema Overview | Done |
| C ControlsBar + live stream + agent detail | Done |
| D Dashboard editor + `/v1/soc/dashboards` | Done |
| E E2E expansion + remove legacy Next `ui/` | Done |
| F Hardening (a11y, redact, mocked #1638) | Done |
| Post catalog — 10 system dashboard templates (#1815–#1820) | Done |
| Charts — `timeseries` + `heatmap` via `soc-query` (#1821–#1822) | Done |
| Differentiators — approval-card, provable-timeline, receipt-integrity (#1824–#1826) | Done |
| Fleet graphs — agent-risk-map, decision-graph (#1827–#1828) | Done |
| 9.2 Runtime pages — Agent Cage Runs + run detail (timeline / events / prompt / model calls) | Done |
| 9.3 Control pages — Ban Center, Quarantine Center, Egress Events, Evidence Graph, Policy Center | Done |
| Pagination — offset-based Previous/Next on Bans / Quarantine / Agent Cage Runs (PR 9.2 acceptance: "handles large lists") | Done |

Panel inventory and system boards: [`docs/components/Console_UI.md`](../docs/components/Console_UI.md).

### Routes

| Path | Notes |
|---|---|
| `/dashboard/` | Schema-driven Overview |
| `/dashboard/approvals` | Queue + approve / reject / **edit** (re-hash) |
| `/dashboard/integrity` | Receipts, verify, range, investigation + compliance packs |
| `/dashboard/explore` | AQL decision search |
| `/dashboard/agents` | Fleet + freeze / unfreeze / restore / revoke |
| `/dashboard/agents/:id` | Agent detail |
| `/dashboard/incidents` | Cases + per-incident evidence-pack ZIP |
| `/dashboard/mcp` | MCP registry, tools, quarantine / restore |
| `/dashboard/detections` | Triggered alerts |
| `/dashboard/rules` | Detection rule catalogue |
| `/dashboard/alerting` | Webhook subscriptions |
| `/dashboard/dashboards` | Tenant dashboard JSON editor + system templates |
| `/dashboard/runs` | Agent Cage Runs — list + pause / resume / kill / quarantine |
| `/dashboard/runs/:id` | Run detail — decision timeline + runtime events |
| `/dashboard/bans` | Ban Center — record / list / revoke |
| `/dashboard/quarantine` | Quarantine Center — record / list / release |
| `/dashboard/egress` | Egress Events — event feed + block / unblock destination |
| `/dashboard/graph` | Evidence Graph — incident / agent / run scoped SVG graph |
| `/dashboard/policies` | Policy Center — Cedar body edit, rollback, delete, audit log |

### System dashboard templates (editor copy-only)

`overview`, `integrity`, `fleet`, `approvals`, `incidents`, `detections`, `mcp`, `rules`, `alerting`, `explore`

### Registered panel types

`stat` · `table` · `timeseries` · `heatmap` · `status` · `feed` · `note` · `approval-card` · `provable-timeline` · `receipt-integrity` · `agent-risk-map` · `decision-graph`
