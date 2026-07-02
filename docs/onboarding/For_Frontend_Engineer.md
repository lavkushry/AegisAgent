# Onboarding: Frontend Engineer

**Goal:** understand the SOC console architecture and ship a panel or dashboard change safely.

## 1. What the UI is

A Next.js (App Router, TypeScript) single-tenant-scoped SOC console in `ui/`, built to `ui/dist` and **served by the gateway** at `/dashboard` (`src/src/routes/dashboard.rs`) — no separate frontend deployment in the default stack. Design language: [../AegisAgent_SOC_Console_Design_System.md](../AegisAgent_SOC_Console_Design_System.md); UX model (Kibana/Grafana hybrid): [../AegisAgent_SOC_UI_Design.md](../AegisAgent_SOC_UI_Design.md).

## 2. Architecture (the three ideas)

1. **Schema-driven dashboards** — dashboards are *data*, not pages: `ui/src/dashboards/schema.ts` defines the shape; `ui/src/dashboards/system/{overview,fleet,integrity,approvals}.ts` are the built-ins; `DashboardLoader.tsx` renders them.
2. **Datasource registry** — panels declare a datasource; implementations in `ui/src/datasources/`: `gatewayEntity.ts` (REST entities), `socQuery.ts` (`POST /v1/soc/query`), `receipt.ts` + `receiptVerification.ts`, `stream.ts` (WebSocket `/v1/ws/events`), `aql/` (query language helpers), all normalized through `frame.ts` → registered in `registry.ts`.
3. **Panel runtime** — `ui/src/panels/` (`PanelRuntime.tsx`, `standard/`, `differentiators/`) renders frames; `registry.ts` maps panel types.

Supporting layers: `ui/src/app/` (`api.ts` client, `store.ts` state, `runtimeConfig.ts`, `providers.tsx`), `ui/src/chrome/` (shell/nav), `ui/src/design-system/`, `ui/src/hooks/`, `ui/src/state/`.

## 3. Auth & tenancy

The console talks to the same `/v1` API with a bearer token (tenant token or JWT) — there is no separate UI backend. Never bake tokens into the bundle; runtime config comes from `runtimeConfig.ts`. Every response is already tenant-scoped by the gateway.

## 4. Common tasks

| Task | Where |
|---|---|
| New panel type | `ui/src/panels/` + register in `panels/registry.ts` |
| New datasource | `ui/src/datasources/` + `datasources/registry.ts` + a `.test.ts` beside it |
| New system dashboard | `ui/src/dashboards/system/*.ts` conforming to `schema.ts` |
| API shape change | update `ui/src/datasources/types.ts` + `app/api.ts`; check the OpenAPI at `/openapi.json` |

## 5. Dev loop & testing

```bash
cd ui && npm ci
npm run dev        # against a locally running gateway (docker compose up)
npm test           # vitest unit tests (datasources/store have colocated *.test.ts)
npm run build      # production build → dist (embedded/served by gateway)
cd ../e2e && npx playwright test   # full-stack E2E (AEGIS_DASHBOARD_URL=http://127.0.0.1:8080)
```

## 6. Things that bite

- The gateway serves the UI — a stale `ui/dist` means your change "doesn't show up"; rebuild.
- `stream.ts` (WS) reconnect behavior matters for the live event feed — test with the gateway restarting.
- Panels must render from **frames**, not raw API JSON — keep transforms in datasources.
- Respect the design system; the SOC console is a product surface, not an admin scaffold.

## 7. Read next

[../components/Console_UI.md](../components/Console_UI.md) · [../AegisAgent_SOC_UI_Design.md](../AegisAgent_SOC_UI_Design.md) · `ui/README.md` · [../api-reference.md](../api-reference.md)
