# Onboarding: Frontend Engineer

**Goal:** understand the SOC console architecture and ship a panel or dashboard change safely.

> **Status:** The active console is the Bun + Vite + React SPA in `ui-next/`, served by the gateway. The legacy `ui/` tree is not the source for new console work.

## Overview

You are building a security investigation interface, not a generic admin dashboard. The UI must preserve tenant scope, evidence identity, status honesty, loading/error states, and the distinction between advisory scores and deterministic decisions.

## 1. What the UI is

A Bun + Vite + React + TypeScript single-tenant-scoped SOC console in `ui-next/`, built to `ui-next/dist` and **served by the gateway** at `/dashboard` (`src/src/routes/dashboard.rs`) — no separate frontend deployment in the default stack. Design language: [../AegisAgent_SOC_Console_Design_System.md](../AegisAgent_SOC_Console_Design_System.md); UX model: [../AegisAgent_SOC_UI_Design.md](../AegisAgent_SOC_UI_Design.md).

## 2. Architecture (the three ideas)

1. **Schema-driven dashboards** — dashboards are data in `ui-next/src/dashboards/`; system definitions and the editor share typed contracts.
2. **Datasource registry** — implementations in `ui-next/src/datasources/` normalize gateway entities, SOC queries, receipts, streams, and AQL results into frames.
3. **Panel runtime** — `ui-next/src/panels/` renders standard and differentiator panels; feature routes in `ui-next/src/features/` compose product workflows.

Supporting layers: `ui-next/src/app/`, `chrome/`, `design-system/`, `domains/`, `hooks/`, `lib/http/`, and `components/`.

## 3. Auth & tenancy

The console talks to the same `/v1` API with a bearer token (tenant token or JWT) — there is no separate UI backend. Never bake tokens into the bundle; runtime config comes from `runtimeConfig.ts`. Every response is already tenant-scoped by the gateway.

## 4. Common tasks

| Task | Where |
|---|---|
| New panel type | `ui-next/src/panels/` + panel registry/contracts |
| New datasource | `ui-next/src/datasources/` + colocated Bun test |
| New product workflow | `ui-next/src/features/<domain>/` + router/navigation entry |
| New system dashboard | `ui-next/src/dashboards/system/` conforming to dashboard contracts |
| API shape change | update domain/datasource client types; verify `/openapi.json` and backend status |

## 5. Dev loop & testing

```bash
cd ui-next
bun install --frozen-lockfile
bun run dev        # Vite dev server against a locally running gateway
bun test           # colocated Bun tests
bun run typecheck
bun run build      # production build → ui-next/dist
cd ../e2e && npx playwright test   # full-stack E2E (AEGIS_DASHBOARD_URL=http://127.0.0.1:8080)
```

## 6. Things that bite

- The gateway serves the selected UI bundle — a stale `ui-next/dist` means your change may not appear; rebuild and check `AEGIS_UI_BUNDLE`/`AEGIS_UI_DIST`.
- `stream.ts` (WS) reconnect behavior matters for the live event feed — test with the gateway restarting.
- Panels must render from **frames**, not raw API JSON — keep transforms in datasources.
- Respect the design system; the SOC console is a product surface, not an admin scaffold.

## 7. Read next

[../components/Console_UI.md](../components/Console_UI.md) · [../AegisAgent_SOC_UI_Design.md](../AegisAgent_SOC_UI_Design.md) · `ui-next/README.md` · [../api-reference.md](../api-reference.md)

## 8. Security and Failure Handling

- Never persist bearer/JWT credentials in source, local storage, screenshots, fixtures, or error telemetry.
- Render server decisions exactly; color, score, or narration must not turn deny/unknown into visual permission.
- Escape attacker-controlled content and avoid dangerous raw HTML rendering.
- Show stale, partial, and unavailable data explicitly; never replace missing evidence with invented values.
- Require confirmation and display target identity for containment/destructive actions.

## 9. Operations and Troubleshooting

Test empty, loading, partial, denied, unauthorized, rate-limited, unavailable, and malformed-response states. Verify keyboard navigation, reduced motion, responsive tables, and evidence links. When data appears wrong, inspect the network response and implementation ledger before changing UI types to match a stale mock.

## 10. References

[Console UI](../components/Console_UI.md) · [Console Contracts](../components/Console_UI_Bun_Contracts.md) · [Implementation Status](../Implementation_Status.md) · [API Reference](../api-reference.md)
