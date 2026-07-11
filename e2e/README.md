# AegisAgent Dashboard E2E (`#1326`, `#1638`)

Playwright browser tests for the production SOC console served at `/dashboard/`.

**Production console:** Bun SPA (`ui-next/`). The gateway Docker image builds `ui-next` and serves it at `/dashboard/`. Specs target React Router routes, Settings form, Dark SOC shell, ControlsBar, dashboard editor, and re-ported mocked workflows (#1638).

## Prerequisites

- Node.js 20+
- A running gateway with the embedded dashboard build (Docker Compose is the CI default)

## Local commands

From the repository root:

```bash
# Start gateway + seed demo tenant data
docker compose up --build -d
bash scripts/seed-demo.sh

# Install Playwright and run the full suite
cd e2e
npm ci
npx playwright install --with-deps chromium
AEGIS_DASHBOARD_URL=http://127.0.0.1:8080 npx playwright test
```

Run a single spec:

```bash
cd e2e
AEGIS_DASHBOARD_URL=http://127.0.0.1:8080 npx playwright test tests/dashboard-shell.spec.ts
```

## Suite layout

| Spec | Mode | Coverage |
|------|------|----------|
| `dashboard-shell.spec.ts` | Live gateway | CSP/CSRF, full nav (incl. Dashboards), ControlsBar, skip-to-main |
| `dashboard-data.spec.ts` | Live gateway | Agents, MCP, Explore, Integrity, Approvals, Overview panels, agent detail, Detections/Rules/Alerting, dashboard editor validate |
| `dashboard-evidence-graph.spec.ts` | Live gateway | Fleet inventory + bookmarkable agent detail |
| `mocked-soc-workflows.spec.ts` | Mocked `/v1/*` | Overview stats, tenant isolation, approve + secret redaction, integrity verify, explore, freeze, MCP quarantine, detections, dashboard validate |
| `mocked-panel-suite.spec.ts` | Mocked `/v1/*` | Overview timeseries/heatmap/risk-map panels, dashboard template previews (decision-graph, chain controls, risk scoreboard) |
| `mocked-phase9-control-pages.spec.ts` | Mocked `/v1/*` | Agent Cage Runs list + pause, run detail (timeline/events/prompt/model calls), Ban Center, Quarantine Center, Egress Events, Evidence Graph, Policy Center edit + rollback |
| `soc-security.spec.ts` | Live gateway | Freeze confirm dialog, operator id field |

Mock fixtures live in `e2e/fixtures/`. They use fake credentials only (`fake-bearer-e2e-only`).

## CI

The `Dashboard E2E (Playwright)` job in `.github/workflows/ci.yml` builds Docker Compose, seeds demo data, runs `npx playwright test`, and uploads `e2e/playwright-report/` on failure.

## Guardrails

- `e2e/fixtures/guardedTest.ts` fails tests on browser `console.error` and uncaught page exceptions.
- Mocked suites assert `unhandled` gateway routes stay empty (no silent 501s).
- `assertNoSecrets()` scans the DOM for fixture secrets and `[REDACTED]` expectations.
