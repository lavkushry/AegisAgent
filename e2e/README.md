# AegisAgent Dashboard E2E (`#1326`, `#1638`)

Playwright browser tests for the production SOC console served at `/dashboard/`.

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

From the UI package:

```bash
cd ui
npm run test:e2e
```

Run a single spec:

```bash
cd e2e
AEGIS_DASHBOARD_URL=http://127.0.0.1:8080 npx playwright test tests/mocked-soc-workflows.spec.ts
```

## Suite layout

| Spec | Mode | Coverage |
|------|------|----------|
| `dashboard-shell.spec.ts` | Live gateway | CSP/CSRF, nav URL sync (incl. split Detections + Rules) |
| `dashboard-data.spec.ts` | Live gateway | Fleet detail, rules, MCP, explore, receipts, approvals, overview |
| `dashboard-evidence-graph.spec.ts` | Live gateway | Fleet inventory navigation |
| `mocked-soc-workflows.spec.ts` | Mocked `/v1/*` | Overview, tenant switch, approve/reject, receipt verify states, explore expand, incident timeline, freeze/unfreeze, MCP quarantine/restore, rule backtest, alert redaction |
| `soc-security.spec.ts` | Mocked `/v1/*` | RBAC-disabled controls, confirm-without-reason, API failures, secret redaction |

Mock fixtures live in `e2e/fixtures/`. They use fake credentials only (`fake-bearer-e2e-only`).

## CI

The `Dashboard E2E (Playwright)` job in `.github/workflows/ci.yml` builds Docker Compose, seeds demo data, runs `npx playwright test`, and uploads `e2e/playwright-report/` on failure.

## Guardrails

- `e2e/fixtures/guardedTest.ts` fails tests on browser `console.error` and uncaught page exceptions.
- Mocked suites assert `unhandled` gateway routes stay empty (no silent 501s).
- `assertNoSecrets()` scans the DOM for fixture secrets and `[REDACTED]` expectations.