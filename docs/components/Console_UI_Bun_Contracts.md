# Console UI contracts — Bun rewrite (Phase 0 freeze)

**Status:** binding for `ui-next/` → eventual cutover to `ui/`  
**Related plan:** full Bun SPA rewrite (React 19 + Vite + Bun)

## 1. Deploy / serve contract

| Item | Value |
|---|---|
| Artifact directory | `ui-next/dist` (cutover: `ui/dist`) |
| Gateway routes | `GET /dashboard/`, `GET /dashboard/*path` |
| Gateway handler | `src/src/routes/dashboard.rs` |
| Vite `base` | `/dashboard/` |
| CSRF | Gateway injects `<meta name="csrf-token">` + `aegis_csrf` cookie on index |
| Client header | `X-CSRF-Token` on state-changing requests when meta present |
| Tenant header | `X-Aegis-Tenant-ID` required on all `/v1` calls from console |
| Auth | `Authorization: Bearer <token>` |
| Demo env | `VITE_AEGIS_DEMO_MODE=true`, `VITE_AEGIS_GATEWAY_URL=http://127.0.0.1:8080` |

## 2. Fail-closed tenant gate

No SOC fetch may run with empty `tenantId`. Client throws:

`A tenant must be selected before calling the AegisAgent gateway.`

## 3. Production token policy

- Demo mode may persist bearer in `localStorage`.  
- Production must **not** persist bearer; strip on load.

## 4. P0 surfaces (scaffold → full port)

| # | Surface | Status |
|---|---|---|
| 1 | Settings / connection (+ operator id) | Phase 1–2 |
| 2 | Overview (`/v1/stats`) | Phase 1 |
| 3 | Approvals (`GET/POST /v1/approvals…`) | Phase 2 |
| 4 | Integrity / receipts (list + verify + verify-range) | Phase 2 |
| 5 | Explore (chip query → `/v1/decisions`) | Phase 2 (simple AQL chips; full compiler later) |
| 6 | Agents fleet + controls | Phase 3 |
| 7 | Incidents + evidence pack | Phase 3 |
| 8 | MCP registry + quarantine | Phase 3 |
| 9 | Approval edit + evidence export | Phase 3 |
| 10 | Detections / Rules / Alerting | Phase 5 |
| 11 | Full AQL + frame/types field catalog | Phase A (datasource spine) |
| 12 | PanelRuntime + gateway-entity + schema Overview | Phase B |

### Phase 2–3 API map

| UI action | Gateway |
|---|---|
| List pending approvals | `GET /v1/approvals` |
| Approve | `POST /v1/approvals/:id/approve` body `{approver_user_id, reason}` |
| Reject | `POST /v1/approvals/:id/reject` body `{approver_user_id, reason}` |
| Edit (re-hash) | `POST /v1/approvals/:id/edit` body `{approver_user_id, edited_tool_call, reason}` |
| List receipts | `GET /v1/receipts?limit=` |
| Verify one | `GET /v1/receipts/:id/verify` (`verified` boolean, fail-closed normalize) |
| Verify range | `POST /v1/receipts/verify-range` |
| Investigation export | `POST /v1/evidence/export` → ZIP |
| Compliance export | `GET /v1/compliance/evidence-pack` → ZIP |
| Explore | `GET /v1/decisions?limit=&q=&agent_id=&decision=&source_trust=&skill=` |
| Agents | `GET /v1/agents`; `POST …/freeze|unfreeze|restore|revoke` |
| Incidents | `GET /v1/incidents`; `GET /v1/incidents/:id`; `GET …/evidence-pack` |
| MCP | `GET /v1/mcp/servers`; tools; quarantine/restore |

## 5. Build commands

```bash
cd ui-next
bun install --frozen-lockfile
bun test
bun run build
# serve: gateway reads ui/dist (copy or cutover path)
```

## 6. Dual-tree period & cutover plan (Phase 4)

Until cutover, **legacy `ui/` (Next)** remains the production console.  
**`ui-next/`** is the rewrite SPA. Do not delete Next until P0 Playwright passes.

### Cutover checklist (Phase 4 — implemented)

| Step | Status |
|---|---|
| CI `ui-next` job: `bun test` + `bun run build` | Done (`.github/workflows/ci.yml`) |
| Docker builds Bun SPA into image | Done (`src/Dockerfile` → `/app/ui/dist` + `/app/ui-next/dist`) |
| Gateway dist resolution | Done (`AEGIS_UI_DIST`, `AEGIS_UI_BUNDLE=next\|legacy`, prefer `ui-next/dist` when present) |
| CSRF meta + cookie on index | Unchanged (`dashboard.rs`) |
| Playwright P0 for ui-next routes | Done (`e2e/tests/dashboard-*.spec.ts`, shell + data) |
| Default image env `AEGIS_UI_BUNDLE=next` | Done |
| Remove Next `ui/` tree | **Deferred** — dual-tree remains for rollback one release |
| Re-port mocked panel harness (#1638) | Deferred (tests skipped) |

**Runtime env:**

| Variable | Effect |
|---|---|
| `AEGIS_UI_DIST` | Absolute/relative path override to SPA root containing `index.html` |
| `AEGIS_UI_BUNDLE=next` | Force `ui-next/dist` |
| `AEGIS_UI_BUNDLE=legacy` | Force `ui/dist` (Next export) |
| *(unset)* | Prefer `ui-next/dist` if `index.html` exists, else `ui/dist` |

## 7. Theme contract (product of record)

| Mode | `data-theme` | Role |
|---|---|---|
| **Dark SOC (default)** | `dark-soc` | Primary operator experience |
| Light | `light` | Daytime / print / evidence export |
| OLED | `oled` | True-black wall / NOC displays |

- Token source: `ui-next/src/design-system/tokens.css` (must stay aligned with `ui/src/design-system/tokens.css`).
- Design system: `docs/AegisAgent_SOC_Console_Design_System.md` §3.
- Density: `data-density` = `compact` (default) | `cozy`.
- **Anti-template:** no stock Material / Ant / full shadcn skin. One brand accent (indigo); severity, decision, and trust ramps are reserved (never used for chrome decoration).
- Persistence keys: `aegis_theme`, `aegis_density` in `localStorage`.
