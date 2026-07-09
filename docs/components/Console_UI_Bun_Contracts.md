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

### Phase 2 API map

| UI action | Gateway |
|---|---|
| List pending approvals | `GET /v1/approvals` |
| Approve | `POST /v1/approvals/:id/approve` body `{approver_user_id, reason}` |
| Reject | `POST /v1/approvals/:id/reject` body `{approver_user_id, reason}` |
| List receipts | `GET /v1/receipts?limit=` |
| Verify one | `GET /v1/receipts/:id/verify` (`verified` boolean, fail-closed normalize) |
| Verify range | `POST /v1/receipts/verify-range` |
| Explore | `GET /v1/decisions?limit=&q=&agent_id=&decision=&source_trust=&skill=` |

## 5. Build commands

```bash
cd ui-next
bun install --frozen-lockfile
bun test
bun run build
# serve: gateway reads ui/dist (copy or cutover path)
```

## 6. Dual-tree period

Until cutover, **legacy `ui/` (Next)** remains the production console.  
**`ui-next/`** is the rewrite scaffold. Do not delete Next until P0 Playwright passes.

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
