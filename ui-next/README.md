# AegisAgent Console — `ui-next` (Bun rewrite)

SPA rewrite of the SOC console. **Bun** is the package manager and test runner; **Vite + React 19** produce a static build served by the gateway at `/dashboard/`.

## Theme (product of record)

| Mode | When |
|---|---|
| **Dark SOC** (default) | Operators / 24×7 console — indigo brand, reserved severity & trust ramps |
| Light | Daytime, print, evidence export |
| OLED | True black wall / NOC displays |

Tokens live in `src/design-system/tokens.css` (parity with `ui/src/design-system/tokens.css` and `docs/AegisAgent_SOC_Console_Design_System.md`). Do **not** adopt stock shadcn/Material skins — semantic tokens only.

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
- Dual-tree: legacy Next `ui/` remains production until cutover

## Phase status

| Phase | Status |
|---|---|
| 0 Contracts freeze | Done |
| 1 Scaffold + Settings + Overview + Dark SOC shell | In progress |
| 2 Approvals / Integrity / Explore port | Pending |
| 3 Full surface parity | Pending |
| 4 Gateway cutover `ui-next/dist` → production path | Pending |
