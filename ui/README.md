# AegisAgent SOC Console

Next.js console for operating AegisAgent as an integrity-anchored Agent SOC.

## Local development

```bash
npm ci
npm run dev
```

Open `http://localhost:3000`. Validate changes with:

```bash
npm test
npm run lint
npm run build
```

Set `NEXT_PUBLIC_AEGIS_DEMO_MODE=true` only for a local demo. Demo mode supplies the historical `tenant_123` tenant/token defaults and permits local role overrides. A production build has no default bearer token, removes legacy persisted tokens, keeps newly entered tokens in memory only, and defaults to a read-only viewer until the gateway session supplies a role.

`NEXT_PUBLIC_AEGIS_GATEWAY_URL` may set the initial gateway URL. The active tenant is sent on every request as `X-Aegis-Tenant-ID`; credentials are never serialized into console URLs.

## UI architecture

- `src/chrome`: responsive AppShell, navigation, and global controls.
- `src/state`: shareable, non-sensitive URL state.
- `src/datasources`: entity, structured query, receipt, and SSE transports. Panels never call REST directly.
- `src/dashboards`: typed dashboards-as-code using `DashboardSchema`.
- `src/panels`: `PanelRuntime`, registry, standard panels, and AegisAgent differentiator panels.
- `src/components/primitives`: accessible loading/error/empty states, confirmation, redacted JSON, hashes, evidence links, and layout primitives.

Standard panel types are `stat`, `timeseries`, `table`, `status`, `feed`, and the U6 `heatmap` placeholder. AegisAgent-specific types are `approval-card`, `provable-timeline`, and `receipt-integrity`. Each panel receives only a `DataFrame`; its options live in its `PanelDefinition` and are type-checked by the component.

Receipt verification is fail closed. Only explicit gateway responses (`verified: true`, `ok: true`, or `status: "verified"`) render green. Missing or ambiguous responses render an unknown warning.
