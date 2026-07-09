# Active tasks — pre-production

## In flight

- **Wave A (local branch `feat/cage-runner-execution-loop`)** — cage binary /
  claim loop (P0). Not on main.

## Wave B — progress

- [x] LLM gateway Dockerfile + Helm + compose.full
- [x] Gateway Helm fail-closed multi-replica without Postgres
- [x] `values-production.yaml` (JWT required, Postgres, REPLAY_STORE=db)
- [x] JWT-only enterprise auth limitation documented (`production-hardening.md` §9)
- [x] Postgres multi-replica guidance (§10)
- [ ] Full Postgres GA ops path / multi-replica e2e still open (#1194 deep)
- [ ] Native OIDC/SAML still open (edge SSO only)

## Wave C — progress

- [x] TypeScript receipt chain verifier (`sdk-typescript/src/receipts.ts`)
- [x] Runtime Timeline console dashboard (ASE)
- [ ] Ban/quarantine entity UI (needs entity catalog)
- [ ] Cage runs UI (after Wave A binary)
- [ ] Branch merge-or-close pass (~80 remotes)

## Recently closed on main

#1793 MCP signing · #1794 LLM gateway · #1795 evidence export · #1792 coverage
gates · #1790/#1791 packaging
