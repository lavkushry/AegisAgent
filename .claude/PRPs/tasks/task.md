# Active tasks — pre-production remaining work

Source of truth for **shipped** features: root [`CLAUDE.md`](../../../CLAUDE.md)
and [`docs/feature_history.md`](../../../docs/feature_history.md).

Source of truth for **capability status**:
[`docs/Implementation_Status.md`](../../../docs/Implementation_Status.md)
(refreshed 2026-07-09 against `main` after #1793–#1795).

This file tracks only **in-flight** and **verified remaining** production work.
Do not re-list shipped items as open.

**Verified against:** `origin/main` @ post-#1795 (investigation evidence export).

---

## In flight

- **`feat/cage-runner-execution-loop` (local)** — cage-runner binary / claim /
  heartbeat / Docker execution loop. **P0.** Needs security review of host
  Docker CLI access before merge. Not on `main` yet.

---

## Wave A — P0 (unknown-agent control plane)

Blocks any claim of runtime control over non-cooperative agents.

- [ ] **Cage-runner `main` + execution loop** — poll/claim runs, start Docker
      sandbox, emit lifecycle events, report status; package Dockerfile/Helm.
- [ ] **Gateway cage lease APIs on main** — claim / heartbeat / ownership-scoped
      status (if not merged with cage PR).
- [ ] **Sensor collectors + host enforcement** — real process/fs/net/secret
      signals; execute signed pause/kill/quarantine against the host/workload.
- [ ] **E2E unknown-agent path** — cage + egress deny + control action +
      receipt/incident in compose or Playwright/integration harness.
- [ ] **Egress forced path for caged runs** — not opt-in only (netns / default
      route through proxy).

---

## Wave B — P1 (production ops / HA)

Blocks multi-replica and enterprise-ops claims.

- [ ] **Postgres production mode (#1194)** — supported primary path, multi-
      replica validation, Helm defaults safe for HA.
- [ ] **Deploy packaging gaps** — Helm/Docker/compose for **cage-runner** and
      **llm-gateway** (broker chart if split out); full-stack Helm story.
- [ ] **OIDC/SAML for console/admin** — or explicit “JWT-only” enterprise
      limitation in public docs.
- [ ] **Production install checklist enforced** — `AEGIS_JWT_REQUIRED`,
      `AEGIS_ADMIN_API_KEY`, `AEGIS_REPLAY_STORE=db`, TLS, demo mode off,
      backups/retention (see `docs/production-hardening.md` §8).

---

## Wave C — P2 (product surface / honesty)

- [ ] **UI Phase 9.2–9.3** — cage runs, ban/quarantine centers, prompt/model/
      egress timelines, evidence export UX, policy center.
- [ ] **TypeScript receipt chain verifier** parity with Python/Go.
- [ ] **Go/TS prompt-model emit** parity with Python Phase 7.2.
- [x] **Ban/quarantine enforcement** at all choke points (authorize, broker,
      cage start/claim, egress) + agent-ban propagation to live runs as signed
      `kill_run` commands — see `feat/ban-enforcement-choke-points`.
      Remaining: `fingerprint`/`image_digest`/`prompt_hash` ban target types
      are stored but not yet consulted anywhere.
- [ ] **Standalone MCP proxy binary** (optional product line; Lite remains prod).
- [ ] **Branch hygiene** — merge-or-close pass on ~80 remote branches (no bulk
      delete without one-by-one review).
- [ ] **Docs stay current** — update `Implementation_Status.md` in the same PR
      as capability landings (validator enforces required row labels).

---

## Recently closed (do not re-open as missing)

| Item | Landing |
|------|---------|
| MCP manifest Ed25519 signing (opt-in) | #1793 |
| Coverage gates raised (Rust 80%, Python 78%) | #1792 |
| Sensor + egress-proxy packaging (Docker/Helm/compose) | #1790 / #1791 |
| Phase 7.1 prompt/model schemas | #1775 |
| Phase 7.2 Python SDK capture | #1776 |
| Phase 7.3 LLM gateway adapter | #1794 |
| Phase 8.3 investigation evidence export + checkpoints | #1795 |
| Dead `feat/1142-*-cursor` branches | deleted (session audit) |

---

## Production claim matrix (quick)

| Claim | Status |
|-------|--------|
| Known-agent integrity gateway | **Shipable** (ops checklist still required) |
| Integrity-anchored SOC evidence | **Mostly shipable** (UI beta) |
| Unknown-agent sandbox control | **Blocked on Wave A** |
| Multi-replica K8s | **Blocked on Wave B / Postgres** |
| Full enterprise console + OIDC | **Blocked on Wave B/C** |
