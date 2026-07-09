# Active tasks

Source of truth for shipped features: [`CLAUDE.md`](/CLAUDE.md) (root) — its
"Current Status & Feature Parity History" section and
[`docs/feature_history.md`](../../../docs/feature_history.md) are kept
current per-PR. This file previously duplicated a feature checklist that
rotted (most items below were checked off in PRs #1276, #1277, #1602,
#1611–#1774, etc. without this file being updated) — don't re-duplicate
that list here again. Track only what's genuinely in flight or genuinely
still missing, verified against the code, not assumed from an old plan doc.

## Verified still missing (2026-07-09 audit)

- **MCP manifest signing** — `manifest_hash`-based drift *detection* exists
  (`lib/storage/src/db/mcp.rs`, `src/src/routes/authorize.rs`), but there is
  no cryptographic signature verification of MCP server manifests (unlike
  policy bundles, which are Ed25519-signed — `src/src/routes/policy.rs`,
  #1280). A manifest that "drifts" is detected and gated; a manifest that's
  simply forged/never-signed is not distinguished from a legitimate one.
- **`aegis-cage-runner` has no binary.** `bins/aegis-cage-runner` is a
  lib-only crate (`SandboxRuntime` trait, Docker CLI wrapper, workspace
  management, event emission — all unit-tested) with no `main.rs`/`[[bin]]`
  target, and the gateway doesn't depend on it either. The
  `/v1/agent-cage/runs` control-plane routes manage run *records*; nothing
  polls them and actually invokes Docker to execute a sandboxed run yet.
  This is a bigger lift than "add a Dockerfile" — it needs an execution
  loop designed and reviewed (it shells out to the host Docker CLI, a
  security-sensitive decision this project's own threat model would want
  scrutinized before landing).
- **Phase 7.3 — LLM gateway adapter** (prompt/model-call choke point) not
  started. Phases 7.1/7.2 (lineage schemas + SDK capture) shipped
  (#1775/#1776); this is the last unbuilt piece of the Phased PR Plan
  (`docs/AegisAgent_Phased_PR_Plan.md` §9).
- **Phase 8.3 — Evidence export** (checkpoints + graph manifest +
  redaction manifest, export action emits its own receipt) not built. The
  existing `GET /v1/compliance/evidence-pack` (#1298) is a different,
  earlier SOC2/GDPR-focused export (receipts/audit/policies/incidents/
  approvals as a ZIP) — it doesn't include the timeline graph
  (`src/src/graph.rs`), cage-runner checkpoints, a redaction manifest, or
  emit a receipt for the export action itself.
- **Deployment packaging gaps (#1297 follow-up)** — `helm/` had only the
  gateway chart, `docker-compose.yml` had only gateway; being fixed in
  branch `deploy-1297-sensor-proxy-packaging` (Dockerfiles + Helm charts +
  compose entries for `aegis-egress-proxy`/`aegis-node-sensor`, plus a
  repo-root `.dockerignore` that didn't exist — every prior `docker build`
  sent the whole repo, including `target/`, as build context).
- **~85 unmerged local/remote branches** (164 total incl. main), several of
  which duplicate work already re-landed on `main` under different PRs
  (confirmed for the five `feat/1142-*-cursor` branches — all six #1142
  pagination targets are already merged via #1747–#1752, including
  `list_policy_templates_cursor`, which lives in `lib/policy/src/compiler.rs`
  rather than `lib/storage` since templates come from an in-memory catalog,
  not `StorageBackend` — those five branches are dead and should be deleted,
  not merged; deletion is blocked pending explicit user
  authorization/action, not a technical blocker).

## Fixed (2026-07-09)

- **Coverage gate raised to match the 80% standard.** `.github/workflows/
  ci.yml`'s Rust gate was `--fail-under-lines 70` against an actual measured
  87.62% — raised to 80 (comfortable margin). Python's was `--fail-under=75`
  against an actual measured exactly 80% — raised to 78, not 80, to leave a
  safety margin rather than sitting flush with the current number.

## Everything else previously listed here

Shipped. See `CLAUDE.md` and `git log --oneline --grep="<keyword>"` for the
landing PR rather than trusting a static checklist again.
