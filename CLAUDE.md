# AegisAgent — Coding-Agent Context (`CLAUDE.md`)

Minimal, current context to work in this repo. For *why* the product is shaped this way, read **[`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md)** (source of truth) — don't re-derive it.

## What AegisAgent is (June 2026)

The **integrity layer for AI agent actions** — open, self-hostable, framework-neutral. The generic gateway loop (intercept → policy → allow/deny → audit → approval) is commodity (free Microsoft toolkit + OSS + SaaS), so it is **table stakes here**. The two defensible differentiators are:

1. **Approval integrity** — the human approval is bound to a SHA-256 hash of the *frozen exact action*; the SDK **fails closed** if a different/edited/expired action would execute (defeats approve-then-swap, replay, render-vs-bytes).
2. **Deterministic trust-provenance gating** — authorization is gated on the *source trust level* of the triggering content (6 levels), not a text score (confused-deputy defense). Plus **verifiable, hash-chained action receipts** as compliance evidence (SOC 2 / EU AI Act Art. 14).

> Motto: **Make the approval trustworthy. Trust the source, not the text.**

## Current status (work-in-progress on branch `feat/approval-integrity`)

**Verified here (Python, 25/25 + runnable demo + CLI):**
- `action_hash` canonicalization unified as scheme **`aegis-jcs-1`** in `sdk-python/aegisagent/canon.py`; SDK fails closed on hash mismatch, on approval expiry, **and if it cannot atomically consume a single-use approval** (replay defense).
- Verifiable receipts: format + reference verifier (`aegisagent/receipts.py`), CLI (`aegis-verify-receipts`), shared corpus (`tests/receipt_chain_vectors.json`).
- End-to-end demo `examples/integrity_demo.py`.

**Written but NOT yet compiled (Rust gateway — no toolchain in some envs):**
- Cross-language `action_hash` corpus test (`canonical_action_matches_shared_corpus`).
- Gateway-side approval expiry (`get_approval` → `EXPIRED`; `approve_approval` → 409): `expired_approval_is_reported_and_cannot_be_approved`.
- Receipt-hash parity lock (`receipt_chain_matches_shared_corpus`).
- **Receipt emission**: `action_receipts` table + `emit_action_receipt` on every decision + `GET /v1/receipts/:id/verify` (`authorize_emits_verifiable_receipt`).
- **Single-use approvals (replay T-A3)**: `consumed_at` column + atomic `db::consume_approval` + `POST /v1/approvals/:id/consume` (`consume_is_single_use`); SDK consumes before executing.

**Next (Rust):** make chain-head selection race-safe (transaction); enterprise receipt signing / transparency-log anchoring. **Build the Rust + run `cargo test` before stacking more Rust.**

Baseline still present: Rust Axum gateway, SQLite/SQLx (tenant-scoped), Cedar policy pack (`policies.cedar` ≡ `gateway/policies.cedar`, incl. deterministic trust-provenance rules), MCP Gateway Lite, audit events, Python `@protect_tool`.

## Commands

```bash
# Gateway (Rust)
cargo check  --manifest-path gateway/Cargo.toml
cargo test   --manifest-path gateway/Cargo.toml        # incl. the 3 tests above
cargo fmt    --manifest-path gateway/Cargo.toml -- --check
cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings
CEDAR_POLICY_PATH=policies.cedar cargo run --manifest-path gateway/Cargo.toml   # binds 127.0.0.1:8080

# SDK + demos (Python)
python3 -m pip install -e sdk-python/
python3 -m unittest discover -s sdk-python/tests       # 25/25
python3 examples/integrity_demo.py                     # zero-setup wedge demo
aegis-verify-receipts <receipts.json>                  # or: python3 -m aegisagent.verify_receipts <f>

# Local stack
docker compose up --build && bash scripts/seed-demo.sh && python3 examples/github-attack-demo.py
```

## API endpoints (contract)

`GET /health` · `POST /v1/agents/register` · `POST /v1/tools` · `GET|POST /v1/mcp/servers` (GET lists servers with `status` + pinned `manifest_hash`) · `GET|POST /v1/mcp/servers/:server_key/tools` · `POST .../tools/:tool_key/approve|disable` · `POST /v1/authorize` (returns `decision`, `action_hash`, approval info; optional `request_id` makes the call idempotent — a repeat with the same `(agent, request_id)` replays the original decision/approval instead of re-evaluating) · `GET /v1/approvals/:id` (returns `status`, bound `action_hash`; `EXPIRED` for stale pending) · `POST /v1/approvals/:id/approve|reject|edit` · `POST /v1/approvals/:id/consume` (single-use; 409 if already used/expired) · `GET /v1/runs/:id/timeline` · `GET /v1/audit/events` · `GET /v1/receipts/:id/verify` (recomputes receipt hash; returns `verified`).

**Management & query API** (tenant-scoped, paginated; batch-1 #1096): `GET /v1/agents` · `GET|PATCH|DELETE /v1/agents/:id` · `POST /v1/agents/:id/freeze|unfreeze|revoke` (freeze accepts optional `{"reason": "..."}`, recorded as `agents.frozen_reason`; agents also track `last_seen_at` heartbeat and `quarantined_at`) · `GET /v1/decisions` (filter `agent_id`,`decision`) · `GET /v1/decisions/:id` · `GET /v1/approvals` (list pending; `EXPIRED` for stale) · `GET /v1/receipts` · `GET /v1/receipts/:id` · `POST /v1/receipts/verify-chain` · `GET|POST /v1/policies` · `PUT|DELETE /v1/policies/:id` · `POST /v1/policies/reload` · `GET|POST /v1/tenants` · `GET /v1/tenants/:id` · `GET /v1/tenants/:id/export` (GDPR data-portability bundle) · `GET|PUT /v1/mcp/servers/:server_key` · `POST /v1/mcp/servers/:server_key/quarantine|restore` · `GET /v1/stats` · `GET /v1/openapi.json` · `GET /v1/version` · `GET /v1/ws/events` (WebSocket live SOC stream). **SOC:** `GET /v1/alerts` · `GET /v1/incidents` · `GET /v1/incidents/:id` · `POST /v1/incidents/:id/close` · `GET /v1/incidents/:id/narrate` · `GET /v1/soc/summary`.

## Critical invariants (do not weaken)

- **Canonicalization `aegis-jcs-1` MUST stay byte-identical across SDK and gateway** (keys sorted by Unicode code point, compact separators, **raw UTF-8 / no `\uXXXX`**, reject non-finite floats). Locked by `tests/canonical_action_vectors.json` + `tests/receipt_chain_vectors.json`. A divergence silently breaks the fail-closed guarantee — never change hashing without bumping the scheme + CI byte-equality.
- **Fail closed:** unknown agent/tool/MCP server/MCP tool → deny; critical → deny; high-risk → require approval. SDK refuses to execute on hash mismatch, expired approval, or unreachable gateway (mutating/high-risk).
- **Approval integrity:** every approval binds to the original `action_hash`; edits re-hash + re-evaluate; expiry enforced (SDK + gateway); never re-decide a decided approval; **single-use** — atomically consumed before execution (no replay).
- **Trust-provenance is deterministic:** classifiers may only *tighten* a label, never loosen it. Mutating action + `untrusted_external`/`malicious_suspected` → deny.
- **Multi-tenant isolation:** every tenant-owned query binds/filters `tenant_id`; parameterized SQLx only (no string interpolation).
- **Local binding** `127.0.0.1` for dev/test; **redact** secrets from logs/receipts (store hashes, not payloads); no `.unwrap()`/`.expect()` in production paths.

## Where things live

- `gateway/src/`: `routes.rs` (handlers, canonicalization, approval integrity, receipt helpers), `db.rs` (tenant-scoped SQLx), `policy.rs` (Cedar), `models.rs`, `main.rs`. `gateway/policies.cedar` (keep ≡ root `policies.cedar`).
- `sdk-python/aegisagent/`: `canon.py` (scheme), `decorator.py` (`@protect_tool`, fail-closed + expiry), `receipts.py` (verifier), `verify_receipts.py` (CLI), `client.py`.
- Strategy docs in `docs/` were re-anchored 2026-06-02 on the integrity wedge; `docs/action-receipt-spec.md` is the open receipt format.

## How to continue

Use TDD (RED → GREEN). Spend effort on the **two integrity primitives + receipts** (the moat); don't reinvent the commodity gateway loop. After Rust edits, run `cargo test/fmt/clippy`; **don't stack unverified Rust** — get the branch green first. `.clauderules`/`.cursorrules` are harness-generated (regenerate via `scripts/setup_agent_harness.sh`, don't hand-edit). Persona scopes: `AGENTS.md`.
