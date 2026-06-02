# AegisAgent — Coding-Agent Context (`CLAUDE.md`)

Minimal, current context to work in this repo. For *why* the product is shaped this way, read **[`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md)** (source of truth) — don't re-derive it.

## What AegisAgent is (June 2026)

The **integrity layer for AI agent actions** — open, self-hostable, framework-neutral. The generic gateway loop (intercept → policy → allow/deny → audit → approval) is commodity (free Microsoft toolkit + OSS + SaaS), so it is **table stakes here**. The two defensible differentiators are:

1. **Approval integrity** — the human approval is bound to a SHA-256 hash of the *frozen exact action*; the SDK **fails closed** if a different/edited/expired action would execute (defeats approve-then-swap, replay, render-vs-bytes).
2. **Deterministic trust-provenance gating** — authorization is gated on the *source trust level* of the triggering content (6 levels), not a text score (confused-deputy defense). Plus **verifiable, hash-chained action receipts** as compliance evidence (SOC 2 / EU AI Act Art. 14).

> Motto: **Make the approval trustworthy. Trust the source, not the text.**

## Current status (work-in-progress on branch `feat/approval-integrity`)

**Verified here (Python, 25/25 + runnable demo + CLI):**
- `action_hash` canonicalization unified as scheme **`aegis-jcs-1`** in `sdk-python/aegisagent/canon.py`; SDK fails closed on hash mismatch **and on approval expiry**.
- Verifiable receipts: format + reference verifier (`aegisagent/receipts.py`), CLI (`aegis-verify-receipts`), shared corpus (`tests/receipt_chain_vectors.json`).
- End-to-end demo `examples/integrity_demo.py`.

**Written but NOT yet compiled (Rust gateway — no toolchain in some envs):**
- Cross-language `action_hash` corpus test (`canonical_action_matches_shared_corpus`).
- Gateway-side approval expiry (`get_approval` → `EXPIRED`; `approve_approval` → 409): `expired_approval_is_reported_and_cannot_be_approved`.
- Receipt-hash parity lock (`receipt_chain_matches_shared_corpus`).

**Next (Rust):** emit `action_receipts` (hash-chained per tenant) on every decision + `GET /v1/receipts/:id/verify`; then single-use `nonce` (replay T-A3). **Build the Rust + run `cargo test` before stacking more Rust.**

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

`GET /health` · `POST /v1/agents/register` · `POST /v1/tools` · `POST /v1/mcp/servers` · `GET|POST /v1/mcp/servers/:server_key/tools` · `POST .../tools/:tool_key/approve|disable` · `POST /v1/authorize` (returns `decision`, `action_hash`, approval info) · `GET /v1/approvals/:id` (returns `status`, bound `action_hash`; `EXPIRED` for stale pending) · `POST /v1/approvals/:id/approve|reject|edit` · `GET /v1/runs/:id/timeline` · `GET /v1/audit/events` · **planned:** `GET /v1/receipts/:id/verify`.

## Critical invariants (do not weaken)

- **Canonicalization `aegis-jcs-1` MUST stay byte-identical across SDK and gateway** (keys sorted by Unicode code point, compact separators, **raw UTF-8 / no `\uXXXX`**, reject non-finite floats). Locked by `tests/canonical_action_vectors.json` + `tests/receipt_chain_vectors.json`. A divergence silently breaks the fail-closed guarantee — never change hashing without bumping the scheme + CI byte-equality.
- **Fail closed:** unknown agent/tool/MCP server/MCP tool → deny; critical → deny; high-risk → require approval. SDK refuses to execute on hash mismatch, expired approval, or unreachable gateway (mutating/high-risk).
- **Approval integrity:** every approval binds to the original `action_hash`; edits re-hash + re-evaluate; expiry enforced (SDK + gateway); never re-decide a decided approval.
- **Trust-provenance is deterministic:** classifiers may only *tighten* a label, never loosen it. Mutating action + `untrusted_external`/`malicious_suspected` → deny.
- **Multi-tenant isolation:** every tenant-owned query binds/filters `tenant_id`; parameterized SQLx only (no string interpolation).
- **Local binding** `127.0.0.1` for dev/test; **redact** secrets from logs/receipts (store hashes, not payloads); no `.unwrap()`/`.expect()` in production paths.

## Where things live

- `gateway/src/`: `routes.rs` (handlers, canonicalization, approval integrity, receipt helpers), `db.rs` (tenant-scoped SQLx), `policy.rs` (Cedar), `models.rs`, `main.rs`. `gateway/policies.cedar` (keep ≡ root `policies.cedar`).
- `sdk-python/aegisagent/`: `canon.py` (scheme), `decorator.py` (`@protect_tool`, fail-closed + expiry), `receipts.py` (verifier), `verify_receipts.py` (CLI), `client.py`.
- Strategy docs in `docs/` were re-anchored 2026-06-02 on the integrity wedge; `docs/action-receipt-spec.md` is the open receipt format.

## How to continue

Use TDD (RED → GREEN). Spend effort on the **two integrity primitives + receipts** (the moat); don't reinvent the commodity gateway loop. After Rust edits, run `cargo test/fmt/clippy`; **don't stack unverified Rust** — get the branch green first. `.clauderules`/`.cursorrules` are harness-generated (regenerate via `scripts/setup_agent_harness.sh`, don't hand-edit). Persona scopes: `AGENTS.md`.
