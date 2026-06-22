# AegisAgent — Coding-Agent Context (`CLAUDE.md`)

Minimal, current context to work in this repo. For *why* the product is shaped this way, read **[`docs/AegisAgent_Gap_Reassessment_2026-06.md`](docs/AegisAgent_Gap_Reassessment_2026-06.md)** (source of truth) — don't re-derive it.

## What AegisAgent is (June 2026)

The **integrity layer for AI agent actions** — open, self-hostable, framework-neutral. The generic gateway loop (intercept -> policy -> allow/deny -> audit -> approval) is commodity, so it is **table stakes here**. The two defensible differentiators are:

1. **Approval integrity** — the human approval is bound to a SHA-256 hash of the *frozen exact action*; the SDK **fails closed** if a different/edited/expired action would execute (defeats approve-then-swap, replay, render-vs-bytes).
2. **Deterministic trust-provenance gating** — authorization is gated on the *source trust level* of the triggering content (6 levels), not a text score (confused-deputy defense). Plus **verifiable, hash-chained action receipts** as compliance evidence (SOC 2 / EU AI Act Art. 14).

> Motto: **Make the approval trustworthy. Trust the source, not the text.**

## Current Status & Feature Parity History
For the complete feature development records, SDK specifications, and ticket parity logs, see **[`docs/feature_history.md`](docs/feature_history.md)**.

* **Baseline**: Rust Axum gateway, SQLite/SQLx (tenant-scoped), Cedar policy pack (`policies.cedar` ≡ `gateway/policies.cedar`, incl. deterministic trust-provenance rules), MCP Gateway Lite, audit events, 3-SDK parity.
* **Agent-to-gateway mTLS (#1310)**: optional mutual-TLS auth, alternative to bearer tokens, gated on `AEGIS_MTLS_CA_CERT` (CRL revocation via `AEGIS_MTLS_CRL_PATH`). Verified client-cert Subject CN maps to an agent via `agents.mtls_cn` (set through `PATCH /v1/agents/:id`); unrecognized CN fails closed (401); unset env var leaves bearer-token auth unchanged. See `src/src/mtls.rs`.
* **Signed policy bundles (#1280)**: `POST /v1/policies/bundles` uploads an Ed25519-signed, multi-policy Cedar bundle, gated on `AEGIS_POLICY_SIGNING_KEY` (verifying/public key); unset, every request fails closed (501). Signature covers the `aegis-jcs-1`-canonicalized `{policies, version, created_at}` hash; entries upsert by `policy_key`; all-or-nothing Cedar validation before any write. See `src/src/routes/policy.rs`.
* **Database encryption at rest (#1192)**: compile-time `sqlcipher` Cargo feature (`cargo build --features sqlcipher`) feature-unifies the workspace's single `libsqlite3-sys` build with SQLCipher (`bundled-sqlcipher-vendored-openssl`), so `sqlx-sqlite` transparently links against SQLCipher instead of plain SQLite. At runtime, set `AEGIS_DB_ENCRYPTION_KEY` to enable the `PRAGMA key` on every connection. Fails closed at startup if the key is set but the binary wasn't compiled with the feature (`PRAGMA cipher_version` detects whether the linked library is SQLCipher-capable). See `lib/storage/src/db/mod.rs`.

## Architecture & Performance Roadmap

### Storage Architecture (June 2026 evaluation)

AegisAgent uses a **two-layer storage model**:

| Layer | Current | Production target |
|---|---|---|
| Relational (approvals, receipts, decisions, audit) | SQLite + WAL + `SQLITE_BUSY` retry | PostgreSQL (#1194, MVCC, concurrent writes) |
| Semantic / vector index | Qdrant (external) via `gateway/src/qdrant.rs` | Qdrant (unchanged — already the right tool) |

* **Why not etcd for metadata?** etcd is optimized for distributed consensus KV store. Relational joins, foreign keys, and transactions needed for decisions/approvals make SQLite/PG the correct choice.
* **Why not a pluggable flat-file store?** Flat-file stores lose ACID/relational integrity.
* **Current SQLite scalability ceiling:** SQLite serializes writes through a WAL journal. pgBouncer/PostgreSQL (#1194) is the production target.

### Performance Quick Wins (priority order)
1. **Local embeddings (`--features fastembed`):** CPU-local embedding generation.
2. **PostgreSQL backend (#1194):** True concurrent MVCC writes.
3. **JCS-1 canonicalization caching:** Memoizing on `(action_hash, request_id)` to avoid redundant CPU work.
4. **Kubernetes / Helm packaging:** Gateway scaling with shared PostgreSQL.

## Commands

```bash
# Gateway (Rust)
cargo check  --manifest-path src/Cargo.toml
cargo test   --manifest-path src/Cargo.toml        # 637 tests
cargo test   --manifest-path src/Cargo.toml --features sqlcipher   # #1192, encryption-at-rest build
cargo fmt    --manifest-path src/Cargo.toml -- --check
cargo clippy --manifest-path src/Cargo.toml -- -D warnings
cargo deny --manifest-path src/Cargo.toml check licenses   # #1174, blocks GPL/AGPL
cargo llvm-cov --manifest-path src/Cargo.toml --fail-under-lines 70   # coverage gate
CEDAR_POLICY_PATH=policies.cedar cargo run --manifest-path src/Cargo.toml   # binds 127.0.0.1:8080

# SDK + Demos (Python)
python3 -m pip install -e sdk-python/
python3 -m unittest discover -s sdk-python/tests       # 187 tests
python3 examples/integrity_demo.py                     # zero-setup wedge demo
aegis-verify-receipts <receipts.json>                  # receipt chain verifier

# Go SDK
cd sdk-go && go test ./...

# TypeScript SDK
cd sdk-typescript && npm ci && npx tsc --noEmit && npm test

# Local Stack & Playwright E2E
docker compose up --build && bash scripts/seed-demo.sh
docker compose -f docker-compose.dev.yml up --build    # seeded dev stack
cd e2e && npm ci && AEGIS_DASHBOARD_URL=http://127.0.0.1:8080 npx playwright test
```

## Critical Invariants (do not weaken)

* **Canonicalization `aegis-jcs-1` MUST stay byte-identical across SDK and gateway** (Unicode sorted keys, compact separators, raw UTF-8, reject non-finite floats). Locked by `tests/canonical_action_vectors.json`.
* **Fail closed:** Unknown agent/tool/MCP server/tool -> deny; critical -> deny; high-risk -> require approval. SDK refuses to execute on hash mismatch, expired approval, or unreachable gateway (mutating/high-risk).
* **Approval integrity:** Every approval binds to the original `action_hash`; edits re-hash + re-evaluate; single-use atomic consume.
* **Trust-provenance is deterministic:** Classifiers may only *tighten* a label, never loosen it. Downstream agent hops gate on the most restrictive trust level seen anywhere upstream (`trust_chain::propagate`).
* **Multi-tenant isolation:** Every tenant-owned query binds/filters `tenant_id`; parameterized SQLx only.
* **Local binding** `127.0.0.1` for dev/test; redact secrets from logs/receipts; no `.unwrap()`/`.expect()` in production.
* **Encryption-at-rest fails closed:** if `AEGIS_DB_ENCRYPTION_KEY` is set but the binary was not compiled with `--features sqlcipher`, startup MUST error rather than silently run unencrypted (`verify_encryption_or_fail_closed` in `lib/storage/src/db/mod.rs`).

## Where Things Live

* `src/`: Routing (`routes/` folder), database (`db` modules/traits under `lib/storage`), policy engine (modules under `lib/policy`), models (`lib/api`), gateway daemon (`main.rs`, `grpc.rs`, etc.), SOC features under `lib/soc/` (detection, correlation, etc.).
* `sdk-python/aegisagent/`: Canonicalization (`canon.py`), decorator (`decorator.py`), client (`client.py`), receipts (`receipts.py`), verify CLI (`verify_receipts.py`).
* `sdk-go/`: `canon/canon.go`, `aegis/client.go`, `aegis/protect.go`, `aegis/receipts.go`.
* `sdk-typescript/src/`: `canon.ts`, `client.ts`, `protect.ts`.
* Architecture ADRs: `docs/adr/`.

## How to Continue

Use TDD (RED -> GREEN). Run `cargo test/fmt/clippy` after Rust edits; don't stack unverified Rust. `.clauderules`/`.cursorrules` are harness-generated; do not hand-edit. Persona scopes are defined in `AGENTS.md`.
