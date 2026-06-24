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
* **Distributed tracing (#1156)**: optional OTLP span export, gated on `AEGIS_OTLP_ENDPOINT`; unset, entirely inert (no exporter, no extra tracing layer, no global OTel state touched). Spans: `authorize`, `cedar_evaluate`, `db_query`, `receipt_hash`, `approval_create`. Propagates an inbound W3C `traceparent` header so a calling SDK's trace stitches together with the gateway's. Exports OTLP/protobuf over plain HTTP with a blocking client (the batch processor runs its own OS thread, not a tokio task). See `src/src/otel.rs`.
* **Soft-delete for policies & MCP servers (#1193)**: `DELETE /v1/policies/:id` and the new `DELETE /v1/mcp/servers/:key` set `deleted_at` instead of removing the row; `list`/`get` queries filter it back out, GDPR `DELETE /v1/tenants/:id` is unaffected (still a real hard delete). Re-registering a soft-deleted MCP server (same unique `server_key`) revives it. `agents`/`skills` were deliberately left alone — agents already had equivalent soft-delete via `status = 'deleted'`, and skills has no user-facing delete API. Also fixed: `get_agent_by_token`/`get_agent_by_mtls_cn` now exclude `status = 'deleted'` (previously only excluded `quarantined`), closing a gap where a deleted agent could still authenticate.
* **Release supply-chain integrity (#1172)**: `.github/workflows/release-publish.yml` now signs every published image keylessly with `cosign` (GitHub OIDC → Sigstore Fulcio/Rekor, by digest not tag), attaches a SLSA Level 3 build-provenance attestation via the `slsa-framework/slsa-github-generator` reusable workflow, and generates an SPDX-format SBOM of the shipped container image (`anchore/sbom-action`) alongside the pre-existing CycloneDX SBOM of the Rust dependency graph. Workflow-only change, exercised only on tagged releases (`push: tags: v*`), not via normal PR CI.
* **Cedar policy hot-reload (#883)**: opt-in background filesystem watcher (`notify-debouncer-mini`) calls the same reload `POST /v1/policies/reload` triggers, automatically, whenever the policy file changes on disk; gated on `AEGIS_POLICY_HOT_RELOAD=true`, inert (no watcher thread) when unset. A failed parse on the new file content never clobbers the last-good policy set. See `src/src/policy_watcher.rs`.
* **OpenTelemetry metrics export (#1287)**: reuses the existing `AEGIS_OTLP_ENDPOINT` gate from tracing (#1156). `approval_hash_mismatch_total`/`provenance_denials_total` are OTLP observable counters reading the existing `SecurityMetrics` atomics (`lib/common`, kept OTel-agnostic); `authorize_latency_seconds` is a true per-request histogram recorded at the existing latency-measurement site. OTLP/HTTP, not gRPC, for the same reason as traces (avoids a second `tonic` major version). See `src/src/otel.rs`.
* **Unified `aegis` CLI (#1202)**: kubectl-style `aegis <subcommand>` entry point (`pip install aegisagent`) dispatching to `status`/`freeze-agent`/`unfreeze-agent`/`verify-receipts`/`export-audit`/`soc-summary`; the pre-existing standalone `aegis-*` scripts are unchanged. Consistent `--format {table,json}` across `status`/`freeze-agent`/`soc-summary`; TTY-aware colorized output (respects `NO_COLOR`). See `sdk-python/aegisagent/cli.py`.
* **Kubernetes Helm chart (#1206)**: `helm install aegis helm/aegis-gateway/` ships Deployment/Service/ConfigMap/Secret/ServiceMonitor/NetworkPolicy/PodDisruptionBudget/HPA templates. Defaults to `replicaCount: 1` and `autoscaling.enabled: false` (HPA template present but inert) since the relational backend is still SQLite+WAL single-writer — PostgreSQL (#1194) is the prerequisite for safe multi-replica writes. Probes wired to the existing `/livez`/`/readyz`/`/startupz` endpoints (#1208); the Cedar policy ConfigMap is checksummed into the pod annotation and `AEGIS_POLICY_HOT_RELOAD=true` by default so a policy-only `helm upgrade` is picked up live via the existing filesystem watcher (#883) without a pod restart. See `helm/aegis-gateway/`.
* **Configurable SQLite statement cache (#906)**: `AEGIS_DB_STATEMENT_CACHE_CAPACITY` explicitly wires sqlx-sqlite's per-connection prepared-statement LRU cache (previously left at sqlx's hardcoded default of 100, with no way to tune it). `0` is a valid, meaningful value (disables caching) rather than filtered out like other batch/interval env vars; unset behavior is unchanged. See `lib/storage/src/db/mod.rs`.
* **Memory-mapped SQLite reads (#919)**: `AEGIS_DB_MMAP_SIZE` (bytes) sets `PRAGMA mmap_size` on every pooled connection via `SqliteConnectOptions`, letting read-heavy workloads skip a syscall+copy per page by reading directly from the OS page cache. `0` is valid (explicitly disables mmap, matching SQLite's own semantics) rather than filtered out; unset leaves the linked SQLite's compiled-in default untouched. See `lib/storage/src/db/mod.rs`.
* **Tokio runtime metrics exporter (#920)**: extends the existing OTLP metrics gate (`AEGIS_OTLP_ENDPOINT`, #1287) with three observable instruments derived from `tokio::runtime::Handle::metrics()` — `tokio_workers_count`, `tokio_worker_poll_count_total`, `tokio_scheduler_utilization_ratio` — the same numbers the ad-hoc `GET /debug/runtime` endpoint (#1160) already exposes, now also available in a real time-series backend. `init_meter_provider` takes a `Handle` parameter (captured once in `main`, inside the runtime) rather than calling `Handle::current()` inside the observable callbacks, since the OTel SDK's periodic exporter invokes those callbacks from its own background thread. See `src/src/otel.rs`.
* **SQLite WAL checkpoint tuning (#896)**: `AEGIS_DB_JOURNAL_SIZE_LIMIT` (bytes, `-1` = no limit per SQLite's own semantics for this pragma) and `AEGIS_DB_WAL_AUTOCHECKPOINT` (pages, `0` = disable auto-checkpointing) make the two WAL-checkpoint PRAGMAs tunable. Also fixes a pre-existing bug found while wiring this up: `journal_size_limit`, `synchronous`, and `wal_autocheckpoint` were previously set via a one-off `sqlx::query(...).execute(&pool)` *after* the pool was created — since none of the three are persisted in the database file, that only ever reached whichever single connection happened to service that one query, leaving every other pooled connection (and any opened later under load) running with SQLite's own compiled-in defaults instead. Moved onto `SqliteConnectOptions` (like `mmap_size`, #919) so every connection the pool ever opens gets them. See `lib/storage/src/db/mod.rs`.
* **Flame graph profiling script (#910)**: `scripts/flamegraph.sh [bench-name]` wraps `cargo-flamegraph` around one of the existing criterion benches (`authorize_benchmark`, `policy_eval_benchmark`, `canon_benchmark`, `receipt_hash_benchmark`, `audit_batch_benchmark`, `evidence_graph_benchmark`) rather than a long-running gateway process — benches are self-contained, finite-duration runs, the workload shape `perf` samples cleanly. `CARGO_PROFILE_RELEASE_DEBUG=true` is passed as an env var override (not edited into `src/Cargo.toml`) so debug symbols are only added for the profiling build. Requires `cargo install flamegraph` and (on Linux) `perf`. See `scripts/flamegraph.sh`.

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
