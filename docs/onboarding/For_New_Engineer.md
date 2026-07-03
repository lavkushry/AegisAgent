# Onboarding: New Engineer

**Goal:** understand the project in ~30 minutes, land your first change in your first week.

## 1. Read first (in order)

1. [../Product_Overview.md](../Product_Overview.md) — what & why (10 min)
2. [../Last_Mile_System_Walkthrough.md](../Last_Mile_System_Walkthrough.md) — the whole system as a story (15 min)
3. [../Architecture_Overview.md](../Architecture_Overview.md) — choke points, two planes, fail-closed invariants (15 min)
4. [../Repo_Knowledge_Map.md](../Repo_Knowledge_Map.md) — keep open as your map
5. [../Implementation_Status.md](../Implementation_Status.md) — so you never confuse shipped vs. designed

## 2. Mental model in three sentences

Aegis is a control plane, not an agent. Known agents pass every tool call through SDK → gateway → Cedar policy → (maybe) hash-bound approval → hash-chained receipt; the async SOC watches the stream and contains misbehavior. Unknown agents are (by design) run in a cage where the choke points are the only working paths.

## 3. Files to inspect (guided tour, ~1 hour)

| Order | File | Why |
|---|---|---|
| 1 | `src/src/main.rs` (router section) | Every route, every layer, startup gating |
| 2 | `src/src/routes/authorize.rs` | The hot path — the product in one file |
| 3 | `lib/policy/src/cedar.rs` + `policies.cedar` | How decisions are made |
| 4 | `src/src/routes/approval.rs` | Differentiator #1 |
| 5 | `src/src/routes/mod.rs` (`compute_receipt_hash`, caches, `TenantId`) | Cross-cutting machinery |
| 6 | `lib/storage/src/traits.rs` | The storage contract everything calls through |
| 7 | `lib/soc/src/detect.rs` → `respond.rs` | The async plane |
| 8 | `sdk-python/aegisagent/decorator.py` | What integrators actually touch |

## 4. Local setup

Follow [../Local_Development.md](../Local_Development.md). Fast path:

```bash
docker compose up --build -d
bash scripts/seed-demo.sh
python3 examples/integrity_demo.py
```

## 5. Non-negotiable invariants (memorize)

- `aegis-jcs-1` canonicalization stays **byte-identical** across gateway + SDKs (`tests/canonical_action_vectors.json`).
- **Fail closed** everywhere: unknown → deny; critical → deny; high-risk → approval; mismatch/expiry/unreachable → refuse.
- Every tenant-owned query **binds `tenant_id`**; parameterized SQLx only.
- No `.unwrap()`/`.expect()` in production Rust; `127.0.0.1` binding for dev/test; secrets redacted from logs/receipts.

## 6. Common first tasks

- Add a route: handler in `src/src/routes/<domain>.rs` → wire in `main.rs` → utoipa annotations (OpenAPI is generated) → tests → check [../api-reference.md](../api-reference.md) regenerates.
- Add a storage method: `lib/storage/src/traits.rs` + `db/<domain>.rs` impl + tenant-scoped test.
- Add a detection rule: `lib/soc/src/detect.rs` or the rule DSL; backtest it.

## 7. Verify your work

```bash
cargo check --workspace
cargo test --workspace -- --test-threads=1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

TDD is the house style (RED → GREEN → refactor); see `CLAUDE.md` and `CONTRIBUTING.md` at the repo root.

## 8. Contribution path

Small PRs; conventional commits (release-please derives versions); CI must be green (fmt, clippy, tests, coverage ≥70, SDK parity, scans). Debugging help: [../AegisAgent_Debugging_Guide.md](../AegisAgent_Debugging_Guide.md).
