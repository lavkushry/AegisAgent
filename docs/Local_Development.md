# Local Development

**One sentence:** everything you need to build, run, test, and demo AegisAgent on your machine.

## 1. Prerequisites

- **Rust** ≥ 1.88 (MSRV in `Cargo.toml`) + `protoc` (protobuf compiler — `lib/api`'s build.rs compiles `proto/*.proto`)
- **Python** ≥ 3.8 (SDK/demo; 3.9+ recommended for full dev extras), **Node** ≥ 20 (UI, TS SDK, e2e), **Go** ≥ 1.22 (Go SDK)
- **Docker + Compose** (full stack), optional: `sqlx-cli`, `cargo-llvm-cov`, `cargo-flamegraph`

## 2. Fastest path (full stack in Docker)

```bash
make doctor                           # read-only local prereq and port checks
make demo                             # gateway, seed data, attack block, approval integrity, receipts
```

Pre-seeded dev variant: `docker compose -f docker-compose.dev.yml up --build -d` (+ `scripts/seed-demo-dev.sh`).

## 3. Running the gateway from source

```bash
CEDAR_POLICY_PATH=policies.cedar cargo run -p gateway --bin gateway
# binds 127.0.0.1:8080 (dev default — loopback on purpose)
```

Useful env for dev: `RUST_LOG=debug`, `AEGIS_APPROVAL_TTL_SECS=120`, `AEGIS_POLICY_HOT_RELOAD=true` (edit `policies.cedar` live). Ports/config: `config/config.yaml`.

### Database

SQLite file store; migrations in `lib/storage/migrations/` run automatically at startup. To add one: `sqlx migrate add -r <name>` (see `.claude/rules/database_migration.md` for the tenant-index template — every new tenant-owned table needs a `tenant_id` index). Postgres mode uses `migrations_postgres/`.

## 4. Test suites

```bash
cargo test --workspace -- --test-threads=1
cargo test -p gateway --features sqlcipher -- --test-threads=1   # encryption-at-rest build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo llvm-cov --workspace --fail-under-lines 70

python3 -m pip install -e sdk-python/
python3 -m unittest discover -s sdk-python/tests

cd sdk-go && go test ./...
cd sdk-typescript && npm ci && npx tsc --noEmit && npm test
cd ui && npm ci && npm test                                # vitest
cd e2e && npm ci && AEGIS_DASHBOARD_URL=http://127.0.0.1:8080 npx playwright test
```

Cross-language canon parity: the gateway and all three SDKs must pass `tests/canonical_action_vectors.json` and `tests/receipt_chain_vectors.json` — CI enforces it; run the SDK test suites locally after touching anything named `canon`.

## 5. Demos

| Demo | Shows |
|---|---|
| `examples/integrity_demo.py` | zero-setup wedge: decision + receipt |
| `examples/approve_then_swap_demo.py` | swap after approval → refused ([approve-then-swap-demo.md](approve-then-swap-demo.md)) |
| `examples/github-attack-demo.py` | prompt-injection via GitHub content → provenance deny ([demo-github-attack.md](demo-github-attack.md)) |
| `examples/mock_server.py` | full approval polling loop against a running gateway |

## 6. Docs site locally

```bash
pip install -r requirements-docs.txt
mkdocs serve          # http://127.0.0.1:8000
node scripts/validate-docs.mjs   # link/inventory/architecture-map checks
```

## 7. Common errors

| Symptom | Fix |
|---|---|
| build fails on `aegis-api` with protoc error | install `protobuf-compiler` |
| `401 Unauthorized` on every call | token must be a valid JWT or start with `tenant_` (dev heuristic); check `AEGIS_JWT_REQUIRED` |
| `404 Tenant not found` | seed first (`scripts/seed-demo.sh`) — the extractor verifies tenant existence |
| `SQLITE_BUSY` under load | expected contention; retries built in — don't run two gateways on one DB file |
| startup error about encryption key | `AEGIS_DB_ENCRYPTION_KEY` set but binary not built with `--features sqlcipher` (fail-closed by design) |
| UI at `/dashboard` looks stale | rebuild `ui/` (`npm run build`) — the gateway serves `ui/dist` |
| approvals instantly expired | your `AEGIS_APPROVAL_TTL_SECS` is tiny; default is 1800 |

More: [AegisAgent_Debugging_Guide.md](AegisAgent_Debugging_Guide.md).

## 8. Related docs

[quickstart.md](quickstart.md) · [installation.md](installation.md) · [onboarding/For_New_Engineer.md](onboarding/For_New_Engineer.md) · [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md)
