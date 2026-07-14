# Walkthrough: Week-3 typed AuthorizeService extraction

**Branch:** `feat/typed-authorize-service`  
**Status:** complete for evaluation extraction + adapter packaging

## What shipped

1. **`aegis-decision` crate** (`lib/decision/`)
   - Context: `AuthorizeContext`, `AuthCredential`, `Transport`
   - Pipeline: `run_authorize_pipeline` = admit → preflight → guard → metadata → evaluate
   - Ports: `DecisionRuntime` (storage, Cedar, caches, SOC, GitHub side effects)
   - Outcomes: `DecisionOutcome` / `DecisionBody` (no Axum/tonic)

2. **Gateway adapters**
   - `decision_runtime.rs` — `GatewayDecisionRuntime`
   - `authorize_service.rs` — wire map + `GatewayAuthorizeService`
   - `routes/authorize.rs` — ~80-line REST entry
   - gRPC `authorize` → context → `evaluate` → `outcome_to_tonic`

3. **Tests / packaging**
   - Equality corpus: `authorize_equality.rs` (REST headers vs typed context)
   - Route tests: `authorize_tests.rs` (co-located, path module)
   - Docs: ROADMAP, MIGRATION_MATRIX, LLD §7, Implementation_Status, CHANGELOG

## Verification commands run

```bash
cargo test -p aegis-decision --lib -- --test-threads=1
# includes pipeline e2e mocks: allow, bad token, idempotent replay, require_approval
cargo test -p gateway --lib equality_ -- --test-threads=1
cargo test -p gateway --lib -- --test-threads=1 authorize_
cargo clippy -p aegis-decision -p gateway --all-targets -- -D warnings
```

## Follow-ons (not this branch)

- Reactor-owned snapshots / generation binding (target AuthorizeService LLD shape)
- Move `authorize_tests` to workspace integration crate
- Further typed SOC gRPC RPCs still on storage-direct paths
