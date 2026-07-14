# Walkthrough: Week-3 typed AuthorizeService extraction

**Branch:** `feat/typed-authorize-service`  
**Status:** complete for evaluation extraction + adapter packaging

## What shipped

1. **`aegis-decision` crate** (`lib/decision/`)
   - Context: `AuthorizeContext`, `AuthCredential`, `Transport`
   - Pipeline: `run_authorize_pipeline` = admit → preflight → guard → metadata → evaluate
   - Ports: `DecisionRuntime` (storage, Cedar, caches, SOC, GitHub side effects)
   - Outcomes: `DecisionOutcome` / `DecisionBody` (no Axum/tonic)
   - Tests: stage units in `*_tests.rs`; shared `test_runtime::MockRuntime`;
     pipeline e2e in `pipeline_tests.rs`; `error_map` class mapping
   - Gateway re-exports only adapter surface (`run_authorize_pipeline`,
     context/outcome types); stage types stay on `aegis_decision`

2. **Gateway adapters**
   - `decision_runtime.rs` — `GatewayDecisionRuntime`
   - `authorize_service.rs` — wire map + `GatewayAuthorizeService`
   - `routes/authorize.rs` — ~80-line REST entry
   - gRPC `authorize` → context → `evaluate` → `outcome_to_tonic`

3. **Tests / packaging**
   - Equality corpus: `authorize_equality.rs` (REST headers vs typed context)
   - Route tests: `authorize_tests.rs` (co-located, path module)
   - Docs: ROADMAP, MIGRATION_MATRIX, LLD §7, Implementation_Status, CHANGELOG

## Docs polish (post-extraction)

- `docs/architecture.md` transitional DAG includes `aegis-decision` + `DecisionRuntime` note
- README authorization row reflects thin adapters → decision pipeline
- `.claude/rules/code_tour.md` lists `lib/decision/` in tree + onboarding order

## Verification commands run

```bash
cargo test -p aegis-decision --lib -- --test-threads=1
# pipeline e2e mocks: allow, 401, idempotent, require_approval, frozen/revoked,
# dry_run, cedar deny, webhook reject, ban, tool permission, MCP permission /
# quarantine / unapproved / approved allow
cargo test -p gateway --lib equality_ -- --test-threads=1
cargo test -p gateway --lib -- --test-threads=1 authorize_
cargo clippy -p aegis-decision -p gateway --all-targets -- -D warnings
```

## Follow-ons (not this branch)

- Reactor-owned snapshots / generation binding (target AuthorizeService LLD shape)
- Move `authorize_tests` to workspace integration crate
- Further typed SOC gRPC RPCs still on storage-direct paths
- Push branch + open PR when requested
