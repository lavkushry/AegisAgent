# Walkthrough: Week-3 typed AuthorizeService extraction

**Branch:** `feat/typed-authorize-service`  
**Status:** complete — evaluation extraction, adapter packaging, and fail-closed e2e coverage

## What shipped

1. **`aegis-decision` crate** (`lib/decision/`)
   - Context: `AuthorizeContext`, `AuthCredential`, `Transport`
   - Pipeline: `run_authorize_pipeline` = admit → preflight → guard → metadata → evaluate
   - Ports: `DecisionRuntime` (storage, Cedar, caches, SOC, GitHub side effects)
   - Outcomes: `DecisionOutcome` / `DecisionBody` (no Axum/tonic)
   - Tests: all stage + pipeline e2e use shared `test_runtime::MockRuntime`;
     `error_map` class mapping
   - Gateway re-exports only adapter surface (`run_authorize_pipeline`,
     context/outcome types); stage types stay on `aegis_decision`

2. **Gateway adapters**
   - `decision_runtime.rs` — `GatewayDecisionRuntime`
   - `authorize_service.rs` — wire map + `GatewayAuthorizeService` (no Axum body bridge)
   - `authorize_service_tests.rs` (wire map + header context + DecisionOutcome
     mapping) + `authorize_equality.rs` path modules
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
# 87 lib tests (cargo test -p aegis-decision --lib -- --list)
cargo test -p gateway --lib authorize_service -- --test-threads=1
cargo test -p gateway --lib equality_ -- --test-threads=1
cargo clippy -p aegis-decision -p gateway --all-targets -- -D warnings
```

## Ship checklist

- [x] Evaluation fully library-owned (`run_authorize_pipeline`)
- [x] REST + gRPC thin adapters; no gRPC→Axum JSON bridge
- [x] Equality corpus (`equality_*`) for HeaderMap vs typed context
- [x] Stage + pipeline e2e with shared `MockRuntime` (**87** decision lib tests)
- [x] Wire-map unit tests (`authorize_service_tests`)
- [x] Docs: architecture transitional DAG, ROADMAP Week 3, Gateway.md, LLD §7,
      Implementation_Status, CLAUDE.md, code_tour / skills onboarding,
      runtime-authorization-api decision vocabulary
- [ ] Push branch + open PR (when requested)

## Follow-ons (not this branch)

- Reactor-owned snapshots / generation binding (target AuthorizeService LLD shape)
- Move large `authorize_tests.rs` to workspace integration crate
- Further typed SOC gRPC RPCs still on storage-direct paths
