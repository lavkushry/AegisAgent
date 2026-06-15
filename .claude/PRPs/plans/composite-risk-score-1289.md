# Title: Composite Risk Score Computation (#1289)

## 1. Architectural Scope & Impact
- New module `gateway/src/risk.rs`: pure, deterministic `compute_composite_risk_score`
  function + `RiskWeights`/`RiskInputs` types. No Cedar/decision-flow impact (Law 1 —
  advisory only, never gates `allow`/`deny`/`require_approval`).
- New table `tenant_risk_weights` (per-tenant overrides; falls back to env-configured
  defaults via `RiskWeights::from_env()` when no row exists).
- `decisions` table: additive `composite_risk_score INTEGER` column
  (`ensure_decisions_composite_risk_score_column`, mirrors existing
  `ensure_decisions_latency_ms_column` pattern).
- `AuthorizeResponse` / `DecisionRecord`: new `composite_risk_score: i32` /
  `Option<i32>` field, populated on every `/v1/authorize` response and idempotent
  replay.
- New tenant-scoped endpoints `GET /v1/tenants/risk-weights` and
  `PUT /v1/tenants/risk-weights` (mirrors the `TenantId`-extractor pattern used by
  `/v1/policies`).

## 2. Step-by-Step Execution Phases

- **Phase 1: Database Migration**
  - `db.rs`: `CREATE TABLE IF NOT EXISTS tenant_risk_weights` (+ tenant_id index),
    `ensure_decisions_composite_risk_score_column`.
  - `db::get_risk_weights(pool, tenant_id) -> RiskWeights` (DB row, else
    `RiskWeights::from_env()`).
  - `db::upsert_risk_weights(pool, tenant_id, &RiskWeights) -> Result<(), sqlx::Error>`.
  - `db::insert_decision` / decision-record SELECTs updated for the new column.

- **Phase 2: Gateway Implementation**
  - `risk.rs`: `RiskWeights { environment_weight_mutating, context_trust_penalty_*
    (one per of the 6 trust levels), mcp_trust_penalty, anomaly_weight_pct,
    approval_credit }`, `RiskInputs { base_action_risk, mutates_state, source_trust,
    is_mcp_call, anomaly_score, had_prior_approval }`,
    `compute_composite_risk_score(&RiskInputs, &RiskWeights) -> i32` (clamped 0..=100).
  - `routes.rs::authorize_action`: after `risk_score`/`risk_level`/`is_mcp_call` are
    resolved, look up `RiskWeights` (cached like `skill_cache`) and compute
    `composite_risk_score`; thread it into `write_decision_and_audit` and every
    `AuthorizeResponse` construction (including early-return deny paths).
  - `idempotent_replay_response`: read `composite_risk_score` from `DecisionRecord`.
  - New handlers `get_tenant_risk_weights` / `put_tenant_risk_weights` in `routes.rs`,
    registered in `main.rs`.

- **Phase 3: Policy Integration**
  - None — composite score is advisory metadata only, never referenced by
    `policies.cedar`.

- **Phase 4: Client SDK/Decorator Updates**
  - None for this issue (response field is additive/optional from the SDK's
    perspective; SDKs already pass through unknown JSON fields where applicable).

## 3. Verification & Testing Targets
- `risk.rs` unit tests: determinism (same inputs → same score), clamping at 0/100,
  each weight component's individual contribution.
- `routes.rs` integration tests: `composite_risk_score` present and correct on
  `/v1/authorize` responses for allow/deny/require_approval and on idempotent
  replay; `GET`/`PUT /v1/tenants/risk-weights` round-trip + tenant isolation.
- `cargo test --manifest-path gateway/Cargo.toml`, `cargo fmt -- --check`,
  `cargo clippy --all-targets -- -D warnings`.

## 4. Security Audit Checklist
- All new queries parameterized, filtered by `tenant_id`.
- Fail-closed unaffected: composite score computed *after* the Cedar decision is
  final and never alters it.
- `PUT /v1/tenants/risk-weights` validates weight ranges (no unbounded ints that
  could overflow `i32` arithmetic; clamp computation regardless).
