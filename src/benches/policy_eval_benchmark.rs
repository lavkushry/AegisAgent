//! TASK-1314: micro-benchmark for `PolicyEngine::authorize` in isolation.
//!
//! Issue #1314 ("In-memory compiled policy cache (avoid Cedar re-parse)")
//! asks for the cached `PolicySet` evaluation path to be benchmarked at
//! `< 1ms`. The existing `authorize_benchmark` (from #1313) measures the
//! *entire* `/v1/authorize` HTTP handler — including DB lookups, SQLite
//! writes for the decision/audit rows, and SOC event emission — which came
//! in around 6.4-6.7ms mean. That number does not isolate the cost of Cedar
//! policy evaluation against the cached `PolicySet`, which is the thing
//! #1314 actually cares about.
//!
//! This benchmark instead constructs a [`PolicyEngine`] exactly as
//! production does (`PolicyEngine::init("policies.cedar")`, parsing the base
//! policy file once), and then calls [`PolicyEngine::authorize`] directly in
//! a tight loop. No HTTP layer, no database, no async runtime overhead in the
//! measured region — just the cached-`PolicySet` read + `Authorizer::is_authorized`
//! call.
//!
//! ## Two scenarios
//!
//! - `base_policy_set_fallback`: no tenant-specific policy set has been
//!   cached (`reload_tenant_policies` was never called for this tenant), so
//!   `authorize` falls back to cloning `base_policy_set`. This is the path
//!   every tenant takes until it first touches `/v1/policies` (see
//!   `docs/performance-baseline.md` for the startup-population finding).
//! - `tenant_policy_set_cached`: `reload_tenant_policies` has been called
//!   once for the tenant (with zero active custom policies in the
//!   `policies` table), populating `tenant_policy_sets` with a clone of the
//!   base set under this tenant's key. `authorize` then clones *that* cached
//!   set instead of falling back to `base_policy_set`. This isolates the
//!   "tenant has an entry in `tenant_policy_sets`" cache-hit path without
//!   tripping the policy-id-collision bug described below.
//!
//! Both scenarios should be sub-millisecond if the cache is doing its job —
//! no `PolicySet::from_str` / re-parse happens in either path.
//!
//! ## Note: a real custom-policy merge scenario isn't exercised here
//!
//! A third scenario -- a tenant with one or more *active custom policies* in
//! the `policies` table, merged on top of the base set by
//! `reload_tenant_policies` -- was attempted and dropped. `PolicySet::from_str`
//! assigns sequential ids `policy0`, `policy1`, ... to every policy in the
//! parsed text, restarting from `policy0` for each call. `policies.cedar`
//! (the base set) has 5 top-level policies, i.e. ids `policy0`..`policy4`.
//! `reload_tenant_policies` (`policy.rs`) merges a freshly-parsed custom
//! `PolicySet` into a clone of the base set via `PolicySet::add`, which
//! errors on a duplicate id. Since any freshly-parsed custom policy text
//! with one or more policies necessarily produces an id in the range
//! `policy0..policyN-1`, and the base set already occupies
//! `policy0..policy4`, a tenant with at least one active custom policy whose
//! generated id falls in `policy0..policy4` (essentially guaranteed for
//! small custom policy sets) causes `reload_tenant_policies` to fail with
//! "duplicate template or policy id", and the tenant's policy set is never
//! cached. This is a real, independently-significant bug in the merge
//! strategy, separate from #1314's caching concern (the cache mechanism
//! itself, `RwLock<HashMap<...>>`, is sound; it's the *population* of that
//! cache for tenants with custom policies that's broken), and is called out
//! in `docs/performance-baseline.md` as a follow-up, not fixed in this PR.

use criterion::{criterion_group, criterion_main, Criterion};
use gateway::models::{
    AuthorizeAgentContext, AuthorizeDynamicContext, AuthorizeRequest, AuthorizeToolCall,
    AuthorizeTraceContext,
};
use gateway::policy::PolicyEngine;
use tokio::runtime::Runtime;

/// Build the same steady-state "allow" request used by `authorize_benchmark`:
/// a read-only `filesystem.read_file` action from a `trusted_internal_signed`
/// context, which the default Cedar policy pack permits instantly.
fn allow_request() -> AuthorizeRequest {
    AuthorizeRequest {
        request_id: None,
        callback: None,
        agent: AuthorizeAgentContext {
            id: "bench-agent".to_string(),
            environment: "production".to_string(),
        },
        user: None,
        tool_call: AuthorizeToolCall {
            tool: "filesystem".to_string(),
            action: "read_file".to_string(),
            resource: Some("bench.txt".to_string()),
            mutates_state: false,
            parameters: serde_json::json!({}),
        },
        context: AuthorizeDynamicContext {
            source_trust: "trusted_internal_signed".to_string(),
            contains_sensitive_data: false,
        },
        trace: Some(AuthorizeTraceContext {
            run_id: "run_bench".to_string(),
            trace_id: "trace_bench".to_string(),
            parent_run_id: None,
            root_trust_level: None,
        }),
        nonce: None,
        timestamp: None,
        dry_run: None,
    }
}

fn policy_eval_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().expect("failed to build tokio runtime");

    let engine = rt.block_on(async {
        PolicyEngine::init("policies.cedar")
            .await
            .expect("PolicyEngine::init")
    });

    let request = allow_request();

    let mut group = c.benchmark_group("policy_engine_authorize");

    // Scenario 1: tenant has never had `reload_tenant_policies` called --
    // `authorize` falls back to cloning `base_policy_set` on every call.
    group.bench_function("base_policy_set_fallback", |b| {
        b.iter(|| {
            let decision = engine
                .authorize("tenant_no_custom_policies", &request, "low")
                .expect("authorize");
            criterion::black_box(decision.decision);
        });
    });

    // Scenario 2: tenant has an entry in `tenant_policy_sets` (populated by
    // `reload_tenant_policies` with zero active custom policies, so it's a
    // clone of the base set under the tenant's key) -- `authorize` hits the
    // `sets.get(tenant_id)` cache path instead of the `base_policy_set`
    // fallback.
    let tenant_id = "tenant_with_cached_policy_set";
    engine
        .reload_tenant_policies(tenant_id, &[])
        .expect("reload_tenant_policies");

    assert!(
        engine.has_tenant(tenant_id),
        "tenant policy set should be cached after reload_tenant_policies"
    );

    group.bench_function("tenant_policy_set_cached", |b| {
        b.iter(|| {
            let decision = engine
                .authorize(tenant_id, &request, "low")
                .expect("authorize");
            criterion::black_box(decision.decision);
        });
    });

    group.finish();
}

criterion_group!(benches, policy_eval_benchmark);
criterion_main!(benches);
