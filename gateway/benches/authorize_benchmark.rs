//! TASK-1313: end-to-end criterion benchmark for `POST /v1/authorize`.
//!
//! This benchmarks the real `gateway::routes::authorize_action` handler
//! in-process against a real (tempfile) SQLite pool with migrations applied,
//! seeded with:
//!   - 1 primary "bench agent" (the one authenticating each request),
//!   - 100 additional registered agents (TASK-1313 implementation note: "100
//!     agents"), so the `agents` table is representative of a populated
//!     tenant rather than a near-empty one,
//!   - 1000 prior decision rows (TASK-1313 implementation note: "1000
//!     decisions"), inserted directly via `db::insert_decision` rather than
//!     by replaying 1000 `/v1/authorize` calls — direct inserts are ~3
//!     orders of magnitude cheaper to set up and exercise the same SQLite
//!     file-size / index characteristics that `decisions` table reads would
//!     see, without spending the whole benchmark budget on setup.
//!
//! The benchmarked request itself is the steady-state hot path: a read-only
//! (`mutates_state: false`) `filesystem.read_file` action from a
//! `trusted_internal_signed` context, which the default Cedar policy pack
//! (`policies.cedar`) permits instantly — `allow`, no approval required. This
//! is the common case for `/v1/authorize` traffic.
//!
//! ## What this measures vs. the issue's targets
//!
//! Criterion's console summary reports **mean + standard deviation** (with a
//! confidence interval on the mean), not true percentiles. The issue's
//! acceptance criteria (p50 < 10ms, p95 < 50ms, p99 < 100ms) are
//! percentile-based. For a tight, low-variance in-process hot path like this
//! one, mean ~= p50 is a reasonable approximation, and criterion's reported
//! max-of-samples is a rough proxy for tail latency — but this is NOT a
//! substitute for true percentiles under concurrent load. See
//! `docs/performance-baseline.md` for the actual numbers and an honest
//! discussion of this limitation, and `gateway/benchmarks/authorize_load.py`
//! / `authorize_load.k6.js` for HTTP-level percentile measurement against a
//! live server.
//!
//! ## Sample size
//!
//! The default criterion sample size (100) with the default measurement time
//! (5s) was too slow for this sandbox given the per-iteration SQLite I/O
//! (each iteration does a real `INSERT INTO decisions` + audit event write).
//! We reduce `sample_size` to 30 — see `docs/performance-baseline.md` for the
//! tradeoff discussion.

use criterion::{criterion_group, criterion_main, Criterion};
use gateway::routes::{self, benchutil};
use std::sync::Arc;
use tokio::runtime::Runtime;

const SEED_AGENTS: usize = 100;
const SEED_DECISIONS: usize = 1000;

fn authorize_allow_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().expect("failed to build tokio runtime");

    // One-time setup: build the DB, seed agents + decisions, outside the
    // measured loop.
    let (state, tenant_id, agent_token) = rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("authorize_bench.db");
        // Leak the tempdir so the SQLite file outlives this closure for the
        // duration of the benchmark process (criterion runs the whole
        // process for one bench target, so this is bounded and acceptable).
        let db_path_str = db_path.to_string_lossy().into_owned();
        std::mem::forget(dir);

        let (state, tenant_id, agent_token) = benchutil::setup_bench_state(&db_path_str)
            .await
            .expect("setup_bench_state");

        benchutil::seed_extra_agents(&state.pool, &tenant_id, SEED_AGENTS)
            .await
            .expect("seed_extra_agents");

        // Find the primary bench agent's id for decision seeding.
        let agent = gateway::db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .expect("get_agent_by_token")
            .expect("bench agent exists");

        benchutil::seed_decisions(&state.pool, &tenant_id, &agent.id, SEED_DECISIONS)
            .await
            .expect("seed_decisions");

        (state, tenant_id, agent_token)
    });

    let headers = benchutil::agent_headers(&agent_token, &tenant_id);

    let mut group = c.benchmark_group("authorize_action");
    group.sample_size(30);

    group.bench_function("allow_readonly_filesystem_read_file", |b| {
        b.to_async(&rt).iter(|| {
            let state: Arc<routes::AppState> = state.clone();
            let headers = headers.clone();
            // Build a fresh request each iteration: a unique trace/run id
            // avoids the idempotency fast-path (`request_id` is unset here
            // anyway, so this isn't strictly required, but keeps the request
            // body construction inside the measured region, matching real
            // end-to-end cost).
            let request = benchutil::allow_authorize_request();
            async move {
                let response = routes::authorize_action(
                    axum::extract::State(state),
                    headers,
                    axum::Json(request),
                )
                .await;
                // Force evaluation of the response (criterion's async iter
                // already awaits it, but `into_response()` mirrors what Axum
                // does on the wire and avoids the compiler optimizing away
                // unused work).
                let _ = axum::response::IntoResponse::into_response(response);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, authorize_allow_benchmark);
criterion_main!(benches);
