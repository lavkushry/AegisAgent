//! #1315 — criterion benchmark comparing one `INSERT INTO audit_events` per
//! row (the pre-#1315 behavior of `write_decision_and_audit`) against a
//! single multi-row `db::insert_audit_events_batch` call for the same rows
//! (the batched path taken by [`gateway::audit_batch::run_audit_batch_writer`]).
//!
//! Each iteration writes a fresh batch of `BATCH_SIZE` audit rows into a
//! tempfile SQLite database (WAL mode, matching production config) to avoid
//! `UNIQUE` constraint collisions across iterations while still exercising
//! real disk I/O.

use chrono::Utc;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use gateway::db;
use gateway::models::AuditEventRecord;
use tokio::runtime::Runtime;
use uuid::Uuid;

/// Matches [`gateway::audit_batch::DEFAULT_BATCH_SIZE`].
const BATCH_SIZE: usize = 100;

fn make_audit_event(tenant_id: &str) -> AuditEventRecord {
    AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: "tool_call_intercepted".to_string(),
        agent_id: Some("agent_1".to_string()),
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: Some("filesystem".to_string()),
        action: Some("read_file".to_string()),
        resource: Some("/tmp/example".to_string()),
        event_json: r#"{"decision":"allow","risk_score":5}"#.to_string(),
        input_hash: None,
        output_hash: None,
        decision_id: Some(Uuid::new_v4().to_string()),
        approval_id: None,
        created_at: Utc::now(),
    }
}

fn audit_insert_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().expect("failed to build tokio runtime");
    let tenant_id = "tenant_bench";

    let pool = rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("audit_batch_bench.db");
        let db_url = format!("sqlite://{}", db_path.to_string_lossy());
        std::mem::forget(dir);

        let pool = db::init_db(&db_url).await.expect("init_db");
        db::register_tenant(&pool, tenant_id, "Bench Tenant", "developer")
            .await
            .expect("register_tenant");
        pool
    });

    let mut group = c.benchmark_group("audit_events_insert");
    group.sample_size(20);

    group.bench_function("sequential_inserts_per_row", |b| {
        b.to_async(&rt).iter_batched(
            || {
                (0..BATCH_SIZE)
                    .map(|_| make_audit_event(tenant_id))
                    .collect::<Vec<_>>()
            },
            |records| {
                let pool = pool.clone();
                async move {
                    for record in &records {
                        db::insert_audit_event(&pool, record)
                            .await
                            .expect("insert_audit_event");
                    }
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("single_batch_insert", |b| {
        b.to_async(&rt).iter_batched(
            || {
                (0..BATCH_SIZE)
                    .map(|_| make_audit_event(tenant_id))
                    .collect::<Vec<_>>()
            },
            |records| {
                let pool = pool.clone();
                async move {
                    db::insert_audit_events_batch(&pool, &records)
                        .await
                        .expect("insert_audit_events_batch");
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, audit_insert_benchmark);
criterion_main!(benches);
