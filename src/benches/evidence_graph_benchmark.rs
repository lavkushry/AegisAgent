//! #1316: criterion benchmark for `GET /v1/graph/agent/:agent_id`, the
//! widest of the three evidence-graph endpoints (up to
//! `GRAPH_AGENT_DECISION_LIMIT` = 50 decisions expanded per call, each
//! contributing a `ToolCall` + `Decision` node and (when present) an
//! `Approval`/`Receipt` node).
//!
//! Before #1316, `add_decision_subgraph` issued up to 2 sequential,
//! unindexed `WHERE tenant_id = ? AND decision_id = ?` lookups per decision
//! (one for the approval, one for the receipt) — up to 100 queries for a
//! 50-decision agent graph. This benchmark seeds exactly 50 decisions, each
//! with both an approval and a receipt, and calls the real
//! `routes::get_graph_for_agent` handler end-to-end against a tempfile
//! SQLite pool with the #1316 composite indexes
//! (`idx_approvals_tenant_decision`, `idx_action_receipts_tenant_decision`)
//! applied, to verify the issue's "< 100ms for a 50-node subgraph" target.

use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};
use gateway::db;
use gateway::models::{ApprovalRecord, DecisionRecord};
use gateway::routes::{self, benchutil};
use std::sync::Arc;
use tokio::runtime::Runtime;
use uuid::Uuid;

const SEED_DECISIONS: usize = 50;

async fn seed_decision_with_approval_and_receipt(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    i: usize,
) -> Result<(), sqlx::Error> {
    let decision_id = Uuid::new_v4().to_string();
    let decision = DecisionRecord {
        id: decision_id.clone(),
        tenant_id: tenant_id.to_string(),
        agent_id: agent_id.to_string(),
        user_id: None,
        run_id: Some(format!("run_graph_bench_{i}")),
        trace_id: Some(format!("trace_graph_bench_{i}")),
        skill: "github".to_string(),
        action: "merge_pull_request".to_string(),
        resource: Some(format!("pr_{i}")),
        input_json: "{}".to_string(),
        decision: "require_approval".to_string(),
        risk_score: Some(75),
        reason: Some("bench".to_string()),
        matched_policy_ids: None,
        request_id: None,
        latency_ms: Some(5),
        composite_risk_score: Some(75),
        root_trust_level: None,
        parent_run_id: None,
        created_at: Utc::now(),
    };
    db::insert_decision(pool, &decision).await?;

    db::insert_approval(
        pool,
        &ApprovalRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: decision_id.clone(),
            status: "approved".to_string(),
            approver_group: None,
            approver_user_id: Some("approver_bench".to_string()),
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: "sha256:deadbeef".to_string(),
            edited_skill_call: None,
            expires_at: None,
            decided_at: Some(Utc::now()),
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now(),
        },
    )
    .await?;

    db::append_action_receipt_atomic(pool, tenant_id, |prev_receipt_hash| {
        gateway::models::ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(decision_id.clone()),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some(agent_id.to_string()),
            user_id: None,
            run_id: Some(format!("run_graph_bench_{i}")),
            trace_id: Some(format!("trace_graph_bench_{i}")),
            tool: Some("github".to_string()),
            action: Some("merge_pull_request".to_string()),
            resource: Some(format!("pr_{i}")),
            source_trust: "trusted_internal_signed".to_string(),
            decision: "require_approval".to_string(),
            approver: Some("approver_bench".to_string()),
            action_hash: Some("sha256:deadbeef".to_string()),
            prev_receipt_hash,
            receipt_hash: format!("sha256:bench_{i}"),
            canon_version: "aegis-jcs-1".to_string(),
            signature: None,
            signer_public_key: None,
            created_at: Utc::now(),
        }
    })
    .await?;

    Ok(())
}

fn evidence_graph_for_agent_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().expect("failed to build tokio runtime");

    let (state, tenant_id, agent_id) = rt.block_on(async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("evidence_graph_bench.db");
        let db_path_str = db_path.to_string_lossy().into_owned();
        std::mem::forget(dir);

        let (state, tenant_id, agent_token) = benchutil::setup_bench_state(&db_path_str)
            .await
            .expect("setup_bench_state");

        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .expect("get_agent_by_token")
            .expect("bench agent exists");

        for i in 0..SEED_DECISIONS {
            seed_decision_with_approval_and_receipt(&state.pool, &tenant_id, &agent.id, i)
                .await
                .expect("seed_decision_with_approval_and_receipt");
        }

        (state, tenant_id, agent.id)
    });

    let mut group = c.benchmark_group("evidence_graph");
    group.sample_size(30);

    group.bench_function("get_graph_for_agent_50_decisions", |b| {
        b.to_async(&rt).iter(|| {
            let state: Arc<routes::AppState> = state.clone();
            let tenant_id = tenant_id.clone();
            let agent_id = agent_id.clone();
            async move {
                let response = routes::get_graph_for_agent(
                    axum::extract::State(state),
                    routes::TenantId(tenant_id),
                    axum::extract::Path(agent_id),
                    axum::extract::Query(routes::GraphDepthParams { depth: Some(3) }),
                )
                .await;
                let _ = axum::response::IntoResponse::into_response(response);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, evidence_graph_for_agent_benchmark);
criterion_main!(benches);
