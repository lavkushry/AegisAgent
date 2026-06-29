//! Phase 2.2 (runtime control plane): `runtime_events` ingest + read.
//!
//! Idempotent append (dedupe on `(tenant_id, event_id)`) plus tenant-scoped
//! reads by run and by tenant. Storage-only; ingest routes land in a later
//! phase. Stores hashes/identifiers only — never raw prompts/secrets/payloads.

use super::SOC_MAX_LIMIT;
use crate::db::DbPool;
use aegis_api::models::*;

/// Tenant-scoped column list shared by the read queries.
const COLS: &str = "id, tenant_id, event_id, event_type, severity, agent_id, run_id, sandbox_id, \
     trace_id, parent_event_id, source_component, source_trust, decision, reason, action_hash, \
     prompt_hash, request_hash, response_hash, receipt_id, receipt_hash, prev_receipt_hash, \
     canonical_version, redaction_status, schema_version, observed_at, received_at";

/// Idempotently append a runtime event. Returns `true` if this call inserted a
/// new row, `false` if the `(tenant_id, event_id)` was already present (a
/// replayed/retried event — a no-op). `ON CONFLICT DO NOTHING` makes concurrent
/// duplicate ingest safe (the leader-lock pattern).
pub async fn insert_runtime_event(
    pool: &DbPool,
    r: &RuntimeEventRecord,
) -> Result<bool, sqlx::Error> {
    let inserted = crate::execute_query!(
        pool,
        "INSERT INTO runtime_events
           (id, tenant_id, event_id, event_type, severity, agent_id, run_id, sandbox_id,
            trace_id, parent_event_id, source_component, source_trust, decision, reason,
            action_hash, prompt_hash, request_hash, response_hash, receipt_id, receipt_hash,
            prev_receipt_hash, canonical_version, redaction_status, schema_version,
            observed_at, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id, event_id) DO NOTHING",
        &r.id,
        &r.tenant_id,
        &r.event_id,
        &r.event_type,
        &r.severity,
        &r.agent_id,
        &r.run_id,
        &r.sandbox_id,
        &r.trace_id,
        &r.parent_event_id,
        &r.source_component,
        &r.source_trust,
        &r.decision,
        &r.reason,
        &r.action_hash,
        &r.prompt_hash,
        &r.request_hash,
        &r.response_hash,
        &r.receipt_id,
        &r.receipt_hash,
        &r.prev_receipt_hash,
        &r.canonical_version,
        &r.redaction_status,
        r.schema_version,
        r.observed_at,
        r.received_at
    )?;
    Ok(inserted.rows_affected() == 1)
}

/// All runtime events for one run, oldest-first (timeline order). Tenant-scoped.
pub async fn list_runtime_events_for_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
    limit: i64,
) -> Result<Vec<RuntimeEventRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {COLS} FROM runtime_events
         WHERE tenant_id = ? AND run_id = ?
         ORDER BY observed_at ASC, rowid ASC
         LIMIT ?"
    );
    crate::fetch_all_as!(
        RuntimeEventRecord,
        pool,
        sql.as_str(),
        tenant_id,
        run_id,
        limit
    )
}

/// Recent runtime events for a tenant, newest-first. Tenant-scoped.
pub async fn list_runtime_events(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<RuntimeEventRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {COLS} FROM runtime_events
         WHERE tenant_id = ?
         ORDER BY observed_at DESC, rowid DESC
         LIMIT ? OFFSET ?"
    );
    crate::fetch_all_as!(
        RuntimeEventRecord,
        pool,
        sql.as_str(),
        tenant_id,
        limit,
        offset
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;
    use chrono::Utc;

    fn ev(tenant: &str, id: &str, event_id: &str, run_id: &str) -> RuntimeEventRecord {
        let now = Utc::now();
        RuntimeEventRecord {
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            event_id: event_id.to_string(),
            event_type: "tool_call_requested".to_string(),
            severity: Some("info".to_string()),
            agent_id: None,
            run_id: Some(run_id.to_string()),
            sandbox_id: Some("sbx-1".to_string()),
            trace_id: Some("trace-1".to_string()),
            parent_event_id: None,
            source_component: "node-sensor".to_string(),
            source_trust: Some("untrusted_external".to_string()),
            decision: Some("require_approval".to_string()),
            reason: None,
            action_hash: Some("a".repeat(64)),
            prompt_hash: None,
            request_hash: None,
            response_hash: None,
            receipt_id: None,
            receipt_hash: None,
            prev_receipt_hash: None,
            canonical_version: Some("aegis-jcs-1".to_string()),
            redaction_status: Some("redacted".to_string()),
            schema_version: 1,
            observed_at: now,
            received_at: now,
        }
    }

    #[tokio::test]
    async fn insert_is_idempotent_on_event_id() {
        let pool = setup_pool("rt_dedup").await;
        assert!(
            insert_runtime_event(&pool, &ev("t_a", "row1", "e1", "run1"))
                .await
                .unwrap(),
            "first insert is new"
        );
        // Same (tenant, event_id) → deduped, even with a different row id.
        assert!(
            !insert_runtime_event(&pool, &ev("t_a", "row2", "e1", "run1"))
                .await
                .unwrap(),
            "duplicate event_id is a no-op"
        );
        let rows = list_runtime_events_for_run(&pool, "t_a", "run1", 50)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "only one row persisted for the deduped event"
        );
    }

    #[tokio::test]
    async fn same_event_id_different_tenant_is_not_a_dup() {
        let pool = setup_pool("rt_tenant_event").await;
        assert!(insert_runtime_event(&pool, &ev("t_a", "r1", "e1", "run1"))
            .await
            .unwrap());
        // Same event_id under a different tenant is a distinct event.
        assert!(insert_runtime_event(&pool, &ev("t_b", "r2", "e1", "run1"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn reads_are_tenant_scoped() {
        let pool = setup_pool("rt_reads").await;
        insert_runtime_event(&pool, &ev("t_a", "r1", "e1", "run1"))
            .await
            .unwrap();
        insert_runtime_event(&pool, &ev("t_a", "r2", "e2", "run1"))
            .await
            .unwrap();
        insert_runtime_event(&pool, &ev("t_b", "r3", "e3", "run1"))
            .await
            .unwrap();

        // Another tenant sees none of tenant A's run events.
        assert!(
            list_runtime_events_for_run(&pool, "t_b", "run1", 50)
                .await
                .unwrap()
                .is_empty()
                || list_runtime_events_for_run(&pool, "t_b", "run1", 50)
                    .await
                    .unwrap()
                    .iter()
                    .all(|e| e.tenant_id == "t_b")
        );
        let a = list_runtime_events(&pool, "t_a", 50, 0).await.unwrap();
        assert_eq!(a.len(), 2);
        assert!(a.iter().all(|e| e.tenant_id == "t_a"));
    }
}
