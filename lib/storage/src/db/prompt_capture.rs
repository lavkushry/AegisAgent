//! Phase 7.1 (prompt/model capture): `prompt_events` / `model_call_events`
//! ingest + read. Idempotent append (dedupe on `(tenant_id, event_id)`),
//! mirroring the `runtime_events` pattern. Stores a hash and a
//! caller-redacted preview only — never a raw prompt, request, or response
//! body.

use super::SOC_MAX_LIMIT;
use crate::db::DbPool;
use aegis_api::models::*;

const PROMPT_EVENT_COLS: &str = "id, tenant_id, event_id, run_id, trace_id, prompt_hash, \
     redacted_prompt_preview, role, source_trust, model_provider, retention_policy, \
     redaction_status, created_at, received_at";

/// Idempotently append a prompt event. Returns `true` if this call inserted a
/// new row, `false` if the `(tenant_id, event_id)` was already present (a
/// replayed/retried event — a no-op).
pub async fn insert_prompt_event(
    pool: &DbPool,
    r: &PromptEventRecord,
) -> Result<bool, sqlx::Error> {
    let inserted = crate::execute_query!(
        pool,
        "INSERT INTO prompt_events
           (id, tenant_id, event_id, run_id, trace_id, prompt_hash, redacted_prompt_preview,
            role, source_trust, model_provider, retention_policy, redaction_status,
            created_at, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id, event_id) DO NOTHING",
        &r.id,
        &r.tenant_id,
        &r.event_id,
        &r.run_id,
        &r.trace_id,
        &r.prompt_hash,
        &r.redacted_prompt_preview,
        &r.role,
        &r.source_trust,
        &r.model_provider,
        &r.retention_policy,
        &r.redaction_status,
        r.created_at,
        r.received_at
    )?;
    Ok(inserted.rows_affected() == 1)
}

/// Tenant-scoped lookup by producer-assigned `event_id`. `None` if absent, or
/// if it belongs to a different tenant.
pub async fn get_prompt_event_by_event_id(
    pool: &DbPool,
    tenant_id: &str,
    event_id: &str,
) -> Result<Option<PromptEventRecord>, sqlx::Error> {
    let sql = format!(
        "SELECT {PROMPT_EVENT_COLS} FROM prompt_events WHERE tenant_id = ? AND event_id = ?"
    );
    crate::fetch_optional_as!(PromptEventRecord, pool, sql.as_str(), tenant_id, event_id)
}

/// Tenant-scoped, run-scoped listing for the console's Prompt Timeline page.
/// Oldest first (chronological read), capped at `SOC_MAX_LIMIT`.
pub async fn list_prompt_events_for_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
    limit: i64,
) -> Result<Vec<PromptEventRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {PROMPT_EVENT_COLS} FROM prompt_events
         WHERE tenant_id = ? AND run_id = ?
         ORDER BY created_at ASC, rowid ASC
         LIMIT ?"
    );
    crate::fetch_all_as!(
        PromptEventRecord,
        pool,
        sql.as_str(),
        tenant_id,
        run_id,
        limit
    )
}

const MODEL_CALL_EVENT_COLS: &str = "id, tenant_id, event_id, run_id, trace_id, provider, model, \
     request_hash, response_hash, started_at, finished_at, token_counts_json, status, \
     redaction_status, received_at";

/// Idempotently append a model-call event. Returns `true` if this call
/// inserted a new row, `false` if the `(tenant_id, event_id)` was already
/// present (a replayed/retried event — a no-op).
pub async fn insert_model_call_event(
    pool: &DbPool,
    r: &ModelCallEventRecord,
) -> Result<bool, sqlx::Error> {
    let inserted = crate::execute_query!(
        pool,
        "INSERT INTO model_call_events
           (id, tenant_id, event_id, run_id, trace_id, provider, model, request_hash,
            response_hash, started_at, finished_at, token_counts_json, status,
            redaction_status, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id, event_id) DO NOTHING",
        &r.id,
        &r.tenant_id,
        &r.event_id,
        &r.run_id,
        &r.trace_id,
        &r.provider,
        &r.model,
        &r.request_hash,
        &r.response_hash,
        r.started_at,
        r.finished_at,
        &r.token_counts_json,
        &r.status,
        &r.redaction_status,
        r.received_at
    )?;
    Ok(inserted.rows_affected() == 1)
}

/// Tenant-scoped lookup by producer-assigned `event_id`. `None` if absent, or
/// if it belongs to a different tenant.
pub async fn get_model_call_event_by_event_id(
    pool: &DbPool,
    tenant_id: &str,
    event_id: &str,
) -> Result<Option<ModelCallEventRecord>, sqlx::Error> {
    let sql = format!(
        "SELECT {MODEL_CALL_EVENT_COLS} FROM model_call_events WHERE tenant_id = ? AND event_id = ?"
    );
    crate::fetch_optional_as!(
        ModelCallEventRecord,
        pool,
        sql.as_str(),
        tenant_id,
        event_id
    )
}

/// Tenant-scoped, run-scoped listing for the console's Model Calls page.
/// Oldest first (chronological read), capped at `SOC_MAX_LIMIT`.
pub async fn list_model_call_events_for_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
    limit: i64,
) -> Result<Vec<ModelCallEventRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {MODEL_CALL_EVENT_COLS} FROM model_call_events
         WHERE tenant_id = ? AND run_id = ?
         ORDER BY received_at ASC, rowid ASC
         LIMIT ?"
    );
    crate::fetch_all_as!(
        ModelCallEventRecord,
        pool,
        sql.as_str(),
        tenant_id,
        run_id,
        limit
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;
    use chrono::Utc;

    fn prompt_ev(tenant: &str, id: &str, event_id: &str) -> PromptEventRecord {
        let now = Utc::now();
        PromptEventRecord {
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            event_id: event_id.to_string(),
            run_id: Some("run-1".to_string()),
            trace_id: Some("trace-1".to_string()),
            prompt_hash: "a".repeat(64),
            redacted_prompt_preview: Some("Summarize the attached [REDACTED] file".to_string()),
            role: Some("user".to_string()),
            source_trust: Some("untrusted_external".to_string()),
            model_provider: Some("openai".to_string()),
            retention_policy: Some("30d".to_string()),
            redaction_status: "redacted".to_string(),
            created_at: now,
            received_at: now,
        }
    }

    fn model_call_ev(tenant: &str, id: &str, event_id: &str) -> ModelCallEventRecord {
        let now = Utc::now();
        ModelCallEventRecord {
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            event_id: event_id.to_string(),
            run_id: Some("run-1".to_string()),
            trace_id: Some("trace-1".to_string()),
            provider: "openai".to_string(),
            model: "gpt-5".to_string(),
            request_hash: Some("b".repeat(64)),
            response_hash: Some("c".repeat(64)),
            started_at: Some(now),
            finished_at: Some(now),
            token_counts_json: Some(r#"{"prompt":10,"completion":20}"#.to_string()),
            status: "success".to_string(),
            redaction_status: "redacted".to_string(),
            received_at: now,
        }
    }

    #[tokio::test]
    async fn prompt_event_insert_is_idempotent_on_event_id() {
        let pool = setup_pool("prompt_event_dedup").await;
        assert!(
            insert_prompt_event(&pool, &prompt_ev("t_a", "row1", "e1"))
                .await
                .unwrap(),
            "first insert is new"
        );
        assert!(
            !insert_prompt_event(&pool, &prompt_ev("t_a", "row2", "e1"))
                .await
                .unwrap(),
            "duplicate event_id is a no-op"
        );
        let fetched = get_prompt_event_by_event_id(&pool, "t_a", "e1")
            .await
            .unwrap()
            .expect("row persisted");
        assert_eq!(fetched.id, "row1", "the first insert's row survives");
    }

    #[tokio::test]
    async fn prompt_event_same_event_id_different_tenant_is_not_a_dup() {
        let pool = setup_pool("prompt_event_tenant_event").await;
        assert!(insert_prompt_event(&pool, &prompt_ev("t_a", "r1", "e1"))
            .await
            .unwrap());
        assert!(insert_prompt_event(&pool, &prompt_ev("t_b", "r2", "e1"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn prompt_event_reads_are_tenant_scoped() {
        let pool = setup_pool("prompt_event_reads").await;
        insert_prompt_event(&pool, &prompt_ev("t_a", "r1", "e1"))
            .await
            .unwrap();
        assert!(get_prompt_event_by_event_id(&pool, "t_b", "e1")
            .await
            .unwrap()
            .is_none());
        assert!(get_prompt_event_by_event_id(&pool, "t_a", "e1")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn model_call_event_insert_is_idempotent_on_event_id() {
        let pool = setup_pool("model_call_dedup").await;
        assert!(
            insert_model_call_event(&pool, &model_call_ev("t_a", "row1", "e1"))
                .await
                .unwrap(),
            "first insert is new"
        );
        assert!(
            !insert_model_call_event(&pool, &model_call_ev("t_a", "row2", "e1"))
                .await
                .unwrap(),
            "duplicate event_id is a no-op"
        );
    }

    #[tokio::test]
    async fn model_call_event_reads_are_tenant_scoped() {
        let pool = setup_pool("model_call_reads").await;
        insert_model_call_event(&pool, &model_call_ev("t_a", "r1", "e1"))
            .await
            .unwrap();
        assert!(get_model_call_event_by_event_id(&pool, "t_b", "e1")
            .await
            .unwrap()
            .is_none());
        let fetched = get_model_call_event_by_event_id(&pool, "t_a", "e1")
            .await
            .unwrap()
            .expect("row persisted");
        assert_eq!(fetched.model, "gpt-5");
    }

    #[tokio::test]
    async fn list_prompt_events_for_run_is_tenant_and_run_scoped() {
        let pool = setup_pool("prompt_event_list_run").await;
        insert_prompt_event(&pool, &prompt_ev("t_a", "r1", "e1"))
            .await
            .unwrap();
        let mut other_run = prompt_ev("t_a", "r2", "e2");
        other_run.run_id = Some("run-2".to_string());
        insert_prompt_event(&pool, &other_run).await.unwrap();
        insert_prompt_event(&pool, &prompt_ev("t_b", "r3", "e3"))
            .await
            .unwrap();

        let rows = list_prompt_events_for_run(&pool, "t_a", "run-1", 50)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "e1");
    }

    #[tokio::test]
    async fn list_model_call_events_for_run_is_tenant_and_run_scoped() {
        let pool = setup_pool("model_call_list_run").await;
        insert_model_call_event(&pool, &model_call_ev("t_a", "r1", "e1"))
            .await
            .unwrap();
        let mut other_run = model_call_ev("t_a", "r2", "e2");
        other_run.run_id = Some("run-2".to_string());
        insert_model_call_event(&pool, &other_run).await.unwrap();
        insert_model_call_event(&pool, &model_call_ev("t_b", "r3", "e3"))
            .await
            .unwrap();

        let rows = list_model_call_events_for_run(&pool, "t_a", "run-1", 50)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "e1");
    }
}
