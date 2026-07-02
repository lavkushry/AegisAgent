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
const MAX_TIME_BUCKETS: i64 = 10_000;

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

const FILTER_SQL: &str = "
   AND (? IS NULL OR event_type = ?)
   AND (? IS NULL OR severity = ?)
   AND (? IS NULL OR agent_id = ?)
   AND (? IS NULL OR run_id = ?)
   AND (? IS NULL OR trace_id = ?)
   AND (? IS NULL OR source_component = ?)
   AND (? IS NULL OR source_trust = ?)
   AND (? IS NULL OR decision = ?)
   AND (? IS NULL OR action_hash = ?)
   AND (? IS NULL OR receipt_hash = ?)
   AND (? IS NULL OR observed_at >= ?)
   AND (? IS NULL OR observed_at <= ?)
   AND (? IS NULL OR (
        event_type LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\'
        OR source_component LIKE ? ESCAPE '\\'
   ))";

fn like_pattern(raw: Option<&str>) -> Option<String> {
    raw.map(|value| {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{escaped}%")
    })
}

macro_rules! bind_runtime_filters {
    ($query:expr, $filters:expr, $q:expr) => {{
        let filters = $filters;
        $query
            .bind(filters.event_type)
            .bind(filters.event_type)
            .bind(filters.severity)
            .bind(filters.severity)
            .bind(filters.agent_id)
            .bind(filters.agent_id)
            .bind(filters.run_id)
            .bind(filters.run_id)
            .bind(filters.trace_id)
            .bind(filters.trace_id)
            .bind(filters.source_component)
            .bind(filters.source_component)
            .bind(filters.source_trust)
            .bind(filters.source_trust)
            .bind(filters.decision)
            .bind(filters.decision)
            .bind(filters.action_hash)
            .bind(filters.action_hash)
            .bind(filters.receipt_hash)
            .bind(filters.receipt_hash)
            .bind(filters.from)
            .bind(filters.from)
            .bind(filters.to)
            .bind(filters.to)
            .bind($q)
            .bind($q)
            .bind($q)
            .bind($q)
    }};
}

/// Bounded, tenant-scoped ASE query. The cursor is an opaque offset for this
/// append-only event stream; callers receive it only when another row exists.
pub async fn query_runtime_events(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    cursor: Option<i64>,
    filters: crate::traits::RuntimeEventListFilters<'_>,
) -> Result<(Vec<RuntimeEventRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let offset = cursor.unwrap_or(0).max(0);
    let q = like_pattern(filters.q);
    let sql = format!(
        "SELECT {COLS} FROM runtime_events WHERE tenant_id = ? {FILTER_SQL}
         ORDER BY observed_at DESC, id DESC LIMIT ? OFFSET ?"
    );

    let mut rows = match pool {
        DbPool::Sqlite(pool) => {
            bind_runtime_filters!(
                sqlx::query_as::<_, RuntimeEventRecord>(&sql).bind(tenant_id),
                filters,
                q.as_deref()
            )
            .bind(limit + 1)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(pool) => {
            let sql = crate::db::to_postgres_sql(&sql);
            bind_runtime_filters!(
                sqlx::query_as::<_, RuntimeEventRecord>(&sql).bind(tenant_id),
                filters,
                q.as_deref()
            )
            .bind(limit + 1)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
    };
    let has_more = rows.len() as i64 > limit;
    if has_more {
        rows.truncate(limit as usize);
    }
    Ok((rows, has_more.then_some(offset + limit)))
}

pub async fn count_runtime_events_over_time(
    pool: &DbPool,
    tenant_id: &str,
    bucket: crate::traits::TimeBucket,
    filters: crate::traits::RuntimeEventListFilters<'_>,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    use sqlx::Row;
    let q = like_pattern(filters.q);
    let rows = match pool {
        DbPool::Sqlite(pool) => {
            let sql = format!(
                "SELECT bucket, cnt FROM (
                   SELECT strftime(?, observed_at) AS bucket, COUNT(*) AS cnt
                   FROM runtime_events WHERE tenant_id = ? {FILTER_SQL}
                   GROUP BY bucket ORDER BY bucket DESC LIMIT {MAX_TIME_BUCKETS}
                 ) ORDER BY bucket ASC"
            );
            bind_runtime_filters!(
                sqlx::query(&sql).bind(bucket.sqlite_fmt()).bind(tenant_id),
                filters,
                q.as_deref()
            )
            .fetch_all(pool)
            .await?
            .iter()
            .map(|row| (row.get("bucket"), row.get("cnt")))
            .collect()
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(pool) => {
            let sql = format!(
                "SELECT bucket, cnt FROM (
                   SELECT to_char(date_trunc(?, observed_at), 'YYYY-MM-DD HH24:MI:SS') AS bucket,
                          COUNT(*) AS cnt
                   FROM runtime_events WHERE tenant_id = ? {FILTER_SQL}
                   GROUP BY bucket ORDER BY bucket DESC LIMIT {MAX_TIME_BUCKETS}
                 ) ORDER BY bucket ASC"
            );
            let sql = crate::db::to_postgres_sql(&sql);
            bind_runtime_filters!(
                sqlx::query(&sql).bind(bucket.pg_unit()).bind(tenant_id),
                filters,
                q.as_deref()
            )
            .fetch_all(pool)
            .await?
            .iter()
            .map(|row| (row.get("bucket"), row.get("cnt")))
            .collect()
        }
    };
    Ok(rows)
}

pub async fn count_runtime_events(
    pool: &DbPool,
    tenant_id: &str,
    filters: crate::traits::RuntimeEventListFilters<'_>,
) -> Result<i64, sqlx::Error> {
    use sqlx::Row;
    let q = like_pattern(filters.q);
    let sql =
        format!("SELECT COUNT(*) AS cnt FROM runtime_events WHERE tenant_id = ? {FILTER_SQL}");
    let count = match pool {
        DbPool::Sqlite(pool) => {
            bind_runtime_filters!(sqlx::query(&sql).bind(tenant_id), filters, q.as_deref())
                .fetch_one(pool)
                .await?
                .get("cnt")
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(pool) => {
            let sql = crate::db::to_postgres_sql(&sql);
            bind_runtime_filters!(sqlx::query(&sql).bind(tenant_id), filters, q.as_deref())
                .fetch_one(pool)
                .await?
                .get("cnt")
        }
    };
    Ok(count)
}

pub async fn count_runtime_events_grouped(
    pool: &DbPool,
    tenant_id: &str,
    field: crate::traits::RuntimeEventGroupField,
    filters: crate::traits::RuntimeEventListFilters<'_>,
    limit: i64,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    use sqlx::Row;
    let q = like_pattern(filters.q);
    let limit = limit.clamp(1, 100);
    let sql = format!(
        "SELECT COALESCE(CAST({} AS TEXT), 'unknown') AS group_value, COUNT(*) AS cnt
         FROM runtime_events WHERE tenant_id = ? {FILTER_SQL}
         GROUP BY group_value ORDER BY cnt DESC, group_value ASC LIMIT ?",
        field.sql_column()
    );
    let rows = match pool {
        DbPool::Sqlite(pool) => {
            bind_runtime_filters!(sqlx::query(&sql).bind(tenant_id), filters, q.as_deref())
                .bind(limit)
                .fetch_all(pool)
                .await?
                .iter()
                .map(|row| (row.get("group_value"), row.get("cnt")))
                .collect()
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(pool) => {
            let sql = crate::db::to_postgres_sql(&sql);
            bind_runtime_filters!(sqlx::query(&sql).bind(tenant_id), filters, q.as_deref())
                .bind(limit)
                .fetch_all(pool)
                .await?
                .iter()
                .map(|row| (row.get("group_value"), row.get("cnt")))
                .collect()
        }
    };
    Ok(rows)
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

    #[tokio::test]
    async fn structured_query_filters_and_paginates_runtime_events() {
        let pool = setup_pool("rt_structured_query").await;
        let mut matching = ev("t_a", "r1", "e1", "run-match");
        matching.agent_id = Some("agent-7".to_string());
        matching.severity = Some("high".to_string());
        matching.trace_id = Some("trace-match".to_string());
        matching.receipt_hash = Some("b".repeat(64));
        matching.reason = Some("manifest drift detected".to_string());
        insert_runtime_event(&pool, &matching).await.unwrap();
        insert_runtime_event(&pool, &ev("t_a", "r2", "e2", "run-other"))
            .await
            .unwrap();
        let mut cross_tenant_match = matching.clone();
        cross_tenant_match.id = "r3".to_string();
        cross_tenant_match.tenant_id = "t_b".to_string();
        cross_tenant_match.event_id = "e3".to_string();
        insert_runtime_event(&pool, &cross_tenant_match)
            .await
            .unwrap();

        let filters = crate::traits::RuntimeEventListFilters {
            event_type: Some("tool_call_requested"),
            severity: Some("high"),
            agent_id: Some("agent-7"),
            run_id: Some("run-match"),
            trace_id: Some("trace-match"),
            source_component: Some("node-sensor"),
            source_trust: Some("untrusted_external"),
            decision: Some("require_approval"),
            action_hash: matching.action_hash.as_deref(),
            receipt_hash: matching.receipt_hash.as_deref(),
            q: Some("manifest drift"),
            ..Default::default()
        };
        let (rows, next) = query_runtime_events(&pool, "t_a", 20, None, filters)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "e1");
        assert!(next.is_none());

        let (first_page, cursor) = query_runtime_events(
            &pool,
            "t_a",
            1,
            None,
            crate::traits::RuntimeEventListFilters::default(),
        )
        .await
        .unwrap();
        assert_eq!(first_page.len(), 1);
        let (second_page, next) = query_runtime_events(
            &pool,
            "t_a",
            1,
            cursor,
            crate::traits::RuntimeEventListFilters::default(),
        )
        .await
        .unwrap();
        assert_eq!(second_page.len(), 1);
        assert_ne!(first_page[0].event_id, second_page[0].event_id);
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn runtime_event_aggregates_are_bounded_and_tenant_scoped() {
        let pool = setup_pool("rt_aggregates").await;
        insert_runtime_event(&pool, &ev("t_a", "r1", "e1", "run1"))
            .await
            .unwrap();
        let mut denied = ev("t_a", "r2", "e2", "run2");
        denied.event_type = "egress_denied".to_string();
        denied.decision = Some("deny".to_string());
        insert_runtime_event(&pool, &denied).await.unwrap();
        insert_runtime_event(&pool, &ev("t_b", "r3", "e3", "run3"))
            .await
            .unwrap();

        let groups = count_runtime_events_grouped(
            &pool,
            "t_a",
            crate::traits::RuntimeEventGroupField::EventType,
            crate::traits::RuntimeEventListFilters::default(),
            500,
        )
        .await
        .unwrap();
        assert_eq!(groups.iter().map(|(_, count)| count).sum::<i64>(), 2);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            count_runtime_events(
                &pool,
                "t_a",
                crate::traits::RuntimeEventListFilters::default()
            )
            .await
            .unwrap(),
            2
        );
        assert_eq!(
            count_runtime_events(
                &pool,
                "t_b",
                crate::traits::RuntimeEventListFilters::default()
            )
            .await
            .unwrap(),
            1
        );

        let points = count_runtime_events_over_time(
            &pool,
            "t_a",
            crate::traits::TimeBucket::Hour,
            crate::traits::RuntimeEventListFilters::default(),
        )
        .await
        .unwrap();
        assert_eq!(points.iter().map(|(_, count)| count).sum::<i64>(), 2);
    }
}
