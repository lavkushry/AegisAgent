use super::{SOC_MAX_LIMIT, SOC_WATCH_BATCH_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Row};

/// #1296: count `deny` decisions for `agent_id` since `since` (inclusive).
/// Tenant-scoped, parameterized.
pub async fn count_recent_denials(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    since: chrono::DateTime<chrono::Utc>,
) -> Result<i64, sqlx::Error> {
    // `decisions.created_at` relies on SQLite's own `DEFAULT CURRENT_TIMESTAMP`
    // (space-separated, no fractional seconds, no `Z`/offset suffix) — sqlx's
    // default `DateTime<Utc>` bind instead serializes RFC3339-style with a
    // `T` separator, which sorts incorrectly against the column's format in
    // a plain string comparison. Format explicitly to match (same scheme as
    // `format_audit_created_at`).
    let since_str = since.format("%F %T%.6f").to_string();
    let (count,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM decisions
         WHERE tenant_id = ? AND agent_id = ? AND decision = 'deny' AND created_at >= ?",
        tenant_id,
        agent_id,
        since_str
    )?;
    Ok(count)
}

/// #1296: persist an auto-escalated `risk_tier` for an agent. Tenant-scoped, parameterized.
pub async fn update_agent_risk_tier(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    new_tier: &str,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "UPDATE agents SET risk_tier = ? WHERE id = ? AND tenant_id = ?",
        new_tier,
        agent_id,
        tenant_id
    )?;
    Ok(())
}

/// #1298 (Compliance Evidence Pack): tenant-scoped `soc_incidents`, optionally
/// bounded by a `[from, to]` `opened_at` window (the table has no
/// `created_at` column; `opened_at` is the analogous lifecycle timestamp).
/// `opened_at` is stored as an RFC-3339 `TEXT` column, so the range bounds are
/// passed as RFC-3339 strings for a lexicographic comparison that matches
/// chronological order.
pub async fn list_soc_incidents_in_range(
    pool: &DbPool,
    tenant_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<Vec<SocIncidentRecord>, sqlx::Error> {
    let from = from.map(|d| d.to_rfc3339());
    let to = to.map(|d| d.to_rfc3339());
    crate::fetch_all_as!(SocIncidentRecord, pool, "SELECT id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at
         FROM soc_incidents
         WHERE tenant_id = ?
           AND (? IS NULL OR opened_at >= ?)
           AND (? IS NULL OR opened_at <= ?)
         ORDER BY opened_at ASC", tenant_id, &from, &from, &to, &to)
}

/// TASK-0088 (#934): create or update (upsert by `(tenant_id, rule_key)`) a
/// tenant-managed detection rule. First step toward SOC-003 (#1186).
#[allow(clippy::too_many_arguments)]
pub async fn upsert_detection_rule(
    pool: &DbPool,
    tenant_id: &str,
    rule_key: &str,
    name: &str,
    severity: &str,
    condition: &str,
    summary_template: &str,
    enabled: bool,
) -> Result<DetectionRuleRecord, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    crate::execute_query!(pool, "INSERT INTO detection_rules (id, tenant_id, rule_key, name, severity, condition, summary_template, enabled) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(tenant_id, rule_key) DO UPDATE SET \
           name=excluded.name, severity=excluded.severity, condition=excluded.condition, \
           summary_template=excluded.summary_template, enabled=excluded.enabled", &id, tenant_id, rule_key, name, severity, condition, summary_template, enabled)?;

    crate::fetch_one_as!(
        DetectionRuleRecord,
        pool,
        "SELECT * FROM detection_rules WHERE tenant_id = ? AND rule_key = ?",
        tenant_id,
        rule_key
    )
}

/// TASK-0088 (#934): list detection rules for a tenant, most recent first.
pub async fn list_detection_rules(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<DetectionRuleRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        DetectionRuleRecord,
        pool,
        "SELECT * FROM detection_rules WHERE tenant_id = ? ORDER BY created_at DESC",
        tenant_id
    )
}

/// TASK-0088 (#934): delete a tenant's detection rule. Returns `true` if a
/// row was deleted.
pub async fn delete_detection_rule(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "DELETE FROM detection_rules WHERE tenant_id = ? AND id = ?",
        tenant_id,
        id
    )?;
    Ok(result.rows_affected() > 0)
}

// ── SOC-007 (#1190): behavioral baselining ────────────────────────────────────

/// Increment the action count for `(tenant_id, agent_id, hour_bucket)` and
/// return the new count. `hour_bucket` is an opaque, sortable string (e.g.
/// `"2026-06-10T12"`) — comparisons are purely lexicographic.
pub async fn increment_agent_hourly_count(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    hour_bucket: &str,
) -> Result<i64, sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO agent_hourly_action_counts (tenant_id, agent_id, hour_bucket, action_count)
         VALUES (?, ?, ?, 1)
         ON CONFLICT (tenant_id, agent_id, hour_bucket)
         DO UPDATE SET action_count = action_count + 1",
        tenant_id,
        agent_id,
        hour_bucket
    )?;

    let count: i64 = crate::fetch_one_scalar!(
        _,
        pool,
        "SELECT action_count FROM agent_hourly_action_counts
         WHERE tenant_id = ? AND agent_id = ? AND hour_bucket = ?",
        tenant_id,
        agent_id,
        hour_bucket
    )?;

    Ok(count)
}

/// Action counts for every hour bucket in `[since_bucket, current_bucket)` for
/// `(tenant_id, agent_id)` — the rolling baseline window, excluding the current
/// (still-accumulating) hour. Lexicographic string comparison works because
/// `hour_bucket` is zero-padded `YYYY-MM-DDTHH`.
pub async fn get_recent_hourly_counts(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    since_bucket: &str,
    current_bucket: &str,
) -> Result<Vec<i64>, sqlx::Error> {
    let counts: Vec<(i64,)> = crate::fetch_all_as!(
        _,
        pool,
        "SELECT action_count FROM agent_hourly_action_counts
         WHERE tenant_id = ? AND agent_id = ?
           AND hour_bucket >= ? AND hour_bucket < ?",
        tenant_id,
        agent_id,
        since_bucket,
        current_bucket
    )?;

    Ok(counts.into_iter().map(|(c,)| c).collect())
}

/// Record that `(tenant_id, agent_id)` has been observed calling
/// `(tool_key, action_key)`. Returns `true` if this is the *first* time this
/// agent has used this tool/action (a deterministic novelty signal), `false`
/// if it was already known.
pub async fn record_known_tool_action(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    tool_key: &str,
    action_key: &str,
    occurred_at: &str,
) -> Result<bool, sqlx::Error> {
    let existing: Option<(i64,)> = crate::fetch_optional_as!(
        _,
        pool,
        "SELECT 1 FROM agent_known_tool_actions
         WHERE tenant_id = ? AND agent_id = ? AND tool_key = ? AND action_key = ?",
        tenant_id,
        agent_id,
        tool_key,
        action_key
    )?;

    if existing.is_some() {
        return Ok(false);
    }

    crate::execute_query!(
        pool,
        "INSERT INTO agent_known_tool_actions
            (tenant_id, agent_id, tool_key, action_key, first_seen_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id, agent_id, tool_key, action_key) DO NOTHING",
        tenant_id,
        agent_id,
        tool_key,
        action_key,
        occurred_at
    )?;

    Ok(true)
}

// ── SOC Phase 5: alert + incident persistence ─────────────────────────────────

/// Persist one detection alert. Tenant-scoped, parameterized. Best-effort: the
/// drain task logs errors but never panics on insert failure (design law 3).
/// Stores ids/summary/severity only — never raw payloads (redaction invariant).
pub async fn insert_soc_alert(pool: &DbPool, record: &SocAlertRecord) -> Result<(), sqlx::Error> {
    crate::execute_query!(pool, "INSERT INTO soc_alerts (id, tenant_id, rule, severity, agent_id, source_event_id, summary, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)", &record.id, &record.tenant_id, &record.rule, &record.severity, &record.agent_id, &record.source_event_id, &record.summary, &record.created_at)?;
    Ok(())
}

/// Persist one correlation incident. Tenant-scoped, parameterized.
/// `source_event_ids` is pre-serialised JSON (never concatenated into SQL).
/// New incidents always start with `status='open'` and `closed_at=NULL`; the
/// lifecycle is advanced via [`close_soc_incident`].
pub async fn insert_soc_incident(
    pool: &DbPool,
    record: &SocIncidentRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(pool, "INSERT INTO soc_incidents (id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL)", &record.id, &record.tenant_id, &record.kind, &record.severity, &record.agent_id, &record.summary, &record.source_event_ids, &record.opened_at)?;
    Ok(())
}

/// Outcome of [`upsert_soc_incident`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentUpsertResult {
    /// A new `soc_incidents` row was created.
    Inserted,
    /// `record` was merged into the existing open incident `id` instead of
    /// creating a new row.
    Merged { id: String },
}

/// Default deduplication window for [`upsert_soc_incident`] (#1188, SOC-005):
/// repeat incidents of the same `(tenant_id, agent_id, kind)` within this
/// window are merged into the most recent open incident rather than creating
/// a new row. Configurable via `AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS`.
const DEFAULT_INCIDENT_DEDUP_WINDOW_SECS: i64 = 3600;

/// Insert `record` as a new `soc_incidents` row, unless an **open** incident
/// with the same `(tenant_id, agent_id, kind)` was opened within the
/// deduplication window (#1188, SOC-005) — in which case `record` is merged
/// into that incident: `source_event_ids` is the union of both (de-duplicated,
/// order-preserving), and `summary`/`opened_at` are bumped to `record`'s
/// values (so the row reflects the most recent activity).
///
/// Tenant-scoped and parameterized throughout (CWE-284 / CWE-89).
pub async fn upsert_soc_incident(
    pool: &DbPool,
    record: &SocIncidentRecord,
) -> Result<IncidentUpsertResult, sqlx::Error> {
    let window_secs: i64 = std::env::var("AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v: &i64| v > 0)
        .unwrap_or(DEFAULT_INCIDENT_DEDUP_WINDOW_SECS);
    let cutoff = (Utc::now() - chrono::Duration::seconds(window_secs)).to_rfc3339();

    let existing: Option<(String, String)> = crate::fetch_optional_as!(
        _,
        pool,
        "SELECT id, source_event_ids FROM soc_incidents
         WHERE tenant_id = ? AND agent_id = ? AND kind = ? AND status = 'open' AND opened_at >= ?
         ORDER BY opened_at DESC LIMIT 1",
        &record.tenant_id,
        &record.agent_id,
        &record.kind,
        &cutoff
    )?;

    if let Some((id, existing_ids_json)) = existing {
        let mut merged_ids: Vec<String> =
            serde_json::from_str(&existing_ids_json).unwrap_or_default();
        let new_ids: Vec<String> =
            serde_json::from_str(&record.source_event_ids).unwrap_or_default();
        for new_id in new_ids {
            if !merged_ids.contains(&new_id) {
                merged_ids.push(new_id);
            }
        }
        let merged_json = serde_json::to_string(&merged_ids).unwrap_or_else(|_| "[]".to_string());

        crate::execute_query!(
            pool,
            "UPDATE soc_incidents SET source_event_ids = ?, opened_at = ?, summary = ?
             WHERE id = ? AND tenant_id = ?",
            &merged_json,
            &record.opened_at,
            &record.summary,
            &id,
            &record.tenant_id
        )?;

        return Ok(IncidentUpsertResult::Merged { id });
    }

    insert_soc_incident(pool, record).await?;
    Ok(IncidentUpsertResult::Inserted)
}

/// List alerts for a tenant, newest-first, with pagination and optional equality filters.
/// `limit` is capped at [`SOC_MAX_LIMIT`]; `offset` defaults to 0.
/// `severity` and `agent_id` are optional equality filters.  The SQL string is
/// STATIC — optional filters use the `(? IS NULL OR col = ?)` pattern so no
/// concatenation ever occurs (CWE-89 safe).  Both filter binds are duplicated
/// because SQLite does not support referencing a positional placeholder twice.
/// Every query binds `tenant_id` first — cross-tenant isolation guaranteed (CWE-284).
pub async fn list_soc_alerts(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    severity: Option<&str>,
    agent_id: Option<&str>,
) -> Result<Vec<SocAlertRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    crate::fetch_all_as!(
        SocAlertRecord,
        pool,
        "SELECT id, tenant_id, rule, severity, agent_id, source_event_id, summary, created_at
         FROM soc_alerts
         WHERE tenant_id = ?
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
        tenant_id,
        severity,
        severity,
        agent_id,
        agent_id,
        limit,
        offset
    )
}

/// Cursor-paginated sibling of [`list_soc_alerts`] (#1142), used only by the
/// `GET /v1/alerts` HTTP route handler — see
/// `decisions::list_decisions_cursor`'s doc comment for why this is a
/// separate function rather than a change to `list_soc_alerts` itself.
pub async fn list_soc_alerts_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    severity: Option<&str>,
    agent_id: Option<&str>,
    cursor: Option<i64>,
) -> Result<(Vec<SocAlertRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let query = "SELECT id, tenant_id, rule, severity, agent_id, source_event_id, summary, created_at, rowid
         FROM soc_alerts
         WHERE tenant_id = ?
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
           AND (? IS NULL OR rowid < ?)
         ORDER BY rowid DESC
         LIMIT ? OFFSET ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(cursor)
                .bind(cursor)
                .bind(limit + 1)
                .bind(if cursor.is_some() { 0 } else { offset })
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, limit)
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(query);
            let rows = sqlx::query(&pg_sql)
                .bind(tenant_id)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(cursor)
                .bind(cursor)
                .bind(limit + 1)
                .bind(if cursor.is_some() { 0 } else { offset })
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, limit)
        }
    }
}

/// Batch-fetch alerts whose `source_event_id` is one of `event_ids`
/// (SOC-006, #1189): used by `GET /v1/incidents/:id/evidence-pack` to find
/// the alerts that contributed to an incident — `soc_alerts.source_event_id`
/// and `soc_incidents.source_event_ids` are both populated from the same
/// `AseEvent.event_id`, so a direct `IN (...)` match is exact, not heuristic.
/// Empty `event_ids` short-circuits to an empty result without querying.
pub async fn list_soc_alerts_by_source_event_ids(
    pool: &DbPool,
    tenant_id: &str,
    event_ids: &[String],
) -> Result<Vec<SocAlertRecord>, sqlx::Error> {
    if event_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = event_ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let query = format!(
        "SELECT id, tenant_id, rule, severity, agent_id, source_event_id, summary, created_at
         FROM soc_alerts
         WHERE tenant_id = ? AND source_event_id IN ({placeholders})"
    );
    match pool {
        DbPool::Sqlite(p) => {
            let mut q = sqlx::query_as::<_, SocAlertRecord>(&query).bind(tenant_id);
            for id in event_ids {
                q = q.bind(id);
            }
            q.fetch_all(p).await
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(&query);
            let mut q = sqlx::query_as::<_, SocAlertRecord>(&pg_sql).bind(tenant_id);
            for id in event_ids {
                q = q.bind(id);
            }
            q.fetch_all(p).await
        }
    }
}

/// Highest `rowid` currently in `soc_alerts` for `tenant_id`, or `0` if none.
/// Used by `GET /v1/alerts?watch=true` (#1146) to establish the watch's
/// starting point — only alerts created *after* the watch connects are
/// streamed, matching Kubernetes `?watch=true` semantics (no historical
/// backfill; pair with a normal `GET /v1/alerts` call for that).
pub async fn max_soc_alert_rowid(pool: &DbPool, tenant_id: &str) -> Result<i64, sqlx::Error> {
    let (max_rowid,): (Option<i64>,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT MAX(rowid) FROM soc_alerts WHERE tenant_id = ?",
        tenant_id
    )?;
    Ok(max_rowid.unwrap_or(0))
}

/// Forward-watch sibling of [`list_soc_alerts_cursor`] (#1146): returns alerts
/// with `rowid > since_rowid`, oldest-first, capped at `SOC_WATCH_BATCH_LIMIT`,
/// alongside the highest `rowid` seen in the batch (the caller's next
/// `since_rowid`). Used to poll for new alerts to push over
/// `GET /v1/alerts?watch=true`'s SSE stream.
pub async fn list_soc_alerts_since(
    pool: &DbPool,
    tenant_id: &str,
    since_rowid: i64,
    severity: Option<&str>,
    agent_id: Option<&str>,
) -> Result<Vec<(SocAlertRecord, i64)>, sqlx::Error> {
    let query = "SELECT id, tenant_id, rule, severity, agent_id, source_event_id, summary, created_at, rowid
         FROM soc_alerts
         WHERE tenant_id = ?
           AND rowid > ?
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
         ORDER BY rowid ASC
         LIMIT ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(since_rowid)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(SOC_WATCH_BATCH_LIMIT)
                .fetch_all(p)
                .await?;
            rows.iter()
                .map(|row| {
                    let record = SocAlertRecord::from_row(row)?;
                    let rowid: i64 = row.try_get("rowid")?;
                    Ok((record, rowid))
                })
                .collect()
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(query);
            let rows = sqlx::query(&pg_sql)
                .bind(tenant_id)
                .bind(since_rowid)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(SOC_WATCH_BATCH_LIMIT)
                .fetch_all(p)
                .await?;
            rows.iter()
                .map(|row| {
                    let record = SocAlertRecord::from_row(row)?;
                    let rowid: i64 = row.try_get("rowid")?;
                    Ok((record, rowid))
                })
                .collect()
        }
    }
}

/// List incidents for a tenant, newest-first, with pagination and optional equality filters.
/// `limit` is capped at [`SOC_MAX_LIMIT`]; `offset` defaults to 0.
/// `status_filter` — optional equality filter (`"open"` or `"closed"`; `None` = all).
/// `severity` and `agent_id` — optional equality filters.
/// All optional filters use the `(? IS NULL OR col = ?)` pattern so the SQL string
/// stays STATIC — no concatenation occurs (CWE-89 safe). Every query binds
/// `tenant_id` first — cross-tenant isolation guaranteed (CWE-284).
pub async fn list_soc_incidents(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    status_filter: Option<&str>,
    severity: Option<&str>,
    agent_id: Option<&str>,
) -> Result<Vec<SocIncidentRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    crate::fetch_all_as!(SocIncidentRecord, pool, "SELECT id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at
         FROM soc_incidents
         WHERE tenant_id = ?
           AND (? IS NULL OR status = ?)
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
         ORDER BY opened_at DESC
         LIMIT ? OFFSET ?", tenant_id, status_filter, status_filter, severity, severity, agent_id, agent_id, limit, offset)
}

/// Cursor-paginated sibling of [`list_soc_incidents`] (#1142), used only by
/// the `GET /v1/incidents` HTTP route handler — see
/// `decisions::list_decisions_cursor`'s doc comment for why this is a
/// separate function rather than a change to `list_soc_incidents` itself.
/// Ordering switches from `opened_at DESC` to `rowid DESC` to give cursor
/// seeking a tie-free sort key; in practice the two orderings agree
/// (incidents are opened in insertion order).
#[allow(clippy::too_many_arguments)]
pub async fn list_soc_incidents_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    status_filter: Option<&str>,
    severity: Option<&str>,
    agent_id: Option<&str>,
    kind: Option<&str>,
    cursor: Option<i64>,
) -> Result<(Vec<SocIncidentRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let query = "SELECT id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at, rowid
         FROM soc_incidents
         WHERE tenant_id = ?
           AND (? IS NULL OR status = ?)
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
           AND (? IS NULL OR kind = ?)
           AND (? IS NULL OR rowid < ?)
         ORDER BY rowid DESC
         LIMIT ? OFFSET ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(status_filter)
                .bind(status_filter)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(kind)
                .bind(kind)
                .bind(cursor)
                .bind(cursor)
                .bind(limit + 1)
                .bind(if cursor.is_some() { 0 } else { offset })
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, limit)
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(query);
            let rows = sqlx::query(&pg_sql)
                .bind(tenant_id)
                .bind(status_filter)
                .bind(status_filter)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(kind)
                .bind(kind)
                .bind(cursor)
                .bind(cursor)
                .bind(limit + 1)
                .bind(if cursor.is_some() { 0 } else { offset })
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, limit)
        }
    }
}

/// Highest `rowid` currently in `soc_incidents` for `tenant_id`, or `0` if
/// none. Watch-start counterpart to [`max_soc_alert_rowid`] for
/// `GET /v1/incidents?watch=true` (#1146).
pub async fn max_soc_incident_rowid(pool: &DbPool, tenant_id: &str) -> Result<i64, sqlx::Error> {
    let (max_rowid,): (Option<i64>,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT MAX(rowid) FROM soc_incidents WHERE tenant_id = ?",
        tenant_id
    )?;
    Ok(max_rowid.unwrap_or(0))
}

/// Forward-watch sibling of [`list_soc_incidents_cursor`] (#1146): returns
/// incidents with `rowid > since_rowid`, oldest-first, capped at
/// `SOC_WATCH_BATCH_LIMIT`, alongside the highest `rowid` seen in the batch.
/// Used to poll for new incidents to push over
/// `GET /v1/incidents?watch=true`'s SSE stream.
#[allow(clippy::too_many_arguments)]
pub async fn list_soc_incidents_since(
    pool: &DbPool,
    tenant_id: &str,
    since_rowid: i64,
    status_filter: Option<&str>,
    severity: Option<&str>,
    agent_id: Option<&str>,
    kind: Option<&str>,
) -> Result<Vec<(SocIncidentRecord, i64)>, sqlx::Error> {
    let query = "SELECT id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at, rowid
         FROM soc_incidents
         WHERE tenant_id = ?
           AND rowid > ?
           AND (? IS NULL OR status = ?)
           AND (? IS NULL OR severity = ?)
           AND (? IS NULL OR agent_id = ?)
           AND (? IS NULL OR kind = ?)
         ORDER BY rowid ASC
         LIMIT ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(since_rowid)
                .bind(status_filter)
                .bind(status_filter)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(kind)
                .bind(kind)
                .bind(SOC_WATCH_BATCH_LIMIT)
                .fetch_all(p)
                .await?;
            rows.iter()
                .map(|row| {
                    let record = SocIncidentRecord::from_row(row)?;
                    let rowid: i64 = row.try_get("rowid")?;
                    Ok((record, rowid))
                })
                .collect()
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(query);
            let rows = sqlx::query(&pg_sql)
                .bind(tenant_id)
                .bind(since_rowid)
                .bind(status_filter)
                .bind(status_filter)
                .bind(severity)
                .bind(severity)
                .bind(agent_id)
                .bind(agent_id)
                .bind(kind)
                .bind(kind)
                .bind(SOC_WATCH_BATCH_LIMIT)
                .fetch_all(p)
                .await?;
            rows.iter()
                .map(|row| {
                    let record = SocIncidentRecord::from_row(row)?;
                    let rowid: i64 = row.try_get("rowid")?;
                    Ok((record, rowid))
                })
                .collect()
        }
    }
}

/// Fetch a single SOC incident by id, scoped to the given tenant.
///
/// Returns `Ok(Some(_))` only when both `id` and `tenant_id` match — never
/// leaks another tenant's row.  The two binds are positional and parameterized;
/// no string concatenation occurs (CWE-89 / CWE-284).
pub async fn get_soc_incident(
    pool: &DbPool,
    tenant_id: &str,
    incident_id: &str,
) -> Result<Option<SocIncidentRecord>, sqlx::Error> {
    crate::fetch_optional_as!(SocIncidentRecord, pool, "SELECT id, tenant_id, kind, severity, agent_id, summary, source_event_ids, opened_at, status, closed_at
         FROM soc_incidents
         WHERE tenant_id = ? AND id = ?", tenant_id, incident_id)
}

/// Close a SOC incident — flip its lifecycle status from `'open'` to `'closed'`
/// and stamp `closed_at` with the current RFC-3339 timestamp. Tenant-scoped and
/// parameterized (CWE-89 / CWE-284 safe). The `AND status != 'closed'` guard
/// makes the operation idempotent: a second close returns `false` without touching
/// the row, preserving the original `closed_at` timestamp.
///
/// Returns `true` if a row was updated (i.e. the incident existed, belonged to
/// this tenant, and was still open), `false` otherwise.
pub async fn close_soc_incident(
    pool: &DbPool,
    tenant_id: &str,
    incident_id: &str,
) -> Result<bool, sqlx::Error> {
    let closed_at = Utc::now().to_rfc3339();
    let result = crate::execute_query!(
        pool,
        "UPDATE soc_incidents
         SET status = 'closed', closed_at = ?
         WHERE tenant_id = ? AND id = ? AND status != 'closed'",
        &closed_at,
        tenant_id,
        incident_id
    )?;
    Ok(result.rows_affected() == 1)
}

/// Aggregate SOC counts for a tenant — all in one call for the `/v1/soc/summary`
/// endpoint. Every COUNT query binds `tenant_id` first (CWE-284); all SQL strings
/// are static (CWE-89). `alerts_high` counts only alerts with `severity = 'high'`;
/// `incidents_open` / `incidents_closed` use the lifecycle `status` column.
pub async fn soc_summary(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<aegis_api::models::SocSummary, sqlx::Error> {
    let (alerts_total,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM soc_alerts WHERE tenant_id = ?",
        tenant_id
    )?;

    let (alerts_high,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM soc_alerts WHERE tenant_id = ? AND severity = 'high'",
        tenant_id
    )?;

    let (incidents_total,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM soc_incidents WHERE tenant_id = ?",
        tenant_id
    )?;

    let (incidents_open,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM soc_incidents WHERE tenant_id = ? AND status = 'open'",
        tenant_id
    )?;

    let (incidents_closed,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM soc_incidents WHERE tenant_id = ? AND status = 'closed'",
        tenant_id
    )?;

    Ok(aegis_api::models::SocSummary {
        alerts_total,
        alerts_high,
        incidents_total,
        incidents_open,
        incidents_closed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::*;
    use crate::db::*;

    #[tokio::test]
    async fn soc_alerts_pagination_limit_offset() {
        let pool = setup_pool("soc_alerts_pagination").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        // Insert 5 alerts.
        for i in 0..5u32 {
            insert_soc_alert(&pool, &make_alert(&format!("al_{}", i), "tenant_a"))
                .await
                .unwrap();
        }

        let page1 = list_soc_alerts(&pool, "tenant_a", 3, 0, None, None)
            .await
            .unwrap();
        assert_eq!(page1.len(), 3);
        let page2 = list_soc_alerts(&pool, "tenant_a", 3, 3, None, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);

        // Hard cap: requesting more than SOC_MAX_LIMIT must not exceed it.
        let all = list_soc_alerts(&pool, "tenant_a", SOC_MAX_LIMIT + 10, 0, None, None)
            .await
            .unwrap();
        assert_eq!(all.len(), 5); // only 5 exist
    }

    #[tokio::test]
    async fn soc_incidents_pagination_limit_offset() {
        let pool = setup_pool("soc_incidents_pagination").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        for i in 0..4u32 {
            insert_soc_incident(&pool, &make_incident(&format!("inc_{}", i), "tenant_a"))
                .await
                .unwrap();
        }

        let page1 = list_soc_incidents(&pool, "tenant_a", 2, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(page1.len(), 2);
        let page2 = list_soc_incidents(&pool, "tenant_a", 2, 2, None, None, None)
            .await
            .unwrap();
        assert_eq!(page2.len(), 2);
        let page3 = list_soc_incidents(&pool, "tenant_a", 2, 4, None, None, None)
            .await
            .unwrap();
        assert!(page3.is_empty());
    }

    #[tokio::test]
    async fn soc_alert_source_event_ids_stored_correctly() {
        let pool = setup_pool("soc_alert_fields").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let record = SocAlertRecord {
            id: "alert_fields".to_string(),
            tenant_id: "tenant_a".to_string(),
            rule: "critical_deny".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_z".to_string(),
            source_event_id: "evt_z123".to_string(),
            summary: "Critical deny detected".to_string(),
            created_at: "2026-06-06T12:00:00Z".to_string(),
        };
        insert_soc_alert(&pool, &record).await.unwrap();

        let alerts = list_soc_alerts(&pool, "tenant_a", 10, 0, None, None)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "critical_deny");
        assert_eq!(alerts[0].source_event_id, "evt_z123");
        assert_eq!(alerts[0].severity, "high");
    }

    #[tokio::test]
    async fn soc_incident_source_event_ids_json_round_trip() {
        let pool = setup_pool("soc_incident_json").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let ids = vec!["evt_1", "evt_2", "evt_3"];
        let source_event_ids_json = serde_json::to_string(&ids).unwrap();
        let record = SocIncidentRecord {
            id: "inc_json".to_string(),
            tenant_id: "tenant_a".to_string(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_q".to_string(),
            summary: "Deny storm detected".to_string(),
            source_event_ids: source_event_ids_json.clone(),
            opened_at: "2026-06-06T12:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        insert_soc_incident(&pool, &record).await.unwrap();

        let incs = list_soc_incidents(&pool, "tenant_a", 10, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(incs.len(), 1);
        assert_eq!(incs[0].source_event_ids, source_event_ids_json);
        let parsed: Vec<String> = serde_json::from_str(&incs[0].source_event_ids).unwrap();
        assert_eq!(parsed, ids);
    }

    #[tokio::test]
    async fn get_soc_incident_returns_none_for_unknown_id() {
        let pool = setup_pool("get_incident_missing").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let result = get_soc_incident(&pool, "tenant_a", "nonexistent_id")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    /// `get_soc_incident` round-trips `status` and `closed_at` correctly.
    #[tokio::test]
    async fn get_soc_incident_round_trips_status_and_closed_at() {
        let pool = setup_pool("inc_lifecycle_roundtrip").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let record = make_incident("inc_rt", "tenant_a");
        insert_soc_incident(&pool, &record).await.unwrap();

        let fetched = get_soc_incident(&pool, "tenant_a", "inc_rt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.status, "open");
        assert!(
            fetched.closed_at.is_none(),
            "closed_at must be NULL on open incidents"
        );
    }

    /// A second `close_soc_incident` call on an already-closed incident is
    /// idempotent — it returns `false` and leaves `closed_at` unchanged.
    #[tokio::test]
    async fn close_soc_incident_is_idempotent() {
        let pool = setup_pool("inc_close_idempotent").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_idem", "tenant_a"))
            .await
            .unwrap();

        let first = close_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap();
        assert!(first, "first close must succeed");

        let first_fetch = get_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap()
            .unwrap();
        let first_closed_at = first_fetch.closed_at.clone().unwrap();

        // Second close must return false and not change the timestamp.
        let second = close_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap();
        assert!(!second, "second close must be a no-op");

        let second_fetch = get_soc_incident(&pool, "tenant_a", "inc_idem")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second_fetch.status, "closed");
        assert_eq!(
            second_fetch.closed_at.unwrap(),
            first_closed_at,
            "closed_at must not change on a second close"
        );
    }

    /// `list_soc_incidents` with `status_filter=Some("open")` only returns open
    /// incidents; `Some("closed")` only returns closed ones.
    #[tokio::test]
    async fn list_soc_incidents_status_filter_works() {
        let pool = setup_pool("inc_status_filter").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_open_1", "tenant_a"))
            .await
            .unwrap();
        insert_soc_incident(&pool, &make_incident("inc_open_2", "tenant_a"))
            .await
            .unwrap();
        insert_soc_incident(&pool, &make_incident("inc_closed_1", "tenant_a"))
            .await
            .unwrap();

        // Close one of the three incidents.
        close_soc_incident(&pool, "tenant_a", "inc_closed_1")
            .await
            .unwrap();

        let open_list = list_soc_incidents(&pool, "tenant_a", 50, 0, Some("open"), None, None)
            .await
            .unwrap();
        assert_eq!(open_list.len(), 2, "only two incidents should be open");
        assert!(open_list.iter().all(|i| i.status == "open"));

        let closed_list = list_soc_incidents(&pool, "tenant_a", 50, 0, Some("closed"), None, None)
            .await
            .unwrap();
        assert_eq!(closed_list.len(), 1, "only one incident should be closed");
        assert_eq!(closed_list[0].id, "inc_closed_1");
        assert!(closed_list[0].closed_at.is_some());

        let all_list = list_soc_incidents(&pool, "tenant_a", 50, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(all_list.len(), 3, "unfiltered list must return all three");
    }

    /// `list_soc_alerts` with `severity=Some("high")` returns only high-severity
    /// alerts for the tenant — and never another tenant's rows.
    #[tokio::test]
    async fn list_soc_alerts_severity_filter_and_isolation() {
        let pool = setup_pool("alerts_severity_filter").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        // Tenant A: 2 high, 1 medium.
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a_h1", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a_h2", "tenant_a", "high", "agent_2"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a_m1", "tenant_a", "medium", "agent_1"),
        )
        .await
        .unwrap();
        // Tenant B: 1 high — must never appear in tenant_a results.
        insert_soc_alert(
            &pool,
            &make_alert_with("al_b_h1", "tenant_b", "high", "agent_x"),
        )
        .await
        .unwrap();

        let high_a = list_soc_alerts(&pool, "tenant_a", 50, 0, Some("high"), None)
            .await
            .unwrap();
        assert_eq!(high_a.len(), 2, "tenant_a must see exactly 2 high alerts");
        assert!(high_a.iter().all(|a| a.severity == "high"));
        assert!(
            high_a.iter().all(|a| a.tenant_id == "tenant_a"),
            "isolation: no tenant_b rows"
        );

        let medium_a = list_soc_alerts(&pool, "tenant_a", 50, 0, Some("medium"), None)
            .await
            .unwrap();
        assert_eq!(medium_a.len(), 1);
        assert_eq!(medium_a[0].id, "al_a_m1");

        let all_a = list_soc_alerts(&pool, "tenant_a", 50, 0, None, None)
            .await
            .unwrap();
        assert_eq!(
            all_a.len(),
            3,
            "unfiltered must return all 3 tenant_a alerts"
        );
    }

    /// `soc_summary` returns correct tenant-scoped aggregate counts and excludes
    /// another tenant's data.
    #[tokio::test]
    async fn soc_summary_counts_are_correct_and_isolated() {
        let pool = setup_pool("soc_summary_counts").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        // Tenant A: 3 alerts (2 high, 1 medium); 3 incidents (2 open, 1 closed).
        insert_soc_alert(
            &pool,
            &make_alert_with("sa1", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("sa2", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("sa3", "tenant_a", "medium", "agent_2"),
        )
        .await
        .unwrap();

        insert_soc_incident(
            &pool,
            &make_incident_with("si1", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("si2", "tenant_a", "high", "agent_1"),
        )
        .await
        .unwrap();
        let inc_to_close = make_incident_with("si3", "tenant_a", "low", "agent_2");
        insert_soc_incident(&pool, &inc_to_close).await.unwrap();
        close_soc_incident(&pool, "tenant_a", "si3").await.unwrap();

        // Tenant B: 1 alert, 1 incident — must not affect tenant_a counts.
        insert_soc_alert(
            &pool,
            &make_alert_with("sb1", "tenant_b", "high", "agent_x"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("sib1", "tenant_b", "high", "agent_x"),
        )
        .await
        .unwrap();

        let summary = soc_summary(&pool, "tenant_a").await.unwrap();
        assert_eq!(summary.alerts_total, 3);
        assert_eq!(summary.alerts_high, 2);
        assert_eq!(summary.incidents_total, 3);
        assert_eq!(summary.incidents_open, 2);
        assert_eq!(summary.incidents_closed, 1);

        // Tenant B summary must not be contaminated by tenant_a data.
        let b_summary = soc_summary(&pool, "tenant_b").await.unwrap();
        assert_eq!(b_summary.alerts_total, 1);
        assert_eq!(b_summary.incidents_total, 1);
        assert_eq!(b_summary.incidents_open, 1);
        assert_eq!(b_summary.incidents_closed, 0);
    }

    #[tokio::test]
    async fn upsert_soc_incident_merges_repeat_incident_within_window() {
        let _guard = DEDUP_ENV_LOCK.lock().await;
        std::env::remove_var("AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS");

        let pool = setup_pool("upsert_dedup").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let first = make_incident("inc_first", "tenant_a");
        let result = upsert_soc_incident(&pool, &first).await.unwrap();
        assert_eq!(result, IncidentUpsertResult::Inserted);

        let mut second = make_incident("inc_second", "tenant_a");
        second.source_event_ids = serde_json::json!(["evt_2", "evt_3"]).to_string();
        second.summary = "Updated summary".to_string();
        let result = upsert_soc_incident(&pool, &second).await.unwrap();
        assert_eq!(
            result,
            IncidentUpsertResult::Merged {
                id: "inc_first".to_string()
            }
        );

        let incidents =
            list_soc_incidents(&pool, "tenant_a", SOC_DEFAULT_LIMIT, 0, None, None, None)
                .await
                .unwrap();
        assert_eq!(incidents.len(), 1, "no new row should be created on merge");
        assert_eq!(incidents[0].id, "inc_first");
        assert_eq!(incidents[0].summary, "Updated summary");

        let merged_ids: Vec<String> = serde_json::from_str(&incidents[0].source_event_ids).unwrap();
        assert_eq!(merged_ids, vec!["evt_1", "evt_2", "evt_3"]);
    }

    #[tokio::test]
    async fn upsert_soc_incident_does_not_merge_outside_window() {
        let _guard = DEDUP_ENV_LOCK.lock().await;
        std::env::set_var("AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS", "1");

        let pool = setup_pool("upsert_window").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let first = make_incident("inc_first", "tenant_a");
        assert_eq!(
            upsert_soc_incident(&pool, &first).await.unwrap(),
            IncidentUpsertResult::Inserted
        );

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let second = make_incident("inc_second", "tenant_a");
        assert_eq!(
            upsert_soc_incident(&pool, &second).await.unwrap(),
            IncidentUpsertResult::Inserted
        );

        let incidents =
            list_soc_incidents(&pool, "tenant_a", SOC_DEFAULT_LIMIT, 0, None, None, None)
                .await
                .unwrap();
        assert_eq!(incidents.len(), 2);

        std::env::remove_var("AEGIS_SOC_INCIDENT_DEDUP_WINDOW_SECS");
    }

    /// #1142: regression test for an off-by-one in `paginate_rows` — see
    /// `decisions::list_decisions_cursor_no_false_next_cursor_at_exact_boundary`
    /// for the full rationale. Two alerts exist; requesting `limit=2` must
    /// return both with `next_cursor: None`.
    #[tokio::test]
    async fn list_soc_alerts_cursor_no_false_next_cursor_at_exact_boundary() {
        let pool = setup_pool("alerts_cursor_boundary").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_alert(&pool, &make_alert("al_1", "tenant_a"))
            .await
            .unwrap();
        insert_soc_alert(&pool, &make_alert("al_2", "tenant_a"))
            .await
            .unwrap();

        let (page, next_cursor) = list_soc_alerts_cursor(&pool, "tenant_a", 2, 0, None, None, None)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(
            next_cursor, None,
            "exact-boundary page must not claim more rows exist"
        );
    }

    /// Same off-by-one regression as the alerts test above, for
    /// `list_soc_incidents_cursor`.
    #[tokio::test]
    async fn list_soc_incidents_cursor_no_false_next_cursor_at_exact_boundary() {
        let pool = setup_pool("incidents_cursor_boundary").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_1", "tenant_a"))
            .await
            .unwrap();
        insert_soc_incident(&pool, &make_incident("inc_2", "tenant_a"))
            .await
            .unwrap();

        let (page, next_cursor) =
            list_soc_incidents_cursor(&pool, "tenant_a", 2, 0, None, None, None, None, None)
                .await
                .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(
            next_cursor, None,
            "exact-boundary page must not claim more rows exist"
        );
    }

    /// #1145: `GET /v1/incidents?kind=...` field filtering.
    #[tokio::test]
    async fn list_soc_incidents_cursor_filters_by_kind() {
        let pool = setup_pool("incidents_kind_filter").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_deny_storm", "tenant_a"))
            .await
            .unwrap();
        let mut drift_incident = make_incident("inc_policy_drift", "tenant_a");
        drift_incident.kind = "policy_drift".to_string();
        insert_soc_incident(&pool, &drift_incident).await.unwrap();

        let (page, _) = list_soc_incidents_cursor(
            &pool,
            "tenant_a",
            10,
            0,
            None,
            None,
            None,
            Some("policy_drift"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, "inc_policy_drift");

        let (unfiltered, _) =
            list_soc_incidents_cursor(&pool, "tenant_a", 10, 0, None, None, None, None, None)
                .await
                .unwrap();
        assert_eq!(unfiltered.len(), 2);
    }

    /// #1146: `GET /v1/alerts?watch=true`'s forward-watch query — only alerts
    /// with `rowid > since_rowid` come back, oldest-first.
    #[tokio::test]
    async fn list_soc_alerts_since_returns_only_newer_rows_ascending() {
        let pool = setup_pool("alerts_since").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_alert(&pool, &make_alert("al_1", "tenant_a"))
            .await
            .unwrap();
        let watch_start = max_soc_alert_rowid(&pool, "tenant_a").await.unwrap();
        assert_eq!(watch_start, 1);

        // Nothing new yet.
        let none_yet = list_soc_alerts_since(&pool, "tenant_a", watch_start, None, None)
            .await
            .unwrap();
        assert!(none_yet.is_empty());

        insert_soc_alert(&pool, &make_alert("al_2", "tenant_a"))
            .await
            .unwrap();
        insert_soc_alert(&pool, &make_alert("al_3", "tenant_a"))
            .await
            .unwrap();

        let new_alerts = list_soc_alerts_since(&pool, "tenant_a", watch_start, None, None)
            .await
            .unwrap();
        assert_eq!(new_alerts.len(), 2);
        assert_eq!(new_alerts[0].0.id, "al_2");
        assert_eq!(new_alerts[1].0.id, "al_3");
        assert_eq!(new_alerts[1].1, 3, "second row's rowid should be 3");
    }

    /// #1146: `GET /v1/incidents?watch=true`'s forward-watch query, mirroring
    /// the alerts test above, plus the `kind` filter (#1145).
    #[tokio::test]
    async fn list_soc_incidents_since_returns_only_newer_rows_ascending() {
        let pool = setup_pool("incidents_since").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_soc_incident(&pool, &make_incident("inc_1", "tenant_a"))
            .await
            .unwrap();
        let watch_start = max_soc_incident_rowid(&pool, "tenant_a").await.unwrap();
        assert_eq!(watch_start, 1);

        let mut drift_incident = make_incident("inc_drift", "tenant_a");
        drift_incident.kind = "policy_drift".to_string();
        insert_soc_incident(&pool, &drift_incident).await.unwrap();
        insert_soc_incident(&pool, &make_incident("inc_3", "tenant_a"))
            .await
            .unwrap();

        let new_incidents =
            list_soc_incidents_since(&pool, "tenant_a", watch_start, None, None, None, None)
                .await
                .unwrap();
        assert_eq!(new_incidents.len(), 2);
        assert_eq!(new_incidents[0].0.id, "inc_drift");
        assert_eq!(new_incidents[1].0.id, "inc_3");

        let kind_filtered = list_soc_incidents_since(
            &pool,
            "tenant_a",
            watch_start,
            None,
            None,
            None,
            Some("policy_drift"),
        )
        .await
        .unwrap();
        assert_eq!(kind_filtered.len(), 1);
        assert_eq!(kind_filtered[0].0.id, "inc_drift");
    }

    /// #1189: `list_soc_alerts_by_source_event_ids` matches alerts by exact
    /// `source_event_id` and stays tenant-scoped even when another tenant has
    /// an alert with the same `source_event_id` string.
    #[tokio::test]
    async fn list_soc_alerts_by_source_event_ids_returns_only_matching_tenant_scoped_rows() {
        let pool = setup_pool("alerts_by_source_event_ids").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        let mut alert_1 = make_alert("al_1", "tenant_a");
        alert_1.source_event_id = "evt_1".to_string();
        insert_soc_alert(&pool, &alert_1).await.unwrap();

        let mut alert_2 = make_alert("al_2", "tenant_a");
        alert_2.source_event_id = "evt_2".to_string();
        insert_soc_alert(&pool, &alert_2).await.unwrap();

        // Unrelated event_id for the same tenant — must not be included.
        let mut alert_3 = make_alert("al_3", "tenant_a");
        alert_3.source_event_id = "evt_unrelated".to_string();
        insert_soc_alert(&pool, &alert_3).await.unwrap();

        // Cross-tenant alert sharing one of the requested event_ids — must
        // never leak into tenant_a's result.
        let mut alert_cross = make_alert("al_cross", "tenant_b");
        alert_cross.source_event_id = "evt_1".to_string();
        insert_soc_alert(&pool, &alert_cross).await.unwrap();

        let event_ids = vec!["evt_1".to_string(), "evt_2".to_string()];
        let alerts = list_soc_alerts_by_source_event_ids(&pool, "tenant_a", &event_ids)
            .await
            .unwrap();

        assert_eq!(alerts.len(), 2);
        let ids: Vec<&str> = alerts.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"al_1"));
        assert!(ids.contains(&"al_2"));

        let empty = list_soc_alerts_by_source_event_ids(&pool, "tenant_a", &[])
            .await
            .unwrap();
        assert!(empty.is_empty());
    }
}

pub async fn get_action_count_last_24h(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<i64, sqlx::Error> {
    super::decisions::get_decision_count_24h_for_agent(pool, tenant_id, agent_id).await
}

/// Get agent hourly action counts for the last 7 days.
pub async fn get_agent_hourly_action_counts_7d(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    crate::fetch_all_as!(
        (String, i64),
        pool,
        "SELECT hour_bucket, action_count FROM agent_hourly_action_counts \
         WHERE tenant_id = ? AND agent_id = ? \
           AND hour_bucket >= strftime('%Y-%m-%dT%H', datetime('now', '-7 days')) \
         ORDER BY hour_bucket ASC",
        tenant_id,
        agent_id
    )
}

/// Get agent known tool actions.
pub async fn get_agent_known_tool_actions(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    crate::fetch_all_as!(
        (String, String),
        pool,
        "SELECT tool_key, action_key FROM agent_known_tool_actions \
         WHERE tenant_id = ? AND agent_id = ?",
        tenant_id,
        agent_id
    )
}
