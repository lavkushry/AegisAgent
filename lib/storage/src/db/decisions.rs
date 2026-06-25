use super::SOC_MAX_LIMIT;
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Row};

/// #1298 (Compliance Evidence Pack): tenant-scoped `audit_events`, optionally
/// bounded by a `[from, to]` `created_at` window. Distinct from
/// [`get_all_audit_events`] (which filters by `decision_id` and caps at 100
/// rows) — evidence packs need the full date-bounded set, uncapped.
pub async fn get_audit_events_in_range(
    pool: &DbPool,
    tenant_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        AuditEventRecord,
        pool,
        "SELECT * FROM audit_events
         WHERE tenant_id = ?
           AND (? IS NULL OR created_at >= ?)
           AND (? IS NULL OR created_at <= ?)
         ORDER BY created_at ASC",
        tenant_id,
        from,
        from,
        to,
        to
    )
}

pub async fn insert_decision(pool: &DbPool, record: &DecisionRecord) -> Result<(), sqlx::Error> {
    crate::execute_query!(pool, "INSERT INTO decisions (id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", &record.id, &record.tenant_id, &record.agent_id, &record.user_id, &record.run_id, &record.trace_id, &record.skill, &record.action, &record.resource, &record.input_json, &record.decision, record.risk_score, &record.reason, &record.matched_policy_ids, &record.request_id, record.latency_ms, record.composite_risk_score, &record.root_trust_level, &record.parent_run_id)?;
    Ok(())
}

/// TASK-0089 (#935): record a historical risk-score sample for `agent_id`,
/// linked to the decision that produced it. Called from
/// `routes::write_decision_and_audit` for every `/v1/authorize` decision.
/// Tenant-scoped, parameterized.
pub async fn insert_agent_risk_score(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    decision_id: &str,
    score: i32,
    reason: &str,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO agent_risk_scores (id, tenant_id, agent_id, decision_id, score, reason) \
         VALUES (?, ?, ?, ?, ?, ?)",
        uuid::Uuid::new_v4().to_string(),
        tenant_id,
        agent_id,
        decision_id,
        score,
        reason
    )?;
    Ok(())
}

/// TASK-0089 (#935): list historical risk-score samples for `agent_id`, most
/// recent first. Tenant-scoped, parameterized.
pub async fn list_agent_risk_scores(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Vec<AgentRiskScoreRecord>, sqlx::Error> {
    crate::fetch_all_as!(AgentRiskScoreRecord, pool, "SELECT * FROM agent_risk_scores WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC", tenant_id, agent_id)
}

/// Idempotency lookup (#0072): find a previously-recorded decision for the same
/// `(tenant_id, agent_id, request_id)`. Used by `/v1/authorize` to short-circuit
/// repeat requests instead of re-evaluating Cedar / writing duplicate side
/// effects (audit events, approvals, receipts).
pub async fn get_decision_by_request_id(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    request_id: &str,
) -> Result<Option<DecisionRecord>, sqlx::Error> {
    crate::fetch_optional_as!(DecisionRecord, pool, "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at
         FROM decisions
         WHERE tenant_id = ? AND agent_id = ? AND request_id = ?", tenant_id, agent_id, request_id)
}

pub async fn list_decisions(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    agent_id: Option<&str>,
    decision: Option<&str>,
) -> Result<Vec<DecisionRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    crate::fetch_all_as!(DecisionRecord, pool, "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at
         FROM decisions
         WHERE tenant_id = ?
           AND (? IS NULL OR agent_id = ?)
           AND (? IS NULL OR decision = ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?", tenant_id, agent_id, agent_id, decision, decision, limit, offset)
}

/// Cursor-paginated sibling of [`list_decisions`] (#1142), used only by the
/// `GET /v1/decisions` HTTP route handler — kept separate rather than
/// changing `list_decisions` itself, since that function has ~10 unrelated
/// internal callers elsewhere in the gateway that have no use for a cursor
/// and shouldn't have to thread one through. `cursor`, when `Some`, is the
/// `rowid` of the last item from a previous page (decoded from the opaque
/// `X-Next-Cursor` response header by `routes::decode_cursor`) — rows are
/// seeked via `rowid < cursor` instead of `OFFSET`, and `offset` is ignored
/// when a cursor is supplied. Returns the page plus the next page's cursor
/// (`None` at the end of the result set) — see [`super::paginate_rows`].
///
/// `q` (#1450), when `Some`, is an already-sanitized SQLite FTS5 MATCH
/// expression (built by `routes::sanitize_fts5_query` from the raw `?q=`
/// value) — never raw user input, and only ever bound as a parameter to the
/// static `MATCH ?` clause below (CWE-89 safe). Matches are looked up via
/// the shared `audit_search_index` FTS5 table (migration
/// `0018_fts5_search_index.sql`), scoped to this row's `source_table` and
/// `tenant_id` so a search can never surface another tenant's or another
/// source table's rows.
#[allow(clippy::too_many_arguments)]
pub async fn list_decisions_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
    agent_id: Option<&str>,
    decision: Option<&str>,
    q: Option<&str>,
    source_trust: Option<&str>,
    skill: Option<&str>,
) -> Result<(Vec<DecisionRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let query = "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at, rowid
         FROM decisions
         WHERE tenant_id = ?
           AND (? IS NULL OR agent_id = ?)
           AND (? IS NULL OR decision = ?)
           AND (? IS NULL OR root_trust_level = ?)
           AND (? IS NULL OR skill = ?)
           AND (? IS NULL OR rowid < ?)
           AND (? IS NULL OR id IN (
                 SELECT source_id FROM audit_search_index
                 WHERE searchable_text MATCH ? AND source_table = 'decisions' AND tenant_id = ?
               ))
         ORDER BY rowid DESC
         LIMIT ? OFFSET ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(agent_id)
                .bind(agent_id)
                .bind(decision)
                .bind(decision)
                .bind(source_trust)
                .bind(source_trust)
                .bind(skill)
                .bind(skill)
                .bind(cursor)
                .bind(cursor)
                .bind(q)
                .bind(q)
                .bind(tenant_id)
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
                .bind(agent_id)
                .bind(agent_id)
                .bind(decision)
                .bind(decision)
                .bind(source_trust)
                .bind(source_trust)
                .bind(skill)
                .bind(skill)
                .bind(cursor)
                .bind(cursor)
                .bind(q)
                .bind(q)
                .bind(tenant_id)
                .bind(limit + 1)
                .bind(if cursor.is_some() { 0 } else { offset })
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, limit)
        }
    }
}

/// #1283: cap on decisions scanned per backtest run. Higher than
/// [`SOC_MAX_LIMIT`] (200, tuned for paginated UI listings) because an
/// under-counted backtest would silently understate `estimated_daily_alert_volume`
/// for an active tenant — 50k decisions covers a very high-volume tenant's
/// full default 7-day window without an unbounded query.
pub const BACKTEST_MAX_DECISIONS: i64 = 50_000;

/// #1283: every `deny`/`require_approval`/etc. decision for `tenant_id`
/// within `[from, to]` (inclusive), oldest first — the historical corpus a
/// detection rule is backtested against. Tenant-scoped, parameterized,
/// capped at [`BACKTEST_MAX_DECISIONS`].
///
/// `decisions.created_at` relies on SQLite's own `DEFAULT CURRENT_TIMESTAMP`
/// (space-separated, no fractional seconds) — formats `from`/`to` to match,
/// the same fix established in `count_recent_denials` (#1296). A plain
/// `DateTime<Utc>` bind serializes RFC3339-style with a `T` separator, which
/// sorts incorrectly against the column's format in a string comparison.
pub async fn list_decisions_in_range(
    pool: &DbPool,
    tenant_id: &str,
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<DecisionRecord>, sqlx::Error> {
    let from_str = from.format("%F %T%.6f").to_string();
    let to_str = to.format("%F %T%.6f").to_string();
    crate::fetch_all_as!(DecisionRecord, pool, "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at
         FROM decisions
         WHERE tenant_id = ? AND created_at >= ? AND created_at <= ?
         ORDER BY created_at ASC
         LIMIT ?", tenant_id, from_str, to_str, BACKTEST_MAX_DECISIONS)
}

pub async fn get_decision_by_id(
    pool: &DbPool,
    tenant_id: &str,
    decision_id: &str,
) -> Result<Option<DecisionRecord>, sqlx::Error> {
    crate::fetch_optional_as!(DecisionRecord, pool, "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at
         FROM decisions
         WHERE tenant_id = ? AND id = ?", tenant_id, decision_id)
}

/// #1326: batch-fetch decisions by id, tenant-scoped. Used to enrich a page
/// of pending approvals with their originating decision's `agent_id` in one
/// query, mirroring `list_approvals_by_decision_ids`'s batching to avoid an
/// N+1 query per row.
pub async fn list_decisions_by_ids(
    pool: &DbPool,
    tenant_id: &str,
    decision_ids: &[String],
) -> Result<std::collections::HashMap<String, DecisionRecord>, sqlx::Error> {
    if decision_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let placeholders = decision_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at
         FROM decisions WHERE tenant_id = ? AND id IN ({placeholders})"
    );
    match pool {
        DbPool::Sqlite(p) => {
            let mut q = sqlx::query_as::<_, DecisionRecord>(&query).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            Ok(rows.into_iter().map(|r| (r.id.clone(), r)).collect())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(&query);
            let mut q = sqlx::query_as::<_, DecisionRecord>(&pg_sql).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            Ok(rows.into_iter().map(|r| (r.id.clone(), r)).collect())
        }
    }
}

/// #1272: all decisions for a single agent run, tenant-scoped. Used to build
/// the `GET /v1/graph/run/:run_id` evidence subgraph.
pub async fn list_decisions_by_run_id(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
) -> Result<Vec<DecisionRecord>, sqlx::Error> {
    crate::fetch_all_as!(DecisionRecord, pool, "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at
         FROM decisions
         WHERE tenant_id = ? AND run_id = ?
         ORDER BY created_at ASC
         LIMIT ?", tenant_id, run_id, SOC_MAX_LIMIT)
}

/// #1286: highest `rowid` currently in `decisions` for `tenant_id` — used to
/// seed a forward-watch cursor at "everything from now on" rather than
/// replaying full history. Mirrors [`super::soc::max_soc_alert_rowid`].
pub async fn max_decision_rowid(pool: &DbPool, tenant_id: &str) -> Result<i64, sqlx::Error> {
    let (max_rowid,): (Option<i64>,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT MAX(rowid) FROM decisions WHERE tenant_id = ?",
        tenant_id
    )?;
    Ok(max_rowid.unwrap_or(0))
}

/// #1286: forward-watch sibling of [`list_decisions_cursor`], mirroring
/// [`super::soc::list_soc_alerts_since`]'s shape — returns decisions with
/// `rowid > since_rowid`, oldest-first, capped at `SOC_WATCH_BATCH_LIMIT`,
/// alongside the highest `rowid` seen in the batch (the caller's next
/// `since_rowid`). Used by the Splunk HEC export job to poll for newly
/// authorized decisions to forward.
pub async fn list_decisions_since(
    pool: &DbPool,
    tenant_id: &str,
    since_rowid: i64,
) -> Result<Vec<(DecisionRecord, i64)>, sqlx::Error> {
    let query = "SELECT id, tenant_id, agent_id, user_id, run_id, trace_id, skill, action, resource, input_json, decision, risk_score, reason, matched_policy_ids, request_id, latency_ms, composite_risk_score, root_trust_level, parent_run_id, created_at, rowid
         FROM decisions
         WHERE tenant_id = ?
           AND rowid > ?
         ORDER BY rowid ASC
         LIMIT ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(since_rowid)
                .bind(super::SOC_WATCH_BATCH_LIMIT)
                .fetch_all(p)
                .await?;
            rows.iter()
                .map(|row| {
                    let record = DecisionRecord::from_row(row)?;
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
                .bind(super::SOC_WATCH_BATCH_LIMIT)
                .fetch_all(p)
                .await?;
            rows.iter()
                .map(|row| {
                    let record = DecisionRecord::from_row(row)?;
                    let rowid: i64 = row.try_get("rowid")?;
                    Ok((record, rowid))
                })
                .collect()
        }
    }
}

/// #1272: the `decision_id` an audit event was linked to (#1301), tenant-scoped.
/// Used to walk `soc_incidents.source_event_ids` -> `decisions` for the
/// `GET /v1/graph/incident/:incident_id` evidence subgraph.
pub async fn get_audit_event_decision_id(
    pool: &DbPool,
    tenant_id: &str,
    event_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    crate::fetch_optional_scalar!(
        Option<String>,
        pool,
        "SELECT decision_id FROM audit_events WHERE tenant_id = ? AND id = ?",
        tenant_id,
        event_id
    )
    .map(|opt| opt.flatten())
}

/// Batch-fetch audit events linked to any of `decision_ids` (SOC-006, #1189):
/// used by `GET /v1/incidents/:id/evidence-pack`, mirroring
/// `list_action_receipts_by_decision_ids`'s batching to avoid a per-decision
/// round trip. Unlike receipts (one per decision), an audit event row is not
/// 1:1 with a decision, so this returns a flat `Vec`, not a map. Empty
/// `decision_ids` short-circuits to an empty result without querying.
pub async fn list_audit_events_by_decision_ids(
    pool: &DbPool,
    tenant_id: &str,
    decision_ids: &[String],
) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    if decision_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = decision_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "SELECT * FROM audit_events WHERE tenant_id = ? AND decision_id IN ({placeholders}) ORDER BY created_at ASC, rowid ASC"
    );
    match pool {
        DbPool::Sqlite(p) => {
            let mut q = sqlx::query_as::<_, AuditEventRecord>(&query).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            q.fetch_all(p).await
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(&query);
            let mut q = sqlx::query_as::<_, AuditEventRecord>(&pg_sql).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            q.fetch_all(p).await
        }
    }
}

/// Format an [`AuditEventRecord::created_at`] at microsecond precision
/// (#1303) rather than relying on the column's `DEFAULT CURRENT_TIMESTAMP`
/// (second precision, assigned at insert time). Without this, events emitted
/// within the same wall-clock second sort by insertion order rather than
/// their logical timestamps, putting timeline views out of chronological
/// order. "%F %T%.6f" is SQLite's native datetime format with a
/// fractional-second suffix, so it stays lexicographically sortable and is
/// decoded by sqlx's chrono support. Shared by [`insert_audit_event`] and
/// [`insert_audit_events_batch`] so both paths order identically (#1315).
fn format_audit_created_at(created_at: chrono::DateTime<Utc>) -> String {
    created_at.format("%F %T%.6f").to_string()
}

pub async fn insert_audit_event(
    pool: &DbPool,
    record: &AuditEventRecord,
) -> Result<(), sqlx::Error> {
    let created_at = format_audit_created_at(record.created_at);
    crate::execute_query!(pool, "INSERT INTO audit_events (id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, decision_id, approval_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", &record.id, &record.tenant_id, &record.event_type, &record.agent_id, &record.user_id, &record.run_id, &record.trace_id, &record.span_id, &record.skill, &record.action, &record.resource, &record.event_json, &record.input_hash, &record.output_hash, &record.decision_id, &record.approval_id, created_at)?;
    Ok(())
}

/// Insert a batch of audit events in a single transaction (#1315). A no-op
/// for an empty slice. Used by the audit-event batch writer to amortize
/// per-INSERT overhead for high-volume `/v1/authorize` traffic; produces
/// identical rows (including the microsecond-precision `created_at`) to
/// calling [`insert_audit_event`] once per record.
pub async fn insert_audit_events_batch(
    pool: &DbPool,
    records: &[AuditEventRecord],
) -> Result<(), sqlx::Error> {
    if records.is_empty() {
        return Ok(());
    }

    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;
            let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
                "INSERT INTO audit_events (id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, decision_id, approval_id, created_at) "
            );
            qb.push_values(records, |mut b, record| {
                let created_at = format_audit_created_at(record.created_at);
                b.push_bind(record.id.clone())
                    .push_bind(record.tenant_id.clone())
                    .push_bind(record.event_type.clone())
                    .push_bind(record.agent_id.clone())
                    .push_bind(record.user_id.clone())
                    .push_bind(record.run_id.clone())
                    .push_bind(record.trace_id.clone())
                    .push_bind(record.span_id.clone())
                    .push_bind(record.skill.clone())
                    .push_bind(record.action.clone())
                    .push_bind(record.resource.clone())
                    .push_bind(record.event_json.clone())
                    .push_bind(record.input_hash.clone())
                    .push_bind(record.output_hash.clone())
                    .push_bind(record.decision_id.clone())
                    .push_bind(record.approval_id.clone())
                    .push_bind(created_at);
            });
            qb.build().execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
                "INSERT INTO audit_events (id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, decision_id, approval_id, created_at) "
            );
            qb.push_values(records, |mut b, record| {
                let created_at = format_audit_created_at(record.created_at);
                b.push_bind(record.id.clone())
                    .push_bind(record.tenant_id.clone())
                    .push_bind(record.event_type.clone())
                    .push_bind(record.agent_id.clone())
                    .push_bind(record.user_id.clone())
                    .push_bind(record.run_id.clone())
                    .push_bind(record.trace_id.clone())
                    .push_bind(record.span_id.clone())
                    .push_bind(record.skill.clone())
                    .push_bind(record.action.clone())
                    .push_bind(record.resource.clone())
                    .push_bind(record.event_json.clone())
                    .push_bind(record.input_hash.clone())
                    .push_bind(record.output_hash.clone())
                    .push_bind(record.decision_id.clone())
                    .push_bind(record.approval_id.clone())
                    .push_bind(created_at);
            });
            qb.build().execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(())
        }
    }
}

/// Move `audit_events` rows older than `cutoff` into `audit_events_archive`
/// (#0106), then delete them from the live table. Runs as a single
/// transaction so a row is never lost or duplicated across the two tables.
/// Returns the number of rows archived.
pub async fn archive_audit_events_older_than(
    pool: &DbPool,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    match pool {
        DbPool::Sqlite(p) => {
            let mut tx = p.begin().await?;

            sqlx::query(
                "INSERT INTO audit_events_archive
                    (id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, decision_id, approval_id, created_at)
                 SELECT id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, decision_id, approval_id, created_at
                 FROM audit_events
                 WHERE created_at < ?",
            )
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;

            let result = sqlx::query("DELETE FROM audit_events WHERE created_at < ?")
                .bind(cutoff)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;
            Ok(result.rows_affected())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;

            sqlx::query(
                "INSERT INTO audit_events_archive
                    (id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, decision_id, approval_id, created_at)
                 SELECT id, tenant_id, event_type, agent_id, user_id, run_id, trace_id, span_id, skill, action, resource, event_json, input_hash, output_hash, decision_id, approval_id, created_at
                 FROM audit_events
                 WHERE created_at < $1",
            )
            .bind(cutoff)
            .execute(&mut *tx)
            .await?;

            let result = sqlx::query("DELETE FROM audit_events WHERE created_at < $1")
                .bind(cutoff)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;
            Ok(result.rows_affected())
        }
    }
}

pub async fn get_audit_events_by_run(
    pool: &DbPool,
    tenant_id: &str,
    run_id: &str,
) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    crate::fetch_all_as!(AuditEventRecord, pool, "SELECT * FROM audit_events WHERE tenant_id = ? AND run_id = ? ORDER BY created_at ASC, rowid ASC", tenant_id, run_id)
}

/// List audit events for a tenant, optionally filtered by `decision_id`
/// (#1301), so operators/compliance can correlate every audit event with a
/// specific authorization decision. Always tenant-scoped; the optional
/// filter uses the `(? IS NULL OR col = ?)` static-SQL pattern (CWE-89 safe).
pub async fn get_all_audit_events(
    pool: &DbPool,
    tenant_id: &str,
    decision_id: Option<&str>,
) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
    crate::fetch_all_as!(AuditEventRecord, pool, "SELECT * FROM audit_events WHERE tenant_id = ? AND (? IS NULL OR decision_id = ?) ORDER BY created_at DESC, rowid DESC LIMIT 100", tenant_id, decision_id, decision_id)
}

/// #1142: this endpoint never exposed `limit`/`offset` — it has always
/// returned (up to) the 100 most recent matching events. `LIMIT` stays
/// hardcoded at that same value; `cursor` only adds the ability to page
/// *past* the first 100 via keyset seeking. Cursor-paginated sibling of
/// [`get_all_audit_events`], used only by the `GET /v1/audit/events` HTTP
/// route handler — kept separate for the same reason documented on
/// [`list_decisions_cursor`].
const AUDIT_EVENTS_PAGE_LIMIT: i64 = 100;

/// `q` (#1450): see [`list_decisions_cursor`]'s doc comment — same
/// already-sanitized FTS5 MATCH expression contract, scoped here to
/// `source_table = 'audit_events'`.
pub async fn get_all_audit_events_cursor(
    pool: &DbPool,
    tenant_id: &str,
    decision_id: Option<&str>,
    cursor: Option<i64>,
    q: Option<&str>,
) -> Result<(Vec<AuditEventRecord>, Option<i64>), sqlx::Error> {
    let query = "SELECT *, rowid FROM audit_events
         WHERE tenant_id = ?
           AND (? IS NULL OR decision_id = ?)
           AND (? IS NULL OR rowid < ?)
           AND (? IS NULL OR id IN (
                 SELECT source_id FROM audit_search_index
                 WHERE searchable_text MATCH ? AND source_table = 'audit_events' AND tenant_id = ?
               ))
         ORDER BY rowid DESC
         LIMIT ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
                .bind(decision_id)
                .bind(decision_id)
                .bind(cursor)
                .bind(cursor)
                .bind(q)
                .bind(q)
                .bind(tenant_id)
                .bind(AUDIT_EVENTS_PAGE_LIMIT + 1)
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, AUDIT_EVENTS_PAGE_LIMIT)
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(query);
            let rows = sqlx::query(&pg_sql)
                .bind(tenant_id)
                .bind(decision_id)
                .bind(decision_id)
                .bind(cursor)
                .bind(cursor)
                .bind(q)
                .bind(q)
                .bind(tenant_id)
                .bind(AUDIT_EVENTS_PAGE_LIMIT + 1)
                .fetch_all(p)
                .await?;
            super::paginate_rows(rows, AUDIT_EVENTS_PAGE_LIMIT)
        }
    }
}

/// Calculate the number of decisions recorded for an agent in the last 24 hours.
pub async fn get_decision_count_24h_for_agent(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM decisions \
         WHERE tenant_id = ? AND agent_id = ? \
           AND created_at >= datetime('now', '-24 hours')",
        tenant_id,
        agent_id
    )?;
    Ok(row.0)
}

pub async fn count_decisions_by_outcome(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<(i64, i64, i64, i64), sqlx::Error> {
    let row: (i64, i64, i64, i64) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*),
                COUNT(CASE WHEN decision = 'allow' THEN 1 END),
                COUNT(CASE WHEN decision = 'deny' THEN 1 END),
                COUNT(CASE WHEN decision = 'require_approval' THEN 1 END)
         FROM decisions WHERE tenant_id = ?",
        tenant_id
    )?;

    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::*;
    use crate::db::*;

    /// #0106: rows older than the cutoff are moved to audit_events_archive
    /// and removed from audit_events; recent rows are untouched.
    #[tokio::test]
    async fn archive_audit_events_older_than_moves_old_rows() {
        let pool = setup_pool("audit_archival").await;
        register_tenant(&pool, "tenant_archive", "Archive Tenant", "developer")
            .await
            .unwrap();

        let old_event = AuditEventRecord {
            id: "evt_old".to_string(),
            tenant_id: "tenant_archive".to_string(),
            event_type: "decision".to_string(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: None,
            action: None,
            resource: None,
            event_json: "{}".to_string(),
            input_hash: None,
            output_hash: None,
            decision_id: None,
            approval_id: None,
            created_at: Utc::now(),
        };
        let new_event = AuditEventRecord {
            id: "evt_new".to_string(),
            ..old_event.clone()
        };
        insert_audit_event(&pool, &old_event).await.unwrap();
        insert_audit_event(&pool, &new_event).await.unwrap();

        // Backdate evt_old so it falls before the cutoff.
        crate::execute_query!(
            pool,
            "UPDATE audit_events SET created_at = '2000-01-01T00:00:00Z' WHERE id = 'evt_old'"
        )
        .unwrap();

        let cutoff = Utc::now() - chrono::Duration::days(1);
        let archived = archive_audit_events_older_than(&pool, cutoff)
            .await
            .unwrap();
        assert_eq!(archived, 1);

        let remaining: (i64,) = crate::fetch_one_as!(
            _,
            pool,
            "SELECT COUNT(*) FROM audit_events WHERE id = 'evt_old'"
        )
        .unwrap();
        assert_eq!(remaining.0, 0);

        let archived_row: (i64,) = crate::fetch_one_as!(
            _,
            pool,
            "SELECT COUNT(*) FROM audit_events_archive WHERE id = 'evt_old'"
        )
        .unwrap();
        assert_eq!(archived_row.0, 1);

        let still_present: (i64,) = crate::fetch_one_as!(
            _,
            pool,
            "SELECT COUNT(*) FROM audit_events WHERE id = 'evt_new'"
        )
        .unwrap();
        assert_eq!(still_present.0, 1);
    }

    /// #1189: `list_audit_events_by_decision_ids` batches across multiple
    /// decision_ids, returns every matching row (not 1:1 like receipts), and
    /// stays tenant-scoped.
    #[tokio::test]
    async fn list_audit_events_by_decision_ids_returns_only_matching_tenant_scoped_rows() {
        let pool = setup_pool("audit_events_by_decision_ids").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        let base_event = AuditEventRecord {
            id: "evt_base".to_string(),
            tenant_id: "tenant_a".to_string(),
            event_type: "decision".to_string(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: None,
            action: None,
            resource: None,
            event_json: "{}".to_string(),
            input_hash: None,
            output_hash: None,
            decision_id: Some("dec_1".to_string()),
            approval_id: None,
            created_at: Utc::now(),
        };
        // Two audit events linked to the same decision_id (not 1:1, unlike receipts).
        insert_audit_event(&pool, &base_event).await.unwrap();
        insert_audit_event(
            &pool,
            &AuditEventRecord {
                id: "evt_base_2".to_string(),
                ..base_event.clone()
            },
        )
        .await
        .unwrap();
        insert_audit_event(
            &pool,
            &AuditEventRecord {
                id: "evt_dec2".to_string(),
                decision_id: Some("dec_2".to_string()),
                ..base_event.clone()
            },
        )
        .await
        .unwrap();
        // Unrelated decision_id for the same tenant — must not be included.
        insert_audit_event(
            &pool,
            &AuditEventRecord {
                id: "evt_unrelated".to_string(),
                decision_id: Some("dec_unrelated".to_string()),
                ..base_event.clone()
            },
        )
        .await
        .unwrap();
        // Cross-tenant audit event sharing a requested decision_id — must
        // never leak into tenant_a's result.
        insert_audit_event(
            &pool,
            &AuditEventRecord {
                id: "evt_cross".to_string(),
                tenant_id: "tenant_b".to_string(),
                decision_id: Some("dec_1".to_string()),
                ..base_event.clone()
            },
        )
        .await
        .unwrap();

        let decision_ids = vec!["dec_1".to_string(), "dec_2".to_string()];
        let events = list_audit_events_by_decision_ids(&pool, "tenant_a", &decision_ids)
            .await
            .unwrap();

        assert_eq!(events.len(), 3);
        let ids: Vec<&str> = events.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&"evt_base"));
        assert!(ids.contains(&"evt_base_2"));
        assert!(ids.contains(&"evt_dec2"));

        let empty = list_audit_events_by_decision_ids(&pool, "tenant_a", &[])
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    /// #1315: an empty batch is a no-op (no transaction error).
    #[tokio::test]
    async fn insert_audit_events_batch_empty_is_noop() {
        let pool = setup_pool("audit_batch_empty").await;
        insert_audit_events_batch(&pool, &[]).await.unwrap();
    }

    /// #1315: a batch insert of N records produces the same rows (same
    /// columns, same microsecond-precision `created_at` ordering) as N
    /// sequential `insert_audit_event` calls.
    #[tokio::test]
    async fn insert_audit_events_batch_matches_sequential_inserts() {
        let pool = setup_pool("audit_batch_parity").await;
        register_tenant(&pool, "tenant_batch", "Batch Tenant", "developer")
            .await
            .unwrap();

        let sequential = vec![
            make_audit_event("evt_seq_0", "tenant_batch"),
            make_audit_event("evt_seq_1", "tenant_batch"),
        ];
        for record in &sequential {
            insert_audit_event(&pool, record).await.unwrap();
        }

        let batched = vec![
            make_audit_event("evt_batch_0", "tenant_batch"),
            make_audit_event("evt_batch_1", "tenant_batch"),
            make_audit_event("evt_batch_2", "tenant_batch"),
        ];
        insert_audit_events_batch(&pool, &batched).await.unwrap();

        let all = get_all_audit_events(&pool, "tenant_batch", None)
            .await
            .unwrap();
        assert_eq!(all.len(), sequential.len() + batched.len());
        for record in batched.iter().chain(sequential.iter()) {
            assert!(
                all.iter().any(|row| row.id == record.id
                    && row.tenant_id == record.tenant_id
                    && row.event_type == record.event_type
                    && row.agent_id == record.agent_id
                    && row.action == record.action
                    && row.resource == record.resource
                    && row.event_json == record.event_json),
                "missing or mismatched row for {}",
                record.id
            );
        }
    }

    #[tokio::test]
    async fn list_approvals_by_decision_ids_empty_input_returns_empty_map_without_querying() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        let map = list_approvals_by_decision_ids(&pool, "tenant_graph_perf", &[])
            .await
            .unwrap();
        assert!(map.is_empty());
    }

    #[tokio::test]
    async fn list_action_receipts_by_decision_ids_empty_input_returns_empty_map_without_querying() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        let map = list_action_receipts_by_decision_ids(&pool, "tenant_graph_perf", &[])
            .await
            .unwrap();
        assert!(map.is_empty());
    }

    /// #1142: regression test for an off-by-one in `paginate_rows` — fetching
    /// exactly `limit` rows from a result set that ends precisely there must
    /// NOT emit a `next_cursor`. Two decisions exist; requesting `limit=2`
    /// must return both with `next_cursor: None`, and seeking past them with
    /// `cursor=Some(last_rowid)` must return an empty page (also `None`).
    #[tokio::test]
    async fn list_decisions_cursor_no_false_next_cursor_at_exact_boundary() {
        let pool = setup_pool("decisions_cursor_boundary").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        crate::execute_query!(pool, "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_graph_perf', 'tenant_a', 'agent_graph_perf', 'token_graph_perf', 'Graph Perf Agent', 'dev', 'low', 'active')")
        .unwrap();

        insert_decision(&pool, &graph_perf_decision("dec_1", "tenant_a"))
            .await
            .unwrap();
        insert_decision(&pool, &graph_perf_decision("dec_2", "tenant_a"))
            .await
            .unwrap();

        let (page, next_cursor) =
            list_decisions_cursor(&pool, "tenant_a", 2, 0, None, None, None, None, None, None)
                .await
                .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(
            next_cursor, None,
            "exact-boundary page must not claim more rows exist"
        );

        let oldest_rowid: i64 =
            crate::fetch_one_scalar!(_, pool, "SELECT MIN(rowid) FROM decisions").unwrap();
        let (empty_page, empty_cursor) = list_decisions_cursor(
            &pool,
            "tenant_a",
            2,
            0,
            Some(oldest_rowid),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(empty_page.is_empty());
        assert_eq!(empty_cursor, None);
    }

    /// #1450: `?q=` keyword search via the shared FTS5 `audit_search_index`.
    /// Covers exact-token matching, prefix-matching (the trailing `*` added
    /// by `routes::sanitize_fts5_query`), and strict tenant isolation (the
    /// `tenant_id` filter inside the FTS subquery itself, not just the
    /// outer query's own tenant filter).
    #[tokio::test]
    async fn list_decisions_cursor_q_filters_via_fts5_search_index() {
        let pool = setup_pool("decisions_fts_search").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();
        crate::execute_query!(pool, "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_graph_perf', 'tenant_a', 'agent_graph_perf', 'token_graph_perf', 'Graph Perf Agent', 'dev', 'low', 'active')")
        .unwrap();

        // `graph_perf_decision` defaults to action "merge_pull_request".
        insert_decision(&pool, &graph_perf_decision("dec_merge", "tenant_a"))
            .await
            .unwrap();

        let mut other_decision = graph_perf_decision("dec_other", "tenant_a");
        other_decision.action = "read_file".to_string();
        insert_decision(&pool, &other_decision).await.unwrap();

        // Same searchable action text under a different tenant — must never
        // leak into tenant_a's results.
        insert_decision(&pool, &graph_perf_decision("dec_cross_tenant", "tenant_b"))
            .await
            .unwrap();

        // Exact-token match.
        let (page, _) = list_decisions_cursor(
            &pool,
            "tenant_a",
            50,
            0,
            None,
            None,
            None,
            Some("merge_pull_request*"),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, "dec_merge");

        // Prefix match — exactly what `sanitize_fts5_query` produces for a
        // partial term like `?q=mer`.
        let (prefix_page, _) =
            list_decisions_cursor(&pool, "tenant_a", 50, 0, None, None, None, Some("mer*"), None, None)
                .await
                .unwrap();
        assert_eq!(prefix_page.len(), 1);
        assert_eq!(prefix_page[0].id, "dec_merge");

        // Tenant isolation: tenant_b's matching row must never appear when
        // searching as tenant_a, and vice versa.
        let (tenant_b_page, _) = list_decisions_cursor(
            &pool,
            "tenant_b",
            50,
            0,
            None,
            None,
            None,
            Some("merge_pull_request*"),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(tenant_b_page.len(), 1);
        assert_eq!(tenant_b_page[0].id, "dec_cross_tenant");

        // No match.
        let (no_match, _) = list_decisions_cursor(
            &pool,
            "tenant_a",
            50,
            0,
            None,
            None,
            None,
            Some("zzzznomatch*"),
            None,
            None,
        )
        .await
        .unwrap();
        assert!(no_match.is_empty());
    }

    /// #SOC-query: `source_trust` is an exact, parameterized filter on
    /// `root_trust_level` (the provenance differentiator) and is tenant-scoped.
    #[tokio::test]
    async fn list_decisions_cursor_filters_by_source_trust_and_is_tenant_scoped() {
        let pool = setup_pool("decisions_source_trust").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();
        crate::execute_query!(pool, "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_graph_perf', 'tenant_a', 'agent_graph_perf', 'token_st', 'ST Agent', 'dev', 'low', 'active')")
        .unwrap();

        let mut untrusted = graph_perf_decision("dec_untrusted", "tenant_a");
        untrusted.root_trust_level = Some("untrusted_external".to_string());
        insert_decision(&pool, &untrusted).await.unwrap();

        let mut trusted = graph_perf_decision("dec_trusted", "tenant_a");
        trusted.root_trust_level = Some("trusted_internal_signed".to_string());
        insert_decision(&pool, &trusted).await.unwrap();

        // Same trust level under a different tenant must never leak.
        let mut cross = graph_perf_decision("dec_cross", "tenant_b");
        cross.root_trust_level = Some("untrusted_external".to_string());
        insert_decision(&pool, &cross).await.unwrap();

        let (page, _) = list_decisions_cursor(
            &pool,
            "tenant_a",
            50,
            0,
            None,
            None,
            None,
            None,
            Some("untrusted_external"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, "dec_untrusted");

        // No source_trust filter returns both tenant_a rows.
        let (all, _) =
            list_decisions_cursor(&pool, "tenant_a", 50, 0, None, None, None, None, None, None)
                .await
                .unwrap();
        assert_eq!(all.len(), 2);
    }

    /// #SOC-query: `skill` (the tool / integration name) is an exact,
    /// parameterized filter.
    #[tokio::test]
    async fn list_decisions_cursor_filters_by_skill_tool() {
        let pool = setup_pool("decisions_skill").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        crate::execute_query!(pool, "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_graph_perf', 'tenant_a', 'agent_graph_perf', 'token_sk', 'SK Agent', 'dev', 'low', 'active')")
        .unwrap();

        // graph_perf_decision defaults to skill "github".
        insert_decision(&pool, &graph_perf_decision("dec_github", "tenant_a"))
            .await
            .unwrap();

        let mut slack = graph_perf_decision("dec_slack", "tenant_a");
        slack.skill = "slack".to_string();
        insert_decision(&pool, &slack).await.unwrap();

        let (page, _) = list_decisions_cursor(
            &pool,
            "tenant_a",
            50,
            0,
            None,
            None,
            None,
            None,
            None,
            Some("github"),
        )
        .await
        .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, "dec_github");
    }

    /// Same off-by-one regression as the decisions test above, for
    /// `get_all_audit_events_cursor`.
    #[tokio::test]
    async fn get_all_audit_events_cursor_no_false_next_cursor_at_exact_boundary() {
        let pool = setup_pool("audit_events_cursor_boundary").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        insert_audit_event(&pool, &make_audit_event("evt_1", "tenant_a"))
            .await
            .unwrap();
        insert_audit_event(&pool, &make_audit_event("evt_2", "tenant_a"))
            .await
            .unwrap();

        let (page, next_cursor) = get_all_audit_events_cursor(&pool, "tenant_a", None, None, None)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(
            next_cursor, None,
            "exact-boundary page must not claim more rows exist"
        );
    }

    /// #1450: `?q=` keyword search on `get_all_audit_events_cursor` — same
    /// exact/prefix/tenant-isolation contract as
    /// `list_decisions_cursor_q_filters_via_fts5_search_index`, scoped to
    /// `source_table = 'audit_events'`.
    #[tokio::test]
    async fn get_all_audit_events_cursor_q_filters_via_fts5_search_index() {
        let pool = setup_pool("audit_events_fts_search").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        // `make_audit_event` defaults to action "read" on a "decision" event_type.
        insert_audit_event(&pool, &make_audit_event("evt_match", "tenant_a"))
            .await
            .unwrap();

        let mut other_event = make_audit_event("evt_other", "tenant_a");
        other_event.event_type = "policy_change".to_string();
        other_event.action = Some("delete".to_string());
        insert_audit_event(&pool, &other_event).await.unwrap();

        // Same searchable text under a different tenant — must never leak
        // into tenant_a's results.
        insert_audit_event(&pool, &make_audit_event("evt_cross_tenant", "tenant_b"))
            .await
            .unwrap();

        // Exact-token match.
        let (page, _) = get_all_audit_events_cursor(&pool, "tenant_a", None, None, Some("read*"))
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, "evt_match");

        // Prefix match.
        let (prefix_page, _) =
            get_all_audit_events_cursor(&pool, "tenant_a", None, None, Some("rea*"))
                .await
                .unwrap();
        assert_eq!(prefix_page.len(), 1);
        assert_eq!(prefix_page[0].id, "evt_match");

        // Tenant isolation.
        let (tenant_b_page, _) =
            get_all_audit_events_cursor(&pool, "tenant_b", None, None, Some("read*"))
                .await
                .unwrap();
        assert_eq!(tenant_b_page.len(), 1);
        assert_eq!(tenant_b_page[0].id, "evt_cross_tenant");

        // No match.
        let (no_match, _) =
            get_all_audit_events_cursor(&pool, "tenant_a", None, None, Some("zzzznomatch*"))
                .await
                .unwrap();
        assert!(no_match.is_empty());
    }

    /// #1286: the Splunk HEC export job's forward-watch query — only
    /// decisions with `rowid > since_rowid` come back, oldest-first, and
    /// tenant isolation holds (mirrors
    /// `list_soc_alerts_since_returns_only_newer_rows_ascending`).
    #[tokio::test]
    async fn list_decisions_since_returns_only_newer_rows_ascending_and_is_tenant_scoped() {
        let pool = setup_pool("decisions_since").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();
        crate::execute_query!(pool, "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('agent_graph_perf', 'tenant_a', 'agent_graph_perf', 'token_graph_perf', 'Graph Perf Agent', 'dev', 'low', 'active')")
        .unwrap();

        insert_decision(&pool, &graph_perf_decision("dec_1", "tenant_a"))
            .await
            .unwrap();
        let watch_start = max_decision_rowid(&pool, "tenant_a").await.unwrap();
        assert_eq!(watch_start, 1);

        // Nothing new yet.
        let none_yet = list_decisions_since(&pool, "tenant_a", watch_start)
            .await
            .unwrap();
        assert!(none_yet.is_empty());

        insert_decision(&pool, &graph_perf_decision("dec_2", "tenant_a"))
            .await
            .unwrap();
        insert_decision(&pool, &graph_perf_decision("dec_cross_tenant", "tenant_b"))
            .await
            .unwrap();
        insert_decision(&pool, &graph_perf_decision("dec_3", "tenant_a"))
            .await
            .unwrap();

        let new_decisions = list_decisions_since(&pool, "tenant_a", watch_start)
            .await
            .unwrap();
        assert_eq!(
            new_decisions.len(),
            2,
            "tenant_b's decision must not appear in tenant_a's watch"
        );
        assert_eq!(new_decisions[0].0.id, "dec_2");
        assert_eq!(new_decisions[1].0.id, "dec_3");
        assert!(new_decisions[1].1 > new_decisions[0].1);
    }
}
