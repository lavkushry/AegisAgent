//! Postgres-backed correlation window persistence (#1210): shares
//! `Correlator`'s sliding windows across gateway replicas so multiple
//! processes pointed at the same Postgres database observe one shared view
//! of a given `(tenant_id, agent_id)` window instead of each replica
//! tracking its own, independent, unsynchronized copy. SQLite
//! (single-instance) mode never calls into this module -- it keeps the
//! original in-process `HashMap`-backed window exactly as before.

#[cfg(feature = "postgres")]
use crate::db::DbPool;

/// Mirrors `aegis_soc::correlate::WindowEntry`'s fields (that type stays
/// private to its own module -- the storage layer only needs to move this
/// data in and out of a table, not interpret it).
#[derive(Debug, Clone)]
pub struct CorrelationWindowEntry {
    pub ts_secs: i64,
    pub event_id: String,
    pub decision: String,
    pub tool: String,
    pub action: String,
    pub exfil_paired: bool,
    pub trust_escalation_paired: bool,
}

/// Atomically load the current window for `(tenant_id, agent_id)`, hand it to
/// `update`, and persist whatever `update` returns as the new window -- all
/// within one transaction serialized by a Postgres advisory lock keyed on
/// this (tenant, agent) pair, so concurrent replicas observing the same
/// agent never race on the same window.
///
/// `update` receives the entries currently on record (may be empty, ordered
/// oldest-first) and returns the new full set (e.g. with the new event
/// appended, stale entries evicted, and any `*_paired` flags flipped by a
/// rule that just fired) plus an arbitrary result `T` for the caller to
/// return upward -- mirroring the signature shape a caller needs to run its
/// own (backend-agnostic) rule evaluation logic against the loaded window
/// without this module knowing anything about correlation rules.
#[cfg(feature = "postgres")]
pub async fn with_window<T, F>(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    update: F,
) -> Result<T, sqlx::Error>
where
    F: FnOnce(Vec<CorrelationWindowEntry>) -> (Vec<CorrelationWindowEntry>, T),
{
    let DbPool::Postgres(pools) = pool else {
        panic!("db::correlate::with_window called on a non-Postgres DbPool");
    };
    let mut tx = pools.write_pool().begin().await?;

    // Serializes concurrent replicas processing the same (tenant, agent)
    // pair; the lock is released automatically when the transaction ends.
    // hashtext() collisions just mean two unrelated agents occasionally
    // serialize against each other -- a performance cost, never a
    // correctness one.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("{tenant_id}\x1f{agent_id}"))
        .execute(&mut *tx)
        .await?;

    let rows: Vec<(i64, String, String, String, String, bool, bool)> = sqlx::query_as(
        "SELECT ts_secs, event_id, decision, tool, action, exfil_paired, trust_escalation_paired
         FROM soc_correlation_windows
         WHERE tenant_id = $1 AND agent_id = $2
         ORDER BY ts_secs ASC",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_all(&mut *tx)
    .await?;

    let current: Vec<CorrelationWindowEntry> = rows
        .into_iter()
        .map(
            |(ts_secs, event_id, decision, tool, action, exfil_paired, trust_escalation_paired)| {
                CorrelationWindowEntry {
                    ts_secs,
                    event_id,
                    decision,
                    tool,
                    action,
                    exfil_paired,
                    trust_escalation_paired,
                }
            },
        )
        .collect();

    let (new_window, result) = update(current);

    // Simplest-correct write-back: rewrite the whole (bounded-size) window
    // rather than diffing for targeted updates/deletes -- window sizes are
    // capped by the same eviction the caller already applied, so this stays
    // cheap and avoids needing to track per-row identity across the closure.
    sqlx::query("DELETE FROM soc_correlation_windows WHERE tenant_id = $1 AND agent_id = $2")
        .bind(tenant_id)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;

    for entry in &new_window {
        sqlx::query(
            "INSERT INTO soc_correlation_windows
             (tenant_id, agent_id, ts_secs, event_id, decision, tool, action, exfil_paired, trust_escalation_paired)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(entry.ts_secs)
        .bind(&entry.event_id)
        .bind(&entry.decision)
        .bind(&entry.tool)
        .bind(&entry.action)
        .bind(entry.exfil_paired)
        .bind(entry.trust_escalation_paired)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(result)
}
