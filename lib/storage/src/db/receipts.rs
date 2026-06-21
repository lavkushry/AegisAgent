use super::SOC_MAX_LIMIT;
use aegis_api::models::*;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

/// #1298 (Compliance Evidence Pack): tenant-scoped `action_receipts`,
/// optionally bounded by a `[from, to]` `created_at` window. Either bound may
/// be `None` to leave that side of the range open. Parameterized; both bounds
/// are bound twice for the `(? IS NULL OR created_at >= ?)` pattern, matching
/// [`get_all_audit_events`]'s optional-filter style.
pub async fn list_action_receipts_in_range(
    pool: &SqlitePool,
    tenant_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT * FROM action_receipts
         WHERE tenant_id = ?
           AND (? IS NULL OR created_at >= ?)
           AND (? IS NULL OR created_at <= ?)
         ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .bind(from)
    .bind(from)
    .bind(to)
    .bind(to)
    .fetch_all(pool)
    .await
}

/// #1272: the receipt produced for a decision (if any), tenant-scoped. Used
/// to add a `Receipt` node to the `GET /v1/graph/*` evidence subgraph.
pub async fn get_action_receipt_by_decision_id(
    pool: &SqlitePool,
    tenant_id: &str,
    decision_id: &str,
) -> Result<Option<ActionReceiptRecord>, sqlx::Error> {
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at
         FROM action_receipts
         WHERE tenant_id = ? AND decision_id = ?",
    )
    .bind(tenant_id)
    .bind(decision_id)
    .fetch_optional(pool)
    .await
}

/// #1316: batch-fetch the receipt (if any) for each of `decision_ids` in a
/// single indexed query (`idx_action_receipts_tenant_decision`), instead of
/// one `get_action_receipt_by_decision_id` call per decision — avoids the
/// N+1 pattern when building an evidence-graph subgraph for N decisions.
/// Tenant-scoped. Empty input returns an empty map without querying.
pub async fn list_action_receipts_by_decision_ids(
    pool: &SqlitePool,
    tenant_id: &str,
    decision_ids: &[String],
) -> Result<std::collections::HashMap<String, ActionReceiptRecord>, sqlx::Error> {
    if decision_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let placeholders = decision_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at
         FROM action_receipts
         WHERE tenant_id = ? AND decision_id IN ({placeholders})"
    );
    let mut q = sqlx::query_as::<_, ActionReceiptRecord>(&query).bind(tenant_id);
    for id in decision_ids {
        q = q.bind(id);
    }
    let rows = q.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.decision_id.clone().map(|id| (id, r)))
        .collect())
}

/// Every receipt for a tenant, oldest-first (chain order). Unlike
/// `list_action_receipts`, this is unpaginated — used by the receipt chain
/// integrity check (#0107), which must walk the whole chain.
pub async fn list_action_receipts_chain_order(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at
         FROM action_receipts
         WHERE tenant_id = ?
         ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

pub async fn list_action_receipts(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at
         FROM action_receipts
         WHERE tenant_id = ?
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// Cursor-paginated sibling of [`list_action_receipts`] (#1142), used only
/// by the `GET /v1/receipts` HTTP route handler — see
/// `decisions::list_decisions_cursor`'s doc comment for why this is a
/// separate function rather than a change to `list_action_receipts` itself.
pub async fn list_action_receipts_cursor(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
) -> Result<(Vec<ActionReceiptRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let rows = sqlx::query(
        "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at, rowid
         FROM action_receipts
         WHERE tenant_id = ?
           AND (? IS NULL OR rowid < ?)
         ORDER BY rowid DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(cursor)
    .bind(cursor)
    .bind(limit + 1)
    .bind(if cursor.is_some() { 0 } else { offset })
    .fetch_all(pool)
    .await?;
    super::paginate_rows(rows, limit)
}

/// Atomically append a receipt to a tenant's hash chain (T-D hardening).
///
/// Reading the chain head and inserting the new (head-referencing) receipt happen
/// inside a single `BEGIN IMMEDIATE` transaction on one connection, so concurrent
/// appends for the same tenant are serialized at the writer and cannot fork the
/// chain (two receipts sharing one `prev_receipt_hash`). `BEGIN IMMEDIATE` takes the
/// SQLite write lock up front, so the head this txn reads is the head no other writer
/// can append past before it commits.
///
/// `build` receives the current head hash (`""` for genesis) and returns the
/// fully-formed, hashed receipt referencing it; the receipt-hash formula stays in the
/// caller so the hashed body remains byte-parity-locked. All access is tenant-scoped
/// and parameterized. Returns the record actually committed.
pub async fn append_action_receipt_atomic<F>(
    pool: &SqlitePool,
    tenant_id: &str,
    build: F,
) -> Result<ActionReceiptRecord, sqlx::Error>
where
    F: FnOnce(String) -> ActionReceiptRecord,
{
    let mut conn = pool.acquire().await?;

    // IMMEDIATE acquires the write lock now, serializing concurrent appenders so the
    // head read below can't be raced by another insert before this txn commits.
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    // Helper: roll back and surface the original error if any step fails mid-txn,
    // so we never leave a dangling write lock or a half-applied chain link.
    async fn rollback(conn: &mut sqlx::SqliteConnection) {
        let _ = sqlx::query("ROLLBACK").execute(conn).await;
    }

    let head: Option<(String,)> = match sqlx::query_as(
        "SELECT receipt_hash FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(h) => h,
        Err(e) => {
            rollback(&mut conn).await;
            return Err(e);
        }
    };
    let prev = head.map(|(h,)| h).unwrap_or_default();

    let record = build(prev);

    if let Err(e) = sqlx::query(
        "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.decision_id)
    .bind(&record.ts)
    .bind(&record.agent_id)
    .bind(&record.user_id)
    .bind(&record.run_id)
    .bind(&record.trace_id)
    .bind(&record.tool)
    .bind(&record.action)
    .bind(&record.resource)
    .bind(&record.source_trust)
    .bind(&record.decision)
    .bind(&record.approver)
    .bind(&record.action_hash)
    .bind(&record.prev_receipt_hash)
    .bind(&record.receipt_hash)
    .bind(&record.canon_version)
    .bind(&record.signature)
    .bind(&record.signer_public_key)
    .bind(&record.signer_key_id)
    .execute(&mut *conn)
    .await
    {
        rollback(&mut conn).await;
        return Err(e);
    }

    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(record)
}

pub async fn get_action_receipt_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    receipt_id: &str,
) -> Result<Option<ActionReceiptRecord>, sqlx::Error> {
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT * FROM action_receipts WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(receipt_id)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::*;
    use crate::db::*;
    const CANON_VERSION: &str = "aegis-jcs-1";
    use uuid::Uuid;

    fn bare_receipt(tenant_id: &str, prev: String) -> ActionReceiptRecord {
        let mut rec = ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: None,
            ts: Utc::now().to_rfc3339(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            tool: Some("filesystem".to_string()),
            action: Some("read_file".to_string()),
            resource: None,
            source_trust: "trusted_internal_signed".to_string(),
            decision: "allow".to_string(),
            approver: None,
            action_hash: Some("sha256:dead".to_string()),
            prev_receipt_hash: prev,
            receipt_hash: String::new(),
            canon_version: CANON_VERSION.to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
            created_at: Utc::now(),
        };
        rec.receipt_hash = crate::db::receipts::compute_receipt_hash(&rec);
        rec
    }

    /// #1142: regression test for an off-by-one in `paginate_rows` — see
    /// `decisions::list_decisions_cursor_no_false_next_cursor_at_exact_boundary`
    /// for the full rationale. Two receipts exist; requesting `limit=2` must
    /// return both with `next_cursor: None`.
    #[tokio::test]
    async fn list_action_receipts_cursor_no_false_next_cursor_at_exact_boundary() {
        let pool = setup_pool("receipts_cursor_boundary").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        append_action_receipt_atomic(&pool, "tenant_a", |prev| bare_receipt("tenant_a", prev))
            .await
            .unwrap();
        append_action_receipt_atomic(&pool, "tenant_a", |prev| bare_receipt("tenant_a", prev))
            .await
            .unwrap();

        let (page, next_cursor) = list_action_receipts_cursor(&pool, "tenant_a", 2, 0, None)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(
            next_cursor, None,
            "exact-boundary page must not claim more rows exist"
        );
    }
}

pub fn receipt_body_value(rec: &ActionReceiptRecord) -> serde_json::Value {
    serde_json::json!({
        "event_id": rec.id,
        "ts": rec.ts,
        "agent_id": rec.agent_id,
        "user_id": rec.user_id,
        "run_id": rec.run_id,
        "trace_id": rec.trace_id,
        "tool": rec.tool,
        "action": rec.action,
        "resource": rec.resource,
        "source_trust": rec.source_trust,
        "decision": rec.decision,
        "approver": rec.approver,
        "action_hash": rec.action_hash,
        "prev_receipt_hash": rec.prev_receipt_hash,
    })
}

pub fn compute_receipt_hash(rec: &ActionReceiptRecord) -> String {
    let canonical = aegis_canon::canonical_value_string(&receipt_body_value(rec));
    aegis_common::hash::sha256_hex(canonical.as_bytes())
}

pub async fn get_latest_action_receipt(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Option<ActionReceiptRecord>, sqlx::Error> {
    sqlx::query_as::<_, ActionReceiptRecord>(
        "SELECT * FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
}

pub async fn insert_action_receipt(
    pool: &SqlitePool,
    record: &ActionReceiptRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.decision_id)
    .bind(&record.ts)
    .bind(&record.agent_id)
    .bind(&record.user_id)
    .bind(&record.run_id)
    .bind(&record.trace_id)
    .bind(&record.tool)
    .bind(&record.action)
    .bind(&record.resource)
    .bind(&record.source_trust)
    .bind(&record.decision)
    .bind(&record.approver)
    .bind(&record.action_hash)
    .bind(&record.prev_receipt_hash)
    .bind(&record.receipt_hash)
    .bind(&record.canon_version)
    .bind(&record.signature)
    .bind(&record.signer_public_key)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn count_receipts(pool: &SqlitePool, tenant_id: &str) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;
    Ok(count)
}
