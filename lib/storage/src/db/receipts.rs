use super::SOC_MAX_LIMIT;
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

/// #1298 (Compliance Evidence Pack): tenant-scoped `action_receipts`,
/// optionally bounded by a `[from, to]` `created_at` window. Either bound may
/// be `None` to leave that side of the range open. Parameterized; both bounds
/// are bound twice for the `(? IS NULL OR created_at >= ?)` pattern, matching
/// [`get_all_audit_events`]'s optional-filter style.
pub async fn list_action_receipts_in_range(
    pool: &DbPool,
    tenant_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        ActionReceiptRecord,
        pool,
        "SELECT * FROM action_receipts
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

/// #1272: the receipt produced for a decision (if any), tenant-scoped. Used
/// to add a `Receipt` node to the `GET /v1/graph/*` evidence subgraph.
pub async fn get_action_receipt_by_decision_id(
    pool: &DbPool,
    tenant_id: &str,
    decision_id: &str,
) -> Result<Option<ActionReceiptRecord>, sqlx::Error> {
    crate::fetch_optional_as!(ActionReceiptRecord, pool, "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at
         FROM action_receipts
         WHERE tenant_id = ? AND decision_id = ?", tenant_id, decision_id)
}

/// #1316: batch-fetch the receipt (if any) for each of `decision_ids` in a
/// single indexed query (`idx_action_receipts_tenant_decision`), instead of
/// one `get_action_receipt_by_decision_id` call per decision — avoids the
/// N+1 pattern when building an evidence-graph subgraph for N decisions.
/// Tenant-scoped. Empty input returns an empty map without querying.
pub async fn list_action_receipts_by_decision_ids(
    pool: &DbPool,
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
    match pool {
        DbPool::Sqlite(p) => {
            let mut q = sqlx::query_as::<_, ActionReceiptRecord>(&query).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            Ok(rows
                .into_iter()
                .filter_map(|r| r.decision_id.clone().map(|id| (id, r)))
                .collect())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(&query);
            let mut q = sqlx::query_as::<_, ActionReceiptRecord>(&pg_sql).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            Ok(rows
                .into_iter()
                .filter_map(|r| r.decision_id.clone().map(|id| (id, r)))
                .collect())
        }
    }
}

/// Every receipt for a tenant, oldest-first (chain order). Unlike
/// `list_action_receipts`, this is unpaginated — used by the receipt chain
/// integrity check (#0107), which must walk the whole chain.
pub async fn list_action_receipts_chain_order(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    crate::fetch_all_as!(ActionReceiptRecord, pool, "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at
         FROM action_receipts
         WHERE tenant_id = ?
         ORDER BY created_at ASC", tenant_id)
}

pub async fn list_action_receipts(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ActionReceiptRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    crate::fetch_all_as!(ActionReceiptRecord, pool, "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at
         FROM action_receipts
         WHERE tenant_id = ?
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?", tenant_id, limit, offset)
}

/// Cursor-paginated sibling of [`list_action_receipts`] (#1142), used only
/// by the `GET /v1/receipts` HTTP route handler — see
/// `decisions::list_decisions_cursor`'s doc comment for why this is a
/// separate function rather than a change to `list_action_receipts` itself.
pub async fn list_action_receipts_cursor(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    cursor: Option<i64>,
) -> Result<(Vec<ActionReceiptRecord>, Option<i64>), sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let query = "SELECT id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id, created_at, rowid
         FROM action_receipts
         WHERE tenant_id = ?
           AND (? IS NULL OR rowid < ?)
         ORDER BY rowid DESC
         LIMIT ? OFFSET ?";
    match pool {
        DbPool::Sqlite(p) => {
            let rows = sqlx::query(query)
                .bind(tenant_id)
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
    pool: &DbPool,
    tenant_id: &str,
    build: F,
) -> Result<ActionReceiptRecord, sqlx::Error>
where
    F: FnOnce(String) -> ActionReceiptRecord,
{
    match pool {
        DbPool::Sqlite(p) => {
            let mut conn = p.acquire().await?;

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
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;

            let head: Option<(String,)> = sqlx::query_as(
                "SELECT receipt_hash FROM action_receipts WHERE tenant_id = $1 ORDER BY rowid DESC LIMIT 1"
            )
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;

            let prev = head.map(|(h,)| h).unwrap_or_default();

            let record = build(prev);

            sqlx::query(
                "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)"
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
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok(record)
        }
    }
}

/// One pending receipt queued for batched hash-chain append (#904).
#[derive(Clone, Debug)]
pub struct PendingReceiptAppend {
    pub tenant_id: String,
    pub record: ActionReceiptRecord,
}

/// Apply head linkage, `receipt_hash`, and optional Ed25519 signature metadata.
pub fn finalize_receipt_link(
    record: &mut ActionReceiptRecord,
    prev_receipt_hash: String,
) -> String {
    record.prev_receipt_hash = prev_receipt_hash;
    record.receipt_hash = compute_receipt_hash(record);
    if let Some(signer) = aegis_common::hash::global_signer() {
        record.signature = Some(signer.sign_hash(&record.receipt_hash));
        record.signer_public_key = Some(signer.public_key_hex());
        record.signer_key_id = signer.key_id().map(str::to_string);
    }
    record.receipt_hash.clone()
}

fn chain_receipts_from_head(records: &mut [ActionReceiptRecord], head: String) {
    let mut prev = head;
    for record in records.iter_mut() {
        prev = finalize_receipt_link(record, prev);
    }
}

fn group_pending_by_tenant(
    pending: &[PendingReceiptAppend],
) -> Vec<(String, Vec<ActionReceiptRecord>)> {
    use std::collections::HashMap;
    let mut order = Vec::new();
    let mut groups: HashMap<String, Vec<ActionReceiptRecord>> = HashMap::new();
    for item in pending {
        if !groups.contains_key(&item.tenant_id) {
            order.push(item.tenant_id.clone());
        }
        groups
            .entry(item.tenant_id.clone())
            .or_default()
            .push(item.record.clone());
    }
    order
        .into_iter()
        .map(|tenant_id| (tenant_id.clone(), groups.remove(&tenant_id).unwrap()))
        .collect()
}

async fn insert_action_receipt_rows_sqlite(
    conn: &mut sqlx::SqliteConnection,
    records: &[ActionReceiptRecord],
) -> Result<(), sqlx::Error> {
    if records.is_empty() {
        return Ok(());
    }
    let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
        "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id) ",
    );
    qb.push_values(records, |mut b, record| {
        b.push_bind(record.id.clone())
            .push_bind(record.tenant_id.clone())
            .push_bind(record.decision_id.clone())
            .push_bind(record.ts.clone())
            .push_bind(record.agent_id.clone())
            .push_bind(record.user_id.clone())
            .push_bind(record.run_id.clone())
            .push_bind(record.trace_id.clone())
            .push_bind(record.tool.clone())
            .push_bind(record.action.clone())
            .push_bind(record.resource.clone())
            .push_bind(record.source_trust.clone())
            .push_bind(record.decision.clone())
            .push_bind(record.approver.clone())
            .push_bind(record.action_hash.clone())
            .push_bind(record.prev_receipt_hash.clone())
            .push_bind(record.receipt_hash.clone())
            .push_bind(record.canon_version.clone())
            .push_bind(record.signature.clone())
            .push_bind(record.signer_public_key.clone())
            .push_bind(record.signer_key_id.clone());
    });
    qb.build().execute(&mut *conn).await?;
    Ok(())
}

#[cfg(feature = "postgres")]
async fn insert_action_receipt_rows_postgres(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    records: &[ActionReceiptRecord],
) -> Result<(), sqlx::Error> {
    if records.is_empty() {
        return Ok(());
    }
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id) ",
    );
    qb.push_values(records, |mut b, record| {
        b.push_bind(record.id.clone())
            .push_bind(record.tenant_id.clone())
            .push_bind(record.decision_id.clone())
            .push_bind(record.ts.clone())
            .push_bind(record.agent_id.clone())
            .push_bind(record.user_id.clone())
            .push_bind(record.run_id.clone())
            .push_bind(record.trace_id.clone())
            .push_bind(record.tool.clone())
            .push_bind(record.action.clone())
            .push_bind(record.resource.clone())
            .push_bind(record.source_trust.clone())
            .push_bind(record.decision.clone())
            .push_bind(record.approver.clone())
            .push_bind(record.action_hash.clone())
            .push_bind(record.prev_receipt_hash.clone())
            .push_bind(record.receipt_hash.clone())
            .push_bind(record.canon_version.clone())
            .push_bind(record.signature.clone())
            .push_bind(record.signer_public_key.clone())
            .push_bind(record.signer_key_id.clone());
    });
    qb.build().execute(&mut **tx).await?;
    Ok(())
}

/// Atomically append multiple receipts in one transaction (#904).
///
/// Receipts are grouped per `tenant_id` (preserving enqueue order within each
/// tenant), each group is chained from the tenant's current DB head, and all
/// groups are committed under a single `BEGIN IMMEDIATE` writer lock so
/// concurrent single-row appends cannot fork a chain mid-batch.
pub async fn append_action_receipts_batch_atomic(
    pool: &DbPool,
    pending: &[PendingReceiptAppend],
) -> Result<(), sqlx::Error> {
    if pending.is_empty() {
        return Ok(());
    }
    let groups = group_pending_by_tenant(pending);

    match pool {
        DbPool::Sqlite(p) => {
            let mut conn = p.acquire().await?;
            sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

            async fn rollback(conn: &mut sqlx::SqliteConnection) {
                let _ = sqlx::query("ROLLBACK").execute(conn).await;
            }

            for (tenant_id, mut records) in groups {
                let head = sqlx::query_as::<_, (String,)>(
                    "SELECT receipt_hash FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
                )
                .bind(&tenant_id)
                .fetch_optional(&mut *conn)
                .await;
                let head = match head {
                    Ok(h) => h,
                    Err(e) => {
                        rollback(&mut conn).await;
                        return Err(e);
                    }
                };
                let prev = head.map(|(h,)| h).unwrap_or_default();
                chain_receipts_from_head(&mut records, prev);
                if let Err(e) = insert_action_receipt_rows_sqlite(&mut conn, &records).await {
                    rollback(&mut conn).await;
                    return Err(e);
                }
            }

            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let mut tx = p.begin().await?;
            for (tenant_id, mut records) in groups {
                let head: Option<(String,)> = sqlx::query_as(
                    "SELECT receipt_hash FROM action_receipts WHERE tenant_id = $1 ORDER BY rowid DESC LIMIT 1",
                )
                .bind(&tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
                let prev = head.map(|(h,)| h).unwrap_or_default();
                chain_receipts_from_head(&mut records, prev);
                insert_action_receipt_rows_postgres(&mut tx, &records).await?;
            }
            tx.commit().await?;
            Ok(())
        }
    }
}

pub async fn get_action_receipt_by_id(
    pool: &DbPool,
    tenant_id: &str,
    receipt_id: &str,
) -> Result<Option<ActionReceiptRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        ActionReceiptRecord,
        pool,
        "SELECT * FROM action_receipts WHERE tenant_id = ? AND id = ?",
        tenant_id,
        receipt_id
    )
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
    /// #904: batched append preserves per-tenant hash-chain order.
    #[tokio::test]
    async fn append_action_receipts_batch_atomic_chains_multiple_per_tenant() {
        let pool = setup_pool("receipts_batch_chain").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        append_action_receipt_atomic(&pool, "tenant_a", |prev| bare_receipt("tenant_a", prev))
            .await
            .unwrap();

        let pending = vec![
            PendingReceiptAppend {
                tenant_id: "tenant_a".to_string(),
                record: bare_receipt("tenant_a", String::new()),
            },
            PendingReceiptAppend {
                tenant_id: "tenant_a".to_string(),
                record: bare_receipt("tenant_a", String::new()),
            },
        ];
        append_action_receipts_batch_atomic(&pool, &pending)
            .await
            .unwrap();

        let chain = list_action_receipts_chain_order(&pool, "tenant_a")
            .await
            .unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].prev_receipt_hash, "");
        for i in 1..chain.len() {
            assert_eq!(
                chain[i].prev_receipt_hash,
                chain[i - 1].receipt_hash,
                "chain link broken at index {i}"
            );
        }
    }

    /// #904: interleaved tenants in one batch each get an independent chain.
    #[tokio::test]
    async fn append_action_receipts_batch_atomic_interleaved_tenants() {
        let pool = setup_pool("receipts_batch_interleaved").await;
        for (id, name) in [("tenant_a", "Tenant A"), ("tenant_b", "Tenant B")] {
            register_tenant(&pool, id, name, "developer").await.unwrap();
        }

        let pending = vec![
            PendingReceiptAppend {
                tenant_id: "tenant_a".to_string(),
                record: bare_receipt("tenant_a", String::new()),
            },
            PendingReceiptAppend {
                tenant_id: "tenant_b".to_string(),
                record: bare_receipt("tenant_b", String::new()),
            },
            PendingReceiptAppend {
                tenant_id: "tenant_a".to_string(),
                record: bare_receipt("tenant_a", String::new()),
            },
        ];
        append_action_receipts_batch_atomic(&pool, &pending)
            .await
            .unwrap();

        for tenant_id in ["tenant_a", "tenant_b"] {
            let chain = list_action_receipts_chain_order(&pool, tenant_id)
                .await
                .unwrap();
            assert_eq!(chain.len(), if tenant_id == "tenant_a" { 2 } else { 1 });
            assert_eq!(chain[0].prev_receipt_hash, "");
            for i in 1..chain.len() {
                assert_eq!(chain[i].prev_receipt_hash, chain[i - 1].receipt_hash);
            }
        }
    }

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

#[tracing::instrument(name = "receipt_hash", skip_all)]
pub fn compute_receipt_hash(rec: &ActionReceiptRecord) -> String {
    let canonical = aegis_canon::canonical_value_string(&receipt_body_value(rec));
    aegis_common::hash::sha256_hex(canonical.as_bytes())
}

pub async fn get_latest_action_receipt(
    pool: &DbPool,
    tenant_id: &str,
) -> Result<Option<ActionReceiptRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        ActionReceiptRecord,
        pool,
        "SELECT * FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
        tenant_id
    )
}

pub async fn insert_action_receipt(
    pool: &DbPool,
    record: &ActionReceiptRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(pool, "INSERT INTO action_receipts (id, tenant_id, decision_id, ts, agent_id, user_id, run_id, trace_id, tool, action, resource, source_trust, decision, approver, action_hash, prev_receipt_hash, receipt_hash, canon_version, signature, signer_public_key, signer_key_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", &record.id, &record.tenant_id, &record.decision_id, &record.ts, &record.agent_id, &record.user_id, &record.run_id, &record.trace_id, &record.tool, &record.action, &record.resource, &record.source_trust, &record.decision, &record.approver, &record.action_hash, &record.prev_receipt_hash, &record.receipt_hash, &record.canon_version, &record.signature, &record.signer_public_key, &record.signer_key_id)?;
    Ok(())
}

pub async fn count_receipts(pool: &DbPool, tenant_id: &str) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ?",
        tenant_id
    )?;
    Ok(count)
}
