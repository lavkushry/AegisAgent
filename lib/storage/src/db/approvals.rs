use super::{retry_on_busy, SOC_MAX_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

/// Atomically consume an APPROVED approval (single-use). Returns `true` only if
/// THIS call consumed it (one row updated); `false` if it was already consumed,
/// expired, not approved, not found, or (when `claimed_action_hash` is supplied)
/// the claimed hash doesn't match the bound `original_call_hash`. The
/// `consumed_at IS NULL` guard makes concurrent double-consume safe — at most one
/// UPDATE matches.
///
/// #1603: the hash check is folded into this same conditional `UPDATE` rather than
/// performed as a separate step after consuming — a mismatch must not burn the
/// single-use slot, otherwise one wrong-hash call could permanently invalidate a
/// legitimately approved action before the real executor consumes it.
pub async fn consume_approval(
    pool: &DbPool,
    tenant_id: &str,
    approval_id: &str,
    claimed_action_hash: Option<&str>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        let result = crate::execute_query!(
            pool,
            "UPDATE approvals
             SET consumed_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'APPROVED' AND consumed_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?)
               AND (? IS NULL OR original_call_hash = ?)",
            now,
            tenant_id,
            approval_id,
            now,
            claimed_action_hash,
            claimed_action_hash
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// #1603: after a `consume_approval` call fails to consume (returns `false`),
/// this distinguishes "the claimed hash didn't match, but the approval is
/// otherwise still valid and consumable" from every other not-consumable
/// reason (already consumed, expired, never approved). `consumed_at` isn't a
/// field on `ApprovalRecord` (it's an internal single-use marker, not part of
/// the public approval shape), so this is a dedicated existence check rather
/// than reusing `get_approval_by_id`.
pub async fn approval_is_still_consumable(
    pool: &DbPool,
    tenant_id: &str,
    approval_id: &str,
) -> Result<bool, sqlx::Error> {
    let now = Utc::now();
    let count: i64 = crate::fetch_one_scalar!(
        i64,
        pool,
        "SELECT COUNT(*) FROM approvals
         WHERE tenant_id = ? AND id = ? AND status = 'APPROVED' AND consumed_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)",
        tenant_id,
        approval_id,
        now
    )?;
    Ok(count > 0)
}

/// #1298 (Compliance Evidence Pack): tenant-scoped `approvals`, optionally
/// bounded by a `[from, to]` `created_at` window. Includes `approver_user_id`
/// and `decided_at` as-is — human-oversight evidence for SOC 2 / EU AI Act
/// Art. 14.
pub async fn list_approvals_in_range(
    pool: &DbPool,
    tenant_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<Vec<ApprovalRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        ApprovalRecord,
        pool,
        "SELECT * FROM approvals
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

/// Fetch the approval record (if any) created for a given decision. Used by the
/// idempotency replay path (#0072) to reconstruct `ApprovalResponseInfo` for a
/// `require_approval` decision without creating a second approval row.
pub async fn get_approval_by_decision_id(
    pool: &DbPool,
    tenant_id: &str,
    decision_id: &str,
) -> Result<Option<ApprovalRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        ApprovalRecord,
        pool,
        "SELECT * FROM approvals WHERE tenant_id = ? AND decision_id = ?",
        tenant_id,
        decision_id
    )
}

/// #1316: batch-fetch the approval (if any) for each of `decision_ids` in a
/// single indexed query (`idx_approvals_tenant_decision`), instead of one
/// `get_approval_by_decision_id` call per decision — avoids the N+1 pattern
/// when building an evidence-graph subgraph for N decisions. Tenant-scoped.
/// Empty input returns an empty map without querying.
pub async fn list_approvals_by_decision_ids(
    pool: &DbPool,
    tenant_id: &str,
    decision_ids: &[String],
) -> Result<std::collections::HashMap<String, ApprovalRecord>, sqlx::Error> {
    if decision_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let placeholders = decision_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let query =
        format!("SELECT * FROM approvals WHERE tenant_id = ? AND decision_id IN ({placeholders})");

    match pool {
        DbPool::Sqlite(p) => {
            let mut q = sqlx::query_as::<_, ApprovalRecord>(&query).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            Ok(rows
                .into_iter()
                .map(|r| (r.decision_id.clone(), r))
                .collect())
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(&query);
            let mut q = sqlx::query_as::<_, ApprovalRecord>(&pg_sql).bind(tenant_id);
            for id in decision_ids {
                q = q.bind(id);
            }
            let rows = q.fetch_all(p).await?;
            Ok(rows
                .into_iter()
                .map(|r| (r.decision_id.clone(), r))
                .collect())
        }
    }
}

#[tracing::instrument(name = "approval_create", skip_all)]
pub async fn insert_approval(pool: &DbPool, record: &ApprovalRecord) -> Result<(), sqlx::Error> {
    crate::execute_query!(pool, "INSERT INTO approvals (id, tenant_id, decision_id, status, approver_group, approver_user_id, reason, original_skill_call, original_call_hash, edited_skill_call, expires_at, decided_at, callback_url, callback_secret_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", &record.id, &record.tenant_id, &record.decision_id, &record.status, &record.approver_group, &record.approver_user_id, &record.reason, &record.original_skill_call, &record.original_call_hash, &record.edited_skill_call, record.expires_at, record.decided_at, &record.callback_url, &record.callback_secret_hash)?;
    Ok(())
}

pub async fn list_pending_approvals(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ApprovalRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let now = Utc::now();
    crate::fetch_all_as!(ApprovalRecord, pool, "SELECT id, tenant_id, decision_id, status, approver_group, approver_user_id, reason, original_skill_call, original_call_hash, edited_skill_call, expires_at, decided_at, callback_url, callback_secret_hash, created_at
         FROM approvals
         WHERE tenant_id = ?
           AND status = 'created'
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?", tenant_id, now, limit, offset)
}

pub async fn get_approval_by_id(
    pool: &DbPool,
    tenant_id: &str,
    approval_id: &str,
) -> Result<Option<ApprovalRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        ApprovalRecord,
        pool,
        "SELECT * FROM approvals WHERE tenant_id = ? AND id = ?",
        tenant_id,
        approval_id
    )
}

/// Apply an edit to a pending approval (#0130): the edited tool call is
/// re-hashed and that new hash becomes the approval's bound `action_hash`, so
/// any subsequent approve/consume is bound to the edited action, not the
/// original one.
///
/// #1300: the UPDATE is the atomic source of truth for the transition — it
/// only matches a still-`created`, non-expired approval (mirroring
/// `consume_approval`'s pattern), closing the TOCTOU window between a
/// handler's pre-read and this write. Returns `true` only if this call
/// performed the transition (one row updated); `false` if the approval was
/// already decided or has expired.
pub async fn update_approval_edit(
    pool: &DbPool,
    tenant_id: &str,
    approval_id: &str,
    user_id: &str,
    reason: Option<&str>,
    edited_call: &str,
    new_action_hash: &str,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        let result = crate::execute_query!(
            pool,
            "UPDATE approvals
             SET status = 'EDITED', approver_user_id = ?, reason = ?, edited_skill_call = ?,
                 original_call_hash = ?, decided_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'created'
               AND (expires_at IS NULL OR expires_at > ?)",
            user_id,
            reason,
            edited_call,
            new_action_hash,
            now,
            tenant_id,
            approval_id,
            now
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// Atomically transition a pending approval to a decided `status`
/// (`APPROVED`/`REJECTED`).
///
/// #1300: the UPDATE itself is the conditional gate — it only matches a row
/// that is still `status = 'created'` and not past its `expires_at` (mirroring
/// `consume_approval`'s pattern). This closes the TOCTOU race where a
/// handler's pre-read of the approval is stale by the time the write happens
/// (e.g. two concurrent approve/reject callbacks, or a callback arriving just
/// as the approval expires). Returns `true` only if this call performed the
/// transition (one row updated); `false` if the approval was already decided
/// or has expired — callers must treat `false` as a 409, never as success.
pub async fn update_approval_status(
    pool: &DbPool,
    tenant_id: &str,
    approval_id: &str,
    status: &str,
    user_id: &str,
    reason: Option<&str>,
    decided_at: Option<DateTime<Utc>>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        let dec_at = decided_at.unwrap_or(now);
        let result = crate::execute_query!(
            pool,
            "UPDATE approvals
             SET status = ?, approver_user_id = ?, reason = ?, decided_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'created'
               AND (expires_at IS NULL OR expires_at > ?)",
            status,
            user_id,
            reason,
            dec_at,
            tenant_id,
            approval_id,
            now
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// Delete `approvals` rows older than `cutoff` whose status is no longer
/// actionable: already decided (`APPROVED`/`REJECTED`/`EDITED`) or still
/// `created` but past `expires_at` (#0105). Returns the number of rows
/// deleted. This keeps the `approvals` table bounded without removing
/// approvals a reviewer might still need to act on.
pub async fn delete_expired_approvals_older_than(
    pool: &DbPool,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let now = Utc::now();
    let result = crate::execute_query!(
        pool,
        "DELETE FROM approvals
         WHERE created_at < ?
           AND (status != 'created' OR (expires_at IS NOT NULL AND expires_at < ?))",
        cutoff,
        now
    )?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::*;
    use crate::db::*;

    /// #0105: `delete_expired_approvals_older_than` removes approvals that are
    /// either already decided or pending-but-past-`expires_at`, as long as
    /// they were created before the cutoff. A still-pending, unexpired
    /// approval older than the cutoff is preserved (a reviewer might still
    /// act on it).
    #[tokio::test]
    async fn delete_expired_approvals_older_than_removes_stale_rows() {
        let pool = setup_pool("approval_cleanup").await;
        register_tenant(&pool, "tenant_cleanup", "Cleanup Tenant", "developer")
            .await
            .unwrap();
        crate::execute_query!(pool, "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
                 VALUES ('agent_cleanup', 'tenant_cleanup', 'agent_cleanup', 'token_cleanup', 'Cleanup Agent', 'dev', 'low', 'active')")
            .unwrap();

        let make_decision = |id: &str| DecisionRecord {
            id: id.to_string(),
            tenant_id: "tenant_cleanup".to_string(),
            agent_id: "agent_cleanup".to_string(),
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "github".to_string(),
            action: "merge_pull_request".to_string(),
            resource: None,
            input_json: "{}".to_string(),
            decision: "require_approval".to_string(),
            risk_score: Some(75),
            reason: None,
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            composite_risk_score: None,
            root_trust_level: None,
            parent_run_id: None,
            created_at: Utc::now(),
        };

        for id in [
            "dec_old_decided",
            "dec_old_expired",
            "dec_old_pending",
            "dec_new_decided",
        ] {
            insert_decision(&pool, &make_decision(id)).await.unwrap();
        }

        let make_approval =
            |id: &str, decision_id: &str, status: &str, expires_at: Option<DateTime<Utc>>| {
                ApprovalRecord {
                    id: id.to_string(),
                    tenant_id: "tenant_cleanup".to_string(),
                    decision_id: decision_id.to_string(),
                    status: status.to_string(),
                    approver_group: None,
                    approver_user_id: None,
                    reason: None,
                    original_skill_call: "{}".to_string(),
                    original_call_hash: "sha256:deadbeef".to_string(),
                    edited_skill_call: None,
                    expires_at,
                    decided_at: None,
                    callback_url: None,
                    callback_secret_hash: None,
                    created_at: Utc::now(),
                }
            };

        // Old + already decided -> should be deleted.
        insert_approval(
            &pool,
            &make_approval("appr_old_decided", "dec_old_decided", "APPROVED", None),
        )
        .await
        .unwrap();
        // Old + still "created" but past expires_at -> should be deleted.
        insert_approval(
            &pool,
            &make_approval(
                "appr_old_expired",
                "dec_old_expired",
                "created",
                Some(Utc::now() - chrono::Duration::days(1)),
            ),
        )
        .await
        .unwrap();
        // Old + still "created" and not expired -> must be preserved.
        insert_approval(
            &pool,
            &make_approval(
                "appr_old_pending",
                "dec_old_pending",
                "created",
                Some(Utc::now() + chrono::Duration::days(1)),
            ),
        )
        .await
        .unwrap();
        // Recently decided -> must be preserved (not old enough).
        insert_approval(
            &pool,
            &make_approval("appr_new_decided", "dec_new_decided", "APPROVED", None),
        )
        .await
        .unwrap();

        // Backdate everything except appr_new_decided so they fall before the cutoff.
        for id in ["appr_old_decided", "appr_old_expired", "appr_old_pending"] {
            crate::execute_query!(
                pool,
                "UPDATE approvals SET created_at = '2000-01-01T00:00:00Z' WHERE id = ?",
                id
            )
            .unwrap();
        }

        let cutoff = Utc::now() - chrono::Duration::days(30);
        let deleted = delete_expired_approvals_older_than(&pool, cutoff)
            .await
            .unwrap();
        assert_eq!(deleted, 2);

        let remaining: Vec<(String,)> =
            crate::fetch_all_as!(_, pool, "SELECT id FROM approvals ORDER BY id").unwrap();
        let remaining: Vec<String> = remaining.into_iter().map(|(id,)| id).collect();
        assert_eq!(remaining, vec!["appr_new_decided", "appr_old_pending"]);
    }
}
