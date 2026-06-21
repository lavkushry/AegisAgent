use super::{retry_on_busy, SOC_MAX_LIMIT};
use aegis_api::models::*;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

/// Atomically consume an APPROVED approval (single-use). Returns `true` only if
/// THIS call consumed it (one row updated); `false` if it was already consumed,
/// expired, not approved, or not found. The `consumed_at IS NULL` guard makes
/// concurrent double-consume safe — at most one UPDATE matches.
pub async fn consume_approval(
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE approvals
             SET consumed_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'APPROVED' AND consumed_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(approval_id)
        .bind(now)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// #1298 (Compliance Evidence Pack): tenant-scoped `approvals`, optionally
/// bounded by a `[from, to]` `created_at` window. Includes `approver_user_id`
/// and `decided_at` as-is — human-oversight evidence for SOC 2 / EU AI Act
/// Art. 14.
pub async fn list_approvals_in_range(
    pool: &SqlitePool,
    tenant_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<Vec<ApprovalRecord>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRecord>(
        "SELECT * FROM approvals
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

/// Fetch the approval record (if any) created for a given decision. Used by the
/// idempotency replay path (#0072) to reconstruct `ApprovalResponseInfo` for a
/// `require_approval` decision without creating a second approval row.
pub async fn get_approval_by_decision_id(
    pool: &SqlitePool,
    tenant_id: &str,
    decision_id: &str,
) -> Result<Option<ApprovalRecord>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRecord>(
        "SELECT * FROM approvals WHERE tenant_id = ? AND decision_id = ?",
    )
    .bind(tenant_id)
    .bind(decision_id)
    .fetch_optional(pool)
    .await
}

/// #1316: batch-fetch the approval (if any) for each of `decision_ids` in a
/// single indexed query (`idx_approvals_tenant_decision`), instead of one
/// `get_approval_by_decision_id` call per decision — avoids the N+1 pattern
/// when building an evidence-graph subgraph for N decisions. Tenant-scoped.
/// Empty input returns an empty map without querying.
pub async fn list_approvals_by_decision_ids(
    pool: &SqlitePool,
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
    let mut q = sqlx::query_as::<_, ApprovalRecord>(&query).bind(tenant_id);
    for id in decision_ids {
        q = q.bind(id);
    }
    let rows = q.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.decision_id.clone(), r))
        .collect())
}

pub async fn insert_approval(
    pool: &SqlitePool,
    record: &ApprovalRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO approvals (id, tenant_id, decision_id, status, approver_group, approver_user_id, reason, original_skill_call, original_call_hash, edited_skill_call, expires_at, decided_at, callback_url, callback_secret_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.decision_id)
    .bind(&record.status)
    .bind(&record.approver_group)
    .bind(&record.approver_user_id)
    .bind(&record.reason)
    .bind(&record.original_skill_call)
    .bind(&record.original_call_hash)
    .bind(&record.edited_skill_call)
    .bind(record.expires_at)
    .bind(record.decided_at)
    .bind(&record.callback_url)
    .bind(&record.callback_secret_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_pending_approvals(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ApprovalRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let now = Utc::now();
    sqlx::query_as::<_, ApprovalRecord>(
        "SELECT id, tenant_id, decision_id, status, approver_group, approver_user_id, reason, original_skill_call, original_call_hash, edited_skill_call, expires_at, decided_at, callback_url, callback_secret_hash, created_at
         FROM approvals
         WHERE tenant_id = ?
           AND status = 'created'
           AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(now)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn get_approval_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
) -> Result<Option<ApprovalRecord>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRecord>("SELECT * FROM approvals WHERE tenant_id = ? AND id = ?")
        .bind(tenant_id)
        .bind(approval_id)
        .fetch_optional(pool)
        .await
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
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
    user_id: &str,
    reason: Option<&str>,
    edited_call: &str,
    new_action_hash: &str,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE approvals
             SET status = 'EDITED', approver_user_id = ?, reason = ?, edited_skill_call = ?,
                 original_call_hash = ?, decided_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'created'
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(user_id)
        .bind(reason)
        .bind(edited_call)
        .bind(new_action_hash)
        .bind(now)
        .bind(tenant_id)
        .bind(approval_id)
        .bind(now)
        .execute(pool)
        .await?;
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
    pool: &SqlitePool,
    tenant_id: &str,
    approval_id: &str,
    status: &str,
    user_id: &str,
    reason: Option<&str>,
    edited_call: Option<&str>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE approvals
             SET status = ?, approver_user_id = ?, reason = ?, edited_skill_call = ?, decided_at = ?
             WHERE tenant_id = ? AND id = ? AND status = 'created'
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(status)
        .bind(user_id)
        .bind(reason)
        .bind(edited_call)
        .bind(now)
        .bind(tenant_id)
        .bind(approval_id)
        .bind(now)
        .execute(pool)
        .await?;
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
    pool: &SqlitePool,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let now = Utc::now();
    let result = sqlx::query(
        "DELETE FROM approvals
         WHERE created_at < ?
           AND (status != 'created' OR (expires_at IS NOT NULL AND expires_at < ?))",
    )
    .bind(cutoff)
    .bind(now)
    .execute(pool)
    .await?;
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
        sqlx::query(
                "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
                 VALUES ('agent_cleanup', 'tenant_cleanup', 'agent_cleanup', 'token_cleanup', 'Cleanup Agent', 'dev', 'low', 'active')",
            )
            .execute(&pool)
            .await
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
            sqlx::query("UPDATE approvals SET created_at = '2000-01-01T00:00:00Z' WHERE id = ?")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }

        let cutoff = Utc::now() - chrono::Duration::days(30);
        let deleted = delete_expired_approvals_older_than(&pool, cutoff)
            .await
            .unwrap();
        assert_eq!(deleted, 2);

        let remaining: Vec<String> = sqlx::query_scalar("SELECT id FROM approvals ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, vec!["appr_new_decided", "appr_old_pending"]);
    }
}
