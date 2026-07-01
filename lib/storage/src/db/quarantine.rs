//! Phase 2.5 (runtime control plane): `quarantine_records` CRUD + the
//! `is_quarantined` enforcement lookup.
//!
//! Quarantine preserves evidence while freezing a target for review. All
//! queries are tenant-scoped and parameterized. Storage-only (quarantine/release
//! routes and receipts land in a later phase).

use super::{retry_on_busy, SOC_MAX_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

const COLS: &str = "id, tenant_id, target_type, target_value, reason, actor, status, \
     incident_id, created_at, released_at, released_by";

/// Record a new quarantine.
pub async fn insert_quarantine(pool: &DbPool, q: &QuarantineRecord) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO quarantine_records
           (id, tenant_id, target_type, target_value, reason, actor, status,
            incident_id, created_at, released_at, released_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &q.id,
        &q.tenant_id,
        &q.target_type,
        &q.target_value,
        &q.reason,
        &q.actor,
        &q.status,
        &q.incident_id,
        q.created_at,
        q.released_at,
        &q.released_by
    )?;
    Ok(())
}

/// Enforcement lookup: is `(target_type, target_value)` under an active
/// quarantine for this tenant? Tenant-scoped, parameterized.
pub async fn is_quarantined(
    pool: &DbPool,
    tenant_id: &str,
    target_type: &str,
    target_value: &str,
) -> Result<bool, sqlx::Error> {
    let count: i64 = crate::fetch_one_scalar!(
        i64,
        pool,
        "SELECT COUNT(*) FROM quarantine_records
         WHERE tenant_id = ? AND target_type = ? AND target_value = ? AND status = 'active'",
        tenant_id,
        target_type,
        target_value
    )?;
    Ok(count > 0)
}

/// Fetch a quarantine by id, tenant-scoped (cross-tenant lookups return `None`).
pub async fn get_quarantine(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<QuarantineRecord>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM quarantine_records WHERE tenant_id = ? AND id = ?");
    crate::fetch_optional_as!(QuarantineRecord, pool, sql.as_str(), tenant_id, id)
}

/// Release (or delete) an active quarantine after review — `status` becomes
/// `released` or `deleted`, stamping released_at/released_by. Tenant-scoped;
/// returns `true` only if an active record transitioned.
pub async fn release_quarantine(
    pool: &DbPool,
    tenant_id: &str,
    id: &str,
    status: &str,
    released_by: &str,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE quarantine_records
             SET status = ?, released_at = ?, released_by = ?
             WHERE tenant_id = ? AND id = ? AND status = 'active'",
            status,
            now,
            released_by,
            tenant_id,
            id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// List a tenant's quarantine records, newest-first. `limit` is clamped.
pub async fn list_quarantine(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<QuarantineRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {COLS} FROM quarantine_records WHERE tenant_id = ?
         ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
    );
    crate::fetch_all_as!(
        QuarantineRecord,
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

    fn q(tenant: &str, id: &str, ttype: &str, tvalue: &str) -> QuarantineRecord {
        QuarantineRecord {
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            target_type: ttype.to_string(),
            target_value: tvalue.to_string(),
            reason: Some("secret exfil detected".to_string()),
            actor: "soc-analyst".to_string(),
            status: "active".to_string(),
            incident_id: Some("inc-1".to_string()),
            created_at: Utc::now(),
            released_at: None,
            released_by: None,
        }
    }

    #[tokio::test]
    async fn is_quarantined_matches_exact_active_target_and_is_tenant_scoped() {
        let pool = setup_pool("q_match").await;
        insert_quarantine(&pool, &q("t_a", "q1", "workspace", "ws-1"))
            .await
            .unwrap();
        assert!(is_quarantined(&pool, "t_a", "workspace", "ws-1")
            .await
            .unwrap());
        assert!(!is_quarantined(&pool, "t_a", "workspace", "ws-2")
            .await
            .unwrap());
        assert!(!is_quarantined(&pool, "t_a", "file", "ws-1").await.unwrap());
        assert!(!is_quarantined(&pool, "t_b", "workspace", "ws-1")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn release_deactivates_and_is_tenant_scoped() {
        let pool = setup_pool("q_release").await;
        insert_quarantine(&pool, &q("t_a", "q1", "agent", "a1"))
            .await
            .unwrap();
        let now = Utc::now();
        // Cross-tenant release matches nothing.
        assert!(
            !release_quarantine(&pool, "t_b", "q1", "released", "admin", now)
                .await
                .unwrap()
        );
        assert!(
            release_quarantine(&pool, "t_a", "q1", "released", "admin", now)
                .await
                .unwrap()
        );
        assert!(!is_quarantined(&pool, "t_a", "agent", "a1").await.unwrap());
        let got = get_quarantine(&pool, "t_a", "q1").await.unwrap().unwrap();
        assert_eq!(got.status, "released");
        assert_eq!(got.released_by.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn get_and_list_are_tenant_scoped() {
        let pool = setup_pool("q_list").await;
        insert_quarantine(&pool, &q("t_a", "q1", "agent", "a1"))
            .await
            .unwrap();
        insert_quarantine(&pool, &q("t_a", "q2", "file", "/etc/x"))
            .await
            .unwrap();
        insert_quarantine(&pool, &q("t_b", "q3", "agent", "a1"))
            .await
            .unwrap();
        assert!(get_quarantine(&pool, "t_b", "q1").await.unwrap().is_none());
        let rows = list_quarantine(&pool, "t_a", 50, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.tenant_id == "t_a"));
    }
}
