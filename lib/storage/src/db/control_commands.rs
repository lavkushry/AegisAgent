//! Phase 2.3 (runtime control plane): `control_commands` CRUD.
//!
//! The gateway persists issued signed commands here; the sensor verifies and
//! executes them. All queries are tenant-scoped and parameterized. Storage-only
//! (issue/ack routes and signature verification land in a later phase).

use super::{retry_on_busy, SOC_MAX_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;

const COLS: &str = "command_id, tenant_id, target_type, target_id, action, reason, issued_by, \
     issued_at, expires_at, nonce, requires_ack, receipt_required, signature, status, created_at";

/// Persist a newly-issued control command. The `(tenant_id, nonce)` unique
/// index rejects a replayed nonce as a conflict (surfaced as an error).
pub async fn insert_control_command(
    pool: &DbPool,
    c: &ControlCommandRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO control_commands
           (command_id, tenant_id, target_type, target_id, action, reason, issued_by,
            issued_at, expires_at, nonce, requires_ack, receipt_required, signature, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &c.command_id,
        &c.tenant_id,
        &c.target_type,
        &c.target_id,
        &c.action,
        &c.reason,
        &c.issued_by,
        c.issued_at,
        c.expires_at,
        &c.nonce,
        c.requires_ack,
        c.receipt_required,
        &c.signature,
        &c.status,
        c.created_at
    )?;
    Ok(())
}

/// Fetch a command by id, tenant-scoped (cross-tenant lookups return `None`).
pub async fn get_control_command(
    pool: &DbPool,
    tenant_id: &str,
    command_id: &str,
) -> Result<Option<ControlCommandRecord>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM control_commands WHERE tenant_id = ? AND command_id = ?");
    crate::fetch_optional_as!(
        ControlCommandRecord,
        pool,
        sql.as_str(),
        tenant_id,
        command_id
    )
}

/// Transition a command's delivery `status` (delivered/acked/nacked/executed/
/// expired), tenant-scoped. Returns `true` only if a row was updated.
pub async fn update_control_command_status(
    pool: &DbPool,
    tenant_id: &str,
    command_id: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE control_commands SET status = ? WHERE tenant_id = ? AND command_id = ?",
            status,
            tenant_id,
            command_id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// List a tenant's control commands, newest-first. `limit` is clamped.
pub async fn list_control_commands(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ControlCommandRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {COLS} FROM control_commands WHERE tenant_id = ?
         ORDER BY issued_at DESC, rowid DESC LIMIT ? OFFSET ?"
    );
    crate::fetch_all_as!(
        ControlCommandRecord,
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
    use chrono::{Duration, Utc};

    fn cmd(tenant: &str, id: &str, nonce: &str) -> ControlCommandRecord {
        let now = Utc::now();
        ControlCommandRecord {
            command_id: id.to_string(),
            tenant_id: tenant.to_string(),
            target_type: "run".to_string(),
            target_id: "run-1".to_string(),
            action: "kill_run".to_string(),
            reason: Some("policy: exfil detected".to_string()),
            issued_by: "soc-analyst".to_string(),
            issued_at: now,
            expires_at: now + Duration::seconds(300),
            nonce: nonce.to_string(),
            requires_ack: true,
            receipt_required: true,
            signature: "ed25519:deadbeef".to_string(),
            status: "issued".to_string(),
            created_at: now,
        }
    }

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let pool = setup_pool("cc_roundtrip").await;
        insert_control_command(&pool, &cmd("t_a", "c1", "n1"))
            .await
            .unwrap();
        let got = get_control_command(&pool, "t_a", "c1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.action, "kill_run");
        assert!(got.requires_ack);
        assert_eq!(got.status, "issued");
    }

    #[tokio::test]
    async fn get_is_tenant_scoped() {
        let pool = setup_pool("cc_tenant").await;
        insert_control_command(&pool, &cmd("t_a", "c1", "n1"))
            .await
            .unwrap();
        assert!(get_control_command(&pool, "t_b", "c1")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn duplicate_nonce_per_tenant_is_rejected() {
        let pool = setup_pool("cc_nonce").await;
        insert_control_command(&pool, &cmd("t_a", "c1", "dup"))
            .await
            .unwrap();
        // Same (tenant, nonce), different command_id → unique-index conflict (replay).
        assert!(insert_control_command(&pool, &cmd("t_a", "c2", "dup"))
            .await
            .is_err());
        // Same nonce under a different tenant is fine.
        insert_control_command(&pool, &cmd("t_b", "c3", "dup"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_update_is_tenant_scoped() {
        let pool = setup_pool("cc_status").await;
        insert_control_command(&pool, &cmd("t_a", "c1", "n1"))
            .await
            .unwrap();
        // Cross-tenant update matches nothing.
        assert!(!update_control_command_status(&pool, "t_b", "c1", "acked")
            .await
            .unwrap());
        assert!(update_control_command_status(&pool, "t_a", "c1", "acked")
            .await
            .unwrap());
        let got = get_control_command(&pool, "t_a", "c1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.status, "acked");
    }

    #[tokio::test]
    async fn list_is_tenant_scoped() {
        let pool = setup_pool("cc_list").await;
        insert_control_command(&pool, &cmd("t_a", "c1", "n1"))
            .await
            .unwrap();
        insert_control_command(&pool, &cmd("t_a", "c2", "n2"))
            .await
            .unwrap();
        insert_control_command(&pool, &cmd("t_b", "c3", "n3"))
            .await
            .unwrap();
        let rows = list_control_commands(&pool, "t_a", 50, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|c| c.tenant_id == "t_a"));
    }
}
