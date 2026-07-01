//! Phase 2.4 (runtime control plane): `agent_bans` CRUD + the hot `is_banned`
//! enforcement lookup.
//!
//! `is_banned` is consulted before sandbox start, authorize, tool/MCP call,
//! egress, and credential issuance, so it must be a single indexed query. All
//! queries are tenant-scoped and parameterized. Storage-only (ban/unban routes
//! and receipts land in a later phase).

use super::{retry_on_busy, SOC_MAX_LIMIT};
use crate::db::DbPool;
use aegis_api::models::*;
use chrono::{DateTime, Utc};

const COLS: &str = "id, tenant_id, target_type, target_value, scope, reason, actor, status, \
     created_at, expires_at, revoked_at, revoked_by";

/// Record a new ban.
pub async fn insert_ban(pool: &DbPool, b: &AgentBanRecord) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO agent_bans
           (id, tenant_id, target_type, target_value, scope, reason, actor, status,
            created_at, expires_at, revoked_at, revoked_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &b.id,
        &b.tenant_id,
        &b.target_type,
        &b.target_value,
        &b.scope,
        &b.reason,
        &b.actor,
        &b.status,
        b.created_at,
        b.expires_at,
        b.revoked_at,
        &b.revoked_by
    )?;
    Ok(())
}

/// Hot enforcement lookup: is `(target_type, target_value)` under an active,
/// unrevoked, unexpired ban for this tenant right now? A single indexed
/// `EXISTS`-style count; tenant-scoped and parameterized.
pub async fn is_banned(
    pool: &DbPool,
    tenant_id: &str,
    target_type: &str,
    target_value: &str,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let count: i64 = crate::fetch_one_scalar!(
        i64,
        pool,
        "SELECT COUNT(*) FROM agent_bans
         WHERE tenant_id = ? AND target_type = ? AND target_value = ?
           AND status = 'active' AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)",
        tenant_id,
        target_type,
        target_value,
        now
    )?;
    Ok(count > 0)
}

/// Fetch a ban by id, tenant-scoped (cross-tenant lookups return `None`).
pub async fn get_ban(
    pool: &DbPool,
    tenant_id: &str,
    ban_id: &str,
) -> Result<Option<AgentBanRecord>, sqlx::Error> {
    let sql = format!("SELECT {COLS} FROM agent_bans WHERE tenant_id = ? AND id = ?");
    crate::fetch_optional_as!(AgentBanRecord, pool, sql.as_str(), tenant_id, ban_id)
}

/// Revoke a ban (sets status='revoked' + stamps revoked_at/revoked_by),
/// tenant-scoped. Returns `true` only if an active ban was revoked.
pub async fn revoke_ban(
    pool: &DbPool,
    tenant_id: &str,
    ban_id: &str,
    revoked_by: &str,
    now: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    retry_on_busy(3, || async {
        let result = crate::execute_query!(
            pool,
            "UPDATE agent_bans
             SET status = 'revoked', revoked_at = ?, revoked_by = ?
             WHERE tenant_id = ? AND id = ? AND status = 'active'",
            now,
            revoked_by,
            tenant_id,
            ban_id
        )?;
        Ok(result.rows_affected() == 1)
    })
    .await
}

/// List a tenant's bans, newest-first. `limit` is clamped.
pub async fn list_bans(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AgentBanRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    let sql = format!(
        "SELECT {COLS} FROM agent_bans WHERE tenant_id = ?
         ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
    );
    crate::fetch_all_as!(AgentBanRecord, pool, sql.as_str(), tenant_id, limit, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::setup_pool;
    use chrono::Duration;

    fn ban(tenant: &str, id: &str, ttype: &str, tvalue: &str) -> AgentBanRecord {
        AgentBanRecord {
            id: id.to_string(),
            tenant_id: tenant.to_string(),
            target_type: ttype.to_string(),
            target_value: tvalue.to_string(),
            scope: "tenant".to_string(),
            reason: Some("exfil attempt".to_string()),
            actor: "soc-analyst".to_string(),
            status: "active".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
            revoked_by: None,
        }
    }

    #[tokio::test]
    async fn is_banned_matches_only_the_exact_active_target() {
        let pool = setup_pool("ban_match").await;
        insert_ban(&pool, &ban("t_a", "b1", "fingerprint", "fp-xyz"))
            .await
            .unwrap();

        let now = Utc::now();
        assert!(is_banned(&pool, "t_a", "fingerprint", "fp-xyz", now)
            .await
            .unwrap());
        // Different value → not banned.
        assert!(!is_banned(&pool, "t_a", "fingerprint", "fp-other", now)
            .await
            .unwrap());
        // Different type → not banned.
        assert!(!is_banned(&pool, "t_a", "agent", "fp-xyz", now)
            .await
            .unwrap());
        // Different tenant → not banned (tenant isolation).
        assert!(!is_banned(&pool, "t_b", "fingerprint", "fp-xyz", now)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn expired_ban_is_not_active() {
        let pool = setup_pool("ban_expired").await;
        let mut b = ban("t_a", "b1", "destination_domain", "evil.example");
        b.expires_at = Some(Utc::now() - Duration::seconds(1));
        insert_ban(&pool, &b).await.unwrap();
        assert!(!is_banned(
            &pool,
            "t_a",
            "destination_domain",
            "evil.example",
            Utc::now()
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn revoked_ban_is_not_active_and_revoke_is_tenant_scoped() {
        let pool = setup_pool("ban_revoke").await;
        insert_ban(&pool, &ban("t_a", "b1", "agent", "agent-1"))
            .await
            .unwrap();
        let now = Utc::now();
        assert!(is_banned(&pool, "t_a", "agent", "agent-1", now)
            .await
            .unwrap());

        // Cross-tenant revoke matches nothing.
        assert!(!revoke_ban(&pool, "t_b", "b1", "admin", now).await.unwrap());
        // Owner revokes.
        assert!(revoke_ban(&pool, "t_a", "b1", "admin", now).await.unwrap());
        assert!(!is_banned(&pool, "t_a", "agent", "agent-1", now)
            .await
            .unwrap());
        let got = get_ban(&pool, "t_a", "b1").await.unwrap().unwrap();
        assert_eq!(got.status, "revoked");
        assert_eq!(got.revoked_by.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn get_and_list_are_tenant_scoped() {
        let pool = setup_pool("ban_list").await;
        insert_ban(&pool, &ban("t_a", "b1", "agent", "a1"))
            .await
            .unwrap();
        insert_ban(&pool, &ban("t_a", "b2", "tool", "shell"))
            .await
            .unwrap();
        insert_ban(&pool, &ban("t_b", "b3", "agent", "a1"))
            .await
            .unwrap();

        assert!(get_ban(&pool, "t_b", "b1").await.unwrap().is_none());
        let rows = list_bans(&pool, "t_a", 50, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|b| b.tenant_id == "t_a"));
    }
}
