//! Permission review queries (#1768) — stale unused agent tool/MCP permissions.

use super::DbPool;
use chrono::{Duration, Utc};

/// Tool permission row eligible for unused-permission review.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StaleToolPermission {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub tool_key: String,
    pub created_at: String,
}

/// MCP server permission row eligible for unused-permission review.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StaleMcpServerPermission {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub server_key: String,
    pub created_at: String,
}

fn usage_cutoff_rfc3339(stale_days: i64) -> String {
    let stale_days = stale_days.clamp(1, 365);
    (Utc::now() - Duration::days(stale_days))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// Tool permissions granted at least `stale_days` ago with no matching
/// `decisions.skill` usage for the same agent in that window.
pub async fn list_stale_unused_tool_permissions(
    pool: &DbPool,
    tenant_id: &str,
    stale_days: i64,
    limit: i64,
) -> Result<Vec<StaleToolPermission>, sqlx::Error> {
    let cutoff = usage_cutoff_rfc3339(stale_days);
    let limit = limit.clamp(1, 500);
    crate::fetch_all_as!(
        StaleToolPermission,
        pool,
        "SELECT p.id, p.tenant_id, p.agent_id, p.tool_key, p.created_at
         FROM agent_tool_permissions p
         WHERE p.tenant_id = ?
           AND p.created_at <= ?
           AND NOT EXISTS (
             SELECT 1 FROM decisions d
             WHERE d.tenant_id = p.tenant_id
               AND d.agent_id = p.agent_id
               AND d.skill = p.tool_key
               AND d.created_at >= ?
           )
         ORDER BY p.created_at ASC
         LIMIT ?",
        tenant_id,
        cutoff.clone(),
        cutoff,
        limit
    )
}

/// MCP server permissions granted at least `stale_days` ago with no matching
/// `decisions.skill = 'mcp:' || server_key` usage for the same agent in that window.
pub async fn list_stale_unused_mcp_server_permissions(
    pool: &DbPool,
    tenant_id: &str,
    stale_days: i64,
    limit: i64,
) -> Result<Vec<StaleMcpServerPermission>, sqlx::Error> {
    let cutoff = usage_cutoff_rfc3339(stale_days);
    let limit = limit.clamp(1, 500);
    crate::fetch_all_as!(
        StaleMcpServerPermission,
        pool,
        "SELECT p.id, p.tenant_id, p.agent_id, p.server_key, p.created_at
         FROM agent_mcp_server_permissions p
         WHERE p.tenant_id = ?
           AND p.created_at <= ?
           AND NOT EXISTS (
             SELECT 1 FROM decisions d
             WHERE d.tenant_id = p.tenant_id
               AND d.agent_id = p.agent_id
               AND d.skill = ('mcp:' || p.server_key)
               AND d.created_at >= ?
           )
         ORDER BY p.created_at ASC
         LIMIT ?",
        tenant_id,
        cutoff.clone(),
        cutoff,
        limit
    )
}

/// Returns true when a permission-review alert already exists for `source_event_id`.
pub async fn has_permission_review_alert(
    pool: &DbPool,
    tenant_id: &str,
    source_event_id: &str,
) -> Result<bool, sqlx::Error> {
    let (count,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM soc_alerts
         WHERE tenant_id = ? AND source_event_id = ?",
        tenant_id,
        source_event_id
    )?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::agents::{grant_agent_mcp_server_permission, grant_agent_tool_permission};
    use crate::db::tenant::register_tenant;
    use crate::db::test_utils::setup_pool;
    use chrono::Utc;

    async fn seed_agent(pool: &DbPool, tenant_id: &str, agent_id: &str) {
        crate::execute_query!(
            pool,
            "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES (?, ?, 'key_perm', 'tok_perm', 'Perm Agent', 'prod', 'medium', 'active')",
            agent_id,
            tenant_id
        )
        .unwrap();
    }

    #[tokio::test]
    async fn list_stale_unused_tool_permissions_excludes_recent_usage() {
        let pool = setup_pool("perm_review_tool").await;
        let tenant_id = "tenant_perm_tool";
        register_tenant(&pool, tenant_id, "Perm Tool Tenant", "developer")
            .await
            .unwrap();
        seed_agent(&pool, tenant_id, "ag_perm").await;

        let perm = grant_agent_tool_permission(&pool, tenant_id, "ag_perm", "github")
            .await
            .unwrap();
        crate::execute_query!(
            &pool,
            "UPDATE agent_tool_permissions SET created_at = datetime('now', '-45 days') WHERE id = ?",
            &perm.id
        )
        .unwrap();

        let now_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        crate::execute_query!(
            &pool,
            "INSERT INTO decisions (id, tenant_id, agent_id, skill, action, input_json, decision, created_at)
             VALUES ('dec-used', ?, 'ag_perm', 'github', 'merge', '{}', 'allow', ?)",
            tenant_id,
            &now_str
        )
        .unwrap();

        let stale = list_stale_unused_tool_permissions(&pool, tenant_id, 30, 50)
            .await
            .unwrap();
        assert!(stale.is_empty());

        crate::execute_query!(&pool, "DELETE FROM decisions WHERE id = 'dec-used'").unwrap();
        let stale = list_stale_unused_tool_permissions(&pool, tenant_id, 30, 50)
            .await
            .unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].tool_key, "github");
    }

    #[tokio::test]
    async fn list_stale_unused_mcp_permissions_matches_mcp_skill_prefix() {
        let pool = setup_pool("perm_review_mcp").await;
        let tenant_id = "tenant_perm_mcp";
        register_tenant(&pool, tenant_id, "Perm MCP Tenant", "developer")
            .await
            .unwrap();
        seed_agent(&pool, tenant_id, "ag_mcp").await;

        let perm = grant_agent_mcp_server_permission(&pool, tenant_id, "ag_mcp", "github-mcp")
            .await
            .unwrap();
        crate::execute_query!(
            &pool,
            "UPDATE agent_mcp_server_permissions SET created_at = datetime('now', '-45 days') WHERE id = ?",
            &perm.id
        )
        .unwrap();

        let stale = list_stale_unused_mcp_server_permissions(&pool, tenant_id, 30, 50)
            .await
            .unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].server_key, "github-mcp");

        let now_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        crate::execute_query!(
            &pool,
            "INSERT INTO decisions (id, tenant_id, agent_id, skill, action, input_json, decision, created_at)
             VALUES ('dec-mcp-used', ?, 'ag_mcp', 'mcp:github-mcp', 'create_issue', '{}', 'allow', ?)",
            tenant_id,
            &now_str
        )
        .unwrap();

        let stale = list_stale_unused_mcp_server_permissions(&pool, tenant_id, 30, 50)
            .await
            .unwrap();
        assert!(stale.is_empty());
    }
}
