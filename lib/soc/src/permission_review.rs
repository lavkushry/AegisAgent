//! Permission review alerts (#1768, LAW-2 compliant).
//!
//! Detects agent tool and MCP server permissions that have not been exercised
//! within a configurable stale window. Produces SOC alerts only — never revokes
//! or blocks permissions.

use aegis_api::models::SocAlertRecord;
use aegis_storage::db;
use aegis_storage::db::DbPool;
use chrono::Utc;
use uuid::Uuid;

pub const DEFAULT_STALE_DAYS: i64 = 30;
pub const RULE_UNUSED_TOOL_PERMISSION: &str = "unused_tool_permission";
pub const RULE_UNUSED_MCP_SERVER_PERMISSION: &str = "unused_mcp_server_permission";

pub fn permission_review_enabled() -> bool {
    std::env::var("AEGIS_PERMISSION_REVIEW_ENABLED")
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

pub fn stale_days_from_env() -> i64 {
    std::env::var("AEGIS_PERMISSION_REVIEW_STALE_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_STALE_DAYS)
        .clamp(1, 365)
}

pub fn tool_source_event_id(permission_id: &str) -> String {
    format!("permission-review:tool:{permission_id}")
}

pub fn mcp_source_event_id(permission_id: &str) -> String {
    format!("permission-review:mcp:{permission_id}")
}

async fn persist_unused_tool_alert(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    tool_key: &str,
    permission_id: &str,
    stale_days: i64,
) -> Result<bool, sqlx::Error> {
    let source_event_id = tool_source_event_id(permission_id);
    if db::has_permission_review_alert(pool, tenant_id, &source_event_id).await? {
        return Ok(false);
    }

    let summary = format!(
        "Agent '{agent_id}' has tool permission '{tool_key}' that has not been used in \
         the last {stale_days} days. Review whether this allow-list entry is still required."
    );
    let now = Utc::now().to_rfc3339();
    let record = SocAlertRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        rule: RULE_UNUSED_TOOL_PERMISSION.to_string(),
        severity: "low".to_string(),
        agent_id: agent_id.to_string(),
        source_event_id,
        summary,
        created_at: now,
        triage_recommendation: None,
    };
    db::insert_soc_alert(pool, &record).await?;
    Ok(true)
}

async fn persist_unused_mcp_alert(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    server_key: &str,
    permission_id: &str,
    stale_days: i64,
) -> Result<bool, sqlx::Error> {
    let source_event_id = mcp_source_event_id(permission_id);
    if db::has_permission_review_alert(pool, tenant_id, &source_event_id).await? {
        return Ok(false);
    }

    let summary = format!(
        "Agent '{agent_id}' has MCP server permission '{server_key}' that has not been used in \
         the last {stale_days} days. Review whether this allow-list entry is still required."
    );
    let now = Utc::now().to_rfc3339();
    let record = SocAlertRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        rule: RULE_UNUSED_MCP_SERVER_PERMISSION.to_string(),
        severity: "low".to_string(),
        agent_id: agent_id.to_string(),
        source_event_id,
        summary,
        created_at: now,
        triage_recommendation: None,
    };
    db::insert_soc_alert(pool, &record).await?;
    Ok(true)
}

/// Scan one tenant for stale unused permissions and persist deduplicated SOC alerts.
pub async fn generate_permission_review_alerts_for_tenant(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
) -> Result<u32, sqlx::Error> {
    if !permission_review_enabled() {
        return Ok(0);
    }

    let stale_days = stale_days_from_env();
    let limit = limit.clamp(1, 100);
    let mut created = 0u32;

    let tool_perms =
        db::list_stale_unused_tool_permissions(pool, tenant_id, stale_days, limit).await?;
    for perm in tool_perms {
        if persist_unused_tool_alert(
            pool,
            tenant_id,
            &perm.agent_id,
            &perm.tool_key,
            &perm.id,
            stale_days,
        )
        .await?
        {
            created += 1;
        }
    }

    let mcp_perms =
        db::list_stale_unused_mcp_server_permissions(pool, tenant_id, stale_days, limit).await?;
    for perm in mcp_perms {
        if persist_unused_mcp_alert(
            pool,
            tenant_id,
            &perm.agent_id,
            &perm.server_key,
            &perm.id,
            stale_days,
        )
        .await?
        {
            created += 1;
        }
    }

    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_event_ids_are_stable_per_permission() {
        assert_eq!(
            tool_source_event_id("perm-123"),
            "permission-review:tool:perm-123"
        );
        assert_eq!(
            mcp_source_event_id("perm-456"),
            "permission-review:mcp:perm-456"
        );
    }

    #[test]
    fn permission_review_disabled_by_default() {
        let prev = std::env::var("AEGIS_PERMISSION_REVIEW_ENABLED").ok();
        std::env::remove_var("AEGIS_PERMISSION_REVIEW_ENABLED");
        assert!(!permission_review_enabled());
        if let Some(v) = prev {
            std::env::set_var("AEGIS_PERMISSION_REVIEW_ENABLED", v);
        }
    }

    #[test]
    fn permission_review_enabled_with_true() {
        let prev = std::env::var("AEGIS_PERMISSION_REVIEW_ENABLED").ok();
        std::env::set_var("AEGIS_PERMISSION_REVIEW_ENABLED", "true");
        assert!(permission_review_enabled());
        if let Some(v) = prev {
            std::env::set_var("AEGIS_PERMISSION_REVIEW_ENABLED", v);
        } else {
            std::env::remove_var("AEGIS_PERMISSION_REVIEW_ENABLED");
        }
    }
}
