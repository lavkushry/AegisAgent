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
    use aegis_api::models::AgentRecord;

    static PERMISSION_REVIEW_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn set_permission_review_env(enabled: Option<&str>, stale_days: Option<&str>) {
        match enabled {
            Some(value) => std::env::set_var("AEGIS_PERMISSION_REVIEW_ENABLED", value),
            None => std::env::remove_var("AEGIS_PERMISSION_REVIEW_ENABLED"),
        }
        match stale_days {
            Some(value) => std::env::set_var("AEGIS_PERMISSION_REVIEW_STALE_DAYS", value),
            None => std::env::remove_var("AEGIS_PERMISSION_REVIEW_STALE_DAYS"),
        }
    }

    async fn setup_pool(test_name: &str) -> DbPool {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/soc_{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        db::init_db(&db_url).await.unwrap()
    }

    async fn seed_agent(pool: &DbPool, tenant_id: &str, agent_id: &str) {
        let agent = AgentRecord {
            id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            agent_key: format!("key_{agent_id}"),
            agent_token: format!("tok_{agent_id}"),
            name: format!("Agent {agent_id}"),
            owner_team: None,
            owner_email: None,
            environment: "prod".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "medium".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            quarantined_at: None,
            force_approval: false,
            signing_key: None,
            allowed_environments: None,
            mtls_cn: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(pool, &agent).await.unwrap();
    }

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

    #[tokio::test]
    async fn permission_review_disabled_by_default() {
        let _guard = PERMISSION_REVIEW_ENV_LOCK.lock().await;
        let prev_enabled = std::env::var("AEGIS_PERMISSION_REVIEW_ENABLED").ok();
        let prev_stale_days = std::env::var("AEGIS_PERMISSION_REVIEW_STALE_DAYS").ok();
        set_permission_review_env(None, None);
        assert!(!permission_review_enabled());
        set_permission_review_env(prev_enabled.as_deref(), prev_stale_days.as_deref());
    }

    #[tokio::test]
    async fn permission_review_enabled_with_true() {
        let _guard = PERMISSION_REVIEW_ENV_LOCK.lock().await;
        let prev_enabled = std::env::var("AEGIS_PERMISSION_REVIEW_ENABLED").ok();
        let prev_stale_days = std::env::var("AEGIS_PERMISSION_REVIEW_STALE_DAYS").ok();
        set_permission_review_env(Some("true"), None);
        assert!(permission_review_enabled());
        set_permission_review_env(prev_enabled.as_deref(), prev_stale_days.as_deref());
    }

    #[tokio::test]
    async fn generates_deduplicated_tenant_scoped_alerts_for_stale_permissions() {
        let _guard = PERMISSION_REVIEW_ENV_LOCK.lock().await;
        let prev_enabled = std::env::var("AEGIS_PERMISSION_REVIEW_ENABLED").ok();
        let prev_stale_days = std::env::var("AEGIS_PERMISSION_REVIEW_STALE_DAYS").ok();
        set_permission_review_env(Some("true"), Some("30"));

        let pool = setup_pool("permission_review_alerts").await;
        db::register_tenant(&pool, "tenant_perm_a", "Permission A", "developer")
            .await
            .unwrap();
        db::register_tenant(&pool, "tenant_perm_b", "Permission B", "developer")
            .await
            .unwrap();
        seed_agent(&pool, "tenant_perm_a", "agent_perm_a").await;
        seed_agent(&pool, "tenant_perm_b", "agent_perm_b").await;

        let tool_perm =
            db::grant_agent_tool_permission(&pool, "tenant_perm_a", "agent_perm_a", "github")
                .await
                .unwrap();
        let mcp_perm = db::grant_agent_mcp_server_permission(
            &pool,
            "tenant_perm_a",
            "agent_perm_a",
            "github-mcp",
        )
        .await
        .unwrap();
        let cross_tenant_perm =
            db::grant_agent_tool_permission(&pool, "tenant_perm_b", "agent_perm_b", "github")
                .await
                .unwrap();

        for permission_id in [&tool_perm.id, &mcp_perm.id, &cross_tenant_perm.id] {
            aegis_storage::execute_query!(
                &pool,
                "UPDATE agent_tool_permissions SET created_at = datetime('now', '-45 days') WHERE id = ?",
                permission_id
            )
            .unwrap();
            aegis_storage::execute_query!(
                &pool,
                "UPDATE agent_mcp_server_permissions SET created_at = datetime('now', '-45 days') WHERE id = ?",
                permission_id
            )
            .unwrap();
        }

        let created = generate_permission_review_alerts_for_tenant(&pool, "tenant_perm_a", 50)
            .await
            .unwrap();
        assert_eq!(created, 2);

        let created_again =
            generate_permission_review_alerts_for_tenant(&pool, "tenant_perm_a", 50)
                .await
                .unwrap();
        assert_eq!(created_again, 0);

        let tenant_a_alerts = db::list_soc_alerts(&pool, "tenant_perm_a", 10, 0, None, None)
            .await
            .unwrap();
        assert_eq!(tenant_a_alerts.len(), 2);
        assert!(tenant_a_alerts.iter().any(|alert| {
            alert.rule == RULE_UNUSED_TOOL_PERMISSION
                && alert.source_event_id == tool_source_event_id(&tool_perm.id)
        }));
        assert!(tenant_a_alerts.iter().any(|alert| {
            alert.rule == RULE_UNUSED_MCP_SERVER_PERMISSION
                && alert.source_event_id == mcp_source_event_id(&mcp_perm.id)
        }));

        let tenant_b_alerts = db::list_soc_alerts(&pool, "tenant_perm_b", 10, 0, None, None)
            .await
            .unwrap();
        assert!(tenant_b_alerts.is_empty());

        set_permission_review_env(prev_enabled.as_deref(), prev_stale_days.as_deref());
    }
}
