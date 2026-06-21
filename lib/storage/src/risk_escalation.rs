//! #1296 — auto-escalate an agent's `risk_tier` after repeated denials.
//!
//! Unlike the advisory `composite_risk_score` (#1289, Law 1: never gates
//! `allow`/`deny`/`require_approval`), `agents.risk_tier` is real
//! authorization state — Cedar policies branch on it via
//! `context.agent_risk_tier` to require approval for actions a `"low"`-tier
//! agent would otherwise be permitted. Escalating it is therefore done
//! inline on the `/v1/authorize` path (fast, local SQLite only — no
//! network I/O) immediately after a `deny` decision is recorded, so the
//! very next call from this agent already sees the tightened tier.

use aegis_common::errors::AegisError;
use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;

/// One step up the tier ladder, or `None` if `current` is already at the
/// top (`"high"`) or is an unrecognized value — escalation never guesses at
/// an unrecognized tier (fail-safe: leave it as the operator set it).
pub fn escalate_tier(current: &str) -> Option<&'static str> {
    match current {
        "low" => Some("medium"),
        "medium" => Some("high"),
        _ => None,
    }
}

/// Counts this agent's `deny` decisions within `config.window_minutes`; if
/// strictly more than `config.denial_threshold` and the tier isn't already
/// maxed out, persists the escalated tier and returns `Some((old, new))`
/// for the caller to audit-log. Returns `Ok(None)` when no escalation
/// happens (below threshold, already `"high"`, or an unrecognized tier).
pub async fn maybe_escalate_agent_risk_tier(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    current_tier: &str,
) -> Result<Option<(String, String)>, AegisError> {
    let config = crate::db::get_risk_escalation_config(pool, tenant_id)
        .await
        .map_err(AegisError::Database)?;
    let since: DateTime<Utc> = Utc::now() - Duration::minutes(config.window_minutes);
    let denial_count = crate::db::count_recent_denials(pool, tenant_id, agent_id, since)
        .await
        .map_err(AegisError::Database)?;

    if denial_count <= config.denial_threshold {
        return Ok(None);
    }

    let Some(new_tier) = escalate_tier(current_tier) else {
        return Ok(None);
    };

    crate::db::update_agent_risk_tier(pool, tenant_id, agent_id, new_tier)
        .await
        .map_err(AegisError::Database)?;
    Ok(Some((current_tier.to_string(), new_tier.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_api::models::RiskEscalationConfig;

    #[test]
    fn escalate_tier_steps_low_to_medium() {
        assert_eq!(escalate_tier("low"), Some("medium"));
    }

    #[test]
    fn escalate_tier_steps_medium_to_high() {
        assert_eq!(escalate_tier("medium"), Some("high"));
    }

    #[test]
    fn escalate_tier_high_is_already_maxed_out() {
        assert_eq!(escalate_tier("high"), None);
    }

    #[test]
    fn escalate_tier_unrecognized_value_does_not_escalate() {
        assert_eq!(escalate_tier("unspecified"), None);
        assert_eq!(escalate_tier(""), None);
    }

    #[test]
    fn default_config_matches_documented_defaults() {
        let config = RiskEscalationConfig::default();
        assert_eq!(config.denial_threshold, 5);
        assert_eq!(config.window_minutes, 60);
    }

    async fn setup_pool() -> SqlitePool {
        let pool = crate::db::init_db("sqlite::memory:").await.unwrap();
        crate::db::register_tenant(&pool, "tenant_1", "Tenant One", "developer")
            .await
            .unwrap();
        pool
    }

    async fn insert_agent(pool: &SqlitePool, agent_id: &str, risk_tier: &str) {
        sqlx::query(
            "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES (?, 'tenant_1', ?, 'tok', 'Test Agent', 'production', ?, 'active')",
        )
        .bind(agent_id)
        .bind(agent_id)
        .bind(risk_tier)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_deny_decision(pool: &SqlitePool, agent_id: &str, created_at: DateTime<Utc>) {
        // Match the space-separated format SQLite's own `DEFAULT
        // CURRENT_TIMESTAMP` produces in the real `db::insert_decision`
        // path (no column-list entry there) — binding a raw `DateTime<Utc>`
        // instead serializes RFC3339-style with a `T` separator, which
        // would make this fixture diverge from production behavior.
        let created_at_str = created_at.format("%F %T%.6f").to_string();
        sqlx::query(
            "INSERT INTO decisions (id, tenant_id, agent_id, skill, action, input_json, decision, created_at)
             VALUES (?, 'tenant_1', ?, 'github', 'merge', '{}', 'deny', ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(agent_id)
        .bind(created_at_str)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn escalates_low_to_medium_after_exceeding_default_threshold() {
        let pool = setup_pool().await;
        insert_agent(&pool, "agent_1", "low").await;
        for _ in 0..6 {
            insert_deny_decision(&pool, "agent_1", Utc::now()).await;
        }

        let result = maybe_escalate_agent_risk_tier(&pool, "tenant_1", "agent_1", "low")
            .await
            .unwrap();
        assert_eq!(result, Some(("low".to_string(), "medium".to_string())));

        let (stored_tier,): (String,) = sqlx::query_as("SELECT risk_tier FROM agents WHERE id = ?")
            .bind("agent_1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored_tier, "medium");
    }

    #[tokio::test]
    async fn does_not_escalate_below_threshold() {
        let pool = setup_pool().await;
        insert_agent(&pool, "agent_1", "low").await;
        for _ in 0..5 {
            insert_deny_decision(&pool, "agent_1", Utc::now()).await;
        }

        let result = maybe_escalate_agent_risk_tier(&pool, "tenant_1", "agent_1", "low")
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn ignores_denials_outside_the_window() {
        let pool = setup_pool().await;
        insert_agent(&pool, "agent_1", "low").await;
        let stale = Utc::now() - Duration::minutes(120);
        for _ in 0..10 {
            insert_deny_decision(&pool, "agent_1", stale).await;
        }

        let result = maybe_escalate_agent_risk_tier(&pool, "tenant_1", "agent_1", "low")
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn already_high_tier_does_not_escalate_further() {
        let pool = setup_pool().await;
        insert_agent(&pool, "agent_1", "high").await;
        for _ in 0..10 {
            insert_deny_decision(&pool, "agent_1", Utc::now()).await;
        }

        let result = maybe_escalate_agent_risk_tier(&pool, "tenant_1", "agent_1", "high")
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn per_tenant_threshold_override_is_respected() {
        let pool = setup_pool().await;
        insert_agent(&pool, "agent_1", "low").await;
        crate::db::upsert_risk_escalation_config(
            &pool,
            "tenant_1",
            &RiskEscalationConfig {
                denial_threshold: 1,
                window_minutes: 60,
            },
        )
        .await
        .unwrap();
        for _ in 0..2 {
            insert_deny_decision(&pool, "agent_1", Utc::now()).await;
        }

        let result = maybe_escalate_agent_risk_tier(&pool, "tenant_1", "agent_1", "low")
            .await
            .unwrap();
        assert_eq!(result, Some(("low".to_string(), "medium".to_string())));
    }
}
