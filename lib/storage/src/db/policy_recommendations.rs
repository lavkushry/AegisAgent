//! Policy recommendation persistence (#1394).

use super::DbPool;
use super::SOC_MAX_LIMIT;
use aegis_api::models::PolicyRecommendationRecord;

/// One denied-action aggregate for policy advisor analysis.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DeniedActionAggregate {
    pub agent_id: String,
    pub tool_key: String,
    pub action_key: String,
    pub deny_count: i64,
    pub sample_reason: Option<String>,
}

/// Denied decisions in the trailing `window_days`, grouped by agent/tool/action.
pub async fn aggregate_denied_decisions(
    pool: &DbPool,
    tenant_id: &str,
    window_days: i64,
    min_deny_count: i64,
) -> Result<Vec<DeniedActionAggregate>, sqlx::Error> {
    let window_days = window_days.clamp(1, 90);
    let min_deny_count = min_deny_count.max(1);
    crate::fetch_all_as!(
        DeniedActionAggregate,
        pool,
        "SELECT agent_id, skill AS tool_key, action AS action_key, COUNT(*) AS deny_count,
                MAX(reason) AS sample_reason
         FROM decisions
         WHERE tenant_id = ?
           AND decision = 'deny'
           AND created_at >= datetime('now', printf('-%d days', ?))
         GROUP BY agent_id, skill, action
         HAVING COUNT(*) >= ?
         ORDER BY deny_count DESC",
        tenant_id,
        window_days,
        min_deny_count
    )
}

pub async fn has_pending_policy_recommendation(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    tool_key: &str,
    action_key: &str,
) -> Result<bool, sqlx::Error> {
    let (count,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM policy_recommendations
         WHERE tenant_id = ? AND agent_id = ? AND tool_key = ? AND action_key = ?
           AND status = 'pending'",
        tenant_id,
        agent_id,
        tool_key,
        action_key
    )?;
    Ok(count > 0)
}

pub async fn insert_policy_recommendation(
    pool: &DbPool,
    record: &PolicyRecommendationRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO policy_recommendations
            (id, tenant_id, agent_id, tool_key, action_key, deny_count, window_days,
             sample_reason, draft_cedar, rationale, status, reviewer_note,
             generated_at, advisor_agent, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &record.id,
        &record.tenant_id,
        &record.agent_id,
        &record.tool_key,
        &record.action_key,
        record.deny_count,
        record.window_days,
        &record.sample_reason,
        &record.draft_cedar,
        &record.rationale,
        &record.status,
        &record.reviewer_note,
        &record.generated_at,
        &record.advisor_agent,
        &record.created_at
    )?;
    Ok(())
}

pub async fn list_policy_recommendations(
    pool: &DbPool,
    tenant_id: &str,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<PolicyRecommendationRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    if let Some(st) = status {
        return crate::fetch_all_as!(
            PolicyRecommendationRecord,
            pool,
            "SELECT id, tenant_id, agent_id, tool_key, action_key, deny_count, window_days,
                    sample_reason, draft_cedar, rationale, status, reviewer_note,
                    generated_at, advisor_agent, created_at
             FROM policy_recommendations
             WHERE tenant_id = ? AND status = ?
             ORDER BY generated_at DESC
             LIMIT ?",
            tenant_id,
            st,
            limit
        );
    }
    crate::fetch_all_as!(
        PolicyRecommendationRecord,
        pool,
        "SELECT id, tenant_id, agent_id, tool_key, action_key, deny_count, window_days,
                sample_reason, draft_cedar, rationale, status, reviewer_note,
                generated_at, advisor_agent, created_at
         FROM policy_recommendations
         WHERE tenant_id = ?
         ORDER BY generated_at DESC
         LIMIT ?",
        tenant_id,
        limit
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tenant::register_tenant;
    use crate::db::test_utils::setup_pool;
    use chrono::Utc;

    #[tokio::test]
    async fn aggregate_denied_decisions_groups_by_agent_tool_action() {
        let pool = setup_pool("policy_rec_agg").await;
        let tenant_id = "tenant_policy_rec";
        register_tenant(&pool, tenant_id, "Tenant Policy Rec", "developer")
            .await
            .unwrap();
        crate::execute_query!(
            &pool,
            "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('ag_denies', ?, 'key_denies', 'tok_denies', 'Agent Denies', 'prod', 'high', 'active')",
            tenant_id
        )
        .unwrap();

        let now_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        for i in 0..4 {
            crate::execute_query!(
                &pool,
                "INSERT INTO decisions (id, tenant_id, agent_id, skill, action, input_json, decision, reason, created_at)
                 VALUES (?, ?, 'ag_denies', 'github', 'merge', '{}', 'deny', 'policy forbid', ?)",
                format!("dec-deny-{i}"),
                tenant_id,
                &now_str
            )
            .unwrap();
        }

        let agg = aggregate_denied_decisions(&pool, tenant_id, 30, 3)
            .await
            .unwrap();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].deny_count, 4);
        assert_eq!(agg[0].tool_key, "github");
        assert_eq!(agg[0].action_key, "merge");
    }
}
