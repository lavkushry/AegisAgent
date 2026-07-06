//! Threat hunt finding persistence (#1395).

use super::DbPool;
use super::SOC_MAX_LIMIT;
use aegis_api::models::ThreatHuntFindingRecord;

/// Off-hours decision volume per agent in the analysis window.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OffHoursActivityAggregate {
    pub agent_id: String,
    pub off_hours_count: i64,
}

/// Many distinct tools invoked within a single agent run.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UnusualToolComboAggregate {
    pub agent_id: String,
    pub run_id: String,
    pub distinct_tools: i64,
}

/// High composite risk score cluster for an agent (optionally scoped to a run).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PrivilegeEscalationAggregate {
    pub agent_id: String,
    pub run_id: Option<String>,
    pub high_risk_count: i64,
    pub max_composite_risk_score: i64,
}

/// Lightweight decision row for evidence linking.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ThreatHuntDecisionEvidence {
    pub id: String,
    pub skill: String,
    pub action: String,
    pub run_id: Option<String>,
}

/// Off-hours decisions grouped by agent (UTC hour outside business window or weekend).
pub async fn aggregate_off_hours_activity(
    pool: &DbPool,
    tenant_id: &str,
    window_days: i64,
    business_hour_start: i64,
    business_hour_end: i64,
    min_count: i64,
) -> Result<Vec<OffHoursActivityAggregate>, sqlx::Error> {
    let window_days = window_days.clamp(1, 90);
    let min_count = min_count.max(1);
    let business_hour_start = business_hour_start.clamp(0, 23);
    let business_hour_end = business_hour_end.clamp(0, 23);
    crate::fetch_all_as!(
        OffHoursActivityAggregate,
        pool,
        "SELECT agent_id, COUNT(*) AS off_hours_count
         FROM decisions
         WHERE tenant_id = ?
           AND created_at >= datetime('now', printf('-%d days', ?))
           AND (
             CAST(strftime('%H', created_at) AS INTEGER) < ?
             OR CAST(strftime('%H', created_at) AS INTEGER) >= ?
             OR strftime('%w', created_at) IN ('0', '6')
           )
         GROUP BY agent_id
         HAVING COUNT(*) >= ?
         ORDER BY off_hours_count DESC",
        tenant_id,
        window_days,
        business_hour_start,
        business_hour_end,
        min_count
    )
}

/// Runs where an agent invoked many distinct tools (possible reconnaissance / combo abuse).
pub async fn aggregate_unusual_tool_combos(
    pool: &DbPool,
    tenant_id: &str,
    window_days: i64,
    min_distinct_tools: i64,
) -> Result<Vec<UnusualToolComboAggregate>, sqlx::Error> {
    let window_days = window_days.clamp(1, 90);
    let min_distinct_tools = min_distinct_tools.max(2);
    crate::fetch_all_as!(
        UnusualToolComboAggregate,
        pool,
        "SELECT agent_id, run_id, COUNT(DISTINCT skill) AS distinct_tools
         FROM decisions
         WHERE tenant_id = ?
           AND run_id IS NOT NULL
           AND created_at >= datetime('now', printf('-%d days', ?))
         GROUP BY agent_id, run_id
         HAVING COUNT(DISTINCT skill) >= ?
         ORDER BY distinct_tools DESC",
        tenant_id,
        window_days,
        min_distinct_tools
    )
}

/// Decisions with elevated composite risk scores (privilege-escalation pattern).
pub async fn aggregate_privilege_escalation(
    pool: &DbPool,
    tenant_id: &str,
    window_days: i64,
    min_composite_risk_score: i64,
    min_count: i64,
) -> Result<Vec<PrivilegeEscalationAggregate>, sqlx::Error> {
    let window_days = window_days.clamp(1, 90);
    let min_composite_risk_score = min_composite_risk_score.clamp(1, 100);
    let min_count = min_count.max(1);
    crate::fetch_all_as!(
        PrivilegeEscalationAggregate,
        pool,
        "SELECT agent_id, run_id, COUNT(*) AS high_risk_count,
                MAX(composite_risk_score) AS max_composite_risk_score
         FROM decisions
         WHERE tenant_id = ?
           AND composite_risk_score IS NOT NULL
           AND composite_risk_score >= ?
           AND created_at >= datetime('now', printf('-%d days', ?))
         GROUP BY agent_id, run_id
         HAVING COUNT(*) >= ?
         ORDER BY max_composite_risk_score DESC",
        tenant_id,
        min_composite_risk_score,
        window_days,
        min_count
    )
}

pub async fn list_threat_hunt_decision_evidence_for_agent(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    run_id: Option<&str>,
    window_days: i64,
    limit: i64,
) -> Result<Vec<ThreatHuntDecisionEvidence>, sqlx::Error> {
    let window_days = window_days.clamp(1, 90);
    let limit = limit.clamp(1, 50);
    if let Some(rid) = run_id {
        return crate::fetch_all_as!(
            ThreatHuntDecisionEvidence,
            pool,
            "SELECT id, skill, action, run_id
             FROM decisions
             WHERE tenant_id = ? AND agent_id = ? AND run_id = ?
               AND created_at >= datetime('now', printf('-%d days', ?))
             ORDER BY created_at DESC
             LIMIT ?",
            tenant_id,
            agent_id,
            rid,
            window_days,
            limit
        );
    }
    crate::fetch_all_as!(
        ThreatHuntDecisionEvidence,
        pool,
        "SELECT id, skill, action, run_id
         FROM decisions
         WHERE tenant_id = ? AND agent_id = ?
           AND created_at >= datetime('now', printf('-%d days', ?))
         ORDER BY created_at DESC
         LIMIT ?",
        tenant_id,
        agent_id,
        window_days,
        limit
    )
}

pub async fn has_open_threat_hunt_finding(
    pool: &DbPool,
    tenant_id: &str,
    agent_id: &str,
    finding_type: &str,
    fingerprint: &str,
) -> Result<bool, sqlx::Error> {
    let (count,): (i64,) = crate::fetch_one_as!(
        _,
        pool,
        "SELECT COUNT(*) FROM threat_hunt_findings
         WHERE tenant_id = ? AND agent_id = ? AND finding_type = ?
           AND fingerprint = ? AND status = 'open'",
        tenant_id,
        agent_id,
        finding_type,
        fingerprint
    )?;
    Ok(count > 0)
}

pub async fn insert_threat_hunt_finding(
    pool: &DbPool,
    record: &ThreatHuntFindingRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO threat_hunt_findings
            (id, tenant_id, agent_id, finding_type, fingerprint, severity, title,
             summary, evidence_json, status, hunter_agent, generated_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &record.id,
        &record.tenant_id,
        &record.agent_id,
        &record.finding_type,
        &record.fingerprint,
        &record.severity,
        &record.title,
        &record.summary,
        &record.evidence_json,
        &record.status,
        &record.hunter_agent,
        &record.generated_at,
        &record.created_at
    )?;
    Ok(())
}

pub async fn list_threat_hunt_findings(
    pool: &DbPool,
    tenant_id: &str,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<ThreatHuntFindingRecord>, sqlx::Error> {
    let limit = limit.clamp(1, SOC_MAX_LIMIT);
    if let Some(st) = status {
        return crate::fetch_all_as!(
            ThreatHuntFindingRecord,
            pool,
            "SELECT id, tenant_id, agent_id, finding_type, fingerprint, severity, title,
                    summary, evidence_json, status, hunter_agent, generated_at, created_at
             FROM threat_hunt_findings
             WHERE tenant_id = ? AND status = ?
             ORDER BY generated_at DESC
             LIMIT ?",
            tenant_id,
            st,
            limit
        );
    }
    crate::fetch_all_as!(
        ThreatHuntFindingRecord,
        pool,
        "SELECT id, tenant_id, agent_id, finding_type, fingerprint, severity, title,
                summary, evidence_json, status, hunter_agent, generated_at, created_at
         FROM threat_hunt_findings
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
    async fn aggregate_unusual_tool_combos_groups_by_run() {
        let pool = setup_pool("threat_hunt_combo").await;
        let tenant_id = "tenant_threat_hunt";
        register_tenant(&pool, tenant_id, "Tenant Threat Hunt", "developer")
            .await
            .unwrap();
        crate::execute_query!(
            &pool,
            "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
             VALUES ('ag_hunt', ?, 'key_hunt', 'tok_hunt', 'Agent Hunt', 'prod', 'high', 'active')",
            tenant_id
        )
        .unwrap();

        let now_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let tools = ["github", "aws", "slack", "jira"];
        for (i, tool) in tools.iter().enumerate() {
            crate::execute_query!(
                &pool,
                "INSERT INTO decisions (id, tenant_id, agent_id, run_id, skill, action, input_json, decision, created_at)
                 VALUES (?, ?, 'ag_hunt', 'run_combo_1', ?, 'read', '{}', 'allow', ?)",
                format!("dec-combo-{i}"),
                tenant_id,
                tool,
                &now_str
            )
            .unwrap();
        }

        let agg = aggregate_unusual_tool_combos(&pool, tenant_id, 30, 4)
            .await
            .unwrap();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].run_id, "run_combo_1");
        assert_eq!(agg[0].distinct_tools, 4);
    }
}
