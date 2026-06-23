use aegis_api::models::*;
use sqlx::SqlitePool;

pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Rotate an agent's token: persist the SHA-256 hash of `new_token`,
/// scoped by `tenant_id` and `agent_id` (CWE-284 tenant isolation).
pub async fn rotate_agent_token(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    new_token: &str,
) -> Result<(), sqlx::Error> {
    let hashed = hash_token(new_token);
    sqlx::query("UPDATE agents SET agent_token = ?, updated_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND id = ?")
        .bind(hashed)
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// #1193: also excludes `status = 'deleted'` (alongside the pre-existing
/// `quarantined` exclusion) — a deleted agent's token must stop resolving
/// to anything at all, rather than relying on `authorize_action`'s
/// frozen/revoked status check, which never accounted for "deleted" and so
/// let a deleted agent's calls proceed unchallenged.
pub async fn get_agent_by_token(
    pool: &SqlitePool,
    tenant_id: &str,
    token: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    let hashed = hash_token(token);
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? AND agent_token = ? AND status NOT IN ('quarantined', 'deleted')",
    )
    .bind(tenant_id)
    .bind(hashed)
    .fetch_optional(pool)
    .await
}

pub async fn migrate_agent_tokens(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let agents = sqlx::query("SELECT id, agent_token FROM agents")
        .fetch_all(pool)
        .await?;

    for row in agents {
        use sqlx::Row;
        let id: String = row.get("id");
        let token: String = row.get("agent_token");

        let is_hash = token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit());
        if !is_hash {
            let hashed = hash_token(&token);
            sqlx::query("UPDATE agents SET agent_token = ? WHERE id = ?")
                .bind(hashed)
                .bind(id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

pub async fn get_agent_by_key(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_key: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>("SELECT * FROM agents WHERE tenant_id = ? AND agent_key = ?")
        .bind(tenant_id)
        .bind(agent_key)
        .fetch_optional(pool)
        .await
}

/// Resolve an agent by its bound mTLS client-certificate Subject CN (#1310).
/// Mirrors `get_agent_by_token`'s fail-closed quarantine filter — an mTLS
/// identity is an authentication path equivalent to a bearer token, so a
/// quarantined agent must not be reachable through it either.
/// #1193: same `deleted` exclusion as [`get_agent_by_token`] — this is the
/// other (mTLS) path to the same `authorize_action`, so it must fail closed
/// identically for a deleted agent.
pub async fn get_agent_by_mtls_cn(
    pool: &SqlitePool,
    tenant_id: &str,
    cn: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? AND mtls_cn = ? AND status NOT IN ('quarantined', 'deleted')",
    )
    .bind(tenant_id)
    .bind(cn)
    .fetch_optional(pool)
    .await
}

/// #1145: `?status=` field filtering. When `status_filter` is `None`, the
/// default soft-delete exclusion (`status != 'deleted'`) applies, matching
/// pre-#1145 behavior; when set, it's an exact match instead (so explicitly
/// requesting `status=deleted` is honored rather than always hidden).
pub async fn list_agents(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
    status_filter: Option<&str>,
) -> Result<Vec<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents
         WHERE tenant_id = ?
           AND (
             (? IS NULL AND status != 'deleted')
             OR status = ?
           )
         ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(status_filter)
    .bind(status_filter)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn get_agent_by_id(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>(
        "SELECT * FROM agents WHERE tenant_id = ? AND id = ? AND status != 'deleted'",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Like [`get_agent_by_id`], but also returns soft-deleted agents
/// (`status = 'deleted'`). Used by evidence-graph queries (#1327) so that
/// historical decisions/incidents triggered by an agent still render an
/// `Agent` node — and the edges pointing at it — after the agent is deleted,
/// rather than leaving a dangling edge reference.
pub async fn get_agent_by_id_any_status(
    pool: &SqlitePool,
    tenant_id: &str,
    id: &str,
) -> Result<Option<AgentRecord>, sqlx::Error> {
    sqlx::query_as::<_, AgentRecord>("SELECT * FROM agents WHERE tenant_id = ? AND id = ?")
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// #1290: rolling 24h average `composite_risk_score` per agent, ranked
/// highest-first, for the dashboard's Agent Risk Scoreboard. Compares against
/// the prior 24h window (24-48h ago) to derive a `trend`:
/// - `"stable"` if there's no current-window activity or no prior-window
///   baseline to compare against (insufficient data, not a real signal).
/// - `"rising"` / `"falling"` if the average moved by more than 5 points
///   (out of the 0-100 composite scale) — a small threshold to avoid
///   flapping between rising/falling on noise from a couple of decisions.
///
/// Agents with zero decisions in the last 24h still appear (LEFT JOIN), with
/// `current_avg_risk_score: 0.0` and `decision_count_24h: 0`. Tenant-scoped,
/// parameterized.
type RiskScoreboardRow = (String, String, Option<f64>, i64, Option<f64>);

pub async fn get_agent_risk_scoreboard(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<Vec<AgentRiskScoreboardEntry>, sqlx::Error> {
    let rows: Vec<RiskScoreboardRow> = sqlx::query_as(
        "SELECT a.id, a.agent_key, cur.avg_score, COALESCE(cur.decision_count, 0), prev.avg_score
         FROM agents a
         LEFT JOIN (
             SELECT agent_id, AVG(composite_risk_score) AS avg_score, COUNT(*) AS decision_count
             FROM decisions
             WHERE tenant_id = ? AND composite_risk_score IS NOT NULL
                 AND created_at >= datetime('now', '-24 hours')
             GROUP BY agent_id
         ) cur ON cur.agent_id = a.id
         LEFT JOIN (
             SELECT agent_id, AVG(composite_risk_score) AS avg_score
             FROM decisions
             WHERE tenant_id = ? AND composite_risk_score IS NOT NULL
                 AND created_at >= datetime('now', '-48 hours')
                 AND created_at < datetime('now', '-24 hours')
             GROUP BY agent_id
         ) prev ON prev.agent_id = a.id
         WHERE a.tenant_id = ? AND a.status != 'deleted'
         ORDER BY COALESCE(cur.avg_score, 0) DESC",
    )
    .bind(tenant_id)
    .bind(tenant_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(agent_id, agent_key, current_avg, decision_count_24h, previous_avg)| {
                let current_avg_risk_score = current_avg.unwrap_or(0.0);
                let trend = match (decision_count_24h, previous_avg) {
                    (0, _) | (_, None) => "stable",
                    (_, Some(prev)) => {
                        let delta = current_avg_risk_score - prev;
                        if delta > 5.0 {
                            "rising"
                        } else if delta < -5.0 {
                            "falling"
                        } else {
                            "stable"
                        }
                    }
                }
                .to_string();

                AgentRiskScoreboardEntry {
                    agent_id,
                    agent_key,
                    current_avg_risk_score,
                    decision_count_24h,
                    trend,
                }
            },
        )
        .collect())
}

pub async fn insert_agent(pool: &SqlitePool, record: &AgentRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, owner_team, owner_email, environment, framework, model_provider, model_name, purpose, risk_tier, status, signing_key, allowed_environments, mtls_cn)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&record.id)
    .bind(&record.tenant_id)
    .bind(&record.agent_key)
    .bind(&record.agent_token)
    .bind(&record.name)
    .bind(&record.owner_team)
    .bind(&record.owner_email)
    .bind(&record.environment)
    .bind(&record.framework)
    .bind(&record.model_provider)
    .bind(&record.model_name)
    .bind(&record.purpose)
    .bind(&record.risk_tier)
    .bind(&record.status)
    .bind(&record.signing_key)
    .bind(&record.allowed_environments)
    .bind(&record.mtls_cn)
    .execute(pool)
    .await?;
    Ok(())
}

pub fn verify_request_signature(signing_key: &str, body: &[u8], sig_header: &str) -> bool {
    aegis_common::hash::verify_request_signature(signing_key, body, sig_header)
}

pub async fn update_agent(pool: &SqlitePool, record: &AgentRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agents SET
            name = ?,
            owner_team = ?,
            owner_email = ?,
            environment = ?,
            framework = ?,
            model_provider = ?,
            model_name = ?,
            purpose = ?,
            risk_tier = ?,
            status = ?,
            mtls_cn = ?,
            updated_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(&record.name)
    .bind(&record.owner_team)
    .bind(&record.owner_email)
    .bind(&record.environment)
    .bind(&record.framework)
    .bind(&record.model_provider)
    .bind(&record.model_name)
    .bind(&record.purpose)
    .bind(&record.risk_tier)
    .bind(&record.status)
    .bind(&record.mtls_cn)
    .bind(&record.tenant_id)
    .bind(&record.id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_skill(
    pool: &SqlitePool,
    tenant_id: &str,
    skill_key: &str,
    name: &str,
    r#type: &str,
    auth_type: Option<&str>,
    owner_team: Option<&str>,
    default_risk: Option<&str>,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO skills (id, tenant_id, skill_key, name, type, auth_type, owner_team, default_risk)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(tenant_id, skill_key) DO UPDATE SET name=excluded.name, type=excluded.type, auth_type=excluded.auth_type, owner_team=excluded.owner_team, default_risk=excluded.default_risk"
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(skill_key)
    .bind(name)
    .bind(r#type)
    .bind(auth_type)
    .bind(owner_team)
    .bind(default_risk)
    .execute(pool)
    .await?;

    let row: (String,) =
        sqlx::query_as("SELECT id FROM skills WHERE tenant_id = ? AND skill_key = ?")
            .bind(tenant_id)
            .bind(skill_key)
            .fetch_one(pool)
            .await?;

    Ok(row.0)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_skill_action(
    pool: &SqlitePool,
    skill_id: &str,
    action_key: &str,
    description: Option<&str>,
    risk: &str,
    mutates_state: bool,
    data_access: Option<&str>,
    approval_required: bool,
    default_decision: &str,
) -> Result<(), sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO skill_actions (id, skill_id, action_key, description, risk, mutates_state, data_access, approval_required, default_decision)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(skill_id, action_key) DO UPDATE SET description=excluded.description, risk=excluded.risk, mutates_state=excluded.mutates_state, data_access=excluded.data_access, approval_required=excluded.approval_required, default_decision=excluded.default_decision"
    )
    .bind(&id)
    .bind(skill_id)
    .bind(action_key)
    .bind(description)
    .bind(risk)
    .bind(mutates_state)
    .bind(data_access)
    .bind(approval_required)
    .bind(default_decision)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_skill_action(
    pool: &SqlitePool,
    tenant_id: &str,
    skill_key: &str,
    action_key: &str,
) -> Result<Option<SkillActionRecord>, sqlx::Error> {
    sqlx::query_as::<_, SkillActionRecord>(
        "SELECT sa.*
         FROM skill_actions sa
         JOIN skills s ON sa.skill_id = s.id
         WHERE s.tenant_id = ? AND s.skill_key = ? AND sa.action_key = ?",
    )
    .bind(tenant_id)
    .bind(skill_key)
    .bind(action_key)
    .fetch_optional(pool)
    .await
}

/// --- SOC Phase 4: Response API ---
///
/// Set an agent's operational status (active | frozen | revoked).
/// Frozen agents are denied on the next authorize call automatically (the
/// authorize handler re-reads `agents.status` on every request).
/// Parameterized and tenant-scoped — never touches another tenant's row.
/// Updates `agents.status` and the lifecycle columns (#0078-#0080) it implies:
/// `quarantined_at` is set to now when entering `quarantined` and cleared on any
/// other status; `frozen_reason` is cleared whenever the new status isn't
/// `frozen` (set separately via [`set_agent_frozen_reason`]).
pub async fn set_agent_status(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE agents SET status = ?, updated_at = CURRENT_TIMESTAMP,
         quarantined_at = CASE WHEN ? = 'quarantined' THEN CURRENT_TIMESTAMP ELSE NULL END,
         frozen_reason = CASE WHEN ? = 'frozen' THEN frozen_reason ELSE NULL END
         WHERE tenant_id = ? AND id = ?",
    )
    .bind(status)
    .bind(status)
    .bind(status)
    .bind(tenant_id)
    .bind(agent_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Records the operator-supplied reason for a freeze (#0079). Tenant-scoped;
/// no-op if the agent doesn't belong to this tenant.
pub async fn set_agent_frozen_reason(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agents SET frozen_reason = ? WHERE tenant_id = ? AND id = ?")
        .bind(reason)
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set or clear `agents.force_approval` (#1184, Phase 4 response engine).
/// While `true`, the authorize handler downgrades every otherwise-`allow`
/// decision for this agent to `require_approval` (set in `routes.rs`).
/// Tenant-scoped; no-op if the agent doesn't belong to this tenant.
pub async fn set_agent_force_approval(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    value: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agents SET force_approval = ? WHERE tenant_id = ? AND id = ?")
        .bind(value)
        .bind(tenant_id)
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Heartbeat (#0080): records the timestamp of an agent's most recent successful
/// `/v1/authorize` call. Tenant-scoped, parameterized, best-effort (callers
/// should not fail the request if this errors).
pub async fn touch_agent_last_seen(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agents SET last_seen_at = CURRENT_TIMESTAMP WHERE tenant_id = ? AND id = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Check whether an agent is currently active (not frozen or revoked).
/// Called by the authorize hot path — must be fast (indexed on tenant_id).
#[allow(dead_code)] // Reserved for authorize hot-path status check (PR-043 follow-up)
pub async fn is_agent_active(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT status FROM agents WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(agent_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(s,)| s == "active").unwrap_or(false))
}

// ── Agent-to-tool permission bindings (#1390) ─────────────────────────────────

/// Grant a tool permission for an agent. Idempotent — a duplicate (tenant_id,
/// agent_id, tool_key) triple is silently ignored (UNIQUE constraint).
pub async fn grant_agent_tool_permission(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    tool_key: &str,
) -> Result<aegis_api::models::AgentToolPermission, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now_str = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO agent_tool_permissions (id, tenant_id, agent_id, tool_key, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(agent_id)
    .bind(tool_key)
    .bind(&now_str)
    .execute(pool)
    .await?;

    let row = sqlx::query_as::<_, aegis_api::models::AgentToolPermission>(
        "SELECT id, tenant_id, agent_id, tool_key, created_at FROM agent_tool_permissions WHERE tenant_id = ? AND agent_id = ? AND tool_key = ?"
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(tool_key)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Return all tool permissions for `agent_id` within `tenant_id`.
pub async fn get_agent_tool_permissions(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
) -> Result<Vec<aegis_api::models::AgentToolPermission>, sqlx::Error> {
    sqlx::query_as::<_, aegis_api::models::AgentToolPermission>(
        "SELECT id, tenant_id, agent_id, tool_key, created_at
         FROM agent_tool_permissions
         WHERE tenant_id = ? AND agent_id = ?
         ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_all(pool)
    .await
}

/// Revoke a single tool permission. Returns `true` if a row was deleted.
pub async fn revoke_agent_tool_permission(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    tool_key: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM agent_tool_permissions
         WHERE tenant_id = ? AND agent_id = ? AND tool_key = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(tool_key)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Check whether `agent_id` is permitted to call `tool_key` in `tenant_id`.
///
/// - `None` — no permissions configured for this agent; unrestricted
///   (backwards-compatible with pre-#1390 agents).
/// - `Some(true)` — the specific tool is in the agent's allow-list.
/// - `Some(false)` — permissions exist but this tool is not allowed (deny).
pub async fn agent_tool_permission_status(
    pool: &SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    tool_key: &str,
) -> Result<Option<bool>, sqlx::Error> {
    // First check if any permission rows exist for this agent.
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM agent_tool_permissions WHERE tenant_id = ? AND agent_id = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_one(pool)
    .await?;

    if count.0 == 0 {
        return Ok(None); // unrestricted
    }

    // Permissions exist — check if this specific tool is allowed.
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM agent_tool_permissions
         WHERE tenant_id = ? AND agent_id = ? AND tool_key = ?",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(tool_key)
    .fetch_one(pool)
    .await?;

    Ok(Some(row.0 > 0))
}

#[cfg(test)]
mod tests {
    use crate::db::test_utils::*;
    use crate::db::*;
    use aegis_api::models::AgentRecord;

    /// `list_soc_alerts` with `agent_id=Some(...)` returns only alerts matching
    /// that agent — and never another tenant's rows.
    #[tokio::test]
    async fn list_soc_alerts_agent_id_filter_and_isolation() {
        let pool = setup_pool("alerts_agent_filter").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        insert_soc_alert(
            &pool,
            &make_alert_with("al_a1", "tenant_a", "high", "agent_target"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_a2", "tenant_a", "low", "agent_other"),
        )
        .await
        .unwrap();
        insert_soc_alert(
            &pool,
            &make_alert_with("al_b1", "tenant_b", "high", "agent_target"),
        )
        .await
        .unwrap();

        let target_alerts = list_soc_alerts(&pool, "tenant_a", 50, 0, None, Some("agent_target"))
            .await
            .unwrap();
        assert_eq!(target_alerts.len(), 1);
        assert_eq!(target_alerts[0].id, "al_a1");
        assert_eq!(target_alerts[0].tenant_id, "tenant_a");

        // Combined severity + agent_id filter.
        let combined =
            list_soc_alerts(&pool, "tenant_a", 50, 0, Some("high"), Some("agent_target"))
                .await
                .unwrap();
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].id, "al_a1");
    }

    /// `list_soc_incidents` with `severity` and `agent_id` filters returns only
    /// matching incidents for the tenant.
    #[tokio::test]
    async fn list_soc_incidents_severity_and_agent_filters() {
        let pool = setup_pool("incidents_filters").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        register_tenant(&pool, "tenant_b", "Tenant B", "developer")
            .await
            .unwrap();

        insert_soc_incident(
            &pool,
            &make_incident_with("inc_a_h1", "tenant_a", "high", "agent_alpha"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("inc_a_h2", "tenant_a", "high", "agent_beta"),
        )
        .await
        .unwrap();
        insert_soc_incident(
            &pool,
            &make_incident_with("inc_a_l1", "tenant_a", "low", "agent_alpha"),
        )
        .await
        .unwrap();
        // Tenant B — must be isolated.
        insert_soc_incident(
            &pool,
            &make_incident_with("inc_b_h1", "tenant_b", "high", "agent_alpha"),
        )
        .await
        .unwrap();

        let high_a = list_soc_incidents(&pool, "tenant_a", 50, 0, None, Some("high"), None)
            .await
            .unwrap();
        assert_eq!(high_a.len(), 2);
        assert!(high_a.iter().all(|i| i.severity == "high"));
        assert!(high_a.iter().all(|i| i.tenant_id == "tenant_a"));

        let alpha_a = list_soc_incidents(&pool, "tenant_a", 50, 0, None, None, Some("agent_alpha"))
            .await
            .unwrap();
        assert_eq!(alpha_a.len(), 2);
        assert!(alpha_a.iter().all(|i| i.agent_id == "agent_alpha"));

        // Status + severity combined.
        let open_high =
            list_soc_incidents(&pool, "tenant_a", 50, 0, Some("open"), Some("high"), None)
                .await
                .unwrap();
        assert_eq!(open_high.len(), 2);
    }

    /// #1290: `get_agent_risk_scoreboard` ranks agents by rolling 24h average
    /// `composite_risk_score` (highest first), derives a trend against the
    /// prior 24h window, and still lists agents with zero recent decisions.
    #[tokio::test]
    async fn get_agent_risk_scoreboard_ranks_and_derives_trend() {
        let pool = init_db("sqlite::memory:").await.unwrap();
        register_tenant(&pool, "tenant_scoreboard", "Scoreboard Tenant", "developer")
            .await
            .unwrap();
        for (id, key) in [
            ("agent_rising", "agent_rising"),
            ("agent_falling", "agent_falling"),
            ("agent_idle", "agent_idle"),
        ] {
            sqlx::query(
                "INSERT INTO agents (id, tenant_id, agent_key, agent_token, name, environment, risk_tier, status)
                 VALUES (?, 'tenant_scoreboard', ?, ?, 'Scoreboard Agent', 'dev', 'low', 'active')",
            )
            .bind(id)
            .bind(key)
            .bind(format!("token_{id}"))
            .execute(&pool)
            .await
            .unwrap();
        }

        // agent_rising: current-window avg 90 (two decisions: 80, 100),
        // prior-window avg 50 (one decision) -> delta +40 -> rising.
        for (dec_id, score) in [("dec_r1", 80), ("dec_r2", 100)] {
            let mut d = graph_perf_decision(dec_id, "tenant_scoreboard");
            d.agent_id = "agent_rising".to_string();
            d.composite_risk_score = Some(score);
            insert_decision(&pool, &d).await.unwrap();
        }
        let mut prior_rising = graph_perf_decision("dec_r_prior", "tenant_scoreboard");
        prior_rising.agent_id = "agent_rising".to_string();
        prior_rising.composite_risk_score = Some(50);
        insert_decision(&pool, &prior_rising).await.unwrap();
        sqlx::query("UPDATE decisions SET created_at = datetime('now', '-30 hours') WHERE id = 'dec_r_prior'")
            .execute(&pool)
            .await
            .unwrap();

        // agent_falling: current-window avg 10, prior-window avg 80 ->
        // delta -70 -> falling.
        let mut cur_falling = graph_perf_decision("dec_f1", "tenant_scoreboard");
        cur_falling.agent_id = "agent_falling".to_string();
        cur_falling.composite_risk_score = Some(10);
        insert_decision(&pool, &cur_falling).await.unwrap();
        let mut prior_falling = graph_perf_decision("dec_f_prior", "tenant_scoreboard");
        prior_falling.agent_id = "agent_falling".to_string();
        prior_falling.composite_risk_score = Some(80);
        insert_decision(&pool, &prior_falling).await.unwrap();
        sqlx::query("UPDATE decisions SET created_at = datetime('now', '-30 hours') WHERE id = 'dec_f_prior'")
            .execute(&pool)
            .await
            .unwrap();

        // agent_idle: no decisions at all.

        let board = get_agent_risk_scoreboard(&pool, "tenant_scoreboard")
            .await
            .unwrap();
        assert_eq!(
            board.len(),
            3,
            "all 3 agents listed, including the idle one"
        );

        // Ranked highest-current-avg first: rising (90) > falling (10) > idle (0).
        assert_eq!(board[0].agent_key, "agent_rising");
        assert!((board[0].current_avg_risk_score - 90.0).abs() < 0.01);
        assert_eq!(board[0].decision_count_24h, 2);
        assert_eq!(board[0].trend, "rising");

        assert_eq!(board[1].agent_key, "agent_falling");
        assert!((board[1].current_avg_risk_score - 10.0).abs() < 0.01);
        assert_eq!(board[1].trend, "falling");

        assert_eq!(board[2].agent_key, "agent_idle");
        assert_eq!(board[2].current_avg_risk_score, 0.0);
        assert_eq!(board[2].decision_count_24h, 0);
        assert_eq!(board[2].trend, "stable");
    }

    fn make_test_agent(
        id: &str,
        tenant_id: &str,
        agent_key: &str,
        plaintext_token: &str,
    ) -> AgentRecord {
        AgentRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            agent_key: agent_key.to_string(),
            agent_token: hash_token(plaintext_token),
            name: "Test Agent".to_string(),
            owner_team: None,
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "low".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            mtls_cn: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// #1193: a deleted agent's token must stop resolving entirely, not
    /// just continue past `authorize_action`'s frozen/revoked status check
    /// (which never accounted for "deleted") unchallenged. Regression test
    /// for the gap discovered while implementing soft-delete for #1193 —
    /// `get_agent_by_token` already excluded `quarantined` but not `deleted`.
    #[tokio::test]
    async fn get_agent_by_token_excludes_deleted_agents() {
        let pool = setup_pool("agent_token_excludes_deleted").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        let agent = make_test_agent("agent_del", "tenant_a", "agent-del-key", "plaintext-tok");
        insert_agent(&pool, &agent).await.unwrap();

        // Active: resolves.
        assert!(get_agent_by_token(&pool, "tenant_a", "plaintext-tok")
            .await
            .unwrap()
            .is_some());

        set_agent_status(&pool, "tenant_a", "agent_del", "deleted")
            .await
            .unwrap();

        // Deleted: must no longer resolve via its token.
        assert!(
            get_agent_by_token(&pool, "tenant_a", "plaintext-tok")
                .await
                .unwrap()
                .is_none(),
            "a deleted agent's token must not resolve to an agent"
        );
    }

    /// #1193: same gap, mTLS auth path.
    #[tokio::test]
    async fn get_agent_by_mtls_cn_excludes_deleted_agents() {
        let pool = setup_pool("agent_mtls_excludes_deleted").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        let mut agent = make_test_agent("agent_del_mtls", "tenant_a", "agent-del-mtls-key", "tok2");
        agent.mtls_cn = Some("client.example.com".to_string());
        insert_agent(&pool, &agent).await.unwrap();

        assert!(
            get_agent_by_mtls_cn(&pool, "tenant_a", "client.example.com")
                .await
                .unwrap()
                .is_some()
        );

        set_agent_status(&pool, "tenant_a", "agent_del_mtls", "deleted")
            .await
            .unwrap();

        assert!(
            get_agent_by_mtls_cn(&pool, "tenant_a", "client.example.com")
                .await
                .unwrap()
                .is_none(),
            "a deleted agent's mTLS CN must not resolve to an agent"
        );
    }
}
