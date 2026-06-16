//! SOC Response Engine — auto-dispatch (Phase 4 completion, #1184).
//!
//! Maps a [`crate::correlate::Incident`] (Phase 3 output) to a deterministic
//! containment action. Called from `events::drain` after
//! `correlator.observe()` — strictly out-of-band (design law 3): never
//! touches the `/v1/authorize` hot path.
//!
//! Per-tenant kill switch: `tenants.auto_respond_enabled` (default `true`,
//! #1184). When disabled, `dispatch` is a no-op and returns `Ok(None)`.
//!
//! Verdict → action mapping (from the issue acceptance criteria):
//! - `deny_storm`         → freeze the agent (fail-closed containment).
//! - `data_exfil_pattern` → freeze the agent + critical notify.
//! - `trust_escalation`   → set `agents.force_approval`, so every future
//!   `allow` decision for this agent is downgraded to `require_approval`
//!   until an operator clears it.
//! - `runaway`            → freeze the agent (throttling would still allow
//!   the runaway loop to keep spending budget; freeze is the safe default).
//!
//! All actions are tenant-scoped and parameterized via `db.rs`. A response
//! action is recorded as an `audit_events` row by the caller (`events.rs`)
//! using the description returned here.

use crate::correlate::Incident;
use crate::db;
use sqlx::SqlitePool;

/// A containment action taken by the Response Engine for one incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseAction {
    /// Stable action identifier, e.g. `"agent_frozen"`, `"force_approval_enabled"`.
    pub action: String,
    /// Human-readable, secret-free description for the audit log (redaction
    /// invariant — no payloads, only ids and the incident summary).
    pub description: String,
    /// `true` if this action warrants a CRITICAL-severity notification
    /// (currently only `data_exfil_pattern`).
    pub critical_notify: bool,
}

/// Pure mapping from `incident.kind` to the [`ResponseAction`] the Response
/// Engine would take, with no database side effects. Used by:
/// - [`dispatch`], which executes the corresponding mutation, and
/// - the SOC-002 (#1185) `L2` "notify + recommend" autonomy level, which
///   logs this recommendation without ever calling [`dispatch`].
///
/// Returns `None` if `incident.kind` has no mapped response (e.g.
/// `repeated_approval`).
pub fn recommended_action(incident: &Incident) -> Option<ResponseAction> {
    match incident.kind.as_str() {
        "deny_storm" | "runaway" => Some(ResponseAction {
            action: "agent_frozen".to_string(),
            description: format!(
                "Auto-froze agent {} in response to {} incident {}: {}",
                incident.agent_id, incident.kind, incident.incident_id, incident.summary
            ),
            critical_notify: false,
        }),
        "data_exfil_pattern" => Some(ResponseAction {
            action: "agent_frozen".to_string(),
            description: format!(
                "Auto-froze agent {} in response to data_exfil_pattern incident {}: {}",
                incident.agent_id, incident.incident_id, incident.summary
            ),
            critical_notify: true,
        }),
        "trust_escalation" => Some(ResponseAction {
            action: "force_approval_enabled".to_string(),
            description: format!(
                "Enabled force_approval for agent {} in response to trust_escalation incident {}: {}",
                incident.agent_id, incident.incident_id, incident.summary
            ),
            critical_notify: false,
        }),
        _ => None,
    }
}

/// Dispatch the deterministic response for `incident`, if any.
///
/// Returns `Ok(None)` if:
/// - auto-respond is disabled for `incident.tenant_id`, or
/// - `incident.kind` has no mapped response (e.g. `repeated_approval`).
///
/// Database errors propagate to the caller, which logs and discards them
/// (best-effort, out-of-band — design law 3).
pub async fn dispatch(
    pool: &SqlitePool,
    incident: &Incident,
) -> Result<Option<ResponseAction>, sqlx::Error> {
    if !db::is_auto_respond_enabled(pool, &incident.tenant_id).await? {
        return Ok(None);
    }

    let action = match recommended_action(incident) {
        Some(action) => action,
        None => return Ok(None),
    };

    match action.action.as_str() {
        "agent_frozen" => freeze_agent(pool, incident).await?,
        "force_approval_enabled" => {
            db::set_agent_force_approval(pool, &incident.tenant_id, &incident.agent_id, true)
                .await?;
        }
        _ => {}
    }

    Ok(Some(action))
}

async fn freeze_agent(pool: &SqlitePool, incident: &Incident) -> Result<(), sqlx::Error> {
    db::set_agent_status(pool, &incident.tenant_id, &incident.agent_id, "frozen").await?;
    db::set_agent_frozen_reason(
        pool,
        &incident.tenant_id,
        &incident.agent_id,
        Some(&format!(
            "auto-response: {} incident {}",
            incident.kind, incident.incident_id
        )),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn make_incident(tenant_id: &str, agent_id: &str, kind: &str) -> Incident {
        // Incident's fields are all public; constructed via JSON round-trip
        // since `Incident::new` is private to `correlate`.
        let json = serde_json::json!({
            "incident_id": uuid::Uuid::new_v4().to_string(),
            "opened_at": chrono::Utc::now().to_rfc3339(),
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "kind": kind,
            "severity": "high",
            "summary": format!("{kind} detected"),
            "source_event_ids": ["evt_1", "evt_2"],
        });
        serde_json::from_value(json).unwrap()
    }

    async fn setup(test_name: &str) -> (SqlitePool, String, String) {
        let db_url = format!("sqlite://target/test_respond_{}.db", test_name);
        let _ = std::fs::remove_file(db_url.strip_prefix("sqlite://").unwrap());
        let pool = db::init_db(&db_url).await.unwrap();
        let tenant_id = format!("tenant_respond_{test_name}");
        db::register_tenant(&pool, &tenant_id, "Respond Tenant", "developer")
            .await
            .unwrap();

        let agent = crate::models::AgentRecord {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "respond-agent".to_string(),
            agent_token: uuid::Uuid::new_v4().to_string(),
            name: "Respond Agent".to_string(),
            owner_team: None,
            owner_email: None,
            environment: "test".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "low".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            quarantined_at: None,
            force_approval: false,
            signing_key: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        db::insert_agent(&pool, &agent).await.unwrap();

        (pool, tenant_id, agent.id)
    }

    #[tokio::test]
    async fn deny_storm_freezes_agent() {
        let (pool, tenant_id, agent_id) = setup("deny_storm").await;
        let incident = make_incident(&tenant_id, &agent_id, "deny_storm");

        let action = dispatch(&pool, &incident).await.unwrap().unwrap();
        assert_eq!(action.action, "agent_frozen");
        assert!(!action.critical_notify);

        let agent = db::get_agent_by_id(&pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "frozen");
        assert!(agent.frozen_reason.unwrap().contains("deny_storm"));
    }

    #[tokio::test]
    async fn runaway_freezes_agent() {
        let (pool, tenant_id, agent_id) = setup("runaway").await;
        let incident = make_incident(&tenant_id, &agent_id, "runaway");

        let action = dispatch(&pool, &incident).await.unwrap().unwrap();
        assert_eq!(action.action, "agent_frozen");

        let agent = db::get_agent_by_id(&pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "frozen");
    }

    #[tokio::test]
    async fn data_exfil_pattern_freezes_agent_and_requests_critical_notify() {
        let (pool, tenant_id, agent_id) = setup("data_exfil").await;
        let incident = make_incident(&tenant_id, &agent_id, "data_exfil_pattern");

        let action = dispatch(&pool, &incident).await.unwrap().unwrap();
        assert_eq!(action.action, "agent_frozen");
        assert!(action.critical_notify);

        let agent = db::get_agent_by_id(&pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "frozen");
    }

    #[tokio::test]
    async fn trust_escalation_sets_force_approval() {
        let (pool, tenant_id, agent_id) = setup("trust_escalation").await;
        let incident = make_incident(&tenant_id, &agent_id, "trust_escalation");

        let action = dispatch(&pool, &incident).await.unwrap().unwrap();
        assert_eq!(action.action, "force_approval_enabled");

        let agent = db::get_agent_by_id(&pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert!(agent.force_approval);
        // Agent is not frozen by this response.
        assert_eq!(agent.status, "active");
    }

    #[tokio::test]
    async fn unmapped_incident_kind_is_noop() {
        let (pool, tenant_id, agent_id) = setup("repeated_approval").await;
        let incident = make_incident(&tenant_id, &agent_id, "repeated_approval");

        let action = dispatch(&pool, &incident).await.unwrap();
        assert!(action.is_none());

        let agent = db::get_agent_by_id(&pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "active");
    }

    #[tokio::test]
    async fn auto_respond_disabled_is_noop() {
        let (pool, tenant_id, agent_id) = setup("disabled").await;
        sqlx::query("UPDATE tenants SET auto_respond_enabled = 0 WHERE id = ?")
            .bind(&tenant_id)
            .execute(&pool)
            .await
            .unwrap();

        let incident = make_incident(&tenant_id, &agent_id, "deny_storm");
        let action = dispatch(&pool, &incident).await.unwrap();
        assert!(action.is_none());

        let agent = db::get_agent_by_id(&pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "active");
    }

    /// SOC-002 (#1185): `recommended_action` is the pure mapping used by the
    /// `L2` ("notify + recommend") autonomy level. It must report the same
    /// action `dispatch` would take, without performing any DB mutation.
    #[tokio::test]
    async fn recommended_action_matches_dispatch_without_side_effects() {
        let (pool, tenant_id, agent_id) = setup("recommend_only").await;
        let incident = make_incident(&tenant_id, &agent_id, "deny_storm");

        let recommended = recommended_action(&incident).unwrap();
        assert_eq!(recommended.action, "agent_frozen");

        let agent = db::get_agent_by_id(&pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            agent.status, "active",
            "recommend-only must not mutate state"
        );
    }

    #[test]
    fn recommended_action_unmapped_incident_kind_returns_none() {
        let incident = make_incident("tenant_x", "agent_x", "repeated_approval");
        assert!(recommended_action(&incident).is_none());
    }
}
