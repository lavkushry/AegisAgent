use chrono::{DateTime, Utc};

/// Environment restriction check (#1391): returns Err if the agent is not
/// permitted to operate in the declared environment. NULL or empty means unrestricted.
pub fn validate_environment(
    allowed_environments_json: Option<&str>,
    declared_env: &str,
) -> Result<(), String> {
    if let Some(env_json) = allowed_environments_json {
        if let Ok(allowed) = serde_json::from_str::<Vec<String>>(env_json) {
            if !allowed.is_empty() && !allowed.contains(&declared_env.to_string()) {
                return Err(format!(
                    "agent not permitted in environment '{}'",
                    declared_env
                ));
            }
        }
    }
    Ok(())
}

/// Timestamp window check (#1306): returns Err if the request's timestamp is more
/// than 5 minutes (300 seconds) in the past or future relative to `now`.
pub fn validate_replay_timestamp(
    now: DateTime<Utc>,
    request_timestamp: Option<DateTime<Utc>>,
) -> Result<(), String> {
    if let Some(ts) = request_timestamp {
        let age_secs = (now - ts).num_seconds().abs();
        if age_secs > 300 {
            return Err("Request timestamp outside the acceptable window".to_string());
        }
    }
    Ok(())
}

/// Apply decision overrides and escalations based on action defaults, risk level,
/// and agent force-approval flags.
/// Returns the updated (decision, reason, matched_policies).
pub fn apply_decision_overrides(
    cedar_decision: String,
    mut reason: String,
    mut matched_policies: Vec<String>,
    risk_level: &str,
    force_approval: bool,
    action_default_decision: &str,
    action_approval_required: bool,
) -> (String, String, Vec<String>) {
    let mut decision_str = cedar_decision;

    if decision_str == "allow" {
        if action_default_decision == "deny" {
            decision_str = "deny".to_string();
            reason = "Registered action default decision is deny.".to_string();
            matched_policies.push("registered_action_default_deny".to_string());
        } else if action_default_decision == "require_approval" || action_approval_required {
            decision_str = "require_approval".to_string();
            reason = "Registered action requires approval.".to_string();
            matched_policies.push("registered_action_approval_required".to_string());
        }
    }

    // Enforce secure defaults (fail-closed)
    // If decision returns allow but action risk is critical, enforce require_approval by default if not set otherwise.
    if decision_str == "allow" && risk_level == "critical" {
        decision_str = "require_approval".to_string();
        reason = "Critical-risk action requires approval by default.".to_string();
        matched_policies.push("critical_risk_requires_approval".to_string());
    }

    // SOC Response Engine (#1184, Phase 4): a prior trust_escalation incident
    // set agents.force_approval for this agent. Downgrade allow -> require_approval
    // for every subsequent action until an operator clears it.
    if decision_str == "allow" && force_approval {
        decision_str = "require_approval".to_string();
        reason = "Agent requires approval for all actions following a trust escalation incident."
            .to_string();
        matched_policies.push("soc_response_force_approval".to_string());
    }

    (decision_str, reason, matched_policies)
}
