//! Guard phase after preflight (library-owned).
//!
//! Frozen/revoked agent, optional admission webhook, action-hash binding,
//! and ban/quarantine enforcement. Early denials are persisted through the
//! host [`DecisionRuntime::write_decision_and_audit`] port (including dry-run
//! score-only path). On success returns a [`GuardedAuthorize`] for skill/MCP
//! metadata (`metadata_authorize`) then Cedar evaluation (`evaluate_authorize`).

use aegis_api::models::{AuthorizeRequest, AuthorizeResponse};
use tracing::error;
use uuid::Uuid;

use crate::agent::AuthorizeAgent;
use crate::error_map::aegis_err_to_outcome;
use crate::outcome::DecisionOutcome;
use crate::preflight::PreflightedAuthorize;
use crate::runtime::{AdmissionEffect, DecisionRuntime, EnforcementStatus};
use crate::write::DecisionAuditWrite;

/// Preflighted request that passed frozen/webhook/ban guards.
#[derive(Debug, Clone)]
pub struct GuardedAuthorize {
    pub request: AuthorizeRequest,
    pub agent: AuthorizeAgent,
    pub root_trust_level: String,
    pub dry_run: bool,
    pub used_mtls: bool,
    pub normalized_tool: String,
    pub normalized_action: String,
    /// SHA-256 of the final (post-webhook) tool call (`aegis-jcs-1`).
    pub action_hash: String,
}

/// MCP tool prefix used for audit event typing.
pub fn mcp_server_key_from_tool(tool: &str) -> Option<&str> {
    tool.strip_prefix("mcp:")
        .filter(|server_key| !server_key.is_empty())
}

fn audit_event_type(normalized_tool: &str) -> &'static str {
    if mcp_server_key_from_tool(normalized_tool).is_some() {
        "mcp_tool_called"
    } else {
        "tool_call_intercepted"
    }
}

#[allow(clippy::too_many_arguments)]
async fn persist_early_deny(
    runtime: &dyn DecisionRuntime,
    request: &AuthorizeRequest,
    agent: &AuthorizeAgent,
    root_trust_level: &str,
    dry_run: bool,
    normalized_tool: &str,
    started_at: std::time::Instant,
    reason: String,
    matched_policies: Vec<String>,
    action_hash: &str,
) -> Result<DecisionOutcome, DecisionOutcome> {
    let decision_id = Uuid::new_v4();
    let risk_score = 100;
    let risk_level = "critical".to_string();
    let audit_event_type = audit_event_type(normalized_tool);
    let write = DecisionAuditWrite {
        tenant_id: &agent.tenant_id,
        agent_id: &agent.id,
        request,
        decision_id,
        decision: "deny",
        risk_score,
        reason: &reason,
        matched_policies: &matched_policies,
        audit_event_type,
        started_at,
        dry_run,
        action_hash,
        root_trust_level,
    };
    let composite_risk_score = match runtime.write_decision_and_audit(write).await {
        Ok(score) => score,
        Err(e) => {
            error!("Failed to write early denial: {:?}", e);
            return Err(aegis_err_to_outcome(e));
        }
    };
    Ok(DecisionOutcome::decision(AuthorizeResponse {
        decision_id,
        decision: "deny".to_string(),
        risk_score,
        risk_level,
        composite_risk_score,
        reason,
        matched_policies,
        approval: None,
        redacted_fields: vec![],
        root_trust_level: root_trust_level.to_string(),
        dry_run,
        receipt: None,
    }))
}

/// Run frozen / admission-webhook / ban-quarantine guards after preflight.
pub async fn guard_authorize(
    runtime: &dyn DecisionRuntime,
    preflighted: PreflightedAuthorize,
    started_at: std::time::Instant,
) -> Result<GuardedAuthorize, DecisionOutcome> {
    let mut request = preflighted.request;
    let agent = preflighted.agent;
    let root_trust_level = preflighted.root_trust_level;
    let dry_run = preflighted.dry_run;
    let used_mtls = preflighted.used_mtls;
    let normalized_tool = preflighted.normalized_tool;
    let normalized_action = preflighted.normalized_action;

    // Frozen / revoked agent (TASK-0014) — fail-closed deny with empty action
    // hash (same as historical gateway path before webhook mutation).
    if agent.status == "frozen" || agent.status == "revoked" {
        let reason = format!(
            "Agent '{}' is {}; all tool calls are denied (fail-closed).",
            agent.agent_key, agent.status
        );
        let matched_policies = vec![format!("agent_{}", agent.status)];
        return Err(persist_early_deny(
            runtime,
            &request,
            &agent,
            &root_trust_level,
            dry_run,
            &normalized_tool,
            started_at,
            reason,
            matched_policies,
            "",
        )
        .await?);
    }

    // Optional admission webhook (#1143): may pass, mutate parameters, or reject.
    match runtime.call_admission_webhook(&request).await {
        Ok(AdmissionEffect::Pass) | Ok(AdmissionEffect::Disabled) => {}
        Ok(AdmissionEffect::Mutate(new_params)) => {
            request.tool_call.parameters = new_params;
        }
        Ok(AdmissionEffect::Reject(reason)) => {
            let matched_policies = vec!["admission_webhook_reject".to_string()];
            return Err(persist_early_deny(
                runtime,
                &request,
                &agent,
                &root_trust_level,
                dry_run,
                &normalized_tool,
                started_at,
                reason,
                matched_policies,
                "",
            )
            .await?);
        }
        Err(e) => {
            error!("Admission webhook error: {:?}", e);
            return Err(aegis_err_to_outcome(e));
        }
    }

    // #1602: action hash after any webhook mutation.
    let action_hash = runtime.compute_action_hash(
        &agent.tenant_id,
        request.request_id.as_deref(),
        &request.tool_call,
    );

    // Ban / quarantine-record enforcement (fail-closed).
    match runtime
        .enforcement_status(&agent.tenant_id, &agent.id, &normalized_tool)
        .await
    {
        Ok(EnforcementStatus::Clear) => {}
        Ok(status) => {
            let (policy, reason) = match status {
                EnforcementStatus::AgentBanned => (
                    "agent_banned",
                    format!(
                        "agent '{}' is banned; all tool calls are denied (fail-closed).",
                        agent.id
                    ),
                ),
                EnforcementStatus::ToolBanned => (
                    "tool_banned",
                    format!(
                        "tool '{normalized_tool}' is banned; calls to it are denied (fail-closed)."
                    ),
                ),
                EnforcementStatus::AgentQuarantined => (
                    "agent_quarantine_record",
                    format!(
                        "agent '{}' is quarantined; all tool calls are denied (fail-closed).",
                        agent.id
                    ),
                ),
                EnforcementStatus::Clear => unreachable!(),
            };
            let matched_policies = vec![policy.to_string()];
            return Err(persist_early_deny(
                runtime,
                &request,
                &agent,
                &root_trust_level,
                dry_run,
                &normalized_tool,
                started_at,
                reason,
                matched_policies,
                &action_hash,
            )
            .await?);
        }
        Err(e) => {
            error!("Failed to check ban/quarantine enforcement state: {:?}", e);
            return Err(aegis_err_to_outcome(e));
        }
    }

    Ok(GuardedAuthorize {
        request,
        agent,
        root_trust_level,
        dry_run,
        used_mtls,
        normalized_tool,
        normalized_action,
        action_hash,
    })
}

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;
