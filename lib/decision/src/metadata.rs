//! Skill / MCP metadata resolution after guard (library-owned).
//!
//! Resolves registered-action risk metadata and MCP server/tool status,
//! applying fail-closed MCP permission and quarantine/approval denials.
//! On success returns risk inputs for Cedar evaluation.

use aegis_api::models::AuthorizeResponse;
use tracing::{error, warn};
use uuid::Uuid;

use crate::error_map::aegis_err_to_outcome;
use crate::guard::{mcp_server_key_from_tool, GuardedAuthorize};
use crate::outcome::DecisionOutcome;
use crate::risk::risk_score_for_level;
use crate::runtime::DecisionRuntime;
use crate::write::DecisionAuditWrite;

/// Guarded request plus resolved risk/MCP metadata for Cedar evaluation.
#[derive(Debug, Clone)]
pub struct MetadataAuthorize {
    pub guarded: GuardedAuthorize,
    pub risk_score: i32,
    pub risk_level: String,
    pub action_approval_required: bool,
    pub action_default_decision: String,
    pub is_tool_known: bool,
    pub is_mcp_call: bool,
    pub mcp_server_key: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn persist_mcp_deny(
    runtime: &dyn DecisionRuntime,
    guarded: &GuardedAuthorize,
    started_at: std::time::Instant,
    reason: String,
    matched_policies: Vec<String>,
    risk_score: i32,
    risk_level: String,
) -> Result<DecisionOutcome, DecisionOutcome> {
    let decision_id = Uuid::new_v4();
    let write = DecisionAuditWrite {
        tenant_id: &guarded.agent.tenant_id,
        agent_id: &guarded.agent.id,
        request: &guarded.request,
        decision_id,
        decision: "deny",
        risk_score,
        reason: &reason,
        matched_policies: &matched_policies,
        audit_event_type: "mcp_tool_called",
        started_at,
        dry_run: guarded.dry_run,
        action_hash: &guarded.action_hash,
        root_trust_level: &guarded.root_trust_level,
    };
    let composite_risk_score = match runtime.write_decision_and_audit(write).await {
        Ok(score) => score,
        Err(e) => {
            error!("Failed to write MCP denial decision: {:?}", e);
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
        root_trust_level: guarded.root_trust_level.clone(),
        dry_run: guarded.dry_run,
        receipt: None,
    }))
}

/// Resolve skill-action and MCP metadata after a successful guard phase.
pub async fn metadata_authorize(
    runtime: &dyn DecisionRuntime,
    guarded: GuardedAuthorize,
    started_at: std::time::Instant,
) -> Result<MetadataAuthorize, DecisionOutcome> {
    let tenant_id = guarded.agent.tenant_id.as_str();
    let agent_id = guarded.agent.id.as_str();
    let normalized_tool = guarded.normalized_tool.as_str();
    let normalized_action = guarded.normalized_action.as_str();

    let mcp_server_key = mcp_server_key_from_tool(normalized_tool).map(str::to_string);
    let is_mcp_call = mcp_server_key.is_some();

    let (skill_result, mcp_server_result, mcp_tool_result) = tokio::join!(
        runtime.skill_action_meta(tenant_id, normalized_tool, normalized_action),
        async {
            match mcp_server_key.as_deref() {
                Some(server_key) => runtime.mcp_server_status(tenant_id, server_key).await,
                None => Ok(None),
            }
        },
        async {
            match mcp_server_key.as_deref() {
                Some(server_key) => {
                    runtime
                        .mcp_tool_meta(tenant_id, server_key, normalized_action)
                        .await
                }
                None => Ok(None),
            }
        }
    );

    let mut risk_score = 10;
    let mut risk_level = "low".to_string();
    let mut action_approval_required = false;
    let mut action_default_decision = "policy".to_string();
    let mut is_tool_known = true;

    let action_meta = match skill_result {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to look up registered action: {:?}", e);
            return Err(aegis_err_to_outcome(e));
        }
    };

    if let Some(meta) = action_meta {
        risk_level = meta.risk;
        risk_score = risk_score_for_level(&risk_level);
        action_approval_required = meta.approval_required;
        action_default_decision = meta.default_decision;
    } else if !is_mcp_call {
        is_tool_known = false;
    }

    if let Some(server_key) = mcp_server_key.as_deref() {
        match runtime
            .agent_mcp_server_permitted(tenant_id, agent_id, server_key)
            .await
        {
            Ok(false) => {
                warn!(
                    "MCP server permission denied: agent={} tenant={} server={}",
                    agent_id, tenant_id, server_key
                );
                return Err(DecisionOutcome::partial_deny(format!(
                    "agent not permitted to call MCP server '{server_key}'"
                )));
            }
            Err(e) => {
                error!("Failed to check MCP server permission: {:?}", e);
                return Err(aegis_err_to_outcome(e));
            }
            Ok(true) => {}
        }

        let server_status = match mcp_server_result {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to look up MCP server status: {:?}", e);
                return Err(aegis_err_to_outcome(e));
            }
        };

        if let Some(status) = server_status.as_deref() {
            if status == "quarantined" {
                let reason = format!(
                    "MCP server '{server_key}' is quarantined; all tool calls are denied (fail-closed)."
                );
                let matched_policies = vec!["mcp_server_quarantined".to_string()];
                risk_level = "critical".to_string();
                risk_score = 100;
                return Err(persist_mcp_deny(
                    runtime,
                    &guarded,
                    started_at,
                    reason,
                    matched_policies,
                    risk_score,
                    risk_level,
                )
                .await?);
            }
        }

        let mcp_tool = match mcp_tool_result {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to look up MCP tool: {:?}", e);
                return Err(aegis_err_to_outcome(e));
            }
        };

        match mcp_tool {
            Some(tool) => {
                risk_level = tool.risk.clone();
                risk_score = risk_score_for_level(&risk_level);
                action_approval_required = action_approval_required || tool.approval_required;

                if tool.status != "approved" {
                    let reason = format!(
                        "MCP tool '{}' on server '{}' is not approved (status: {}).",
                        guarded.request.tool_call.action, server_key, tool.status
                    );
                    let matched_policies = vec!["mcp_tool_status".to_string()];
                    return Err(persist_mcp_deny(
                        runtime,
                        &guarded,
                        started_at,
                        reason,
                        matched_policies,
                        risk_score,
                        risk_level,
                    )
                    .await?);
                }
            }
            None => {
                is_tool_known = false;
                risk_level = "critical".to_string();
                risk_score = 100;
            }
        }
    }

    Ok(MetadataAuthorize {
        guarded,
        risk_score,
        risk_level,
        action_approval_required,
        action_default_decision,
        is_tool_known,
        is_mcp_call,
        mcp_server_key,
    })
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
