//! Cedar evaluation and post-decision effects (library-owned).
//!
//! Loads tenant policies, evaluates Cedar, applies decision overrides, writes
//! the decision/audit trail (with audit-writer fail-closed), emits receipts,
//! handles quarantine / require_approval / risk escalation, and returns a
//! full [`DecisionOutcome`].

use aegis_api::models::{ApprovalResponseInfo, AuthorizeResponse, ReceiptIdentity};
use aegis_common::metrics::is_untrusted_provenance;
use tracing::{error, info};
use uuid::Uuid;

use crate::error_map::aegis_err_to_outcome;
use crate::metadata::MetadataAuthorize;
use crate::outcome::{DecisionFailure, DecisionOutcome};
use crate::risk::{decision_requires_durable_receipt, is_high_risk_for_audit};
use crate::runtime::{ApprovalCreateParams, DecisionRuntime};
use crate::write::DecisionAuditWrite;

/// Optional knobs for evaluation (approval TTL, etc.).
#[derive(Debug, Clone, Copy)]
pub struct EvaluateConfig {
    pub approval_ttl_secs: i64,
}

impl Default for EvaluateConfig {
    fn default() -> Self {
        Self {
            approval_ttl_secs: 1800,
        }
    }
}

/// Run Cedar evaluation and finish the authorize path after metadata.
pub async fn evaluate_authorize(
    runtime: &dyn DecisionRuntime,
    meta: MetadataAuthorize,
    started_at: std::time::Instant,
    config: EvaluateConfig,
) -> DecisionOutcome {
    let payload = meta.guarded.request;
    let dry_run = meta.guarded.dry_run;
    let root_trust_level = meta.guarded.root_trust_level;
    let agent = meta.guarded.agent;
    let is_mtls = meta.guarded.used_mtls;
    let tenant_id = agent.tenant_id.clone();
    let agent_id = agent.id.clone();
    let action_hash = meta.guarded.action_hash;
    let risk_score = meta.risk_score;
    let risk_level = meta.risk_level;
    let action_approval_required = meta.action_approval_required;
    let action_default_decision = meta.action_default_decision;
    let is_tool_known = meta.is_tool_known;
    let is_mcp_call = meta.is_mcp_call;

    if let Err(e) = runtime.ensure_policies_loaded(&tenant_id).await {
        error!("Failed to load tenant policies: {:?}", e);
        // Preserve pre-extraction HTTP 500 class; StatusError envelope is fine.
        return DecisionOutcome::failure(DecisionFailure::internal(
            "Failed to load tenant policies",
        ));
    }

    let policy_decision = match runtime
        .evaluate_cedar(
            &tenant_id,
            &payload,
            &agent.risk_tier,
            is_tool_known,
            is_mtls,
        )
        .await
    {
        Ok(d) => d,
        Err(e) => {
            error!("Policy engine error: {:?}", e);
            return DecisionOutcome::failure(DecisionFailure::internal(format!(
                "Policy engine failure: {e}"
            )));
        }
    };

    let decision_id = Uuid::new_v4();

    if policy_decision.decision == "deny"
        && payload.tool_call.mutates_state
        && is_untrusted_provenance(&payload.context.source_trust)
    {
        runtime.record_provenance_denial();
    }

    let (decision_str, reason, matched_policies) =
        aegis_policy::validation::apply_decision_overrides(
            policy_decision.decision.clone(),
            policy_decision.reason.clone(),
            policy_decision.matched_policies.clone(),
            &risk_level,
            agent.force_approval,
            &action_default_decision,
            action_approval_required,
        );

    let mut redacted_fields = policy_decision.redacted_fields.clone();
    let audit_event_type = if is_mcp_call {
        "mcp_tool_called"
    } else {
        "tool_call_intercepted"
    };

    if !dry_run
        && is_high_risk_for_audit(&risk_level, payload.tool_call.mutates_state)
        && !runtime.audit_stream_has_capacity()
    {
        return DecisionOutcome::decision(AuthorizeResponse {
            decision_id,
            decision: "deny".to_string(),
            risk_score,
            risk_level,
            composite_risk_score: risk_score,
            reason: "Audit writer unavailable (SOC event stream full): action denied (audit_writer_unavailable, fail-closed).".to_string(),
            matched_policies: vec!["audit_writer_unavailable".to_string()],
            approval: None,
            redacted_fields: vec![],
            root_trust_level: root_trust_level.clone(),
            dry_run,
            receipt: None,
        });
    }

    let write = DecisionAuditWrite {
        tenant_id: &tenant_id,
        agent_id: &agent_id,
        request: &payload,
        decision_id,
        decision: &decision_str,
        risk_score,
        reason: &reason,
        matched_policies: &matched_policies,
        audit_event_type,
        started_at,
        dry_run,
        action_hash: &action_hash,
        root_trust_level: &root_trust_level,
    };

    let composite_risk_score = match runtime.write_decision_and_audit(write).await {
        Ok(score) => {
            runtime.set_audit_writer_healthy(true);
            score
        }
        Err(e) => {
            error!(
                "Failed to write decision/audit record (audit writer unavailable): {:?}",
                e
            );
            runtime.set_audit_writer_healthy(false);

            if is_high_risk_for_audit(&risk_level, payload.tool_call.mutates_state) {
                return DecisionOutcome::decision(AuthorizeResponse {
                    decision_id,
                    decision: "deny".to_string(),
                    risk_score,
                    risk_level,
                    composite_risk_score: risk_score,
                    reason: "Audit writer unavailable (database write failed): action denied (audit_writer_unavailable, fail-closed).".to_string(),
                    matched_policies: vec!["audit_writer_unavailable".to_string()],
                    approval: None,
                    redacted_fields: vec![],
                    root_trust_level: root_trust_level.clone(),
                    dry_run,
                    receipt: None,
                });
            }

            tracing::warn!(
                tool = %payload.tool_call.tool,
                action = %payload.tool_call.action,
                "Audit writer unavailable for low-risk action; allowing without persisted audit record"
            );
            return DecisionOutcome::decision(AuthorizeResponse {
                decision_id,
                decision: decision_str,
                risk_score,
                risk_level,
                composite_risk_score: risk_score,
                reason,
                matched_policies,
                approval: None,
                redacted_fields: vec![],
                root_trust_level: root_trust_level.clone(),
                dry_run,
                receipt: None,
            });
        }
    };

    let mut receipt_identity: Option<ReceiptIdentity> = None;
    if !dry_run {
        if decision_requires_durable_receipt(
            &decision_str,
            &risk_level,
            payload.tool_call.mutates_state,
        ) {
            match runtime
                .emit_receipt_durable(
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    &decision_str,
                    &action_hash,
                )
                .await
            {
                Ok(receipt) => receipt_identity = Some(receipt),
                Err(e) => {
                    error!(
                        decision_id = %decision_id,
                        tenant_id = %tenant_id,
                        "Fail-closed: durable receipt write failed for protected decision: {:?}",
                        e
                    );
                    return DecisionOutcome::failure(DecisionFailure::internal(
                        "Failed to durably record decision evidence; action not authorized",
                    ));
                }
            }
        } else {
            runtime
                .emit_receipt_best_effort(
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    &decision_str,
                    &action_hash,
                )
                .await;
        }
    }

    if !dry_run && decision_str == "quarantine" {
        match runtime.quarantine_agent(&tenant_id, &agent_id).await {
            Ok(()) => {
                info!(
                    agent_id = %agent_id,
                    tenant_id = %tenant_id,
                    "Agent quarantined by Cedar policy"
                );
                runtime.emit_agent_quarantined(
                    &tenant_id,
                    &agent_id,
                    &payload,
                    risk_score,
                    &reason,
                    &matched_policies,
                );
            }
            Err(e) => {
                error!(
                    "Failed to quarantine agent {} after Cedar policy decision: {:?}",
                    agent_id, e
                );
            }
        }
    }

    let mut approval_info: Option<ApprovalResponseInfo> = None;
    if !dry_run && decision_str == "require_approval" {
        let (callback_url, callback_secret) = match &payload.callback {
            Some(cb) => (Some(cb.url.clone()), cb.secret.clone()),
            None => (None, None),
        };
        match runtime
            .create_approval(
                &tenant_id,
                &agent_id,
                &payload,
                ApprovalCreateParams {
                    decision_id,
                    action_hash: action_hash.clone(),
                    approver_group: policy_decision.approver_group.clone(),
                    callback_url,
                    callback_secret,
                    approval_ttl_secs: config.approval_ttl_secs,
                },
            )
            .await
        {
            Ok(info) => approval_info = Some(info),
            Err(e) => {
                // Preserve BadRequest for SSRF / invalid callback vs internal create failures.
                return aegis_err_to_outcome(e);
            }
        }
    }

    if !dry_run && decision_str == "deny" {
        match runtime
            .maybe_escalate_risk_tier(&tenant_id, &agent_id, &agent.risk_tier)
            .await
        {
            Ok(Some((old_tier, new_tier))) => {
                info!(
                    agent_id = %agent_id,
                    tenant_id = %tenant_id,
                    old_tier = %old_tier,
                    new_tier = %new_tier,
                    "Agent risk tier auto-escalated after repeated denials"
                );
                runtime
                    .emit_risk_escalated(
                        &tenant_id,
                        &agent_id,
                        &payload,
                        &decision_str,
                        decision_id,
                        risk_score,
                        &old_tier,
                        &new_tier,
                        &matched_policies,
                    )
                    .await;
            }
            Ok(None) => {}
            Err(e) => {
                error!(
                    "Failed to evaluate risk tier escalation for agent {}: {:?}",
                    agent_id, e
                );
            }
        }
    }

    if !dry_run {
        runtime.notify_github_decision(
            &payload,
            &decision_str,
            &reason,
            risk_score,
            decision_id,
            &matched_policies,
        );
    }

    if decision_str != "redact" {
        redacted_fields.clear();
    }

    DecisionOutcome::decision(AuthorizeResponse {
        decision_id,
        decision: decision_str,
        risk_score,
        risk_level,
        composite_risk_score,
        reason,
        matched_policies,
        approval: approval_info,
        redacted_fields,
        root_trust_level,
        dry_run,
        receipt: receipt_identity,
    })
}

#[cfg(test)]
#[path = "evaluate_tests.rs"]
mod tests;
