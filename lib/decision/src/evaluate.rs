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
mod tests {
    use super::*;
    use crate::agent::AuthorizeAgent;
    use crate::guard::GuardedAuthorize;
    use crate::metadata::MetadataAuthorize;
    use crate::outcome::DecisionBody;
    use crate::runtime::{
        AdmissionEffect, DecisionRuntime, EnforcementStatus, McpToolMeta, PolicyDecisionView,
        RegisteredActionMeta,
    };
    use aegis_api::models::{AuthorizeRequest, AuthorizeToolCall, DecisionRecord};
    use aegis_common::errors::AegisError;
    use chrono::{DateTime, Utc};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Instant;

    struct MockRt {
        cedar: PolicyDecisionView,
        capacity: bool,
        write_fail: bool,
        writes: Mutex<u32>,
    }

    #[async_trait::async_trait]
    impl DecisionRuntime for MockRt {
        async fn get_agent_by_token(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<AuthorizeAgent>, AegisError> {
            Ok(None)
        }
        async fn get_agent_by_mtls_cn(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<AuthorizeAgent>, AegisError> {
            Ok(None)
        }
        fn auth_failure_blocked(&self, _: SocketAddr, _: &str) -> bool {
            false
        }
        fn record_auth_failure(&self, _: SocketAddr, _: &str) {}
        async fn agent_tool_permitted(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<bool, AegisError> {
            Ok(true)
        }
        async fn get_decision_by_request_id(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<DecisionRecord>, AegisError> {
            Ok(None)
        }
        async fn check_and_record_nonce(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: DateTime<Utc>,
        ) -> Result<bool, AegisError> {
            Ok(false)
        }
        async fn check_rate_limit(&self, _: &str) -> bool {
            true
        }
        fn check_quota(&self, _: &str) -> bool {
            true
        }
        fn touch_heartbeat(&self, _: &str, _: &str) {}
        async fn write_decision_and_audit(
            &self,
            w: DecisionAuditWrite<'_>,
        ) -> Result<i32, AegisError> {
            if self.write_fail {
                return Err(AegisError::Internal("db down".into()));
            }
            *self.writes.lock().expect("l") += 1;
            Ok(w.risk_score)
        }
        async fn call_admission_webhook(
            &self,
            _: &AuthorizeRequest,
        ) -> Result<AdmissionEffect, AegisError> {
            Ok(AdmissionEffect::Disabled)
        }
        fn compute_action_hash(&self, _: &str, _: Option<&str>, _: &AuthorizeToolCall) -> String {
            "h".into()
        }
        async fn enforcement_status(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<EnforcementStatus, AegisError> {
            Ok(EnforcementStatus::Clear)
        }
        async fn skill_action_meta(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<RegisteredActionMeta>, AegisError> {
            Ok(None)
        }
        async fn agent_mcp_server_permitted(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<bool, AegisError> {
            Ok(true)
        }
        async fn mcp_server_status(&self, _: &str, _: &str) -> Result<Option<String>, AegisError> {
            Ok(None)
        }
        async fn mcp_tool_meta(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<McpToolMeta>, AegisError> {
            Ok(None)
        }
        async fn ensure_policies_loaded(&self, _: &str) -> Result<(), AegisError> {
            Ok(())
        }
        async fn evaluate_cedar(
            &self,
            _: &str,
            _: &AuthorizeRequest,
            _: &str,
            _: bool,
            _: bool,
        ) -> Result<PolicyDecisionView, AegisError> {
            Ok(self.cedar.clone())
        }
        fn record_provenance_denial(&self) {}
        fn audit_stream_has_capacity(&self) -> bool {
            self.capacity
        }
        fn set_audit_writer_healthy(&self, _: bool) {}
        async fn emit_receipt_durable(
            &self,
            _: &str,
            _: &str,
            _: &AuthorizeRequest,
            _: Uuid,
            _: &str,
            _: &str,
        ) -> Result<ReceiptIdentity, AegisError> {
            Ok(ReceiptIdentity {
                receipt_id: "r1".into(),
                receipt_hash: "rh".into(),
                prev_receipt_hash: "ph".into(),
                canon_version: "aegis-jcs-1".into(),
            })
        }
        async fn emit_receipt_best_effort(
            &self,
            _: &str,
            _: &str,
            _: &AuthorizeRequest,
            _: Uuid,
            _: &str,
            _: &str,
        ) {
        }
        async fn quarantine_agent(&self, _: &str, _: &str) -> Result<(), AegisError> {
            Ok(())
        }
        fn emit_agent_quarantined(
            &self,
            _: &str,
            _: &str,
            _: &AuthorizeRequest,
            _: i32,
            _: &str,
            _: &[String],
        ) {
        }
        async fn create_approval(
            &self,
            _: &str,
            _: &str,
            _: &AuthorizeRequest,
            params: ApprovalCreateParams,
        ) -> Result<ApprovalResponseInfo, AegisError> {
            Ok(ApprovalResponseInfo {
                approval_id: Uuid::nil(),
                status: "created".into(),
                approver_group: None,
                expires_at: Utc::now(),
                action_hash: params.action_hash,
            })
        }
        async fn maybe_escalate_risk_tier(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<(String, String)>, AegisError> {
            Ok(None)
        }
        async fn emit_risk_escalated(
            &self,
            _: &str,
            _: &str,
            _: &AuthorizeRequest,
            _: &str,
            _: Uuid,
            _: i32,
            _: &str,
            _: &str,
            _: &[String],
        ) {
        }
        fn notify_github_decision(
            &self,
            _: &AuthorizeRequest,
            _: &str,
            _: &str,
            _: i32,
            _: Uuid,
            _: &[String],
        ) {
        }

        async fn idempotent_replay(
            &self,
            record: aegis_api::models::DecisionRecord,
        ) -> Result<aegis_api::models::AuthorizeResponse, AegisError> {
            Ok(crate::pipeline::authorize_response_from_decision_record(
                record, None,
            ))
        }
    }

    fn meta_allow() -> MetadataAuthorize {
        let body = serde_json::json!({
            "agent": { "id": "a1", "environment": "dev" },
            "tool_call": {
                "tool": "echo",
                "action": "run",
                "parameters": {},
                "mutates_state": false
            },
            "context": {
                "source_trust": "trusted_internal_unsigned",
                "contains_sensitive_data": false
            }
        });
        MetadataAuthorize {
            guarded: GuardedAuthorize {
                request: serde_json::from_value(body).expect("req"),
                agent: AuthorizeAgent::new("agent-1", "tenant-1", "low"),
                root_trust_level: "trusted_internal_unsigned".into(),
                dry_run: false,
                used_mtls: false,
                normalized_tool: "echo".into(),
                normalized_action: "run".into(),
                action_hash: "h".into(),
            },
            risk_score: 10,
            risk_level: "low".into(),
            action_approval_required: false,
            action_default_decision: "policy".into(),
            is_tool_known: true,
            is_mcp_call: false,
            mcp_server_key: None,
        }
    }

    #[tokio::test]
    async fn evaluate_allow_low_risk_writes() {
        let rt = MockRt {
            cedar: PolicyDecisionView {
                decision: "allow".into(),
                matched_policies: vec!["p1".into()],
                approver_group: None,
                reason: "ok".into(),
                redacted_fields: vec![],
            },
            capacity: true,
            write_fail: false,
            writes: Mutex::new(0),
        };
        let out =
            evaluate_authorize(&rt, meta_allow(), Instant::now(), EvaluateConfig::default()).await;
        match out.body {
            DecisionBody::Decision(resp) => {
                assert_eq!(resp.decision, "allow");
                assert_eq!(resp.risk_score, 10);
            }
            _ => panic!("decision"),
        }
        assert_eq!(*rt.writes.lock().expect("l"), 1);
    }

    #[tokio::test]
    async fn evaluate_audit_capacity_fail_closed_high_risk() {
        let mut m = meta_allow();
        m.risk_level = "critical".into();
        m.risk_score = 95;
        let rt = MockRt {
            cedar: PolicyDecisionView {
                decision: "allow".into(),
                matched_policies: vec![],
                approver_group: None,
                reason: "ok".into(),
                redacted_fields: vec![],
            },
            capacity: false,
            write_fail: false,
            writes: Mutex::new(0),
        };
        let out = evaluate_authorize(&rt, m, Instant::now(), EvaluateConfig::default()).await;
        match out.body {
            DecisionBody::Decision(resp) => {
                assert_eq!(resp.decision, "deny");
                assert!(resp.reason.contains("audit_writer_unavailable"));
            }
            _ => panic!("decision"),
        }
        assert_eq!(*rt.writes.lock().expect("l"), 0);
    }
}
