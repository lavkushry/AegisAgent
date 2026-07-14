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
mod tests {
    use super::*;
    use crate::agent::AuthorizeAgent;
    use crate::outcome::DecisionBody;
    use crate::preflight::PreflightedAuthorize;
    use crate::runtime::DecisionRuntime;
    use aegis_api::models::{AuthorizeToolCall, DecisionRecord};
    use aegis_common::errors::AegisError;
    use chrono::{DateTime, Utc};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Instant;

    struct MockRt {
        admission: AdmissionEffect,
        enforcement: EnforcementStatus,
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
            *self.writes.lock().expect("l") += 1;
            assert_eq!(w.decision, "deny");
            Ok(w.risk_score)
        }
        async fn call_admission_webhook(
            &self,
            _: &AuthorizeRequest,
        ) -> Result<AdmissionEffect, AegisError> {
            Ok(self.admission.clone())
        }
        fn compute_action_hash(&self, _: &str, _: Option<&str>, _: &AuthorizeToolCall) -> String {
            "deadbeef".into()
        }
        async fn enforcement_status(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<EnforcementStatus, AegisError> {
            Ok(self.enforcement)
        }
        async fn skill_action_meta(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<crate::runtime::RegisteredActionMeta>, AegisError> {
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
        ) -> Result<Option<crate::runtime::McpToolMeta>, AegisError> {
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
        ) -> Result<crate::runtime::PolicyDecisionView, AegisError> {
            Ok(crate::runtime::PolicyDecisionView {
                decision: "allow".into(),
                matched_policies: vec![],
                approver_group: None,
                reason: "ok".into(),
                redacted_fields: vec![],
            })
        }
        fn record_provenance_denial(&self) {}
        fn audit_stream_has_capacity(&self) -> bool {
            true
        }
        fn set_audit_writer_healthy(&self, _: bool) {}
        async fn emit_receipt_durable(
            &self,
            _: &str,
            _: &str,
            _: &AuthorizeRequest,
            _: uuid::Uuid,
            _: &str,
            _: &str,
        ) -> Result<aegis_api::models::ReceiptIdentity, AegisError> {
            Ok(aegis_api::models::ReceiptIdentity {
                receipt_id: "r".into(),
                receipt_hash: "h".into(),
                prev_receipt_hash: "p".into(),
                canon_version: "aegis-jcs-1".into(),
            })
        }
        async fn emit_receipt_best_effort(
            &self,
            _: &str,
            _: &str,
            _: &AuthorizeRequest,
            _: uuid::Uuid,
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
            _: crate::runtime::ApprovalCreateParams,
        ) -> Result<aegis_api::models::ApprovalResponseInfo, AegisError> {
            Ok(aegis_api::models::ApprovalResponseInfo {
                approval_id: uuid::Uuid::nil(),
                status: "created".into(),
                approver_group: None,
                expires_at: chrono::Utc::now(),
                action_hash: "h".into(),
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
            _: uuid::Uuid,
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
            _: uuid::Uuid,
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

    fn preflighted(status: &str) -> PreflightedAuthorize {
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
        let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
        agent.status = status.into();
        agent.agent_key = "my-agent".into();
        PreflightedAuthorize {
            request: serde_json::from_value(body).expect("req"),
            agent,
            root_trust_level: "trusted_internal_unsigned".into(),
            dry_run: false,
            used_mtls: false,
            normalized_tool: "echo".into(),
            normalized_action: "run".into(),
        }
    }

    #[tokio::test]
    async fn guard_denies_frozen_agent() {
        let rt = MockRt {
            admission: AdmissionEffect::Disabled,
            enforcement: EnforcementStatus::Clear,
            writes: Mutex::new(0),
        };
        let err = guard_authorize(&rt, preflighted("frozen"), Instant::now())
            .await
            .expect_err("frozen");
        assert!(matches!(err.body, DecisionBody::Decision(_)));
        assert_eq!(*rt.writes.lock().expect("l"), 1);
    }

    #[tokio::test]
    async fn guard_denies_banned_agent_after_hash() {
        let rt = MockRt {
            admission: AdmissionEffect::Disabled,
            enforcement: EnforcementStatus::AgentBanned,
            writes: Mutex::new(0),
        };
        let err = guard_authorize(&rt, preflighted("active"), Instant::now())
            .await
            .expect_err("banned");
        match err.body {
            DecisionBody::Decision(resp) => {
                assert_eq!(resp.decision, "deny");
                assert!(resp.reason.contains("banned"));
            }
            _ => panic!("decision"),
        }
        assert_eq!(*rt.writes.lock().expect("l"), 1);
    }

    #[tokio::test]
    async fn guard_webhook_mutate_then_continue() {
        let rt = MockRt {
            admission: AdmissionEffect::Mutate(serde_json::json!({"x": 1})),
            enforcement: EnforcementStatus::Clear,
            writes: Mutex::new(0),
        };
        let got = guard_authorize(&rt, preflighted("active"), Instant::now())
            .await
            .expect("ok");
        assert_eq!(got.action_hash, "deadbeef");
        assert_eq!(
            got.request.tool_call.parameters,
            serde_json::json!({"x": 1})
        );
        assert_eq!(*rt.writes.lock().expect("l"), 0);
    }

    #[tokio::test]
    async fn guard_webhook_reject() {
        let rt = MockRt {
            admission: AdmissionEffect::Reject("blocked by admission".into()),
            enforcement: EnforcementStatus::Clear,
            writes: Mutex::new(0),
        };
        let err = guard_authorize(&rt, preflighted("active"), Instant::now())
            .await
            .expect_err("reject");
        match err.body {
            DecisionBody::Decision(resp) => {
                assert!(resp.reason.contains("blocked by admission"));
                assert_eq!(resp.matched_policies, vec!["admission_webhook_reject"]);
            }
            _ => panic!("decision"),
        }
    }

    #[test]
    fn mcp_server_key_extraction() {
        assert_eq!(mcp_server_key_from_tool("mcp:fs"), Some("fs"));
        assert_eq!(mcp_server_key_from_tool("mcp:"), None);
        assert_eq!(mcp_server_key_from_tool("echo"), None);
    }
}
