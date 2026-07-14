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
mod tests {
    use super::*;
    use crate::agent::AuthorizeAgent;
    use crate::guard::GuardedAuthorize;
    use crate::outcome::DecisionBody;
    use crate::runtime::{
        AdmissionEffect, DecisionRuntime, EnforcementStatus, McpToolMeta, RegisteredActionMeta,
    };
    use aegis_api::models::{AuthorizeRequest, AuthorizeToolCall, DecisionRecord};
    use aegis_common::errors::AegisError;
    use chrono::{DateTime, Utc};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Instant;

    struct MockRt {
        skill: Option<RegisteredActionMeta>,
        mcp_permitted: bool,
        server_status: Option<String>,
        tool: Option<McpToolMeta>,
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
            Ok(w.risk_score)
        }
        async fn call_admission_webhook(
            &self,
            _: &AuthorizeRequest,
        ) -> Result<AdmissionEffect, AegisError> {
            Ok(AdmissionEffect::Disabled)
        }
        fn compute_action_hash(&self, _: &str, _: Option<&str>, _: &AuthorizeToolCall) -> String {
            "hash".into()
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
            Ok(self.skill.clone())
        }
        async fn agent_mcp_server_permitted(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<bool, AegisError> {
            Ok(self.mcp_permitted)
        }
        async fn mcp_server_status(&self, _: &str, _: &str) -> Result<Option<String>, AegisError> {
            Ok(self.server_status.clone())
        }
        async fn mcp_tool_meta(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<McpToolMeta>, AegisError> {
            Ok(self.tool.clone())
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
    }

    fn guarded(tool: &str, action: &str) -> GuardedAuthorize {
        let body = serde_json::json!({
            "agent": { "id": "a1", "environment": "dev" },
            "tool_call": {
                "tool": tool,
                "action": action,
                "parameters": {},
                "mutates_state": false
            },
            "context": {
                "source_trust": "trusted_internal_unsigned",
                "contains_sensitive_data": false
            }
        });
        GuardedAuthorize {
            request: serde_json::from_value(body).expect("req"),
            agent: AuthorizeAgent::new("agent-1", "tenant-1", "low"),
            root_trust_level: "trusted_internal_unsigned".into(),
            dry_run: false,
            used_mtls: false,
            normalized_tool: tool.to_lowercase(),
            normalized_action: action.to_lowercase(),
            action_hash: "hash".into(),
        }
    }

    #[tokio::test]
    async fn metadata_skill_action_sets_risk() {
        let rt = MockRt {
            skill: Some(RegisteredActionMeta {
                risk: "high".into(),
                mutates_state: true,
                approval_required: true,
                default_decision: "require_approval".into(),
            }),
            mcp_permitted: true,
            server_status: None,
            tool: None,
            writes: Mutex::new(0),
        };
        let got = metadata_authorize(&rt, guarded("echo", "run"), Instant::now())
            .await
            .expect("ok");
        assert_eq!(got.risk_level, "high");
        assert_eq!(got.risk_score, 75);
        assert!(got.action_approval_required);
        assert!(!got.is_mcp_call);
        assert!(got.is_tool_known);
    }

    #[tokio::test]
    async fn metadata_mcp_permission_denied() {
        let rt = MockRt {
            skill: None,
            mcp_permitted: false,
            server_status: Some("active".into()),
            tool: Some(McpToolMeta {
                risk: "low".into(),
                approval_required: false,
                status: "approved".into(),
            }),
            writes: Mutex::new(0),
        };
        let err = metadata_authorize(&rt, guarded("mcp:fs", "read"), Instant::now())
            .await
            .expect_err("deny");
        assert_eq!(err.http_status, 403);
        match err.body {
            DecisionBody::PartialDeny { reason } => {
                assert!(reason.contains("MCP server"));
            }
            _ => panic!("partial deny"),
        }
    }

    #[tokio::test]
    async fn metadata_mcp_quarantined_server() {
        let rt = MockRt {
            skill: None,
            mcp_permitted: true,
            server_status: Some("quarantined".into()),
            tool: None,
            writes: Mutex::new(0),
        };
        let err = metadata_authorize(&rt, guarded("mcp:fs", "read"), Instant::now())
            .await
            .expect_err("quarantine");
        match err.body {
            DecisionBody::Decision(resp) => {
                assert_eq!(resp.decision, "deny");
                assert!(resp.reason.contains("quarantined"));
            }
            _ => panic!("decision"),
        }
        assert_eq!(*rt.writes.lock().expect("l"), 1);
    }

    #[tokio::test]
    async fn metadata_mcp_unapproved_tool() {
        let rt = MockRt {
            skill: None,
            mcp_permitted: true,
            server_status: Some("active".into()),
            tool: Some(McpToolMeta {
                risk: "medium".into(),
                approval_required: false,
                status: "pending".into(),
            }),
            writes: Mutex::new(0),
        };
        let err = metadata_authorize(&rt, guarded("mcp:fs", "read_file"), Instant::now())
            .await
            .expect_err("unapproved");
        match err.body {
            DecisionBody::Decision(resp) => {
                assert!(resp.reason.contains("not approved"));
            }
            _ => panic!("decision"),
        }
    }

    #[tokio::test]
    async fn metadata_unknown_mcp_tool_critical() {
        let rt = MockRt {
            skill: None,
            mcp_permitted: true,
            server_status: Some("active".into()),
            tool: None,
            writes: Mutex::new(0),
        };
        let got = metadata_authorize(&rt, guarded("mcp:fs", "unknown"), Instant::now())
            .await
            .expect("ok continue");
        assert!(!got.is_tool_known);
        assert_eq!(got.risk_level, "critical");
        assert_eq!(got.risk_score, 100);
    }
}
