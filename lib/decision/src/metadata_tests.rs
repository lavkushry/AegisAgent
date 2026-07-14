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
    async fn agent_tool_permitted(&self, _: &str, _: &str, _: &str) -> Result<bool, AegisError> {
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
    async fn write_decision_and_audit(&self, w: DecisionAuditWrite<'_>) -> Result<i32, AegisError> {
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

    async fn idempotent_replay(
        &self,
        record: aegis_api::models::DecisionRecord,
    ) -> Result<aegis_api::models::AuthorizeResponse, AegisError> {
        Ok(crate::pipeline::authorize_response_from_decision_record(
            record, None,
        ))
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
