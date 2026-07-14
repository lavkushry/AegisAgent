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
