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
