use super::*;
use crate::agent::AuthorizeAgent;
use crate::context::{AuthCredential, Transport};
use crate::outcome::DecisionBody;
use crate::runtime::{
    AdmissionEffect, ApprovalCreateParams, DecisionRuntime, EnforcementStatus, McpToolMeta,
    PolicyDecisionView, RegisteredActionMeta,
};
use crate::write::DecisionAuditWrite;
use aegis_api::models::{
    ApprovalResponseInfo, AuthorizeRequest, AuthorizeToolCall, ReceiptIdentity,
};
use aegis_common::errors::AegisError;
use chrono::{DateTime, Utc};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Full-stack mock for `run_authorize_pipeline` integration tests.
struct PipelineRt {
    agent: Option<AuthorizeAgent>,
    cedar: PolicyDecisionView,
    idempotent: Option<DecisionRecord>,
    tool_permitted: bool,
    admission: AdmissionEffect,
    enforcement: EnforcementStatus,
    mcp_server_permitted: bool,
    mcp_server_status: Option<String>,
    mcp_tool: Option<McpToolMeta>,
    rate_ok: bool,
    quota_ok: bool,
    audit_capacity: bool,
    writes: Mutex<u32>,
    heartbeats: Mutex<u32>,
    receipts: Mutex<u32>,
    approvals: Mutex<u32>,
}

impl Default for PipelineRt {
    fn default() -> Self {
        Self {
            agent: Some(AuthorizeAgent::new("agent-1", "tenant-1", "low")),
            cedar: PolicyDecisionView {
                decision: "allow".into(),
                matched_policies: vec!["base_allow".into()],
                approver_group: None,
                reason: "ok".into(),
                redacted_fields: vec![],
            },
            idempotent: None,
            tool_permitted: true,
            admission: AdmissionEffect::Disabled,
            enforcement: EnforcementStatus::Clear,
            mcp_server_permitted: true,
            mcp_server_status: None,
            mcp_tool: None,
            rate_ok: true,
            quota_ok: true,
            audit_capacity: true,
            writes: Mutex::new(0),
            heartbeats: Mutex::new(0),
            receipts: Mutex::new(0),
            approvals: Mutex::new(0),
        }
    }
}

#[async_trait::async_trait]
impl DecisionRuntime for PipelineRt {
    async fn get_agent_by_token(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<AuthorizeAgent>, AegisError> {
        Ok(self.agent.clone())
    }
    async fn get_agent_by_mtls_cn(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<AuthorizeAgent>, AegisError> {
        Ok(self.agent.clone())
    }
    fn auth_failure_blocked(&self, _: SocketAddr, _: &str) -> bool {
        false
    }
    fn record_auth_failure(&self, _: SocketAddr, _: &str) {}
    async fn agent_tool_permitted(&self, _: &str, _: &str, _: &str) -> Result<bool, AegisError> {
        Ok(self.tool_permitted)
    }
    async fn get_decision_by_request_id(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<DecisionRecord>, AegisError> {
        Ok(self.idempotent.clone())
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
        self.rate_ok
    }
    fn check_quota(&self, _: &str) -> bool {
        self.quota_ok
    }
    fn touch_heartbeat(&self, _: &str, _: &str) {
        *self.heartbeats.lock().expect("l") += 1;
    }
    async fn write_decision_and_audit(&self, w: DecisionAuditWrite<'_>) -> Result<i32, AegisError> {
        *self.writes.lock().expect("l") += 1;
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
    ) -> Result<Option<RegisteredActionMeta>, AegisError> {
        Ok(None)
    }
    async fn agent_mcp_server_permitted(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<bool, AegisError> {
        Ok(self.mcp_server_permitted)
    }
    async fn mcp_server_status(&self, _: &str, _: &str) -> Result<Option<String>, AegisError> {
        Ok(self.mcp_server_status.clone())
    }
    async fn mcp_tool_meta(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<McpToolMeta>, AegisError> {
        Ok(self.mcp_tool.clone())
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
        self.audit_capacity
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
        *self.receipts.lock().expect("l") += 1;
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
        *self.approvals.lock().expect("l") += 1;
        Ok(ApprovalResponseInfo {
            approval_id: Uuid::nil(),
            status: "created".into(),
            approver_group: params.approver_group,
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
        record: DecisionRecord,
    ) -> Result<AuthorizeResponse, AegisError> {
        Ok(authorize_response_from_decision_record(record, None))
    }
}

fn body_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
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
    }))
    .expect("json")
}

fn mcp_body_json(server: &str, action: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "agent": { "id": "a1", "environment": "dev" },
        "tool_call": {
            "tool": format!("mcp:{server}"),
            "action": action,
            "parameters": {},
            "mutates_state": false
        },
        "context": {
            "source_trust": "trusted_internal_unsigned",
            "contains_sensitive_data": false
        }
    }))
    .expect("json")
}

fn ctx() -> AuthorizeContext {
    AuthorizeContext::new(
        "tenant-1",
        SocketAddr::from(([10, 0, 0, 1], 4443)),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    )
}

#[test]
fn response_from_record_maps_fields() {
    let record = DecisionRecord {
        id: Uuid::nil().to_string(),
        tenant_id: "t1".into(),
        agent_id: "a1".into(),
        user_id: None,
        run_id: None,
        trace_id: None,
        skill: "echo".into(),
        action: "run".into(),
        resource: None,
        input_json: "{}".into(),
        decision: "allow".into(),
        risk_score: Some(10),
        reason: Some("ok".into()),
        matched_policy_ids: Some("p1,p2".into()),
        request_id: Some("r1".into()),
        latency_ms: None,
        composite_risk_score: Some(12),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let resp = authorize_response_from_decision_record(record, None);
    assert_eq!(resp.decision, "allow");
    assert_eq!(resp.risk_score, 10);
    assert_eq!(resp.composite_risk_score, 12);
    assert_eq!(resp.matched_policies, vec!["p1", "p2"]);
    assert!(!resp.dry_run);
    assert!(resp.receipt.is_none());
}

#[tokio::test]
async fn pipeline_allow_writes_decision_and_heartbeats() {
    let rt = PipelineRt::default();
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "ok");
        }
        other => panic!("expected decision, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_bad_token_unauthorized() {
    let rt = PipelineRt {
        agent: None,
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 401);
    assert!(matches!(out.body, DecisionBody::Failure(_)));
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_idempotent_replay_skips_cedar_write() {
    let record = DecisionRecord {
        id: Uuid::nil().to_string(),
        tenant_id: "tenant-1".into(),
        agent_id: "agent-1".into(),
        user_id: None,
        run_id: None,
        trace_id: None,
        skill: "echo".into(),
        action: "run".into(),
        resource: None,
        input_json: "{}".into(),
        decision: "allow".into(),
        risk_score: Some(10),
        reason: Some("cached".into()),
        matched_policy_ids: None,
        request_id: Some("req-1".into()),
        latency_ms: None,
        composite_risk_score: Some(10),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let rt = PipelineRt {
        idempotent: Some(record),
        ..PipelineRt::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["request_id"] = serde_json::json!("req-1");
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "cached");
        }
        other => panic!("expected replay decision, got {other:?}"),
    }
    // Idempotent path must not re-write a decision row.
    assert_eq!(*rt.writes.lock().expect("l"), 0);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_require_approval_creates_approval_info() {
    let rt = PipelineRt {
        cedar: PolicyDecisionView {
            decision: "require_approval".into(),
            matched_policies: vec!["needs_human".into()],
            approver_group: Some("sec".into()),
            reason: "human gate".into(),
            redacted_fields: vec![],
        },
        ..PipelineRt::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "require_approval");
            assert!(resp.approval.is_some());
        }
        other => panic!("expected approval decision, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.approvals.lock().expect("l"), 1);
    // Mutating require_approval requires a durable receipt.
    assert_eq!(*rt.receipts.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_frozen_agent_denies_and_persists() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.status = "frozen".into();
    let rt = PipelineRt {
        agent: Some(agent),
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("frozen"),
                "reason should mention frozen: {}",
                resp.reason
            );
            assert_eq!(resp.matched_policies, vec!["agent_frozen".to_string()]);
            assert!(resp.approval.is_none());
            assert!(resp.receipt.is_none());
        }
        other => panic!("expected frozen deny decision, got {other:?}"),
    }
    // Early deny still records a decision row (fail-closed audit trail).
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    // Heartbeat is touched during preflight before the frozen guard.
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_dry_run_allow_skips_receipt_and_side_effects() {
    let rt = PipelineRt::default();
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["dry_run"] = serde_json::json!(true);
    body["request_id"] = serde_json::json!("dry-req-1");
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert!(resp.dry_run, "response must echo dry_run");
            assert!(resp.receipt.is_none(), "dry-run must not emit receipts");
            assert!(resp.approval.is_none());
        }
        other => panic!("expected dry-run allow, got {other:?}"),
    }
    // Host port is still invoked for composite score (#1281 score-only path);
    // durable side effects (heartbeat, receipts, approvals) stay off.
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_dry_run_bypasses_idempotent_replay() {
    // A prior real decision exists for request_id, but dry-run must ignore it
    // and re-evaluate (idempotency is for durable requests only).
    let record = DecisionRecord {
        id: Uuid::nil().to_string(),
        tenant_id: "tenant-1".into(),
        agent_id: "agent-1".into(),
        user_id: None,
        run_id: None,
        trace_id: None,
        skill: "echo".into(),
        action: "run".into(),
        resource: None,
        input_json: "{}".into(),
        decision: "deny".into(),
        risk_score: Some(99),
        reason: Some("cached deny".into()),
        matched_policy_ids: None,
        request_id: Some("req-dry".into()),
        latency_ms: None,
        composite_risk_score: Some(99),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let rt = PipelineRt {
        idempotent: Some(record),
        cedar: PolicyDecisionView {
            decision: "allow".into(),
            matched_policies: vec!["base_allow".into()],
            approver_group: None,
            reason: "fresh dry-run allow".into(),
            redacted_fields: vec![],
        },
        ..PipelineRt::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["dry_run"] = serde_json::json!(true);
    body["request_id"] = serde_json::json!("req-dry");
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "fresh dry-run allow");
            assert!(resp.dry_run);
        }
        other => panic!("expected fresh dry-run allow, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_cedar_deny_persists() {
    let rt = PipelineRt {
        cedar: PolicyDecisionView {
            decision: "deny".into(),
            matched_policies: vec!["forbid_tool".into()],
            approver_group: None,
            reason: "policy deny".into(),
            redacted_fields: vec![],
        },
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert_eq!(resp.reason, "policy deny");
            assert_eq!(resp.matched_policies, vec!["forbid_tool".to_string()]);
            assert!(resp.approval.is_none());
        }
        other => panic!("expected cedar deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_revoked_agent_denies() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.status = "revoked".into();
    let rt = PipelineRt {
        agent: Some(agent),
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("revoked"), "reason={}", resp.reason);
            assert_eq!(resp.matched_policies, vec!["agent_revoked".to_string()]);
        }
        other => panic!("expected revoked deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_admission_webhook_reject_denies() {
    let rt = PipelineRt {
        admission: AdmissionEffect::Reject("webhook blocked".into()),
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert_eq!(resp.reason, "webhook blocked");
            assert_eq!(
                resp.matched_policies,
                vec!["admission_webhook_reject".to_string()]
            );
        }
        other => panic!("expected webhook reject deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_agent_banned_denies() {
    let rt = PipelineRt {
        enforcement: EnforcementStatus::AgentBanned,
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(resp.reason.contains("banned"), "reason={}", resp.reason);
            assert_eq!(resp.matched_policies, vec!["agent_banned".to_string()]);
        }
        other => panic!("expected ban deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_tool_not_permitted_partial_deny() {
    let rt = PipelineRt {
        tool_permitted: false,
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 403);
    match out.body {
        DecisionBody::PartialDeny { reason } => {
            assert!(reason.contains("not permitted"), "reason={reason}");
        }
        other => panic!("expected PartialDeny, got {other:?}"),
    }
    // Preflight partial deny does not write a full decision row.
    assert_eq!(*rt.writes.lock().expect("l"), 0);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_mcp_server_not_permitted_partial_deny() {
    let rt = PipelineRt {
        mcp_server_permitted: false,
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("fs", "read_file"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 403);
    match out.body {
        DecisionBody::PartialDeny { reason } => {
            assert!(reason.contains("MCP server"), "reason={reason}");
        }
        other => panic!("expected MCP permission PartialDeny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_mcp_quarantined_server_denies() {
    let rt = PipelineRt {
        mcp_server_status: Some("quarantined".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "medium".into(),
            approval_required: false,
            status: "approved".into(),
        }),
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("fs", "read_file"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("quarantined"),
                "reason={}",
                resp.reason
            );
            assert_eq!(
                resp.matched_policies,
                vec!["mcp_server_quarantined".to_string()]
            );
        }
        other => panic!("expected MCP quarantine deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_mcp_unapproved_tool_denies() {
    let rt = PipelineRt {
        mcp_server_status: Some("active".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "high".into(),
            approval_required: false,
            status: "pending".into(),
        }),
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("github", "merge_pr"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("not approved"),
                "reason={}",
                resp.reason
            );
            assert_eq!(resp.matched_policies, vec!["mcp_tool_status".to_string()]);
        }
        other => panic!("expected MCP tool status deny, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_mcp_approved_tool_allows() {
    let rt = PipelineRt {
        mcp_server_status: Some("active".into()),
        mcp_tool: Some(McpToolMeta {
            risk: "low".into(),
            approval_required: false,
            status: "approved".into(),
        }),
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &mcp_body_json("fs", "read_file"),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert_eq!(resp.reason, "ok");
        }
        other => panic!("expected MCP allow, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_rate_limit_returns_429() {
    let rt = PipelineRt {
        rate_ok: false,
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 429);
    match out.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("Rate limit"), "message={}", f.message);
        }
        other => panic!("expected rate-limit Failure, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_quota_exceeded_returns_429() {
    let rt = PipelineRt {
        quota_ok: false,
        ..PipelineRt::default()
    };
    let out = run_authorize_pipeline(
        &rt,
        &ctx(),
        &body_json(),
        Instant::now(),
        EvaluateConfig::default(),
    )
    .await;
    assert_eq!(out.http_status, 429);
    match out.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("quota"), "message={}", f.message);
        }
        other => panic!("expected quota Failure, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_audit_stream_full_fail_closed_for_mutating() {
    let rt = PipelineRt {
        audit_capacity: false,
        ..PipelineRt::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "deny");
            assert!(
                resp.reason.contains("audit_writer_unavailable")
                    || resp.reason.contains("Audit writer unavailable"),
                "reason={}",
                resp.reason
            );
            assert_eq!(
                resp.matched_policies,
                vec!["audit_writer_unavailable".to_string()]
            );
        }
        other => panic!("expected audit fail-closed deny, got {other:?}"),
    }
    // Fail-closed before durable write when the SOC stream is full.
    assert_eq!(*rt.writes.lock().expect("l"), 0);
    assert_eq!(*rt.receipts.lock().expect("l"), 0);
}

#[tokio::test]
async fn pipeline_mutating_allow_emits_durable_receipt() {
    let rt = PipelineRt::default();
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "allow");
            assert!(
                resp.receipt.is_some(),
                "mutating allow must carry receipt identity"
            );
        }
        other => panic!("expected mutating allow, got {other:?}"),
    }
    assert_eq!(*rt.writes.lock().expect("l"), 1);
    assert_eq!(*rt.receipts.lock().expect("l"), 1);
}

#[tokio::test]
async fn pipeline_dry_run_require_approval_creates_no_approval_row() {
    let rt = PipelineRt {
        cedar: PolicyDecisionView {
            decision: "require_approval".into(),
            matched_policies: vec!["needs_human".into()],
            approver_group: Some("sec".into()),
            reason: "human gate".into(),
            redacted_fields: vec![],
        },
        ..PipelineRt::default()
    };
    let mut body: serde_json::Value = serde_json::from_slice(&body_json()).expect("v");
    body["dry_run"] = serde_json::json!(true);
    body["tool_call"]["mutates_state"] = serde_json::json!(true);
    let raw = serde_json::to_vec(&body).expect("ser");
    let out =
        run_authorize_pipeline(&rt, &ctx(), &raw, Instant::now(), EvaluateConfig::default()).await;
    match out.body {
        DecisionBody::Decision(resp) => {
            assert_eq!(resp.decision, "require_approval");
            assert!(resp.dry_run);
            assert!(
                resp.approval.is_none(),
                "dry-run must not create approval info"
            );
            assert!(resp.receipt.is_none());
        }
        other => panic!("expected dry-run require_approval, got {other:?}"),
    }
    assert_eq!(*rt.approvals.lock().expect("l"), 0);
    assert_eq!(*rt.receipts.lock().expect("l"), 0);
    // Score-only host write still invoked.
    assert_eq!(*rt.writes.lock().expect("l"), 1);
}
