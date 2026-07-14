//! Shared mock [`DecisionRuntime`] for unit and pipeline e2e tests.
//!
//! Kept under `#[cfg(test)]` so production crates never link this code.
//! Stage and pipeline tests configure fields via struct update syntax.

use crate::agent::AuthorizeAgent;
use crate::pipeline::authorize_response_from_decision_record;
use crate::runtime::{
    AdmissionEffect, ApprovalCreateParams, DecisionRuntime, EnforcementStatus, McpToolMeta,
    PolicyDecisionView, RegisteredActionMeta,
};
use crate::write::DecisionAuditWrite;
use aegis_api::models::{
    ApprovalResponseInfo, AuthorizeRequest, AuthorizeResponse, AuthorizeToolCall, DecisionRecord,
    ReceiptIdentity,
};
use aegis_common::errors::AegisError;
use chrono::{DateTime, Utc};
use std::net::SocketAddr;
use std::sync::Mutex;
use uuid::Uuid;

/// Configurable host-port stub for decision-crate tests.
pub struct MockRuntime {
    pub agent: Option<AuthorizeAgent>,
    pub auth_blocked: bool,
    pub auth_failures: Mutex<u32>,
    pub tool_permitted: bool,
    pub idempotent: Option<DecisionRecord>,
    /// When true, `check_and_record_nonce` reports a replay.
    pub nonce_is_replay: bool,
    pub rate_ok: bool,
    pub quota_ok: bool,
    pub admission: AdmissionEffect,
    pub enforcement: EnforcementStatus,
    pub skill: Option<RegisteredActionMeta>,
    pub mcp_server_permitted: bool,
    pub mcp_server_status: Option<String>,
    pub mcp_tool: Option<McpToolMeta>,
    pub cedar: PolicyDecisionView,
    pub audit_capacity: bool,
    /// When true, `write_decision_and_audit` returns an internal error.
    pub write_fail: bool,
    /// When true, `emit_receipt_durable` fails (protected-path fail-closed).
    pub receipt_fail: bool,
    /// When set, `create_approval` returns `BadRequest` (e.g. invalid callback).
    pub approval_bad_request: Option<String>,
    /// When true, `create_approval` returns an internal error.
    pub approval_fail: bool,
    /// When true, `ensure_policies_loaded` fails.
    pub policies_load_fail: bool,
    /// When true, `evaluate_cedar` fails.
    pub cedar_fail: bool,
    /// When set, `maybe_escalate_risk_tier` returns this `(old, new)` pair.
    pub escalate_to: Option<(String, String)>,
    pub action_hash: String,
    pub writes: Mutex<u32>,
    pub heartbeats: Mutex<u32>,
    pub receipts: Mutex<u32>,
    pub approvals: Mutex<u32>,
    pub quarantines: Mutex<u32>,
    pub escalations: Mutex<u32>,
    pub provenance_denials: Mutex<u32>,
    pub best_effort_receipts: Mutex<u32>,
}

impl Default for MockRuntime {
    fn default() -> Self {
        Self {
            agent: Some(AuthorizeAgent::new("agent-1", "tenant-1", "low")),
            auth_blocked: false,
            auth_failures: Mutex::new(0),
            tool_permitted: true,
            idempotent: None,
            nonce_is_replay: false,
            rate_ok: true,
            quota_ok: true,
            admission: AdmissionEffect::Disabled,
            enforcement: EnforcementStatus::Clear,
            skill: None,
            mcp_server_permitted: true,
            mcp_server_status: None,
            mcp_tool: None,
            cedar: PolicyDecisionView {
                decision: "allow".into(),
                matched_policies: vec!["base_allow".into()],
                approver_group: None,
                reason: "ok".into(),
                redacted_fields: vec![],
            },
            audit_capacity: true,
            write_fail: false,
            receipt_fail: false,
            approval_bad_request: None,
            approval_fail: false,
            policies_load_fail: false,
            cedar_fail: false,
            escalate_to: None,
            action_hash: "deadbeef".into(),
            writes: Mutex::new(0),
            heartbeats: Mutex::new(0),
            receipts: Mutex::new(0),
            approvals: Mutex::new(0),
            quarantines: Mutex::new(0),
            escalations: Mutex::new(0),
            provenance_denials: Mutex::new(0),
            best_effort_receipts: Mutex::new(0),
        }
    }
}

#[async_trait::async_trait]
impl DecisionRuntime for MockRuntime {
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
        self.auth_blocked
    }

    fn record_auth_failure(&self, _: SocketAddr, _: &str) {
        *self.auth_failures.lock().expect("lock") += 1;
    }

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
        Ok(self.nonce_is_replay)
    }

    async fn check_rate_limit(&self, _: &str) -> bool {
        self.rate_ok
    }

    fn check_quota(&self, _: &str) -> bool {
        self.quota_ok
    }

    fn touch_heartbeat(&self, _: &str, _: &str) {
        *self.heartbeats.lock().expect("lock") += 1;
    }

    async fn write_decision_and_audit(&self, w: DecisionAuditWrite<'_>) -> Result<i32, AegisError> {
        if self.write_fail {
            return Err(AegisError::Internal("db down".into()));
        }
        *self.writes.lock().expect("lock") += 1;
        Ok(w.risk_score)
    }

    async fn call_admission_webhook(
        &self,
        _: &AuthorizeRequest,
    ) -> Result<AdmissionEffect, AegisError> {
        Ok(self.admission.clone())
    }

    fn compute_action_hash(&self, _: &str, _: Option<&str>, _: &AuthorizeToolCall) -> String {
        self.action_hash.clone()
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
        Ok(self.skill.clone())
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
        if self.policies_load_fail {
            return Err(AegisError::Internal("policy pack unavailable".into()));
        }
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
        if self.cedar_fail {
            return Err(AegisError::Internal("cedar engine down".into()));
        }
        Ok(self.cedar.clone())
    }

    fn record_provenance_denial(&self) {
        *self.provenance_denials.lock().expect("lock") += 1;
    }

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
        if self.receipt_fail {
            return Err(AegisError::Internal("receipt store unavailable".into()));
        }
        *self.receipts.lock().expect("lock") += 1;
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
        *self.best_effort_receipts.lock().expect("lock") += 1;
    }

    async fn quarantine_agent(&self, _: &str, _: &str) -> Result<(), AegisError> {
        *self.quarantines.lock().expect("lock") += 1;
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
        if let Some(msg) = &self.approval_bad_request {
            return Err(AegisError::BadRequest(msg.clone()));
        }
        if self.approval_fail {
            return Err(AegisError::Internal("approval store unavailable".into()));
        }
        *self.approvals.lock().expect("lock") += 1;
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
        Ok(self.escalate_to.clone())
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
        *self.escalations.lock().expect("lock") += 1;
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
