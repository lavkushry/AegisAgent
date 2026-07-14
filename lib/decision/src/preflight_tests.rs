use super::*;
use crate::agent::AuthorizeAgent;
use crate::outcome::DecisionBody;
use aegis_common::errors::AegisError;
use chrono::{Duration, Utc};
use std::net::SocketAddr;
use std::sync::Mutex;

struct MockRt {
    permitted: bool,
    rate_ok: bool,
    quota_ok: bool,
    replay: bool,
    idempotent: Option<DecisionRecord>,
    heartbeats: Mutex<u32>,
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
        Ok(self.permitted)
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
        _: chrono::DateTime<Utc>,
    ) -> Result<bool, AegisError> {
        Ok(self.replay)
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
    async fn write_decision_and_audit(
        &self,
        _: crate::write::DecisionAuditWrite<'_>,
    ) -> Result<i32, AegisError> {
        Ok(0)
    }
    async fn call_admission_webhook(
        &self,
        _: &aegis_api::models::AuthorizeRequest,
    ) -> Result<crate::runtime::AdmissionEffect, AegisError> {
        Ok(crate::runtime::AdmissionEffect::Disabled)
    }
    fn compute_action_hash(
        &self,
        _: &str,
        _: Option<&str>,
        _: &aegis_api::models::AuthorizeToolCall,
    ) -> String {
        String::new()
    }
    async fn enforcement_status(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<crate::runtime::EnforcementStatus, AegisError> {
        Ok(crate::runtime::EnforcementStatus::Clear)
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

fn admitted(nonce: Option<&str>, request_id: Option<&str>) -> AdmittedAuthorize {
    let body = serde_json::json!({
        "request_id": request_id,
        "nonce": nonce,
        "agent": { "id": "a1", "environment": "dev" },
        "tool_call": {
            "tool": "Echo",
            "action": "Run",
            "parameters": {},
            "mutates_state": false
        },
        "context": {
            "source_trust": "trusted_internal_unsigned",
            "contains_sensitive_data": false
        }
    });
    let request: AuthorizeRequest = serde_json::from_value(body).expect("req");
    AdmittedAuthorize {
        request,
        agent: AuthorizeAgent::new("agent-1", "tenant-1", "low"),
        root_trust_level: "trusted_internal_unsigned".into(),
        dry_run: false,
        used_mtls: false,
    }
}

#[tokio::test]
async fn preflight_denies_tool_permission() {
    let rt = MockRt {
        permitted: false,
        rate_ok: true,
        quota_ok: true,
        replay: false,
        idempotent: None,
        heartbeats: Mutex::new(0),
    };
    let err = preflight_authorize(&rt, admitted(None, None))
        .await
        .expect_err("deny");
    match err {
        PreflightTerminal::Outcome(o) => {
            assert_eq!(o.http_status, 403);
            match o.body {
                DecisionBody::PartialDeny { reason } => {
                    assert!(reason.contains("not permitted"));
                }
                _ => panic!("partial deny"),
            }
        }
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_rejects_replay_nonce() {
    let rt = MockRt {
        permitted: true,
        rate_ok: true,
        quota_ok: true,
        replay: true,
        idempotent: None,
        heartbeats: Mutex::new(0),
    };
    let err = preflight_authorize(&rt, admitted(Some("n1"), None))
        .await
        .expect_err("replay");
    match err {
        PreflightTerminal::Outcome(o) => {
            assert_eq!(o.http_status, 409);
        }
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_rejects_stale_timestamp() {
    let rt = MockRt {
        permitted: true,
        rate_ok: true,
        quota_ok: true,
        replay: false,
        idempotent: None,
        heartbeats: Mutex::new(0),
    };
    let mut a = admitted(Some("n1"), None);
    a.request.timestamp = Some(Utc::now() - Duration::seconds(600));
    let err = preflight_authorize(&rt, a).await.expect_err("stale");
    match err {
        PreflightTerminal::Outcome(o) => assert_eq!(o.http_status, 409),
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_idempotent_replay() {
    let record = DecisionRecord {
        id: uuid::Uuid::nil().to_string(),
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
        reason: Some("ok".into()),
        matched_policy_ids: None,
        request_id: Some("r1".into()),
        latency_ms: None,
        composite_risk_score: Some(10),
        root_trust_level: Some("trusted_internal_unsigned".into()),
        parent_run_id: None,
        created_at: Utc::now(),
    };
    let rt = MockRt {
        permitted: true,
        rate_ok: true,
        quota_ok: true,
        replay: false,
        idempotent: Some(record),
        heartbeats: Mutex::new(0),
    };
    let err = preflight_authorize(&rt, admitted(None, Some("r1")))
        .await
        .expect_err("replay id");
    match err {
        PreflightTerminal::IdempotentReplay(r) => assert_eq!(r.decision, "allow"),
        PreflightTerminal::Outcome(_) => panic!("idempotent"),
    }
    // Heartbeat only on continue path
    assert_eq!(*rt.heartbeats.lock().expect("l"), 0);
}

#[tokio::test]
async fn preflight_rate_limit() {
    let rt = MockRt {
        permitted: true,
        rate_ok: false,
        quota_ok: true,
        replay: false,
        idempotent: None,
        heartbeats: Mutex::new(0),
    };
    let err = preflight_authorize(&rt, admitted(None, None))
        .await
        .expect_err("rate");
    match err {
        PreflightTerminal::Outcome(o) => assert_eq!(o.http_status, 429),
        _ => panic!("outcome"),
    }
}

#[tokio::test]
async fn preflight_success_normalizes_and_heartbeats() {
    let rt = MockRt {
        permitted: true,
        rate_ok: true,
        quota_ok: true,
        replay: false,
        idempotent: None,
        heartbeats: Mutex::new(0),
    };
    let got = preflight_authorize(&rt, admitted(None, None))
        .await
        .expect("ok");
    assert_eq!(got.normalized_tool, "echo");
    assert_eq!(got.normalized_action, "run");
    assert_eq!(*rt.heartbeats.lock().expect("l"), 1);
}
