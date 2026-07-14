use super::*;
use crate::context::{AuthCredential, AuthorizeContext, Transport};
use crate::outcome::DecisionBody;
use aegis_api::models::DecisionRecord;
use aegis_common::errors::AegisError;
use chrono::{DateTime, Utc};
use std::net::SocketAddr;
use std::sync::Mutex;

struct MockRuntime {
    agent: Option<AuthorizeAgent>,
    blocked: bool,
    failures: Mutex<u32>,
}

#[async_trait::async_trait]
impl DecisionRuntime for MockRuntime {
    async fn get_agent_by_token(
        &self,
        _tenant_id: &str,
        _token: &str,
    ) -> Result<Option<AuthorizeAgent>, AegisError> {
        Ok(self.agent.clone())
    }

    async fn get_agent_by_mtls_cn(
        &self,
        _tenant_id: &str,
        _cn: &str,
    ) -> Result<Option<AuthorizeAgent>, AegisError> {
        Ok(self.agent.clone())
    }

    fn auth_failure_blocked(&self, _client_addr: SocketAddr, _tenant_id: &str) -> bool {
        self.blocked
    }

    fn record_auth_failure(&self, _client_addr: SocketAddr, _tenant_id: &str) {
        *self.failures.lock().expect("lock") += 1;
    }

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

fn addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 4443))
}

fn minimal_body(env: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "agent": {
            "id": "a1",
            "environment": env,
            "framework": "test"
        },
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

#[tokio::test]
async fn admit_rejects_invalid_json() {
    let rt = MockRuntime {
        agent: None,
        blocked: false,
        failures: Mutex::new(0),
    };
    let ctx = AuthorizeContext::new(
        "t1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    );
    let err = admit_authorize(&rt, &ctx, b"not-json")
        .await
        .expect_err("must fail");
    assert_eq!(err.http_status, 400);
}

#[tokio::test]
async fn admit_rejects_bad_token_and_records_failure() {
    let rt = MockRuntime {
        agent: None,
        blocked: false,
        failures: Mutex::new(0),
    };
    let ctx = AuthorizeContext::new(
        "t1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("bad".into()),
    );
    let body = minimal_body("dev");
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("must fail");
    assert_eq!(err.http_status, 401);
    assert_eq!(*rt.failures.lock().expect("lock"), 1);
    match err.body {
        DecisionBody::Failure(f) => {
            assert!(f.message.contains("Invalid or quarantined"));
        }
        _ => panic!("expected failure body"),
    }
}

#[tokio::test]
async fn admit_lockout_returns_429() {
    let rt = MockRuntime {
        agent: None,
        blocked: true,
        failures: Mutex::new(0),
    };
    let ctx = AuthorizeContext::new(
        "t1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("tok".into()),
    );
    let body = minimal_body("dev");
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("must fail");
    assert_eq!(err.http_status, 429);
}

#[tokio::test]
async fn admit_success_bearer() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.allowed_environments = None;
    let rt = MockRuntime {
        agent: Some(agent),
        blocked: false,
        failures: Mutex::new(0),
    };
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("good".into()),
    );
    let body = minimal_body("production");
    let admitted = admit_authorize(&rt, &ctx, &body).await.expect("ok");
    assert_eq!(admitted.agent.id, "agent-1");
    assert!(!admitted.used_mtls);
    assert!(!admitted.dry_run);
    assert_eq!(admitted.root_trust_level, "trusted_internal_unsigned");
}

#[tokio::test]
async fn admit_environment_restriction_partial_deny() {
    let mut agent = AuthorizeAgent::new("agent-1", "tenant-1", "low");
    agent.allowed_environments = Some(r#"["staging"]"#.into());
    let rt = MockRuntime {
        agent: Some(agent),
        blocked: false,
        failures: Mutex::new(0),
    };
    let ctx = AuthorizeContext::new(
        "tenant-1",
        addr(),
        Transport::Rest,
        AuthCredential::BearerToken("good".into()),
    );
    let body = minimal_body("production");
    let err = admit_authorize(&rt, &ctx, &body)
        .await
        .expect_err("must deny");
    assert_eq!(err.http_status, 403);
    match err.body {
        DecisionBody::PartialDeny { reason } => {
            assert!(!reason.is_empty());
        }
        _ => panic!("expected partial deny"),
    }
}
