//! End-to-end authorize pipeline (library-owned).
//!
//! Chains admit → preflight → guard → metadata → evaluate behind a single
//! entry point so gateway adapters only build context and map outcomes.

use aegis_api::models::{ApprovalResponseInfo, AuthorizeResponse, DecisionRecord};
use uuid::Uuid;

use crate::context::AuthorizeContext;
use crate::evaluate::{evaluate_authorize, EvaluateConfig};
use crate::guard::guard_authorize;
use crate::metadata::metadata_authorize;
use crate::outcome::DecisionOutcome;
use crate::preflight::{preflight_authorize, PreflightTerminal};
use crate::risk::risk_level_for_score;
use crate::runtime::DecisionRuntime;

/// Rebuild an [`AuthorizeResponse`] for an idempotent decision replay (#0072).
pub fn authorize_response_from_decision_record(
    record: DecisionRecord,
    approval: Option<ApprovalResponseInfo>,
) -> AuthorizeResponse {
    let decision_id = Uuid::parse_str(&record.id).unwrap_or_else(|_| Uuid::nil());
    let risk_score = record.risk_score.unwrap_or(0);
    let composite_risk_score = record.composite_risk_score.unwrap_or(risk_score);
    let matched_policies: Vec<String> = record
        .matched_policy_ids
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    AuthorizeResponse {
        decision_id,
        decision: record.decision,
        risk_score,
        risk_level: risk_level_for_score(risk_score),
        composite_risk_score,
        reason: record.reason.unwrap_or_default(),
        matched_policies,
        approval,
        redacted_fields: vec![],
        root_trust_level: record
            .root_trust_level
            .unwrap_or_else(|| "unknown".to_string()),
        // Idempotency replays only ever read a previously-persisted real
        // decision — dry-run requests bypass idempotency entirely (#1281).
        dry_run: false,
        // The original decision already wrote its durable receipt; a replay
        // returns the cached decision and does not re-emit one.
        receipt: None,
    }
}

/// Run the full authorize pipeline for one already-authenticated context.
///
/// Callers must have built [`AuthorizeContext`] (tenant + credential + peer).
/// Returns a protocol-neutral [`DecisionOutcome`]; adapters map to REST/gRPC.
pub async fn run_authorize_pipeline(
    runtime: &dyn DecisionRuntime,
    ctx: &AuthorizeContext,
    raw_body: &[u8],
    started_at: std::time::Instant,
    config: EvaluateConfig,
) -> DecisionOutcome {
    let admitted = match crate::admit_authorize(runtime, ctx, raw_body).await {
        Ok(a) => a,
        Err(outcome) => return outcome,
    };

    let preflighted = match preflight_authorize(runtime, admitted).await {
        Ok(p) => p,
        Err(PreflightTerminal::Outcome(outcome)) => return outcome,
        Err(PreflightTerminal::IdempotentReplay(record)) => {
            return match runtime.idempotent_replay(*record).await {
                Ok(resp) => DecisionOutcome::decision(resp),
                Err(e) => crate::error_map::aegis_err_to_outcome(e),
            };
        }
    };

    let guarded = match guard_authorize(runtime, preflighted, started_at).await {
        Ok(g) => g,
        Err(outcome) => return outcome,
    };

    let meta = match metadata_authorize(runtime, guarded, started_at).await {
        Ok(m) => m,
        Err(outcome) => return outcome,
    };

    evaluate_authorize(runtime, meta, started_at, config).await
}

#[cfg(test)]
mod tests {
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
        writes: Mutex<u32>,
        heartbeats: Mutex<u32>,
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
                writes: Mutex::new(0),
                heartbeats: Mutex::new(0),
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
            true
        }
        fn check_quota(&self, _: &str) -> bool {
            true
        }
        fn touch_heartbeat(&self, _: &str, _: &str) {
            *self.heartbeats.lock().expect("l") += 1;
        }
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
        fn compute_action_hash(
            &self,
            _: &str,
            _: Option<&str>,
            _: &AuthorizeToolCall,
        ) -> String {
            "deadbeef".into()
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
        async fn mcp_server_status(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<String>, AegisError> {
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
            true
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
        let out = run_authorize_pipeline(
            &rt,
            &ctx(),
            &raw,
            Instant::now(),
            EvaluateConfig::default(),
        )
        .await;
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
        let out = run_authorize_pipeline(
            &rt,
            &ctx(),
            &raw,
            Instant::now(),
            EvaluateConfig::default(),
        )
        .await;
        match out.body {
            DecisionBody::Decision(resp) => {
                assert_eq!(resp.decision, "require_approval");
                assert!(resp.approval.is_some());
            }
            other => panic!("expected approval decision, got {other:?}"),
        }
        assert_eq!(*rt.writes.lock().expect("l"), 1);
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
        let out = run_authorize_pipeline(
            &rt,
            &ctx(),
            &raw,
            Instant::now(),
            EvaluateConfig::default(),
        )
        .await;
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
        let out = run_authorize_pipeline(
            &rt,
            &ctx(),
            &raw,
            Instant::now(),
            EvaluateConfig::default(),
        )
        .await;
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
}
