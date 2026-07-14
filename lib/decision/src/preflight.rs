//! Preflight phase after admit (library-owned).
//!
//! Tool permission, replay protection, idempotency lookup, heartbeat touch,
//! rate limit, and quota. On success returns a [`PreflightedAuthorize`] for
//! admission-webhook / ban / Cedar stages still hosted in the gateway.

use aegis_api::models::{AuthorizeRequest, DecisionRecord};
use chrono::Utc;
use tracing::{error, warn};

use crate::admit::AdmittedAuthorize;
use crate::agent::AuthorizeAgent;
use crate::error_map::aegis_err_to_outcome;
use crate::outcome::{DecisionFailure, DecisionOutcome};
use crate::runtime::DecisionRuntime;

/// Admitted + preflighted request ready for admission webhook / Cedar.
#[derive(Debug, Clone)]
pub struct PreflightedAuthorize {
    pub request: AuthorizeRequest,
    pub agent: AuthorizeAgent,
    pub root_trust_level: String,
    pub dry_run: bool,
    pub used_mtls: bool,
    /// Normalized tool identifier for authorization lookups (#1335).
    pub normalized_tool: String,
    /// Normalized action identifier for authorization lookups (#1335).
    pub normalized_action: String,
}

/// How preflight ended when it did not continue the main pipeline.
#[derive(Debug)]
pub enum PreflightTerminal {
    /// Structured failure or partial deny (permission, replay, rate, quota, …).
    Outcome(DecisionOutcome),
    /// Prior decision for this request_id — host rebuilds the response.
    IdempotentReplay(Box<DecisionRecord>),
}

/// Run preflight guards after a successful [`crate::admit_authorize`].
///
/// Ordering matches the historical gateway path: tool permission and
/// idempotency lookup run concurrently; results are checked in permission →
/// replay → idempotent-replay priority order; then rate limit and quota.
pub async fn preflight_authorize(
    runtime: &dyn DecisionRuntime,
    admitted: AdmittedAuthorize,
) -> Result<PreflightedAuthorize, PreflightTerminal> {
    let request = admitted.request;
    let agent = admitted.agent;
    let root_trust_level = admitted.root_trust_level;
    let dry_run = admitted.dry_run;
    let used_mtls = admitted.used_mtls;

    let tenant_id = agent.tenant_id.clone();
    let agent_id = agent.id.clone();
    let tool = request.tool_call.tool.clone();

    let request_id = if dry_run {
        None
    } else {
        request
            .request_id
            .as_deref()
            .filter(|r| !r.is_empty())
            .map(str::to_string)
    };

    let (permission_result, idempotency_result) = tokio::join!(
        runtime.agent_tool_permitted(&tenant_id, &agent_id, &tool),
        async {
            match request_id.as_deref() {
                Some(rid) => {
                    runtime
                        .get_decision_by_request_id(&tenant_id, &agent_id, rid)
                        .await
                }
                None => Ok(None),
            }
        }
    );

    match permission_result {
        Ok(false) => {
            warn!(
                "Tool permission denied: agent={} tenant={} tool={}",
                agent_id, tenant_id, tool
            );
            return Err(PreflightTerminal::Outcome(DecisionOutcome::partial_deny(
                format!("agent not permitted to call tool '{tool}'"),
            )));
        }
        Ok(true) => {}
        Err(e) => {
            error!("DB error checking tool permissions: {:?}", e);
            return Err(PreflightTerminal::Outcome(aegis_err_to_outcome(e)));
        }
    }

    if let Some(nonce) = request.nonce.as_deref().filter(|n| !n.is_empty()) {
        let now = Utc::now();
        if let Err(reason) =
            aegis_policy::validation::validate_replay_timestamp(now, request.timestamp)
        {
            warn!(
                "Replay protection: rejecting request with stale timestamp for tenant={} agent={} (timestamp validation failed)",
                tenant_id, agent_id
            );
            return Err(PreflightTerminal::Outcome(DecisionOutcome::failure(
                DecisionFailure {
                    class: crate::outcome::DecisionFailureClass::Conflict,
                    message: reason,
                    details: Some(serde_json::json!({"reason": "replay_timestamp_expired"})),
                },
            )));
        }

        let is_replay = match runtime
            .check_and_record_nonce(&tenant_id, &agent_id, nonce, now)
            .await
        {
            Ok(replayed) => replayed,
            Err(e) => {
                error!("Replay store error (failing closed): {:?}", e);
                return Err(PreflightTerminal::Outcome(DecisionOutcome::failure(
                    DecisionFailure::internal("Replay protection unavailable"),
                )));
            }
        };
        if is_replay {
            warn!(
                "Replay protection: rejecting duplicate nonce for tenant={} agent={}",
                tenant_id, agent_id
            );
            return Err(PreflightTerminal::Outcome(DecisionOutcome::failure(
                DecisionFailure {
                    class: crate::outcome::DecisionFailureClass::Conflict,
                    message: "Duplicate nonce: possible replay attack".into(),
                    details: Some(serde_json::json!({"reason": "replay_nonce_reused"})),
                },
            )));
        }
    }

    let normalized_tool =
        aegis_policy::validation::normalize_tool_identifier(&request.tool_call.tool);
    let normalized_action =
        aegis_policy::validation::normalize_tool_identifier(&request.tool_call.action);

    if !dry_run {
        match idempotency_result {
            Ok(Some(record)) => {
                return Err(PreflightTerminal::IdempotentReplay(Box::new(record)));
            }
            Ok(None) => {}
            Err(e) => {
                error!("Idempotency lookup failed: {:?}", e);
                return Err(PreflightTerminal::Outcome(aegis_err_to_outcome(e)));
            }
        }
        runtime.touch_heartbeat(&tenant_id, &agent_id);
    }

    if !runtime.check_rate_limit(&tenant_id).await {
        return Err(PreflightTerminal::Outcome(DecisionOutcome::failure(
            DecisionFailure::too_many_requests("Too many requests. Rate limit exceeded."),
        )));
    }

    if !runtime.check_quota(&tenant_id) {
        return Err(PreflightTerminal::Outcome(DecisionOutcome::failure(
            DecisionFailure::too_many_requests("Request quota exceeded."),
        )));
    }

    Ok(PreflightedAuthorize {
        request,
        agent,
        root_trust_level,
        dry_run,
        used_mtls,
        normalized_tool,
        normalized_action,
    })
}

#[cfg(test)]
mod tests {
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
        async fn agent_tool_permitted(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<bool, AegisError> {
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
}
