//! Admit phase of authorization evaluation (library-owned).
//!
//! Covers the front of the former gateway `authorize_action_impl` through
//! agent authentication, request-signature verification, and environment
//! restriction. Cedar evaluation, persistence, and receipts remain in the
//! gateway until subsequent extraction stages.

use aegis_api::models::AuthorizeRequest;
use tracing::warn;

use crate::agent::AuthorizeAgent;
use crate::context::{AuthCredential, AuthorizeContext};
use crate::error_map::aegis_err_to_outcome;
use crate::outcome::{DecisionFailure, DecisionOutcome};
use crate::runtime::DecisionRuntime;

/// Successfully admitted request ready for policy evaluation and persistence.
#[derive(Debug, Clone)]
pub struct AdmittedAuthorize {
    pub request: AuthorizeRequest,
    pub agent: AuthorizeAgent,
    /// Tighten-only effective trust for this hop (also reported on responses).
    pub root_trust_level: String,
    pub dry_run: bool,
    /// True when the agent was resolved via mTLS CN rather than bearer token.
    pub used_mtls: bool,
}

/// Parse, authenticate, and validate the request against agent configuration.
///
/// Uses [`AuthorizeContext`] as the single tenant/credential authority (no
/// header re-reads). Failures return a typed [`DecisionOutcome`]; success is
/// an [`AdmittedAuthorize`] for the rest of the pipeline.
pub async fn admit_authorize(
    runtime: &dyn DecisionRuntime,
    ctx: &AuthorizeContext,
    raw_body: &[u8],
) -> Result<AdmittedAuthorize, DecisionOutcome> {
    let mut request: AuthorizeRequest = match serde_json::from_slice(raw_body) {
        Ok(p) => p,
        Err(_) => {
            return Err(DecisionOutcome::failure(DecisionFailure::bad_request(
                "Invalid JSON body",
            )));
        }
    };

    let dry_run = request.dry_run.unwrap_or(false);

    let root_trust_level = aegis_policy::trust_chain::propagate(
        request
            .trace
            .as_ref()
            .and_then(|t| t.root_trust_level.as_deref()),
        &request.context.source_trust,
    );

    let runtime_tenant_id = ctx.tenant_id.as_str();
    if runtime_tenant_id.trim().is_empty() {
        return Err(DecisionOutcome::failure(DecisionFailure::bad_request(
            "Missing tenant_id",
        )));
    }

    if runtime.auth_failure_blocked(ctx.client_addr, runtime_tenant_id) {
        return Err(DecisionOutcome::failure(
            DecisionFailure::too_many_requests(
                "Too many failed authentication attempts. Try again later.",
            )
            .with_details(serde_json::json!({"reason": "rate_limited_auth_failures"})),
        ));
    }

    let (agent, used_mtls) = match &ctx.credential {
        AuthCredential::MtlsCn(cn) => {
            if cn.is_empty() {
                runtime.record_auth_failure(ctx.client_addr, runtime_tenant_id);
                return Err(DecisionOutcome::failure(DecisionFailure::unauthorized(
                    "Missing agent token",
                )));
            }
            match runtime
                .get_agent_by_mtls_cn(runtime_tenant_id, cn)
                .await
                .map_err(aegis_err_to_outcome)?
            {
                Some(a) => (a, true),
                None => {
                    runtime.record_auth_failure(ctx.client_addr, runtime_tenant_id);
                    return Err(DecisionOutcome::failure(DecisionFailure::unauthorized(
                        "Unrecognized mTLS client certificate",
                    )));
                }
            }
        }
        AuthCredential::BearerToken(token) => {
            if token.is_empty() {
                runtime.record_auth_failure(ctx.client_addr, runtime_tenant_id);
                return Err(DecisionOutcome::failure(DecisionFailure::unauthorized(
                    "Missing agent token",
                )));
            }
            match runtime
                .get_agent_by_token(runtime_tenant_id, token)
                .await
                .map_err(aegis_err_to_outcome)?
            {
                Some(a) => (a, false),
                None => {
                    runtime.record_auth_failure(ctx.client_addr, runtime_tenant_id);
                    return Err(DecisionOutcome::failure(DecisionFailure::unauthorized(
                        "Invalid or quarantined agent token",
                    )));
                }
            }
        }
    };

    let tenant_id = agent.tenant_id.clone();
    let agent_id = agent.id.clone();

    if let Some(ref signing_key) = agent.signing_key {
        let sig = match ctx.request_signature.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => {
                warn!(
                    "Request signature missing for agent={} tenant={}",
                    agent_id, tenant_id
                );
                return Err(DecisionOutcome::failure(DecisionFailure::unauthorized(
                    "missing_request_signature",
                )));
            }
        };
        if !aegis_common::hash::verify_request_signature(signing_key, raw_body, sig) {
            warn!(
                "Request signature invalid for agent={} tenant={}",
                agent_id, tenant_id
            );
            return Err(DecisionOutcome::failure(DecisionFailure::unauthorized(
                "invalid_request_signature",
            )));
        }
    }

    if let Err(reason) = aegis_policy::validation::validate_environment(
        agent.allowed_environments.as_deref(),
        &request.agent.environment,
    ) {
        warn!(
            "Environment restriction: agent={} tenant={} env={} error={}",
            agent_id, tenant_id, request.agent.environment, reason
        );
        return Err(DecisionOutcome::partial_deny(reason));
    }

    // Keep the request body owned for the rest of the pipeline; we already
    // validated parse. Mutating later stages (admission webhook) still need
    // a mut request — leave ownership with the caller via this struct.
    let _ = &mut request;

    Ok(AdmittedAuthorize {
        request,
        agent,
        root_trust_level,
        dry_run,
        used_mtls,
    })
}

#[cfg(test)]
mod tests {
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
}
