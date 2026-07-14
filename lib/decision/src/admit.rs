//! Admit phase of authorization evaluation (library-owned).
//!
//! Parses the request body, authenticates the agent (bearer or mTLS), verifies
//! optional request signatures, and applies environment restrictions. On
//! success returns an [`AdmittedAuthorize`] for preflight → guard → metadata →
//! evaluate (see [`crate::run_authorize_pipeline`]).

use aegis_api::models::AuthorizeRequest;
use tracing::warn;

use crate::agent::AuthorizeAgent;
use crate::context::{AuthCredential, AuthorizeContext};
use crate::error_map::aegis_err_to_outcome;
use crate::outcome::{DecisionFailure, DecisionOutcome};
use crate::runtime::DecisionRuntime;

/// Successfully admitted request ready for preflight (and later pipeline stages).
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
#[path = "admit_tests.rs"]
mod tests;
