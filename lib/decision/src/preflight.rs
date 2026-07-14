//! Preflight phase after admit (library-owned).
//!
//! Tool permission, replay protection, idempotency lookup, heartbeat touch,
//! rate limit, and quota. On success returns a [`PreflightedAuthorize`] for
//! the guard stage (`guard_authorize`).

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
#[path = "preflight_tests.rs"]
mod tests;
