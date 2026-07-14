//! REST adapter for `POST /v1/authorize`.
//!
//! Thin path: OTel parent → [`AuthorizeContext`] from headers →
//! [`aegis_decision::run_authorize_pipeline`] → wire map. Evaluation lives in
//! `lib/decision`; host I/O is [`crate::decision_runtime::GatewayDecisionRuntime`].

use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::IntoResponse,
};
use std::net::SocketAddr;
use std::sync::Arc;

use super::*;

// Re-export helpers from sub-modules so existing call sites keep a flat
// `routes::` namespace (`hash_tool_call`, receipts, decision writes, …).
pub(crate) use super::authorize_canon::*;
pub(crate) use super::authorize_decision::*;
pub(crate) use super::authorize_receipts::*;

/// Composite tracker key for `/v1/authorize` auth-failure lockout (#1604).
/// Used by [`crate::decision_runtime::GatewayDecisionRuntime`].
pub(crate) fn auth_failure_tracker_key(client_addr: &SocketAddr, tenant_id: &str) -> String {
    format!("{}|{}", client_addr.ip(), tenant_id)
}

/// REST handler: parse ConnectInfo + headers + body, map outcome to response.
#[tracing::instrument(name = "authorize", skip_all)]
pub async fn authorize_action(
    State(state): State<Arc<AppState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    crate::authorize_service::outcome_to_response(
        authorize_action_impl(state, headers, body, client_addr).await,
    )
}

/// Thin REST entry: OTel parent, context from headers, library pipeline, map outcome.
#[tracing::instrument(name = "authorize", skip_all)]
#[doc(hidden)]
pub async fn authorize_action_impl(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Bytes,
    client_addr: SocketAddr,
) -> crate::authorize_service::AuthorizedOutcome {
    // #1156: parent this span to the caller's trace, if the SDK sent a W3C
    // `traceparent` header. A no-op when OTel export isn't configured.
    crate::otel::set_parent_from_headers(&headers);

    let started_at = std::time::Instant::now();
    let auth_ctx =
        match crate::authorize_service::authorize_context_from_headers(&headers, client_addr) {
            Ok(c) => c,
            Err(e) => {
                return crate::authorize_service::AuthorizedOutcome::status_error(e);
            }
        };

    let runtime = crate::authorize_service::GatewayDecisionRuntime::new(state.clone());
    let outcome = crate::authorize_service::run_authorize_pipeline(
        &runtime,
        &auth_ctx,
        &body,
        started_at,
        crate::authorize_service::EvaluateConfig {
            approval_ttl_secs: state.approval_ttl_secs,
        },
    )
    .await;
    crate::authorize_service::decision_outcome_to_authorized(outcome)
}

#[cfg(test)]
#[path = "authorize_tests.rs"]
mod tests;
