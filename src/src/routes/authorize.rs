#![allow(unused_imports)]
use crate::error::StatusError;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn, Instrument};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;
use aegis_storage::traits::DecisionListFilters;

use super::*;

// Re-export helpers from sub-modules so existing call sites are unaffected.
pub(crate) use super::authorize_canon::*;
pub(crate) use super::authorize_decision::*;
pub(crate) use super::authorize_receipts::*;

/// Composite tracker key for `/v1/authorize` auth-failure lockout (#1604).
/// Used by [`crate::authorize_service::GatewayDecisionRuntime`].
pub(crate) fn auth_failure_tracker_key(client_addr: &SocketAddr, tenant_id: &str) -> String {
    format!("{}|{}", client_addr.ip(), tenant_id)
}

// Authorize Action Handler
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
