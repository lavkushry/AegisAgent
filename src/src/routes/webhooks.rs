#![allow(unused_imports)]
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
use tracing::{error, info, warn};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;

use super::*;

/// Verifies a GitHub-style `X-Hub-Signature-256: sha256=<hex>` header against
/// `body` using `secret` (#1339). Returns `false` on any malformed input
/// (missing `sha256=` prefix, non-hex digest, wrong length) as well as on a
/// digest mismatch — fail closed. Uses [`Mac::verify_slice`], which performs
/// a constant-time comparison.
pub(crate) fn verify_github_webhook_signature(
    secret: &str,
    body: &[u8],
    sig_header: &axum::http::HeaderValue,
) -> bool {
    let Ok(sig_header) = sig_header.to_str() else {
        return false;
    };
    let Some(hex_digest) = sig_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_digest) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Verifies a Slack-style `X-Slack-Signature: v0=<hex>` header against
/// `v0:{timestamp}:{body}` using `secret` (#1276), per Slack's request
/// signing spec. Returns `false` on any malformed input (missing `v0=`
/// prefix, non-hex digest, wrong length) as well as on a digest mismatch —
/// fail closed. Uses [`Mac::verify_slice`], which performs a constant-time
/// comparison.
pub(crate) fn verify_slack_signature(
    secret: &str,
    timestamp: &str,
    body: &[u8],
    sig_header: &str,
) -> bool {
    let Some(hex_digest) = sig_header.strip_prefix("v0=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_digest) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Returns `true` if `timestamp` (Slack's `X-Slack-Request-Timestamp`, Unix
/// seconds) is within 5 minutes of `now` in either direction (#1276). Slack's
/// own verification guidance rejects requests older than 5 minutes to defend
/// against replay of a captured request/signature pair. Also rejects
/// malformed (non-integer) timestamps — fail closed.
pub(crate) fn slack_timestamp_is_fresh(timestamp: &str, now: DateTime<Utc>) -> bool {
    let Ok(ts) = timestamp.parse::<i64>() else {
        return false;
    };
    let Some(ts_time) = DateTime::<Utc>::from_timestamp(ts, 0) else {
        return false;
    };
    (now - ts_time).abs() <= Duration::minutes(5)
}

/// Extracts the `payload` field from a Slack interactive-component callback
/// body, `application/x-www-form-urlencoded` with a single `payload=<url
/// -encoded JSON>` field. Returns `None` if the field is absent or not valid
/// UTF-8 after percent-decoding.
pub(crate) fn extract_slack_payload_field(body: &[u8]) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    for pair in body_str.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key == "payload" {
            let value = value.replace('+', " ");
            return percent_encoding::percent_decode_str(&value)
                .decode_utf8()
                .ok()
                .map(|s| s.to_string());
        }
    }
    None
}

/// `POST /v1/callbacks/slack` (#1276) — verifies and processes a Slack
/// interactive-component (Block Kit button) callback for an approval
/// decision.
///
/// Not tenant-scoped via [`TenantId`]: Slack does not send our agent
/// authentication header, so the tenant is recovered from the callback
/// payload itself (see below). Authenticity instead comes entirely from the
/// HMAC signature.
///
/// Security checks, all fail-closed:
/// - If [`AppState::slack_signing_secret`] is not configured, the endpoint
///   refuses every request with `404` (the feature is effectively disabled —
///   no valid signature can ever be verified without a secret).
/// - `X-Slack-Request-Timestamp` must be present, a valid Unix timestamp, and
///   within 5 minutes of now ([`slack_timestamp_is_fresh`]) — defends against
///   replay of a captured request.
/// - `X-Slack-Signature` must be present and match `v0=HMAC-SHA256("v0:{ts}:
///   {body}")` ([`verify_slack_signature`]) — defends against forged
///   callbacks (spoofed approvals).
///
/// On success, the `payload` form field is parsed as Slack's
/// `block_actions` interactive payload. `actions[0].value` is expected to
/// encode `"{tenant_id}:{approval_id}"` (set when the approval notification
/// was sent to Slack) and `actions[0].action_id` is `"approve"` or
/// `"reject"`; the approver identity is taken from `user.username` (falling
/// back to `user.id`). The corresponding approval is then approved/rejected
/// exactly as `POST /v1/approvals/:id/{approve,reject}` would.
pub async fn slack_callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let Some(secret) = state.slack_signing_secret.as_ref() else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response();
    };

    let timestamp = match headers
        .get("X-Slack-Request-Timestamp")
        .and_then(|v| v.to_str().ok())
    {
        Some(ts) if slack_timestamp_is_fresh(ts, Utc::now()) => ts,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "missing or stale X-Slack-Request-Timestamp",
                    "reason": "stale_timestamp",
                })),
            )
                .into_response();
        }
    };

    match headers
        .get("X-Slack-Signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(sig) if verify_slack_signature(secret, timestamp, &body, sig) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid Slack callback signature",
                    "reason": "invalid_signature",
                })),
            )
                .into_response();
        }
    }

    let Some(payload_json) = extract_slack_payload_field(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing or invalid 'payload' field"})),
        )
            .into_response();
    };
    let payload: Value = match serde_json::from_str(&payload_json) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid 'payload' JSON: {}", e)})),
            )
                .into_response();
        }
    };

    let action = payload
        .get("actions")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first());
    let action_id = action
        .and_then(|a| a.get("action_id"))
        .and_then(|v| v.as_str());
    let value = action.and_then(|a| a.get("value")).and_then(|v| v.as_str());
    let approver_user_id = payload
        .get("user")
        .and_then(|u| u.get("username").or_else(|| u.get("id")))
        .and_then(|v| v.as_str())
        .unwrap_or("slack_user")
        .to_string();

    let (tenant_id, approval_id) = match value.and_then(|v| v.split_once(':')) {
        Some((tenant_id, approval_id)) => match Uuid::parse_str(approval_id) {
            Ok(id) => (tenant_id.to_string(), id),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid approval id in callback value"})),
                )
                    .into_response();
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "missing or malformed callback value"})),
            )
                .into_response();
        }
    };

    let decision_payload = ApproveRequest {
        approver_user_id,
        reason: Some("Decided via Slack interactive callback".to_string()),
    };

    let response = match action_id {
        Some("approve") => {
            approve_approval_inner(state.clone(), tenant_id, approval_id, decision_payload).await
        }
        Some("reject") => {
            reject_approval_inner(state.clone(), tenant_id, approval_id, decision_payload).await
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "unsupported action_id"})),
            )
                .into_response();
        }
    };
    record_approval_attempt_failure(&state, &response, &approval_id);
    response
}

/// `POST /v1/ingest` (SOC-004, #1187) — agentless event ingestion.
///
/// Tenant-scoped (via [`TenantId`]) and authenticated like every other
/// management endpoint. Normalizes `payload` per `source` (see
/// [`crate::ingest`]) and emits the result onto the same
/// [`crate::events::EventSink`] the inline `/v1/authorize` path uses, so it
/// flows through the identical detect -> correlate -> respond pipeline.
/// Never touches the authorize hot path itself (Law 3) — this is its own
/// request/response cycle.
///
/// GitHub webhook signature verification (#1339): when
/// [`AppState::github_webhook_secret`] is configured and `source ==
/// "github_webhook"`, the request must carry a valid `X-Hub-Signature-256`
/// HMAC-SHA256 over the raw request body, or the request is rejected with
/// `401`. This is opt-in — when the secret is unset, behavior is unchanged
/// from pre-#1339.
pub async fn ingest_event(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let payload: IngestRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid JSON body: {}", e)})),
            )
                .into_response();
        }
    };

    // GitHub webhook signature verification (#1339, opt-in via
    // AEGIS_GITHUB_WEBHOOK_SECRET). Skipped entirely when the secret is not
    // configured, and for sources other than "github_webhook" — matching
    // GitHub's actual webhook delivery mechanism (X-Hub-Signature-256).
    if payload.source == "github_webhook" {
        if let Some(secret) = state.github_webhook_secret.as_ref() {
            match headers.get("X-Hub-Signature-256") {
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "missing X-Hub-Signature-256 header",
                            "reason": "missing_signature",
                        })),
                    )
                        .into_response();
                }
                Some(sig_header) => {
                    if !verify_github_webhook_signature(secret, &body, sig_header) {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "invalid webhook signature",
                                "reason": "invalid_signature",
                            })),
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    match crate::ingest::normalize(&tenant_id, &payload.source, &payload.payload) {
        Err(()) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "unsupported ingest source '{}'; supported: {:?}",
                    payload.source,
                    crate::ingest::SUPPORTED_SOURCES
                )
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "payload could not be normalized for this source"})),
        )
            .into_response(),
        Ok(Some(event)) => {
            let event_id = event.event_id.clone();
            state.events.emit(event);
            (
                StatusCode::ACCEPTED,
                Json(json!({"status": "accepted", "event_id": event_id})),
            )
                .into_response()
        }
    }
}

/// `POST /v1/webhooks/github` (#1381) — dedicated GitHub App webhook receiver.
///
/// Accepts native GitHub webhook event payloads with:
/// - `X-GitHub-Event` header: event type (`pull_request`, `issues`,
///   `issue_comment`)
/// - `X-Hub-Signature-256` header: HMAC-SHA256 over the raw body — **always
///   required** when [`AppState::github_webhook_secret`] is configured; 401
///   when the secret is absent (fail-closed: unconfigured endpoint rejects all)
/// - `X-Aegis-Tenant-ID` or `X-Tenant-ID` header: target tenant
///
/// Supported events are forwarded into the same SOC pipeline as
/// `/v1/authorize`. Unrecognized event types or actions are silently
/// acknowledged (`202 ignored`) without emitting an event — this avoids
/// polluting the SOC stream with GitHub events we don't model yet.
pub async fn receive_github_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Tenant identification — same header as authorize_action.
    let tenant_id = match get_runtime_tenant_from_headers(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "missing X-Aegis-Tenant-ID header"})),
            )
                .into_response();
        }
    };

    // Signature verification — fail-closed: require signature always; 401 if
    // the secret is not configured so the endpoint cannot be used accidentally.
    match state.github_webhook_secret.as_ref() {
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "webhook not configured: AEGIS_GITHUB_WEBHOOK_SECRET is not set",
                    "reason": "webhook_not_configured",
                })),
            )
                .into_response();
        }
        Some(secret) => match headers.get("X-Hub-Signature-256") {
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "missing X-Hub-Signature-256 header",
                        "reason": "missing_signature",
                    })),
                )
                    .into_response();
            }
            Some(sig_header) => {
                if !verify_github_webhook_signature(secret, &body, sig_header) {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid webhook signature",
                            "reason": "invalid_signature",
                        })),
                    )
                        .into_response();
                }
            }
        },
    }

    // Event type from X-GitHub-Event header.
    let event_type = match headers.get("X-GitHub-Event").and_then(|h| h.to_str().ok()) {
        Some(et) => et.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "missing X-GitHub-Event header",
                    "reason": "missing_event_type",
                })),
            )
                .into_response();
        }
    };

    // Parse body.
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid JSON body: {}", e)})),
            )
                .into_response();
        }
    };

    // Normalize and emit.
    match crate::ingest::normalize_github_native_event(&tenant_id, &event_type, &payload) {
        None => (
            StatusCode::ACCEPTED,
            Json(json!({"status": "ignored", "reason": "unsupported_event_type"})),
        )
            .into_response(),
        Some(event) => {
            let event_id = event.event_id.clone();
            state.events.emit(event);
            (
                StatusCode::ACCEPTED,
                Json(json!({"status": "accepted", "event_id": event_id})),
            )
                .into_response()
        }
    }
}

pub(crate) fn default_webhook_event_types() -> String {
    "*".to_string()
}

/// TASK-0092 (#938): register a tenant-managed webhook subscription for SOC
/// notifications (alerts/incidents). Only `sha256(secret)` of the optional
/// operator-supplied `secret` is stored. #1285 additionally generates a
/// `delivery_secret` returned once in this response — the gateway keeps it
/// to HMAC-sign every future delivery to this subscription's `url`.
pub async fn create_webhook_subscription(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<CreateWebhookSubscriptionRequest>,
) -> impl IntoResponse {
    let min_severity = payload.min_severity.unwrap_or_else(|| "info".to_string());
    if min_severity != "info" && min_severity != "high" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "min_severity must be 'info' or 'high'"})),
        )
            .into_response();
    }
    let format = payload.format.unwrap_or_else(|| "json".to_string());
    if format != "json" && format != "cef" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "format must be 'json' or 'cef'"})),
        )
            .into_response();
    }

    let secret_hash = payload.secret.as_ref().map(|s| sha256_hex(s.as_bytes()));
    let delivery_secret = format!("whsec_{}", Uuid::new_v4().simple());
    match db::insert_webhook_subscription(
        &state.pool,
        &tenant_id,
        &payload.url,
        secret_hash.as_deref(),
        &payload.event_types,
        &delivery_secret,
        &min_severity,
        &format,
    )
    .await
    {
        Ok(record) => (
            StatusCode::CREATED,
            Json(json!({
                "id": record.id,
                "tenant_id": record.tenant_id,
                "url": record.url,
                "secret_hash": record.secret_hash,
                "event_types": record.event_types,
                "status": record.status,
                "min_severity": record.min_severity,
                "format": record.format,
                "delivery_status": record.delivery_status,
                "consecutive_failures": record.consecutive_failures,
                "last_delivery_at": record.last_delivery_at,
                "last_success_at": record.last_success_at,
                "delivery_secret": delivery_secret,
                "created_at": record.created_at,
            })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to create webhook subscription: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// TASK-0092 (#938): list this tenant's webhook subscriptions.
pub async fn list_webhook_subscriptions(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match db::list_webhook_subscriptions(&state.pool, &tenant_id).await {
        Ok(subs) => (StatusCode::OK, Json(subs)).into_response(),
        Err(e) => {
            error!("Failed to list webhook subscriptions: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// TASK-0092 (#938): delete a tenant's webhook subscription.
pub async fn delete_webhook_subscription(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::delete_webhook_subscription(&state.pool, &tenant_id, &id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"message": "Webhook subscription successfully deleted"})),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Webhook subscription not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete webhook subscription: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct UpsertDetectionRuleRequest {
    pub rule_key: String,
    pub name: String,
    pub severity: String,
    pub condition: String,
    pub summary_template: String,
    #[serde(default = "default_detection_rule_enabled")]
    pub enabled: bool,
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::db;
    use crate::events;
    use crate::metrics::SecurityMetrics;
    use crate::models::*;
    use crate::policy::PolicyEngine;
    use crate::routes::test_helpers::*;
    use axum::body::{to_bytes, Bytes};
    use axum::extract::{FromRequestParts, Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;
    /// SOC-004 (#1187): `POST /v1/ingest` normalizes a GitHub webhook payload,
    /// emits it onto the SOC event stream, and the drain task's behavioral
    /// baseline records it as the agent's first-ever (tool, action) — proving
    /// the ingested event flows through the same pipeline as `/v1/authorize`.
    #[tokio::test]
    async fn test_ingest_github_webhook_route() {
        let (state, tenant_id, _) = setup_state("ingest_github_webhook").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({
                "action": "opened",
                "repository": {"full_name": "lavkushry/AegisAgent"},
                "sender": {"login": "alice"}
            }),
        };

        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            HeaderMap::new(),
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // Give the background drain task a moment to persist the alert.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let alerts = db::list_soc_alerts(&state.pool, &tenant_id, 10, 0, None, None)
            .await
            .unwrap();
        assert!(
            alerts
                .iter()
                .any(|a| a.rule == "behavioral_anomaly_new_tool" && a.agent_id == "alice"),
            "expected the ingested github event to flow through the SOC pipeline, got: {alerts:?}"
        );
    }

    /// SOC-004 (#1187): an unsupported `source` is rejected with 400.
    #[tokio::test]
    async fn test_ingest_rejects_unsupported_source() {
        let (state, tenant_id, _) = setup_state("ingest_unsupported_source").await;

        let payload = IngestRequest {
            source: "slack_webhook".to_string(),
            payload: serde_json::json!({}),
        };

        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            HeaderMap::new(),
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// SOC-004 (#1187): a payload missing required fields for the chosen
    /// source is rejected with 400 rather than emitting a malformed event.
    #[tokio::test]
    async fn test_ingest_rejects_unnormalizable_payload() {
        let (state, tenant_id, _) = setup_state("ingest_bad_payload").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({"foo": "bar"}),
        };

        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            HeaderMap::new(),
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Computes the GitHub-style `X-Hub-Signature-256` header value
    /// (`sha256=<hex hmac>`) for `body` using `secret`.
    fn github_signature_header(secret: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// #1339: a `github_webhook` ingest request with a correctly-computed
    /// `X-Hub-Signature-256` header (over the exact raw body bytes) is
    /// processed normally (202 Accepted), when `github_webhook_secret` is
    /// configured.
    #[tokio::test]
    async fn ingest_github_webhook_valid_signature_is_processed() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("ingest_gh_valid_sig", "test_secret").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({
                "action": "opened",
                "repository": {"full_name": "lavkushry/AegisAgent"},
                "sender": {"login": "alice"}
            }),
        };
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let sig = github_signature_header("test_secret", &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            headers,
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    /// #1339: a `github_webhook` ingest request with an `X-Hub-Signature-256`
    /// header computed using the WRONG secret is rejected with `401` and
    /// `reason: "invalid_signature"`.
    #[tokio::test]
    async fn ingest_github_webhook_invalid_signature_returns_401() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("ingest_gh_invalid_sig", "test_secret").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({
                "action": "opened",
                "repository": {"full_name": "lavkushry/AegisAgent"},
                "sender": {"login": "alice"}
            }),
        };
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        // Signed with a different secret than the one configured server-side.
        let sig = github_signature_header("wrong_secret", &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            headers,
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["reason"], "invalid_signature");
    }

    /// #1339: a `github_webhook` ingest request with NO
    /// `X-Hub-Signature-256` header at all is rejected with `401` and
    /// `reason: "missing_signature"`, when `github_webhook_secret` is
    /// configured.
    #[tokio::test]
    async fn ingest_github_webhook_missing_signature_header_returns_401() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("ingest_gh_missing_sig", "test_secret").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({
                "action": "opened",
                "repository": {"full_name": "lavkushry/AegisAgent"},
                "sender": {"login": "alice"}
            }),
        };
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());

        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            HeaderMap::new(),
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["reason"], "missing_signature");
    }

    /// #1339 (AC#4): a `github_webhook` ingest request with a VALID signature
    /// but a payload shape that `normalize_github_webhook` cannot normalize
    /// (e.g. missing `sender`) is still rejected with `400` (payload-shape
    /// validation), not `401` — signature verification and payload-shape
    /// validation are independent.
    #[tokio::test]
    async fn ingest_github_webhook_valid_signature_unrecognized_payload_returns_400() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("ingest_gh_valid_sig_bad_payload", "test_secret").await;

        let payload = IngestRequest {
            source: "github_webhook".to_string(),
            payload: serde_json::json!({"foo": "bar"}),
        };
        let body = Bytes::from(serde_json::to_vec(&payload).unwrap());
        let sig = github_signature_header("test_secret", &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = ingest_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            headers,
            body,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // --- receive_github_webhook tests (#1381) ---

    /// Helper: build an HMAC-SHA256 `sha256=<hex>` signature over `body`.
    fn github_sig(secret: &str, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Build the common headers for a GitHub webhook request.
    fn gh_headers(event_type: &str, sig: &str, tenant_id: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "X-GitHub-Event",
            axum::http::HeaderValue::from_str(event_type).unwrap(),
        );
        h.insert(
            "X-Hub-Signature-256",
            axum::http::HeaderValue::from_str(sig).unwrap(),
        );
        h.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(tenant_id).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn receive_github_webhook_pull_request_opened_returns_202() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_pr_opened", "whsecret").await;

        let body_json = serde_json::json!({
            "action": "opened",
            "number": 1,
            "repository": {"full_name": "org/repo"},
            "sender": {"login": "alice"},
            "pull_request": {"merged": false}
        });
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let sig = github_sig("whsecret", &body);
        let headers = gh_headers("pull_request", &sig, &tenant_id);

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["status"], "accepted");
        assert!(v["event_id"].is_string());
    }

    #[tokio::test]
    async fn receive_github_webhook_issues_opened_returns_202() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_issues_opened", "whsecret").await;

        let body_json = serde_json::json!({
            "action": "opened",
            "issue": {"number": 42},
            "repository": {"full_name": "org/repo"},
            "sender": {"login": "bob"}
        });
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let sig = github_sig("whsecret", &body);
        let headers = gh_headers("issues", &sig, &tenant_id);

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["status"], "accepted");
    }

    #[tokio::test]
    async fn receive_github_webhook_issue_comment_created_returns_202() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_comment_created", "whsecret").await;

        let body_json = serde_json::json!({
            "action": "created",
            "repository": {"full_name": "org/repo"},
            "sender": {"login": "carol"},
            "comment": {"body": "looks good"}
        });
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let sig = github_sig("whsecret", &body);
        let headers = gh_headers("issue_comment", &sig, &tenant_id);

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn receive_github_webhook_pull_request_merged_returns_202() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_pr_merged", "whsecret").await;

        let body_json = serde_json::json!({
            "action": "closed",
            "number": 5,
            "repository": {"full_name": "org/repo"},
            "sender": {"login": "dave"},
            "pull_request": {"merged": true}
        });
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let sig = github_sig("whsecret", &body);
        let headers = gh_headers("pull_request", &sig, &tenant_id);

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["status"], "accepted");
    }

    #[tokio::test]
    async fn receive_github_webhook_invalid_signature_returns_401() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_bad_sig", "whsecret").await;

        let body_json = serde_json::json!({"action": "opened", "sender": {"login": "alice"}});
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let bad_sig = "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-GitHub-Event",
            axum::http::HeaderValue::from_str("pull_request").unwrap(),
        );
        headers.insert(
            "X-Hub-Signature-256",
            axum::http::HeaderValue::from_str(bad_sig).unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["reason"], "invalid_signature");
    }

    #[tokio::test]
    async fn receive_github_webhook_missing_signature_header_returns_401() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_missing_sig", "whsecret").await;

        let body_json = serde_json::json!({"action": "opened"});
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-GitHub-Event",
            axum::http::HeaderValue::from_str("pull_request").unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["reason"], "missing_signature");
    }

    #[tokio::test]
    async fn receive_github_webhook_no_secret_configured_returns_401() {
        // `setup_state` creates state with `github_webhook_secret: None`.
        let (state, tenant_id, _) = setup_state("gh_wh_no_secret").await;

        let body_json = serde_json::json!({"action": "opened"});
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-GitHub-Event",
            axum::http::HeaderValue::from_str("pull_request").unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["reason"], "webhook_not_configured");
    }

    #[tokio::test]
    async fn receive_github_webhook_missing_event_header_returns_400() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_no_event_hdr", "whsecret").await;

        let body_json = serde_json::json!({"action": "opened"});
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let sig = github_sig("whsecret", &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["reason"], "missing_event_type");
    }

    #[tokio::test]
    async fn receive_github_webhook_missing_tenant_header_returns_400() {
        let (state, _, _) = setup_state_with_github_secret("gh_wh_no_tenant", "whsecret").await;

        let body_json = serde_json::json!({"action": "opened"});
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let sig = github_sig("whsecret", &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-GitHub-Event",
            axum::http::HeaderValue::from_str("pull_request").unwrap(),
        );
        headers.insert(
            "X-Hub-Signature-256",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn receive_github_webhook_unsupported_event_type_returns_202_ignored() {
        let (state, tenant_id, _) =
            setup_state_with_github_secret("gh_wh_unsupported_evt", "whsecret").await;

        let body_json = serde_json::json!({
            "action": "pushed",
            "repository": {"full_name": "org/repo"},
            "sender": {"login": "alice"}
        });
        let body = Bytes::from(serde_json::to_vec(&body_json).unwrap());
        let sig = github_sig("whsecret", &body);
        let headers = gh_headers("push", &sig, &tenant_id);

        let resp = receive_github_webhook(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["status"], "ignored");
        assert_eq!(v["reason"], "unsupported_event_type");
    }
}
