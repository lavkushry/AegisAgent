//! Protocol-neutral seam for `POST /v1/authorize` (roadmap Week 3).
//!
//! Repository law (`docs/architecture.md` §5) requires REST and gRPC adapters
//! to `authenticate/parse -> typed service call -> typed error/response
//! mapping` and forbids gRPC from buffering an Axum response body or parsing
//! response JSON. The legacy gRPC `authorize` does exactly the forbidden
//! thing: it serializes the request to JSON, forges HTTP headers and a
//! `127.0.0.1:0` peer address, calls the REST impl, buffers the Axum body,
//! re-parses the response JSON, and collapses every structured error into
//! `Status::internal`.
//!
//! This module is the extraction boundary:
//! - [`Transport`] / [`AuthorizeContext`] / [`AuthCredential`] — transport-
//!   neutral, already-authenticated inputs an adapter resolves before calling
//!   the service;
//! - [`error_reason_to_tonic_code`] / [`status_error_to_tonic`] — faithful
//!   `ErrorReason -> tonic::Status` mapping that replaces the
//!   `Status::internal` collapse;
//! - [`typed_authorize_enabled`] — feature flag `AEGIS_TYPED_AUTHORIZE`
//!   (default off) gating the gRPC direct path until the equality corpus
//!   passes (plan Phase C);
//! - [`authorize`] — protocol-neutral entry that both adapters call. During
//!   the extraction it still drives `authorize_action_impl` so behavior stays
//!   byte-identical to REST; the adapters no longer forge loopback peers or
//!   invent headers themselves.
//!
//! Full `authorize_core` Result-typed extraction (no Axum `Response` at the
//! service boundary) lands in the next phase that splits the 1.4k-line
//! `authorize_action_impl` body; the types and gRPC path here make that split
//! mechanical.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;

use crate::error::{ErrorReason, StatusError};
use crate::models::AuthorizeRequest;
use crate::routes::AppState;

/// Which protocol admitted this authorization request. The service treats the
/// two identically; adapters differ only in how they authenticate and encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Rest,
    Grpc,
}

/// How the adapter proved the caller's agent identity.
///
/// Fail-closed: if neither credential form can be established, the adapter
/// returns its transport error and never builds an [`AuthorizeContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCredential {
    /// Bearer agent token (already stripped of the `Bearer ` prefix).
    BearerToken(String),
    /// Verified mTLS client-certificate Subject CN from the TLS accept loop.
    MtlsCn(String),
}

/// Transport-neutral, already-authenticated context for one authorization
/// evaluation. An adapter constructs this only after it has verified the
/// caller (bearer token, mTLS CN, or request signature) and resolved the
/// tenant; the service trusts these fields and never re-reads a header for
/// tenant authority.
///
/// Fail-closed by construction: if an adapter cannot authenticate the caller
/// or determine the tenant, it returns its transport-appropriate error and
/// never builds an `AuthorizeContext`.
#[derive(Debug, Clone)]
pub struct AuthorizeContext {
    /// The authenticated runtime tenant (from `X-Aegis-Tenant-ID` on REST,
    /// request `tenant_id` / metadata on gRPC). Single tenant authority the
    /// service uses — it does not consult any other source.
    pub tenant_id: String,
    /// Real remote peer, used to key the auth-failure tracker. gRPC supplies
    /// tonic's `remote_addr`, never a forged loopback address.
    pub client_addr: std::net::SocketAddr,
    /// Admitting protocol.
    pub transport: Transport,
    /// Agent identity credential resolved by the adapter.
    pub credential: AuthCredential,
    /// Optional `X-Aegis-Request-Signature` value (agents with signing keys).
    pub request_signature: Option<String>,
}

impl AuthorizeContext {
    pub fn new(
        tenant_id: impl Into<String>,
        client_addr: std::net::SocketAddr,
        transport: Transport,
        credential: AuthCredential,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            client_addr,
            transport,
            credential,
            request_signature: None,
        }
    }

    pub fn with_request_signature(mut self, sig: Option<String>) -> Self {
        self.request_signature = sig.filter(|s| !s.is_empty());
        self
    }
}

/// Success body for a completed authorization evaluation.
///
/// Transitional: decision denies that still emit partial JSON
/// (`{"decision":"deny",...}`) travel as [`AuthorizedBody::Json`] so REST
/// response shapes stay byte-stable during extraction. Typed gRPC maps
/// full [`crate::models::AuthorizeResponse`] values and StatusError failures;
/// partial JSON denials become `PermissionDenied` with the raw body message.
#[derive(Debug, Clone)]
pub enum AuthorizedBody {
    Decision(Box<crate::models::AuthorizeResponse>),
    Json(serde_json::Value),
}

/// Typed service outcome (status + body). Adapters map this to their wire form.
#[derive(Debug, Clone)]
pub struct AuthorizedOutcome {
    pub status: axum::http::StatusCode,
    pub body: AuthorizedBody,
}

/// Feature flag for the typed gRPC authorize path (`AEGIS_TYPED_AUTHORIZE`).
///
/// Default **off** until Phase C equality corpus is green. Accepted truthy
/// values: `1`, `true`, `yes`, `on` (case-insensitive). Any other value,
/// including unset, keeps the legacy JSON-bridge path.
pub fn typed_authorize_enabled() -> bool {
    match std::env::var("AEGIS_TYPED_AUTHORIZE") {
        Ok(v) => {
            let v = v.trim();
            v.eq_ignore_ascii_case("1")
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        }
        Err(_) => false,
    }
}

/// The gRPC status code a `StatusError`'s reason maps to.
///
/// This is the mapping the current gRPC adapter throws away by collapsing
/// everything to `Status::internal`. Each arm mirrors the HTTP status the
/// same reason already produces on REST (`ErrorReason::status_code`), so the
/// two protocols report the same failure class:
///
/// | reason | HTTP | gRPC |
/// |---|---|---|
/// | BadRequest / Invalid / UnsupportedMediaType | 400/422/415 | InvalidArgument |
/// | Unauthorized | 401 | Unauthenticated |
/// | Forbidden | 403 | PermissionDenied |
/// | NotFound | 404 | NotFound |
/// | Conflict / AlreadyExists | 409 | Aborted / AlreadyExists |
/// | Timeout | 408 | DeadlineExceeded |
/// | TooManyRequests | 429 | ResourceExhausted |
/// | NotImplemented | 501 | Unimplemented |
/// | ServiceUnavailable | 503 | Unavailable |
/// | InternalError / Unknown | 500 | Internal |
pub fn error_reason_to_tonic_code(reason: ErrorReason) -> tonic::Code {
    use tonic::Code;
    match reason {
        ErrorReason::BadRequest | ErrorReason::Invalid | ErrorReason::UnsupportedMediaType => {
            Code::InvalidArgument
        }
        ErrorReason::Unauthorized => Code::Unauthenticated,
        ErrorReason::Forbidden => Code::PermissionDenied,
        ErrorReason::NotFound => Code::NotFound,
        ErrorReason::Conflict => Code::Aborted,
        ErrorReason::AlreadyExists => Code::AlreadyExists,
        ErrorReason::Timeout => Code::DeadlineExceeded,
        ErrorReason::TooManyRequests => Code::ResourceExhausted,
        ErrorReason::NotImplemented => Code::Unimplemented,
        ErrorReason::ServiceUnavailable => Code::Unavailable,
        ErrorReason::InternalError | ErrorReason::Unknown => Code::Internal,
    }
}

/// Build a tonic `Status` from a structured gateway [`StatusError`].
pub fn status_error_to_tonic(err: &StatusError) -> tonic::Status {
    tonic::Status::new(error_reason_to_tonic_code(err.reason), err.message.clone())
}

/// Map an HTTP error body (from the transitional Response path) to tonic Status.
///
/// Prefers a deserializable [`StatusError`] envelope so clients see the same
/// failure class as REST. Falls back to coarse HTTP-status mapping when the
/// body is a decision-deny JSON or plain text (legacy partial shapes).
pub fn http_error_to_tonic(status: axum::http::StatusCode, body: &[u8]) -> tonic::Status {
    if let Ok(err) = serde_json::from_slice::<StatusError>(body) {
        return status_error_to_tonic(&err);
    }
    let msg = String::from_utf8_lossy(body).into_owned();
    let code = match status.as_u16() {
        400 | 422 | 415 => tonic::Code::InvalidArgument,
        401 => tonic::Code::Unauthenticated,
        403 => tonic::Code::PermissionDenied,
        404 => tonic::Code::NotFound,
        408 => tonic::Code::DeadlineExceeded,
        409 => tonic::Code::Aborted,
        429 => tonic::Code::ResourceExhausted,
        501 => tonic::Code::Unimplemented,
        503 => tonic::Code::Unavailable,
        _ if status.is_client_error() => tonic::Code::InvalidArgument,
        _ => tonic::Code::Internal,
    };
    tonic::Status::new(code, msg)
}

/// Build the HeaderMap the current `authorize_action_impl` still reads for
/// tenant, agent credential, optional mTLS CN, and request signature.
///
/// During extraction the service reuses the impl; adapters never forge these
/// headers themselves. Once `authorize_core` takes typed inputs only, this
/// helper is deleted with the header re-reads.
#[allow(clippy::result_large_err)] // StatusError is the gateway-wide error type
pub fn build_service_headers(ctx: &AuthorizeContext) -> Result<HeaderMap, StatusError> {
    let mut headers = HeaderMap::new();

    let tenant = HeaderValue::from_str(&ctx.tenant_id)
        .map_err(|_| StatusError::bad_request("tenant_id contains invalid header characters"))?;
    headers.insert("X-Aegis-Tenant-ID", tenant);

    match &ctx.credential {
        AuthCredential::BearerToken(token) => {
            let value = format!("Bearer {token}");
            let hv = HeaderValue::from_str(&value).map_err(|_| {
                StatusError::unauthorized("agent token contains invalid header characters")
            })?;
            headers.insert(axum::http::header::AUTHORIZATION, hv);
        }
        AuthCredential::MtlsCn(cn) => {
            let hv = HeaderValue::from_str(cn).map_err(|_| {
                StatusError::unauthorized("mTLS CN contains invalid header characters")
            })?;
            headers.insert(crate::mtls::MTLS_CN_HEADER, hv);
        }
    }

    if let Some(sig) = ctx.request_signature.as_deref() {
        let hv = HeaderValue::from_str(sig).map_err(|_| {
            StatusError::unauthorized("request signature contains invalid header characters")
        })?;
        headers.insert("x-aegis-request-signature", hv);
    }

    Ok(headers)
}

/// Protocol-neutral authorize entry used by REST (optional) and typed gRPC.
///
/// Serializes `payload` to the raw body bytes the existing HMAC-over-body
/// check expects (identical to what the legacy gRPC bridge produced), builds
/// service headers from [`AuthorizeContext`], and calls
/// `authorize_action_impl` with the **real** client address.
///
/// Callers that already hold raw REST body bytes (HMAC over the exact on-wire
/// bytes) should prefer [`authorize_raw`] so signature verification stays
/// bound to the bytes the client signed.
pub async fn authorize(
    state: Arc<AppState>,
    ctx: AuthorizeContext,
    payload: &AuthorizeRequest,
) -> axum::response::Response {
    let body_bytes = match serde_json::to_vec(payload) {
        Ok(b) => Bytes::from(b),
        Err(e) => {
            return StatusError::bad_request(format!("Failed to serialize authorize payload: {e}"))
                .into_response();
        }
    };
    authorize_raw(state, ctx, body_bytes).await
}

/// Like [`authorize`], but uses caller-supplied raw body bytes (REST HMAC path).
pub async fn authorize_raw(
    state: Arc<AppState>,
    ctx: AuthorizeContext,
    raw_body: Bytes,
) -> axum::response::Response {
    let headers = match build_service_headers(&ctx) {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    crate::routes::authorize_action_impl(state, headers, raw_body, ctx.client_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StatusError;
    use axum::http::StatusCode;
    use tonic::Code;

    #[test]
    fn context_filters_empty_request_signature() {
        let addr = std::net::SocketAddr::from(([10, 0, 0, 1], 4443));
        let ctx = AuthorizeContext::new(
            "tenant_a",
            addr,
            Transport::Grpc,
            AuthCredential::BearerToken("tok".into()),
        )
        .with_request_signature(Some(String::new()));
        assert_eq!(ctx.request_signature, None);
        assert_eq!(ctx.tenant_id, "tenant_a");
        assert_eq!(ctx.transport, Transport::Grpc);
    }

    #[test]
    fn auth_and_policy_failures_are_not_collapsed_to_internal() {
        // The exact defect this replaces: a policy deny (403) and a bad token
        // (401) must NOT reach the gRPC client as `Internal`.
        assert_eq!(
            error_reason_to_tonic_code(ErrorReason::Forbidden),
            Code::PermissionDenied
        );
        assert_eq!(
            error_reason_to_tonic_code(ErrorReason::Unauthorized),
            Code::Unauthenticated
        );
        assert_eq!(
            error_reason_to_tonic_code(ErrorReason::TooManyRequests),
            Code::ResourceExhausted
        );
        assert_ne!(
            error_reason_to_tonic_code(ErrorReason::BadRequest),
            Code::Internal
        );
    }

    #[test]
    fn only_genuine_server_errors_map_to_internal() {
        assert_eq!(
            error_reason_to_tonic_code(ErrorReason::InternalError),
            Code::Internal
        );
        assert_eq!(
            error_reason_to_tonic_code(ErrorReason::Unknown),
            Code::Internal
        );
    }

    #[test]
    fn every_reason_maps_consistently_with_its_http_status() {
        // The gRPC code and the HTTP status a StatusError already yields must
        // agree on the coarse success/client-error/server-error class, so the
        // two protocols never disagree about whose fault a failure is.
        for reason in [
            ErrorReason::BadRequest,
            ErrorReason::Unauthorized,
            ErrorReason::Forbidden,
            ErrorReason::NotFound,
            ErrorReason::Conflict,
            ErrorReason::AlreadyExists,
            ErrorReason::Invalid,
            ErrorReason::Timeout,
            ErrorReason::TooManyRequests,
            ErrorReason::NotImplemented,
            ErrorReason::UnsupportedMediaType,
            ErrorReason::InternalError,
            ErrorReason::ServiceUnavailable,
            ErrorReason::Unknown,
        ] {
            let http = reason.status_code();
            let code = error_reason_to_tonic_code(reason);
            let http_is_server_error = http.is_server_error();
            // 501 NotImplemented → Unimplemented and 503 → Unavailable are
            // server-side in both models; 5xx Internal matches Internal/Unknown.
            let grpc_is_server_error = matches!(
                code,
                Code::Internal | Code::Unavailable | Code::Unknown | Code::Unimplemented
            );
            if http == StatusCode::SERVICE_UNAVAILABLE {
                assert_eq!(code, Code::Unavailable);
            } else if http == StatusCode::NOT_IMPLEMENTED {
                assert_eq!(code, Code::Unimplemented);
            } else {
                assert_eq!(
                    http_is_server_error, grpc_is_server_error,
                    "reason {reason:?}: HTTP {http} vs gRPC {code:?} disagree on server-vs-client fault"
                );
            }
        }
    }

    #[test]
    fn status_error_to_tonic_preserves_message_and_code() {
        let err = StatusError::unauthorized("Invalid or quarantined agent token");
        let status = status_error_to_tonic(&err);
        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(status.message(), "Invalid or quarantined agent token");
    }

    #[test]
    fn http_error_to_tonic_parses_status_error_envelope() {
        let err = StatusError::forbidden("policy deny");
        let body = serde_json::to_vec(&err).expect("serialize");
        let status = http_error_to_tonic(StatusCode::FORBIDDEN, &body);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "policy deny");
    }

    #[test]
    fn http_error_to_tonic_maps_partial_decision_deny_by_status() {
        let body = br#"{"decision":"deny","reason":"agent frozen"}"#;
        let status = http_error_to_tonic(StatusCode::FORBIDDEN, body);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("agent frozen"));
    }

    #[test]
    fn build_service_headers_sets_tenant_bearer_and_signature() {
        let addr = std::net::SocketAddr::from(([203, 0, 113, 9], 5555));
        let ctx = AuthorizeContext::new(
            "tenant_x",
            addr,
            Transport::Grpc,
            AuthCredential::BearerToken("secret-token".into()),
        )
        .with_request_signature(Some("sig-abc".into()));
        let headers = build_service_headers(&ctx).expect("headers");
        assert_eq!(
            headers
                .get("X-Aegis-Tenant-ID")
                .and_then(|v| v.to_str().ok()),
            Some("tenant_x")
        );
        assert_eq!(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer secret-token")
        );
        assert_eq!(
            headers
                .get("x-aegis-request-signature")
                .and_then(|v| v.to_str().ok()),
            Some("sig-abc")
        );
        assert!(headers.get(crate::mtls::MTLS_CN_HEADER).is_none());
    }

    #[test]
    fn build_service_headers_sets_mtls_cn_without_bearer() {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let ctx = AuthorizeContext::new(
            "t1",
            addr,
            Transport::Rest,
            AuthCredential::MtlsCn("agent.example".into()),
        );
        let headers = build_service_headers(&ctx).expect("headers");
        assert_eq!(
            headers
                .get(crate::mtls::MTLS_CN_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some("agent.example")
        );
        assert!(headers.get(axum::http::header::AUTHORIZATION).is_none());
    }

    #[test]
    fn typed_authorize_flag_defaults_off_and_accepts_truthy() {
        // Isolate from the ambient process env for this test.
        let prev = std::env::var("AEGIS_TYPED_AUTHORIZE").ok();
        std::env::remove_var("AEGIS_TYPED_AUTHORIZE");
        assert!(!typed_authorize_enabled());

        std::env::set_var("AEGIS_TYPED_AUTHORIZE", "true");
        assert!(typed_authorize_enabled());
        std::env::set_var("AEGIS_TYPED_AUTHORIZE", "1");
        assert!(typed_authorize_enabled());
        std::env::set_var("AEGIS_TYPED_AUTHORIZE", "yes");
        assert!(typed_authorize_enabled());
        std::env::set_var("AEGIS_TYPED_AUTHORIZE", "on");
        assert!(typed_authorize_enabled());
        std::env::set_var("AEGIS_TYPED_AUTHORIZE", "false");
        assert!(!typed_authorize_enabled());
        std::env::set_var("AEGIS_TYPED_AUTHORIZE", "0");
        assert!(!typed_authorize_enabled());

        match prev {
            Some(v) => std::env::set_var("AEGIS_TYPED_AUTHORIZE", v),
            None => std::env::remove_var("AEGIS_TYPED_AUTHORIZE"),
        }
    }

    // ── Phase C: equality corpus ─────────────────────────────────────────
    // Drive the legacy header/body path and the typed service entry with the
    // same requests and assert equal decision class, risk, error class, and
    // approval shape. decision_id / approval_id / expires_at differ by design
    // (fresh UUIDs and clocks) and are excluded from the fingerprint.

    use crate::models::{AuthorizeRequest, RegisterToolAction, RegisterToolRequest};
    use crate::routes::test_helpers::{
        agent_headers, mcp_authorize_request, setup_state, test_conn_info,
    };
    use crate::routes::{register_tool, TenantId};
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::Json;
    use std::sync::Arc;

    /// Snapshot of authorize response fields that must match across paths.
    #[derive(Debug, PartialEq, Eq)]
    struct DecisionFingerprint {
        http_status: u16,
        body_kind: &'static str,
        decision: Option<String>,
        risk_score: Option<i32>,
        risk_level: Option<String>,
        reason: Option<String>,
        matched_policies: Option<Vec<String>>,
        root_trust_level: Option<String>,
        dry_run: Option<bool>,
        has_approval: bool,
        approver_group: Option<String>,
        has_action_hash: bool,
        error_reason: Option<String>,
        error_message: Option<String>,
    }

    async fn fingerprint_response(response: axum::response::Response) -> DecisionFingerprint {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        if status == StatusCode::OK || status == StatusCode::CREATED {
            let res: crate::models::AuthorizeResponse =
                serde_json::from_slice(&body).expect("AuthorizeResponse");
            // Cedar match order / primary-reason selection can be non-deterministic
            // when multiple annotations fire; sort policies and drop free-text
            // reason so the corpus compares the security-relevant outcome.
            let mut policies = res.matched_policies;
            policies.sort();
            let reason = if policies.len() > 1 {
                None
            } else {
                Some(res.reason)
            };
            return DecisionFingerprint {
                http_status: status.as_u16(),
                body_kind: "ok",
                decision: Some(res.decision),
                risk_score: Some(res.risk_score),
                risk_level: Some(res.risk_level),
                reason,
                matched_policies: Some(policies),
                root_trust_level: Some(res.root_trust_level),
                dry_run: Some(res.dry_run),
                has_approval: res.approval.is_some(),
                approver_group: res.approval.as_ref().and_then(|a| a.approver_group.clone()),
                has_action_hash: res
                    .approval
                    .as_ref()
                    .map(|a| !a.action_hash.is_empty())
                    .unwrap_or(false),
                error_reason: None,
                error_message: None,
            };
        }
        if let Ok(err) = serde_json::from_slice::<StatusError>(&body) {
            return DecisionFingerprint {
                http_status: status.as_u16(),
                body_kind: "status_error",
                decision: None,
                risk_score: None,
                risk_level: None,
                reason: None,
                matched_policies: None,
                root_trust_level: None,
                dry_run: None,
                has_approval: false,
                approver_group: None,
                has_action_hash: false,
                error_reason: Some(format!("{:?}", err.reason)),
                error_message: Some(err.message),
            };
        }
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        DecisionFingerprint {
            http_status: status.as_u16(),
            body_kind: "other",
            decision: v
                .get("decision")
                .and_then(|d| d.as_str())
                .map(str::to_string),
            risk_score: v
                .get("risk_score")
                .and_then(|x| x.as_i64())
                .map(|x| x as i32),
            risk_level: v
                .get("risk_level")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            reason: v.get("reason").and_then(|x| x.as_str()).map(str::to_string),
            matched_policies: None,
            root_trust_level: None,
            dry_run: None,
            has_approval: false,
            approver_group: None,
            has_action_hash: false,
            error_reason: None,
            error_message: None,
        }
    }

    async fn run_legacy(
        state: Arc<crate::routes::AppState>,
        tenant_id: &str,
        agent_token: &str,
        request: &AuthorizeRequest,
        client_addr: std::net::SocketAddr,
    ) -> DecisionFingerprint {
        let headers = agent_headers(agent_token, tenant_id);
        let body = Bytes::from(serde_json::to_vec(request).expect("serialize"));
        let response =
            crate::routes::authorize_action_impl(state, headers, body, client_addr).await;
        fingerprint_response(response).await
    }

    async fn run_typed(
        state: Arc<crate::routes::AppState>,
        tenant_id: &str,
        agent_token: &str,
        request: &AuthorizeRequest,
        client_addr: std::net::SocketAddr,
    ) -> DecisionFingerprint {
        let ctx = AuthorizeContext::new(
            tenant_id,
            client_addr,
            Transport::Grpc,
            AuthCredential::BearerToken(agent_token.to_string()),
        );
        let response = authorize(state, ctx, request).await;
        fingerprint_response(response).await
    }

    async fn register_ship(state: &Arc<crate::routes::AppState>, tenant_id: &str) {
        let req = RegisterToolRequest {
            skill_key: "deployer".to_string(),
            name: "Deployer".to_string(),
            r#type: "static".to_string(),
            auth_type: None,
            owner_team: None,
            default_risk: None,
            actions: vec![RegisterToolAction {
                action_key: "ship".to_string(),
                description: None,
                risk: "low".to_string(),
                mutates_state: false,
                data_access: None,
                approval_required: false,
                default_decision: "policy".to_string(),
            }],
        };
        let resp = register_tool(
            State(state.clone()),
            TenantId(tenant_id.to_string()),
            Json(req),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn equality_on_fresh_states(
        label: &str,
        setup_prefix: &str,
        mut build: impl FnMut() -> AuthorizeRequest,
        prepare: impl Fn(
            Arc<crate::routes::AppState>,
            String,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) {
        let peer = std::net::SocketAddr::from(([198, 51, 100, 10], 9000));

        let (state_a, tenant_a, token_a) = setup_state(&format!("{setup_prefix}_legacy")).await;
        prepare(state_a.clone(), tenant_a.clone()).await;
        let legacy = run_legacy(state_a, &tenant_a, &token_a, &build(), peer).await;

        let (state_b, tenant_b, token_b) = setup_state(&format!("{setup_prefix}_typed")).await;
        prepare(state_b.clone(), tenant_b.clone()).await;
        let typed = run_typed(state_b, &tenant_b, &token_b, &build(), peer).await;

        assert_eq!(
            legacy, typed,
            "equality corpus mismatch for `{label}`:\n  legacy={legacy:?}\n  typed={typed:?}"
        );
    }

    #[tokio::test]
    async fn equality_allow_read_only() {
        equality_on_fresh_states(
            "allow_read_only",
            "eq_allow",
            || {
                let mut r = mcp_authorize_request("deployer", "ship");
                r.tool_call.mutates_state = false;
                r.context.source_trust = "trusted_internal_signed".to_string();
                r
            },
            |state, tenant| {
                Box::pin(async move {
                    register_ship(&state, &tenant).await;
                })
            },
        )
        .await;
    }

    #[tokio::test]
    async fn equality_deny_untrusted_mutation() {
        equality_on_fresh_states(
            "deny_untrusted_mutation",
            "eq_deny_untrusted",
            || {
                let mut r = mcp_authorize_request("deployer", "ship");
                r.tool_call.mutates_state = true;
                r.context.source_trust = "untrusted_external".to_string();
                r
            },
            |state, tenant| {
                Box::pin(async move {
                    register_ship(&state, &tenant).await;
                })
            },
        )
        .await;
    }

    #[tokio::test]
    async fn equality_require_approval_customer_context() {
        equality_on_fresh_states(
            "require_approval",
            "eq_req_approval",
            || {
                let mut r = mcp_authorize_request("deployer", "ship");
                r.tool_call.mutates_state = true;
                r.context.source_trust = "semi_trusted_customer".to_string();
                r
            },
            |state, tenant| {
                Box::pin(async move {
                    register_ship(&state, &tenant).await;
                })
            },
        )
        .await;
    }

    #[tokio::test]
    async fn equality_dry_run_allow() {
        equality_on_fresh_states(
            "dry_run_allow",
            "eq_dry_run",
            || {
                let mut r = mcp_authorize_request("deployer", "ship");
                r.tool_call.mutates_state = false;
                r.context.source_trust = "trusted_internal_signed".to_string();
                r.dry_run = Some(true);
                r
            },
            |state, tenant| {
                Box::pin(async move {
                    register_ship(&state, &tenant).await;
                })
            },
        )
        .await;
    }

    #[tokio::test]
    async fn equality_frozen_agent_deny() {
        equality_on_fresh_states(
            "frozen_agent",
            "eq_frozen",
            || mcp_authorize_request("filesystem", "read_file"),
            |state, tenant| {
                Box::pin(async move {
                    let agents = state
                        .storage
                        .list_agents(&tenant, 10, 0, None)
                        .await
                        .expect("list agents");
                    for a in agents {
                        state
                            .storage
                            .set_agent_status(&tenant, &a.id, "frozen")
                            .await
                            .expect("freeze");
                    }
                })
            },
        )
        .await;
    }

    #[tokio::test]
    async fn equality_bad_token_unauthorized() {
        let peer = std::net::SocketAddr::from(([198, 51, 100, 20], 9001));
        let (state, tenant_id, _good_token) = setup_state("eq_bad_token").await;
        let request = mcp_authorize_request("filesystem", "read_file");

        let legacy = run_legacy(
            state.clone(),
            &tenant_id,
            "not-a-real-token",
            &request,
            peer,
        )
        .await;
        let typed = run_typed(state, &tenant_id, "not-a-real-token", &request, peer).await;
        assert_eq!(legacy, typed, "bad token must match across paths");
        assert_eq!(legacy.http_status, 401);
        assert_eq!(legacy.body_kind, "status_error");
        assert_eq!(legacy.error_reason.as_deref(), Some("Unauthorized"));
        assert_eq!(
            error_reason_to_tonic_code(ErrorReason::Unauthorized),
            Code::Unauthenticated
        );
    }

    #[tokio::test]
    async fn equality_missing_tenant_is_client_error_on_both_paths() {
        let peer = test_conn_info();
        let (state, _tenant, token) = setup_state("eq_missing_tenant").await;
        let request = mcp_authorize_request("filesystem", "read_file");

        let mut headers = agent_headers(&token, "ignored");
        headers.remove("X-Aegis-Tenant-ID");
        let body = Bytes::from(serde_json::to_vec(&request).unwrap());
        let legacy_resp =
            crate::routes::authorize_action_impl(state.clone(), headers, body, peer).await;
        let legacy = fingerprint_response(legacy_resp).await;

        let ctx = AuthorizeContext::new(
            "",
            peer,
            Transport::Grpc,
            AuthCredential::BearerToken(token),
        );
        let typed_resp = match build_service_headers(&ctx) {
            Ok(h) => {
                let body = Bytes::from(serde_json::to_vec(&request).unwrap());
                crate::routes::authorize_action_impl(state, h, body, peer).await
            }
            Err(e) => e.into_response(),
        };
        let typed = fingerprint_response(typed_resp).await;

        assert!(
            (400..500).contains(&legacy.http_status),
            "legacy missing tenant must be client error, got {legacy:?}"
        );
        assert!(
            (400..500).contains(&typed.http_status),
            "typed empty tenant must be client error, got {typed:?}"
        );
    }

    #[tokio::test]
    async fn equality_replay_nonce_conflict_on_both_paths() {
        for (label, use_typed) in [("legacy", false), ("typed", true)] {
            let (state, tenant_id, token) = setup_state(&format!("eq_replay_{label}")).await;
            register_ship(&state, &tenant_id).await;
            let peer = std::net::SocketAddr::from(([203, 0, 113, 80], 7000));
            let mut request = mcp_authorize_request("deployer", "ship");
            request.tool_call.mutates_state = false;
            request.context.source_trust = "trusted_internal_signed".to_string();
            request.nonce = Some(format!("nonce-{label}"));
            request.timestamp = Some(chrono::Utc::now());

            let first = if use_typed {
                run_typed(state.clone(), &tenant_id, &token, &request, peer).await
            } else {
                run_legacy(state.clone(), &tenant_id, &token, &request, peer).await
            };
            assert_eq!(first.decision.as_deref(), Some("allow"), "{label} first");

            let second = if use_typed {
                run_typed(state, &tenant_id, &token, &request, peer).await
            } else {
                run_legacy(state, &tenant_id, &token, &request, peer).await
            };
            assert_eq!(
                second.http_status, 409,
                "{label} replay must conflict: {second:?}"
            );
            assert_eq!(second.body_kind, "status_error");
            assert_eq!(second.error_reason.as_deref(), Some("Conflict"));
        }
        assert_eq!(
            error_reason_to_tonic_code(ErrorReason::Conflict),
            Code::Aborted
        );
    }

    #[tokio::test]
    async fn equality_require_approval_persists_matching_action_hash() {
        let peer = std::net::SocketAddr::from(([198, 51, 100, 30], 9002));
        let build = || {
            let mut r = mcp_authorize_request("deployer", "ship");
            r.tool_call.mutates_state = true;
            r.context.source_trust = "semi_trusted_customer".to_string();
            r
        };

        let (state_a, tenant_a, token_a) = setup_state("eq_approval_hash_legacy").await;
        register_ship(&state_a, &tenant_a).await;
        let legacy = run_legacy(state_a.clone(), &tenant_a, &token_a, &build(), peer).await;
        assert!(legacy.has_approval && legacy.has_action_hash, "{legacy:?}");

        let (state_b, tenant_b, token_b) = setup_state("eq_approval_hash_typed").await;
        register_ship(&state_b, &tenant_b).await;
        let typed = run_typed(state_b.clone(), &tenant_b, &token_b, &build(), peer).await;
        assert!(typed.has_approval && typed.has_action_hash, "{typed:?}");

        assert_eq!(legacy.decision, typed.decision);
        assert_eq!(legacy.approver_group, typed.approver_group);
        assert_eq!(legacy.risk_score, typed.risk_score);

        for (state, tenant) in [(state_a, tenant_a), (state_b, tenant_b)] {
            let approvals = state
                .storage
                .list_pending_approvals(&tenant, 10, 0)
                .await
                .expect("list pending approvals");
            assert_eq!(approvals.len(), 1, "one pending approval row");
            assert_eq!(approvals[0].original_call_hash.len(), 64);
        }
    }
}
