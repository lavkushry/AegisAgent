//! Wire mapping and gateway service entry for `POST /v1/authorize` (Week 3).
//!
//! Repository law (`docs/architecture.md` §5):
//! `authenticate/parse → typed service call → typed error/response mapping`.
//!
//! - Evaluation: [`aegis_decision::run_authorize_pipeline`] via
//!   [`GatewayDecisionRuntime`] (`decision_runtime` module).
//! - This module: re-exports library types, maps [`DecisionOutcome`] ↔
//!   [`AuthorizedOutcome`], REST/gRPC status helpers, and
//!   [`GatewayAuthorizeService`].

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value;

use crate::error::{ErrorReason, StatusError};
use crate::models::{AuthorizeRequest, AuthorizeResponse};
use crate::routes::AppState;

// Adapter-facing library surface. Prefer `run_authorize_pipeline` from REST/gRPC;
// stage types (`GuardedAuthorize`, …) stay on `aegis_decision` for the host
// port implementor (`decision_runtime`) rather than re-exported here.
pub use aegis_decision::{
    authorize_response_from_decision_record, run_authorize_pipeline, AuthCredential,
    AuthorizeContext, AuthorizeService, DecisionBody, DecisionFailure, DecisionFailureClass,
    DecisionOutcome, DecisionRuntime, EvaluateConfig, Transport,
};

/// Body carried by a completed authorization evaluation.
///
/// - [`AuthorizedBody::Decision`] — full success / decision payload (HTTP 200)
/// - [`AuthorizedBody::Status`] — structured [`StatusError`] envelope
/// - [`AuthorizedBody::Json`] — transitional partial decision-deny JSON
///   (`{"decision":"deny",...}`) that is not a full `AuthorizeResponse`
#[derive(Debug, Clone)]
pub enum AuthorizedBody {
    Decision(Box<AuthorizeResponse>),
    Status(Box<StatusError>),
    Json(Value),
}

/// Typed service outcome. Adapters map this to REST or gRPC; they never receive
/// an Axum `Response` from [`authorize`] / [`authorize_raw`].
#[derive(Debug, Clone)]
pub struct AuthorizedOutcome {
    pub status: StatusCode,
    pub body: AuthorizedBody,
}

impl AuthorizedOutcome {
    pub fn decision(resp: AuthorizeResponse) -> Self {
        Self {
            status: StatusCode::OK,
            body: AuthorizedBody::Decision(Box::new(resp)),
        }
    }

    pub fn status_error(err: StatusError) -> Self {
        Self {
            status: err.reason.status_code(),
            body: AuthorizedBody::Status(Box::new(err)),
        }
    }

    /// Success with an arbitrary JSON body (register_agent, create_tenant, …).
    pub fn json(status: StatusCode, value: Value) -> Self {
        Self {
            status,
            body: AuthorizedBody::Json(value),
        }
    }

    pub fn json_ok(value: Value) -> Self {
        Self::json(StatusCode::OK, value)
    }

    pub fn json_created(value: Value) -> Self {
        Self::json(StatusCode::CREATED, value)
    }

    pub fn is_success(&self) -> bool {
        self.status == StatusCode::OK || self.status == StatusCode::CREATED
    }
}

/// The gRPC status code a `StatusError`'s reason maps to.
///
/// Replaces the pre-Phase-D collapse of every failure to `Status::internal`.
/// Each arm mirrors the HTTP status the same reason already produces on REST
/// (`ErrorReason::status_code`), so the two protocols report the same failure
/// class:
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

/// Map a storage/domain [`AegisError`] through [`StatusError`] to tonic.
///
/// Storage-direct gRPC methods (playbooks, contact points, dashboards, …)
/// use this so `NotFound` / `Conflict` / pool exhaustion become
/// `NotFound` / `Aborted` / `Unavailable` instead of collapsed `Internal`.
pub fn aegis_error_to_tonic(err: aegis_common::errors::AegisError) -> tonic::Status {
    status_error_to_tonic(&StatusError::from(err))
}

/// Map a serialization failure (e.g. dashboard JSON) to tonic InvalidArgument.
pub fn serialize_error_to_tonic(context: &str, err: impl std::fmt::Display) -> tonic::Status {
    status_error_to_tonic(&StatusError::bad_request(format!("{context}: {err}")))
}

/// Map an HTTP error body to tonic Status (prefers [`StatusError`] envelope).
pub fn http_error_to_tonic(status: StatusCode, body: &[u8]) -> tonic::Status {
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

/// Map a typed outcome back to an Axum `Response` (REST adapter / tests).
pub fn outcome_to_response(outcome: AuthorizedOutcome) -> Response {
    match outcome.body {
        AuthorizedBody::Decision(resp) => (outcome.status, Json(*resp)).into_response(),
        AuthorizedBody::Status(err) => (*err).into_response(),
        AuthorizedBody::Json(v) => (outcome.status, Json(v)).into_response(),
    }
}

/// Map a typed outcome to a gRPC success body or tonic `Status`.
///
/// This is the only mapping the gRPC adapter needs — no Axum body buffering.
#[allow(clippy::result_large_err)] // tonic::Status is the gRPC wire error type
pub fn outcome_to_tonic(outcome: AuthorizedOutcome) -> Result<AuthorizeResponse, tonic::Status> {
    match outcome.body {
        AuthorizedBody::Decision(resp) if outcome.is_success() => Ok(*resp),
        AuthorizedBody::Decision(_) => Err(tonic::Status::internal(format!(
            "authorize returned decision body with HTTP {}",
            outcome.status
        ))),
        AuthorizedBody::Status(err) => Err(status_error_to_tonic(&err)),
        AuthorizedBody::Json(v) => {
            let bytes = serde_json::to_vec(&v).unwrap_or_default();
            Err(http_error_to_tonic(outcome.status, &bytes))
        }
    }
}

/// Map a typed outcome whose success body is JSON (approve/reject style) to
/// either the JSON value or a tonic `Status`. No Axum body buffering.
#[allow(clippy::result_large_err)]
pub fn outcome_to_tonic_json(
    outcome: AuthorizedOutcome,
) -> Result<serde_json::Value, tonic::Status> {
    match outcome.body {
        AuthorizedBody::Json(v) if outcome.is_success() => Ok(v),
        AuthorizedBody::Decision(resp) if outcome.is_success() => serde_json::to_value(*resp)
            .map_err(|e| tonic::Status::internal(format!("serialize decision: {e}"))),
        AuthorizedBody::Status(err) => Err(status_error_to_tonic(&err)),
        AuthorizedBody::Json(v) => {
            let bytes = serde_json::to_vec(&v).unwrap_or_default();
            Err(http_error_to_tonic(outcome.status, &bytes))
        }
        AuthorizedBody::Decision(_) => Err(tonic::Status::internal(format!(
            "service returned decision body with HTTP {}",
            outcome.status
        ))),
    }
}

/// Map any remaining Axum `Response` bridge to tonic, preferring StatusError
/// envelopes over collapsed `Status::internal`. Prefer typed outcomes when
/// available; this is the transitional helper for RPCs not yet extracted.
pub async fn axum_response_to_tonic_json(
    response: Response,
) -> Result<(StatusCode, serde_json::Value), tonic::Status> {
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|e| tonic::Status::internal(e.to_string()))?;
    if status.is_success() {
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| tonic::Status::internal(format!("Failed to parse response JSON: {e}")))?;
        return Ok((status, v));
    }
    Err(http_error_to_tonic(status, &body))
}

/// Build the HeaderMap for residual gateway code that still reads transport
/// headers after admit (OTel parent, etc.). Adapters prefer typed
/// [`AuthorizeContext`]; admit no longer re-reads credentials from headers.
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

/// Map a library [`DecisionOutcome`] to the gateway wire [`AuthorizedOutcome`].
pub fn decision_outcome_to_authorized(outcome: DecisionOutcome) -> AuthorizedOutcome {
    match outcome.body {
        DecisionBody::Decision(resp) => AuthorizedOutcome {
            status: StatusCode::from_u16(outcome.http_status).unwrap_or(StatusCode::OK),
            body: AuthorizedBody::Decision(resp),
        },
        DecisionBody::Failure(f) => {
            let mut err = decision_failure_to_status_error(f);
            if err.code != outcome.http_status {
                err.code = outcome.http_status;
            }
            AuthorizedOutcome::status_error(err)
        }
        DecisionBody::PartialDeny { reason } => AuthorizedOutcome {
            status: StatusCode::FORBIDDEN,
            body: AuthorizedBody::Json(serde_json::json!({
                "decision": "deny",
                "reason": reason
            })),
        },
    }
}

fn decision_failure_to_status_error(f: DecisionFailure) -> StatusError {
    let reason = match f.class {
        DecisionFailureClass::BadRequest => ErrorReason::BadRequest,
        DecisionFailureClass::Unauthorized => ErrorReason::Unauthorized,
        DecisionFailureClass::Forbidden => ErrorReason::Forbidden,
        DecisionFailureClass::NotFound => ErrorReason::NotFound,
        DecisionFailureClass::Conflict => ErrorReason::Conflict,
        DecisionFailureClass::AlreadyExists => ErrorReason::AlreadyExists,
        DecisionFailureClass::Invalid => ErrorReason::Invalid,
        DecisionFailureClass::Timeout => ErrorReason::Timeout,
        DecisionFailureClass::TooManyRequests => ErrorReason::TooManyRequests,
        DecisionFailureClass::NotImplemented => ErrorReason::NotImplemented,
        DecisionFailureClass::UnsupportedMediaType => ErrorReason::UnsupportedMediaType,
        DecisionFailureClass::Internal => ErrorReason::InternalError,
        DecisionFailureClass::ServiceUnavailable => ErrorReason::ServiceUnavailable,
        DecisionFailureClass::Unknown => ErrorReason::Unknown,
    };
    let mut err = StatusError::new(reason, f.message);
    if let Some(details) = f.details {
        err = err.with_details(details);
    }
    err
}

/// Reconstruct [`AuthorizeContext`] from REST request headers (handler edge).
#[allow(clippy::result_large_err)]
pub fn authorize_context_from_headers(
    headers: &HeaderMap,
    client_addr: std::net::SocketAddr,
) -> Result<AuthorizeContext, StatusError> {
    let tenant_id = crate::routes::get_runtime_tenant_from_headers(headers).ok_or_else(|| {
        StatusError::bad_request("Missing X-Aegis-Tenant-ID or X-Tenant-ID header")
    })?;

    let credential = if let Some(cn) = headers
        .get(crate::mtls::MTLS_CN_HEADER)
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        AuthCredential::MtlsCn(cn.to_string())
    } else {
        let token = headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_string();
        AuthCredential::BearerToken(token)
    };

    let sig = headers
        .get("x-aegis-request-signature")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);

    Ok(
        AuthorizeContext::new(tenant_id, client_addr, Transport::Rest, credential)
            .with_request_signature(sig),
    )
}

/// Re-export gateway DecisionRuntime implementor.
pub use crate::decision_runtime::GatewayDecisionRuntime;

/// Protocol-neutral authorize entry used by REST (optional) and gRPC.
///
/// Runs [`run_authorize_pipeline`] with the real client address and returns a
/// typed [`AuthorizedOutcome`]. Adapters map via [`outcome_to_response`] or
/// [`outcome_to_tonic`]. Prefer [`authorize_raw`] when the caller already holds
/// the signed REST body bytes.
pub async fn authorize(
    state: Arc<AppState>,
    ctx: AuthorizeContext,
    payload: &AuthorizeRequest,
) -> AuthorizedOutcome {
    let body_bytes = match serde_json::to_vec(payload) {
        Ok(b) => Bytes::from(b),
        Err(e) => {
            return AuthorizedOutcome::status_error(StatusError::bad_request(format!(
                "Failed to serialize authorize payload: {e}"
            )));
        }
    };
    authorize_raw(state, ctx, body_bytes).await
}

/// Like [`authorize`], but uses caller-supplied raw body bytes (REST HMAC path).
pub async fn authorize_raw(
    state: Arc<AppState>,
    ctx: AuthorizeContext,
    raw_body: Bytes,
) -> AuthorizedOutcome {
    // Optional: build headers only for OTel parent propagation parity with REST.
    if let Ok(headers) = build_service_headers(&ctx) {
        crate::otel::set_parent_from_headers(&headers);
    }
    let started_at = std::time::Instant::now();
    let runtime = GatewayDecisionRuntime::new(state.clone());
    let outcome = run_authorize_pipeline(
        &runtime,
        &ctx,
        &raw_body,
        started_at,
        EvaluateConfig {
            approval_ttl_secs: state.approval_ttl_secs,
        },
    )
    .await;
    decision_outcome_to_authorized(outcome)
}

/// Gateway-owned implementor of [`AuthorizeService`].
///
/// Holds shared [`AppState`] and runs [`run_authorize_pipeline`] through
/// [`GatewayDecisionRuntime`]. Prefer [`GatewayAuthorizeService::evaluate`] for
/// full wire fidelity; [`AuthorizeService::authorize`] returns the narrower
/// `Result<AuthorizeResponse, AegisError>` contract.
#[derive(Clone)]
pub struct GatewayAuthorizeService {
    state: Arc<AppState>,
}

impl GatewayAuthorizeService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Full evaluation with gateway wire outcome (preferred by REST/gRPC).
    pub async fn evaluate(
        &self,
        ctx: AuthorizeContext,
        request: &AuthorizeRequest,
    ) -> AuthorizedOutcome {
        authorize(self.state.clone(), ctx, request).await
    }

    /// Full evaluation with caller-supplied raw body (REST HMAC path).
    pub async fn evaluate_raw(&self, ctx: AuthorizeContext, raw_body: Bytes) -> AuthorizedOutcome {
        authorize_raw(self.state.clone(), ctx, raw_body).await
    }
}

#[async_trait::async_trait]
impl AuthorizeService for GatewayAuthorizeService {
    async fn authorize(
        &self,
        ctx: AuthorizeContext,
        request: AuthorizeRequest,
    ) -> Result<AuthorizeResponse, aegis_common::errors::AegisError> {
        let outcome = self.evaluate(ctx, &request).await;
        outcome_to_authorize_result(outcome)
    }
}

/// Map a rich gateway outcome to the library [`AuthorizeService`] result shape.
pub fn outcome_to_authorize_result(
    outcome: AuthorizedOutcome,
) -> Result<AuthorizeResponse, aegis_common::errors::AegisError> {
    use aegis_common::errors::AegisError;
    match outcome.body {
        AuthorizedBody::Decision(resp) if outcome.is_success() => Ok(*resp),
        AuthorizedBody::Status(err) => Err(status_error_to_aegis(*err)),
        AuthorizedBody::Json(v) => {
            // Partial deny JSON or unstructured failure — fail closed with a
            // stable client-visible class derived from the HTTP status.
            let msg = v
                .get("reason")
                .or_else(|| v.get("message"))
                .and_then(|x| x.as_str())
                .unwrap_or("authorization failed")
                .to_string();
            Err(match outcome.status.as_u16() {
                400 | 422 | 415 => AegisError::BadRequest(msg),
                401 => AegisError::Unauthorized(msg),
                404 => AegisError::NotFound(msg),
                409 => AegisError::Conflict(msg),
                _ => AegisError::Internal(msg),
            })
        }
        AuthorizedBody::Decision(_) => Err(aegis_common::errors::AegisError::Internal(format!(
            "authorize returned decision body with HTTP {}",
            outcome.status
        ))),
    }
}

fn status_error_to_aegis(err: StatusError) -> aegis_common::errors::AegisError {
    use aegis_common::errors::AegisError;
    match err.reason {
        ErrorReason::Unauthorized => AegisError::Unauthorized(err.message),
        ErrorReason::NotFound => AegisError::NotFound(err.message),
        ErrorReason::BadRequest | ErrorReason::Invalid | ErrorReason::UnsupportedMediaType => {
            AegisError::BadRequest(err.message)
        }
        ErrorReason::Conflict | ErrorReason::AlreadyExists => AegisError::Conflict(err.message),
        ErrorReason::Forbidden
        | ErrorReason::Timeout
        | ErrorReason::TooManyRequests
        | ErrorReason::NotImplemented
        | ErrorReason::ServiceUnavailable
        | ErrorReason::InternalError
        | ErrorReason::Unknown => AegisError::Internal(err.message),
    }
}

/// Map [`AegisError`] from the library trait back to a gateway [`StatusError`]
/// for adapters that still prefer the rich error envelope.
pub fn aegis_error_to_status_error(err: aegis_common::errors::AegisError) -> StatusError {
    match err {
        aegis_common::errors::AegisError::Unauthorized(m) => StatusError::unauthorized(m),
        aegis_common::errors::AegisError::NotFound(m) => StatusError::not_found(m),
        aegis_common::errors::AegisError::BadRequest(m) => StatusError::bad_request(m),
        aegis_common::errors::AegisError::Conflict(m) => StatusError::conflict(m),
        aegis_common::errors::AegisError::Database(e) => StatusError::from(e),
        aegis_common::errors::AegisError::Serialization(e) => {
            StatusError::bad_request(format!("Serialization error: {e}"))
        }
        aegis_common::errors::AegisError::Internal(m) => StatusError::internal(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StatusError;
    use axum::http::StatusCode;
    use tonic::Code;

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
    fn outcome_to_authorize_result_maps_status_error_to_aegis_error() {
        let outcome = AuthorizedOutcome::status_error(StatusError::unauthorized("bad token"));
        let err = outcome_to_authorize_result(outcome).expect_err("must err");
        match err {
            aegis_common::errors::AegisError::Unauthorized(m) => {
                assert_eq!(m, "bad token");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn outcome_to_authorize_result_passes_through_decision() {
        let resp = AuthorizeResponse {
            decision_id: uuid::Uuid::nil(),
            decision: "allow".into(),
            risk_score: 0,
            risk_level: "low".into(),
            composite_risk_score: 0,
            reason: "ok".into(),
            matched_policies: vec![],
            approval: None,
            redacted_fields: vec![],
            root_trust_level: "trusted_internal_unsigned".into(),
            dry_run: false,
            receipt: None,
        };
        let outcome = AuthorizedOutcome::decision(resp.clone());
        let got = outcome_to_authorize_result(outcome).expect("ok");
        assert_eq!(got.decision, "allow");
        assert_eq!(got.reason, "ok");
    }

    #[test]
    fn aegis_error_status_error_round_trip_preserves_class() {
        let se = StatusError::not_found("missing");
        let ae = status_error_to_aegis(se.clone());
        let back = aegis_error_to_status_error(ae);
        assert_eq!(back.reason, ErrorReason::NotFound);
        assert_eq!(back.message, "missing");
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
    fn aegis_error_to_tonic_maps_not_found_and_conflict() {
        let s = aegis_error_to_tonic(aegis_common::errors::AegisError::NotFound(
            "Incident not found".into(),
        ));
        assert_eq!(s.code(), Code::NotFound);
        assert_eq!(s.message(), "Incident not found");

        let s = aegis_error_to_tonic(aegis_common::errors::AegisError::Conflict(
            "Tenant already exists".into(),
        ));
        assert_eq!(s.code(), Code::Aborted);
        assert_eq!(s.message(), "Tenant already exists");
    }

    #[test]
    fn serialize_error_to_tonic_is_invalid_argument() {
        let s = serialize_error_to_tonic("serialize dashboard", "boom");
        assert_eq!(s.code(), Code::InvalidArgument);
        assert!(s.message().contains("serialize dashboard"));
    }

    #[test]
    fn outcome_to_tonic_maps_status_error_without_axum_body() {
        let outcome = AuthorizedOutcome::status_error(StatusError::forbidden("policy deny"));
        let err = outcome_to_tonic(outcome).expect_err("must be error");
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(err.message(), "policy deny");
    }

    #[test]
    fn outcome_to_tonic_maps_json_deny_by_http_status() {
        let outcome = AuthorizedOutcome {
            status: StatusCode::FORBIDDEN,
            body: AuthorizedBody::Json(serde_json::json!({
                "decision": "deny",
                "reason": "agent frozen"
            })),
        };
        let err = outcome_to_tonic(outcome).expect_err("must be error");
        assert_eq!(err.code(), Code::PermissionDenied);
        assert!(err.message().contains("agent frozen"));
    }

    #[test]
    fn outcome_to_response_round_trips_status_error() {
        let outcome = AuthorizedOutcome::status_error(StatusError::unauthorized("bad token"));
        let response = outcome_to_response(outcome);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
}

#[cfg(test)]
#[path = "authorize_equality.rs"]
mod authorize_equality;
