//! Kubernetes-style structured error responses (#1144).
//!
//! Replaces the previous ad-hoc `{"error": "..."}` JSON bodies with a single
//! consistent envelope, so every Aegis gateway error response — regardless of
//! which handler produced it — has the same shape and a typed `reason` an
//! SDK or dashboard can branch on instead of pattern-matching free-text.

use aegis_common::errors::AegisError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// A defined, finite set of machine-readable error reasons.
///
/// Mirrors the precedent set by Kubernetes' own `StatusReason` enum: each
/// reason maps to exactly one HTTP status code, so a `reason` always implies
/// the same `code` (see [`ErrorReason::status_code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum ErrorReason {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    AlreadyExists,
    Invalid,
    Timeout,
    TooManyRequests,
    NotImplemented,
    UnsupportedMediaType,
    InternalError,
    /// The server is temporarily overloaded and cannot accept the request
    /// right now (#911: Tower load-shed layer). Distinct from `TooManyRequests`
    /// (a per-tenant rate-limit policy decision) — this is a process-wide
    /// backpressure signal with no `tenant_id` involved at all.
    ServiceUnavailable,
    Unknown,
}

impl ErrorReason {
    pub fn status_code(self) -> StatusCode {
        match self {
            ErrorReason::BadRequest => StatusCode::BAD_REQUEST,
            ErrorReason::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorReason::Forbidden => StatusCode::FORBIDDEN,
            ErrorReason::NotFound => StatusCode::NOT_FOUND,
            ErrorReason::Conflict => StatusCode::CONFLICT,
            ErrorReason::AlreadyExists => StatusCode::CONFLICT,
            ErrorReason::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorReason::Timeout => StatusCode::REQUEST_TIMEOUT,
            ErrorReason::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ErrorReason::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            ErrorReason::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorReason::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorReason::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorReason::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// A structured, Kubernetes `Status`-style error response.
///
/// ```json
/// {
///   "kind": "Status",
///   "apiVersion": "v1",
///   "status": "Failure",
///   "message": "agent not found",
///   "reason": "NotFound",
///   "details": {"name": "agent-123"},
///   "code": 404
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatusError {
    pub kind: String,
    pub api_version: String,
    pub status: String,
    pub message: String,
    pub reason: ErrorReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    pub code: u16,
}

impl StatusError {
    pub fn new(reason: ErrorReason, message: impl Into<String>) -> Self {
        StatusError {
            kind: "Status".to_string(),
            api_version: "v1".to_string(),
            status: "Failure".to_string(),
            message: message.into(),
            reason,
            details: None,
            code: reason.status_code().as_u16(),
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::BadRequest, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::Unauthorized, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::Forbidden, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::NotFound, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::Conflict, message)
    }

    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::AlreadyExists, message)
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::Invalid, message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::Timeout, message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::TooManyRequests, message)
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::NotImplemented, message)
    }

    pub fn unsupported_media_type(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::UnsupportedMediaType, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::InternalError, message)
    }

    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorReason::ServiceUnavailable, message)
    }
}

impl IntoResponse for StatusError {
    fn into_response(self) -> Response {
        let code = self.reason.status_code();
        if self.reason == ErrorReason::ServiceUnavailable {
            (code, [("Retry-After", "5")], Json(self)).into_response()
        } else {
            (code, Json(self)).into_response()
        }
    }
}

impl From<sqlx::Error> for StatusError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::PoolTimedOut => {
                StatusError::service_unavailable("Database connection pool exhausted")
            }
            sqlx::Error::PoolClosed => StatusError::internal("Database error"),
            _ => StatusError::internal("Database error"),
        }
    }
}

impl From<AegisError> for StatusError {
    fn from(err: AegisError) -> Self {
        match err {
            AegisError::Database(sqlx_err) => StatusError::from(sqlx_err),
            AegisError::NotFound(msg) => StatusError::not_found(msg),
            AegisError::Unauthorized(msg) => StatusError::unauthorized(msg),
            AegisError::BadRequest(msg) => StatusError::bad_request(msg),
            AegisError::Conflict(msg) => StatusError::conflict(msg),
            AegisError::Internal(msg) => StatusError::internal(msg),
            AegisError::Serialization(e) => {
                StatusError::bad_request(format!("Serialization error: {e}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_serializes_to_kubernetes_status_shape() {
        let err = StatusError::not_found("agent not found");
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value["kind"], "Status");
        assert_eq!(value["apiVersion"], "v1");
        assert_eq!(value["status"], "Failure");
        assert_eq!(value["message"], "agent not found");
        assert_eq!(value["reason"], "NotFound");
        assert_eq!(value["code"], 404);
        assert!(value.get("details").is_none());
    }

    #[test]
    fn each_reason_maps_to_its_documented_status_code() {
        assert_eq!(
            StatusError::bad_request("x").code,
            StatusCode::BAD_REQUEST.as_u16()
        );
        assert_eq!(
            StatusError::unauthorized("x").code,
            StatusCode::UNAUTHORIZED.as_u16()
        );
        assert_eq!(
            StatusError::forbidden("x").code,
            StatusCode::FORBIDDEN.as_u16()
        );
        assert_eq!(
            StatusError::not_found("x").code,
            StatusCode::NOT_FOUND.as_u16()
        );
        assert_eq!(
            StatusError::conflict("x").code,
            StatusCode::CONFLICT.as_u16()
        );
        assert_eq!(
            StatusError::already_exists("x").code,
            StatusCode::CONFLICT.as_u16()
        );
        assert_eq!(
            StatusError::invalid("x").code,
            StatusCode::UNPROCESSABLE_ENTITY.as_u16()
        );
        assert_eq!(
            StatusError::timeout("x").code,
            StatusCode::REQUEST_TIMEOUT.as_u16()
        );
        assert_eq!(
            StatusError::too_many_requests("x").code,
            StatusCode::TOO_MANY_REQUESTS.as_u16()
        );
        assert_eq!(
            StatusError::internal("x").code,
            StatusCode::INTERNAL_SERVER_ERROR.as_u16()
        );
    }

    #[test]
    fn with_details_attaches_structured_context() {
        let err = StatusError::not_found("agent not found")
            .with_details(serde_json::json!({"name": "agent-123"}));
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value["details"]["name"], "agent-123");
    }

    #[tokio::test]
    async fn into_response_uses_the_reason_status_code() {
        let response = StatusError::conflict("already approved").into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn into_response_body_round_trips_through_json() {
        use axum::body::to_bytes;

        let response = StatusError::internal("db unavailable").into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["reason"], "InternalError");
        assert_eq!(value["message"], "db unavailable");
        assert_eq!(value["code"], 500);
    }
}
