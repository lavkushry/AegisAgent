//! Protocol-neutral decision outcome (no Axum / tonic).
//!
//! Adapters map [`DecisionOutcome`] to REST (`StatusError` / JSON) or gRPC
//! (tonic `Status` / `AuthorizeResponse`). Evaluation never builds wire types.

use aegis_api::models::AuthorizeResponse;
use serde_json::Value;

/// Coarse failure class shared by REST and gRPC adapters.
///
/// Mirrors gateway `ErrorReason` without depending on Axum `StatusCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionFailureClass {
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
    Internal,
    ServiceUnavailable,
    Unknown,
}

impl DecisionFailureClass {
    /// HTTP status the REST adapter should emit for this class.
    pub fn http_status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Timeout => 408,
            Self::Conflict | Self::AlreadyExists => 409,
            Self::UnsupportedMediaType => 415,
            Self::Invalid => 422,
            Self::TooManyRequests => 429,
            Self::NotImplemented => 501,
            Self::ServiceUnavailable => 503,
            Self::Internal | Self::Unknown => 500,
        }
    }
}

/// Structured evaluation failure (auth, validation, infrastructure).
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionFailure {
    pub class: DecisionFailureClass,
    pub message: String,
    pub details: Option<Value>,
}

impl DecisionFailure {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            class: DecisionFailureClass::BadRequest,
            message: msg.into(),
            details: None,
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            class: DecisionFailureClass::Unauthorized,
            message: msg.into(),
            details: None,
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            class: DecisionFailureClass::Forbidden,
            message: msg.into(),
            details: None,
        }
    }

    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self {
            class: DecisionFailureClass::TooManyRequests,
            message: msg.into(),
            details: None,
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            class: DecisionFailureClass::Internal,
            message: msg.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Body of a completed authorization evaluation.
#[derive(Debug, Clone)]
pub enum DecisionBody {
    /// Full success / policy decision payload (HTTP 200).
    Decision(Box<AuthorizeResponse>),
    /// Structured failure envelope.
    Failure(DecisionFailure),
    /// Transitional partial deny JSON (`{"decision":"deny","reason":...}`).
    PartialDeny { reason: String },
}

/// Typed evaluation outcome. Adapters map this to wire forms.
#[derive(Debug, Clone)]
pub struct DecisionOutcome {
    pub http_status: u16,
    pub body: DecisionBody,
}

impl DecisionOutcome {
    pub fn decision(resp: AuthorizeResponse) -> Self {
        Self {
            http_status: 200,
            body: DecisionBody::Decision(Box::new(resp)),
        }
    }

    pub fn failure(f: DecisionFailure) -> Self {
        Self {
            http_status: f.class.http_status(),
            body: DecisionBody::Failure(f),
        }
    }

    pub fn partial_deny(reason: impl Into<String>) -> Self {
        Self {
            http_status: 403,
            body: DecisionBody::PartialDeny {
                reason: reason.into(),
            },
        }
    }

    pub fn is_success(&self) -> bool {
        self.http_status == 200 || self.http_status == 201
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_classes_map_stable_http_status() {
        assert_eq!(DecisionFailureClass::Unauthorized.http_status(), 401);
        assert_eq!(DecisionFailureClass::TooManyRequests.http_status(), 429);
        assert_eq!(DecisionFailureClass::NotImplemented.http_status(), 501);
        let f = DecisionFailure::unauthorized("bad token");
        let o = DecisionOutcome::failure(f);
        assert_eq!(o.http_status, 401);
        assert!(!o.is_success());
    }
}
