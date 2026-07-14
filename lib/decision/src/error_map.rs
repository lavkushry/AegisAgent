//! Map [`AegisError`] to [`DecisionOutcome`] at library boundaries.

use aegis_common::errors::AegisError;

use crate::outcome::{DecisionFailure, DecisionFailureClass, DecisionOutcome};

/// Preserve the AegisError class so adapters map the same way as
/// `StatusError::from(AegisError)` on the gateway (including pool
/// exhaustion → 503 without pulling sqlx into this crate).
pub(crate) fn aegis_err_to_outcome(e: AegisError) -> DecisionOutcome {
    if e.is_pool_exhausted() {
        return DecisionOutcome::failure(DecisionFailure {
            class: DecisionFailureClass::ServiceUnavailable,
            message: "Database connection pool exhausted".into(),
            details: None,
        });
    }
    let failure = match e {
        AegisError::Unauthorized(m) => DecisionFailure::unauthorized(m),
        AegisError::NotFound(m) => DecisionFailure {
            class: DecisionFailureClass::NotFound,
            message: m,
            details: None,
        },
        AegisError::BadRequest(m) => DecisionFailure::bad_request(m),
        AegisError::Conflict(m) => DecisionFailure {
            class: DecisionFailureClass::Conflict,
            message: m,
            details: None,
        },
        AegisError::Serialization(err) => {
            DecisionFailure::bad_request(format!("Serialization error: {err}"))
        }
        AegisError::Database(_) => DecisionFailure::internal("Database error"),
        AegisError::Internal(m) => DecisionFailure::internal(m),
    };
    DecisionOutcome::failure(failure)
}
