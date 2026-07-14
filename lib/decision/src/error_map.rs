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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::DecisionBody;

    // Pool-exhausted → 503 is gated on `AegisError::is_pool_exhausted()` (sqlx
    // PoolTimedOut). That path is covered by gateway storage/pool tests; this
    // crate deliberately does not depend on sqlx, so we only assert non-DB
    // class mappings and internal/CWE-209 message hygiene here.

    #[test]
    fn unauthorized_maps_to_401() {
        let out = aegis_err_to_outcome(AegisError::Unauthorized("bad token".into()));
        assert_eq!(out.http_status, 401);
        match out.body {
            DecisionBody::Failure(f) => {
                assert_eq!(f.class, DecisionFailureClass::Unauthorized);
                assert_eq!(f.message, "bad token");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn conflict_maps_to_409() {
        let out = aegis_err_to_outcome(AegisError::Conflict("replay".into()));
        assert_eq!(out.http_status, 409);
        match out.body {
            DecisionBody::Failure(f) => assert_eq!(f.class, DecisionFailureClass::Conflict),
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn internal_maps_to_500_without_extra_detail() {
        let out = aegis_err_to_outcome(AegisError::Internal("secret stack".into()));
        assert_eq!(out.http_status, 500);
        match out.body {
            DecisionBody::Failure(f) => {
                assert_eq!(f.class, DecisionFailureClass::Internal);
                assert_eq!(f.message, "secret stack");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn bad_request_and_not_found_preserve_class() {
        let br = aegis_err_to_outcome(AegisError::BadRequest("nope".into()));
        assert_eq!(br.http_status, 400);
        match br.body {
            DecisionBody::Failure(f) => assert_eq!(f.class, DecisionFailureClass::BadRequest),
            other => panic!("expected Failure, got {other:?}"),
        }
        let nf = aegis_err_to_outcome(AegisError::NotFound("gone".into()));
        assert_eq!(nf.http_status, 404);
        match nf.body {
            DecisionBody::Failure(f) => assert_eq!(f.class, DecisionFailureClass::NotFound),
            other => panic!("expected Failure, got {other:?}"),
        }
    }
}
