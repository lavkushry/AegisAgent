//! Maps `aegis_tool_broker_connectors::ExecuteError` to an HTTP response.
//! Status-code mapping is unchanged from the gateway's own (pre-extraction)
//! `broker_execute_error_response` in `routes/broker.rs` — only relocated.

use crate::dto::ErrorBody;
use aegis_tool_broker_connectors::ExecuteError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};

pub fn execute_error_response(e: ExecuteError) -> Response {
    let (status, kind) = match &e {
        ExecuteError::ToolNotActive { .. } => (StatusCode::FORBIDDEN, "tool_not_active"),
        ExecuteError::UnknownConnectorType { .. } => {
            (StatusCode::NOT_IMPLEMENTED, "unknown_connector_type")
        }
        ExecuteError::ApprovalRequired => (StatusCode::FORBIDDEN, "approval_required"),
        ExecuteError::ApprovalActionMismatch { .. } => {
            (StatusCode::FORBIDDEN, "approval_action_mismatch")
        }
        ExecuteError::Credential(_) => (StatusCode::SERVICE_UNAVAILABLE, "credential"),
        ExecuteError::Connector(_) => (StatusCode::SERVICE_UNAVAILABLE, "connector"),
    };
    (
        status,
        Json(ErrorBody {
            error: e.to_string(),
            kind,
        }),
    )
        .into_response()
}
