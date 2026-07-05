//! Phase 6.2 (tool broker): gateway APIs for broker tool registrations.
//! A broker tool binds a tenant-visible `tool_name` to a connector type and
//! an *opaque* `credential_ref` — the credential value never transits these
//! APIs and is never stored by the gateway; the broker's Phase 6.1
//! `CredentialResolver` resolves the ref at execution time, so an agent
//! never sees a raw credential. Tenant-scoped via the same `TenantId`
//! bearer-auth extractor every other route uses.

#![allow(unused_imports)]
use crate::error::StatusError;
use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::error;

use crate::models::*;

use super::{parse_pagination, AppState, TenantId};

/// Body for `POST /v1/broker/tools`. `credential_ref` is an opaque
/// reference (e.g. `env:GITHUB_TOKEN`) — never a secret value; requests
/// that look like they embed a raw secret are rejected outright.
#[derive(Debug, Deserialize)]
pub struct RegisterBrokerToolRequest {
    pub tool_name: String,
    pub connector_type: String,
    pub credential_ref: String,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
}

fn is_valid_status(status: &str) -> bool {
    matches!(status, "active" | "disabled")
}

/// POST /v1/broker/tools — register a broker tool. Tenant-scoped; 409 if
/// the tenant already has a tool with the same name.
pub async fn register_broker_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<RegisterBrokerToolRequest>,
) -> impl IntoResponse {
    if req.tool_name.trim().is_empty() {
        return StatusError::bad_request("tool_name must not be empty").into_response();
    }
    if req.connector_type.trim().is_empty() {
        return StatusError::bad_request("connector_type must not be empty").into_response();
    }
    // A credential *reference* is a short scheme-prefixed locator, never the
    // secret itself. Reject anything without a `scheme:` shape so raw tokens
    // pasted here by mistake never reach storage.
    if !req.credential_ref.contains(':') {
        return StatusError::bad_request(
            "credential_ref must be a scheme-prefixed reference (e.g. env:VAR_NAME), never a raw secret",
        )
        .into_response();
    }
    let allowed_scopes_json = match serde_json::to_string(&req.allowed_scopes) {
        Ok(s) => s,
        Err(_) => return StatusError::bad_request("invalid allowed_scopes").into_response(),
    };

    // Friendly 409 instead of a unique-constraint 500 on duplicate names.
    match state
        .storage
        .get_broker_tool_by_name(&tenant_id, &req.tool_name)
        .await
    {
        Ok(Some(_)) => {
            return StatusError::conflict("a broker tool with this tool_name already exists")
                .into_response()
        }
        Ok(None) => {}
        Err(e) => {
            error!("Failed to check broker tool name: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    }

    let now = Utc::now();
    let tool_id = match state
        .storage
        .insert_broker_tool(
            &tenant_id,
            &req.tool_name,
            &req.connector_type,
            &req.credential_ref,
            &allowed_scopes_json,
            now,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register broker tool: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    match state.storage.get_broker_tool(&tenant_id, &tool_id).await {
        Ok(Some(tool)) => (StatusCode::CREATED, Json(tool)).into_response(),
        Ok(None) => StatusError::internal("broker tool vanished immediately after registration")
            .into_response(),
        Err(e) => {
            error!("Failed to fetch broker tool after registration: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/broker/tools/:id — fetch one broker tool. Tenant-scoped (404
/// cross-tenant).
pub async fn get_broker_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(tool_id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_broker_tool(&tenant_id, &tool_id).await {
        Ok(Some(tool)) => (StatusCode::OK, Json(tool)).into_response(),
        Ok(None) => StatusError::not_found("broker tool not found").into_response(),
        Err(e) => {
            error!("Failed to get broker tool: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/broker/tools — list the tenant's broker tools (paginated).
pub async fn list_broker_tools(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    match state
        .storage
        .list_broker_tools(&tenant_id, limit, offset)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list broker tools: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/broker/tools/:id/status`.
#[derive(Debug, Deserialize)]
pub struct SetBrokerToolStatusRequest {
    /// `active` | `disabled`.
    pub status: String,
}

/// POST /v1/broker/tools/:id/status — enable/disable a broker tool.
/// Tenant-scoped; 404 on an unknown or cross-tenant tool id. Execution
/// (Phase 6.3 connectors) fails closed on anything but `active`.
pub async fn set_broker_tool_status(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(tool_id): Path<String>,
    Json(req): Json<SetBrokerToolStatusRequest>,
) -> impl IntoResponse {
    if !is_valid_status(&req.status) {
        return StatusError::bad_request("status must be active or disabled").into_response();
    }

    match state
        .storage
        .set_broker_tool_status(&tenant_id, &tool_id, &req.status, Utc::now())
        .await
    {
        Ok(true) => (StatusCode::OK, Json(json!({ "status": req.status }))).into_response(),
        Ok(false) => StatusError::not_found("broker tool not found").into_response(),
        Err(e) => {
            error!("Failed to update broker tool status: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;
    use axum::body::to_bytes;

    fn sample_register_request(tool_name: &str) -> RegisterBrokerToolRequest {
        RegisterBrokerToolRequest {
            tool_name: tool_name.to_string(),
            connector_type: "github".to_string(),
            credential_ref: "env:GITHUB_TOKEN".to_string(),
            allowed_scopes: vec!["repo:read".to_string()],
        }
    }

    #[tokio::test]
    async fn register_then_get_and_list_round_trip() {
        let (state, tenant_id, _agent_token) = setup_state("broker_register_route").await;

        let response = register_broker_tool(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_register_request("gh-issues")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: BrokerToolRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.tool_name, "gh-issues");
        assert_eq!(created.status, "active");
        assert_eq!(created.credential_ref, "env:GITHUB_TOKEN");

        let response = get_broker_tool(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let fetched: BrokerToolRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched.connector_type, "github");

        let response = list_broker_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<BrokerToolRecord> = serde_json::from_slice(&body).unwrap();
        assert!(rows.iter().any(|t| t.id == created.id));
    }

    #[tokio::test]
    async fn duplicate_tool_name_returns_conflict() {
        let (state, tenant_id, _agent_token) = setup_state("broker_duplicate_route").await;

        let response = register_broker_tool(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_register_request("gh-issues")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = register_broker_tool(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_register_request("gh-issues")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn raw_secret_credential_ref_is_rejected() {
        let (state, tenant_id, _agent_token) = setup_state("broker_raw_secret_route").await;

        let mut req = sample_register_request("gh-issues");
        // Looks like a pasted raw token: no `scheme:` prefix.
        req.credential_ref = "ghp_abc123SecretValue".to_string();
        let response =
            register_broker_tool(State(state.clone()), TenantId(tenant_id.clone()), Json(req))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Nothing was stored.
        let response = list_broker_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<BrokerToolRecord> = serde_json::from_slice(&body).unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn empty_fields_are_rejected() {
        let (state, tenant_id, _agent_token) = setup_state("broker_empty_fields_route").await;

        let mut req = sample_register_request("  ");
        req.tool_name = "  ".to_string();
        let response =
            register_broker_tool(State(state.clone()), TenantId(tenant_id.clone()), Json(req))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut req = sample_register_request("gh-issues");
        req.connector_type = "".to_string();
        let response =
            register_broker_tool(State(state.clone()), TenantId(tenant_id.clone()), Json(req))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn status_update_validates_input_and_unknown_ids() {
        let (state, tenant_id, _agent_token) = setup_state("broker_status_route").await;

        let response = register_broker_tool(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_register_request("gh-issues")),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: BrokerToolRecord = serde_json::from_slice(&body).unwrap();

        // Invalid status value -> 400.
        let response = set_broker_tool_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
            Json(SetBrokerToolStatusRequest {
                status: "paused".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Unknown id -> 404.
        let response = set_broker_tool_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("bt-does-not-exist".to_string()),
            Json(SetBrokerToolStatusRequest {
                status: "disabled".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Valid disable -> 200, and the change is visible on re-fetch.
        let response = set_broker_tool_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
            Json(SetBrokerToolStatusRequest {
                status: "disabled".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let response = get_broker_tool(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let fetched: BrokerToolRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched.status, "disabled");
    }
}
