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
use uuid::Uuid;

use aegis_tool_broker_connectors::{
    BrokerExecutor, BrokerToolBinding, ConnectorRegistry, ConsumedApproval, ExecuteError,
    FilesystemConnector, GithubConnector, GithubMode, HttpConnector, ShellConnector,
};
use aegis_tool_broker_core::{action_hash, BrokerAction, CredentialRef, EnvCredentialResolver};

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

/// Builds the [`BrokerExecutor`] used by [`execute_broker_action`]. GitHub
/// runs in mock mode unless `AEGIS_GITHUB_API_BASE` is set (real mode);
/// `HttpConnector` is always registered (HTTPS-only). The filesystem and
/// shell connectors are opt-in via `AEGIS_BROKER_WORKSPACE` — with no
/// configured workspace there is nothing safe to scope them to, so they're
/// simply absent from the registry (an execute against `filesystem`/`shell`
/// then fails closed with `UnknownConnectorType`, not a wide-open default).
pub fn default_broker_executor() -> Arc<BrokerExecutor> {
    let github_mode = match std::env::var("AEGIS_GITHUB_API_BASE") {
        Ok(base_url) if !base_url.trim().is_empty() => GithubMode::Real {
            base_url: base_url.trim_end_matches('/').to_string(),
        },
        _ => GithubMode::Mock,
    };
    let mut registry = ConnectorRegistry::default()
        .register(Arc::new(GithubConnector::new(github_mode)))
        .register(Arc::new(HttpConnector::new()));

    if let Ok(workspace) = std::env::var("AEGIS_BROKER_WORKSPACE") {
        if !workspace.trim().is_empty() {
            match FilesystemConnector::new(&workspace) {
                Ok(fs) => registry = registry.register(Arc::new(fs)),
                Err(e) => error!(
                    "AEGIS_BROKER_WORKSPACE {:?} unusable for filesystem connector: {}",
                    workspace, e
                ),
            }
            match ShellConnector::new(&workspace) {
                Ok(shell) => registry = registry.register(Arc::new(shell)),
                Err(e) => error!(
                    "AEGIS_BROKER_WORKSPACE {:?} unusable for shell connector: {}",
                    workspace, e
                ),
            }
        }
    }

    Arc::new(BrokerExecutor::new(
        registry,
        Arc::new(EnvCredentialResolver),
    ))
}

/// Body for `POST /v1/broker/execute`.
#[derive(Debug, Deserialize)]
pub struct ExecuteBrokerActionBody {
    pub action: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub mutates_state: bool,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteBrokerActionRequest {
    pub tool_name: String,
    pub action: ExecuteBrokerActionBody,
    #[serde(default)]
    pub approval_id: Option<String>,
}

/// POST /v1/broker/execute — the Phase 6.4 execute route: consumes the
/// approval atomically via storage (for mutating actions), delegates to the
/// [`BrokerExecutor`], and durably appends a hash-chained receipt before
/// reporting success — mirroring `decision_requires_durable_receipt`'s
/// "protected decision" rule from the `/v1/authorize` path (mutating and/or
/// security-relevant actions must not be lost to a crash between execution
/// and evidence).
pub async fn execute_broker_action(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<ExecuteBrokerActionRequest>,
) -> impl IntoResponse {
    if req.tool_name.trim().is_empty() {
        return StatusError::bad_request("tool_name must not be empty").into_response();
    }
    if req.action.action.trim().is_empty() {
        return StatusError::bad_request("action must not be empty").into_response();
    }

    let tool = match state
        .storage
        .get_broker_tool_by_name(&tenant_id, &req.tool_name)
        .await
    {
        Ok(Some(tool)) => tool,
        Ok(None) => return StatusError::not_found("broker tool not found").into_response(),
        Err(e) => {
            error!("Failed to look up broker tool for execute: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // The tool identity always comes from the registration lookup above,
    // never from the request body — otherwise a caller could claim any
    // `tool_name` string while pointing `action`/`parameters` at whatever
    // it likes, decoupling the approval binding from what actually executes.
    let action = BrokerAction {
        tool: tool.tool_name.clone(),
        action: req.action.action,
        resource: req.action.resource,
        mutates_state: req.action.mutates_state,
        parameters: req.action.parameters,
    };
    let claimed_hash = action_hash(&action);

    let consumed: Option<ConsumedApproval> = if action.mutates_state {
        let approval_id = match req.approval_id.as_deref() {
            Some(id) if !id.trim().is_empty() => id,
            _ => {
                return StatusError::forbidden(
                    "approval_id is required for a state-mutating action",
                )
                .into_response()
            }
        };
        match state
            .storage
            .consume_approval(&tenant_id, approval_id, Some(&claimed_hash))
            .await
        {
            Ok(true) => Some(ConsumedApproval {
                approval_id: approval_id.to_string(),
                action_hash: claimed_hash.clone(),
            }),
            Ok(false) => {
                // The claimed-hash check failed atomically inside
                // consume_approval — nothing was consumed. Distinguish "wrong
                // hash, approval otherwise still valid" (409, approval
                // survives for a retry with the right action) from "not
                // consumable at all" (403: already used/expired/never
                // approved).
                return match state
                    .storage
                    .approval_is_still_consumable(&tenant_id, approval_id)
                    .await
                {
                    Ok(true) => {
                        StatusError::conflict("approval is bound to a different action_hash")
                            .into_response()
                    }
                    Ok(false) => StatusError::forbidden(
                        "approval is not consumable (already consumed, expired, or not approved)",
                    )
                    .into_response(),
                    Err(e) => {
                        error!("Failed to re-check approval consumability: {:?}", e);
                        StatusError::internal("Database error").into_response()
                    }
                };
            }
            Err(e) => {
                error!("Failed to consume approval for broker execute: {:?}", e);
                return StatusError::internal("Database error").into_response();
            }
        }
    } else {
        if req.approval_id.is_some() {
            return StatusError::bad_request(
                "approval_id is only meaningful when action.mutates_state is true",
            )
            .into_response();
        }
        None
    };

    let binding = BrokerToolBinding {
        tool_name: tool.tool_name.clone(),
        connector_type: tool.connector_type.clone(),
        credential_ref: if tool.credential_ref.is_empty() {
            None
        } else {
            Some(CredentialRef::new(tool.credential_ref.clone()))
        },
        status: tool.status.clone(),
    };

    let output = match state
        .broker_executor
        .execute(&binding, &action, consumed.as_ref())
        .await
    {
        Ok(output) => output,
        Err(e) => return broker_execute_error_response(e),
    };

    // Protected-decision receipt: mirroring `decision_requires_durable_receipt`'s
    // "protected decision" rule from the `/v1/authorize` path, this route treats
    // every successful execution as protected — a broker action is itself a real
    // external side effect (unlike a plain read-only `/v1/authorize` allow that
    // never touches the outside world). Written durably and hash-chained BEFORE
    // the success response goes out, so a crash between execution and receipt
    // write can never lose the evidence for what the broker just did. Built
    // directly (not through `build_decision_receipt`, which takes an
    // `AuthorizeRequest`) since a `BrokerAction` isn't one.
    let receipt = ActionReceiptRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        decision_id: None,
        ts: Utc::now().to_rfc3339(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        tool: Some(action.tool.clone()),
        action: Some(action.action.clone()),
        resource: action.resource.clone(),
        source_trust: "trusted_internal_signed".to_string(),
        decision: "broker_execute".to_string(),
        approver: consumed.as_ref().map(|c| c.approval_id.clone()),
        action_hash: Some(claimed_hash.clone()),
        prev_receipt_hash: String::new(),
        receipt_hash: String::new(),
        canon_version: super::authorize_canon::CANON_VERSION.to_string(),
        signature: None,
        signer_public_key: None,
        signer_key_id: None,
        created_at: Utc::now(),
    };
    if let Err(e) = super::retry_storage_write_on_busy(3, || {
        state
            .storage
            .append_action_receipt_atomic(&tenant_id, receipt.clone())
    })
    .await
    {
        error!(
            "Failed to durably append broker execute receipt (tenant={}, tool={}): {:?}",
            tenant_id, tool.tool_name, e
        );
        return StatusError::internal(
            "action executed but its receipt could not be durably recorded",
        )
        .into_response();
    }

    (
        StatusCode::OK,
        Json(json!({
            "tool_name": tool.tool_name,
            "connector_type": tool.connector_type,
            "action_hash": claimed_hash,
            "output": output,
        })),
    )
        .into_response()
}

fn broker_execute_error_response(e: ExecuteError) -> axum::response::Response {
    match e {
        ExecuteError::ToolNotActive { .. } => StatusError::forbidden(e.to_string()),
        ExecuteError::UnknownConnectorType { .. } => StatusError::not_implemented(e.to_string()),
        ExecuteError::ApprovalRequired | ExecuteError::ApprovalActionMismatch { .. } => {
            StatusError::forbidden(e.to_string())
        }
        ExecuteError::Credential(_) => StatusError::service_unavailable(e.to_string()),
        ExecuteError::Connector(_) => StatusError::service_unavailable(e.to_string()),
    }
    .into_response()
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

    /// Registers a GitHub mock-mode broker tool with no credential
    /// (`credential_ref: ""` -> `BrokerToolBinding.credential_ref: None`), so
    /// these tests never depend on an env var being set. `default_broker_executor`
    /// always registers `github` in mock mode unless `AEGIS_GITHUB_API_BASE`
    /// is set, matching this helper's assumption.
    async fn insert_active_github_tool(state: &Arc<AppState>, tenant_id: &str, tool_name: &str) {
        state
            .storage
            .insert_broker_tool(tenant_id, tool_name, "github", "", "[]", Utc::now())
            .await
            .unwrap();
    }

    fn read_action(tool_name: &str) -> ExecuteBrokerActionRequest {
        ExecuteBrokerActionRequest {
            tool_name: tool_name.to_string(),
            action: ExecuteBrokerActionBody {
                action: "read".to_string(),
                resource: Some("repo:acme/api".to_string()),
                mutates_state: false,
                parameters: json!({"path": "/repos/acme/api/issues"}),
            },
            approval_id: None,
        }
    }

    fn write_action(tool_name: &str) -> ExecuteBrokerActionRequest {
        ExecuteBrokerActionRequest {
            tool_name: tool_name.to_string(),
            action: ExecuteBrokerActionBody {
                action: "write".to_string(),
                resource: Some("repo:acme/api".to_string()),
                mutates_state: true,
                parameters: json!({"path": "/repos/acme/api/issues", "body": {"title": "hi"}}),
            },
            approval_id: None,
        }
    }

    /// Computes the `action_hash` a given execute request's `BrokerAction`
    /// resolves to, exactly as `execute_broker_action` does — used to bind a
    /// test-seeded approval to the right hash.
    fn request_action_hash(tool_name: &str, req: &ExecuteBrokerActionRequest) -> String {
        action_hash(&BrokerAction {
            tool: tool_name.to_string(),
            action: req.action.action.clone(),
            resource: req.action.resource.clone(),
            mutates_state: req.action.mutates_state,
            parameters: req.action.parameters.clone(),
        })
    }

    /// `approvals.decision_id` has a foreign key onto `decisions`, so a
    /// well-formed approval needs a real decision row first; the routes
    /// test-helper agent (`agent_key: "routes-agent"`, from `setup_state`)
    /// is reused as that decision's `agent_id`.
    async fn insert_approval_bound_to(
        state: &Arc<AppState>,
        tenant_id: &str,
        action_hash: &str,
    ) -> String {
        let agent = state
            .storage
            .get_agent_by_key(tenant_id, "routes-agent")
            .await
            .unwrap()
            .expect("setup_state's fixture agent");
        let decision = DecisionRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            agent_id: agent.id,
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "github".to_string(),
            action: "write".to_string(),
            resource: Some("repo:acme/api".to_string()),
            input_json: "{}".to_string(),
            decision: "require_approval".to_string(),
            risk_score: None,
            reason: None,
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            composite_risk_score: None,
            root_trust_level: None,
            parent_run_id: None,
            created_at: Utc::now(),
        };
        state.storage.insert_decision(&decision).await.unwrap();

        let approval = ApprovalRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: decision.id,
            status: "APPROVED".to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: action_hash.to_string(),
            edited_skill_call: None,
            effective_call_hash: None,
            expires_at: None,
            decided_at: Some(Utc::now()),
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now(),
        };
        let id = approval.id.clone();
        state.storage.insert_approval(&approval).await.unwrap();
        id
    }

    #[tokio::test]
    async fn a_known_active_tool_allows_a_read_and_appends_a_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("broker_execute_read").await;
        insert_active_github_tool(&state, &tenant_id, "gh-read").await;
        let receipts_before = state.storage.count_receipts(&tenant_id).await.unwrap();

        let response = execute_broker_action(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(read_action("gh-read")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["output"]["result"], json!("ok"));

        let receipts_after = state.storage.count_receipts(&tenant_id).await.unwrap();
        assert_eq!(receipts_after, receipts_before + 1);
    }

    #[tokio::test]
    async fn a_mutating_action_with_no_approval_id_is_forbidden() {
        let (state, tenant_id, _agent_token) = setup_state("broker_execute_no_approval").await;
        insert_active_github_tool(&state, &tenant_id, "gh-write").await;

        let response = execute_broker_action(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(write_action("gh-write")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_wrong_hash_approval_is_a_conflict_and_the_approval_survives() {
        let (state, tenant_id, _agent_token) = setup_state("broker_execute_wrong_hash").await;
        insert_active_github_tool(&state, &tenant_id, "gh-write").await;

        // Bound to some *other* action, not the one we're about to request.
        let approval_id = insert_approval_bound_to(&state, &tenant_id, &"0".repeat(64)).await;

        let mut req = write_action("gh-write");
        req.approval_id = Some(approval_id.clone());
        let response =
            execute_broker_action(State(state.clone()), TenantId(tenant_id.clone()), Json(req))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // The approval was NOT burned — it's still consumable with the
        // right hash bound to it (#1603 atomic-hash-check precedent).
        assert!(state
            .storage
            .approval_is_still_consumable(&tenant_id, &approval_id)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_hash_bound_approval_executes_and_appends_a_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("broker_execute_valid_approval").await;
        insert_active_github_tool(&state, &tenant_id, "gh-write").await;

        let req = write_action("gh-write");
        let hash = request_action_hash("gh-write", &req);
        let approval_id = insert_approval_bound_to(&state, &tenant_id, &hash).await;
        let receipts_before = state.storage.count_receipts(&tenant_id).await.unwrap();

        let mut req = req;
        req.approval_id = Some(approval_id.clone());
        let response =
            execute_broker_action(State(state.clone()), TenantId(tenant_id.clone()), Json(req))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["output"]["result"], json!("created"));

        let receipts_after = state.storage.count_receipts(&tenant_id).await.unwrap();
        assert_eq!(receipts_after, receipts_before + 1);

        // Single-use: the same approval cannot be consumed again.
        assert!(!state
            .storage
            .approval_is_still_consumable(&tenant_id, &approval_id)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_disabled_tool_fails_closed() {
        let (state, tenant_id, _agent_token) = setup_state("broker_execute_disabled").await;
        insert_active_github_tool(&state, &tenant_id, "gh-read").await;
        let tool = state
            .storage
            .get_broker_tool_by_name(&tenant_id, "gh-read")
            .await
            .unwrap()
            .unwrap();
        state
            .storage
            .set_broker_tool_status(&tenant_id, &tool.id, "disabled", Utc::now())
            .await
            .unwrap();

        let response = execute_broker_action(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(read_action("gh-read")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_unknown_tool_name_is_not_found() {
        let (state, tenant_id, _agent_token) = setup_state("broker_execute_unknown_tool").await;

        let response = execute_broker_action(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(read_action("does-not-exist")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_unregistered_connector_type_is_not_implemented() {
        let (state, tenant_id, _agent_token) =
            setup_state("broker_execute_unknown_connector").await;
        state
            .storage
            .insert_broker_tool(&tenant_id, "smtp-tool", "smtp", "", "[]", Utc::now())
            .await
            .unwrap();

        let response = execute_broker_action(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(read_action("smtp-tool")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
