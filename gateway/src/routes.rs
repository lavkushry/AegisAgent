use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;

use crate::db;
use crate::models::*;
use crate::policy::PolicyEngine;

// Shared app state containing DB pool and Cedar policy engine
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub policy_engine: PolicyEngine,
}

// Extractor helper to get tenant_id from Bearer token
fn get_tenant_from_headers(
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Missing Authorization header"})),
        ))?;

    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid Authorization format"})),
        ));
    }

    let token = &auth_header["Bearer ".len()..];
    // For local testing, if token is "aegis_secret" or similar, use "tenant_123"
    // If it starts with "tenant_", treat it as the tenant_id.
    if token.starts_with("tenant_") {
        Ok(token.to_string())
    } else {
        Ok("tenant_123".to_string())
    }
}

fn get_runtime_tenant_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("X-Aegis-Tenant-ID")
        .or_else(|| headers.get("X-Tenant-ID"))
        .and_then(|h| h.to_str().ok())
        .filter(|tenant_id| !tenant_id.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "tenant_123".to_string())
}

async fn ensure_tenant_exists(pool: &sqlx::SqlitePool, tenant_id: &str) -> Result<(), sqlx::Error> {
    if db::get_tenant_by_id(pool, tenant_id).await?.is_none() {
        db::register_tenant(pool, tenant_id, "Default Org", "developer").await?;
    }
    Ok(())
}

fn risk_score_for_level(risk_level: &str) -> i32 {
    match risk_level {
        "low" => 10,
        "medium" => 40,
        "high" => 75,
        "critical" => 95,
        _ => 10,
    }
}

fn mcp_server_key_from_tool(tool: &str) -> Option<&str> {
    tool.strip_prefix("mcp:")
        .filter(|server_key| !server_key.is_empty())
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_json).collect()),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            let mut sorted = serde_json::Map::new();
            for (key, value) in entries {
                sorted.insert(key, canonicalize_json(value));
            }
            Value::Object(sorted)
        }
        primitive => primitive,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// Canonicalization scheme version. MUST stay byte-identical with the SDKs
/// (see `tests/canonical_action_vectors.json` and `aegisagent.decorator.CANON_VERSION`).
/// Scheme "aegis-jcs-1": keys sorted by Unicode code point, compact separators,
/// raw UTF-8 (serde_json does not escape non-ASCII), null for absent resource.
pub const CANON_VERSION: &str = "aegis-jcs-1";

/// Deterministic canonical string for a tool call. The SDK hashes the exact same
/// string; byte-equality here is the foundation of the fail-closed approval guarantee.
fn canonical_action_string(tool_call: &AuthorizeToolCall) -> String {
    let value = serde_json::to_value(tool_call).unwrap_or(Value::Null);
    let canonical = canonicalize_json(value);
    serde_json::to_string(&canonical).unwrap_or_default()
}

fn hash_tool_call(tool_call: &AuthorizeToolCall) -> String {
    sha256_hex(canonical_action_string(tool_call).as_bytes())
}

/// Canonical (scheme `aegis-jcs-1`) string for an arbitrary JSON value. Used for
/// action-receipt hashing; MUST match the SDK's `canonicalize()` byte-for-byte
/// (see `docs/action-receipt-spec.md` and `tests/receipt_chain_vectors.json`).
fn canonical_value_string(value: &Value) -> String {
    serde_json::to_string(&canonicalize_json(value.clone())).unwrap_or_default()
}

/// True if the approval window has passed. Defense-in-depth alongside the SDK's
/// client-side expiry check: the gateway must not hand out, or grant, an approval
/// whose `expires_at` is in the past.
fn approval_is_expired(app: &ApprovalRecord) -> bool {
    app.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
}

async fn write_decision_and_audit(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    payload: &AuthorizeRequest,
    decision_id: Uuid,
    decision: &str,
    risk_score: i32,
    reason: &str,
    matched_policies: &[String],
    audit_event_type: &str,
) -> Result<(), sqlx::Error> {
    let decision_record = DecisionRecord {
        id: decision_id.to_string(),
        tenant_id: tenant_id.to_string(),
        agent_id: agent_id.to_string(),
        user_id: payload.user.as_ref().map(|u| u.id.clone()),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        skill: payload.tool_call.tool.clone(),
        action: payload.tool_call.action.clone(),
        resource: payload.tool_call.resource.clone(),
        input_json: serde_json::to_string(&payload.tool_call.parameters).unwrap_or_default(),
        decision: decision.to_string(),
        risk_score: Some(risk_score),
        reason: Some(reason.to_string()),
        matched_policy_ids: Some(matched_policies.join(",")),
        created_at: Utc::now(),
    };

    db::insert_decision(pool, &decision_record).await?;

    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: audit_event_type.to_string(),
        agent_id: Some(agent_id.to_string()),
        user_id: payload.user.as_ref().map(|u| u.id.clone()),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        span_id: None,
        skill: Some(payload.tool_call.tool.clone()),
        action: Some(payload.tool_call.action.clone()),
        resource: payload.tool_call.resource.clone(),
        event_json: serde_json::to_string(&decision_record).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    db::insert_audit_event(pool, &audit_record).await?;

    Ok(())
}

// Register Agent Handler
pub async fn register_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Ensure tenant exists in database, auto-create if missing for developer onboarding convenience
    if let Err(e) = db::get_tenant_by_id(&state.pool, &tenant_id).await {
        error!("Database lookup error: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
            .into_response();
    }
    if let Ok(None) = db::get_tenant_by_id(&state.pool, &tenant_id).await {
        if let Err(e) =
            db::register_tenant(&state.pool, &tenant_id, "Default Org", "developer").await
        {
            error!("Failed to auto-register tenant: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to initialize tenant"})),
            )
                .into_response();
        }
    }

    // Check if agent already exists
    match db::get_agent_by_key(&state.pool, &tenant_id, &payload.agent_key).await {
        Ok(Some(agent)) => {
            info!("Agent already registered: {}", payload.agent_key);
            return (
                StatusCode::OK,
                Json(RegisterAgentResponse {
                    id: Uuid::parse_str(&agent.id).unwrap(),
                    agent_key: agent.agent_key,
                    agent_token: agent.agent_token,
                }),
            )
                .into_response();
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        _ => {}
    }

    // Generate a secure agent token
    let agent_token = format!("agent_tok_{}", Uuid::new_v4().simple());

    let agent_id = Uuid::new_v4();

    let agent_record = AgentRecord {
        id: agent_id.to_string(),
        tenant_id: tenant_id.clone(),
        agent_key: payload.agent_key,
        agent_token: agent_token.clone(),
        name: payload.name,
        owner_team: payload.owner_team,
        owner_email: None,
        environment: payload.environment,
        framework: payload.framework,
        model_provider: payload.model_provider,
        model_name: payload.model_name,
        purpose: payload.purpose,
        risk_tier: payload.risk_tier,
        status: "active".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    if let Err(e) = db::insert_agent(&state.pool, &agent_record).await {
        error!("Failed to insert agent: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database insert failed"})),
        )
            .into_response();
    }

    // Log audit event
    let audit_id = Uuid::new_v4().to_string();
    let audit_record = AuditEventRecord {
        id: audit_id,
        tenant_id,
        event_type: "agent_registered".to_string(),
        agent_id: Some(agent_id.to_string()),
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&agent_record).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::CREATED,
        Json(RegisterAgentResponse {
            id: agent_id,
            agent_key: agent_record.agent_key,
            agent_token,
        }),
    )
        .into_response()
}

// Register Static Tool Handler
pub async fn register_tool(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterToolRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Insert skill
    let skill_id = match db::insert_skill(
        &state.pool,
        &tenant_id,
        &payload.skill_key,
        &payload.name,
        &payload.r#type,
        payload.auth_type.as_deref(),
        payload.owner_team.as_deref(),
        payload.default_risk.as_deref(),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register skill: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register skill"})),
            )
                .into_response();
        }
    };

    // Insert skill actions
    for action in payload.actions {
        if let Err(e) = db::insert_skill_action(
            &state.pool,
            &skill_id,
            &action.action_key,
            action.description.as_deref(),
            &action.risk,
            action.mutates_state,
            action.data_access.as_deref(),
            action.approval_required,
            &action.default_decision,
        )
        .await
        {
            error!("Failed to register skill action: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register skill action"})),
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        Json(json!({"status": "success", "skill_id": skill_id})),
    )
        .into_response()
}

// Register MCP Server Handler
pub async fn register_mcp_server(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterMcpServerRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    if let Err(e) = ensure_tenant_exists(&state.pool, &tenant_id).await {
        error!("Failed to initialize tenant for MCP server: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to initialize tenant"})),
        )
            .into_response();
    }

    let server_id = match db::upsert_mcp_server(
        &state.pool,
        &tenant_id,
        &payload.server_key,
        &payload.name,
        payload.owner_team.as_deref(),
        &payload.transport,
        payload.source.as_deref(),
        &payload.trust_level,
        &payload.endpoint,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register MCP server: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    (
        StatusCode::CREATED,
        Json(RegisterMcpServerResponse {
            server_id,
            server_key: payload.server_key,
            status: "active".to_string(),
        }),
    )
        .into_response()
}

pub async fn discover_mcp_tools(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(server_key): Path<String>,
    Json(payload): Json<DiscoverMcpToolsRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let server = match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
        Ok(Some(server)) => server,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "MCP server not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to look up MCP server: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let skill_key = format!("mcp:{}", server_key);
    let skill_id = match db::insert_skill(
        &state.pool,
        &tenant_id,
        &skill_key,
        &server.name,
        "mcp",
        None,
        server.owner_team.as_deref(),
        None,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register MCP skill manifest: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register MCP skill manifest"})),
            )
                .into_response();
        }
    };

    let mut registered = 0usize;
    for tool in &payload.tools {
        if let Err(e) = db::upsert_mcp_tool(&state.pool, &tenant_id, &server.id, tool).await {
            error!("Failed to upsert MCP tool manifest: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register MCP tool manifest"})),
            )
                .into_response();
        }

        let default_decision = if tool.approval_required {
            "require_approval"
        } else {
            "policy"
        };
        if let Err(e) = db::insert_skill_action(
            &state.pool,
            &skill_id,
            &tool.tool_key,
            tool.description.as_deref(),
            &tool.risk,
            tool.mutates_state,
            None,
            tool.approval_required,
            default_decision,
        )
        .await
        {
            error!("Failed to upsert MCP skill action: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to register MCP skill action"})),
            )
                .into_response();
        }

        let audit_record = AuditEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            event_type: "mcp_tool_discovered".to_string(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: Some(skill_key.clone()),
            action: Some(tool.tool_key.clone()),
            resource: Some(server_key.clone()),
            event_json: serde_json::to_string(tool).unwrap_or_default(),
            input_hash: None,
            output_hash: None,
            created_at: Utc::now(),
        };
        let _ = db::insert_audit_event(&state.pool, &audit_record).await;
        registered += 1;
    }

    let tools = match db::list_mcp_tools(&state.pool, &tenant_id, &server_key).await {
        Ok(tools) => tools,
        Err(e) => {
            error!("Failed to list MCP tools after discovery: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "server_key": server_key,
            "tools_registered": registered,
            "tools": tools,
        })),
    )
        .into_response()
}

pub async fn get_mcp_tool_manifest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::get_mcp_server_by_key(&state.pool, &tenant_id, &server_key).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "MCP server not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to look up MCP server: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    }

    match db::list_mcp_tools(&state.pool, &tenant_id, &server_key).await {
        Ok(tools) => (
            StatusCode::OK,
            Json(json!({"server_key": server_key, "tools": tools})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to list MCP tools: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn approve_mcp_tool(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((server_key, tool_key)): Path<(String, String)>,
) -> impl IntoResponse {
    update_mcp_tool_status(state, headers, server_key, tool_key, "approved").await
}

pub async fn disable_mcp_tool(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((server_key, tool_key)): Path<(String, String)>,
) -> impl IntoResponse {
    update_mcp_tool_status(state, headers, server_key, tool_key, "disabled").await
}

async fn update_mcp_tool_status(
    state: Arc<AppState>,
    headers: HeaderMap,
    server_key: String,
    tool_key: String,
    status: &str,
) -> axum::response::Response {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::set_mcp_tool_status(&state.pool, &tenant_id, &server_key, &tool_key, status).await {
        Ok(true) => {
            let audit_record = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id,
                event_type: "mcp_tool_status_changed".to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: Some(format!("mcp:{}", server_key)),
                action: Some(tool_key.clone()),
                resource: Some(server_key.clone()),
                event_json: serde_json::to_string(&json!({
                    "server_key": server_key,
                    "tool_key": tool_key,
                    "status": status,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                created_at: Utc::now(),
            };
            let _ = db::insert_audit_event(&state.pool, &audit_record).await;

            (
                StatusCode::OK,
                Json(McpToolStatusResponse {
                    server_key,
                    tool_key,
                    status: status.to_string(),
                }),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "MCP tool not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update MCP tool status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Authorize Action Handler
pub async fn authorize_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<AuthorizeRequest>,
) -> impl IntoResponse {
    // Resolve agent from Bearer agent_token
    let auth_header = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => &h["Bearer ".len()..],
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing agent token"})),
            )
                .into_response()
        }
    };

    let runtime_tenant_id = get_runtime_tenant_from_headers(&headers);
    let agent = match db::get_agent_by_token(&state.pool, &runtime_tenant_id, auth_header).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or quarantined agent token"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let tenant_id = agent.tenant_id.clone();
    let agent_id = agent.id.clone();

    // Map risk levels based on DB registered action, falling back to policy engine defaults.
    let mut risk_score = 10;
    let mut risk_level = "low".to_string();
    let mut action_approval_required = false;
    let mut action_default_decision = "policy".to_string();

    match db::get_skill_action(
        &state.pool,
        &tenant_id,
        &payload.tool_call.tool,
        &payload.tool_call.action,
    )
    .await
    {
        Ok(Some((risk, _, approval_required, default_decision))) => {
            risk_level = risk;
            risk_score = risk_score_for_level(&risk_level);
            action_approval_required = approval_required;
            action_default_decision = default_decision;
        }
        Ok(None) => {}
        Err(e) => {
            error!("Failed to look up registered action: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    }

    let mcp_server_key = mcp_server_key_from_tool(&payload.tool_call.tool).map(str::to_string);
    let is_mcp_call = mcp_server_key.is_some();

    if let Some(server_key) = mcp_server_key.as_deref() {
        match db::get_mcp_tool_by_key(
            &state.pool,
            &tenant_id,
            server_key,
            &payload.tool_call.action,
        )
        .await
        {
            Ok(Some(tool)) => {
                risk_level = tool.risk.clone();
                risk_score = risk_score_for_level(&risk_level);
                action_approval_required = action_approval_required || tool.approval_required;

                if tool.status != "approved" {
                    let decision_id = Uuid::new_v4();
                    let reason = format!(
                        "MCP tool '{}' on server '{}' is not approved (status: {}).",
                        payload.tool_call.action, server_key, tool.status
                    );
                    let matched_policies = vec!["mcp_tool_status".to_string()];

                    if let Err(e) = write_decision_and_audit(
                        &state.pool,
                        &tenant_id,
                        &agent_id,
                        &payload,
                        decision_id,
                        "deny",
                        risk_score,
                        &reason,
                        &matched_policies,
                        "mcp_tool_called",
                    )
                    .await
                    {
                        error!("Failed to write MCP denial decision: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "Database error"})),
                        )
                            .into_response();
                    }

                    return (
                        StatusCode::OK,
                        Json(AuthorizeResponse {
                            decision_id,
                            decision: "deny".to_string(),
                            risk_score,
                            risk_level,
                            reason,
                            matched_policies,
                            approval: None,
                        }),
                    )
                        .into_response();
                }
            }
            Ok(None) => {
                let decision_id = Uuid::new_v4();
                let reason = format!(
                    "Unknown MCP tool '{}' for server '{}' is denied by default.",
                    payload.tool_call.action, server_key
                );
                let matched_policies = vec!["mcp_unknown_tool".to_string()];
                risk_level = "critical".to_string();
                risk_score = 100;

                if let Err(e) = write_decision_and_audit(
                    &state.pool,
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    "deny",
                    risk_score,
                    &reason,
                    &matched_policies,
                    "mcp_tool_called",
                )
                .await
                {
                    error!("Failed to write unknown MCP denial decision: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                return (
                    StatusCode::OK,
                    Json(AuthorizeResponse {
                        decision_id,
                        decision: "deny".to_string(),
                        risk_score,
                        risk_level,
                        reason,
                        matched_policies,
                        approval: None,
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Failed to look up MCP tool: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        }
    }

    // Call policy engine to evaluate Cedar rules
    let policy_decision = match state.policy_engine.authorize(&payload) {
        Ok(d) => d,
        Err(e) => {
            error!("Policy engine error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Policy engine failure: {}", e)})),
            )
                .into_response();
        }
    };

    let decision_id = Uuid::new_v4();
    let mut decision_str = policy_decision.decision.clone();
    let mut reason = policy_decision.reason.clone();
    let mut matched_policies = policy_decision.matched_policies.clone();

    if decision_str == "allow" {
        if action_default_decision == "deny" {
            decision_str = "deny".to_string();
            reason = "Registered action default decision is deny.".to_string();
            matched_policies.push("registered_action_default_deny".to_string());
        } else if action_default_decision == "require_approval" || action_approval_required {
            decision_str = "require_approval".to_string();
            reason = "Registered action requires approval.".to_string();
            matched_policies.push("registered_action_approval_required".to_string());
        }
    }

    // Enforce secure defaults (fail-closed)
    // If decision returns allow but action risk is critical, enforce require_approval by default if not set otherwise.
    if decision_str == "allow" && risk_level == "critical" {
        decision_str = "require_approval".to_string();
        reason = "Critical-risk action requires approval by default.".to_string();
        matched_policies.push("critical_risk_requires_approval".to_string());
    }

    let audit_event_type = if is_mcp_call {
        "mcp_tool_called"
    } else {
        "tool_call_intercepted"
    };

    if let Err(e) = write_decision_and_audit(
        &state.pool,
        &tenant_id,
        &agent_id,
        &payload,
        decision_id,
        &decision_str,
        risk_score,
        &reason,
        &matched_policies,
        audit_event_type,
    )
    .await
    {
        error!("Failed to write decision: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
            .into_response();
    }

    let mut approval_info = None;

    if decision_str == "require_approval" {
        let approval_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::minutes(30);
        let original_call_hash = hash_tool_call(&payload.tool_call);

        let approval_record = ApprovalRecord {
            id: approval_id.to_string(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id.to_string(),
            status: "created".to_string(),
            approver_group: policy_decision.approver_group.clone(),
            approver_user_id: None,
            reason: None,
            original_skill_call: serde_json::to_string(&payload.tool_call).unwrap_or_default(),
            original_call_hash: original_call_hash.clone(),
            edited_skill_call: None,
            expires_at: Some(expires_at),
            decided_at: None,
            created_at: Utc::now(),
        };

        if let Err(e) = db::insert_approval(&state.pool, &approval_record).await {
            error!("Failed to create approval request: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create approval request"})),
            )
                .into_response();
        }

        // Write audit event for approval creation
        let audit_app_record = AuditEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            event_type: "approval_created".to_string(),
            agent_id: Some(agent_id.clone()),
            user_id: payload.user.as_ref().map(|u| u.id.clone()),
            run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
            span_id: None,
            skill: Some(payload.tool_call.tool.clone()),
            action: Some(payload.tool_call.action.clone()),
            resource: payload.tool_call.resource.clone(),
            event_json: serde_json::to_string(&approval_record).unwrap_or_default(),
            input_hash: Some(original_call_hash.clone()),
            output_hash: None,
            created_at: Utc::now(),
        };
        let _ = db::insert_audit_event(&state.pool, &audit_app_record).await;

        approval_info = Some(ApprovalResponseInfo {
            approval_id,
            status: "created".to_string(),
            approver_group: policy_decision.approver_group,
            expires_at,
            action_hash: original_call_hash,
        });
    }

    (
        StatusCode::OK,
        Json(AuthorizeResponse {
            decision_id,
            decision: decision_str,
            risk_score,
            risk_level,
            reason,
            matched_policies,
            approval: approval_info,
        }),
    )
        .into_response()
}

// Get Approval Status Handler
pub async fn get_approval(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(approval_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string()).await {
        Ok(Some(app)) => {
            let edited_call: Option<AuthorizeToolCall> = app
                .edited_skill_call
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());
            // A still-pending approval past its window is dead: report EXPIRED so
            // any client (even a forked SDK) fails closed instead of waiting.
            let effective_status = if app.status == "created" && approval_is_expired(&app) {
                "EXPIRED".to_string()
            } else {
                app.status.clone()
            };
            (
                StatusCode::OK,
                Json(json!({
                    "approval_id": app.id,
                    "status": effective_status,
                    "approver_group": app.approver_group,
                    "approver_user_id": app.approver_user_id,
                    "reason": app.reason,
                    "action_hash": app.original_call_hash,
                    "edited_tool_call": edited_call,
                    "expires_at": app.expires_at,
                    "decided_at": app.decided_at,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Approval request not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Approve Handler
pub async fn approve_approval(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(approval_id): Path<Uuid>,
    Json(payload): Json<ApproveRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Load the approval first so we can fail closed on stale or already-decided
    // requests instead of blindly transitioning to APPROVED.
    let approval =
        match db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string()).await {
            Ok(Some(app)) => app,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Approval request not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Database lookup error: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        };

    // Only a pending approval may be approved (no re-deciding an APPROVED/REJECTED/EDITED one).
    if approval.status != "created" {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Approval already decided",
                "status": approval.status,
                "approval_id": approval_id,
            })),
        )
            .into_response();
    }

    // Fail closed if the approval window has already passed.
    if approval_is_expired(&approval) {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Approval has expired",
                "approval_id": approval_id,
            })),
        )
            .into_response();
    }

    // Update approval status to APPROVED
    if let Err(e) = db::update_approval_status(
        &state.pool,
        &tenant_id,
        &approval_id.to_string(),
        "APPROVED",
        &payload.approver_user_id,
        payload.reason.as_deref(),
        None,
    )
    .await
    {
        error!("Failed to approve request: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to approve request"})),
        )
            .into_response();
    }

    // Write audit event
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        event_type: "approval_decided".to_string(),
        agent_id: None,
        user_id: Some(payload.approver_user_id),
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&json!({
            "approval_id": approval_id,
            "status": "APPROVED",
            "reason": payload.reason
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Reject Handler
pub async fn reject_approval(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(approval_id): Path<Uuid>,
    Json(payload): Json<ApproveRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Update approval status to REJECTED
    if let Err(e) = db::update_approval_status(
        &state.pool,
        &tenant_id,
        &approval_id.to_string(),
        "REJECTED",
        &payload.approver_user_id,
        payload.reason.as_deref(),
        None,
    )
    .await
    {
        error!("Failed to reject request: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to reject request"})),
        )
            .into_response();
    }

    // Write audit event
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        event_type: "approval_decided".to_string(),
        agent_id: None,
        user_id: Some(payload.approver_user_id),
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&json!({
            "approval_id": approval_id,
            "status": "REJECTED",
            "reason": payload.reason
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Edit parameters handler
pub async fn edit_approval(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(approval_id): Path<Uuid>,
    Json(payload): Json<EditApprovalRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let edited_call_str = serde_json::to_string(&payload.edited_tool_call).unwrap_or_default();

    // Update approval status to EDITED
    if let Err(e) = db::update_approval_status(
        &state.pool,
        &tenant_id,
        &approval_id.to_string(),
        "EDITED",
        &payload.approver_user_id,
        payload.reason.as_deref(),
        Some(&edited_call_str),
    )
    .await
    {
        error!("Failed to edit approval: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to edit request"})),
        )
            .into_response();
    }

    // Write audit event
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        event_type: "approval_decided".to_string(),
        agent_id: None,
        user_id: Some(payload.approver_user_id),
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&json!({
            "approval_id": approval_id,
            "status": "EDITED",
            "reason": payload.reason,
            "edited_tool_call": payload.edited_tool_call
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Get Investigation Run Timeline
pub async fn get_timeline(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::get_audit_events_by_run(&state.pool, &tenant_id, &run_id).await {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Get All Audit Events Logs
pub async fn get_audit_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::get_all_audit_events(&state.pool, &tenant_id).await {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn setup_state(test_name: &str) -> (Arc<AppState>, String, String) {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/routes_{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();
        let tenant_id = "tenant_routes".to_string();
        db::register_tenant(&pool, &tenant_id, "Routes Tenant", "developer")
            .await
            .unwrap();

        let agent_id = Uuid::new_v4().to_string();
        let agent_token = format!("agent_tok_{}", Uuid::new_v4().simple());
        let agent = AgentRecord {
            id: agent_id,
            tenant_id: tenant_id.clone(),
            agent_key: "routes-agent".to_string(),
            agent_token: agent_token.clone(),
            name: "Routes Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&pool, &agent).await.unwrap();

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let state = Arc::new(AppState {
            pool,
            policy_engine,
        });

        (state, tenant_id, agent_token)
    }

    fn agent_headers(agent_token: &str, tenant_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", agent_token).parse().unwrap(),
        );
        headers.insert("X-Aegis-Tenant-ID", tenant_id.parse().unwrap());
        headers
    }

    fn mcp_authorize_request(tool: &str, action: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: tool.to_string(),
                action: action.to_string(),
                resource: None,
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: Some(AuthorizeTraceContext {
                run_id: "run_routes".to_string(),
                trace_id: "trace_routes".to_string(),
            }),
        }
    }

    async fn call_authorize(
        state: Arc<AppState>,
        tenant_id: &str,
        agent_token: &str,
        request: AuthorizeRequest,
    ) -> AuthorizeResponse {
        let response = authorize_action(
            State(state),
            agent_headers(agent_token, tenant_id),
            Json(request),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn canonical_action_matches_shared_corpus() {
        // Locks the gateway side of the cross-language canonicalization contract to
        // the same corpus the Python SDK test pins. If both sides match the corpus
        // string, their SHA-256 action hashes are equal by construction, which is
        // what makes the fail-closed approval guarantee sound across languages.
        let corpus_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/canonical_action_vectors.json"
        );
        let raw = std::fs::read_to_string(corpus_path)
            .expect("shared canonical corpus must exist at tests/canonical_action_vectors.json");
        let corpus: Value = serde_json::from_str(&raw).expect("corpus must be valid JSON");

        assert_eq!(
            corpus["canon_version"].as_str(),
            Some(CANON_VERSION),
            "corpus canon_version must match gateway CANON_VERSION"
        );

        let vectors = corpus["vectors"].as_array().expect("vectors array");
        for vector in vectors {
            let name = vector["name"].as_str().unwrap_or("<unnamed>");
            let tool_call: AuthorizeToolCall =
                serde_json::from_value(vector["tool_call"].clone())
                    .unwrap_or_else(|e| panic!("vector {name}: tool_call must deserialize: {e}"));

            let produced = canonical_action_string(&tool_call);
            let expected = vector["canonical"].as_str().unwrap();
            assert_eq!(produced, expected, "vector {name}: canonical string mismatch");

            // Hash must equal SHA-256 of the corpus canonical string.
            let expected_hash = sha256_hex(expected.as_bytes());
            assert_eq!(
                hash_tool_call(&tool_call),
                expected_hash,
                "vector {name}: action_hash mismatch"
            );
        }
    }

    fn make_test_approval(
        expires_at: Option<chrono::DateTime<Utc>>,
        status: &str,
    ) -> ApprovalRecord {
        ApprovalRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: "t".to_string(),
            decision_id: Uuid::new_v4().to_string(),
            status: status.to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: "x".to_string(),
            edited_skill_call: None,
            expires_at,
            decided_at: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn approval_is_expired_detects_past_window() {
        assert!(approval_is_expired(&make_test_approval(
            Some(Utc::now() - Duration::minutes(1)),
            "created"
        )));
        assert!(!approval_is_expired(&make_test_approval(
            Some(Utc::now() + Duration::minutes(30)),
            "created"
        )));
        // No expiry set -> never expired.
        assert!(!approval_is_expired(&make_test_approval(None, "created")));
    }

    #[test]
    fn receipt_chain_matches_shared_corpus() {
        // Proves the gateway reproduces the Python-generated receipt_hash values
        // byte-for-byte: receipt_hash = SHA-256(canonical(body)) where body is
        // every field except receipt_hash (incl. prev_receipt_hash). This is the
        // cross-language guarantee that lets the Python verifier / aegis-verify-receipts
        // validate gateway-emitted receipts. See docs/action-receipt-spec.md.
        let corpus_path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/receipt_chain_vectors.json");
        let raw = std::fs::read_to_string(corpus_path)
            .expect("shared receipt corpus must exist at tests/receipt_chain_vectors.json");
        let corpus: Value = serde_json::from_str(&raw).expect("corpus must be valid JSON");

        assert_eq!(corpus["canon_version"].as_str(), Some(CANON_VERSION));

        let receipts = corpus["receipts"].as_array().expect("receipts array");
        let mut prev = String::new();
        for receipt in receipts {
            let obj = receipt.as_object().expect("receipt object");
            let stored = obj
                .get("receipt_hash")
                .and_then(|v| v.as_str())
                .expect("receipt_hash present");

            // body = all fields except receipt_hash (prev_receipt_hash stays in).
            let mut body = obj.clone();
            body.remove("receipt_hash");
            let recomputed = sha256_hex(canonical_value_string(&Value::Object(body)).as_bytes());
            assert_eq!(recomputed, stored, "receipt hash mismatch vs corpus");

            // Chain linkage: each receipt references the previous receipt's hash.
            let prev_in_receipt = obj
                .get("prev_receipt_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert_eq!(prev_in_receipt, prev, "broken chain link");
            prev = stored.to_string();
        }
    }

    #[tokio::test]
    async fn expired_approval_is_reported_and_cannot_be_approved() {
        let (state, tenant_id, agent_token) = setup_state("approve_expired").await;

        // Create a real require_approval via authorize (merge to main).
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/7".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        // Force the approval past its window.
        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        // get_approval reports EXPIRED for the still-pending, past-window approval.
        let get_resp = get_approval(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Path(approval_id),
        )
        .await
        .into_response();
        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "EXPIRED");

        // approve_approval refuses to grant an expired approval.
        let approve_resp = approve_approval(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve_resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn authorize_denies_unknown_mcp_tools_by_default() {
        let (state, tenant_id, agent_token) = setup_state("unknown_mcp_tool").await;
        let response = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "unknown_tool"),
        )
        .await;

        assert_eq!(response.decision, "deny");
        assert_eq!(response.risk_level, "critical");
        assert_eq!(response.risk_score, 100);
        assert!(response
            .matched_policies
            .contains(&"mcp_unknown_tool".to_string()));
    }

    #[tokio::test]
    async fn approval_flow_binds_original_action_hash() {
        let (state, tenant_id, agent_token) = setup_state("approval_action_hash").await;
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/42".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");

        let approval = response.approval.expect("approval info should be present");
        assert_eq!(approval.action_hash.len(), 64);
        assert!(approval
            .action_hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit()));

        let status_response = get_approval(
            State(state),
            agent_headers("tenant_routes", &tenant_id),
            Path(approval.approval_id),
        )
        .await
        .into_response();
        assert_eq!(status_response.status(), StatusCode::OK);

        let body = to_bytes(status_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status_json["action_hash"], approval.action_hash);
    }

    #[tokio::test]
    async fn authorize_requires_mcp_tool_approval() {
        let (state, tenant_id, agent_token) = setup_state("mcp_tool_approval").await;
        let server_id = db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();
        let tool = McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create issue".to_string(),
            description: None,
            input_schema: None,
            risk: "medium".to_string(),
            mutates_state: false,
            approval_required: false,
        };
        db::upsert_mcp_tool(&state.pool, &tenant_id, &server_id, &tool)
            .await
            .unwrap();

        let pending_response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(pending_response.decision, "deny");
        assert!(pending_response
            .matched_policies
            .contains(&"mcp_tool_status".to_string()));

        let updated = db::set_mcp_tool_status(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "create_issue",
            "approved",
        )
        .await
        .unwrap();
        assert!(updated);

        let approved_response = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(approved_response.decision, "allow");
        assert_eq!(approved_response.risk_level, "medium");
        assert_eq!(approved_response.risk_score, 40);
    }
}
