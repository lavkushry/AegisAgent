use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};
use tracing::{info, error};

use crate::models::*;
use crate::db;
use crate::policy::PolicyEngine;

// Shared app state containing DB pool and Cedar policy engine
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub policy_engine: PolicyEngine,
}

// Extractor helper to get tenant_id from Bearer token
fn get_tenant_from_headers(headers: &HeaderMap) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, Json(json!({"error": "Missing Authorization header"}))))?;

    if !auth_header.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid Authorization format"}))));
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
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response();
    }
    if let Ok(None) = db::get_tenant_by_id(&state.pool, &tenant_id).await {
        if let Err(e) = db::register_tenant(&state.pool, &tenant_id, "Default Org", "developer").await {
            error!("Failed to auto-register tenant: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to initialize tenant"}))).into_response();
        }
    }

    // Check if agent already exists
    match db::get_agent_by_key(&state.pool, &tenant_id, &payload.agent_key).await {
        Ok(Some(agent)) => {
            info!("Agent already registered: {}", payload.agent_key);
            return (StatusCode::OK, Json(RegisterAgentResponse {
                id: Uuid::parse_str(&agent.id).unwrap(),
                agent_key: agent.agent_key,
                agent_token: agent.agent_token,
            })).into_response();
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response();
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
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database insert failed"}))).into_response();
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

    (StatusCode::CREATED, Json(RegisterAgentResponse {
        id: agent_id,
        agent_key: agent_record.agent_key,
        agent_token,
    })).into_response()
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
    ).await {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register skill: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to register skill"}))).into_response();
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
        ).await {
            error!("Failed to register skill action: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to register skill action"}))).into_response();
        }
    }

    (StatusCode::OK, Json(json!({"status": "success", "skill_id": skill_id}))).into_response()
}

// Register MCP Server Handler (Stub for MVP)
pub async fn register_mcp_server(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterMcpServerRequest>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let server_id = Uuid::new_v4().to_string();
    let query = "INSERT INTO mcp_servers (id, tenant_id, server_key, name, owner_team, transport, source, trust_level, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    if let Err(e) = sqlx::query(query)
        .bind(&server_id)
        .bind(&tenant_id)
        .bind(&payload.server_key)
        .bind(&payload.name)
        .bind(&payload.owner_team)
        .bind(&payload.transport)
        .bind(&payload.source)
        .bind(&payload.trust_level)
        .bind("active")
        .execute(&state.pool)
        .await
    {
        error!("Failed to register MCP server: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response();
    }

    (StatusCode::OK, Json(json!({"status": "success", "server_id": server_id}))).into_response()
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
        _ => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Missing agent token"}))).into_response(),
    };

    let agent = match db::get_agent_by_token(&state.pool, auth_header).await {
        Ok(Some(a)) => a,
        Ok(None) => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid or quarantined agent token"}))).into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response();
        }
    };

    let tenant_id = agent.tenant_id.clone();
    let agent_id = agent.id.clone();

    // Map risk levels based on DB registered action, falling back to policy engine defaults
    let mut risk_score = 10; // default low
    let mut risk_level = "low".to_string();

    if let Ok(Some((risk, _, _, _))) = db::get_skill_action(&state.pool, &tenant_id, &payload.tool_call.tool, &payload.tool_call.action).await {
        risk_level = risk.clone();
        risk_score = match risk.as_str() {
            "low" => 10,
            "medium" => 40,
            "high" => 75,
            "critical" => 95,
            _ => 10,
        };
    }

    // Call policy engine to evaluate Cedar rules
    let policy_decision = match state.policy_engine.authorize(&payload) {
        Ok(d) => d,
        Err(e) => {
            error!("Policy engine error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("Policy engine failure: {}", e)}))).into_response();
        }
    };

    let decision_id = Uuid::new_v4();
    let mut decision_str = policy_decision.decision.clone();

    // Enforce secure defaults (fail-closed)
    // If decision returns allow but action risk is critical, enforce require_approval by default if not set otherwise
    if decision_str == "allow" && risk_level == "critical" {
        decision_str = "require_approval".to_string();
    }

    // Write decision to database
    let decision_record = DecisionRecord {
        id: decision_id.to_string(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        user_id: payload.user.as_ref().map(|u| u.id.clone()),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        skill: payload.tool_call.tool.clone(),
        action: payload.tool_call.action.clone(),
        resource: payload.tool_call.resource.clone(),
        input_json: serde_json::to_string(&payload.tool_call.parameters).unwrap_or_default(),
        decision: decision_str.clone(),
        risk_score: Some(risk_score),
        reason: Some(policy_decision.reason.clone()),
        matched_policy_ids: Some(policy_decision.matched_policies.join(",")),
        created_at: Utc::now(),
    };

    if let Err(e) = db::insert_decision(&state.pool, &decision_record).await {
        error!("Failed to write decision: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response();
    }

    // Write audit event for interception
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_type: "tool_call_intercepted".to_string(),
        agent_id: Some(agent_id.clone()),
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
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    let mut approval_info = None;

    if decision_str == "require_approval" {
        let approval_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::minutes(30);

        let approval_record = ApprovalRecord {
            id: approval_id.to_string(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id.to_string(),
            status: "created".to_string(),
            approver_group: policy_decision.approver_group.clone(),
            approver_user_id: None,
            reason: None,
            original_skill_call: serde_json::to_string(&payload.tool_call).unwrap_or_default(),
            edited_skill_call: None,
            expires_at: Some(expires_at),
            decided_at: None,
            created_at: Utc::now(),
        };

        if let Err(e) = db::insert_approval(&state.pool, &approval_record).await {
            error!("Failed to create approval request: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to create approval request"}))).into_response();
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
            input_hash: None,
            output_hash: None,
            created_at: Utc::now(),
        };
        let _ = db::insert_audit_event(&state.pool, &audit_app_record).await;

        approval_info = Some(ApprovalResponseInfo {
            approval_id,
            status: "created".to_string(),
            approver_group: policy_decision.approver_group,
            expires_at,
        });
    }

    (StatusCode::OK, Json(AuthorizeResponse {
        decision_id,
        decision: decision_str,
        risk_score,
        risk_level,
        reason: policy_decision.reason,
        matched_policies: policy_decision.matched_policies,
        approval: approval_info,
    })).into_response()
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
            let edited_call: Option<AuthorizeToolCall> = app.edited_skill_call
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());
            (StatusCode::OK, Json(json!({
                "approval_id": app.id,
                "status": app.status,
                "approver_group": app.approver_group,
                "approver_user_id": app.approver_user_id,
                "reason": app.reason,
                "edited_tool_call": edited_call,
                "expires_at": app.expires_at,
                "decided_at": app.decided_at,
            }))).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "Approval request not found"}))).into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response()
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

    // Update approval status to APPROVED
    if let Err(e) = db::update_approval_status(
        &state.pool,
        &tenant_id,
        &approval_id.to_string(),
        "APPROVED",
        &payload.approver_user_id,
        payload.reason.as_deref(),
        None,
    ).await {
        error!("Failed to approve request: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to approve request"}))).into_response();
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
        })).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (StatusCode::OK, Json(json!({"status": "success", "approval_id": approval_id}))).into_response()
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
    ).await {
        error!("Failed to reject request: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to reject request"}))).into_response();
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
        })).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (StatusCode::OK, Json(json!({"status": "success", "approval_id": approval_id}))).into_response()
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
    ).await {
        error!("Failed to edit approval: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to edit request"}))).into_response();
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
        })).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit_record).await;

    (StatusCode::OK, Json(json!({"status": "success", "approval_id": approval_id}))).into_response()
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
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response()
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
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Database error"}))).into_response()
        }
    }
}
