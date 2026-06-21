#![allow(unused_imports)]
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;

use super::*;

pub async fn register_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    // Check if agent already exists
    match db::get_agent_by_key(&state.pool, &tenant_id, &payload.agent_key).await {
        Ok(Some(agent)) => {
            info!(
                "Agent already registered: {} — rotating token",
                payload.agent_key
            );
            let id = match Uuid::parse_str(&agent.id) {
                Ok(id) => id,
                Err(e) => {
                    error!("Stored agent id is not a valid UUID: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Database error"})),
                    )
                        .into_response();
                }
            };

            // Rotate the agent's token so the caller receives a usable
            // plaintext credential instead of "[REDACTED]" — the previous
            // token's hash cannot be reversed (see #1366).
            let new_token = format!("agent_tok_{}", Uuid::new_v4().simple());
            if let Err(e) =
                db::rotate_agent_token(&state.pool, &tenant_id, &agent.id, &new_token).await
            {
                error!("Failed to rotate agent token: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }

            return (
                StatusCode::OK,
                Json(RegisterAgentResponse {
                    id,
                    agent_key: agent.agent_key,
                    agent_token: new_token,
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
    let hashed_token = db::hash_token(&agent_token);

    let agent_id = Uuid::new_v4();

    let agent_record = AgentRecord {
        id: agent_id.to_string(),
        tenant_id: tenant_id.clone(),
        agent_key: payload.agent_key,
        agent_token: hashed_token,
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
        last_seen_at: None,
        frozen_reason: None,
        force_approval: false,
        quarantined_at: None,
        signing_key: payload.signing_key,
        allowed_environments: payload.allowed_environments.as_ref().and_then(|envs| {
            if envs.is_empty() {
                None
            } else {
                serde_json::to_string(envs).ok()
            }
        }),
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
        decision_id: None,
        approval_id: None,
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

pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    let status_filter = super::parse_filter(raw_query.as_deref(), "status");

    match db::list_agents(
        &state.pool,
        &tenant_id,
        limit,
        offset,
        status_filter.as_deref(),
    )
    .await
    {
        Ok(agents) => (StatusCode::OK, Json(agents)).into_response(),
        Err(e) => {
            error!("Failed to list agents: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// #1290: `GET /v1/agents/risk-scoreboard` — rolling 24h average
/// `composite_risk_score` per agent, ranked highest-first, with a trend vs.
/// the prior 24h window. `?format=csv` returns `text/csv` for the dashboard's
/// CSV export button; default is JSON.
pub async fn get_agent_risk_scoreboard(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let board = match db::get_agent_risk_scoreboard(&state.pool, &tenant_id).await {
        Ok(board) => board,
        Err(e) => {
            error!("Failed to get agent risk scoreboard: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if super::parse_filter(raw_query.as_deref(), "format").as_deref() == Some("csv") {
        let mut csv =
            String::from("agent_id,agent_key,current_avg_risk_score,decision_count_24h,trend\n");
        for entry in &board {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                entry.agent_id,
                entry.agent_key,
                entry.current_avg_risk_score,
                entry.decision_count_24h,
                entry.trend
            ));
        }
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/csv")],
            csv,
        )
            .into_response();
    }

    (StatusCode::OK, Json(board)).into_response()
}

pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::get_agent_by_id(&state.pool, &tenant_id, &id).await {
        Ok(Some(agent)) => (StatusCode::OK, Json(agent)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to get agent detail: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn patch_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(payload): Json<PatchAgentRequest>,
) -> impl IntoResponse {
    let mut agent = match db::get_agent_by_id(&state.pool, &tenant_id, &id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to lookup agent for patch: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if let Some(name) = payload.name {
        agent.name = name;
    }
    if let Some(owner_team) = payload.owner_team {
        agent.owner_team = Some(owner_team);
    }
    if let Some(owner_email) = payload.owner_email {
        agent.owner_email = Some(owner_email);
    }
    if let Some(environment) = payload.environment {
        agent.environment = environment;
    }
    if let Some(framework) = payload.framework {
        agent.framework = Some(framework);
    }
    if let Some(model_provider) = payload.model_provider {
        agent.model_provider = Some(model_provider);
    }
    if let Some(model_name) = payload.model_name {
        agent.model_name = Some(model_name);
    }
    if let Some(purpose) = payload.purpose {
        agent.purpose = Some(purpose);
    }
    if let Some(risk_tier) = payload.risk_tier {
        agent.risk_tier = risk_tier;
    }
    if let Some(status) = payload.status {
        agent.status = status;
    }

    match db::update_agent(&state.pool, &agent).await {
        Ok(_) => (StatusCode::OK, Json(agent)).into_response(),
        Err(e) => {
            error!("Failed to update agent: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

pub async fn delete_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match db::set_agent_status(&state.pool, &tenant_id, &id, "deleted").await {
        Ok(true) => {
            write_admin_action_audit_event(
                &state.pool,
                &tenant_id,
                "agent_deleted",
                Some(&id),
                None,
                json!({"agent_id": id}),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({"message": "Agent successfully deleted"})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete agent: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// Register Static Tool Handler
pub async fn register_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<RegisterToolRequest>,
) -> impl IntoResponse {
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
        // #899: a (re-)registration may tighten this action's settings, so drop any
        // cached entry — the next authorize re-reads the fresh row (fail-closed).
        state.skill_cache.invalidate(&SkillActionCache::cache_key(
            &tenant_id,
            &payload.skill_key,
            &action.action_key,
        ));
    }

    (
        StatusCode::OK,
        Json(json!({"status": "success", "skill_id": skill_id})),
    )
        .into_response()
}

/// Freeze an agent: all subsequent /v1/authorize calls for this agent will be
/// denied immediately without Cedar evaluation. Reversible via /unfreeze.
pub async fn freeze_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
    body: Option<Json<FreezeAgentRequest>>,
) -> impl IntoResponse {
    let reason = body.and_then(|Json(b)| b.reason);
    let resp =
        set_agent_operational_status(state.clone(), tenant_id.clone(), agent_id.clone(), "frozen")
            .await;
    if resp.status() == StatusCode::OK {
        let _ = db::set_agent_frozen_reason(&state.pool, &tenant_id, &agent_id, reason.as_deref())
            .await;
    }
    resp
}

/// Restore a frozen agent to active status.
pub async fn unfreeze_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, tenant_id, agent_id, "active").await
}

/// Permanently revoke an agent — not reversible via API.
pub async fn revoke_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, tenant_id, agent_id, "revoked").await
}

/// Restore a quarantined agent to active status (#1386).
/// Sets `status = 'active'`, which clears `quarantined_at`; subsequent
/// `/v1/authorize` calls resolve the agent normally again.
pub async fn restore_agent(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, tenant_id, agent_id, "active").await
}

/// Optional request body for `POST /v1/agents/:id/rotate-token` (#1295).
#[derive(Debug, serde::Deserialize, Default)]
pub struct RotateTokenRequest {
    pub reason: Option<String>,
}

/// Generate a fresh plaintext token, hash and store it, and write the
/// `agent_token_rotated` audit event. Shared by the operator-triggered
/// manual rotation endpoint and the leak-report auto-rotation path (#1295).
/// Returns the new plaintext token — the only time it is ever returned in
/// cleartext (matching `register_agent`'s re-registration rotation, #1366).
pub(crate) async fn rotate_and_audit_agent_token(
    state: &Arc<AppState>,
    tenant_id: &str,
    agent_id: &str,
    reason: &str,
) -> Result<String, sqlx::Error> {
    let new_token = format!("agent_tok_{}", Uuid::new_v4().simple());
    db::rotate_agent_token(&state.pool, tenant_id, agent_id, &new_token).await?;

    let audit = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: "agent_token_rotated".to_string(),
        agent_id: Some(agent_id.to_string()),
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: None,
        event_json: serde_json::to_string(&json!({ "reason": reason })).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        decision_id: None,
        approval_id: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit).await;

    Ok(new_token)
}

/// Operator-triggered token rotation: the old token's hash is immediately
/// unusable (the next `/v1/authorize` call with it fails `get_agent_by_token`),
/// and the new plaintext token is returned exactly once. Always allowed,
/// regardless of the tenant's `auto_rotate_token_on_leak_enabled` setting —
/// that flag only gates the *automatic* path below (#1295).
pub async fn rotate_agent_token(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
    body: Option<Json<RotateTokenRequest>>,
) -> impl IntoResponse {
    match db::get_agent_by_id(&state.pool, &tenant_id, &agent_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to look up agent {}: {:?}", agent_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    }

    let reason = body
        .and_then(|Json(b)| b.reason)
        .unwrap_or_else(|| "manual_rotation".to_string());

    match rotate_and_audit_agent_token(&state, &tenant_id, &agent_id, &reason).await {
        Ok(new_token) => (
            StatusCode::OK,
            Json(json!({ "agent_id": agent_id, "agent_token": new_token })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to rotate token for agent {}: {:?}", agent_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// Request body for `POST /v1/agents/:id/report-leaked-token` (#1295).
#[derive(Debug, serde::Deserialize)]
pub struct ReportLeakedTokenRequest {
    /// Free-text description of how the leak was detected (e.g. "found in
    /// public GitHub repo via secret-scanning partner alert").
    pub reason: String,
}

/// Report that an agent's token may have leaked. If the tenant has
/// `auto_rotate_token_on_leak_enabled` (the default), the token is rotated
/// immediately and the new plaintext token is returned in the response —
/// the caller (a leak-detection integration or operator) is responsible for
/// delivering it to the agent owner over its own secure channel; AegisAgent
/// never persists the plaintext or pushes it over a webhook itself, which
/// would just relocate the secret-handling risk (#1295). If disabled, no
/// rotation happens — the report is still recorded (audit + SOC event) so
/// operators have visibility, but the existing token remains valid.
pub async fn report_leaked_agent_token(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
    Json(payload): Json<ReportLeakedTokenRequest>,
) -> impl IntoResponse {
    match db::get_agent_by_id(&state.pool, &tenant_id, &agent_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to look up agent {}: {:?}", agent_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    }

    let auto_rotate_enabled = match db::get_tenant_by_id(&state.pool, &tenant_id).await {
        Ok(Some(tenant)) => tenant.auto_rotate_token_on_leak_enabled,
        Ok(None) => true,
        Err(e) => {
            error!("Failed to look up tenant {}: {:?}", tenant_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let new_token = if auto_rotate_enabled {
        let reason = format!("leak_detected: {}", payload.reason);
        match rotate_and_audit_agent_token(&state, &tenant_id, &agent_id, &reason).await {
            Ok(token) => Some(token),
            Err(e) => {
                error!(
                    "Failed to auto-rotate token for agent {}: {:?}",
                    agent_id, e
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        }
    } else {
        let audit = AuditEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            event_type: "agent_token_leak_detected_no_rotation".to_string(),
            agent_id: Some(agent_id.clone()),
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: None,
            action: None,
            resource: None,
            event_json: serde_json::to_string(&json!({ "reason": payload.reason }))
                .unwrap_or_default(),
            input_hash: None,
            output_hash: None,
            decision_id: None,
            approval_id: None,
            created_at: Utc::now(),
        };
        let _ = db::insert_audit_event(&state.pool, &audit).await;
        None
    };

    // SOC visibility either way (Law 3, out-of-band — never blocks this response).
    state.events.emit(AseEvent {
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        tenant_id: tenant_id.clone(),
        kind: "agent_token_leak_detected".to_string(),
        agent_id: agent_id.clone(),
        decision: "allow".to_string(),
        tool: String::new(),
        action: String::new(),
        resource: None,
        risk_score: 0,
        reason: payload.reason.clone(),
        run_id: None,
        trace_id: None,
        matched_policies: vec![],
        redacted_fields: vec![],
        schema_version: 1,
    });

    (
        StatusCode::OK,
        Json(json!({
            "agent_id": agent_id,
            "rotated": new_token.is_some(),
            "agent_token": new_token,
        })),
    )
        .into_response()
}

pub(crate) async fn set_agent_operational_status(
    state: Arc<AppState>,
    tenant_id: String,
    agent_id: String,
    status: &str,
) -> axum::response::Response {
    match db::set_agent_status(&state.pool, &tenant_id, &agent_id, status).await {
        Ok(true) => {
            let audit = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                event_type: format!("agent_{}", status),
                agent_id: Some(agent_id.clone()),
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: None,
                event_json: serde_json::to_string(&json!({
                    "agent_id": agent_id,
                    "new_status": status,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at: Utc::now(),
            };
            let _ = db::insert_audit_event(&state.pool, &audit).await;
            info!(agent_id = %agent_id, status = %status, "Agent status changed");
            (
                StatusCode::OK,
                Json(json!({ "agent_id": agent_id, "status": status })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Agent not found" })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update agent status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
                .into_response()
        }
    }
}

// ── Agent-to-tool permission bindings (#1390) ─────────────────────────────────

/// `POST /v1/agents/:id/permissions` — grant a tool permission to an agent.
///
/// Idempotent: granting the same tool twice is a no-op. Returns 200 on success
/// and 404 when the agent does not exist (or belongs to a different tenant).
pub async fn grant_agent_tool_permission(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
    Json(payload): Json<crate::models::GrantToolPermissionRequest>,
) -> impl IntoResponse {
    match db::get_agent_by_id(&state.pool, &tenant_id, &agent_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("DB error checking agent for permission grant: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        Ok(Some(_)) => {}
    }

    match db::grant_agent_tool_permission(&state.pool, &tenant_id, &agent_id, &payload.tool_key)
        .await
    {
        Ok(_permission) => (
            StatusCode::OK,
            Json(json!({
                "agent_id": agent_id,
                "tool_key": payload.tool_key,
                "granted": true
            })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to grant tool permission: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// `GET /v1/agents/:id/permissions` — list all tool permissions for an agent.
///
/// Returns an empty array when no permissions are set (agent is unrestricted).
/// 404 when the agent does not exist.
pub async fn list_agent_tool_permissions(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match db::get_agent_by_id(&state.pool, &tenant_id, &agent_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("DB error checking agent for permission list: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        Ok(Some(_)) => {}
    }

    match db::get_agent_tool_permissions(&state.pool, &tenant_id, &agent_id).await {
        Ok(perms) => (StatusCode::OK, Json(json!({ "permissions": perms }))).into_response(),
        Err(e) => {
            error!("Failed to list tool permissions: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// `DELETE /v1/agents/:id/permissions/:tool_key` — revoke a tool permission.
///
/// Returns 200 when deleted, 404 when no such binding exists (or agent not
/// found in this tenant).
pub async fn revoke_agent_tool_permission(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path((agent_id, tool_key)): Path<(String, String)>,
) -> impl IntoResponse {
    match db::revoke_agent_tool_permission(&state.pool, &tenant_id, &agent_id, &tool_key).await {
        Ok(true) => {
            write_admin_action_audit_event(
                &state.pool,
                &tenant_id,
                "agent_tool_permission_revoked",
                Some(&agent_id),
                Some(&tool_key),
                json!({"agent_id": agent_id, "tool_key": tool_key}),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({
                    "agent_id": agent_id,
                    "tool_key": tool_key,
                    "revoked": true
                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Permission not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to revoke tool permission: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::db;
    use crate::events;
    use crate::metrics::SecurityMetrics;
    use crate::models::*;
    use crate::policy::PolicyEngine;
    use crate::routes::test_helpers::*;
    use axum::body::{to_bytes, Bytes};
    use axum::extract::{FromRequestParts, Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;
    #[tokio::test]
    async fn test_list_agents_returns_tenant_scoped_and_paginated_agents() {
        let (state, tenant_id, _agent_token) = setup_state("list_agents_route").await;

        // Seed 3 agents for this tenant
        for idx in 1..=3 {
            let agent = AgentRecord {
                id: format!("agent_id_{}", idx),
                tenant_id: tenant_id.clone(),
                agent_key: format!("agent-key-{}", idx),
                agent_token: format!("agent-token-{}", idx),
                name: format!("Agent Name {}", idx),
                owner_team: Some("platform".to_string()),
                owner_email: None,
                environment: "production".to_string(),
                framework: None,
                model_provider: None,
                model_name: None,
                purpose: None,
                risk_tier: "high".to_string(),
                status: "active".to_string(),
                last_seen_at: None,
                frozen_reason: None,
                force_approval: false,
                quarantined_at: None,
                signing_key: None,
                allowed_environments: None,
                created_at: Utc::now() - Duration::hours(idx), // older first
                updated_at: Utc::now(),
            };
            db::insert_agent(&state.pool, &agent).await.unwrap();
        }

        // Seed an agent for another tenant to test isolation
        let other_tenant = "other_tenant_id".to_string();
        db::register_tenant(&state.pool, &other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();
        let other_agent = AgentRecord {
            id: "other_agent_id".to_string(),
            tenant_id: other_tenant.clone(),
            agent_key: "other-agent-key".to_string(),
            agent_token: "other-agent-token".to_string(),
            name: "Other Agent Name".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &other_agent).await.unwrap();

        // 1. Check all agents for tenant_id (should be 4 total including the default setup agent)
        let response = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        // 3 newly seeded agents + 1 setup agent = 4
        assert_eq!(arr.len(), 4);

        // 2. Check pagination (limit=2)
        let response_paginated = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("limit=2".to_string())),
        )
        .await
        .into_response();
        assert_eq!(response_paginated.status(), StatusCode::OK);
        let body_p = to_bytes(response_paginated.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_p: serde_json::Value = serde_json::from_slice(&body_p).unwrap();
        assert_eq!(json_p.as_array().unwrap().len(), 2);
    }

    /// #1145: `GET /v1/agents?status=...` field filtering. Also verifies the
    /// pre-#1145 default (no filter) still excludes soft-deleted agents.
    #[tokio::test]
    async fn list_agents_route_filters_by_status() {
        let (state, tenant_id, _agent_token) = setup_state("list_agents_status_filter").await;

        for (idx, status) in ["active", "active", "quarantined", "deleted"]
            .iter()
            .enumerate()
        {
            let agent = AgentRecord {
                id: format!("status_filter_agent_{}", idx),
                tenant_id: tenant_id.clone(),
                agent_key: format!("status-filter-agent-key-{}", idx),
                agent_token: format!("status-filter-agent-token-{}", idx),
                name: format!("Status Filter Agent {}", idx),
                owner_team: Some("platform".to_string()),
                owner_email: None,
                environment: "production".to_string(),
                framework: None,
                model_provider: None,
                model_name: None,
                purpose: None,
                risk_tier: "high".to_string(),
                status: status.to_string(),
                last_seen_at: None,
                frozen_reason: None,
                force_approval: false,
                quarantined_at: None,
                signing_key: None,
                allowed_environments: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            db::insert_agent(&state.pool, &agent).await.unwrap();
        }

        // ?status=active matches exactly the 2 active agents seeded above
        // (the default setup agent from `setup_state` is also "active", so 3).
        let response = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("status=active".to_string())),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!(arr.iter().all(|a| a["status"] == "active"));

        // ?status=quarantined matches exactly 1.
        let response_q = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("status=quarantined".to_string())),
        )
        .await
        .into_response();
        let body_q = to_bytes(response_q.into_body(), usize::MAX).await.unwrap();
        let json_q: serde_json::Value = serde_json::from_slice(&body_q).unwrap();
        assert_eq!(json_q.as_array().unwrap().len(), 1);

        // No filter: default behavior still hides the soft-deleted agent.
        let response_default = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        let body_default = to_bytes(response_default.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_default: serde_json::Value = serde_json::from_slice(&body_default).unwrap();
        let arr_default = json_default.as_array().unwrap();
        assert!(arr_default.iter().all(|a| a["status"] != "deleted"));

        // ?status=deleted explicitly surfaces the soft-deleted agent.
        let response_deleted = list_agents(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("status=deleted".to_string())),
        )
        .await
        .into_response();
        let body_deleted = to_bytes(response_deleted.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_deleted: serde_json::Value = serde_json::from_slice(&body_deleted).unwrap();
        assert_eq!(json_deleted.as_array().unwrap().len(), 1);
        assert_eq!(json_deleted.as_array().unwrap()[0]["status"], "deleted");
    }

    /// #1290: `GET /v1/agents/risk-scoreboard` returns the same data as
    /// `db::get_agent_risk_scoreboard`, and `?format=csv` returns a `text/csv`
    /// body with a header row. Also exercises the route actually being
    /// reachable — `/v1/agents/risk-scoreboard` and `/v1/agents/:id` share a
    /// path depth, so this catches any router registration regression.
    #[tokio::test]
    async fn test_agent_risk_scoreboard_route_json_and_csv() {
        let (state, tenant_id, _agent_token) = setup_state("risk_scoreboard_route").await;

        let response = get_agent_risk_scoreboard(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let board: Vec<AgentRiskScoreboardEntry> = serde_json::from_slice(&body).unwrap();
        // setup_state registers one default agent.
        assert_eq!(board.len(), 1);
        assert_eq!(board[0].decision_count_24h, 0);
        assert_eq!(board[0].trend, "stable");

        let csv_response = get_agent_risk_scoreboard(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("format=csv".to_string())),
        )
        .await
        .into_response();
        assert_eq!(csv_response.status(), StatusCode::OK);
        assert_eq!(
            csv_response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/csv"
        );
        let csv_body = to_bytes(csv_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let csv_text = String::from_utf8(csv_body.to_vec()).unwrap();
        assert!(csv_text
            .starts_with("agent_id,agent_key,current_avg_risk_score,decision_count_24h,trend\n"));
        assert_eq!(csv_text.lines().count(), 2, "header + 1 agent row");
    }

    #[tokio::test]
    async fn test_get_agent_detail_route() {
        let (state, tenant_id, _agent_token) = setup_state("get_agent_route").await;

        // Seed an agent
        let agent = AgentRecord {
            id: "get_agent_test_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "get-agent-key".to_string(),
            agent_token: "get-agent-token".to_string(),
            name: "Get Agent Name".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();

        // 1. Fetch existing agent (should return 200)
        let response = get_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("get_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let fetched: AgentRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched.id, "get_agent_test_id");
        assert_eq!(fetched.name, "Get Agent Name");

        // 2. Fetch non-existing agent (should return 404)
        let response_404 = get_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non_existent_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);

        // 3. Fetch cross-tenant agent (should return 404)
        let other_tenant = "other_tenant_id".to_string();
        let response_cross = get_agent(
            State(state.clone()),
            TenantId(other_tenant),
            Path("get_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_patch_agent_route() {
        let (state, tenant_id, _agent_token) = setup_state("patch_agent_route").await;

        // Seed an agent
        let agent = AgentRecord {
            id: "patch_agent_test_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "patch-agent-key".to_string(),
            agent_token: "patch-agent-token".to_string(),
            name: "Original Name".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();

        // 1. Patch name and environment
        let patch_request = PatchAgentRequest {
            name: Some("Updated Name".to_string()),
            owner_team: Some("new-team".to_string()),
            owner_email: None,
            environment: Some("staging".to_string()),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: None,
            status: Some("frozen".to_string()),
        };

        let response = patch_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("patch_agent_test_id".to_string()),
            Json(patch_request),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let updated: AgentRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated.name, "Updated Name");
        assert_eq!(updated.owner_team, Some("new-team".to_string()));
        assert_eq!(updated.environment, "staging");
        assert_eq!(updated.status, "frozen");

        // Verify it was actually updated in the database
        let db_agent = db::get_agent_by_id(&state.pool, &tenant_id, "patch_agent_test_id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(db_agent.name, "Updated Name");
        assert_eq!(db_agent.environment, "staging");
        assert_eq!(db_agent.status, "frozen");

        // 2. Patch non-existing agent (should return 404)
        let response_404 = patch_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non_existent_id".to_string()),
            Json(PatchAgentRequest {
                name: Some("New Name".to_string()),
                owner_team: None,
                owner_email: None,
                environment: None,
                framework: None,
                model_provider: None,
                model_name: None,
                purpose: None,
                risk_tier: None,
                status: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_agent_route() {
        let (state, tenant_id, _agent_token) = setup_state("delete_agent_route").await;

        // Seed an agent
        let agent = AgentRecord {
            id: "delete_agent_test_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "delete-agent-key".to_string(),
            agent_token: "delete-agent-token".to_string(),
            name: "Delete Test Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();

        // 1. Delete the agent
        let response = delete_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("delete_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // 2. Fetch the agent (should return 404 because it is soft-deleted)
        let response_get = get_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("delete_agent_test_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_get.status(), StatusCode::NOT_FOUND);

        // 3. Delete non-existing agent (should return 404)
        let response_404 = delete_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non_existent_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);
    }

    /// #1157: `DELETE /v1/agents/:id` previously left no audit trail at all.
    /// Verify a successful delete now writes an `admin_action` audit row.
    #[tokio::test]
    async fn delete_agent_route_writes_admin_action_audit_event() {
        let (state, tenant_id, _agent_token) = setup_state("delete_agent_audit_trail").await;

        let agent = AgentRecord {
            id: "delete_agent_audit_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "delete-agent-audit-key".to_string(),
            agent_token: "delete-agent-audit-token".to_string(),
            name: "Delete Audit Test Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();

        let response = delete_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("delete_agent_audit_id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        let admin_event = events
            .iter()
            .find(|e| {
                e.event_type == "admin_action" && e.action.as_deref() == Some("agent_deleted")
            })
            .expect("expected an admin_action audit event for agent_deleted");
        assert_eq!(
            admin_event.agent_id.as_deref(),
            Some("delete_agent_audit_id")
        );
    }

    /// #1157: `DELETE /v1/agents/:id/permissions/:tool_key` previously left no
    /// audit trail at all. Verify a successful revoke now writes an
    /// `admin_action` audit row.
    #[tokio::test]
    async fn revoke_agent_tool_permission_route_writes_admin_action_audit_event() {
        let (state, tenant_id, _agent_token) = setup_state("revoke_permission_audit_trail").await;

        let agent = AgentRecord {
            id: "revoke_permission_agent_id".to_string(),
            tenant_id: tenant_id.clone(),
            agent_key: "revoke-permission-agent-key".to_string(),
            agent_token: "revoke-permission-agent-token".to_string(),
            name: "Revoke Permission Test Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent).await.unwrap();
        db::grant_agent_tool_permission(&state.pool, &tenant_id, &agent.id, "github")
            .await
            .unwrap();

        let response = revoke_agent_tool_permission(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path((agent.id.clone(), "github".to_string())),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        let admin_event = events
            .iter()
            .find(|e| {
                e.event_type == "admin_action"
                    && e.action.as_deref() == Some("agent_tool_permission_revoked")
            })
            .expect("expected an admin_action audit event for agent_tool_permission_revoked");
        assert_eq!(admin_event.agent_id.as_deref(), Some(agent.id.as_str()));
        assert_eq!(admin_event.resource.as_deref(), Some("github"));
    }

    /// `POST /v1/agents/:id/restore` sets a quarantined agent back to `active`
    /// and subsequent authorize calls resolve normally.
    #[tokio::test]
    async fn restore_agent_reactivates_quarantined_agent() {
        let (state, tenant_id, agent_token) = setup_state("cedar_quarantine_restore").await;

        // Retrieve agent id for the restore call.
        let agent_id: String =
            sqlx::query_scalar("SELECT id FROM agents WHERE tenant_id = ? AND agent_token = ?")
                .bind(&tenant_id)
                .bind(db::hash_token(&agent_token))
                .fetch_one(&state.pool)
                .await
                .unwrap();

        // Quarantine the agent directly via DB (simulates Cedar-triggered quarantine).
        db::set_agent_status(&state.pool, &tenant_id, &agent_id, "quarantined")
            .await
            .unwrap();

        // Verify the agent is quarantined (authorize returns 401).
        let req = mcp_authorize_request("filesystem", "read_file");
        let resp_before = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_before.status(), StatusCode::UNAUTHORIZED);

        // Restore the agent.
        let restore_resp = restore_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(restore_resp.status(), StatusCode::OK);
        let restore_body = to_bytes(restore_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let restore_json: serde_json::Value = serde_json::from_slice(&restore_body).unwrap();
        assert_eq!(restore_json["status"], "active");

        // After restore, authorize should work again.
        let req2 = mcp_authorize_request("filesystem", "read_file");
        let resp_after = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req2).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_after.status(), StatusCode::OK);
    }

    // ── #1295: Auto-Rotate Leaked Agent Token ───────────────────────────────

    /// `POST /v1/agents/:id/rotate-token` issues a new token that immediately
    /// works while the old token immediately stops working — no grace period.
    #[tokio::test]
    async fn rotate_agent_token_invalidates_old_token_and_issues_new_one() {
        let (state, tenant_id, old_token) = setup_state("rotate_token_manual").await;
        let agent_id: String =
            sqlx::query_scalar("SELECT id FROM agents WHERE tenant_id = ? AND agent_token = ?")
                .bind(&tenant_id)
                .bind(db::hash_token(&old_token))
                .fetch_one(&state.pool)
                .await
                .unwrap();

        let resp = rotate_agent_token(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
            None,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let new_token = json["agent_token"].as_str().unwrap().to_string();
        assert_ne!(new_token, old_token);

        // Old token is rejected.
        let req = mcp_authorize_request("filesystem", "read_file");
        let resp_old = authorize_action(
            State(state.clone()),
            agent_headers(&old_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_old.status(), StatusCode::UNAUTHORIZED);

        // New token works.
        let req2 = mcp_authorize_request("filesystem", "read_file");
        let resp_new = authorize_action(
            State(state.clone()),
            agent_headers(&new_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req2).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_new.status(), StatusCode::OK);

        // Audit event recorded.
        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        assert!(events.iter().any(|e| e.event_type == "agent_token_rotated"));
    }

    #[tokio::test]
    async fn rotate_agent_token_unknown_agent_returns_404() {
        let (state, tenant_id, _) = setup_state("rotate_token_404").await;

        let resp = rotate_agent_token(
            State(state.clone()),
            TenantId(tenant_id),
            Path("nonexistent-agent".to_string()),
            None,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// #0078-#0080: agent lifecycle columns. `last_seen_at` is a heartbeat updated
    /// on every authorize call; `freeze_agent` records an operator-supplied
    /// `frozen_reason` that is cleared on unfreeze; `quarantined_at` is set when
    /// status transitions to `quarantined` and cleared on any other transition.
    #[tokio::test]
    async fn agent_lifecycle_columns_are_populated_and_cleared() {
        let (state, tenant_id, agent_token) = setup_state("agent_lifecycle").await;
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id.clone();
        assert!(agent.last_seen_at.is_none());

        // last_seen_at: populated by a successful authorize call.
        let request = mcp_authorize_request("filesystem", "read_file");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert!(agent.last_seen_at.is_some());

        // frozen_reason: set via freeze_agent's optional body, cleared on unfreeze.
        let resp = freeze_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
            Some(Json(FreezeAgentRequest {
                reason: Some("compromised credentials".to_string()),
            })),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "frozen");
        assert_eq!(
            agent.frozen_reason.as_deref(),
            Some("compromised credentials")
        );

        let _ = unfreeze_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
        )
        .await
        .into_response();
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "active");
        assert!(agent.frozen_reason.is_none());

        // quarantined_at: set on transition to quarantined, cleared on transition out.
        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "quarantined")
                .await
                .unwrap()
        );
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "quarantined");
        assert!(agent.quarantined_at.is_some());

        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "active")
                .await
                .unwrap()
        );
        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "active");
        assert!(agent.quarantined_at.is_none());
    }

    /// #0141: revoke_agent permanently sets the agent's status to "revoked".
    #[tokio::test]
    async fn revoke_agent_sets_status_to_revoked() {
        let (state, tenant_id, agent_token) = setup_state("revoke_agent_status").await;
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let resp = revoke_agent(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let agent = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent.status, "revoked");
    }

    /// #0142: quarantine_mcp_server sets the MCP server's status to
    /// "quarantined", retrievable via db::get_mcp_server_by_key.
    #[tokio::test]
    async fn quarantine_mcp_server_sets_status_to_quarantined() {
        let (state, tenant_id, _agent_token) = setup_state("quarantine_mcp_server_status").await;
        db::upsert_mcp_server(
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

        let resp = quarantine_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let server = db::get_mcp_server_by_key(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap()
            .expect("server should exist");
        assert_eq!(server.status, "quarantined");
    }

    /// #0111: POST /v1/agents/register with a valid payload returns 201 and
    /// a fresh agent_id/agent_token.
    #[tokio::test]
    async fn register_agent_returns_201_with_valid_payload() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_agent_201").await;
        let app = register_agent_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_agent_payload("new-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: RegisterAgentResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.agent_key, "new-agent");
        assert!(!parsed.agent_token.is_empty());
    }

    /// #0112: registering the same agent_key twice returns 200 with the
    /// existing agent's id/token, instead of creating a duplicate.
    #[tokio::test]
    async fn register_agent_returns_existing_agent_on_duplicate_key() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_agent_dup").await;
        let state_pool = state.pool.clone();
        let app = register_agent_router(state);

        let make_request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/agents/register")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", tenant_id))
                .body(axum::body::Body::from(
                    register_agent_payload("dup-agent").to_string(),
                ))
                .unwrap()
        };

        let first = app.clone().oneshot(make_request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
        let first_parsed: RegisterAgentResponse = serde_json::from_slice(&first_body).unwrap();

        let second = app.clone().oneshot(make_request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second_body = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        let second_parsed: RegisterAgentResponse = serde_json::from_slice(&second_body).unwrap();

        assert_eq!(second_parsed.id, first_parsed.id);
        // The duplicate registration rotates the token and returns a usable
        // plaintext credential — never the unrecoverable "[REDACTED]" stub (#1366).
        assert_ne!(second_parsed.agent_token, "[REDACTED]");
        assert!(!second_parsed.agent_token.is_empty());
        assert_ne!(second_parsed.agent_token, first_parsed.agent_token);

        // The old (first) token must no longer authenticate...
        let old_agent = db::get_agent_by_token(&state_pool, &tenant_id, &first_parsed.agent_token)
            .await
            .unwrap();
        assert!(old_agent.is_none());

        // ...while the newly rotated token does.
        let new_agent = db::get_agent_by_token(&state_pool, &tenant_id, &second_parsed.agent_token)
            .await
            .unwrap();
        assert!(new_agent.is_some());
        assert_eq!(new_agent.unwrap().id, second_parsed.id.to_string());
    }

    #[tokio::test]
    async fn test_agent_token_is_hashed_in_db() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _) = setup_state("agent_token_hashing").await;
        let app = register_agent_router(state.clone());

        // 1. Register a new agent
        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_agent_payload("hash-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: RegisterAgentResponse = serde_json::from_slice(&body).unwrap();
        let cleartext_token = parsed.agent_token;

        // Verify we got a valid-looking cleartext token
        assert!(cleartext_token.starts_with("agent_tok_"));

        // 2. Query the DB directly to check the stored token
        let stored_agent = db::get_agent_by_key(&state.pool, &tenant_id, "hash-agent")
            .await
            .unwrap()
            .expect("agent should exist in database");

        // Stored token must NOT be cleartext
        assert_ne!(stored_agent.agent_token, cleartext_token);

        // Stored token must be the SHA-256 hash of the cleartext token
        let expected_hash = db::hash_token(&cleartext_token);
        assert_eq!(stored_agent.agent_token, expected_hash);

        // 3. Verify that get_agent_by_token successfully resolves the agent using cleartext
        let resolved = db::get_agent_by_token(&state.pool, &tenant_id, &cleartext_token)
            .await
            .unwrap();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().agent_key, "hash-agent");
    }

    /// #0113: a payload missing the required agent_key field is rejected
    /// before reaching the handler (JSON extractor failure).
    #[tokio::test]
    async fn register_agent_rejects_missing_agent_key() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_agent_missing_key").await;
        let app = register_agent_router(state);

        let mut payload = register_agent_payload("ignored");
        payload.as_object_mut().unwrap().remove("agent_key");

        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert!(
            response.status().is_client_error(),
            "expected a 4xx for missing agent_key, got {:?}",
            response.status()
        );
    }

    /// #0114: a request with no Authorization header is rejected with 401
    /// before the handler runs (TenantId extractor).
    #[tokio::test]
    async fn register_agent_rejects_missing_authorization_header() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, _tenant_id, _agent_token) = setup_state("register_agent_no_auth").await;
        let app = register_agent_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                register_agent_payload("no-auth-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// #0115: POST /v1/tools with a valid payload creates the skill and its
    /// actions, retrievable via `db::get_skill_action`.
    #[tokio::test]
    async fn register_tool_creates_skill_with_actions() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_tool_creates").await;
        let pool = state.pool.clone();
        let app = register_tool_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_tool_payload("deployer", "low").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let action = db::get_skill_action(&pool, &tenant_id, "deployer", "ship")
            .await
            .unwrap()
            .expect("registered action should be queryable");
        let risk = action.risk;
        let mutates_state = action.mutates_state;
        let approval_required = action.approval_required;
        let default_decision = action.default_decision;
        assert_eq!(risk, "low");
        assert!(mutates_state);
        assert!(!approval_required);
        assert_eq!(default_decision, "policy");
    }

    /// #0116: re-registering the same skill_key with a different action risk
    /// upserts in place rather than creating a duplicate skill/action.
    #[tokio::test]
    async fn register_tool_upserts_on_duplicate_skill_key() {
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, tenant_id, _agent_token) = setup_state("register_tool_dup").await;
        let pool = state.pool.clone();
        let app = register_tool_router(state);

        let first = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_tool_payload("deployer", "low").to_string(),
            ))
            .unwrap();
        let first_response = app.clone().oneshot(first).await.unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);

        let second = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer {}", tenant_id))
            .body(axum::body::Body::from(
                register_tool_payload("deployer", "high").to_string(),
            ))
            .unwrap();
        let second_response = app.oneshot(second).await.unwrap();
        assert_eq!(second_response.status(), StatusCode::OK);

        let action = db::get_skill_action(&pool, &tenant_id, "deployer", "ship")
            .await
            .unwrap()
            .expect("registered action should be queryable");
        let risk = action.risk;
        assert_eq!(risk, "high", "second registration should upsert risk");

        let skill_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM skills WHERE tenant_id = ? AND skill_key = 'deployer'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            skill_count, 1,
            "duplicate registration must not create a second skill row"
        );
    }
}
