#![allow(unused_imports)]
use crate::error::StatusError;
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

// Register MCP Server Handler
pub async fn register_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<RegisterMcpServerRequest>,
) -> impl IntoResponse {
    let server_id = Uuid::new_v4().to_string();
    let record = McpServerRecord {
        id: server_id.clone(),
        tenant_id: tenant_id.clone(),
        server_key: payload.server_key.clone(),
        name: payload.name.clone(),
        owner_team: payload.owner_team.clone(),
        transport: payload.transport.clone(),
        source: payload.source.clone(),
        trust_level: payload.trust_level.clone(),
        endpoint: payload.endpoint.clone(),
        version: None,
        status: "active".to_string(),
        manifest_hash: String::new(),
        last_discovery_at: None,
        inspection_enabled: false,
        created_at: Utc::now(),
    };

    match state.storage.register_mcp_server(&record).await {
        Ok(_) => {}
        Err(e) => {
            error!("Failed to register MCP server: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let final_server = match state
        .storage
        .get_mcp_server_by_key(&tenant_id, &payload.server_key)
        .await
    {
        Ok(Some(s)) => s,
        _ => record,
    };

    state
        .mcp_server_cache
        .invalidate(&McpServerCache::cache_key(&tenant_id, &payload.server_key));

    (
        StatusCode::CREATED,
        Json(RegisterMcpServerResponse {
            server_id: final_server.id,
            server_key: payload.server_key,
            status: "active".to_string(),
        }),
    )
        .into_response()
}

pub async fn discover_mcp_tools(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
    Json(payload): Json<DiscoverMcpToolsRequest>,
) -> impl IntoResponse {
    let server = match state
        .storage
        .get_mcp_server_by_key(&tenant_id, &server_key)
        .await
    {
        Ok(Some(server)) => server,
        Ok(None) => return StatusError::not_found("MCP server not found").into_response(),
        Err(e) => {
            error!("Failed to look up MCP server: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let new_manifest_hash = compute_mcp_manifest_hash(&payload.tools);

    let tools = match state
        .storage
        .discover_mcp_tools(&tenant_id, &server_key, &payload.tools, &new_manifest_hash)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to discover MCP tools: {:?}", e);
            return StatusError::internal("Failed to register MCP tools").into_response();
        }
    };

    let skill_key = format!("mcp:{}", server_key);
    let mut registered = 0usize;
    for tool in &payload.tools {
        state.skill_cache.invalidate(&SkillActionCache::cache_key(
            &tenant_id,
            &skill_key,
            &tool.tool_key,
        ));

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
            decision_id: None,
            approval_id: None,
            created_at: Utc::now(),
        };
        let _ = state.storage.insert_audit_event(&audit_record).await;
        registered += 1;
    }

    // MCP tool-manifest drift detection (SOC `mcp_manifest_drift`). Pin the manifest
    // hash on first discovery; on a later discovery whose hash differs from the pin,
    // surface a drift event on the async SOC stream and re-pin to the new value (so
    // each distinct change alerts exactly once). STRICTLY ADDITIVE and best-effort:
    // any DB error here is logged and never blocks the discovery response, and the
    // SOC emit is non-blocking (`try_send`). Carries the server key + hashes only —
    // never any tool payload.
    let manifest_json = serde_json::to_string(&payload.tools).unwrap_or_default();
    let snapshot_rec = McpManifestSnapshotRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        server_key: server_key.clone(),
        manifest_hash: new_manifest_hash.clone(),
        manifest_json,
        created_at: Utc::now(),
    };
    if let Err(e) = state
        .storage
        .insert_mcp_manifest_snapshot(&snapshot_rec)
        .await
    {
        error!("Failed to record MCP manifest snapshot: {:?}", e);
    }

    let pinned = server.manifest_hash.clone();
    if !pinned.is_empty() && pinned != new_manifest_hash {
        // #1336: diff against the manifest pinned just before this discovery
        // (the second-most-recent snapshot — the most recent is the one just
        // inserted above for this discovery) to classify drift severity and
        // describe what changed, instead of a single generic "drift" signal.
        let old_tools: Vec<McpToolManifestItem> = state
            .storage
            .list_mcp_manifest_snapshots(&tenant_id, &server_key, 2)
            .await
            .ok()
            .and_then(|snapshots| snapshots.into_iter().nth(1))
            .and_then(|snapshot| serde_json::from_str(&snapshot.manifest_json).ok())
            .unwrap_or_default();

        let (classification, diff) = classify_manifest_drift(&old_tools, &payload.tools);
        let severity = severity_for_manifest_drift(classification);

        state.events.emit(AseEvent {
            event_id: Uuid::new_v4().to_string(),
            occurred_at: Utc::now().to_rfc3339(),
            tenant_id: tenant_id.clone(),
            kind: "mcp_manifest_drift".to_string(),
            agent_id: "system".to_string(),
            // Not a deny — drift is a server-integrity flag, not an authorize
            // decision (kept out of the deny-storm correlation, design law 1).
            decision: "flag".to_string(),
            tool: format!("mcp:{}", server_key),
            action: "discover".to_string(),
            resource: Some(server_key.clone()),
            // #1336: encodes the severity classification (high/medium/low)
            // via the same risk-score buckets `risk_score_for_level` uses,
            // decoded back to a severity by `detect::mcp_manifest_drift`.
            risk_score: risk_score_for_level(severity),
            reason: format!(
                "MCP tool-manifest drift on server '{}' ({}): pinned {} != observed {} — {}",
                server_key, classification, pinned, new_manifest_hash, diff
            ),
            run_id: None,
            trace_id: None,
            matched_policies: Vec::new(),
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
        });

        // Fail-closed response (Phase 4): drift is a tool-hijack signal, so
        // auto-quarantine the server. The inline authorize gate above then
        // denies every tool call until an operator verifies the new manifest
        // out-of-band and explicitly restores the server. Best-effort: a DB
        // error is logged and never blocks the discovery response.
        match state
            .storage
            .update_mcp_server(
                &tenant_id,
                &server_key,
                None,
                None,
                None,
                None,
                None,
                None,
                Some("quarantined"),
                None,
            )
            .await
        {
            Ok(Some(_updated_server)) => {
                // #1332: record a dedicated, queryable audit event (distinct
                // from the manual `mcp_server_quarantined` event written by
                // `update_mcp_server_quarantine`) carrying the drift details
                // that triggered the auto-quarantine.
                let audit_record = AuditEventRecord {
                    id: Uuid::new_v4().to_string(),
                    tenant_id: tenant_id.clone(),
                    event_type: "mcp_server_auto_quarantined".to_string(),
                    agent_id: None,
                    user_id: None,
                    run_id: None,
                    trace_id: None,
                    span_id: None,
                    skill: Some(format!("mcp:{}", server_key)),
                    action: None,
                    resource: Some(server_key.clone()),
                    event_json: serde_json::to_string(&json!({
                        "server_key": server_key,
                        "owner_team": server.owner_team,
                        "classification": classification,
                        "severity": severity,
                        "pinned_manifest_hash": pinned,
                        "observed_manifest_hash": new_manifest_hash,
                        "diff": diff,
                    }))
                    .unwrap_or_default(),
                    input_hash: None,
                    output_hash: None,
                    decision_id: None,
                    approval_id: None,
                    created_at: Utc::now(),
                };
                let _ = state.storage.insert_audit_event(&audit_record).await;
            }
            Ok(None) => {}
            Err(e) => {
                error!("Failed to auto-quarantine drifted MCP server: {:?}", e);
            }
        }
    }
    if pinned != new_manifest_hash {
        if let Err(e) = state
            .storage
            .set_mcp_server_manifest_hash(&tenant_id, &server_key, &new_manifest_hash)
            .await
        {
            error!("Failed to pin MCP manifest hash: {:?}", e);
        }
    }

    // DB-007 (#932): record discovery timestamp regardless of drift outcome.
    // Best-effort: a DB error here never blocks the discovery response.
    if let Err(e) = state
        .storage
        .touch_mcp_server_discovery(&tenant_id, &server_key)
        .await
    {
        error!("Failed to record MCP discovery timestamp: {:?}", e);
    }

    // Invalidate server and tool caches
    state
        .mcp_server_cache
        .invalidate(&McpServerCache::cache_key(&tenant_id, &server_key));
    state
        .mcp_tool_cache
        .invalidate_server(&tenant_id, &server_key);

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
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_mcp_server_by_key(&tenant_id, &server_key)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusError::not_found("MCP server not found").into_response(),
        Err(e) => {
            error!("Failed to look up MCP server: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    }

    match state.storage.list_mcp_tools(&tenant_id, &server_key).await {
        Ok(tools) => (
            StatusCode::OK,
            Json(json!({"server_key": server_key, "tools": tools})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to list MCP tools: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1334: surfaces `db::list_mcp_manifest_snapshots` (most recent first,
/// capped at 20) over HTTP so the dashboard's MCP server detail view can
/// render manifest drift history. Tenant-scoped, fail-closed (404 for an
/// unknown server, matching `get_mcp_tool_manifest`'s existing pattern).
pub async fn get_mcp_manifest_history(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_mcp_server_by_key(&tenant_id, &server_key)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return StatusError::not_found("MCP server not found").into_response(),
        Err(e) => {
            error!("Failed to look up MCP server: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    }

    match state
        .storage
        .list_mcp_manifest_snapshots(&tenant_id, &server_key, 20)
        .await
    {
        Ok(snapshots) => (
            StatusCode::OK,
            Json(json!({"server_key": server_key, "snapshots": snapshots})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to list MCP manifest snapshots: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn approve_mcp_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path((server_key, tool_key)): Path<(String, String)>,
) -> impl IntoResponse {
    update_mcp_tool_status(state, tenant_id, server_key, tool_key, "approved").await
}

pub async fn disable_mcp_tool(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path((server_key, tool_key)): Path<(String, String)>,
) -> impl IntoResponse {
    update_mcp_tool_status(state, tenant_id, server_key, tool_key, "disabled").await
}

async fn update_mcp_tool_status(
    state: Arc<AppState>,
    tenant_id: String,
    server_key: String,
    tool_key: String,
    status: &str,
) -> axum::response::Response {
    match state
        .storage
        .set_mcp_tool_status(&tenant_id, &server_key, &tool_key, status)
        .await
    {
        Ok(true) => {
            let audit_record = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
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
                decision_id: None,
                approval_id: None,
                created_at: Utc::now(),
            };
            let _ = state.storage.insert_audit_event(&audit_record).await;

            state.mcp_tool_cache.invalidate(&McpToolCache::cache_key(
                &tenant_id,
                &server_key,
                &tool_key,
            ));

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
        Ok(false) => StatusError::not_found("MCP tool not found").into_response(),
        Err(e) => {
            error!("Failed to update MCP tool status: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Quarantine an MCP server — the gateway will deny all tool calls from this
/// server until it is restored. Tenant-scoped, parameterized, fail-closed.
pub async fn quarantine_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
    body: Option<Json<ActiveResponseRequest>>,
) -> impl IntoResponse {
    let reason = active_response_reason(body.map(|Json(b)| b));
    update_mcp_server_quarantine(
        state,
        tenant_id,
        server_key,
        "quarantined",
        "mcp_server_quarantined",
        reason.as_deref(),
    )
    .await
}

/// Restore a quarantined MCP server to active status.
pub async fn restore_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
    body: Option<Json<ActiveResponseRequest>>,
) -> impl IntoResponse {
    let reason = active_response_reason(body.map(|Json(b)| b));
    update_mcp_server_quarantine(
        state,
        tenant_id,
        server_key,
        "active",
        "mcp_server_restored",
        reason.as_deref(),
    )
    .await
}

/// #1193: soft-deletes an MCP server (sets `deleted_at`) — it stops
/// appearing in `list`/`get`, and (security-relevant, not just a management
/// UI concern) the authorize path's own server lookups, so its tools stop
/// being callable. The row and its tool history are kept for audit/receipt
/// integrity; only `DELETE /v1/tenants/:id` (GDPR erasure) actually removes it.
pub async fn delete_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .delete_mcp_server(&tenant_id, &server_key)
        .await
    {
        Ok(true) => {
            super::write_admin_action_audit_event(
                state.storage.as_ref(),
                &tenant_id,
                "mcp_server_deleted",
                None,
                Some(&server_key),
                json!({"server_key": server_key}),
            )
            .await;

            state
                .mcp_server_cache
                .invalidate(&McpServerCache::cache_key(&tenant_id, &server_key));
            state
                .mcp_tool_cache
                .invalidate_server(&tenant_id, &server_key);

            (
                StatusCode::OK,
                Json(json!({"message": "MCP server successfully deleted"})),
            )
                .into_response()
        }
        Ok(false) => StatusError::not_found("MCP server not found").into_response(),
        Err(e) => {
            error!("Failed to delete MCP server: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub(crate) async fn update_mcp_server_quarantine(
    state: Arc<AppState>,
    tenant_id: String,
    server_key: String,
    status: &str,
    audit_action: &str,
    reason: Option<&str>,
) -> axum::response::Response {
    match state
        .storage
        .update_mcp_server(
            &tenant_id,
            &server_key,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(status),
            None,
        )
        .await
    {
        Ok(Some(_)) => {
            let audit = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                event_type: audit_action.to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: Some(format!("mcp:{}", server_key)),
                action: Some(audit_action.to_string()),
                resource: Some(server_key.clone()),
                event_json: serde_json::to_string(&json!({
                    "server_key": server_key,
                    "new_status": status,
                    "action": audit_action,
                    "reason": reason,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at: Utc::now(),
            };
            let _ = state.storage.insert_audit_event(&audit).await;
            info!(server_key = %server_key, status = %status, "MCP server status changed");

            state
                .mcp_server_cache
                .invalidate(&McpServerCache::cache_key(&tenant_id, &server_key));

            (
                StatusCode::OK,
                Json(ActiveResponseStatusResponse {
                    agent_id: None,
                    server_key: Some(server_key),
                    status: status.to_string(),
                    action: audit_action.to_string(),
                    reason_recorded: reason.is_some(),
                }),
            )
                .into_response()
        }
        Ok(None) => StatusError::not_found("MCP server not found").into_response(),
        Err(e) => {
            error!("Failed to update MCP server status: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn list_mcp_servers(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());

    match state
        .storage
        .list_mcp_servers(&tenant_id, limit, offset)
        .await
    {
        Ok(servers) => (StatusCode::OK, Json(servers)).into_response(),
        Err(e) => {
            error!("Failed to list MCP servers: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn get_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_mcp_server_by_key(&tenant_id, &server_key)
        .await
    {
        Ok(Some(server)) => (StatusCode::OK, Json(server)).into_response(),
        Ok(None) => StatusError::not_found("MCP server not found").into_response(),
        Err(e) => {
            error!("Failed to get MCP server: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn update_mcp_server(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
    Json(payload): Json<UpdateMcpServerRequest>,
) -> impl IntoResponse {
    match state
        .storage
        .get_mcp_server_by_key(&tenant_id, &server_key)
        .await
    {
        Ok(None) => {
            return StatusError::not_found("MCP server not found").into_response();
        }
        Err(e) => {
            error!("Database error getting MCP server: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
        _ => {}
    }

    match state
        .storage
        .update_mcp_server(
            &tenant_id,
            &server_key,
            payload.name.as_deref(),
            payload.owner_team.as_ref().map(|o| o.as_deref()),
            payload.transport.as_deref(),
            payload.source.as_ref().map(|o| o.as_deref()),
            payload.trust_level.as_deref(),
            payload.endpoint.as_deref(),
            payload.status.as_deref(),
            payload.inspection_enabled,
        )
        .await
    {
        Ok(Some(server)) => {
            state
                .mcp_server_cache
                .invalidate(&McpServerCache::cache_key(&tenant_id, &server_key));
            (StatusCode::OK, Json(server)).into_response()
        }
        Ok(None) => StatusError::not_found("MCP server not found").into_response(),
        Err(e) => {
            error!("Failed to update MCP server: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// `POST /v1/mcp/servers/:server_key/inspect` (#1333) — scans an MCP tool
/// response for sensitive-data patterns and prompt-injection attempts.
///
/// This endpoint exists because the gateway's `/v1/authorize` path only ever
/// sees the *request* side of a tool call — the SDK executes the tool
/// itself and the gateway never observes the return value. The SDK is
/// expected to call this **after** it has already returned the tool's
/// result to the agent (fire-and-forget, never blocking the MCP call return
/// path — the AC's async requirement is satisfied by the caller, not by
/// anything synchronous in this handler).
///
/// Behavior, all tenant-scoped:
/// - `404` if the MCP server doesn't exist for this tenant.
/// - If [`McpServerRecord::inspection_enabled`] is `false` (the default —
///   opt-in per server via `PATCH /v1/mcp/servers/:server_key`), returns
///   `200 {"inspected": false, "reason": "inspection_disabled"}` without
///   scanning anything.
/// - Otherwise runs [`mcp_inspect::scan`] against `response_text`. The raw
///   text is **never persisted or logged** — only finding categories and
///   counts (the redaction invariant). If any category matched, inserts a
///   `soc_alerts` row (`rule: "mcp_response_sensitive_data"` or
///   `"mcp_response_injection_attempt"`, one alert per matched category) so
///   it's visible via `GET /v1/alerts`/`GET /v1/soc/summary`.
///
/// Scope note (v1): unlike alerts produced by the `events::drain` pipeline,
/// alerts from this endpoint are written directly and do **not** flow
/// through the live notify sink, webhook export, or `GET /v1/ws/events` —
/// this endpoint is a dedicated, synchronous request/response API, not a
/// background event source. An operator polling `GET /v1/alerts` will see
/// them; a live Slack push or WebSocket subscriber will not, today.
pub async fn inspect_mcp_response(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(server_key): Path<String>,
    Json(payload): Json<InspectMcpResponseRequest>,
) -> impl IntoResponse {
    let server = match state
        .storage
        .get_mcp_server_by_key(&tenant_id, &server_key)
        .await
    {
        Ok(Some(server)) => server,
        Ok(None) => {
            return StatusError::not_found("MCP server not found").into_response();
        }
        Err(e) => {
            error!("Database error getting MCP server: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    if !server.inspection_enabled {
        return (
            StatusCode::OK,
            Json(json!({"inspected": false, "reason": "inspection_disabled"})),
        )
            .into_response();
    }

    let result = mcp_inspect::scan(&payload.response_text);

    if result.flagged {
        let now = Utc::now().to_rfc3339();
        let source_event_id = payload
            .decision_id
            .clone()
            .unwrap_or_else(|| format!("mcp_inspect:{}", Uuid::new_v4()));
        for finding in &result.findings {
            let rule = match finding.category {
                mcp_inspect::FindingCategory::InjectionAttempt => "mcp_response_injection_attempt",
                _ => "mcp_response_sensitive_data",
            };
            let alert = SocAlertRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                rule: rule.to_string(),
                severity: "high".to_string(),
                agent_id: payload.agent_id.clone(),
                source_event_id: source_event_id.clone(),
                summary: format!(
                    "MCP server '{}' tool '{}' response flagged: {:?} (count={})",
                    server_key, payload.tool_key, finding.category, finding.count
                ),
                created_at: now.clone(),
            };
            if let Err(e) = state.storage.insert_soc_alert(&alert).await {
                error!("Failed to persist MCP response inspection alert: {:?}", e);
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "inspected": true,
            "flagged": result.flagged,
            "findings": result.findings,
        })),
    )
        .into_response()
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
    fn drift_tool(tool_key: &str, risk: &str) -> McpToolManifestItem {
        McpToolManifestItem {
            tool_key: tool_key.to_string(),
            name: format!("Tool {}", tool_key),
            description: None,
            input_schema: None,
            risk: risk.to_string(),
            mutates_state: false,
            approval_required: false,
        }
    }

    /// The manifest hash is order-independent (discovery order must not matter) but
    /// sensitive to any security-relevant field change (e.g. a tool's risk level).
    #[test]
    fn mcp_manifest_hash_is_order_independent_and_change_sensitive() {
        let a = vec![
            drift_tool("create_issue", "medium"),
            drift_tool("merge", "high"),
        ];
        let b = vec![
            drift_tool("merge", "high"),
            drift_tool("create_issue", "medium"),
        ];
        assert_eq!(
            compute_mcp_manifest_hash(&a),
            compute_mcp_manifest_hash(&b),
            "reordering tools must not change the manifest hash"
        );

        let c = vec![
            drift_tool("create_issue", "critical"),
            drift_tool("merge", "high"),
        ];
        assert_ne!(
            compute_mcp_manifest_hash(&a),
            compute_mcp_manifest_hash(&c),
            "changing a tool's risk must change the manifest hash"
        );

        assert!(compute_mcp_manifest_hash(&a).starts_with("sha256:"));
    }

    /// #1336: a brand-new tool in the manifest classifies as `tool_added` (high).
    #[test]
    fn classify_manifest_drift_tool_added_is_high() {
        let old = vec![drift_tool("create_issue", "medium")];
        let new = vec![
            drift_tool("create_issue", "medium"),
            drift_tool("merge", "high"),
        ];
        let (classification, diff) = classify_manifest_drift(&old, &new);
        assert_eq!(classification, "tool_added");
        assert_eq!(severity_for_manifest_drift(classification), "high");
        assert!(diff.contains("tools added: merge"));
    }

    /// #1336: a tool disappearing from the manifest classifies as `tool_removed`
    /// (high) — even if another tool was also modified, removal takes precedence.
    #[test]
    fn classify_manifest_drift_tool_removed_is_high() {
        let old = vec![
            drift_tool("create_issue", "medium"),
            drift_tool("merge", "high"),
        ];
        let new = vec![drift_tool("create_issue", "medium")];
        let (classification, diff) = classify_manifest_drift(&old, &new);
        assert_eq!(classification, "tool_removed");
        assert_eq!(severity_for_manifest_drift(classification), "high");
        assert!(diff.contains("tools removed: merge"));
    }

    /// #1336 acceptance criterion: adding an optional parameter to an existing
    /// tool's `input_schema` (no tools added/removed) classifies as
    /// `tool_modified` — medium severity.
    #[test]
    fn classify_manifest_drift_new_optional_parameter_is_tool_modified_medium() {
        let old = vec![McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create Issue".to_string(),
            description: Some("Open a new issue".to_string()),
            input_schema: Some(json!({
                "type": "object",
                "properties": {"title": {"type": "string"}},
                "required": ["title"],
            })),
            risk: "medium".to_string(),
            mutates_state: true,
            approval_required: false,
        }];
        let new = vec![McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create Issue".to_string(),
            description: Some("Open a new issue".to_string()),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "labels": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title"],
            })),
            risk: "medium".to_string(),
            mutates_state: true,
            approval_required: false,
        }];
        let (classification, diff) = classify_manifest_drift(&old, &new);
        assert_eq!(classification, "tool_modified");
        assert_eq!(severity_for_manifest_drift(classification), "medium");
        assert!(diff.contains("tools modified: create_issue"));
    }

    /// #1336: only a description/name change classifies as `metadata_changed` —
    /// low severity.
    #[test]
    fn classify_manifest_drift_description_only_is_metadata_changed_low() {
        let old = vec![drift_tool("create_issue", "medium")];
        let mut renamed = drift_tool("create_issue", "medium");
        renamed.description = Some("Updated description".to_string());
        let new = vec![renamed];
        let (classification, diff) = classify_manifest_drift(&old, &new);
        assert_eq!(classification, "metadata_changed");
        assert_eq!(severity_for_manifest_drift(classification), "low");
        assert!(diff.contains("metadata changed: create_issue"));
    }

    /// Re-discovering a server whose advertised manifest changed must emit a
    /// `mcp_manifest_drift` AseEvent onto the SOC stream (and only on change).
    #[tokio::test]
    async fn discover_emits_manifest_drift_only_when_manifest_changes() {
        let (state, tenant_id, _agent_token, mut events_rx) =
            setup_state_with_events("mcp_drift").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
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

        // 1) First discovery pins the manifest — no drift.
        let req1 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req1),
        )
        .await;

        // 2) Identical re-discovery — still no drift.
        let req2 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req2),
        )
        .await;

        // 3) Changed manifest (risk escalated) — must drift.
        let req3 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "critical")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req3),
        )
        .await;

        let mut drift_events = 0;
        while let Ok(ev) = events_rx.try_recv() {
            if ev.kind == "mcp_manifest_drift" {
                assert_eq!(ev.tenant_id, tenant_id);
                assert_eq!(ev.decision, "flag");
                assert_eq!(ev.resource.as_deref(), Some("github-mcp"));
                assert_eq!(ev.tool, "mcp:github-mcp");
                drift_events += 1;
            }
        }
        assert_eq!(
            drift_events, 1,
            "exactly one drift event — pinned first, silent on identical, fires on change"
        );

        // The new manifest is now pinned (re-pinned on drift).
        let pinned =
            db::get_mcp_server_manifest_hash(state.storage.get_pool(), &tenant_id, "github-mcp")
                .await
                .unwrap();
        let expected = compute_mcp_manifest_hash(&[drift_tool("create_issue", "critical")]);
        assert_eq!(pinned, expected);

        // Fail-closed response: drift must auto-quarantine the server.
        let server = state
            .storage
            .get_mcp_server_by_key(&tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.status, "quarantined");
    }

    /// #1332 AC#5: auto-quarantining a drifted MCP server must write a
    /// dedicated, queryable `audit_events` row (`mcp_server_auto_quarantined`)
    /// distinct from the manual `mcp_server_quarantined` event, carrying the
    /// drift classification/severity/hashes/owner so operators and compliance
    /// can see *why* the server was auto-quarantined without reading SOC events.
    #[tokio::test]
    async fn discover_drift_auto_quarantine_writes_audit_event() {
        let (state, tenant_id, _agent_token, _events_rx) =
            setup_state_with_events("mcp_drift_audit").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform-team"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        // 1) First discovery pins the manifest — no drift.
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(DiscoverMcpToolsRequest {
                tools: vec![drift_tool("create_issue", "medium")],
            }),
        )
        .await;

        // 2) Manifest changes (a tool is added) — must drift and auto-quarantine.
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(DiscoverMcpToolsRequest {
                tools: vec![
                    drift_tool("create_issue", "medium"),
                    drift_tool("delete_repo", "critical"),
                ],
            }),
        )
        .await;

        let server = state
            .storage
            .get_mcp_server_by_key(&tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.status, "quarantined");

        let events = state
            .storage
            .get_audit_events(&tenant_id, None, None, None)
            .await
            .unwrap()
            .0;
        let audit_event = events
            .iter()
            .find(|e| e.event_type == "mcp_server_auto_quarantined")
            .expect("auto-quarantine must write a mcp_server_auto_quarantined audit event");
        assert_eq!(audit_event.resource.as_deref(), Some("github-mcp"));
        assert_eq!(audit_event.skill.as_deref(), Some("mcp:github-mcp"));

        let details: serde_json::Value = serde_json::from_str(&audit_event.event_json).unwrap();
        assert_eq!(details["server_key"], "github-mcp");
        assert_eq!(details["owner_team"], "platform-team");
        assert_eq!(details["classification"], "tool_added");
        assert_eq!(details["severity"], "high");
        assert!(details["pinned_manifest_hash"].is_string());
        assert!(details["observed_manifest_hash"].is_string());
        assert_ne!(
            details["pinned_manifest_hash"],
            details["observed_manifest_hash"]
        );
        assert!(details["diff"].is_string());
    }

    /// #1336 acceptance criterion: adding an optional parameter to an existing
    /// tool's `input_schema` must still trigger drift (any manifest hash change
    /// drifts), but classified `tool_modified` — a medium-severity alert, not the
    /// flat "high" every drift used to produce.
    #[tokio::test]
    async fn discover_classifies_new_optional_parameter_as_medium_severity_drift() {
        let (state, tenant_id, _agent_token, mut events_rx) =
            setup_state_with_events("mcp_drift_param").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
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

        fn create_issue_tool(with_labels_param: bool) -> McpToolManifestItem {
            let properties = if with_labels_param {
                json!({
                    "title": {"type": "string"},
                    "labels": {"type": "array", "items": {"type": "string"}},
                })
            } else {
                json!({"title": {"type": "string"}})
            };
            McpToolManifestItem {
                tool_key: "create_issue".to_string(),
                name: "Create Issue".to_string(),
                description: Some("Open a new issue".to_string()),
                input_schema: Some(json!({
                    "type": "object",
                    "properties": properties,
                    "required": ["title"],
                })),
                risk: "medium".to_string(),
                mutates_state: true,
                approval_required: false,
            }
        }

        // 1) First discovery pins the manifest — no drift.
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(DiscoverMcpToolsRequest {
                tools: vec![create_issue_tool(false)],
            }),
        )
        .await;

        // 2) Re-discovery adds an optional `labels` parameter — same tool, no
        // tools added/removed, so this must classify as `tool_modified`.
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(DiscoverMcpToolsRequest {
                tools: vec![create_issue_tool(true)],
            }),
        )
        .await;

        let mut drift_event = None;
        while let Ok(ev) = events_rx.try_recv() {
            if ev.kind == "mcp_manifest_drift" {
                drift_event = Some(ev);
            }
        }
        let ev = drift_event.expect("a new parameter must still trigger drift");
        assert_eq!(
            ev.risk_score, 40,
            "tool_modified drift must encode medium severity (risk_score 40)"
        );
        assert!(
            ev.reason.contains("tool_modified"),
            "reason must classify the drift: {}",
            ev.reason
        );
        assert!(
            ev.reason.contains("tools modified: create_issue"),
            "reason must include a diff naming the changed tool: {}",
            ev.reason
        );
    }

    /// DB-007 (#932): `last_discovery_at` is `None` until the first discovery
    /// call, then set (and bumped on every subsequent discovery).
    #[tokio::test]
    async fn discover_sets_last_discovery_at_timestamp() {
        let (state, tenant_id, _agent_token, _events_rx) =
            setup_state_with_events("mcp_last_discovery_at").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
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

        let before = state
            .storage
            .get_mcp_server_by_key(&tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert!(
            before.last_discovery_at.is_none(),
            "no discovery has run yet"
        );

        let req = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req),
        )
        .await;

        let after = state
            .storage
            .get_mcp_server_by_key(&tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert!(
            after.last_discovery_at.is_some(),
            "discovery must stamp last_discovery_at"
        );
    }

    /// TASK-0090 (#936): each `POST /v1/mcp/servers/:server_key/tools` discovery
    /// call must record a `mcp_manifest_snapshots` row capturing the computed
    /// `mcp-manifest-1` hash and the raw discovered tool list, so a later
    /// `mcp_manifest_drift` alert can be diffed against prior manifest versions.
    #[tokio::test]
    async fn discover_records_manifest_snapshot() {
        let (state, tenant_id, _agent_token, _events_rx) =
            setup_state_with_events("mcp_manifest_snapshots").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
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

        // First discovery.
        let req1 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req1),
        )
        .await;

        let snapshots = state
            .storage
            .list_mcp_manifest_snapshots(&tenant_id, "github-mcp", 10)
            .await
            .unwrap();
        assert_eq!(snapshots.len(), 1, "first discovery records one snapshot");
        let first_hash = snapshots[0].manifest_hash.clone();
        assert!(first_hash.starts_with("sha256:"));
        assert!(snapshots[0].manifest_json.contains("create_issue"));
        assert_eq!(snapshots[0].tenant_id, tenant_id);
        assert_eq!(snapshots[0].server_key, "github-mcp");

        // Second discovery with a changed manifest records a second, distinct
        // snapshot — most-recent first.
        let req2 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "critical")],
        };
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req2),
        )
        .await;

        let snapshots = state
            .storage
            .list_mcp_manifest_snapshots(&tenant_id, "github-mcp", 10)
            .await
            .unwrap();
        assert_eq!(
            snapshots.len(),
            2,
            "second discovery records another snapshot"
        );
        assert_ne!(
            snapshots[0].manifest_hash, first_hash,
            "changed manifest must produce a different hash"
        );
        assert_eq!(snapshots[1].manifest_hash, first_hash);
    }

    /// #1334: `GET /v1/mcp/servers/:server_key/manifest-history` surfaces the
    /// existing `db::list_mcp_manifest_snapshots` data (previously DB-only,
    /// no HTTP route) so the dashboard's MCP server detail view can render
    /// drift/manifest history without a new DB layer.
    #[tokio::test]
    async fn manifest_history_route_returns_snapshots_most_recent_first() {
        let (state, tenant_id, _agent_token, _events_rx) =
            setup_state_with_events("mcp_manifest_history_route").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
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

        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(DiscoverMcpToolsRequest {
                tools: vec![drift_tool("create_issue", "medium")],
            }),
        )
        .await;
        discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(DiscoverMcpToolsRequest {
                tools: vec![drift_tool("create_issue", "critical")],
            }),
        )
        .await;

        let response = get_mcp_manifest_history(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let snapshots = body["snapshots"].as_array().unwrap();
        assert_eq!(snapshots.len(), 2, "both discoveries recorded a snapshot");
        assert!(snapshots[0]["manifest_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(snapshots[0]["manifest_json"]
            .as_str()
            .unwrap()
            .contains("critical"));
        assert!(snapshots[1]["manifest_json"]
            .as_str()
            .unwrap()
            .contains("medium"));
    }

    #[tokio::test]
    async fn manifest_history_route_404s_for_unknown_server() {
        let (state, tenant_id, _agent_token, _events_rx) =
            setup_state_with_events("mcp_manifest_history_404").await;

        let response = get_mcp_manifest_history(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("nonexistent-mcp".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// TASK-0152 (#998): `discover_mcp_tools` must register a `skills` row
    /// (skill_key `mcp:<server_key>`) and a `skill_actions` row per discovered
    /// tool, so the regular authorize path (`db::get_skill_action`) finds them.
    #[tokio::test]
    async fn discover_mcp_tools_creates_skill_actions() {
        let (state, tenant_id, _agent_token, _events_rx) =
            setup_state_with_events("mcp_discover_skill_actions").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
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

        // No skill action exists prior to discovery.
        assert!(state
            .storage
            .get_skill_action(&tenant_id, "mcp:github-mcp", "create_issue")
            .await
            .unwrap()
            .is_none());

        let mut approval_required_tool = drift_tool("merge_pr", "high");
        approval_required_tool.approval_required = true;
        approval_required_tool.mutates_state = true;

        let req = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium"), approval_required_tool],
        };
        let response = discover_mcp_tools(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
            Json(req),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let create_issue = state
            .storage
            .get_skill_action(&tenant_id, "mcp:github-mcp", "create_issue")
            .await
            .unwrap()
            .expect("create_issue skill action must be registered");
        let risk = create_issue.risk;
        let mutates_state = create_issue.mutates_state;
        let approval_required = create_issue.approval_required;
        let default_decision = create_issue.default_decision;
        assert_eq!(risk, "medium");
        assert!(!mutates_state);
        assert!(!approval_required);
        assert_eq!(default_decision, "policy");

        let merge_pr = state
            .storage
            .get_skill_action(&tenant_id, "mcp:github-mcp", "merge_pr")
            .await
            .unwrap()
            .expect("merge_pr skill action must be registered");
        let risk = merge_pr.risk;
        let mutates_state = merge_pr.mutates_state;
        let approval_required = merge_pr.approval_required;
        let default_decision = merge_pr.default_decision;
        assert_eq!(risk, "high");
        assert!(mutates_state);
        assert!(approval_required);
        assert_eq!(default_decision, "require_approval");
    }

    /// A quarantined MCP server must deny an otherwise-approved tool inline
    /// (Phase 4 response enforcement). Before this, quarantine was recorded but
    /// never checked on the authorize hot path.
    #[tokio::test]
    async fn quarantined_mcp_server_denies_approved_tool() {
        let (state, tenant_id, agent_token) = setup_state("mcp_quarantine_enforced").await;
        let server_id = db::upsert_mcp_server(
            state.storage.get_pool(),
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
        db::upsert_mcp_tool(state.storage.get_pool(), &tenant_id, &server_id, &tool)
            .await
            .unwrap();
        db::set_mcp_tool_status(
            state.storage.get_pool(),
            &tenant_id,
            "github-mcp",
            "create_issue",
            "approved",
        )
        .await
        .unwrap();

        // Baseline: the approved tool authorizes while the server is active.
        let allowed = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(allowed.decision, "allow");

        // Quarantine the server — the same approved tool must now be denied.
        assert!(db::set_mcp_server_status(
            state.storage.get_pool(),
            &tenant_id,
            "github-mcp",
            "quarantined"
        )
        .await
        .unwrap());
        state
            .mcp_server_cache
            .invalidate(&McpServerCache::cache_key(&tenant_id, "github-mcp"));
        let denied = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(denied.decision, "deny");
        assert!(denied
            .matched_policies
            .contains(&"mcp_server_quarantined".to_string()));
    }

    /// #1193: `DELETE /v1/mcp/servers/:key` soft-deletes a server — it must
    /// disappear from `get`/`list`, leave an `admin_action` audit row, and
    /// 404 on a second delete or a delete of a server that never existed.
    #[tokio::test]
    async fn test_delete_mcp_server_route() {
        let (state, tenant_id, _) = setup_state("delete_mcp_server_route").await;
        db::upsert_mcp_server(
            state.storage.get_pool(),
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

        // 1. Delete it.
        let response = delete_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // 2. It must no longer be gettable.
        let get_resp = get_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);

        // 3. ...nor listed.
        let list_resp = list_mcp_servers(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        let body_list = to_bytes(list_resp.into_body(), usize::MAX).await.unwrap();
        let list: Vec<McpServerRecord> = serde_json::from_slice(&body_list).unwrap();
        assert!(list.is_empty());

        // 4. Deleting it again returns 404 (idempotent, not a 200 double-delete).
        let response_404 = delete_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("github-mcp".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);

        // 5. Deleting a server that never existed also 404s.
        let response_never_existed = delete_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("never-existed".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_never_existed.status(), StatusCode::NOT_FOUND);

        // 6. The successful delete left an admin_action audit row.
        let events = state
            .storage
            .get_audit_events(&tenant_id, None, None, None)
            .await
            .unwrap()
            .0;
        let admin_event = events
            .iter()
            .find(|e| {
                e.event_type == "admin_action" && e.action.as_deref() == Some("mcp_server_deleted")
            })
            .expect("expected an admin_action audit event for mcp_server_deleted");
        assert_eq!(admin_event.resource.as_deref(), Some("github-mcp"));
    }

    #[test]
    fn normalize_tool_identifier_lowercases() {
        assert_eq!(normalize_tool_identifier("GitHub"), "github");
        assert_eq!(normalize_tool_identifier("FILESYSTEM"), "filesystem");
        assert_eq!(normalize_tool_identifier("MixedCase"), "mixedcase");
    }

    #[test]
    fn normalize_tool_identifier_percent_decodes() {
        assert_eq!(normalize_tool_identifier("git%20hub"), "git hub");
        assert_eq!(
            normalize_tool_identifier("merge%5Fpull%5Frequest"),
            "merge_pull_request"
        );
    }

    #[test]
    fn normalize_tool_identifier_trims_whitespace() {
        assert_eq!(normalize_tool_identifier("  github  "), "github");
        assert_eq!(normalize_tool_identifier("\tread_file\n"), "read_file");
    }

    #[test]
    fn normalize_tool_identifier_already_normalized_is_idempotent() {
        let inputs = ["github", "merge_pull_request", "filesystem_read"];
        for s in &inputs {
            assert_eq!(&normalize_tool_identifier(s), s);
        }
    }

    #[tokio::test]
    async fn test_mcp_servers_metadata_route() {
        let (state, tenant_id, _) = setup_state("mcp_servers_metadata_route").await;

        // Register two MCP servers
        let server_key1 = "github-mcp";
        let payload1 = RegisterMcpServerRequest {
            server_key: server_key1.to_string(),
            name: "GitHub MCP Server".to_string(),
            owner_team: Some("secops".to_string()),
            transport: "stdio".to_string(),
            source: Some("npx".to_string()),
            trust_level: "semi_trusted".to_string(),
            endpoint: "http://localhost:5001".to_string(),
        };
        let _ = register_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload1),
        )
        .await;

        let server_key2 = "slack-mcp";
        let payload2 = RegisterMcpServerRequest {
            server_key: server_key2.to_string(),
            name: "Slack MCP Server".to_string(),
            owner_team: Some("comms".to_string()),
            transport: "http".to_string(),
            source: None,
            trust_level: "trusted_internal".to_string(),
            endpoint: "http://localhost:5002".to_string(),
        };
        let _ = register_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload2),
        )
        .await;

        // 1. List MCP servers
        let list_resp = list_mcp_servers(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("limit=10".to_string())),
        )
        .await
        .into_response();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let body_list = to_bytes(list_resp.into_body(), usize::MAX).await.unwrap();
        let list: Vec<McpServerRecord> = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(list.len(), 2);

        // 2. Get specific MCP server
        let get_resp = get_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(server_key1.to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body_get = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let s1: McpServerRecord = serde_json::from_slice(&body_get).unwrap();
        assert_eq!(s1.server_key, server_key1);
        assert_eq!(s1.trust_level, "semi_trusted");

        // 3. Update MCP server metadata
        let update_payload = UpdateMcpServerRequest {
            name: Some("GitHub Enterprise MCP".to_string()),
            owner_team: Some(Some("devops-core".to_string())),
            transport: None,
            source: None,
            trust_level: Some("trusted_internal".to_string()),
            endpoint: Some("http://internal-gateway:8081".to_string()),
            status: Some("active".to_string()),
            inspection_enabled: None,
        };
        let update_resp = update_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(server_key1.to_string()),
            Json(update_payload),
        )
        .await
        .into_response();
        assert_eq!(update_resp.status(), StatusCode::OK);
        let body_update = to_bytes(update_resp.into_body(), usize::MAX).await.unwrap();
        let s_updated: McpServerRecord = serde_json::from_slice(&body_update).unwrap();
        assert_eq!(s_updated.name, "GitHub Enterprise MCP");
        assert_eq!(s_updated.owner_team, Some("devops-core".to_string()));
        assert_eq!(s_updated.trust_level, "trusted_internal");
        assert_eq!(s_updated.endpoint, "http://internal-gateway:8081");

        // 4. Update non-existent (should return 404)
        let update_404_resp = update_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("non-existent".to_string()),
            Json(UpdateMcpServerRequest {
                name: Some("xyz".to_string()),
                owner_team: None,
                transport: None,
                source: None,
                trust_level: None,
                endpoint: None,
                status: None,
                inspection_enabled: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(update_404_resp.status(), StatusCode::NOT_FOUND);
    }

    /// Registers an MCP server for the given tenant and returns its `server_key`.
    async fn register_test_mcp_server(state: &Arc<AppState>, tenant_id: &str, server_key: &str) {
        let _ = register_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.to_string()),
            Json(RegisterMcpServerRequest {
                server_key: server_key.to_string(),
                name: "Test MCP Server".to_string(),
                owner_team: None,
                transport: "http".to_string(),
                source: None,
                trust_level: "semi_trusted".to_string(),
                endpoint: "http://localhost:5099".to_string(),
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn update_mcp_server_can_toggle_inspection_enabled() {
        let (state, tenant_id, _agent_token) = setup_state("mcp_inspect_toggle").await;
        let server_key = "toggle-server";
        register_test_mcp_server(&state, &tenant_id, server_key).await;

        // Newly registered servers default to inspection disabled.
        let server = state
            .storage
            .get_mcp_server_by_key(&tenant_id, server_key)
            .await
            .unwrap()
            .unwrap();
        assert!(!server.inspection_enabled);

        // Enable it via PATCH.
        let resp = update_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(server_key.to_string()),
            Json(UpdateMcpServerRequest {
                name: None,
                owner_team: None,
                transport: None,
                source: None,
                trust_level: None,
                endpoint: None,
                status: None,
                inspection_enabled: Some(true),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let updated: McpServerRecord = serde_json::from_slice(&body).unwrap();
        assert!(updated.inspection_enabled);

        // Disable it again.
        let resp = update_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(server_key.to_string()),
            Json(UpdateMcpServerRequest {
                name: None,
                owner_team: None,
                transport: None,
                source: None,
                trust_level: None,
                endpoint: None,
                status: None,
                inspection_enabled: Some(false),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let updated: McpServerRecord = serde_json::from_slice(&body).unwrap();
        assert!(!updated.inspection_enabled);
    }

    #[tokio::test]
    async fn inspect_mcp_response_returns_404_for_unknown_server() {
        let (state, tenant_id, _agent_token) = setup_state("mcp_inspect_404").await;

        let resp = inspect_mcp_response(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("nonexistent".to_string()),
            Json(InspectMcpResponseRequest {
                agent_id: "agent_1".to_string(),
                tool_key: "read_file".to_string(),
                response_text: "irrelevant".to_string(),
                decision_id: None,
                run_id: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn inspect_mcp_response_skips_scanning_when_disabled() {
        let (state, tenant_id, _agent_token) = setup_state("mcp_inspect_disabled").await;
        register_test_mcp_server(&state, &tenant_id, "test-mcp").await;

        let resp = inspect_mcp_response(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("test-mcp".to_string()),
            Json(InspectMcpResponseRequest {
                agent_id: "agent_1".to_string(),
                tool_key: "read_file".to_string(),
                response_text: "SSN: 123-45-6789".to_string(),
                decision_id: None,
                run_id: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["inspected"], json!(false));
        assert_eq!(json["reason"], json!("inspection_disabled"));

        // No alert should have been created since inspection never ran.
        let alerts = state
            .storage
            .list_soc_alerts(&tenant_id, None, None, 50, None)
            .await
            .unwrap()
            .0;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn inspect_mcp_response_flags_sensitive_data_and_creates_alert() {
        let (state, tenant_id, _agent_token) = setup_state("mcp_inspect_flagged").await;
        register_test_mcp_server(&state, &tenant_id, "test-mcp").await;
        db::set_mcp_server_inspection_enabled(
            state.storage.get_pool(),
            &tenant_id,
            "test-mcp",
            true,
        )
        .await
        .unwrap();

        let resp = inspect_mcp_response(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("test-mcp".to_string()),
            Json(InspectMcpResponseRequest {
                agent_id: "agent_1".to_string(),
                tool_key: "read_file".to_string(),
                response_text: "Customer SSN: 123-45-6789".to_string(),
                decision_id: Some("decision_xyz".to_string()),
                run_id: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["inspected"], json!(true));
        assert_eq!(json["flagged"], json!(true));

        // The raw matched text must never appear in the response.
        let body_str = serde_json::to_string(&json).unwrap();
        assert!(!body_str.contains("123-45-6789"));

        let alerts = state
            .storage
            .list_soc_alerts(&tenant_id, None, None, 50, None)
            .await
            .unwrap()
            .0;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "mcp_response_sensitive_data");
        assert_eq!(alerts[0].agent_id, "agent_1");
        assert_eq!(alerts[0].source_event_id, "decision_xyz");
        // The alert summary must never carry the raw matched SSN.
        assert!(!alerts[0].summary.contains("123-45-6789"));
    }

    #[tokio::test]
    async fn inspect_mcp_response_benign_text_is_not_flagged_and_creates_no_alert() {
        let (state, tenant_id, _agent_token) = setup_state("mcp_inspect_benign").await;
        register_test_mcp_server(&state, &tenant_id, "test-mcp").await;
        db::set_mcp_server_inspection_enabled(
            state.storage.get_pool(),
            &tenant_id,
            "test-mcp",
            true,
        )
        .await
        .unwrap();

        let resp = inspect_mcp_response(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("test-mcp".to_string()),
            Json(InspectMcpResponseRequest {
                agent_id: "agent_1".to_string(),
                tool_key: "read_file".to_string(),
                response_text: "The build passed with 42 tests green.".to_string(),
                decision_id: None,
                run_id: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["flagged"], json!(false));

        let alerts = state
            .storage
            .list_soc_alerts(&tenant_id, None, None, 50, None)
            .await
            .unwrap()
            .0;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn inspect_mcp_response_is_tenant_scoped() {
        let (state, tenant_id_a, _agent_token_a) = setup_state("mcp_inspect_tenant_a").await;
        let tenant_id_b = "mcp_inspect_iso_tenant_b".to_string();
        register_tenant_helper(
            state.storage.as_ref(),
            &tenant_id_b,
            "Iso Tenant B",
            "developer",
        )
        .await;
        register_test_mcp_server(&state, &tenant_id_a, "test-mcp").await;

        // Tenant B must not be able to inspect-against tenant A's server key.
        let resp = inspect_mcp_response(
            State(state.clone()),
            TenantId(tenant_id_b.clone()),
            Path("test-mcp".to_string()),
            Json(InspectMcpResponseRequest {
                agent_id: "agent_1".to_string(),
                tool_key: "read_file".to_string(),
                response_text: "irrelevant".to_string(),
                decision_id: None,
                run_id: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// GET /v1/mcp/servers lists a tenant's servers with status + manifest_hash,
    /// and never leaks another tenant's servers.
    #[tokio::test]
    async fn list_mcp_servers_is_tenant_scoped_and_shows_status() {
        let (state, tenant_id, _agent_token) = setup_state("list_mcp_servers").await;

        for key in ["alpha-mcp", "beta-mcp"] {
            db::upsert_mcp_server(
                state.storage.get_pool(),
                &tenant_id,
                key,
                "Server",
                Some("platform"),
                "http",
                Some("internal-registry"),
                "trusted_internal_signed",
                "http://127.0.0.1:9001/mcp",
            )
            .await
            .unwrap();
        }
        // beta is quarantined; alpha gets a pinned manifest hash.
        db::set_mcp_server_status(
            state.storage.get_pool(),
            &tenant_id,
            "beta-mcp",
            "quarantined",
        )
        .await
        .unwrap();
        state
            .storage
            .set_mcp_server_manifest_hash(&tenant_id, "alpha-mcp", "sha256:abc")
            .await
            .unwrap();

        let response = list_mcp_servers(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let servers: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(servers.len(), 2);
        // Order-agnostic: locate each server by key (the handler paginates by
        // created_at DESC).
        let alpha = servers
            .iter()
            .find(|s| s["server_key"] == "alpha-mcp")
            .unwrap();
        let beta = servers
            .iter()
            .find(|s| s["server_key"] == "beta-mcp")
            .unwrap();
        assert_eq!(alpha["status"], "active");
        assert_eq!(alpha["manifest_hash"], "sha256:abc");
        assert_eq!(beta["status"], "quarantined");

        // A different tenant sees none of these servers.
        register_tenant_helper(
            state.storage.as_ref(),
            "tenant_other",
            "Other Tenant",
            "developer",
        )
        .await;
        let other = list_mcp_servers(
            State(state),
            TenantId("tenant_other".to_string()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        let other_body = to_bytes(other.into_body(), usize::MAX).await.unwrap();
        let other_servers: Vec<serde_json::Value> = serde_json::from_slice(&other_body).unwrap();
        assert!(other_servers.is_empty());
    }

    // ---- #899: skill_action read-through LRU cache ----
}
