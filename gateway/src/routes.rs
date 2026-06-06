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
use crate::events::{AseEvent, EventSink};
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;

// Shared app state containing DB pool, Cedar policy engine, and the async SOC
// event sink (Phase 0): the authorize hot path emits decisions onto it.
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub policy_engine: PolicyEngine,
    pub events: EventSink,
    /// Process-wide security counters exposed on GET /metrics.
    pub metrics: SecurityMetrics,
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
// Referenced by the cross-language corpus tests; unused in the non-test binary build.
#[allow(dead_code)]
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

/// Deterministic, order-independent hash of an MCP server's advertised tool
/// manifest. Re-discovery recomputes this and compares it to the value pinned on
/// the server row; a mismatch is tool-manifest drift (supply-chain / tool-hijack
/// signal — the threat the `mcp_manifest_drift` SOC rule surfaces).
///
/// This is a server-integrity hash, NOT the byte-parity-locked `aegis-jcs-1`
/// action/receipt hash, so it carries its own `mcp-manifest-1` scheme tag and is
/// not covered by the cross-language corpus. It hashes only the security-relevant
/// shape of each tool (key, name, description, risk, mutation, approval, input
/// schema) — never any call payload. Tools are sorted by `tool_key` so discovery
/// order never changes the hash.
fn compute_mcp_manifest_hash(tools: &[McpToolManifestItem]) -> String {
    let mut entries: Vec<Value> = tools
        .iter()
        .map(|t| {
            json!({
                "tool_key": t.tool_key,
                "name": t.name,
                "description": t.description,
                "risk": t.risk,
                "mutates_state": t.mutates_state,
                "approval_required": t.approval_required,
                "input_schema": t.input_schema,
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        a.get("tool_key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                b.get("tool_key")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
    });
    let canonical = canonical_value_string(&Value::Array(entries));
    format!("sha256:{}", sha256_hex(canonical.as_bytes()))
}

/// Canonical (scheme `aegis-jcs-1`) string for an arbitrary JSON value. Used for
/// action-receipt hashing; MUST match the SDK's `canonicalize()` byte-for-byte
/// (see `docs/action-receipt-spec.md` and `tests/receipt_chain_vectors.json`).
fn canonical_value_string(value: &Value) -> String {
    serde_json::to_string(&canonicalize_json(value.clone())).unwrap_or_default()
}

/// The hashed body of an action receipt: every semantic field plus the chain
/// link, excluding `receipt_hash` and the volatile DB `created_at`. Built
/// identically at emit time and verify time so the hash is reproducible. All
/// fields are strings/null (no round-trip drift). Scheme aegis-jcs-1.
fn receipt_body_value(rec: &ActionReceiptRecord) -> Value {
    json!({
        "event_id": rec.id,
        "ts": rec.ts,
        "agent_id": rec.agent_id,
        "user_id": rec.user_id,
        "run_id": rec.run_id,
        "trace_id": rec.trace_id,
        "tool": rec.tool,
        "action": rec.action,
        "resource": rec.resource,
        "source_trust": rec.source_trust,
        "decision": rec.decision,
        "approver": rec.approver,
        "action_hash": rec.action_hash,
        "prev_receipt_hash": rec.prev_receipt_hash,
    })
}

fn compute_receipt_hash(rec: &ActionReceiptRecord) -> String {
    sha256_hex(canonical_value_string(&receipt_body_value(rec)).as_bytes())
}

/// Optionally attach an Ed25519 signature OVER the already-computed `receipt_hash`.
///
/// This runs AFTER `compute_receipt_hash` and never feeds back into the hash: the
/// signature and signer public key are additive metadata stored alongside the
/// receipt, so the byte-parity-locked `aegis-jcs-1` chain is untouched. When no
/// signer is configured (`global_signer() == None`), both fields stay NULL and
/// the receipt is emitted unsigned (hermetic default). We sign the hash, never a
/// payload (redaction preserved).
fn apply_receipt_signature(receipt: &mut ActionReceiptRecord) {
    if let Some(signer) = sign::global_signer() {
        receipt.signature = Some(signer.sign_hash(&receipt.receipt_hash));
        receipt.signer_public_key = Some(signer.public_key_hex());
    }
}

/// Emit a hash-chained, verifiable receipt for a finalized decision. Non-fatal:
/// a receipt write failure is logged but does not change the authorization result.
async fn emit_action_receipt(
    pool: &sqlx::SqlitePool,
    tenant_id: &str,
    agent_id: &str,
    payload: &AuthorizeRequest,
    decision_id: Uuid,
    decision: &str,
) {
    // Build the head-referencing receipt inside one atomic transaction (T-D
    // hardening): the chain head is read and the new link inserted under a single
    // write lock, so concurrent authorizes for this tenant cannot fork the chain.
    let result = db::append_action_receipt_atomic(pool, tenant_id, |prev_receipt_hash| {
        let mut receipt = ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(decision_id.to_string()),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some(agent_id.to_string()),
            user_id: payload.user.as_ref().map(|u| u.id.clone()),
            run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
            tool: Some(payload.tool_call.tool.clone()),
            action: Some(payload.tool_call.action.clone()),
            resource: payload.tool_call.resource.clone(),
            source_trust: payload.context.source_trust.clone(),
            decision: decision.to_string(),
            approver: None,
            action_hash: Some(hash_tool_call(&payload.tool_call)),
            prev_receipt_hash,
            receipt_hash: String::new(),
            signature: None,
            signer_public_key: None,
            created_at: Utc::now(),
        };
        // Hash FIRST (byte-parity-locked), then optionally sign OVER the hash.
        receipt.receipt_hash = compute_receipt_hash(&receipt);
        apply_receipt_signature(&mut receipt);
        receipt
    })
    .await;

    if let Err(e) = result {
        error!("Failed to write action receipt: {:?}", e);
    }
}

/// Decision label for a receipt recording a detected integrity violation (T-D:
/// attacks on the evidence chain). A tamper-attempt receipt is appended to the same
/// hash chain as normal decisions so the chain itself records the attack — storing
/// ONLY hashes, never payloads.
const TAMPER_DECISION: &str = "tamper_attempt";

/// Append a tamper-attempt record to a tenant's receipt chain when the gateway
/// detects an integrity violation (an approval `action_hash` mismatch, or a consume
/// of an already-used / expired approval). Reuses the atomic, hash-chained receipt
/// machinery so the attack is tamper-evidently recorded. `kind` is a short, stable
/// tag for the violation; `action_hash` is the bound hash (never a payload). Also
/// mirrors the event into the audit log. Best-effort: a write failure is logged and
/// does not change the caller's response.
async fn emit_tamper_attempt_receipt(
    pool: &sqlx::SqlitePool,
    events: &EventSink,
    tenant_id: &str,
    agent_id: Option<&str>,
    kind: &str,
    approval_id: &str,
    action_hash: Option<String>,
) {
    let kind_owned = kind.to_string();
    let action_hash_for_receipt = action_hash.clone();
    let result = db::append_action_receipt_atomic(pool, tenant_id, |prev_receipt_hash| {
        let mut receipt = ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: None,
            ts: Utc::now().to_rfc3339(),
            agent_id: None,
            user_id: None,
            run_id: None,
            trace_id: None,
            // `tool`/`resource` carry only the violation tag + approval id (no payload).
            tool: Some(kind_owned.clone()),
            action: Some(TAMPER_DECISION.to_string()),
            resource: Some(format!("approval:{}", approval_id)),
            source_trust: "malicious_suspected".to_string(),
            decision: TAMPER_DECISION.to_string(),
            approver: None,
            action_hash: action_hash_for_receipt,
            prev_receipt_hash,
            receipt_hash: String::new(),
            signature: None,
            signer_public_key: None,
            created_at: Utc::now(),
        };
        // Hash FIRST (byte-parity-locked), then optionally sign OVER the hash.
        receipt.receipt_hash = compute_receipt_hash(&receipt);
        apply_receipt_signature(&mut receipt);
        receipt
    })
    .await;

    if let Err(e) = result {
        error!("Failed to write tamper-attempt receipt: {:?}", e);
        return;
    }

    // Mirror to the audit log (hashes only — never payloads).
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: "tamper_attempt".to_string(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: Some(kind.to_string()),
        resource: Some(format!("approval:{}", approval_id)),
        event_json: serde_json::to_string(&json!({
            "kind": kind,
            "approval_id": approval_id,
            "action_hash": action_hash,
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    if let Err(e) = db::insert_audit_event(pool, &audit_record).await {
        error!("Failed to write tamper-attempt audit event: {:?}", e);
    }

    // Integrity→SOC loop: the tamper-evident receipt now also surfaces on the async
    // SOC stream as a `replay_attempt` AseEvent so the detector raises a HIGH alert
    // (visible in `GET /v1/alerts`), not only in the receipt chain. STRICTLY
    // ADDITIVE: this runs only after the receipt write above succeeded, and the
    // emit is NON-BLOCKING (`try_send`) — a full/closed channel is dropped and never
    // affects the caller's 409/CONFLICT response. Carries ids + the violation tag
    // only (no payloads); tenant-scoped.
    events.emit(AseEvent {
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        tenant_id: tenant_id.to_string(),
        kind: "replay_attempt".to_string(),
        agent_id: agent_id.unwrap_or("unknown").to_string(),
        decision: "deny".to_string(),
        tool: kind.to_string(),
        action: TAMPER_DECISION.to_string(),
        resource: Some(format!("approval:{}", approval_id)),
        risk_score: 0,
        reason: format!(
            "approval-integrity violation: {} (approval:{})",
            kind, approval_id
        ),
        run_id: None,
        trace_id: None,
        matched_policies: Vec::new(),
    });
}

/// True if the approval window has passed. Defense-in-depth alongside the SDK's
/// client-side expiry check: the gateway must not hand out, or grant, an approval
/// whose `expires_at` is in the past.
fn approval_is_expired(app: &ApprovalRecord) -> bool {
    app.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
async fn write_decision_and_audit(
    pool: &sqlx::SqlitePool,
    events: &EventSink,
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

    // Phase 0 keystone: feed the async SOC stream. Non-blocking — the inline
    // decision has already been recorded above; emission never delays the caller.
    events.emit(AseEvent {
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        tenant_id: tenant_id.to_string(),
        kind: "authorize_decision".to_string(),
        agent_id: agent_id.to_string(),
        decision: decision.to_string(),
        tool: payload.tool_call.tool.clone(),
        action: payload.tool_call.action.clone(),
        resource: payload.tool_call.resource.clone(),
        risk_score,
        reason: reason.to_string(),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        matched_policies: matched_policies.to_vec(),
    });

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
            return (
                StatusCode::OK,
                Json(RegisterAgentResponse {
                    id,
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

/// GET /v1/mcp/servers — tenant-scoped list of registered MCP servers with their
/// current `status` (incl. `quarantined`) and pinned `manifest_hash`. Read-only;
/// lets an operator (or the SOC console) triage a `mcp_manifest_drift` alert by
/// seeing which servers are quarantined / drifted and acting via the
/// quarantine/restore endpoints.
pub async fn list_mcp_servers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::list_mcp_servers(&state.pool, &tenant_id).await {
        Ok(servers) => (StatusCode::OK, Json(servers)).into_response(),
        Err(e) => {
            error!("Failed to list MCP servers: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
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

    // MCP tool-manifest drift detection (SOC `mcp_manifest_drift`). Pin the manifest
    // hash on first discovery; on a later discovery whose hash differs from the pin,
    // surface a drift event on the async SOC stream and re-pin to the new value (so
    // each distinct change alerts exactly once). STRICTLY ADDITIVE and best-effort:
    // any DB error here is logged and never blocks the discovery response, and the
    // SOC emit is non-blocking (`try_send`). Carries the server key + hashes only —
    // never any tool payload.
    let new_manifest_hash = compute_mcp_manifest_hash(&payload.tools);
    match db::get_mcp_server_manifest_hash(&state.pool, &tenant_id, &server_key).await {
        Ok(pinned) => {
            if !pinned.is_empty() && pinned != new_manifest_hash {
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
                    risk_score: 0,
                    reason: format!(
                        "MCP tool-manifest drift on server '{}': pinned {} != observed {}",
                        server_key, pinned, new_manifest_hash
                    ),
                    run_id: None,
                    trace_id: None,
                    matched_policies: Vec::new(),
                });

                // Fail-closed response (Phase 4): drift is a tool-hijack signal, so
                // auto-quarantine the server. The inline authorize gate above then
                // denies every tool call until an operator verifies the new manifest
                // out-of-band and explicitly restores the server. Best-effort: a DB
                // error is logged and never blocks the discovery response.
                if let Err(e) =
                    db::set_mcp_server_status(&state.pool, &tenant_id, &server_key, "quarantined")
                        .await
                {
                    error!("Failed to auto-quarantine drifted MCP server: {:?}", e);
                }
            }
            if pinned != new_manifest_hash {
                if let Err(e) = db::set_mcp_server_manifest_hash(
                    &state.pool,
                    &tenant_id,
                    &server_key,
                    &new_manifest_hash,
                )
                .await
                {
                    error!("Failed to pin MCP manifest hash: {:?}", e);
                }
            }
        }
        Err(e) => error!("Failed to read pinned MCP manifest hash: {:?}", e),
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
        // Fail-closed server-level gate (Phase 4 response enforcement). A
        // quarantined MCP server — whether quarantined by an operator or
        // auto-quarantined on tool-manifest drift — denies ALL of its tool calls
        // inline, regardless of any tool's prior approved status. Without this,
        // quarantine was recorded but never enforced on the authorize hot path.
        match db::get_mcp_server_by_key(&state.pool, &tenant_id, server_key).await {
            Ok(Some(server)) if server.status == "quarantined" => {
                let decision_id = Uuid::new_v4();
                let reason = format!(
                    "MCP server '{}' is quarantined; all tool calls are denied (fail-closed).",
                    server_key
                );
                let matched_policies = vec!["mcp_server_quarantined".to_string()];
                risk_level = "critical".to_string();
                risk_score = 100;

                if let Err(e) = write_decision_and_audit(
                    &state.pool,
                    &state.events,
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
                    error!("Failed to write quarantined-server denial: {:?}", e);
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
            Ok(_) => {}
            Err(e) => {
                error!("Failed to look up MCP server status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        }

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
                        &state.events,
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
                    &state.events,
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

    // Security metric: provenance_denials_total — count Cedar-level denials driven by
    // untrusted/malicious/unknown provenance on a mutating action (anti-confused-deputy).
    if decision_str == "deny"
        && payload.tool_call.mutates_state
        && is_untrusted_provenance(&payload.context.source_trust)
    {
        state.metrics.inc_provenance_denial();
    }

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
        &state.events,
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

    // Emit a verifiable, hash-chained receipt for this decision (non-fatal).
    emit_action_receipt(
        &state.pool,
        &tenant_id,
        &agent_id,
        &payload,
        decision_id,
        &decision_str,
    )
    .await;

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

/// Optional body for the consume endpoint. If `claimed_action_hash` is supplied,
/// the gateway validates it against the bound hash and increments
/// `approval_hash_mismatch_total` on a discrepancy (approve-then-swap defence).
#[derive(Debug, serde::Deserialize, Default)]
pub struct ConsumeApprovalBody {
    pub claimed_action_hash: Option<String>,
}

// Consume Handler: single-use, atomic consumption of an APPROVED approval.
// The SDK calls this before executing so an approval cannot be replayed/reused.
pub async fn consume_approval(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(approval_id): Path<Uuid>,
    // JSON body is optional; old callers that POST with no body still work.
    body: Option<Json<ConsumeApprovalBody>>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let consumed =
        match db::consume_approval(&state.pool, &tenant_id, &approval_id.to_string()).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to consume approval: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Database error"})),
                )
                    .into_response();
            }
        };

    if !consumed {
        // A consume of an already-used / expired / not-approved approval is an
        // attack on the evidence chain (replay / T-D): record it as a tamper-attempt
        // receipt so the chain itself captures the attempt. Hashes only, no payloads.
        let bound_hash = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .ok()
            .flatten()
            .map(|a| a.original_call_hash);
        // The approval record does not carry the agent id; the SOC event uses the
        // "unknown" placeholder (the violation tag + approval id are the evidence).
        emit_tamper_attempt_receipt(
            &state.pool,
            &state.events,
            &tenant_id,
            None,
            "consume_not_consumable",
            &approval_id.to_string(),
            bound_hash,
        )
        .await;
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "Approval not consumable (already used, expired, or not approved)",
                "approval_id": approval_id,
            })),
        )
            .into_response();
    }

    // Return the bound action hash so the SDK can re-verify before executing.
    let action_hash = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
        .await
        .ok()
        .flatten()
        .map(|a| a.original_call_hash)
        .unwrap_or_default();

    // Security metric: if the caller supplied a claimed_action_hash, compare it
    // against the bound hash. A mismatch means an approve-then-swap was attempted.
    if let Some(Json(ref b)) = body {
        if let Some(ref claimed) = b.claimed_action_hash {
            if *claimed != action_hash {
                state.metrics.inc_hash_mismatch();
                error!(
                    approval_id = %approval_id,
                    "approval_hash_mismatch: claimed hash does not match bound hash"
                );
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "Action hash mismatch: the action to be executed differs from the approved action",
                        "approval_id": approval_id,
                    })),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "consumed",
            "approval_id": approval_id,
            "action_hash": action_hash,
        })),
    )
        .into_response()
}

// Verify a stored action receipt by recomputing its hash from the canonical body.
pub async fn verify_receipt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(receipt_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::get_action_receipt_by_id(&state.pool, &tenant_id, &receipt_id).await {
        Ok(Some(rec)) => {
            // Hash (chain) integrity — UNCHANGED. This is the byte-parity-locked check.
            let recomputed = compute_receipt_hash(&rec);
            let verified = recomputed == rec.receipt_hash;

            // Optional signature verification — ADDITIVE, never affects `verified`.
            // signed   -> signature_verified = true/false (Ed25519 over receipt_hash)
            // unsigned -> signature_verified = null (no signer was configured)
            let signature_verified = match (&rec.signature, &rec.signer_public_key) {
                (Some(sig), Some(pk)) => {
                    Value::Bool(sign::verify_signature(pk, &rec.receipt_hash, sig))
                }
                _ => Value::Null,
            };

            (
                StatusCode::OK,
                Json(json!({
                    "receipt_id": rec.id,
                    "verified": verified,
                    "receipt_hash": rec.receipt_hash,
                    "recomputed_hash": recomputed,
                    "prev_receipt_hash": rec.prev_receipt_hash,
                    "signed": rec.signature.is_some(),
                    "signature_verified": signature_verified,
                    "signer_public_key": rec.signer_public_key,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Receipt not found"})),
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

    // Fail closed if the approval window has already passed. Granting an expired
    // approval is an attack on the evidence chain (T-D); record the attempt as a
    // tamper-attempt receipt (hashes only) before refusing.
    if approval_is_expired(&approval) {
        emit_tamper_attempt_receipt(
            &state.pool,
            &state.events,
            &tenant_id,
            None,
            "approve_expired",
            &approval_id.to_string(),
            Some(approval.original_call_hash.clone()),
        )
        .await;
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

// ── SOC Phase 5: Indexer Query API ───────────────────────────────────────────

/// Parse a `?limit=` / `?offset=` query string with sane defaults and hard caps.
/// Avoids extracting `axum::extract::Query<HashMap<…>>` to keep the code simple;
/// falls back to the default on any parse error.
fn parse_pagination(query: Option<&str>) -> (i64, i64) {
    let mut limit = db::SOC_DEFAULT_LIMIT;
    let mut offset = 0i64;

    if let Some(q) = query {
        for pair in q.split('&') {
            let mut kv = pair.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("limit"), Some(v)) => {
                    if let Ok(n) = v.parse::<i64>() {
                        limit = n;
                    }
                }
                (Some("offset"), Some(v)) => {
                    if let Ok(n) = v.parse::<i64>() {
                        offset = n.max(0);
                    }
                }
                _ => {}
            }
        }
    }
    (limit.clamp(1, db::SOC_MAX_LIMIT), offset)
}

/// Parse an optional equality filter value from a raw query string.
/// Returns `Some(value)` only when the key is present and non-empty; combined
/// with the `(? IS NULL OR col = ?)` SQL pattern this keeps all SQL strings
/// STATIC and avoids any concatenation (CWE-89 safe).
fn parse_filter(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let mut kv = pair.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some(k), Some(v)) if k == key && !v.is_empty() => Some(v.to_string()),
            _ => None,
        }
    })
}

/// GET /v1/alerts — list SOC detection alerts for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `severity` — optional equality filter (e.g. `?severity=high`).
///   `agent_id`  — optional equality filter (e.g. `?agent_id=abc`).
/// Returns a JSON array of [`SocAlertRecord`]s ordered newest-first.
/// Every result row is tenant-scoped via parameterized SQL — never leaks
/// another tenant's data.
pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let (limit, offset) = parse_pagination(raw_query.as_deref());
    let severity = parse_filter(raw_query.as_deref(), "severity");
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");

    match db::list_soc_alerts(
        &state.pool,
        &tenant_id,
        limit,
        offset,
        severity.as_deref(),
        agent_id.as_deref(),
    )
    .await
    {
        Ok(alerts) => (StatusCode::OK, Json(alerts)).into_response(),
        Err(e) => {
            error!("Failed to list SOC alerts: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// GET /v1/incidents — list SOC correlation incidents for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `status`   — optional filter: `"open"` or `"closed"` (omit for all).
///   `severity` — optional equality filter (e.g. `?severity=high`).
///   `agent_id` — optional equality filter (e.g. `?agent_id=abc`).
/// Returns a JSON array of [`SocIncidentRecord`]s ordered newest-first.
/// Every result row is tenant-scoped via parameterized SQL — never leaks
/// another tenant's data.
pub async fn list_incidents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let (limit, offset) = parse_pagination(raw_query.as_deref());
    let status_filter = parse_filter(raw_query.as_deref(), "status");
    let severity = parse_filter(raw_query.as_deref(), "severity");
    let agent_id = parse_filter(raw_query.as_deref(), "agent_id");

    match db::list_soc_incidents(
        &state.pool,
        &tenant_id,
        limit,
        offset,
        status_filter.as_deref(),
        severity.as_deref(),
        agent_id.as_deref(),
    )
    .await
    {
        Ok(incidents) => (StatusCode::OK, Json(incidents)).into_response(),
        Err(e) => {
            error!("Failed to list SOC incidents: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// ── SOC query layer: incident detail + aggregate summary ─────────────────────

/// `GET /v1/incidents/:id` — single-incident detail, tenant-scoped.
///
/// Returns the full [`SocIncidentRecord`] for the given `id` when it belongs to
/// the authenticated tenant, or HTTP 404 when the `id` is unknown **or** belongs
/// to a different tenant (CWE-284: no information leakage across tenants).
/// Both DB binds (`tenant_id`, `incident_id`) are parameterized — no SQL
/// concatenation (CWE-89).
pub async fn get_incident(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(incident)) => (StatusCode::OK, Json(incident)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Incident not found"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to fetch SOC incident {}: {:?}", incident_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

/// `GET /v1/soc/summary` — tenant-scoped SOC aggregate counts.
///
/// Returns `{ alerts_total, alerts_high, incidents_total, incidents_open,
/// incidents_closed }` derived from five parameterized COUNT queries, all
/// binding `tenant_id` (CWE-284).  `alerts_high` counts alerts with
/// `severity = 'high'`; open/closed split on the incident `status` column.
/// No SQL concatenation occurs (CWE-89).
pub async fn soc_summary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::soc_summary(&state.pool, &tenant_id).await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => {
            error!("Failed to compute SOC summary: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response()
        }
    }
}

// ── SOC Phase 6: Incident lifecycle ──────────────────────────────────────────

/// `POST /v1/incidents/:id/close` — close an open SOC incident.
///
/// Transitions the incident from `"open"` to `"closed"`, stamps `closed_at`,
/// and writes an `"incident_closed"` audit event. Tenant-scoped: 404 if the
/// incident does not exist for this tenant. Idempotent on a second call: a
/// 200 response is returned with `"already_closed": true` so callers can
/// distinguish the first close from a repeat without erroring.
///
/// # Security invariants
/// * Two parameterized binds on every DB call (`tenant_id` + `id`).
/// * No payload fields in the audit event — only the incident id and new status.
/// * `close_soc_incident` uses `AND status != 'closed'` to make the UPDATE
///   idempotent at the DB level; concurrent closes are safe.
pub async fn close_incident(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // First verify the incident exists for this tenant (provides a meaningful 404
    // rather than a silent no-op when the id is simply wrong or belongs to another
    // tenant — CWE-284 isolation).
    let incident = match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(inc)) => inc,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Incident not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident for close: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    // If already closed, return a clear idempotent response (200 with a flag).
    if incident.status == "closed" {
        return (
            StatusCode::OK,
            Json(json!({
                "incident_id": incident.id,
                "status": "closed",
                "closed_at": incident.closed_at,
                "already_closed": true,
            })),
        )
            .into_response();
    }

    // Atomically flip status → 'closed' and stamp closed_at.
    let did_close = match db::close_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to close incident {}: {:?}", incident_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if !did_close {
        // Race: incident was closed between the get and the update. Treat as
        // idempotent — re-fetch to return the correct closed_at.
        return match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
            Ok(Some(inc)) => (
                StatusCode::OK,
                Json(json!({
                    "incident_id": inc.id,
                    "status": "closed",
                    "closed_at": inc.closed_at,
                    "already_closed": true,
                })),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response(),
        };
    }

    // Re-fetch to pick up the DB-stamped `closed_at` timestamp.
    let closed_at = match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(inc)) => inc.closed_at,
        Ok(None) => None,
        Err(e) => {
            error!("Failed to re-fetch incident after close: {:?}", e);
            None
        }
    };

    // Write audit event (hashes / ids only — no payloads, no raw evidence).
    let audit = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_type: "incident_closed".to_string(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: None,
        resource: Some(incident_id.clone()),
        event_json: serde_json::to_string(&json!({
            "incident_id": incident_id,
            "new_status": "closed",
        }))
        .unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        created_at: Utc::now(),
    };
    let _ = db::insert_audit_event(&state.pool, &audit).await;

    info!(incident_id = %incident_id, "SOC incident closed");

    (
        StatusCode::OK,
        Json(json!({
            "incident_id": incident_id,
            "status": "closed",
            "closed_at": closed_at,
            "already_closed": false,
        })),
    )
        .into_response()
}

// ── SOC Phase 6: RCA Narrator ────────────────────────────────────────────────

/// GET /v1/incidents/:id/narrate — on-demand RCA narrative for a closed incident.
///
/// # LAW-2 compliance
/// * On-demand only — never called from the authorize / drain hot paths.
/// * Tenant-scoped db fetch (two parameterized binds: tenant_id + id).
/// * 404 if the incident does not exist **or** belongs to a different tenant.
/// * The [`crate::narrate`] module builds the narrative from structured,
///   already-redacted fields only — never raw evidence or live telemetry.
/// * The narrator is constructed inside the handler (no AppState mutation).
pub async fn narrate_incident(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(incident_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let incident = match db::get_soc_incident(&state.pool, &tenant_id, &incident_id).await {
        Ok(Some(inc)) => inc,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Incident not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch incident for narration: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    // Construct narrator from env — hermetic template by default, optional Claude.
    // Never touches AppState; no network call in the default path.
    let narrator = crate::narrate::from_env();
    let narrative = narrator.narrate(&incident);

    info!(incident_id = %incident_id, "RCA narrative generated");

    (
        StatusCode::OK,
        Json(json!({
            "incident_id": incident.id,
            "narrative": narrative,
        })),
    )
        .into_response()
}

// ── SOC Phase 4: Response API ─────────────────────────────────────────────────

/// Freeze an agent: all subsequent /v1/authorize calls for this agent will be
/// denied immediately without Cedar evaluation. Reversible via /unfreeze.
pub async fn freeze_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, headers, agent_id, "frozen").await
}

/// Restore a frozen agent to active status.
pub async fn unfreeze_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, headers, agent_id, "active").await
}

/// Permanently revoke an agent — not reversible via API.
pub async fn revoke_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    set_agent_operational_status(state, headers, agent_id, "revoked").await
}

async fn set_agent_operational_status(
    state: Arc<AppState>,
    headers: HeaderMap,
    agent_id: String,
    status: &str,
) -> axum::response::Response {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

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

/// Quarantine an MCP server — the gateway will deny all tool calls from this
/// server until it is restored. Tenant-scoped, parameterized, fail-closed.
pub async fn quarantine_mcp_server(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    update_mcp_server_quarantine(state, headers, server_key, "quarantined").await
}

/// Restore a quarantined MCP server to active status.
pub async fn restore_mcp_server(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(server_key): Path<String>,
) -> impl IntoResponse {
    update_mcp_server_quarantine(state, headers, server_key, "active").await
}

async fn update_mcp_server_quarantine(
    state: Arc<AppState>,
    headers: HeaderMap,
    server_key: String,
    status: &str,
) -> axum::response::Response {
    let tenant_id = match get_tenant_from_headers(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    match db::set_mcp_server_status(&state.pool, &tenant_id, &server_key, status).await {
        Ok(true) => {
            let audit = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                event_type: format!("mcp_server_{}", status),
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
                    "new_status": status,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                created_at: Utc::now(),
            };
            let _ = db::insert_audit_event(&state.pool, &audit).await;
            info!(server_key = %server_key, status = %status, "MCP server status changed");
            (
                StatusCode::OK,
                Json(json!({ "server_key": server_key, "status": status })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "MCP server not found" })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update MCP server status: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events;
    use axum::body::to_bytes;
    use tokio::sync::mpsc;

    async fn setup_state(test_name: &str) -> (Arc<AppState>, String, String) {
        let (state, tenant_id, agent_token, events_rx) = setup_state_with_events(test_name).await;
        // Drain in the background so existing tests are unaffected by the stream.
        // Phase 5: pass pool.clone() so the drain can persist alerts + incidents.
        tokio::spawn(events::drain(events_rx, state.pool.clone()));
        (state, tenant_id, agent_token)
    }

    async fn setup_state_with_events(
        test_name: &str,
    ) -> (Arc<AppState>, String, String, mpsc::Receiver<AseEvent>) {
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
        let (events, events_rx) = EventSink::channel(events::DEFAULT_CAPACITY);
        let state = Arc::new(AppState {
            pool,
            policy_engine,
            events,
            metrics: crate::metrics::SecurityMetrics::new(),
        });

        (state, tenant_id, agent_token, events_rx)
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

    #[tokio::test]
    async fn authorize_emits_security_event() {
        // Phase 0 keystone: every authorize decision must feed the async SOC
        // stream, non-blocking. We keep the receiver and assert the decision
        // surfaces as exactly one AseEvent — the spine every later SOC phase
        // (detection, correlation, response, indexing) consumes.
        let (state, tenant_id, agent_token, mut events_rx) =
            setup_state_with_events("emits_security_event").await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let event = events_rx
            .try_recv()
            .expect("authorize must emit exactly one ASE event onto the SOC stream");
        assert_eq!(event.kind, "authorize_decision");
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.decision, response.decision);
        assert_eq!(event.tool, "filesystem");
        assert_eq!(event.action, "read_file");
        assert_eq!(event.run_id.as_deref(), Some("run_routes"));
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
            let tool_call: AuthorizeToolCall = serde_json::from_value(vector["tool_call"].clone())
                .unwrap_or_else(|e| panic!("vector {name}: tool_call must deserialize: {e}"));

            let produced = canonical_action_string(&tool_call);
            let expected = vector["canonical"].as_str().unwrap();
            assert_eq!(
                produced, expected,
                "vector {name}: canonical string mismatch"
            );

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
        let corpus_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/receipt_chain_vectors.json"
        );
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
    async fn consume_is_single_use() {
        let (state, tenant_id, agent_token) = setup_state("consume_single_use").await;

        // Create an approval (merge to main) and approve it.
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/9".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        // First consume succeeds.
        let first = consume_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        // Second consume is rejected — single-use.
        let second = consume_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn authorize_emits_verifiable_receipt() {
        let (state, tenant_id, agent_token) = setup_state("emit_receipt").await;

        // Any decision (here a read-only allow) must emit a receipt.
        let mut request = mcp_authorize_request("github", "read_issue");
        request.tool_call.mutates_state = false;
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let (receipt_id,): (String,) = sqlx::query_as(
            "SELECT id FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .expect("a receipt should have been emitted for the decision");

        // The /verify endpoint recomputes the hash and confirms integrity.
        let response = verify_receipt(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(receipt_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(true));
        assert_eq!(json["receipt_id"].as_str(), Some(receipt_id.as_str()));
        // Hermetic default: no signing key configured → unsigned.
        // signature_verified is null and `signed` is false; hash `verified` unchanged.
        assert_eq!(json["signed"].as_bool(), Some(false));
        assert!(json["signature_verified"].is_null());
    }

    // A fixed test secret (hex, 32 bytes). Test-only — not a real key. Used to
    // emit a signed receipt directly via the atomic appender (so we exercise the
    // verify endpoint's signature path without coupling to the process-global env
    // signer, which `OnceLock`-initializes once per process).
    const TEST_SIGNING_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn unsigned_receipt_template(tenant_id: &str) -> ActionReceiptRecord {
        ActionReceiptRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(Uuid::new_v4().to_string()),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some("signing-agent".to_string()),
            user_id: None,
            run_id: None,
            trace_id: None,
            tool: Some("github".to_string()),
            action: Some("merge_pull_request".to_string()),
            resource: Some("payments#1".to_string()),
            source_trust: "trusted_internal_signed".to_string(),
            decision: "allow".to_string(),
            approver: None,
            action_hash: Some("aaaa".to_string()),
            prev_receipt_hash: String::new(),
            receipt_hash: String::new(),
            signature: None,
            signer_public_key: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn verify_reports_signature_for_a_signed_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("signed_receipt").await;
        let signer = sign::ReceiptSigner::from_secret_hex(TEST_SIGNING_SECRET_HEX).unwrap();

        // Insert a signed receipt through the real atomic appender. Hash FIRST over
        // the live chain head, then sign OVER that hash (additive metadata).
        let rec = db::append_action_receipt_atomic(&state.pool, &tenant_id, |prev| {
            let mut r = unsigned_receipt_template(&tenant_id);
            r.prev_receipt_hash = prev;
            r.receipt_hash = compute_receipt_hash(&r);
            r.signature = Some(signer.sign_hash(&r.receipt_hash));
            r.signer_public_key = Some(signer.public_key_hex());
            r
        })
        .await
        .expect("signed receipt insert");

        let response = verify_receipt(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Hash integrity unchanged AND signature verifies.
        assert_eq!(json["verified"].as_bool(), Some(true));
        assert_eq!(json["signed"].as_bool(), Some(true));
        assert_eq!(json["signature_verified"].as_bool(), Some(true));
        assert_eq!(
            json["signer_public_key"].as_str(),
            Some(signer.public_key_hex().as_str())
        );
    }

    #[test]
    fn signing_does_not_perturb_receipt_hash() {
        // BYTE-PARITY GUARD: compute_receipt_hash must be identical whether or not
        // the signature/signer fields are populated. The signature sits OVER the
        // hash; it is never an input to it.
        let signer = sign::ReceiptSigner::from_secret_hex(TEST_SIGNING_SECRET_HEX).unwrap();

        let mut unsigned = ActionReceiptRecord {
            id: "rcpt_parity".to_string(),
            tenant_id: "t".to_string(),
            decision_id: None,
            ts: "2026-06-02T12:00:00Z".to_string(),
            agent_id: Some("a".to_string()),
            user_id: None,
            run_id: None,
            trace_id: None,
            tool: Some("github".to_string()),
            action: Some("merge_pull_request".to_string()),
            resource: Some("payments#1".to_string()),
            source_trust: "trusted_internal_signed".to_string(),
            decision: "allow".to_string(),
            approver: None,
            action_hash: Some("aaaa".to_string()),
            prev_receipt_hash: String::new(),
            receipt_hash: String::new(),
            signature: None,
            signer_public_key: None,
            created_at: Utc::now(),
        };
        let hash_unsigned = compute_receipt_hash(&unsigned);

        // Populate the signature fields and re-hash: the hash MUST be unchanged.
        unsigned.signature = Some(signer.sign_hash(&hash_unsigned));
        unsigned.signer_public_key = Some(signer.public_key_hex());
        let hash_signed = compute_receipt_hash(&unsigned);

        assert_eq!(
            hash_unsigned, hash_signed,
            "signing must not change the receipt hash (byte-parity moat)"
        );
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
            agent_headers(&tenant_id, &tenant_id),
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
            agent_headers(&tenant_id, &tenant_id),
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

    // T-D hardening (a): concurrent appends must keep a tenant's receipt chain
    // strictly linear. If head-select + insert were not atomic, two racing tasks
    // could read the same head and fork the chain (two receipts sharing one
    // `prev_receipt_hash`). We append from many tokio tasks at once and assert the
    // resulting chain is a single unbroken line with no duplicated prev-hash.
    #[tokio::test]
    async fn concurrent_receipt_appends_stay_linear() {
        let (state, tenant_id, _agent_token) = setup_state("concurrent_chain").await;

        const TASKS: usize = 24;
        let mut handles = Vec::with_capacity(TASKS);
        for i in 0..TASKS {
            let pool = state.pool.clone();
            let tenant = tenant_id.clone();
            handles.push(tokio::spawn(async move {
                db::append_action_receipt_atomic(&pool, &tenant, |prev| {
                    let mut rec = ActionReceiptRecord {
                        id: Uuid::new_v4().to_string(),
                        tenant_id: tenant.clone(),
                        decision_id: Some(Uuid::new_v4().to_string()),
                        ts: Utc::now().to_rfc3339(),
                        agent_id: Some("concurrency-agent".to_string()),
                        user_id: None,
                        run_id: None,
                        trace_id: None,
                        tool: Some("github".to_string()),
                        action: Some(format!("op_{}", i)),
                        resource: None,
                        source_trust: "trusted_internal_signed".to_string(),
                        decision: "allow".to_string(),
                        approver: None,
                        action_hash: Some(format!("sha256:dead{:04}", i)),
                        prev_receipt_hash: prev,
                        receipt_hash: String::new(),
                        signature: None,
                        signer_public_key: None,
                        created_at: Utc::now(),
                    };
                    rec.receipt_hash = compute_receipt_hash(&rec);
                    rec
                })
                .await
            }));
        }
        for h in handles {
            h.await.unwrap().expect("atomic append must succeed");
        }

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT prev_receipt_hash, receipt_hash FROM action_receipts
             WHERE tenant_id = ? ORDER BY rowid ASC",
        )
        .bind(tenant_id.as_str())
        .fetch_all(&state.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), TASKS, "every append must commit exactly once");

        let mut seen_prev = std::collections::HashSet::new();
        let mut seen_receipt = std::collections::HashSet::new();
        let mut expected_prev = String::new();
        for (prev, receipt) in &rows {
            assert_eq!(
                prev, &expected_prev,
                "fork detected: prev-hash does not chain to the prior receipt"
            );
            assert!(
                seen_prev.insert(prev.clone()),
                "fork detected: duplicate prev_receipt_hash {}",
                prev
            );
            assert!(
                seen_receipt.insert(receipt.clone()),
                "duplicate receipt_hash {}",
                receipt
            );
            expected_prev = receipt.clone();
        }
    }

    // T-D hardening (b): a consume of an already-used approval is a replay attack on
    // the evidence chain. The gateway must record a tamper-attempt receipt (hashes
    // only, no payloads) so the chain captures the attempt, and still return 409.
    #[tokio::test]
    async fn replay_consume_emits_tamper_receipt() {
        let (state, tenant_id, agent_token) = setup_state("tamper_consume").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/11".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let first = consume_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let (before,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ?",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(before, 0);

        let replay = consume_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        let recs: Vec<ActionReceiptRecord> = sqlx::query_as(
            "SELECT * FROM action_receipts WHERE tenant_id = ? AND decision = ? ORDER BY rowid ASC",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_all(&state.pool)
        .await
        .unwrap();
        assert_eq!(recs.len(), 1, "exactly one tamper receipt for the replay");
        let tamper = &recs[0];
        assert_eq!(tamper.receipt_hash, compute_receipt_hash(tamper));
        assert!(!tamper.prev_receipt_hash.is_empty(), "must chain onto head");
        assert_eq!(tamper.tool.as_deref(), Some("consume_not_consumable"));
        assert_eq!(
            tamper.resource.as_deref(),
            Some(format!("approval:{}", approval_id).as_str())
        );

        let (audit_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND event_type = 'tamper_attempt'",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);
    }

    // Integrity→SOC loop: a replay (consume of an already-consumed approval) must
    // STILL return 409 and STILL write exactly one tamper receipt (unchanged) AND
    // now ALSO emit a `replay_attempt` AseEvent onto the SOC stream so the detector
    // can raise a HIGH alert. We keep the receiver (no drain spawned) and assert the
    // event lands — mirroring `authorize_emits_security_event`.
    #[tokio::test]
    async fn replay_consume_emits_replay_attempt_security_event() {
        let (state, tenant_id, agent_token, mut events_rx) =
            setup_state_with_events("tamper_consume_soc").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/13".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let first = consume_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        // The replay: a second consume of the now-used approval.
        let replay = consume_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        // 409 response is UNCHANGED.
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        // The tamper receipt is UNCHANGED — exactly one written for the replay.
        let (receipt_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ? AND tool = 'consume_not_consumable'",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            receipt_count, 1,
            "exactly one tamper receipt for the replay"
        );

        // NEW: a `replay_attempt` AseEvent must have landed on the SOC stream. Drain
        // the receiver (the earlier authorize_decision event is also queued since no
        // drain task consumes it in this harness) and find the replay event.
        let mut found_replay = false;
        while let Ok(ev) = events_rx.try_recv() {
            if ev.kind == "replay_attempt" {
                assert_eq!(ev.decision, "deny");
                assert_eq!(ev.tenant_id, tenant_id);
                assert_eq!(ev.tool, "consume_not_consumable");
                assert_eq!(
                    ev.resource.as_deref(),
                    Some(format!("approval:{}", approval_id).as_str())
                );
                found_replay = true;
            }
        }
        assert!(
            found_replay,
            "replay must emit a replay_attempt AseEvent onto the SOC stream"
        );
    }

    // T-D hardening (b): approving an expired approval is a detected integrity
    // violation; it must likewise leave a tamper-attempt receipt and return 409.
    #[tokio::test]
    async fn approve_expired_emits_tamper_receipt() {
        let (state, tenant_id, agent_token) = setup_state("tamper_approve_expired").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/12".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        let approve = approve_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::CONFLICT);

        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ? AND tool = 'approve_expired'",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            count, 1,
            "an expired-approval grant attempt must be recorded"
        );
    }

    // ── Security metrics tests ────────────────────────────────────────────────

    /// A mutating action from an untrusted-external source is denied by Cedar's
    /// "untrusted-mutation-forbid" rule AND increments `provenance_denials_total`.
    #[tokio::test]
    async fn provenance_denial_increments_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_denial_counter").await;

        let mut request = mcp_authorize_request("github", "push_commit");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "untrusted_external".to_string();

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            0,
            "counter must start at zero"
        );

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(
            response.decision, "deny",
            "untrusted mutating action must be denied"
        );

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            1,
            "provenance_denials_total must be 1 after one denied provenance"
        );

        let metrics_text = state.metrics.render_prometheus();
        assert!(
            metrics_text.contains("provenance_denials_total 1\n"),
            "metrics text must include updated counter value"
        );
        assert!(
            metrics_text.contains("# TYPE provenance_denials_total counter"),
            "metrics text must include TYPE declaration"
        );
    }

    /// All three untrusted levels increment the same counter.
    #[tokio::test]
    async fn provenance_denial_counter_accumulates() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_denial_accumulates").await;

        for trust in &["untrusted_external", "malicious_suspected", "unknown"] {
            let mut req = mcp_authorize_request("github", "delete_branch");
            req.tool_call.mutates_state = true;
            req.context.source_trust = (*trust).to_string();
            let resp = call_authorize(state.clone(), &tenant_id, &agent_token, req).await;
            assert_eq!(resp.decision, "deny");
        }

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            3,
            "all three untrusted trust levels must increment the counter"
        );
    }

    /// A trusted-internal mutating action that is ALLOWED must NOT increment the counter.
    #[tokio::test]
    async fn trusted_mutating_action_does_not_increment_provenance_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_no_increment").await;

        let mut req = mcp_authorize_request("github", "push_commit");
        req.tool_call.mutates_state = true;
        req.context.source_trust = "trusted_internal_signed".to_string();
        let resp = call_authorize(state.clone(), &tenant_id, &agent_token, req).await;
        assert_ne!(resp.decision, "deny");

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            0,
            "trusted mutating actions must not touch the provenance counter"
        );
    }

    /// Hash mismatch on consume_approval increments approval_hash_mismatch_total
    /// and returns 409 CONFLICT, blocking execution (approve-then-swap defence).
    #[tokio::test]
    async fn hash_mismatch_on_consume_increments_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("hash_mismatch_counter").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/99".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        assert_eq!(
            state
                .metrics
                .approval_hash_mismatch_total
                .load(Ordering::Relaxed),
            0
        );

        let mismatch_resp = consume_approval(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            Path(approval_id),
            Some(Json(ConsumeApprovalBody {
                claimed_action_hash: Some(
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ),
            })),
        )
        .await
        .into_response();
        assert_eq!(
            mismatch_resp.status(),
            StatusCode::CONFLICT,
            "hash mismatch must return 409"
        );

        assert_eq!(
            state
                .metrics
                .approval_hash_mismatch_total
                .load(Ordering::Relaxed),
            1,
            "approval_hash_mismatch_total must be 1 after one swap attempt"
        );
    }

    // ── SOC Phase 5: Indexer route tests ─────────────────────────────────────

    /// list_alerts returns an empty array when no alerts exist, not an error.
    #[tokio::test]
    async fn list_alerts_empty_when_no_alerts() {
        let (state, tenant_id, _agent_token) = setup_state("alerts_empty").await;

        let response = list_alerts(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    /// list_incidents returns an empty array when no incidents exist.
    #[tokio::test]
    async fn list_incidents_empty_when_no_incidents() {
        let (state, tenant_id, _agent_token) = setup_state("incidents_empty").await;

        let response = list_incidents(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    /// Inserting a SOC alert directly into the DB then calling list_alerts via the
    /// route returns that alert scoped to the correct tenant.
    #[tokio::test]
    async fn list_alerts_returns_tenant_scoped_alerts() {
        let (state, tenant_id, _agent_token) = setup_state("alerts_tenant_route").await;

        // Directly seed an alert for the tenant.
        let alert = crate::models::SocAlertRecord {
            id: "route_alert_1".to_string(),
            tenant_id: tenant_id.clone(),
            rule: "confused_deputy_block".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_route".to_string(),
            source_event_id: "evt_route_1".to_string(),
            summary: "Route test alert".to_string(),
            created_at: "2026-06-06T10:00:00Z".to_string(),
        };
        db::insert_soc_alert(&state.pool, &alert).await.unwrap();

        let response = list_alerts(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "route_alert_1");
        assert_eq!(arr[0]["rule"], "confused_deputy_block");
        assert_eq!(arr[0]["severity"], "high");
        assert_eq!(arr[0]["tenant_id"], tenant_id.as_str());
    }

    /// Inserting a SOC incident directly then calling list_incidents via the route
    /// returns it tenant-scoped.
    #[tokio::test]
    async fn list_incidents_returns_tenant_scoped_incidents() {
        let (state, tenant_id, _agent_token) = setup_state("incidents_tenant_route").await;

        let source_ids = serde_json::to_string(&vec!["evt_1", "evt_2"]).unwrap();
        let incident = crate::models::SocIncidentRecord {
            id: "route_inc_1".to_string(),
            tenant_id: tenant_id.clone(),
            kind: "deny_storm".to_string(),
            severity: "high".to_string(),
            agent_id: "agent_route".to_string(),
            summary: "Route test incident".to_string(),
            source_event_ids: source_ids.clone(),
            opened_at: "2026-06-06T10:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(&state.pool, &incident)
            .await
            .unwrap();

        let response = list_incidents(
            State(state.clone()),
            agent_headers(&tenant_id, &tenant_id),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], "route_inc_1");
        assert_eq!(arr[0]["kind"], "deny_storm");
        assert_eq!(arr[0]["tenant_id"], tenant_id.as_str());
    }

    /// parse_pagination caps limit at SOC_MAX_LIMIT and defaults correctly.
    #[test]
    fn parse_pagination_caps_and_defaults() {
        // No query string → defaults
        let (limit, offset) = parse_pagination(None);
        assert_eq!(limit, db::SOC_DEFAULT_LIMIT);
        assert_eq!(offset, 0);

        // Explicit small limit and offset
        let (limit, offset) = parse_pagination(Some("limit=10&offset=5"));
        assert_eq!(limit, 10);
        assert_eq!(offset, 5);

        // Exceeding max cap
        let (limit, _) = parse_pagination(Some("limit=99999"));
        assert_eq!(limit, db::SOC_MAX_LIMIT);

        // Zero limit → clamped to 1
        let (limit, _) = parse_pagination(Some("limit=0"));
        assert_eq!(limit, 1);

        // Negative offset → clamped to 0
        let (_, offset) = parse_pagination(Some("offset=-5"));
        assert_eq!(offset, 0);
    }

    // ── SOC Phase 6: narrate_incident route tests ─────────────────────────────

    /// Helper: insert a bare-minimum incident row for a tenant (no agent required).
    async fn insert_test_incident(
        pool: &sqlx::SqlitePool,
        tenant_id: &str,
        incident_id: &str,
        kind: &str,
    ) {
        let record = SocIncidentRecord {
            id: incident_id.to_string(),
            tenant_id: tenant_id.to_string(),
            kind: kind.to_string(),
            severity: "high".to_string(),
            agent_id: "agent-test".to_string(),
            summary: "Test incident for narration".to_string(),
            source_event_ids: serde_json::json!(["evt_a", "evt_b"]).to_string(),
            opened_at: "2026-06-06T12:00:00Z".to_string(),
            status: "open".to_string(),
            closed_at: None,
        };
        db::insert_soc_incident(pool, &record).await.unwrap();
    }

    #[tokio::test]
    async fn narrate_incident_returns_narrative_for_own_incident() {
        let (state, tenant_id, _agent_token) = setup_state("narrate_own").await;

        insert_test_incident(&state.pool, &tenant_id, "inc_narrate_1", "deny_storm").await;

        // Call the handler directly — same pattern used by all other route tests.
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );

        let response = narrate_incident(State(state), headers, Path("inc_narrate_1".to_string()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["incident_id"], "inc_narrate_1");
        let narrative = json["narrative"].as_str().unwrap();
        // Default template must include the incident kind.
        assert!(
            narrative.contains("deny_storm"),
            "narrative must contain kind"
        );
    }

    #[tokio::test]
    async fn narrate_incident_returns_404_for_other_tenants_incident() {
        let (state, tenant_id, _agent_token) = setup_state("narrate_isolation").await;

        // Register a second tenant and insert the incident under it.
        let other_tenant = "tenant_other_narrator";
        db::register_tenant(&state.pool, other_tenant, "Other", "developer")
            .await
            .unwrap();
        insert_test_incident(&state.pool, other_tenant, "inc_other", "deny_storm").await;

        // Authenticate as our tenant and try to fetch the other tenant's incident.
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );

        let response = narrate_incident(State(state), headers, Path("inc_other".to_string()))
            .await
            .into_response();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "must not expose another tenant's incident"
        );
    }

    // ── close_incident route tests ────────────────────────────────────────────

    /// Helper: close an incident via the route handler and parse the JSON body.
    async fn do_close(
        state: Arc<AppState>,
        tenant_id: &str,
        incident_id: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", tenant_id).parse().unwrap(),
        );
        let response = close_incident(State(state), headers, Path(incident_id.to_string()))
            .await
            .into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        (status, json)
    }

    /// `POST /v1/incidents/:id/close` returns 200 with `status: "closed"` and a
    /// non-null `closed_at` for a persisted open incident owned by the tenant.
    #[tokio::test]
    async fn close_incident_returns_closed_for_own_incident() {
        let (state, tenant_id, _) = setup_state("close_own").await;
        insert_test_incident(&state.pool, &tenant_id, "inc_close_route_1", "deny_storm").await;

        let (status, json) = do_close(state, &tenant_id, "inc_close_route_1").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "closed");
        assert_eq!(json["incident_id"], "inc_close_route_1");
        assert!(
            !json["closed_at"].is_null(),
            "closed_at must be set after close"
        );
        assert_eq!(json["already_closed"], false);
    }

    /// `POST /v1/incidents/:id/close` returns 404 when the incident id belongs
    /// to a different tenant — tenant-isolation (CWE-284).
    #[tokio::test]
    async fn close_incident_returns_404_for_other_tenants_incident() {
        let (state, tenant_id, _) = setup_state("close_iso").await;

        let other_tenant = "tenant_other_close_iso";
        db::register_tenant(&state.pool, other_tenant, "Other", "developer")
            .await
            .unwrap();
        insert_test_incident(&state.pool, other_tenant, "inc_other_close", "deny_storm").await;

        let (status, json) = do_close(state, &tenant_id, "inc_other_close").await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "must not expose another tenant's incident"
        );
        assert!(json["error"].as_str().is_some());
    }

    /// A second `POST /v1/incidents/:id/close` is idempotent — returns 200 with
    /// `already_closed: true` and the original `closed_at` unchanged.
    #[tokio::test]
    async fn close_incident_is_idempotent() {
        let (state, tenant_id, _) = setup_state("close_idempotent_route").await;
        insert_test_incident(&state.pool, &tenant_id, "inc_idem_route", "replay_attempt").await;

        let (s1, j1) = do_close(state.clone(), &tenant_id, "inc_idem_route").await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(j1["already_closed"], false);
        let first_closed_at = j1["closed_at"].as_str().unwrap().to_string();

        let (s2, j2) = do_close(state, &tenant_id, "inc_idem_route").await;
        assert_eq!(s2, StatusCode::OK, "second close must still be 200");
        assert_eq!(j2["already_closed"], true);
        assert_eq!(
            j2["closed_at"].as_str().unwrap(),
            first_closed_at,
            "closed_at must not change on second close"
        );
    }

    // ── SOC query layer: get_incident + soc_summary route tests ──────────────

    /// Helper: call GET /v1/incidents/:id and return (status, json body).
    async fn do_get_incident(
        state: Arc<AppState>,
        tenant_id: &str,
        incident_id: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = get_incident(
            State(state),
            agent_headers(tenant_id, tenant_id),
            Path(incident_id.to_string()),
        )
        .await
        .into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json)
    }

    /// GET /v1/incidents/:id returns 200 with the incident body for the owning tenant.
    #[tokio::test]
    async fn get_incident_returns_200_for_own_incident() {
        let (state, tenant_id, _) = setup_state("get_inc_own").await;
        insert_test_incident(&state.pool, &tenant_id, "inc_get_own", "deny_storm").await;

        let (status, json) = do_get_incident(state, &tenant_id, "inc_get_own").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["id"], "inc_get_own");
        assert_eq!(json["kind"], "deny_storm");
        assert_eq!(json["tenant_id"], tenant_id.as_str());
    }

    /// GET /v1/incidents/:id returns 404 for an unknown id.
    #[tokio::test]
    async fn get_incident_returns_404_for_unknown_id() {
        let (state, tenant_id, _) = setup_state("get_inc_missing").await;

        let (status, json) = do_get_incident(state, &tenant_id, "does_not_exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["error"].as_str().is_some());
    }

    /// GET /v1/incidents/:id returns 404 when the incident belongs to a different
    /// tenant — cross-tenant isolation (CWE-284).
    #[tokio::test]
    async fn get_incident_returns_404_cross_tenant() {
        let (state, tenant_id_a, _) = setup_state("get_inc_cross_tenant").await;
        // Register a second tenant and insert an incident under it.
        let tenant_id_b = format!("tenant_b_{}", uuid::Uuid::new_v4().simple());
        db::register_tenant(&state.pool, &tenant_id_b, "Tenant B", "developer")
            .await
            .unwrap();
        db::insert_soc_incident(
            &state.pool,
            &SocIncidentRecord {
                id: "inc_other_tenant".to_string(),
                tenant_id: tenant_id_b.clone(),
                kind: "deny_storm".to_string(),
                severity: "high".to_string(),
                agent_id: "agent-b".to_string(),
                summary: "B's incident".to_string(),
                source_event_ids: serde_json::json!(["e1"]).to_string(),
                opened_at: "2026-06-06T12:00:00Z".to_string(),
                status: "open".to_string(),
                closed_at: None,
            },
        )
        .await
        .unwrap();

        // tenant_a must get 404, not tenant_b's data.
        let (status, _) = do_get_incident(state, &tenant_id_a, "inc_other_tenant").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant incident must return 404"
        );
    }

    /// GET /v1/alerts?severity=high only returns high-severity alerts (route-level).
    #[tokio::test]
    async fn list_alerts_severity_filter_via_route() {
        let (state, tenant_id, _) = setup_state("alerts_sev_route").await;

        // Insert 1 high + 1 low alert.
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ra_high".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r1".to_string(),
                severity: "high".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt1".to_string(),
                summary: "High alert".to_string(),
                created_at: "2026-06-06T10:00:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ra_low".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r2".to_string(),
                severity: "low".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt2".to_string(),
                summary: "Low alert".to_string(),
                created_at: "2026-06-06T10:01:00Z".to_string(),
            },
        )
        .await
        .unwrap();

        let response = list_alerts(
            State(state),
            agent_headers(&tenant_id, &tenant_id),
            axum::extract::RawQuery(Some("severity=high".to_string())),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let arr: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 1, "only 1 high-severity alert");
        assert_eq!(arr[0]["id"], "ra_high");
        assert_eq!(arr[0]["severity"], "high");
    }

    /// GET /v1/soc/summary returns correct aggregate counts for the tenant.
    #[tokio::test]
    async fn soc_summary_returns_correct_counts() {
        let (state, tenant_id, _) = setup_state("soc_summary_route").await;

        // Seed: 2 alerts (1 high, 1 medium), 2 incidents (1 open, 1 closed).
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ss_a1".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r1".to_string(),
                severity: "high".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt1".to_string(),
                summary: "High".to_string(),
                created_at: "2026-06-06T10:00:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        db::insert_soc_alert(
            &state.pool,
            &SocAlertRecord {
                id: "ss_a2".to_string(),
                tenant_id: tenant_id.clone(),
                rule: "r2".to_string(),
                severity: "medium".to_string(),
                agent_id: "ag1".to_string(),
                source_event_id: "evt2".to_string(),
                summary: "Medium".to_string(),
                created_at: "2026-06-06T10:01:00Z".to_string(),
            },
        )
        .await
        .unwrap();
        insert_test_incident(&state.pool, &tenant_id, "ss_i1", "deny_storm").await;
        insert_test_incident(&state.pool, &tenant_id, "ss_i2", "exfil").await;
        db::close_soc_incident(&state.pool, &tenant_id, "ss_i2")
            .await
            .unwrap();

        let response = soc_summary(State(state), agent_headers(&tenant_id, &tenant_id))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alerts_total"], 2);
        assert_eq!(json["alerts_high"], 1);
        assert_eq!(json["incidents_total"], 2);
        assert_eq!(json["incidents_open"], 1);
        assert_eq!(json["incidents_closed"], 1);
    }

    /// GET /v1/soc/summary for a tenant with no data returns all-zero counts.
    #[tokio::test]
    async fn soc_summary_returns_zeros_when_empty() {
        let (state, tenant_id, _) = setup_state("soc_summary_empty").await;

        let response = soc_summary(State(state), agent_headers(&tenant_id, &tenant_id))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alerts_total"], 0);
        assert_eq!(json["alerts_high"], 0);
        assert_eq!(json["incidents_total"], 0);
        assert_eq!(json["incidents_open"], 0);
        assert_eq!(json["incidents_closed"], 0);
    }

    // --- MCP tool-manifest drift (SOC `mcp_manifest_drift`) ---

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

    /// Re-discovering a server whose advertised manifest changed must emit a
    /// `mcp_manifest_drift` AseEvent onto the SOC stream (and only on change).
    #[tokio::test]
    async fn discover_emits_manifest_drift_only_when_manifest_changes() {
        let (state, tenant_id, _agent_token, mut events_rx) =
            setup_state_with_events("mcp_drift").await;
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

        let headers = agent_headers(&tenant_id, &tenant_id);

        // 1) First discovery pins the manifest — no drift.
        let req1 = DiscoverMcpToolsRequest {
            tools: vec![drift_tool("create_issue", "medium")],
        };
        discover_mcp_tools(
            State(state.clone()),
            headers.clone(),
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
            headers.clone(),
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
            headers,
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
        let pinned = db::get_mcp_server_manifest_hash(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap();
        let expected = compute_mcp_manifest_hash(&[drift_tool("create_issue", "critical")]);
        assert_eq!(pinned, expected);

        // Fail-closed response: drift must auto-quarantine the server.
        let server = db::get_mcp_server_by_key(&state.pool, &tenant_id, "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.status, "quarantined");
    }

    /// A quarantined MCP server must deny an otherwise-approved tool inline
    /// (Phase 4 response enforcement). Before this, quarantine was recorded but
    /// never checked on the authorize hot path.
    #[tokio::test]
    async fn quarantined_mcp_server_denies_approved_tool() {
        let (state, tenant_id, agent_token) = setup_state("mcp_quarantine_enforced").await;
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
        db::set_mcp_tool_status(
            &state.pool,
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
        assert!(
            db::set_mcp_server_status(&state.pool, &tenant_id, "github-mcp", "quarantined")
                .await
                .unwrap()
        );
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

    /// GET /v1/mcp/servers lists a tenant's servers with status + manifest_hash,
    /// and never leaks another tenant's servers.
    #[tokio::test]
    async fn list_mcp_servers_is_tenant_scoped_and_shows_status() {
        let (state, tenant_id, _agent_token) = setup_state("list_mcp_servers").await;

        for key in ["alpha-mcp", "beta-mcp"] {
            db::upsert_mcp_server(
                &state.pool,
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
        db::set_mcp_server_status(&state.pool, &tenant_id, "beta-mcp", "quarantined")
            .await
            .unwrap();
        db::set_mcp_server_manifest_hash(&state.pool, &tenant_id, "alpha-mcp", "sha256:abc")
            .await
            .unwrap();

        let response =
            list_mcp_servers(State(state.clone()), agent_headers(&tenant_id, &tenant_id))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let servers: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(servers.len(), 2);
        // ORDER BY server_key ASC → alpha, beta.
        assert_eq!(servers[0]["server_key"], "alpha-mcp");
        assert_eq!(servers[0]["status"], "active");
        assert_eq!(servers[0]["manifest_hash"], "sha256:abc");
        assert_eq!(servers[1]["server_key"], "beta-mcp");
        assert_eq!(servers[1]["status"], "quarantined");

        // A different tenant sees none of these servers.
        db::register_tenant(&state.pool, "tenant_other", "Other Tenant", "developer")
            .await
            .unwrap();
        let other = list_mcp_servers(State(state), agent_headers("tenant_other", "tenant_other"))
            .await
            .into_response();
        let other_body = to_bytes(other.into_body(), usize::MAX).await.unwrap();
        let other_servers: Vec<serde_json::Value> = serde_json::from_slice(&other_body).unwrap();
        assert!(other_servers.is_empty());
    }
}
