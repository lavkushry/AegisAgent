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

/// True if the approval window has passed. Defense-in-depth alongside the SDK's
/// client-side expiry check: the gateway must not hand out, or grant, an approval
/// whose `expires_at` is in the past.
pub(crate) fn approval_is_expired(app: &ApprovalRecord) -> bool {
    app.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
}

/// #1307: anti-brute-force header carrying a tenant-scoped API key (#939,
/// `api_keys` table) that — if it matches an `active` key for the requesting
/// tenant — bypasses both the per-IP (AC#1) and per-approval-id (AC#2) rate
/// limits on approval-decision callbacks (AC#4). There is no separate
/// "admin token" concept in this codebase; a tenant's own active API key is
/// the closest existing analogue to a trusted-automation credential, so it
/// is reused here rather than inventing a new credential type.
const ADMIN_BYPASS_HEADER: &str = "X-Aegis-Admin-Key";

/// Returns `true` if `headers` carries an `X-Aegis-Admin-Key` that matches an
/// `active` API key for `tenant_id`. Fails closed (`false`) on any missing
/// header, malformed value, or DB error.
pub(crate) async fn has_admin_bypass(
    storage: &dyn StorageBackend,
    tenant_id: &str,
    headers: &HeaderMap,
) -> bool {
    let Some(key) = headers
        .get(ADMIN_BYPASS_HEADER)
        .and_then(|h| h.to_str().ok())
    else {
        return false;
    };
    if key.is_empty() {
        return false;
    }
    let key_hash = db::hash_token(key);
    storage
        .is_active_api_key(tenant_id, &key_hash)
        .await
        .unwrap_or(false)
}

/// #1307: shared anti-brute-force guard for `POST /v1/approvals/:id/{approve,
/// reject,edit}`.
///
/// - **AC#1** (max 10 attempts/IP/minute): checks `approval_callback_ip_limiter`
///   keyed by the caller's source IP (`ConnectInfo`).
/// - **AC#2** (max 5 failed attempts/approval_id/hour): checks
///   `approval_attempt_tracker.is_blocked(approval_id)` — this only reflects
///   *previously recorded* failures (404/409 outcomes), so it never blocks the
///   very first few attempts against a real, pending approval.
/// - **AC#4**: an `X-Aegis-Admin-Key` matching an active tenant API key (#939)
///   bypasses both checks.
///
/// Returns `Some(response)` with a 429 if either limit is exceeded and no
/// bypass applies, else `None` (caller should proceed).
pub(crate) async fn approval_callback_rate_limit_guard(
    state: &Arc<AppState>,
    tenant_id: &str,
    approval_id: &Uuid,
    addr: SocketAddr,
    headers: &HeaderMap,
) -> Option<axum::response::Response> {
    if has_admin_bypass(&*state.storage, tenant_id, headers).await {
        return None;
    }

    if !state
        .approval_callback_ip_limiter
        .check_rate_limit(&addr.ip().to_string())
    {
        return Some(
            StatusError::too_many_requests(
                "Too many approval attempts from this IP. Try again later.",
            )
            .with_details(serde_json::json!({"reason": "rate_limited_ip"}))
            .into_response(),
        );
    }

    if state
        .approval_attempt_tracker
        .is_blocked(&approval_id.to_string())
    {
        return Some(
            StatusError::too_many_requests("Too many failed attempts for this approval. Try again later.").with_details(serde_json::json!({"approval_id": approval_id, "reason": "rate_limited_approval_attempts"}))
                .into_response(),
        );
    }

    None
}

/// #1307 (AC#2): record a failed approval-decision attempt for `approval_id`
/// if `response` is a 4xx outcome (404 unknown approval, 409 already-decided
/// or expired, etc.). 429s from [`approval_callback_rate_limit_guard`] are
/// never passed here (the guard returns early), and successful 2xx
/// decisions never count — the approval is decided either way, and any
/// further attempts against it will already 409.
pub(crate) fn record_approval_attempt_failure(
    state: &Arc<AppState>,
    response: &axum::response::Response,
    approval_id: &Uuid,
) {
    if response.status().is_client_error() {
        state
            .approval_attempt_tracker
            .record_failure(&approval_id.to_string());
    }
}

/// #1300: build the 409 CONFLICT response when an atomic conditional approval
/// transition (`db::update_approval_status`/`update_approval_edit`) returned
/// `false` — i.e. the approval was no longer `status = 'created'` and
/// non-expired at the instant of the UPDATE. Re-reads the approval (best
/// effort) purely to produce a helpful error message; the UPDATE's failure,
/// not this re-read, is the authority that the transition did not happen.
///
/// If the approval has expired, emits a tamper-attempt receipt tagged with
/// `expired_tamper_kind` (e.g. `"reject_expired"`/`"edit_expired"`), matching
/// the receipt `approve_approval` already emits for its pre-check expiry case.
pub(crate) async fn conflict_response_for_failed_transition(
    state: &Arc<AppState>,
    tenant_id: &str,
    approval_id: &Uuid,
    expired_tamper_kind: &str,
) -> axum::response::Response {
    let approval = state
        .storage
        .get_approval_by_id(tenant_id, &approval_id.to_string())
        .await
        .ok()
        .flatten();

    match approval {
        Some(approval) if approval.status == "created" && approval_is_expired(&approval) => {
            emit_tamper_attempt_receipt(
                &*state.storage,
                &state.events,
                tenant_id,
                None,
                expired_tamper_kind,
                &approval_id.to_string(),
                Some(approval.original_call_hash.clone()),
                Some(&approval.decision_id),
            )
            .await;
            StatusError::conflict("Approval has expired").with_details(serde_json::json!({"approval_id": approval_id, "reason": "approval_expired"}))
                .into_response()
        }
        Some(approval) => StatusError::conflict("Approval already decided").with_details(serde_json::json!({"status": approval.status, "approval_id": approval_id, "reason": "approval_already_decided"}))
            .into_response(),
        None => StatusError::conflict("Approval already decided").with_details(serde_json::json!({"approval_id": approval_id, "reason": "approval_already_decided"}))
            .into_response(),
    }
}

// Get Approval Status Handler
pub async fn get_approval(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
) -> impl IntoResponse {
    match state
        .storage
        .get_approval_by_id(&tenant_id, &approval_id.to_string())
        .await
    {
        Ok(Some(app)) => {
            let edited_call: Option<AuthorizeToolCall> = app
                .edited_skill_call
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok());
            // #1326: the *original* frozen tool call and its triggering agent
            // were stored at approval-creation time but never surfaced over the
            // API — a human approver had no way to see what they were
            // approving. Additive fields only; existing consumers are unaffected.
            let tool_call: Option<AuthorizeToolCall> =
                serde_json::from_str(&app.original_skill_call).ok();
            let agent_id = state
                .storage
                .get_decision_by_id(&tenant_id, &app.decision_id)
                .await
                .ok()
                .flatten()
                .map(|d| d.agent_id);
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
                    // #approval-edit-lifecycle: surface the full hash story so a
                    // human/SDK can see exactly what they're acting on.
                    // `action_hash` (kept for SDK back-compat) and
                    // `effective_action_hash` are the hash an approve/consume
                    // binds to — the edited action's hash once edited.
                    "action_hash": app.effective_action_hash(),
                    "original_action_hash": app.original_call_hash,
                    "edited_action_hash": app.effective_call_hash,
                    "effective_action_hash": app.effective_action_hash(),
                    "is_edited": app.is_edited(),
                    "tool_call": tool_call,
                    "agent_id": agent_id,
                    "edited_tool_call": edited_call,
                    "expires_at": app.expires_at,
                    "decided_at": app.decided_at,
                })),
            )
                .into_response()
        }
        Ok(None) => StatusError::not_found("Approval request not found").into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            StatusError::internal("Database error").into_response()
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
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    // JSON body is optional; old callers that POST with no body still work.
    body: Option<Json<ConsumeApprovalBody>>,
) -> impl IntoResponse {
    let claimed_action_hash = body
        .as_ref()
        .and_then(|Json(b)| b.claimed_action_hash.as_deref());

    // #1603: the claimed-hash check is folded into the same atomic conditional
    // UPDATE as the consume itself (db::consume_approval), so a mismatch never
    // burns the single-use slot. Checking the hash as a separate step *after*
    // consuming (the prior behavior) let one wrong-hash call permanently
    // invalidate a legitimately approved action before the real executor could
    // consume it — a self-inflicted DoS on the replay defense.
    let consumed = match state
        .storage
        .consume_approval(&tenant_id, &approval_id.to_string(), claimed_action_hash)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to consume approval: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    if !consumed {
        let bound_approval = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .ok()
            .flatten();
        let bound_hash = bound_approval
            .as_ref()
            .map(|a| a.original_call_hash.clone());
        let bound_decision_id = bound_approval.as_ref().map(|a| a.decision_id.clone());

        // Distinguish a hash mismatch (the approval is otherwise still valid and
        // consumable, but the claimed hash didn't match) from every other
        // not-consumable reason (already used, expired, not approved) so the
        // error message and tamper-attempt tag reflect what actually happened.
        let is_hash_mismatch = claimed_action_hash.is_some()
            && state
                .storage
                .approval_is_still_consumable(&tenant_id, &approval_id.to_string())
                .await
                .unwrap_or(false);

        let (tamper_tag, error_message) = if is_hash_mismatch {
            state.metrics.inc_hash_mismatch();
            error!(
                approval_id = %approval_id,
                "approval_hash_mismatch: claimed hash does not match bound hash"
            );
            (
                "consume_hash_mismatch",
                "Action hash mismatch: the action to be executed differs from the approved action",
            )
        } else {
            (
                "consume_not_consumable",
                "Approval not consumable (already used, expired, or not approved)",
            )
        };

        // A consume that didn't take effect is an attack on the evidence chain
        // (replay / approve-then-swap / T-D): record it as a tamper-attempt
        // receipt so the chain itself captures the attempt. Hashes only, no
        // payloads. The approval record does not carry the agent id; the SOC
        // event uses the "unknown" placeholder (the violation tag + approval id
        // are the evidence).
        emit_tamper_attempt_receipt(
            &*state.storage,
            &state.events,
            &tenant_id,
            None,
            tamper_tag,
            &approval_id.to_string(),
            bound_hash,
            bound_decision_id.as_deref(),
        )
        .await;
        return StatusError::conflict(error_message)
            .with_details(serde_json::json!({"approval_id": approval_id}))
            .into_response();
    }

    // Return the bound action hash so the SDK can re-verify before executing.
    // #approval-edit-lifecycle: this is the *effective* hash — the edited
    // action's hash for an edited approval, so the SDK re-verifies against what
    // was actually approved, not the agent's original action.
    let action_hash = state
        .storage
        .get_approval_by_id(&tenant_id, &approval_id.to_string())
        .await
        .ok()
        .flatten()
        .map(|a| a.effective_action_hash().to_string())
        .unwrap_or_default();

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

// Approve Handler
pub async fn approve_approval(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<ApproveRequest>,
) -> axum::response::Response {
    if let Some(resp) =
        approval_callback_rate_limit_guard(&state, &tenant_id, &approval_id, addr, &headers).await
    {
        return resp;
    }

    let response = approve_approval_inner(state.clone(), tenant_id, approval_id, payload).await;
    record_approval_attempt_failure(&state, &response, &approval_id);
    response
}

pub(crate) async fn approve_approval_inner(
    state: Arc<AppState>,
    tenant_id: String,
    approval_id: Uuid,
    payload: ApproveRequest,
) -> axum::response::Response {
    // Load the approval first so we can fail closed on stale or already-decided
    // requests instead of blindly transitioning to APPROVED.
    let approval = match state
        .storage
        .get_approval_by_id(&tenant_id, &approval_id.to_string())
        .await
    {
        Ok(Some(app)) => app,
        Ok(None) => {
            return StatusError::not_found("Approval request not found").into_response();
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // Only a pending approval may be approved (no re-deciding an
    // APPROVED/REJECTED one). An edited approval stays `created` and is
    // approvable — approve binds to its effective (edited) hash.
    if approval.status != "created" {
        return StatusError::conflict("Approval already decided").with_details(serde_json::json!({"status": approval.status, "approval_id": approval_id, "reason": "approval_already_decided"}))
            .into_response();
    }

    // Fail closed if the approval window has already passed. Granting an expired
    // approval is an attack on the evidence chain (T-D); record the attempt as a
    // tamper-attempt receipt (hashes only) before refusing.
    if approval_is_expired(&approval) {
        emit_tamper_attempt_receipt(
            &*state.storage,
            &state.events,
            &tenant_id,
            None,
            "approve_expired",
            &approval_id.to_string(),
            Some(approval.original_call_hash.clone()),
            Some(&approval.decision_id),
        )
        .await;
        return StatusError::conflict("Approval has expired")
            .with_details(
                serde_json::json!({"approval_id": approval_id, "reason": "approval_expired"}),
            )
            .into_response();
    }

    // Atomically transition to APPROVED (#1300). The UPDATE itself is the
    // source of truth: it only matches a still-`created`, non-expired row, so
    // a concurrent decision or last-instant expiry between the pre-checks
    // above and this write is caught here rather than silently overwritten.
    let updated = match state
        .storage
        .update_approval_status(
            &tenant_id,
            &approval_id.to_string(),
            "APPROVED",
            &payload.approver_user_id,
            payload.reason.as_deref(),
            None,
        )
        .await
    {
        Ok(updated) => updated,
        Err(e) => {
            error!("Failed to approve request: {:?}", e);
            return StatusError::internal("Failed to approve request").into_response();
        }
    };

    if !updated {
        return conflict_response_for_failed_transition(
            &state,
            &tenant_id,
            &approval_id,
            "approve_expired",
        )
        .await;
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
        decision_id: Some(approval.decision_id.clone()),
        approval_id: Some(approval.id.clone()),
        created_at: Utc::now(),
    };
    let _ = state.storage.insert_audit_event(&audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Reject Handler
pub async fn reject_approval(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<ApproveRequest>,
) -> axum::response::Response {
    if let Some(resp) =
        approval_callback_rate_limit_guard(&state, &tenant_id, &approval_id, addr, &headers).await
    {
        return resp;
    }

    let response = reject_approval_inner(state.clone(), tenant_id, approval_id, payload).await;
    record_approval_attempt_failure(&state, &response, &approval_id);
    response
}

pub(crate) async fn reject_approval_inner(
    state: Arc<AppState>,
    tenant_id: String,
    approval_id: Uuid,
    payload: ApproveRequest,
) -> axum::response::Response {
    // 404 if the approval doesn't exist for this tenant.
    let approval = match state
        .storage
        .get_approval_by_id(&tenant_id, &approval_id.to_string())
        .await
    {
        Ok(Some(app)) => app,
        Ok(None) => {
            return StatusError::not_found("Approval request not found").into_response();
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // Atomically transition to REJECTED (#1300). Previously this handler had
    // NO status/expiry guard at all and would unconditionally overwrite an
    // already-decided approval's status — the UPDATE itself is now the
    // source of truth: it only matches a still-`created`, non-expired row.
    let updated = match state
        .storage
        .update_approval_status(
            &tenant_id,
            &approval_id.to_string(),
            "REJECTED",
            &payload.approver_user_id,
            payload.reason.as_deref(),
            None,
        )
        .await
    {
        Ok(updated) => updated,
        Err(e) => {
            error!("Failed to reject request: {:?}", e);
            return StatusError::internal("Failed to reject request").into_response();
        }
    };

    if !updated {
        return conflict_response_for_failed_transition(
            &state,
            &tenant_id,
            &approval_id,
            "reject_expired",
        )
        .await;
    }

    let linked_decision_id = Some(approval.decision_id.clone());

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
        decision_id: linked_decision_id,
        approval_id: Some(approval_id.to_string()),
        created_at: Utc::now(),
    };
    let _ = state.storage.insert_audit_event(&audit_record).await;

    (
        StatusCode::OK,
        Json(json!({"status": "success", "approval_id": approval_id})),
    )
        .into_response()
}

// Edit parameters handler
pub async fn edit_approval(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TenantId(tenant_id): TenantId,
    Path(approval_id): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<EditApprovalRequest>,
) -> axum::response::Response {
    if let Some(resp) =
        approval_callback_rate_limit_guard(&state, &tenant_id, &approval_id, addr, &headers).await
    {
        return resp;
    }

    let response = edit_approval_inner(state.clone(), tenant_id, approval_id, payload).await;
    record_approval_attempt_failure(&state, &response, &approval_id);
    response
}

pub(crate) async fn edit_approval_inner(
    state: Arc<AppState>,
    tenant_id: String,
    approval_id: Uuid,
    payload: EditApprovalRequest,
) -> axum::response::Response {
    // Load the approval first so we can fail closed on stale or already-decided
    // requests instead of blindly re-binding the action (#0131).
    let approval = match state
        .storage
        .get_approval_by_id(&tenant_id, &approval_id.to_string())
        .await
    {
        Ok(Some(app)) => app,
        Ok(None) => {
            return StatusError::not_found("Approval request not found").into_response();
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // Only a pending approval may be edited (no editing an
    // APPROVED/REJECTED/consumed one). Re-editing an already-edited approval is
    // fine — it is still `created`, and the new edit re-binds the effective hash.
    if approval.status != "created" {
        return StatusError::conflict("Approval already decided").with_details(serde_json::json!({"status": approval.status, "approval_id": approval_id, "reason": "approval_already_decided"}))
            .into_response();
    }

    let edited_call_str = serde_json::to_string(&payload.edited_tool_call).unwrap_or_default();
    // Re-hash the edited call (#0130): the approval is now bound to the edited
    // action, so a subsequent approve/consume re-verifies against this hash,
    // not the original.
    let new_action_hash = hash_tool_call(&payload.edited_tool_call);

    // Atomically re-bind the approval to the edited action (#1300,
    // #approval-edit-lifecycle): store the edited call + its hash as the
    // effective hash while keeping the approval pending (`status = 'created'`),
    // so it stays listed and approvable. The UPDATE is the source of truth: it
    // only matches a still-`created`, non-expired row, closing the TOCTOU window
    // between the pre-check above and this write.
    let updated = match state
        .storage
        .update_approval_edit(
            &tenant_id,
            &approval_id.to_string(),
            &payload.approver_user_id,
            payload.reason.as_deref(),
            &edited_call_str,
            &new_action_hash,
        )
        .await
    {
        Ok(updated) => updated,
        Err(e) => {
            error!("Failed to edit approval: {:?}", e);
            return StatusError::internal("Failed to edit request").into_response();
        }
    };

    if !updated {
        return conflict_response_for_failed_transition(
            &state,
            &tenant_id,
            &approval_id,
            "edit_expired",
        )
        .await;
    }

    // Write audit event. The approval stays pending after an edit; record the
    // edit as provenance, binding both the original and the new effective hash
    // (no raw secrets — only the structured tool call + hashes).
    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        event_type: "approval_edited".to_string(),
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
            "status": "created",
            "edited": true,
            "reason": payload.reason,
            "original_action_hash": approval.original_call_hash,
            "effective_action_hash": new_action_hash,
            "edited_tool_call": payload.edited_tool_call
        }))
        .unwrap_or_default(),
        input_hash: Some(approval.original_call_hash.clone()),
        output_hash: Some(new_action_hash.clone()),
        decision_id: Some(approval.decision_id.clone()),
        approval_id: Some(approval.id.clone()),
        created_at: Utc::now(),
    };
    let _ = state.storage.insert_audit_event(&audit_record).await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "approval_id": approval_id,
            "effective_action_hash": new_action_hash,
            "original_action_hash": approval.original_call_hash,
        })),
    )
        .into_response()
}

/// GET /v1/approvals — list pending approvals for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());

    match state
        .storage
        .list_pending_approvals(&tenant_id, limit, offset)
        .await
    {
        Ok(approvals) => {
            // #1326: batch-fetch the originating decisions once (not one query
            // per approval) purely to surface `agent_id` — a human approver
            // needs to know which agent is asking, not just an action hash.
            let decision_ids: Vec<String> =
                approvals.iter().map(|a| a.decision_id.clone()).collect();
            let decisions_by_id = state
                .storage
                .list_decisions_by_ids(&tenant_id, &decision_ids)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|d| (d.id.clone(), d))
                .collect::<std::collections::HashMap<_, _>>();
            let mapped: Vec<serde_json::Value> = approvals
                .into_iter()
                .map(|app| {
                    let edited_call: Option<AuthorizeToolCall> = app
                        .edited_skill_call
                        .as_ref()
                        .and_then(|s| serde_json::from_str(s).ok());
                    let tool_call: Option<AuthorizeToolCall> =
                        serde_json::from_str(&app.original_skill_call).ok();
                    let agent_id = decisions_by_id.get(&app.decision_id).map(|d| &d.agent_id);
                    let effective_status = if app.status == "created" && approval_is_expired(&app) {
                        "EXPIRED".to_string()
                    } else {
                        app.status.clone()
                    };
                    json!({
                        "approval_id": app.id,
                        "status": effective_status,
                        "approver_group": app.approver_group,
                        "approver_user_id": app.approver_user_id,
                        "reason": app.reason,
                        // Keep the queue contract aligned with GET /:id: the
                        // hash beside the canonical action bytes must always be
                        // the hash an approve/consume operation will bind to.
                        "action_hash": app.effective_action_hash(),
                        "original_action_hash": app.original_call_hash,
                        "edited_action_hash": app.effective_call_hash,
                        "effective_action_hash": app.effective_action_hash(),
                        "is_edited": app.is_edited(),
                        "tool_call": tool_call,
                        "agent_id": agent_id,
                        "edited_tool_call": edited_call,
                        "expires_at": app.expires_at,
                        "decided_at": app.decided_at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(mapped)).into_response()
        }
        Err(e) => {
            error!("Failed to list pending approvals: {:?}", e);
            StatusError::internal("Database error").into_response()
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
    /// #0127: approve_approval transitions a pending approval to APPROVED.
    #[tokio::test]
    async fn approve_approval_changes_status_to_approved() {
        let (state, tenant_id, agent_token) = setup_state("approve_sets_status").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "20").await;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "APPROVED");
    }

    /// #0128: approve_approval records the approver_user_id on the approval.
    #[tokio::test]
    async fn approve_approval_sets_approver_user_id() {
        let (state, tenant_id, agent_token) = setup_state("approve_sets_approver").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "21").await;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer-42".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.approver_user_id.as_deref(), Some("reviewer-42"));
    }

    /// #0129: reject_approval transitions a pending approval to REJECTED.
    #[tokio::test]
    async fn reject_approval_changes_status_to_rejected() {
        let (state, tenant_id, agent_token) = setup_state("reject_sets_status").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "22").await;

        let reject = reject_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: Some("not safe to ship".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(reject.status(), StatusCode::OK);

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "REJECTED");
        assert_eq!(stored.reason.as_deref(), Some("not safe to ship"));
    }

    /// #1300: approve_approval's expiry 409 response carries a machine-readable
    /// `reason` field so Slack callback handlers can distinguish "expired" from
    /// other conflict cases.
    #[tokio::test]
    async fn approve_approval_expired_response_includes_reason_field() {
        let (state, tenant_id, agent_token) = setup_state("approve_expired_reason").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "30").await;

        // Force the approval past its window before it is ever decided.
        aegis_storage::execute_query!(
            state.storage.get_pool(),
            "UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?",
            Utc::now() - Duration::minutes(5),
            tenant_id.as_str(),
            approval_id.to_string()
        )
        .unwrap();

        let approve_resp = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve_resp.status(), StatusCode::CONFLICT);
        let body = to_bytes(approve_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["details"]["reason"], "approval_expired");

        // The stored status must remain "created" — the conditional UPDATE
        // must not have stomped it.
        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "created");
    }

    /// #1300: reject_approval previously had NO status/expiry guard at all and
    /// would unconditionally overwrite an already-APPROVED approval's status to
    /// REJECTED. A reject callback arriving after the approval has already been
    /// decided must be refused with 409 and must not change the stored status.
    #[tokio::test]
    async fn reject_approval_rejects_already_approved_approval() {
        let (state, tenant_id, agent_token) = setup_state("reject_after_approve").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "31").await;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let reject = reject_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: Some("too late".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(reject.status(), StatusCode::CONFLICT);
        let body = to_bytes(reject.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["details"]["reason"], "approval_already_decided");
        assert_eq!(json["details"]["status"], "APPROVED");

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(
            stored.status, "APPROVED",
            "reject must not overwrite an already-decided approval"
        );
    }

    /// #1300: reject_approval must fail closed (409, reason `approval_expired`)
    /// when the approval window has already passed, mirroring
    /// `consume_approval_rejects_expired_approval`.
    #[tokio::test]
    async fn reject_approval_rejects_expired_approval() {
        let (state, tenant_id, agent_token) = setup_state("reject_rejects_expired").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "32").await;

        // Age the approval out while it is still pending.
        aegis_storage::execute_query!(
            state.storage.get_pool(),
            "UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?",
            Utc::now() - Duration::minutes(5),
            tenant_id.as_str(),
            approval_id.to_string()
        )
        .unwrap();

        let reject = reject_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: Some("too late".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(reject.status(), StatusCode::CONFLICT);
        let body = to_bytes(reject.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["details"]["reason"], "approval_expired");

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(
            stored.status, "created",
            "reject must not change the status of an expired pending approval"
        );
    }

    /// #1300: edit_approval must fail closed (409, reason `approval_expired`)
    /// when the approval window has already passed, mirroring the reject/consume
    /// expiry guards.
    #[tokio::test]
    async fn edit_approval_rejects_expired_approval() {
        let (state, tenant_id, agent_token) = setup_state("edit_rejects_expired").await;
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/33".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        // Age the approval out while it is still pending.
        aegis_storage::execute_query!(
            state.storage.get_pool(),
            "UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?",
            Utc::now() - Duration::minutes(5),
            tenant_id.as_str(),
            approval_id.to_string()
        )
        .unwrap();

        let edit_resp = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                reason: Some("tightening scope".to_string()),
                edited_tool_call: AuthorizeToolCall {
                    tool: "github".to_string(),
                    action: "merge_pull_request".to_string(),
                    resource: Some("repo/example/pull/33".to_string()),
                    mutates_state: true,
                    parameters: serde_json::json!({"base_branch": "main2"}),
                },
            }),
        )
        .await
        .into_response();
        assert_eq!(edit_resp.status(), StatusCode::CONFLICT);
        let body = to_bytes(edit_resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["details"]["reason"], "approval_expired");

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(
            stored.status, "created",
            "edit must not change the status of an expired pending approval"
        );
    }

    /// #1300 (AC #3): concurrent approve + reject against the same pending
    /// approval must race safely — exactly one wins (200 OK), the other is
    /// rejected with 409 `approval_already_decided`, and the final stored
    /// status reflects whichever decision won (never both, never neither).
    #[tokio::test]
    async fn concurrent_approve_and_reject_only_one_wins() {
        let (state, tenant_id, agent_token) = setup_state("concurrent_approve_reject").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "34").await;

        let (approve_resp, reject_resp) = tokio::join!(
            approve_approval(
                State(state.clone()),
                ConnectInfo(test_conn_info()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                HeaderMap::new(),
                Json(ApproveRequest {
                    approver_user_id: "reviewer-a".to_string(),
                    reason: None,
                }),
            ),
            reject_approval(
                State(state.clone()),
                ConnectInfo(test_conn_info()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                HeaderMap::new(),
                Json(ApproveRequest {
                    approver_user_id: "reviewer-b".to_string(),
                    reason: Some("racing reject".to_string()),
                }),
            ),
        );

        let approve_resp = approve_resp.into_response();
        let reject_resp = reject_resp.into_response();
        let statuses = [approve_resp.status(), reject_resp.status()];
        let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
        let conflict_count = statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count();
        assert_eq!(ok_count, 1, "exactly one of approve/reject must succeed");
        assert_eq!(
            conflict_count, 1,
            "exactly one of approve/reject must be rejected"
        );

        // Whichever lost must report `approval_already_decided`.
        let loser = if approve_resp.status() == StatusCode::CONFLICT {
            approve_resp
        } else {
            reject_resp
        };
        let body = to_bytes(loser.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["details"]["reason"], "approval_already_decided");

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert!(
            stored.status == "APPROVED" || stored.status == "REJECTED",
            "final status must reflect exactly the winning decision, got {}",
            stored.status
        );
    }

    /// #0130 / #approval-edit-lifecycle: edit_approval re-hashes the edited tool
    /// call and binds the approval's *effective* hash to it, while PRESERVING the
    /// original hash and keeping the approval pending (`status = 'created'`) so it
    /// stays listed and approvable.
    #[tokio::test]
    async fn edit_approval_rehashes_and_stores_edited_call() {
        let (state, tenant_id, agent_token) = setup_state("edit_rehashes").await;
        let (approval_id, original_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "30").await;

        let mut edited_tool_call = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited_tool_call.resource = Some("repo/example/pull/30".to_string());
        edited_tool_call.parameters = serde_json::json!({"base_branch": "release"});
        let expected_hash = hash_tool_call(&edited_tool_call);
        assert_ne!(expected_hash, original_hash);

        let edit = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call: edited_tool_call.clone(),
                reason: Some("changed target branch".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::OK);

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        // Stays pending and approvable after an edit (the bug this fixes left it
        // as "EDITED", which made it invisible and unapprovable).
        assert_eq!(stored.status, "created");
        // Original is preserved; the edited hash becomes the effective one.
        assert_eq!(stored.original_call_hash, original_hash);
        assert_eq!(
            stored.effective_call_hash.as_deref(),
            Some(expected_hash.as_str())
        );
        assert_eq!(stored.effective_action_hash(), expected_hash);
        assert!(stored.is_edited());
        let stored_edited: AuthorizeToolCall =
            serde_json::from_str(stored.edited_skill_call.as_deref().unwrap()).unwrap();
        assert_eq!(stored_edited.parameters, edited_tool_call.parameters);
    }

    /// #0131: edit_approval rejects an approval that has already been decided
    /// (e.g. already consumed/approved) — no re-deciding a decided approval.
    #[tokio::test]
    async fn edit_approval_rejects_if_already_consumed() {
        let (state, tenant_id, agent_token) = setup_state("edit_rejects_consumed").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "31").await;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let consume = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(consume.status(), StatusCode::OK);

        let mut edited_tool_call = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited_tool_call.resource = Some("repo/example/pull/31".to_string());

        let edit = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::CONFLICT);
    }

    // ── #approval-edit-lifecycle acceptance tests ────────────────────────────
    // Before this fix, editing set status to 'EDITED', which approve and the
    // pending list (both keyed on 'created') treated as not-pending — so an
    // edited approval silently vanished and could never be approved. These lock
    // in the corrected lifecycle: edit keeps the approval pending and re-binds
    // it to the edited action's effective hash, preserving the original.

    /// create → edit → approve → consume with the EDITED hash succeeds.
    #[tokio::test]
    async fn edit_then_approve_then_consume_with_edited_hash_succeeds() {
        let (state, tenant_id, agent_token) = setup_state("edit_lifecycle_happy").await;
        let (approval_id, original_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "40").await;

        let mut edited = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited.resource = Some("repo/example/pull/40".to_string());
        edited.parameters = serde_json::json!({"base_branch": "release"});
        let edited_hash = hash_tool_call(&edited);
        assert_ne!(edited_hash, original_hash);

        let edit = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call: edited,
                reason: Some("retarget".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::OK);

        // The edited approval is still approvable (the bug made this fail).
        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        // Consume with the EDITED hash succeeds.
        let consume = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Some(Json(ConsumeApprovalBody {
                claimed_action_hash: Some(edited_hash.clone()),
            })),
        )
        .await
        .into_response();
        assert_eq!(consume.status(), StatusCode::OK);
        let body = to_bytes(consume.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["action_hash"].as_str(), Some(edited_hash.as_str()));
    }

    /// create → edit → approve → consume with the ORIGINAL hash fails (409) and
    /// must NOT burn the approval; a follow-up consume with the edited hash works.
    #[tokio::test]
    async fn edit_then_consume_with_original_hash_fails_without_burning() {
        let (state, tenant_id, agent_token) = setup_state("edit_lifecycle_oldhash").await;
        let (approval_id, original_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "41").await;

        let mut edited = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited.resource = Some("repo/example/pull/41".to_string());
        edited.parameters = serde_json::json!({"base_branch": "release"});
        let edited_hash = hash_tool_call(&edited);

        let edit = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call: edited,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::OK);

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        // Consume with the stale ORIGINAL hash must be rejected...
        let wrong = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Some(Json(ConsumeApprovalBody {
                claimed_action_hash: Some(original_hash.clone()),
            })),
        )
        .await
        .into_response();
        assert_eq!(wrong.status(), StatusCode::CONFLICT);

        // ...and must NOT have burned the approval — the edited hash still works.
        let ok = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Some(Json(ConsumeApprovalBody {
                claimed_action_hash: Some(edited_hash),
            })),
        )
        .await
        .into_response();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    /// An edited approval still appears in the pending list and exposes the
    /// original/edited/effective hashes via GET.
    #[tokio::test]
    async fn edited_approval_is_listed_and_get_exposes_all_hashes() {
        let (state, tenant_id, agent_token) = setup_state("edit_lifecycle_list").await;
        let (approval_id, original_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "42").await;

        let mut edited = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited.resource = Some("repo/example/pull/42".to_string());
        edited.parameters = serde_json::json!({"base_branch": "release"});
        let edited_hash = hash_tool_call(&edited);

        let edit = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call: edited,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::OK);

        // Still surfaced by the pending list.
        let list = list_approvals(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let list_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let listed = list_json
            .as_array()
            .or_else(|| list_json.get("approvals").and_then(|a| a.as_array()))
            .and_then(|arr| {
                arr.iter()
                    .find(|a| a["approval_id"] == approval_id.to_string())
            });
        assert!(
            listed.is_some(),
            "edited approval must still appear in the pending list"
        );
        let listed = listed.unwrap();
        assert_eq!(listed["is_edited"], true);
        assert_eq!(
            listed["original_action_hash"].as_str(),
            Some(original_hash.as_str())
        );
        assert_eq!(
            listed["effective_action_hash"].as_str(),
            Some(edited_hash.as_str())
        );
        assert_eq!(listed["action_hash"].as_str(), Some(edited_hash.as_str()));

        // GET exposes the full hash story.
        let get = get_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
        )
        .await
        .into_response();
        let gbody = to_bytes(get.into_body(), usize::MAX).await.unwrap();
        let gjson: serde_json::Value = serde_json::from_slice(&gbody).unwrap();
        assert_eq!(gjson["status"], "created");
        assert_eq!(gjson["is_edited"], true);
        assert_eq!(
            gjson["original_action_hash"].as_str(),
            Some(original_hash.as_str())
        );
        assert_eq!(
            gjson["edited_action_hash"].as_str(),
            Some(edited_hash.as_str())
        );
        assert_eq!(
            gjson["effective_action_hash"].as_str(),
            Some(edited_hash.as_str())
        );
        assert_eq!(gjson["action_hash"].as_str(), Some(edited_hash.as_str()));
    }

    /// create → edit → reject succeeds (an edited approval is still rejectable).
    #[tokio::test]
    async fn edit_then_reject_succeeds() {
        let (state, tenant_id, agent_token) = setup_state("edit_lifecycle_reject").await;
        let (approval_id, _original_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "43").await;

        let mut edited = mcp_authorize_request("github", "merge_pull_request").tool_call;
        edited.resource = Some("repo/example/pull/43".to_string());
        edited.parameters = serde_json::json!({"base_branch": "release"});

        let edit = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call: edited,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::OK);

        let reject = reject_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: Some("not allowed".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(reject.status(), StatusCode::OK);
    }

    /// #1307 (AC#1/AC#5): the per-IP rate limiter on approval-decision
    /// callbacks allows the first 10 attempts per minute and 429s the rest.
    /// 20 rapid `approve_approval` attempts from the same source IP, each
    /// against its own distinct pending approval (so the per-approval-id
    /// failure tracker, AC#2, never factors in) -> the first 10 succeed
    /// (200 OK) and attempts 11-20 get 429 with reason `rate_limited_ip`.
    #[tokio::test]
    async fn approve_approval_rate_limited_after_10_per_ip_per_minute() {
        let (state, tenant_id, agent_token) = setup_state("approve_ip_rate_limit").await;

        for attempt in 1..=20u32 {
            let (approval_id, _hash) =
                create_pending_approval(&state, &tenant_id, &agent_token, &format!("2{attempt}"))
                    .await;

            let resp = approve_approval(
                State(state.clone()),
                ConnectInfo(test_conn_info()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                HeaderMap::new(),
                Json(ApproveRequest {
                    approver_user_id: "reviewer".to_string(),
                    reason: None,
                }),
            )
            .await
            .into_response();

            if attempt <= 10 {
                assert_eq!(
                    resp.status(),
                    StatusCode::OK,
                    "attempt {attempt} should succeed"
                );
            } else {
                assert_eq!(
                    resp.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "attempt {attempt} should be rate limited"
                );
                let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
                let json: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["details"]["reason"], "rate_limited_ip");
            }
        }
    }

    /// #1307 (AC#3): `reject_approval` and `edit_approval` are also covered
    /// by the per-IP rate limiter — exhaust the bucket via `approve_approval`
    /// against 10 distinct pending approvals (so AC#2's per-approval-id
    /// tracker never factors in) and confirm a subsequent
    /// `reject_approval`/`edit_approval` from the same IP are 429'd with
    /// reason `rate_limited_ip`.
    #[tokio::test]
    async fn reject_and_edit_approval_covered_by_ip_rate_limiter() {
        let (state, tenant_id, agent_token) = setup_state("reject_edit_ip_rate_limit").await;

        // Exhaust the 10-token bucket for this IP via 10 approvals of 10
        // distinct pending approvals.
        for i in 1..=10u32 {
            let (other_approval_id, _hash) =
                create_pending_approval(&state, &tenant_id, &agent_token, &format!("3{i}")).await;
            let resp = approve_approval(
                State(state.clone()),
                ConnectInfo(test_conn_info()),
                TenantId(tenant_id.clone()),
                Path(other_approval_id),
                HeaderMap::new(),
                Json(ApproveRequest {
                    approver_user_id: "reviewer".to_string(),
                    reason: None,
                }),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "399").await;

        let reject = reject_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(reject.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(reject.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["details"]["reason"], "rate_limited_ip");

        let edited_tool_call = mcp_authorize_request("github", "merge_pull_request").tool_call;
        let edit = edit_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(EditApprovalRequest {
                approver_user_id: "reviewer".to_string(),
                edited_tool_call,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(edit.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(edit.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["details"]["reason"], "rate_limited_ip");
    }

    /// #1307 (AC#2): 6 failed approval attempts against the same
    /// `approval_id` (a nonexistent one, so each is a 404) from *different*
    /// source IPs (isolating from AC#1's per-IP limit) -> the 6th gets 429
    /// with reason `rate_limited_approval_attempts`.
    #[tokio::test]
    async fn approve_approval_rate_limited_after_5_failed_attempts_per_approval_id() {
        let (state, tenant_id, _agent_token) = setup_state("approve_attempt_limit").await;
        let nonexistent_approval_id = Uuid::new_v4();

        for attempt in 1..=6u32 {
            let resp = approve_approval(
                State(state.clone()),
                ConnectInfo(conn_info_for_ip(attempt as u8)),
                TenantId(tenant_id.clone()),
                Path(nonexistent_approval_id),
                HeaderMap::new(),
                Json(ApproveRequest {
                    approver_user_id: "reviewer".to_string(),
                    reason: None,
                }),
            )
            .await
            .into_response();

            if attempt <= 5 {
                assert_eq!(
                    resp.status(),
                    StatusCode::NOT_FOUND,
                    "attempt {attempt} should be a plain 404"
                );
            } else {
                assert_eq!(
                    resp.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "attempt {attempt} should be rate limited"
                );
                let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
                let json: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["details"]["reason"], "rate_limited_approval_attempts");
            }
        }
    }

    /// #1307 (AC#4): a valid `X-Aegis-Admin-Key` (a tenant-scoped API key,
    /// #939) bypasses both the per-IP (AC#1) and per-approval-id (AC#2)
    /// rate limits.
    #[tokio::test]
    async fn approve_approval_admin_key_bypasses_rate_limits() {
        let (state, tenant_id, agent_token) = setup_state("approve_admin_bypass").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "102").await;

        let (_id, plaintext_key) = state
            .storage
            .create_api_key(&tenant_id, "admin-bypass")
            .await
            .expect("create api key");

        let mut headers = HeaderMap::new();
        headers.insert("X-Aegis-Admin-Key", plaintext_key.parse().unwrap());

        // 15 attempts (> both the 10/min IP limit and the 5/hr attempt
        // limit) from the same IP, all carrying the admin key.
        for attempt in 1..=15u32 {
            let resp = approve_approval(
                State(state.clone()),
                ConnectInfo(test_conn_info()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                headers.clone(),
                Json(ApproveRequest {
                    approver_user_id: "reviewer".to_string(),
                    reason: None,
                }),
            )
            .await
            .into_response();

            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "attempt {attempt} with valid admin key should never be rate limited"
            );
        }
    }

    #[tokio::test]
    async fn test_list_approvals_route() {
        let (state, tenant_id, agent_token) = setup_state("list_approvals").await;
        let agent = state
            .storage
            .get_agent_by_token(&tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let decision_id1 = Uuid::new_v4().to_string();
        let record_dec = DecisionRecord {
            id: decision_id1.clone(),
            tenant_id: tenant_id.clone(),
            agent_id,
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "fs".to_string(),
            action: "write".to_string(),
            resource: None,
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
        state.storage.insert_decision(&record_dec).await.unwrap();

        let approval_id1 = Uuid::new_v4().to_string();
        let record1 = ApprovalRecord {
            id: approval_id1.clone(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id1.clone(),
            status: "created".to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: "hash1".to_string(),
            edited_skill_call: None,
            effective_call_hash: None,
            expires_at: Some(Utc::now() + Duration::minutes(10)),
            decided_at: None,
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now(),
        };
        state.storage.insert_approval(&record1).await.unwrap();

        // Expired approval
        let approval_id2 = Uuid::new_v4().to_string();
        let record2 = ApprovalRecord {
            id: approval_id2.clone(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id1.clone(),
            status: "created".to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: "{}".to_string(),
            original_call_hash: "hash2".to_string(),
            edited_skill_call: None,
            effective_call_hash: None,
            expires_at: Some(Utc::now() - Duration::minutes(10)),
            decided_at: None,
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now() - Duration::minutes(10),
        };
        state.storage.insert_approval(&record2).await.unwrap();

        // 1. List approvals (should only return non-expired record1)
        let response = list_approvals(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = json.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["approval_id"].as_str(), Some(approval_id1.as_str()));
    }

    /// #1326: the dashboard's Approvals queue needs to show a human approver
    /// *what* they're approving (agent, tool, action, resource) — not just an
    /// opaque action hash. `agent_id` is resolved from the approval's linked
    /// decision row; `tool_call` is the original frozen `AuthorizeToolCall`
    /// that was already stored on the approval but never surfaced over the API.
    #[tokio::test]
    async fn test_list_approvals_route_includes_agent_id_and_tool_call() {
        let (state, tenant_id, agent_token) = setup_state("list_approvals_enriched").await;
        let agent = state
            .storage
            .get_agent_by_token(&tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id.clone();

        let decision_id = Uuid::new_v4().to_string();
        let record_dec = DecisionRecord {
            id: decision_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "github".to_string(),
            action: "merge_pull_request".to_string(),
            resource: Some("octocat/demo#42".to_string()),
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
        state.storage.insert_decision(&record_dec).await.unwrap();

        let tool_call_json = serde_json::json!({
            "tool": "github",
            "action": "merge_pull_request",
            "resource": "octocat/demo#42",
            "mutates_state": true,
            "parameters": {"base_branch": "main"}
        })
        .to_string();

        let approval_id = Uuid::new_v4().to_string();
        let record = ApprovalRecord {
            id: approval_id.clone(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id.clone(),
            status: "created".to_string(),
            approver_group: None,
            approver_user_id: None,
            reason: None,
            original_skill_call: tool_call_json,
            original_call_hash: "hash1".to_string(),
            edited_skill_call: None,
            effective_call_hash: None,
            expires_at: Some(Utc::now() + Duration::minutes(10)),
            decided_at: None,
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now(),
        };
        state.storage.insert_approval(&record).await.unwrap();

        let response = list_approvals(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = json.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["agent_id"].as_str(), Some(agent_id.as_str()));
        assert_eq!(list[0]["tool_call"]["tool"].as_str(), Some("github"));
        assert_eq!(
            list[0]["tool_call"]["action"].as_str(),
            Some("merge_pull_request")
        );
        assert_eq!(
            list[0]["tool_call"]["resource"].as_str(),
            Some("octocat/demo#42")
        );

        // GET /v1/approvals/:id must surface the same enrichment.
        let single_response = get_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(Uuid::parse_str(&approval_id).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(single_response.status(), StatusCode::OK);
        let single_body = to_bytes(single_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let single_json: serde_json::Value = serde_json::from_slice(&single_body).unwrap();
        assert_eq!(single_json["agent_id"].as_str(), Some(agent_id.as_str()));
        assert_eq!(single_json["tool_call"]["tool"].as_str(), Some("github"));
    }

    /// #0145: tenant isolation — an approval created under tenant A is invisible
    /// (404) to tenant B via GET /v1/approvals/:id, and is excluded from
    /// tenant B's GET /v1/approvals listing.
    #[tokio::test]
    async fn get_approval_returns_404_cross_tenant() {
        let (state, tenant_a, agent_token) = setup_state("approval_cross_tenant").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_a, &agent_token, "40").await;

        let tenant_b = format!("tenant_b_{}", Uuid::new_v4().simple());
        register_tenant_helper(state.storage.as_ref(), &tenant_b, "Tenant B", "developer").await;

        // Owning tenant can fetch it.
        let own = get_approval(
            State(state.clone()),
            TenantId(tenant_a.clone()),
            Path(approval_id),
        )
        .await
        .into_response();
        assert_eq!(own.status(), StatusCode::OK);

        // Cross-tenant fetch returns 404, not the other tenant's approval.
        let cross = get_approval(
            State(state.clone()),
            TenantId(tenant_b.clone()),
            Path(approval_id),
        )
        .await
        .into_response();
        assert_eq!(cross.status(), StatusCode::NOT_FOUND);

        // Cross-tenant listing must not include tenant A's approval.
        let list_response = list_approvals(
            State(state.clone()),
            TenantId(tenant_b),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    /// Computes the `X-Slack-Signature: v0=<hex hmac>` header value for a
    /// Slack interactive-component callback, per Slack's signing spec:
    /// `HMAC-SHA256(secret, "v0:{timestamp}:{body}")`.
    fn slack_signature_header(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(b"v0:");
        mac.update(timestamp.as_bytes());
        mac.update(b":");
        mac.update(body);
        format!("v0={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Builds a Slack interactive-component callback body
    /// (`payload=<percent-encoded JSON>`) for `action_id`/`value`.
    fn slack_callback_body(action_id: &str, value: &str) -> Bytes {
        let payload = json!({
            "actions": [{"action_id": action_id, "value": value}],
            "user": {"username": "reviewer", "id": "U123"},
        });
        let encoded = percent_encoding::utf8_percent_encode(
            &payload.to_string(),
            percent_encoding::NON_ALPHANUMERIC,
        )
        .to_string();
        Bytes::from(format!("payload={encoded}"))
    }

    /// #1276: when `slack_signing_secret` is not configured, the callback
    /// endpoint fails closed with `404` regardless of headers/body.
    #[tokio::test]
    async fn slack_callback_returns_404_when_secret_not_configured() {
        let (state, _tenant_id, _agent_token) = setup_state("slack_no_secret").await;

        let response = slack_callback(State(state.clone()), HeaderMap::new(), Bytes::new())
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// #1276: a callback with a timestamp older than 5 minutes is rejected
    /// with `401` and `reason: "stale_timestamp"`, even if the signature
    /// over that (stale) timestamp is otherwise valid.
    #[tokio::test]
    async fn slack_callback_rejects_stale_timestamp_with_401() {
        let (state, _tenant_id, _agent_token) =
            setup_state_with_slack_secret("slack_stale_ts", "test_secret").await;

        let body = slack_callback_body("approve", "tenant:00000000-0000-0000-0000-000000000000");
        let stale_ts = (Utc::now() - Duration::minutes(10)).timestamp().to_string();
        let sig = slack_signature_header("test_secret", &stale_ts, &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Slack-Request-Timestamp",
            axum::http::HeaderValue::from_str(&stale_ts).unwrap(),
        );
        headers.insert(
            "X-Slack-Signature",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = slack_callback(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["details"]["reason"], "stale_timestamp");
    }

    /// #1276: a callback signed with the wrong secret is rejected with `401`
    /// and `reason: "invalid_signature"`.
    #[tokio::test]
    async fn slack_callback_rejects_invalid_signature_with_401() {
        let (state, _tenant_id, _agent_token) =
            setup_state_with_slack_secret("slack_bad_sig", "test_secret").await;

        let body = slack_callback_body("approve", "tenant:00000000-0000-0000-0000-000000000000");
        let ts = Utc::now().timestamp().to_string();
        // Signed with a different secret than the one configured server-side.
        let sig = slack_signature_header("wrong_secret", &ts, &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Slack-Request-Timestamp",
            axum::http::HeaderValue::from_str(&ts).unwrap(),
        );
        headers.insert(
            "X-Slack-Signature",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = slack_callback(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["details"]["reason"], "invalid_signature");
    }

    /// #1329: a captured valid (timestamp, signature) pair replayed against a
    /// modified body is rejected with `401`/`invalid_signature` — the HMAC
    /// covers the body, so tampering after signing invalidates it.
    #[tokio::test]
    async fn slack_callback_rejects_tampered_body_with_401() {
        let (state, _tenant_id, _agent_token) =
            setup_state_with_slack_secret("slack_tampered_body", "test_secret").await;

        let original_body =
            slack_callback_body("approve", "tenant:00000000-0000-0000-0000-000000000000");
        let ts = Utc::now().timestamp().to_string();
        // Signature is computed over the original body...
        let sig = slack_signature_header("test_secret", &ts, &original_body);

        // ...but the attacker swaps in a different body (e.g. a different
        // action_id/approval id) while keeping the original signature/timestamp.
        let tampered_body =
            slack_callback_body("reject", "tenant:11111111-1111-1111-1111-111111111111");
        assert_ne!(original_body, tampered_body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Slack-Request-Timestamp",
            axum::http::HeaderValue::from_str(&ts).unwrap(),
        );
        headers.insert(
            "X-Slack-Signature",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = slack_callback(State(state.clone()), headers, tampered_body)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["details"]["reason"], "invalid_signature");
    }

    /// #1276: a validly-signed callback with `action_id: "approve"` and
    /// `value: "{tenant_id}:{approval_id}"` transitions the matching pending
    /// approval to `APPROVED`.
    #[tokio::test]
    async fn slack_callback_approve_action_approves_pending_approval() {
        let (state, tenant_id, agent_token) =
            setup_state_with_slack_secret("slack_approve", "test_secret").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "30").await;

        let value = format!("{tenant_id}:{approval_id}");
        let body = slack_callback_body("approve", &value);
        let ts = Utc::now().timestamp().to_string();
        let sig = slack_signature_header("test_secret", &ts, &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Slack-Request-Timestamp",
            axum::http::HeaderValue::from_str(&ts).unwrap(),
        );
        headers.insert(
            "X-Slack-Signature",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = slack_callback(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "APPROVED");
        assert_eq!(stored.approver_user_id.as_deref(), Some("reviewer"));
    }

    /// #1276: a validly-signed callback with `action_id: "reject"` transitions
    /// the matching pending approval to `REJECTED`.
    #[tokio::test]
    async fn slack_callback_reject_action_rejects_pending_approval() {
        let (state, tenant_id, agent_token) =
            setup_state_with_slack_secret("slack_reject", "test_secret").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "31").await;

        let value = format!("{tenant_id}:{approval_id}");
        let body = slack_callback_body("reject", &value);
        let ts = Utc::now().timestamp().to_string();
        let sig = slack_signature_header("test_secret", &ts, &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Slack-Request-Timestamp",
            axum::http::HeaderValue::from_str(&ts).unwrap(),
        );
        headers.insert(
            "X-Slack-Signature",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = slack_callback(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let stored = state
            .storage
            .get_approval_by_id(&tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval should exist");
        assert_eq!(stored.status, "REJECTED");
    }

    /// #1276: a validly-signed callback whose body has no `payload` field is
    /// rejected with `400`.
    #[tokio::test]
    async fn slack_callback_missing_payload_field_returns_400() {
        let (state, _tenant_id, _agent_token) =
            setup_state_with_slack_secret("slack_missing_payload", "test_secret").await;

        let body = Bytes::from("not_a_payload=true");
        let ts = Utc::now().timestamp().to_string();
        let sig = slack_signature_header("test_secret", &ts, &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Slack-Request-Timestamp",
            axum::http::HeaderValue::from_str(&ts).unwrap(),
        );
        headers.insert(
            "X-Slack-Signature",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = slack_callback(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// #1276: a validly-signed callback whose `value` does not contain a
    /// well-formed `{tenant_id}:{approval_id}` (non-UUID approval id) is
    /// rejected with `400`.
    #[tokio::test]
    async fn slack_callback_malformed_approval_id_returns_400() {
        let (state, tenant_id, _agent_token) =
            setup_state_with_slack_secret("slack_bad_id", "test_secret").await;

        let value = format!("{tenant_id}:not-a-uuid");
        let body = slack_callback_body("approve", &value);
        let ts = Utc::now().timestamp().to_string();
        let sig = slack_signature_header("test_secret", &ts, &body);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Slack-Request-Timestamp",
            axum::http::HeaderValue::from_str(&ts).unwrap(),
        );
        headers.insert(
            "X-Slack-Signature",
            axum::http::HeaderValue::from_str(&sig).unwrap(),
        );

        let response = slack_callback(State(state.clone()), headers, body)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
