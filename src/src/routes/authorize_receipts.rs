//! Receipt emission helpers for the authorization pipeline.
//!
//! Extracted from `authorize.rs` for clarity. All functions are `pub(crate)` and
//! re-exported via `routes/mod.rs` so existing call sites are unaffected.

use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::models::*;
use crate::sign;

use super::authorize_canon::{hash_tool_call, sha256_hex, CANON_VERSION};
use super::compute_receipt_hash;

/// Optionally attach an Ed25519 signature OVER the already-computed `receipt_hash`.
///
/// This runs AFTER `compute_receipt_hash` and never feeds back into the hash: the
/// signature and signer public key are additive metadata stored alongside the
/// receipt, so the byte-parity-locked `aegis-jcs-1` chain is untouched. When no
/// signer is configured (`global_signer() == None`), both fields stay NULL and
/// the receipt is emitted unsigned (hermetic default). We sign the hash, never a
/// payload (redaction preserved).
#[allow(dead_code)]
pub(crate) fn apply_receipt_signature(receipt: &mut ActionReceiptRecord) {
    if let Some(signer) = sign::global_signer() {
        receipt.signature = Some(signer.sign_hash(&receipt.receipt_hash));
        receipt.signer_public_key = Some(signer.public_key_hex());
        receipt.signer_key_id = signer.key_id().map(str::to_string);
    }
}

/// Emit a hash-chained, verifiable receipt for a finalized decision. Non-fatal:
/// a receipt write failure is logged but does not change the authorization
/// result. #1512: the write itself is spawned as a tracked background task
/// (see [`super::DeferredWriteTracker`]) rather than `.await`ed inline — it
/// competed for the SQLite WAL write lock with the decision write on every
/// request. This function returns as soon as the write is scheduled, not
/// once it lands.
///
/// 8 args: each is an independently-required identifier/handle (storage,
/// tracker, tenant/agent ids, the request payload, the decision outcome, and
/// the precomputed `action_hash` threaded in to avoid re-hashing the tool
/// call — see the JCS-1 canonicalization cache). Single call site
/// (`authorize.rs`'s decision path); a wrapper struct would be pure
/// ceremony here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn emit_action_receipt(
    storage: &Arc<dyn aegis_storage::traits::StorageBackend>,
    deferred_write_tracker: &Arc<super::DeferredWriteTracker>,
    tenant_id: &str,
    agent_id: &str,
    payload: &AuthorizeRequest,
    decision_id: Uuid,
    decision: &str,
    action_hash: &str,
) {
    // Build the head-referencing receipt inside one atomic transaction (T-D
    // hardening): the chain head is read and the new link inserted under a single
    // write lock, so concurrent authorizes for this tenant cannot fork the chain.
    let receipt = ActionReceiptRecord {
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
        action_hash: Some(action_hash.to_string()),
        prev_receipt_hash: String::new(),
        receipt_hash: String::new(),
        // Self-describing scheme tag; additive, not folded into receipt_hash.
        canon_version: CANON_VERSION.to_string(),
        signature: None,
        signer_public_key: None,
        signer_key_id: None,
        created_at: Utc::now(),
    };

    let storage = Arc::clone(storage);
    let tenant_id_owned = tenant_id.to_string();
    deferred_write_tracker.spawn_tracked(async move {
        // `SqliteStorage::append_action_receipt_atomic` doesn't retry on its
        // own, so wrap it the same way the deferred risk-score write is.
        if let Err(e) = super::retry_storage_write_on_busy(3, || {
            storage.append_action_receipt_atomic(&tenant_id_owned, receipt.clone())
        })
        .await
        {
            error!("Failed to write action receipt: {:?}", e);
        }
    });
}

/// Decision label for a receipt recording a detected integrity violation (T-D:
/// attacks on the evidence chain). A tamper-attempt receipt is appended to the same
/// hash chain as normal decisions so the chain itself records the attack — storing
/// ONLY hashes, never payloads.
pub(crate) const TAMPER_DECISION: &str = "tamper_attempt";

/// Append a tamper-attempt record to a tenant's receipt chain when the gateway
/// detects an integrity violation (an approval `action_hash` mismatch, or a consume
/// of an already-used / expired approval). Reuses the atomic, hash-chained receipt
/// machinery so the attack is tamper-evidently recorded. `kind` is a short, stable
/// tag for the violation; `action_hash` is the bound hash (never a payload). Also
/// mirrors the event into the audit log. Best-effort: a write failure is logged and
/// does not change the caller's response.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn emit_tamper_attempt_receipt(
    storage: &dyn aegis_storage::traits::StorageBackend,
    events: &EventSink,
    tenant_id: &str,
    agent_id: Option<&str>,
    kind: &str,
    approval_id: &str,
    action_hash: Option<String>,
    decision_id: Option<&str>,
) {
    let kind_owned = kind.to_string();
    let action_hash_for_receipt = action_hash.clone();
    let receipt = ActionReceiptRecord {
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
        prev_receipt_hash: String::new(),
        receipt_hash: String::new(),
        canon_version: CANON_VERSION.to_string(),
        signature: None,
        signer_public_key: None,
        signer_key_id: None,
        created_at: Utc::now(),
    };

    if let Err(e) = storage
        .append_action_receipt_atomic(tenant_id, receipt)
        .await
    {
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
        decision_id: decision_id.map(|s| s.to_string()),
        approval_id: Some(approval_id.to_string()),
        created_at: Utc::now(),
    };
    if let Err(e) = storage.insert_audit_event(&audit_record).await {
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
        redacted_fields: vec![],
        schema_version: 1,
    });
}
