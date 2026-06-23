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

// Verify a stored action receipt by recomputing its hash from the canonical body.
pub async fn verify_receipt(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(receipt_id): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_action_receipt_by_id(&tenant_id, &receipt_id)
        .await
    {
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
                    "signer_key_id": rec.signer_key_id,
                })),
            )
                .into_response()
        }
        Ok(None) => StatusError::not_found("Receipt not found").into_response(),
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/receipts — list paginated action receipts for the authenticated tenant.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
///   `cursor` (#1142) — opaque keyset-pagination token from a previous
///   page's `X-Next-Cursor` response header; takes priority over `offset`
///   when both are supplied.
pub async fn list_receipts(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    let cursor = match parse_cursor(raw_query.as_deref()) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };

    match state
        .storage
        .list_action_receipts_cursor(&tenant_id, limit, offset, cursor)
        .await
    {
        Ok((receipts, next_cursor)) => paginated_response(&receipts, next_cursor),
        Err(e) => {
            error!("Failed to list receipts: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/receipts/:id — get a single action receipt for the authenticated tenant.
pub async fn get_receipt(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_action_receipt_by_id(&tenant_id, &id)
        .await
    {
        Ok(Some(receipt)) => (StatusCode::OK, Json(receipt)).into_response(),
        Ok(None) => StatusError::not_found("Receipt not found").into_response(),
        Err(e) => {
            error!("Failed to get receipt: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct VerifyChainRequest {
    pub receipts: Vec<Value>,
}

pub async fn verify_receipt_chain(
    State(_state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<VerifyChainRequest>,
) -> impl IntoResponse {
    let receipts = &payload.receipts;
    if receipts.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({
                "verified": true,
                "error": null
            })),
        )
            .into_response();
    }

    let mut prev = String::new();
    for (i, receipt) in receipts.iter().enumerate() {
        let obj = match receipt.as_object() {
            Some(o) => o,
            None => {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "verified": false,
                        "error": format!("Receipt at index {} is not a valid JSON object", i)
                    })),
                )
                    .into_response();
            }
        };

        // 1. Tenant validation (CWE-284 isolation!)
        if let Some(tenant_in_receipt) = obj.get("tenant_id").and_then(|v| v.as_str()) {
            if tenant_in_receipt != tenant_id {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "verified": false,
                        "error": format!("Tenant mismatch at index {}: receipt has tenant '{}' but request is for '{}'", i, tenant_in_receipt, tenant_id)
                    })),
                )
                    .into_response();
            }
        }

        // 2. Hash validation
        let stored = match obj.get("receipt_hash").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "verified": false,
                        "error": format!("Missing receipt_hash at index {}", i)
                    })),
                )
                    .into_response();
            }
        };

        // Remove receipt_hash, signature, signer_public_key, signer_key_id, and
        // created_at to get canonical body
        let mut body = obj.clone();
        body.remove("receipt_hash");
        body.remove("signature");
        body.remove("signer_public_key");
        body.remove("signer_key_id");
        body.remove("created_at");

        let recomputed = sha256_hex(canonical_value_string(&Value::Object(body)).as_bytes());
        if recomputed != stored {
            return (
                StatusCode::OK,
                Json(json!({
                    "verified": false,
                    "error": format!("Hash mismatch at index {}: stored '{}', recomputed '{}'", i, stored, recomputed)
                })),
            )
                .into_response();
        }

        // 3. Linkage validation
        let prev_in_receipt = obj
            .get("prev_receipt_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if i == 0 {
            prev = prev_in_receipt.to_string();
        }
        if prev_in_receipt != prev {
            return (
                StatusCode::OK,
                Json(json!({
                    "verified": false,
                    "error": format!("Link broken at index {}: prev_receipt_hash '{}' does not match expected '{}'", i, prev_in_receipt, prev)
                })),
            )
                .into_response();
        }

        prev = stored.to_string();
    }

    (
        StatusCode::OK,
        Json(json!({
            "verified": true,
            "error": null
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub struct CreatePolicyRequest {
    pub policy_key: String,
    pub name: String,
    pub body: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdatePolicyRequest {
    pub policy_key: Option<String>,
    pub name: Option<String>,
    pub body: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct IngestRequest {
    /// One of [`crate::ingest::SUPPORTED_SOURCES`].
    pub source: String,
    /// The raw event payload from the external system, in that system's
    /// native shape (e.g. a GitHub webhook body, an OpenAI trace entry).
    pub payload: serde_json::Value,
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

    // A fixed test secret (hex, 32 bytes). Test-only — not a real key. Used to
    // emit a signed receipt directly via the atomic appender (so we exercise the
    // verify endpoint's signature path without coupling to the process-global env
    // signer, which `OnceLock`-initializes once per process).
    const TEST_SIGNING_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    /// #0136: verify_receipt detects a receipt whose stored `receipt_hash` no
    /// longer matches its recomputed value (tamper detection).
    #[tokio::test]
    async fn verify_receipt_detects_tampered_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("tampered_single_receipt").await;

        let prev = state.storage.get_latest_action_receipt(&tenant_id).await.unwrap()
            .map(|r| r.receipt_hash).unwrap_or_default();
        let mut r = unsigned_receipt_template(&tenant_id);
        r.prev_receipt_hash = prev;
        r.receipt_hash = db::compute_receipt_hash(&r);
        state.storage.insert_action_receipt(&r).await.unwrap();
        let rec = r;

        sqlx::query("UPDATE action_receipts SET receipt_hash = 'sha256:tampered' WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id.as_str())
            .bind(&rec.id)
            .execute(state.storage.get_pool())
            .await
            .unwrap();

        let response = verify_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(false));
        assert_eq!(json["receipt_hash"].as_str(), Some("sha256:tampered"));
        assert_ne!(
            json["recomputed_hash"].as_str(),
            json["receipt_hash"].as_str()
        );
    }

    #[tokio::test]
    async fn verify_reports_signature_for_a_signed_receipt() {
        let (state, tenant_id, _agent_token) = setup_state("signed_receipt").await;
        let signer = sign::ReceiptSigner::from_secret_hex(TEST_SIGNING_SECRET_HEX).unwrap();

        // Insert a signed receipt through the real atomic appender. Hash FIRST over
        // the live chain head, then sign OVER that hash (additive metadata).
        let prev = state.storage.get_latest_action_receipt(&tenant_id).await.unwrap()
            .map(|r| r.receipt_hash).unwrap_or_default();
        let mut r = unsigned_receipt_template(&tenant_id);
        r.prev_receipt_hash = prev;
        r.receipt_hash = db::compute_receipt_hash(&r);
        r.signature = Some(signer.sign_hash(&r.receipt_hash));
        r.signer_public_key = Some(signer.public_key_hex());
        state.storage.insert_action_receipt(&r).await.unwrap();
        let rec = r;

        let response = verify_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
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

    /// #1211: a signer constructed from a `"key_id:hex_secret"` value
    /// persists and round-trips its `key_id` through the real DB insert +
    /// `GET /v1/receipts/:id/verify` response, alongside the existing
    /// `signer_public_key` — auditors can tell which generation of key
    /// produced a given receipt without recognizing a raw public-key hex.
    #[tokio::test]
    async fn verify_reports_signer_key_id_when_present() {
        let (state, tenant_id, _agent_token) = setup_state("signed_receipt_key_id").await;
        let signer = sign::ReceiptSigner::from_env_value(&format!(
            "rotation-2026-06:{TEST_SIGNING_SECRET_HEX}"
        ))
        .unwrap();
        assert_eq!(signer.key_id(), Some("rotation-2026-06"));

        let prev = state.storage.get_latest_action_receipt(&tenant_id).await.unwrap()
            .map(|r| r.receipt_hash).unwrap_or_default();
        let mut r = unsigned_receipt_template(&tenant_id);
        r.prev_receipt_hash = prev;
        r.receipt_hash = db::compute_receipt_hash(&r);
        r.signature = Some(signer.sign_hash(&r.receipt_hash));
        r.signer_public_key = Some(signer.public_key_hex());
        r.signer_key_id = signer.key_id().map(str::to_string);
        state.storage.insert_action_receipt(&r).await.unwrap();
        let rec = r;

        let response = verify_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["signature_verified"].as_bool(), Some(true));
        assert_eq!(json["signer_key_id"].as_str(), Some("rotation-2026-06"));

        // Also round-trips through a direct DB read, not just the verify response.
        let fetched = state.storage.get_action_receipt_by_id( &tenant_id, &rec.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.signer_key_id.as_deref(), Some("rotation-2026-06"));
    }

    /// A receipt signed with no `key_id` prefix (the pre-#1211 plain hex
    /// secret format) must still verify and report `signer_key_id: null`,
    /// not break or silently invent a value.
    #[tokio::test]
    async fn verify_reports_null_signer_key_id_when_absent() {
        let (state, tenant_id, _agent_token) = setup_state("signed_receipt_no_key_id").await;
        let signer = sign::ReceiptSigner::from_env_value(TEST_SIGNING_SECRET_HEX).unwrap();
        assert_eq!(signer.key_id(), None);

        let prev = state.storage.get_latest_action_receipt(&tenant_id).await.unwrap()
            .map(|r| r.receipt_hash).unwrap_or_default();
        let mut r = unsigned_receipt_template(&tenant_id);
        r.prev_receipt_hash = prev;
        r.receipt_hash = db::compute_receipt_hash(&r);
        r.signature = Some(signer.sign_hash(&r.receipt_hash));
        r.signer_public_key = Some(signer.public_key_hex());
        r.signer_key_id = signer.key_id().map(str::to_string);
        state.storage.insert_action_receipt(&r).await.unwrap();
        let rec = r;

        let response = verify_receipt(State(state), TenantId(tenant_id), Path(rec.id))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["signature_verified"].as_bool(), Some(true));
        assert!(json["signer_key_id"].is_null());
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
            canon_version: CANON_VERSION.to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
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

        // #1211: populating signer_key_id on top must ALSO leave the hash unchanged.
        unsigned.signer_key_id = Some("rotation-2026-06".to_string());
        let hash_with_key_id = compute_receipt_hash(&unsigned);
        assert_eq!(
            hash_unsigned, hash_with_key_id,
            "signer_key_id must not change the receipt hash (byte-parity moat)"
        );
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
            let pool = state.storage.get_pool().clone();
            let tenant = tenant_id.clone();
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                let rec = ActionReceiptRecord {
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
                    prev_receipt_hash: String::new(),
                    receipt_hash: String::new(),
                    canon_version: CANON_VERSION.to_string(),
                    signature: None,
                    signer_public_key: None,
                    signer_key_id: None,
                    created_at: Utc::now(),
                };
                state.storage.append_action_receipt_atomic(&tenant, rec).await
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
        .fetch_all(state.storage.get_pool())
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

    #[tokio::test]
    async fn test_verify_receipt_chain_route() {
        let (state, tenant_id, _) = setup_state("verify_chain_route").await;

        let corpus_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/receipt_chain_vectors.json"
        );
        let raw = std::fs::read_to_string(corpus_path).expect("shared receipt corpus must exist");
        let corpus: Value = serde_json::from_str(&raw).unwrap();
        let receipts = corpus["receipts"].as_array().unwrap().clone();

        // 1. Verify successful corpus chain
        let payload = VerifyChainRequest {
            receipts: receipts.clone(),
        };
        let response = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(true));

        // 2. Tampered field (hash mismatch)
        let mut tampered_receipts = receipts.clone();
        if let Some(obj) = tampered_receipts[1].as_object_mut() {
            obj.insert("action".to_string(), json!("delete_repo"));
        }
        let payload_tampered = VerifyChainRequest {
            receipts: tampered_receipts,
        };
        let response_tampered = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload_tampered),
        )
        .await
        .into_response();
        assert_eq!(response_tampered.status(), StatusCode::OK);
        let body_tampered = to_bytes(response_tampered.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_tampered: Value = serde_json::from_slice(&body_tampered).unwrap();
        assert_eq!(json_tampered["verified"].as_bool(), Some(false));

        // 3. Mismatched tenant validation
        let mut tenant_receipts = receipts.clone();
        if let Some(obj) = tenant_receipts[0].as_object_mut() {
            obj.insert("tenant_id".to_string(), json!("tenant_other"));
        }
        let payload_tenant = VerifyChainRequest {
            receipts: tenant_receipts,
        };
        let response_tenant = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload_tenant),
        )
        .await
        .into_response();
        assert_eq!(response_tenant.status(), StatusCode::OK);
        let body_tenant = to_bytes(response_tenant.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_tenant: Value = serde_json::from_slice(&body_tenant).unwrap();
        assert_eq!(json_tenant["verified"].as_bool(), Some(false));
    }

    /// TASK-0157 (#1003): a 1000-entry receipt chain must verify end-to-end —
    /// `POST /v1/receipts/verify-chain` must walk all 1000 links without error,
    /// and a single tampered entry anywhere in a 1000-entry chain must still be
    /// detected (hash mismatch breaks the chain from that point on).
    #[tokio::test]
    async fn receipt_chain_with_1000_entries_verifies() {
        let (state, tenant_id, _agent_token) = setup_state("receipt_chain_1000").await;

        const N: usize = 1000;
        for i in 0..N {
            let receipt = ActionReceiptRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                decision_id: None,
                ts: Utc::now().to_rfc3339(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                tool: Some("filesystem".to_string()),
                action: Some("read_file".to_string()),
                resource: Some(format!("/tmp/file-{i}")),
                source_trust: "trusted_internal_signed".to_string(),
                decision: "allow".to_string(),
                approver: None,
                action_hash: Some(format!("{i:064x}")),
                prev_receipt_hash: String::new(),
                receipt_hash: String::new(),
                canon_version: CANON_VERSION.to_string(),
                signature: None,
                signer_public_key: None,
                signer_key_id: None,
                created_at: Utc::now(),
            };
            state.storage.append_action_receipt_atomic(&tenant_id, receipt).await.unwrap();
        }

        let chain = state.storage.list_action_receipts_chain_order( &tenant_id)
            .await
            .unwrap();
        assert_eq!(chain.len(), N, "all 1000 receipts must be persisted");

        let receipts: Vec<Value> = chain
            .iter()
            .map(|r| {
                let mut body = receipt_body_value(r);
                body["receipt_hash"] = json!(r.receipt_hash);
                body
            })
            .collect();

        // 1. A clean 1000-entry chain verifies.
        let response = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(VerifyChainRequest {
                receipts: receipts.clone(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(true));

        // 2. Tampering with an entry in the middle of a 1000-entry chain is detected.
        let mut tampered = receipts.clone();
        if let Some(obj) = tampered[N / 2].as_object_mut() {
            obj.insert("action".to_string(), json!("delete_file"));
        }
        let response_tampered = verify_receipt_chain(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(VerifyChainRequest { receipts: tampered }),
        )
        .await
        .into_response();
        assert_eq!(response_tampered.status(), StatusCode::OK);
        let body_tampered = to_bytes(response_tampered.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_tampered: Value = serde_json::from_slice(&body_tampered).unwrap();
        assert_eq!(json_tampered["verified"].as_bool(), Some(false));
    }
}
