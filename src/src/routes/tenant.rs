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

/// #1289: returns the effective per-tenant composite-risk-score weights
/// (DB override if present, otherwise `RiskWeights::from_env()`). Advisory
/// configuration only — never affects `allow`/`deny`/`require_approval`.
pub async fn get_tenant_risk_weights(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state.storage.get_tenant_risk_weights(&tenant_id).await {
        Ok(Some(weights)) => (StatusCode::OK, Json(weights)).into_response(),
        Ok(None) => (StatusCode::OK, Json(RiskWeights::from_env())).into_response(),
        Err(e) => {
            error!("Failed to get tenant risk weights: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1289: upserts per-tenant composite-risk-score weight overrides.
/// Advisory configuration only — never affects `allow`/`deny`/`require_approval`.
pub async fn put_tenant_risk_weights(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(weights): Json<RiskWeights>,
) -> impl IntoResponse {
    match state
        .storage
        .put_tenant_risk_weights(&tenant_id, &weights)
        .await
    {
        Ok(_) => {
            // #1513: drop the cached entry so the next `/v1/authorize` call
            // picks up this override immediately instead of waiting out the
            // TTL on a now-stale cached value.
            state.risk_weight_cache.invalidate(&tenant_id);
            (StatusCode::OK, Json(weights)).into_response()
        }
        Err(e) => {
            error!("Failed to upsert tenant risk weights: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1296: returns this tenant's risk-escalation thresholds (DB override if
/// present, otherwise the built-in default of 5 denials / 60-minute window).
pub async fn get_tenant_risk_escalation_config(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state
        .storage
        .get_tenant_risk_escalation_config(&tenant_id)
        .await
    {
        Ok(Some((threshold, window))) => {
            let config = RiskEscalationConfig {
                denial_threshold: threshold as i64,
                window_minutes: window as i64,
            };
            (StatusCode::OK, Json(config)).into_response()
        }
        Ok(None) => {
            let config = RiskEscalationConfig::default();
            (StatusCode::OK, Json(config)).into_response()
        }
        Err(e) => {
            error!("Failed to get tenant risk escalation config: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1296: upserts this tenant's risk-escalation thresholds. Both fields must
/// be positive — a zero or negative threshold/window would either escalate
/// on every single denial or never match any window at all, neither of
/// which is a meaningful configuration.
pub async fn put_tenant_risk_escalation_config(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(config): Json<RiskEscalationConfig>,
) -> impl IntoResponse {
    if config.denial_threshold < 1 || config.window_minutes < 1 {
        return StatusError::bad_request("denial_threshold and window_minutes must each be >= 1")
            .into_response();
    }
    match state
        .storage
        .put_tenant_risk_escalation_config(
            &tenant_id,
            config.denial_threshold as i32,
            config.window_minutes as i32,
        )
        .await
    {
        Ok(_) => (StatusCode::OK, Json(config)).into_response(),
        Err(e) => {
            error!("Failed to upsert tenant risk escalation config: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// POST /v1/api_keys — create a new tenant-managed API key. TASK-0093
/// (#939): the plaintext key is returned exactly once in the response body;
/// only `sha256(key)` is persisted (see `db::create_api_key`).
pub async fn create_api_key(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    match state
        .storage
        .create_api_key(&tenant_id, &payload.name)
        .await
    {
        Ok((id, key)) => (StatusCode::CREATED, Json(json!({"id": id, "key": key}))).into_response(),
        Err(e) => {
            error!("Failed to create API key: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/api_keys — list the authenticated tenant's API keys.
/// `key_hash` is included (it is not a secret), the plaintext key never is.
pub async fn list_api_keys(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state.storage.list_api_keys(&tenant_id).await {
        Ok(keys) => (StatusCode::OK, Json(keys)).into_response(),
        Err(e) => {
            error!("Failed to list API keys: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// POST /v1/api_keys/:id/revoke — revoke a tenant-managed API key.
pub async fn revoke_api_key(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.revoke_api_key(&tenant_id, &id).await {
        Ok(true) => (StatusCode::OK, Json(json!({"message": "API key revoked"}))).into_response(),
        Ok(false) => StatusError::not_found("API key not found").into_response(),
        Err(e) => {
            error!("Failed to revoke API key: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn get_tenant(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if tenant_id != id {
        return StatusError::not_found("Tenant not found").into_response();
    }

    match state.storage.get_tenant_by_id(&tenant_id).await {
        Ok(Some(tenant)) => (StatusCode::OK, Json(tenant)).into_response(),
        Ok(None) => StatusError::not_found("Tenant not found").into_response(),
        Err(e) => {
            error!("Failed to get tenant: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Query params for `GET /v1/compliance/evidence-pack` (#1298). Both bounds
/// are optional RFC-3339 timestamps; an absent bound leaves that side of the
/// range open. Strings (not `DateTime<Utc>`) so invalid input can be reported
/// as a 400 rather than rejected silently by the extractor.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EvidencePackParams {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

/// GET /v1/compliance/evidence-pack — compliance evidence pack export (#1298).
///
/// Returns a ZIP archive (tenant-scoped, optionally date-bounded by `from`/`to`
/// RFC-3339 query params) containing:
/// - `manifest.json` — schema tag, tenant id, generation time, requested
///   range, row counts, and the canonicalization scheme.
/// - `receipts.jsonl` — date-filtered `action_receipts` (one JSON object per
///   line). Receipts may carry an optional Ed25519 `signature` /
///   `signer_public_key` (plus an optional human-readable `signer_key_id`,
///   #1211) — non-repudiation evidence (SOC 2 / EU AI Act Art. 14).
/// - `audit_events.jsonl` — date-filtered `audit_events`.
/// - `policies.json` — the tenant's *current* policy set (not date-filtered;
///   documented in `manifest.json`).
/// - `incidents.json` — date-filtered `soc_incidents` (by `opened_at`).
/// - `approvals.json` — date-filtered `approvals`, including
///   `approver_user_id` / `decided_at` — human-oversight evidence.
///
/// Fails closed: an unparsable `from`/`to` returns `400 Bad Request` rather
/// than silently ignoring the filter.
pub async fn get_evidence_pack(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::Query(params): axum::extract::Query<EvidencePackParams>,
) -> impl IntoResponse {
    let from = match params.from.as_deref().map(DateTime::parse_from_rfc3339) {
        Some(Ok(dt)) => Some(dt.with_timezone(&Utc)),
        Some(Err(e)) => {
            return StatusError::bad_request(format!("invalid 'from' timestamp: {e}"))
                .into_response();
        }
        None => None,
    };
    let to = match params.to.as_deref().map(DateTime::parse_from_rfc3339) {
        Some(Ok(dt)) => Some(dt.with_timezone(&Utc)),
        Some(Err(e)) => {
            return StatusError::bad_request(format!("invalid 'to' timestamp: {e}"))
                .into_response();
        }
        None => None,
    };

    let receipts = match state
        .storage
        .list_action_receipts_in_range(&tenant_id, from, to)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to load receipts for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    let audit_events = match state
        .storage
        .get_audit_events_in_range(&tenant_id, from, to)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to load audit events for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    let approvals = match state
        .storage
        .list_approvals_in_range(&tenant_id, from, to)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to load approvals for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    let incidents = match state
        .storage
        .list_soc_incidents_in_range(&tenant_id, from, to)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to load incidents for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    let policies = match state.storage.list_policies(&tenant_id).await {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to load policies for evidence pack: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let manifest = json!({
        "schema": "aegis-evidence-pack-1",
        "tenant_id": tenant_id,
        "generated_at": Utc::now().to_rfc3339(),
        "range": {
            "from": params.from,
            "to": params.to,
        },
        "counts": {
            "receipts": receipts.len(),
            "audit_events": audit_events.len(),
            "approvals": approvals.len(),
            "incidents": incidents.len(),
            "policies": policies.len(),
        },
        "canonicalization_scheme": "aegis-jcs-1",
        "policies_note": "policies.json reflects current policy state, not date-filtered",
    });

    let zip_bytes = match build_evidence_pack_zip(
        &manifest,
        &receipts,
        &audit_events,
        &policies,
        &incidents,
        &approvals,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to build evidence pack zip: {:?}", e);
            return StatusError::internal("Failed to build evidence pack").into_response();
        }
    };

    let filename = format!("evidence-pack-{tenant_id}-{}.zip", Utc::now().timestamp());
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/zip".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        zip_bytes,
    )
        .into_response()
}

/// Serialize the evidence-pack entries into an in-memory ZIP archive
/// (#1298). `manifest` is written as pretty JSON; the `.jsonl` entries are one
/// compact JSON object per line; the `.json` entries are JSON arrays.
pub(crate) fn build_evidence_pack_zip(
    manifest: &Value,
    receipts: &[ActionReceiptRecord],
    audit_events: &[AuditEventRecord],
    policies: &[PolicyRecord],
    incidents: &[SocIncidentRecord],
    approvals: &[ApprovalRecord],
) -> Result<Vec<u8>, std::io::Error> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        writer.start_file("manifest.json", options)?;
        let manifest_bytes = serde_json::to_vec_pretty(manifest)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &manifest_bytes)?;

        writer.start_file("receipts.jsonl", options)?;
        for receipt in receipts {
            let line = serde_json::to_string(receipt)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::io::Write::write_all(&mut writer, line.as_bytes())?;
            std::io::Write::write_all(&mut writer, b"\n")?;
        }

        writer.start_file("audit_events.jsonl", options)?;
        for event in audit_events {
            let line = serde_json::to_string(event)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::io::Write::write_all(&mut writer, line.as_bytes())?;
            std::io::Write::write_all(&mut writer, b"\n")?;
        }

        writer.start_file("policies.json", options)?;
        let policies_bytes = serde_json::to_vec_pretty(policies)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &policies_bytes)?;

        writer.start_file("incidents.json", options)?;
        let incidents_bytes = serde_json::to_vec_pretty(incidents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &incidents_bytes)?;

        writer.start_file("approvals.json", options)?;
        let approvals_bytes = serde_json::to_vec_pretty(approvals)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &approvals_bytes)?;

        writer.finish().map_err(std::io::Error::other)?;
    }
    Ok(cursor.into_inner())
}

/// GET /v1/tenants/:id/export — GDPR data-portability (#946). Returns the full
/// tenant-scoped data bundle (agents, decisions, approvals, receipts, audit
/// events, MCP servers) as JSON. A caller may export ONLY its own tenant: a path
/// id that doesn't match the authenticated tenant returns 404 (same convention as
/// `get_tenant`, so tenant existence isn't leaked).
pub async fn export_tenant(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if tenant_id != id {
        return StatusError::not_found("Tenant not found").into_response();
    }

    match state.storage.export_tenant_data(&tenant_id).await {
        Ok(export) => (StatusCode::OK, Json(export)).into_response(),
        Err(e) => {
            error!("Failed to export tenant data: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// DELETE /v1/tenants/:id (#947, GDPR right to erasure): permanently delete
/// every row owned by the tenant, including the tenant itself. Irreversible —
/// callers should fetch `GET /v1/tenants/:id/export` first if a portability
/// copy is needed.
pub async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if tenant_id != id {
        return StatusError::not_found("Tenant not found").into_response();
    }

    match state.storage.delete_tenant_data(&tenant_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            error!("Failed to delete tenant data: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateTenantRequest>,
) -> impl IntoResponse {
    match state.storage.get_tenant_by_id(&payload.id).await {
        Ok(Some(_)) => {
            return StatusError::conflict("Tenant already exists").into_response();
        }
        Err(e) => {
            error!("Database error checking tenant existence: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
        _ => {}
    }

    let record = TenantRecord {
        id: payload.id.clone(),
        name: payload.name.clone(),
        plan: payload.plan.clone(),
        created_at: Utc::now(),
        auto_respond_enabled: false,
        auto_rotate_token_on_leak_enabled: true,
    };
    match state.storage.insert_tenant(&record).await {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            error!("Failed to register tenant: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn get_tenant_stats(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state.storage.get_tenant_stats(&tenant_id).await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => {
            error!("Failed to get tenant stats: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/admin/db-stats (#949, #950): operational, whole-database
/// monitoring snapshot — on-disk size and per-table row counts. Not
/// tenant-scoped (reflects the single SQLite file shared by all tenants);
/// intended for ops dashboards on the local-only gateway listener.
pub async fn get_db_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.storage.get_db_stats().await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => {
            error!("Failed to get db stats: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// POST /v1/admin/backup (#945): write a consistent point-in-time copy of the
/// database via `VACUUM INTO`. The destination filename is restricted to a
/// bare filename (no path separators or `..`) under `AEGIS_BACKUP_DIR`
/// (default `backups`), which is created if missing, to prevent path
/// traversal to arbitrary filesystem locations.
pub async fn create_db_backup(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateBackupRequest>,
) -> impl IntoResponse {
    let filename = std::path::Path::new(&payload.filename);
    if payload.filename.is_empty()
        || filename.file_name().map(|f| f.to_owned()) != Some(filename.as_os_str().to_owned())
        || payload.filename.contains("..")
    {
        return StatusError::bad_request(
            "filename must be a bare filename with no path separators",
        )
        .into_response();
    }

    let backup_dir = std::env::var("AEGIS_BACKUP_DIR").unwrap_or_else(|_| "backups".to_string());
    if let Err(e) = std::fs::create_dir_all(&backup_dir) {
        error!("Failed to create backup directory: {:?}", e);
        return StatusError::internal("Failed to create backup directory").into_response();
    }

    let dest_path = std::path::Path::new(&backup_dir).join(&payload.filename);
    let dest_path_str = dest_path.to_string_lossy().to_string();

    // VACUUM INTO refuses to write to an already-existing file.
    if dest_path.exists() {
        return StatusError::conflict("Backup file already exists").into_response();
    }

    match state.storage.backup_database_to(&dest_path_str).await {
        Ok(()) => {
            let size_bytes = std::fs::metadata(&dest_path)
                .map(|m| m.len() as i64)
                .unwrap_or(0);
            (
                StatusCode::OK,
                Json(CreateBackupResponse {
                    path: dest_path_str,
                    size_bytes,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to create db backup: {:?}", e);
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
    /// TASK-0092 (#938): CRUD lifecycle for tenant-managed webhook
    /// subscriptions. The secret is hashed before storage, never persisted
    /// in plaintext.
    #[tokio::test]
    async fn test_webhook_subscription_crud_route() {
        let (state, tenant_id, _) = setup_state("webhook_subscription_crud").await;

        // 1. List (initially empty)
        let response =
            list_webhook_subscriptions(State(state.clone()), TenantId(tenant_id.clone()))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());

        // 2. Create with a secret
        let payload = CreateWebhookSubscriptionRequest {
            url: "https://example.com/hook".to_string(),
            secret: Some("super-secret".to_string()),
            event_types: "alert,incident".to_string(),
            min_severity: None,
            format: None,
        };
        let response_create = create_webhook_subscription(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response_create.status(), StatusCode::CREATED);
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let record: WebhookSubscriptionRecord = serde_json::from_slice(&body_create).unwrap();
        assert_eq!(record.url, "https://example.com/hook");
        assert_eq!(record.event_types, "alert,incident");
        assert_eq!(record.status, "active");
        // The plaintext secret is never stored — only its hash.
        assert_eq!(
            record.secret_hash.as_deref(),
            Some(sha256_hex("super-secret".as_bytes()).as_str())
        );

        // 3. List (should contain 1 subscription)
        let response_list =
            list_webhook_subscriptions(State(state.clone()), TenantId(tenant_id.clone()))
                .await
                .into_response();
        assert_eq!(response_list.status(), StatusCode::OK);
        let body_list = to_bytes(response_list.into_body(), usize::MAX)
            .await
            .unwrap();
        let subs: Vec<WebhookSubscriptionRecord> = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id, record.id);

        // 4. Delete
        let response_delete = delete_webhook_subscription(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(record.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete.status(), StatusCode::OK);

        // 5. Delete again (should return 404)
        let response_delete_404 = delete_webhook_subscription(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(record.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete_404.status(), StatusCode::NOT_FOUND);

        // 6. List (empty again)
        let response_list2 = list_webhook_subscriptions(State(state), TenantId(tenant_id))
            .await
            .into_response();
        let body_list2 = to_bytes(response_list2.into_body(), usize::MAX)
            .await
            .unwrap();
        let subs2: Vec<WebhookSubscriptionRecord> = serde_json::from_slice(&body_list2).unwrap();
        assert!(subs2.is_empty());
    }

    /// #1584: a `dead` webhook subscription (>= 10 consecutive delivery
    /// failures, per #912's circuit breaker) can be reactivated without
    /// deleting and recreating it — which would also rotate
    /// `delivery_secret`, forcing the tenant to update their receiving
    /// endpoint's HMAC verification key.
    #[tokio::test]
    async fn test_reactivate_webhook_subscription_route() {
        let (state, tenant_id, _) = setup_state("webhook_subscription_reactivate").await;

        let payload = CreateWebhookSubscriptionRequest {
            url: "https://example.com/hook".to_string(),
            secret: None,
            event_types: "alert,incident".to_string(),
            min_severity: None,
            format: None,
        };
        let response_create = create_webhook_subscription(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let record: WebhookSubscriptionRecord = serde_json::from_slice(&body_create).unwrap();
        let original_delivery_secret = record.delivery_secret.clone();

        // Drive it to `dead` directly via storage (mirrors how #912's
        // circuit breaker would, after 10 consecutive failed deliveries).
        for _ in 0..10 {
            state
                .storage
                .record_webhook_delivery_attempt(&tenant_id, &record.id, false)
                .await
                .unwrap();
        }
        let dead = state
            .storage
            .get_webhook_subscription(&tenant_id, &record.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dead.delivery_status, "dead");
        assert_eq!(dead.consecutive_failures, 10);

        // Reactivate.
        let response_reactivate = reactivate_webhook_subscription(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(record.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_reactivate.status(), StatusCode::OK);

        let revived = state
            .storage
            .get_webhook_subscription(&tenant_id, &record.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revived.delivery_status, "healthy");
        assert_eq!(revived.consecutive_failures, 0);
        // url/delivery_secret are untouched by reactivation.
        assert_eq!(revived.url, "https://example.com/hook");
        assert_eq!(revived.delivery_secret, original_delivery_secret);

        // Reactivating a nonexistent subscription 404s.
        let response_404 = reactivate_webhook_subscription(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("nonexistent-id".to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_404.status(), StatusCode::NOT_FOUND);
    }

    /// TASK-0093 (#939): CRUD lifecycle for tenant-managed API keys. The
    /// plaintext key is returned only at creation; list/revoke never expose it.
    #[tokio::test]
    async fn test_api_key_crud_route() {
        let (state, tenant_id, _) = setup_state("api_key_crud").await;

        // 1. List (initially empty)
        let response = list_api_keys(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let keys: Vec<ApiKeyRecord> = serde_json::from_slice(&body).unwrap();
        assert!(keys.is_empty());

        // 2. Create
        let payload = CreateApiKeyRequest {
            name: "ci-deploy-key".to_string(),
        };
        let response_create = create_api_key(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response_create.status(), StatusCode::CREATED);
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: Value = serde_json::from_slice(&body_create).unwrap();
        let key_id = created["id"].as_str().unwrap().to_string();
        let plaintext_key = created["key"].as_str().unwrap().to_string();
        assert!(!plaintext_key.is_empty());

        // 3. List (should contain 1 key, hashed, status active, no plaintext)
        let response_list = list_api_keys(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        let body_list = to_bytes(response_list.into_body(), usize::MAX)
            .await
            .unwrap();
        let keys_list: Vec<ApiKeyRecord> = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(keys_list.len(), 1);
        assert_eq!(keys_list[0].id, key_id);
        assert_eq!(keys_list[0].name, "ci-deploy-key");
        assert_eq!(keys_list[0].status, "active");
        assert_eq!(keys_list[0].key_hash, sha256_hex(plaintext_key.as_bytes()));

        // 4. Revoke
        let response_revoke = revoke_api_key(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(key_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_revoke.status(), StatusCode::OK);

        // 5. Revoke again (already revoked -> 404)
        let response_revoke_404 = revoke_api_key(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(key_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_revoke_404.status(), StatusCode::NOT_FOUND);

        // 6. List shows status revoked
        let response_list2 = list_api_keys(State(state), TenantId(tenant_id))
            .await
            .into_response();
        let body_list2 = to_bytes(response_list2.into_body(), usize::MAX)
            .await
            .unwrap();
        let keys_list2: Vec<ApiKeyRecord> = serde_json::from_slice(&body_list2).unwrap();
        assert_eq!(keys_list2.len(), 1);
        assert_eq!(keys_list2[0].status, "revoked");
    }

    #[tokio::test]
    async fn test_tenant_crud_route() {
        let (state, tenant_id, _) = setup_state("tenant_crud_route").await;

        // 1. Create a new tenant
        let new_tenant_id = "tenant_test_xyz";
        let create_payload = CreateTenantRequest {
            id: new_tenant_id.to_string(),
            name: "XYZ Corporation".to_string(),
            plan: "enterprise".to_string(),
        };

        let create_resp = create_tenant(State(state.clone()), Json(create_payload))
            .await
            .into_response();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let body = to_bytes(create_resp.into_body(), usize::MAX).await.unwrap();
        let record: TenantRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(record.id, new_tenant_id);
        assert_eq!(record.name, "XYZ Corporation");
        assert_eq!(record.plan, "enterprise");

        // 2. Create again (should conflict)
        let create_payload_dup = CreateTenantRequest {
            id: new_tenant_id.to_string(),
            name: "XYZ Corporation".to_string(),
            plan: "enterprise".to_string(),
        };
        let create_resp_dup = create_tenant(State(state.clone()), Json(create_payload_dup))
            .await
            .into_response();
        assert_eq!(create_resp_dup.status(), StatusCode::CONFLICT);

        // 3. Get tenant info
        let get_resp = get_tenant(
            State(state.clone()),
            TenantId(new_tenant_id.to_string()),
            Path(new_tenant_id.to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body_get = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let record_get: TenantRecord = serde_json::from_slice(&body_get).unwrap();
        assert_eq!(record_get.id, new_tenant_id);

        // 4. Get tenant info (cross-tenant, should return 404)
        let get_resp_cross = get_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(new_tenant_id.to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_tenant_stats_route() {
        let (state, tenant_id, agent_token) = setup_state("tenant_stats_route").await;

        let auth_payload = AuthorizeRequest {
            request_id: None,
            callback: None,
            dry_run: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "read_file".to_string(),
                resource: Some("README.md".to_string()),
                mutates_state: false,
                parameters: json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Authorization",
            axum::http::HeaderValue::from_str(&format!("Bearer {}", agent_token)).unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let _ = authorize_action(
            State(state.clone()),
            headers,
            Bytes::from(serde_json::to_vec(&auth_payload).unwrap()),
        )
        .await;

        // Query stats
        let stats_resp = get_tenant_stats(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(stats_resp.status(), StatusCode::OK);
        let body_stats = to_bytes(stats_resp.into_body(), usize::MAX).await.unwrap();
        let stats: TenantStats = serde_json::from_slice(&body_stats).unwrap();
        assert_eq!(stats.total_decisions, 1);
        assert_eq!(stats.decisions_allow, 1);
        assert_eq!(stats.total_agents, 1);
    }

    /// #949, #950: GET /v1/admin/db-stats reports a non-zero on-disk size and
    /// includes a row-count entry for every core table, with `decisions`
    /// reflecting at least the one row written above.
    #[tokio::test]
    async fn test_db_stats_route() {
        let (state, tenant_id, agent_token) = setup_state("db_stats_route").await;

        let auth_payload = AuthorizeRequest {
            request_id: None,
            callback: None,
            dry_run: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "github".to_string(),
                action: "read_file".to_string(),
                resource: Some("README.md".to_string()),
                mutates_state: false,
                parameters: json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Authorization",
            axum::http::HeaderValue::from_str(&format!("Bearer {}", agent_token)).unwrap(),
        );
        headers.insert(
            "X-Aegis-Tenant-ID",
            axum::http::HeaderValue::from_str(&tenant_id).unwrap(),
        );

        let _ = authorize_action(
            State(state.clone()),
            headers,
            Bytes::from(serde_json::to_vec(&auth_payload).unwrap()),
        )
        .await;

        let resp = get_db_stats(State(state.clone())).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let stats: DbStats = serde_json::from_slice(&body).unwrap();

        assert!(stats.size_bytes > 0);
        let decisions = stats
            .tables
            .iter()
            .find(|t| t.table == "decisions")
            .expect("decisions table present in db-stats");
        assert!(decisions.row_count >= 1);
    }

    /// #945: POST /v1/admin/backup writes a point-in-time copy under
    /// AEGIS_BACKUP_DIR; rejects path-traversal filenames; rejects a repeat
    /// request for the same filename (VACUUM INTO refuses to overwrite).
    #[tokio::test]
    async fn test_create_db_backup_route() {
        let _guard = get_env_lock().lock().await;
        let (state, _tenant_id, _agent_token) = setup_state("db_backup_route").await;

        let backup_dir = format!("target/backup_route_{}", Uuid::new_v4().simple());
        std::env::set_var("AEGIS_BACKUP_DIR", &backup_dir);

        // Path traversal is rejected.
        let bad_resp = create_db_backup(
            State(state.clone()),
            Json(CreateBackupRequest {
                filename: "../escape.db".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);

        // A bare filename succeeds and reports a non-zero size.
        let resp = create_db_backup(
            State(state.clone()),
            Json(CreateBackupRequest {
                filename: "snapshot.db".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let backup: CreateBackupResponse = serde_json::from_slice(&body).unwrap();
        assert!(backup.size_bytes > 0);
        assert!(std::path::Path::new(&backup.path).exists());

        // A repeat with the same filename is rejected (file already exists).
        let dup_resp = create_db_backup(
            State(state.clone()),
            Json(CreateBackupRequest {
                filename: "snapshot.db".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(dup_resp.status(), StatusCode::CONFLICT);

        std::env::remove_var("AEGIS_BACKUP_DIR");
        let _ = std::fs::remove_dir_all(&backup_dir);
    }

    /// #947 (GDPR right to erasure): DELETE /v1/tenants/:id removes the
    /// tenant row plus every owned row across decisions, approvals,
    /// receipts, audit events, and MCP servers/tools — without touching a
    /// second tenant's data, and a cross-tenant request 404s.
    #[tokio::test]
    async fn test_delete_tenant_route_removes_all_owned_data() {
        let (state, tenant_id, agent_token) = setup_state("delete_tenant_route").await;

        // Populate decisions/audit_events/action_receipts via authorize.
        let read_request = mcp_authorize_request("github", "read_file");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, read_request).await;

        // Populate an approval (require_approval decision).
        let _ = create_pending_approval(&state, &tenant_id, &agent_token, "99").await;

        // Populate an MCP server.
        let _ = register_mcp_server(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(RegisterMcpServerRequest {
                server_key: "gdpr-test-server".to_string(),
                name: "GDPR Test Server".to_string(),
                owner_team: None,
                transport: "stdio".to_string(),
                source: None,
                trust_level: "trusted_internal_signed".to_string(),
                endpoint: "stdio://test".to_string(),
            }),
        )
        .await;

        // A second tenant with its own data must be unaffected.
        let tenant_b = format!("tenant_b_{}", Uuid::new_v4().simple());
        register_tenant_helper(state.storage.as_ref(), &tenant_b, "Tenant B", "developer").await;

        // Sanity check: tenant_id has rows before deletion.
        let stats_before = state.storage.get_tenant_stats(&tenant_id).await.unwrap();
        assert!(stats_before.total_decisions >= 1);

        let resp = delete_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(tenant_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // The tenant and all owned rows are gone.
        assert!(state
            .storage
            .get_tenant_by_id(&tenant_id)
            .await
            .unwrap()
            .is_none());
        let stats_after = state.storage.get_tenant_stats(&tenant_id).await.unwrap();
        assert_eq!(stats_after.total_decisions, 0);
        assert_eq!(stats_after.total_agents, 0);
        assert_eq!(stats_after.total_receipts, 0);

        let remaining_approvals = state
            .storage
            .list_pending_approvals(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(remaining_approvals.is_empty());

        let remaining_servers = state
            .storage
            .list_mcp_servers(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(remaining_servers.is_empty());

        // tenant_b is untouched.
        assert!(state
            .storage
            .get_tenant_by_id(&tenant_b)
            .await
            .unwrap()
            .is_some());

        // A cross-tenant delete (now that tenant_id is gone) reports 404.
        let cross = delete_tenant(
            State(state.clone()),
            TenantId(tenant_b.clone()),
            Path(tenant_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_openapi_spec_route() {
        let spec_resp = get_openapi_spec().await.into_response();
        assert_eq!(spec_resp.status(), StatusCode::OK);
        let body_spec = to_bytes(spec_resp.into_body(), usize::MAX).await.unwrap();
        let spec_json: Value = serde_json::from_slice(&body_spec).unwrap();
        assert_eq!(spec_json["openapi"], "3.0.3");
        assert_eq!(spec_json["info"]["title"], "AegisAgent Control Plane API");
    }

    /// #946 GDPR export: a tenant exports its own data bundle; a mismatched path
    /// id is 404; another tenant's export contains none of this tenant's records.
    #[tokio::test]
    async fn export_tenant_bundles_own_data_and_is_scoped() {
        let (state, tenant_id, agent_token) = setup_state("tenant_export").await;

        // Generate data: one authorize → a decision + receipt + audit event.
        let _ = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("github", "read_issue"),
        )
        .await;

        // #1512: the receipt write is now a deferred background task — wait
        // for it to land before exporting.
        state
            .deferred_write_tracker
            .drain(std::time::Duration::from_secs(5))
            .await;

        // Happy path: export own tenant.
        let resp = export_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(tenant_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["schema"], "aegis-tenant-export-1");
        assert_eq!(v["tenant_id"], tenant_id);
        assert!(
            !v["agents"].as_array().unwrap().is_empty(),
            "export must include the tenant's agent"
        );
        assert!(
            !v["decisions"].as_array().unwrap().is_empty(),
            "export must include the decision"
        );
        assert!(!v["action_receipts"].as_array().unwrap().is_empty());

        // Cross-tenant: a path id that isn't the authenticated tenant → 404.
        let denied = export_tenant(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("tenant_other".to_string()),
        )
        .await
        .into_response();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);

        // Tenant isolation: another tenant's export contains none of A's records.
        register_tenant_helper(state.storage.as_ref(), "tenant_other", "Other", "developer").await;
        let other = state
            .storage
            .export_tenant_data("tenant_other")
            .await
            .unwrap();
        assert!(other.agents.is_empty());
        assert!(other.decisions.is_empty());
        assert!(other.action_receipts.is_empty());
    }

    /// Seed a minimal set of compliance-relevant rows for `tenant_id`:
    /// an agent + decision (via authorize), an action receipt, an audit
    /// event, an approval with `approver_user_id` set, a current policy, and
    /// a SOC incident. Returns the decision id used for the receipt.
    async fn seed_evidence_pack_data(state: &Arc<AppState>, tenant_id: &str, agent_token: &str) {
        // Agent + decision + receipt + audit event via a normal authorize call.
        let _ = call_authorize(
            state.clone(),
            tenant_id,
            agent_token,
            mcp_authorize_request("github", "read_issue"),
        )
        .await;

        // #1512: the receipt write is now a deferred background task — wait
        // for it to land before the rest of this seed helper queries for it.
        state
            .deferred_write_tracker
            .drain(std::time::Duration::from_secs(5))
            .await;

        // Reuse the decision row created above so the approval's FK is valid.
        let decision_id: String = aegis_storage::fetch_one_scalar!(
            String,
            state.storage.get_pool(),
            "SELECT id FROM decisions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1",
            tenant_id
        )
        .unwrap();

        // Approval with approver identity set.
        let approval = ApprovalRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id,
            status: "approved".to_string(),
            approver_group: Some("platform-leads".to_string()),
            approver_user_id: Some("user_alice".to_string()),
            reason: Some("looks safe".to_string()),
            original_skill_call: "{}".to_string(),
            original_call_hash: "deadbeef".to_string(),
            edited_skill_call: None,
            expires_at: None,
            decided_at: Some(Utc::now()),
            callback_url: None,
            callback_secret_hash: None,
            created_at: Utc::now(),
        };
        state.storage.insert_approval(&approval).await.unwrap();

        // Current policy snapshot.
        let policy = PolicyRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            policy_key: "evidence_pack_policy".to_string(),
            name: "Evidence Pack Policy".to_string(),
            language: "cedar".to_string(),
            body: "permit(principal, action, resource);".to_string(),
            version: 1,
            status: "active".to_string(),
            created_by: None,
            created_at: Utc::now(),
        };
        state.storage.insert_policy(&policy).await.unwrap();

        // SOC incident.
        let incident = SocIncidentRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            kind: "test_incident".to_string(),
            severity: "high".to_string(),
            agent_id: "evidence-agent".to_string(),
            summary: "Evidence pack test incident".to_string(),
            source_event_ids: "[]".to_string(),
            opened_at: Utc::now().to_rfc3339(),
            status: "open".to_string(),
            closed_at: None,
        };
        state.storage.insert_soc_incident(&incident).await.unwrap();
    }

    /// Parse a ZIP byte buffer and return the set of entry names it contains.
    fn zip_entry_names(bytes: &[u8]) -> std::collections::HashSet<String> {
        let reader = std::io::Cursor::new(bytes);
        let archive = zip::ZipArchive::new(reader).unwrap();
        archive.file_names().map(|s| s.to_string()).collect()
    }

    /// Read a single entry from a ZIP byte buffer as a UTF-8 string.
    fn zip_entry_string(bytes: &[u8], name: &str) -> String {
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader).unwrap();
        let mut file = archive.by_name(name).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut file, &mut out).unwrap();
        out
    }

    #[tokio::test]
    async fn evidence_pack_returns_zip_with_expected_entries() {
        let (state, tenant_id, agent_token) = setup_state("evidence_pack_entries").await;
        seed_evidence_pack_data(&state, &tenant_id, &agent_token).await;

        let resp = get_evidence_pack(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::Query(EvidencePackParams {
                from: None,
                to: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let entries = zip_entry_names(&body);
        for expected in [
            "manifest.json",
            "receipts.jsonl",
            "audit_events.jsonl",
            "policies.json",
            "incidents.json",
            "approvals.json",
        ] {
            assert!(
                entries.contains(expected),
                "missing zip entry: {expected} (have {entries:?})"
            );
        }

        let manifest: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "manifest.json")).unwrap();
        assert_eq!(manifest["schema"], "aegis-evidence-pack-1");
        assert_eq!(manifest["tenant_id"], tenant_id);
        assert_eq!(manifest["canonicalization_scheme"], "aegis-jcs-1");
        assert!(manifest["counts"]["receipts"].as_u64().unwrap() >= 1);
        assert!(manifest["counts"]["audit_events"].as_u64().unwrap() >= 1);
        assert_eq!(manifest["counts"]["approvals"].as_u64().unwrap(), 1);
        assert_eq!(manifest["counts"]["incidents"].as_u64().unwrap(), 1);
        assert_eq!(manifest["counts"]["policies"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn evidence_pack_date_range_filters_receipts_and_audit_events() {
        let (state, tenant_id, agent_token) = setup_state("evidence_pack_range").await;

        // Old receipt + audit event (outside range).
        let _ = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("github", "read_issue"),
        )
        .await;
        // #1512: the receipt write is now deferred — wait for it to land
        // before the UPDATE below ages its created_at, otherwise the UPDATE
        // can race the write and miss the row entirely.
        state
            .deferred_write_tracker
            .drain(std::time::Duration::from_secs(5))
            .await;
        let old_time = Utc::now() - Duration::days(10);
        aegis_storage::execute_query!(
            state.storage.get_pool(),
            "UPDATE action_receipts SET created_at = ? WHERE tenant_id = ?",
            old_time,
            &tenant_id
        )
        .unwrap();
        aegis_storage::execute_query!(
            state.storage.get_pool(),
            "UPDATE audit_events SET created_at = ? WHERE tenant_id = ?",
            old_time,
            &tenant_id
        )
        .unwrap();

        // New receipt + audit event (inside range).
        let _ = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("github", "read_issue"),
        )
        .await;
        // #1512: wait for this second receipt's deferred write to land
        // before querying the evidence pack below.
        state
            .deferred_write_tracker
            .drain(std::time::Duration::from_secs(5))
            .await;

        // Narrow the range to exclude the 10-day-old rows but include "now".
        let from = (Utc::now() - Duration::days(1)).to_rfc3339();
        let to = (Utc::now() + Duration::days(1)).to_rfc3339();

        let resp = get_evidence_pack(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::Query(EvidencePackParams {
                from: Some(from),
                to: Some(to),
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();

        let receipts_jsonl = zip_entry_string(&body, "receipts.jsonl");
        let receipt_lines: Vec<&str> = receipts_jsonl.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            receipt_lines.len(),
            1,
            "only the in-range receipt should be present"
        );

        let audit_jsonl = zip_entry_string(&body, "audit_events.jsonl");
        let audit_lines: Vec<&str> = audit_jsonl.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            audit_lines.len(),
            1,
            "only the in-range audit event should be present"
        );
    }

    #[tokio::test]
    async fn evidence_pack_is_tenant_scoped() {
        let (state, tenant_a, agent_a) = setup_state("evidence_pack_tenant_a").await;
        seed_evidence_pack_data(&state, &tenant_a, &agent_a).await;

        // Register a second tenant + agent in the *same* pool and seed its
        // own evidence data.
        let tenant_b = "tenant_other_evidence".to_string();
        register_tenant_helper(
            state.storage.as_ref(),
            &tenant_b,
            "Other Tenant",
            "developer",
        )
        .await;
        let register_resp = register_agent(
            State(state.clone()),
            TenantId(tenant_b.clone()),
            Json(RegisterAgentRequest {
                agent_key: "evidence-agent-b".to_string(),
                name: "Evidence Agent B".to_string(),
                owner_team: None,
                environment: "production".to_string(),
                framework: None,
                model_provider: None,
                model_name: None,
                risk_tier: "low".to_string(),
                purpose: None,
                signing_key: None,
                allowed_environments: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(register_resp.status(), StatusCode::CREATED);
        let register_body = to_bytes(register_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let register_json: serde_json::Value = serde_json::from_slice(&register_body).unwrap();
        let agent_b = register_json["agent_token"].as_str().unwrap().to_string();

        seed_evidence_pack_data(&state, &tenant_b, &agent_b).await;

        let resp = get_evidence_pack(
            State(state.clone()),
            TenantId(tenant_a.clone()),
            axum::extract::Query(EvidencePackParams {
                from: None,
                to: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();

        let approvals: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "approvals.json")).unwrap();
        let approvals = approvals.as_array().unwrap();
        assert_eq!(approvals.len(), 1, "only tenant A's approval is included");
        for approval in approvals {
            assert_eq!(approval["tenant_id"], tenant_a);
            assert_ne!(approval["tenant_id"], tenant_b);
        }

        let incidents: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "incidents.json")).unwrap();
        let incidents = incidents.as_array().unwrap();
        assert_eq!(incidents.len(), 1, "only tenant A's incident is included");
        for incident in incidents {
            assert_eq!(incident["tenant_id"], tenant_a);
        }

        let policies: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "policies.json")).unwrap();
        let policies = policies.as_array().unwrap();
        assert_eq!(policies.len(), 1, "only tenant A's policy is included");
        for policy in policies {
            assert_eq!(policy["tenant_id"], tenant_a);
        }
    }

    #[tokio::test]
    async fn evidence_pack_invalid_date_param_returns_400() {
        let (state, tenant_id, _agent_token) = setup_state("evidence_pack_invalid_date").await;

        let resp = get_evidence_pack(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::Query(EvidencePackParams {
                from: Some("not-a-date".to_string()),
                to: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn evidence_pack_includes_approver_identity_in_approvals() {
        let (state, tenant_id, agent_token) = setup_state("evidence_pack_approver").await;
        seed_evidence_pack_data(&state, &tenant_id, &agent_token).await;

        let resp = get_evidence_pack(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::Query(EvidencePackParams {
                from: None,
                to: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();

        let approvals: serde_json::Value =
            serde_json::from_str(&zip_entry_string(&body, "approvals.json")).unwrap();
        let approvals = approvals.as_array().unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0]["approver_user_id"], "user_alice");
    }

    /// #1289: `GET /v1/tenants/risk-weights` returns the built-in defaults
    /// when no per-tenant override has been configured.
    #[tokio::test]
    async fn get_tenant_risk_weights_returns_defaults_when_unset() {
        let (state, tenant_id, _) = setup_state("risk_weights_get_default").await;

        let response = get_tenant_risk_weights(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let weights: RiskWeights = serde_json::from_slice(&body).unwrap();
        assert_eq!(weights, RiskWeights::from_env());
    }

    /// #1289: `PUT /v1/tenants/risk-weights` persists an override, and a
    /// subsequent `GET` returns it; a different tenant's weights are
    /// unaffected (tenant isolation).
    #[tokio::test]
    async fn put_tenant_risk_weights_round_trips_and_is_tenant_scoped() {
        let (state, tenant_id, _) = setup_state("risk_weights_put_roundtrip").await;
        let other_tenant = "tenant_other_risk_weights";
        register_tenant_helper(
            state.storage.as_ref(),
            other_tenant,
            "Other Tenant",
            "developer",
        )
        .await;

        let mut custom = RiskWeights::DEFAULT;
        custom.environment_weight_mutating = 42;
        custom.mcp_trust_penalty = 7;

        let response_put = put_tenant_risk_weights(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(custom),
        )
        .await
        .into_response();
        assert_eq!(response_put.status(), StatusCode::OK);

        // GET for the configured tenant returns the override.
        let response_get =
            get_tenant_risk_weights(State(state.clone()), TenantId(tenant_id.clone()))
                .await
                .into_response();
        assert_eq!(response_get.status(), StatusCode::OK);
        let body_get = to_bytes(response_get.into_body(), usize::MAX)
            .await
            .unwrap();
        let weights_get: RiskWeights = serde_json::from_slice(&body_get).unwrap();
        assert_eq!(weights_get, custom);

        // GET for a different tenant is unaffected (still defaults).
        let response_other =
            get_tenant_risk_weights(State(state.clone()), TenantId(other_tenant.to_string()))
                .await
                .into_response();
        assert_eq!(response_other.status(), StatusCode::OK);
        let body_other = to_bytes(response_other.into_body(), usize::MAX)
            .await
            .unwrap();
        let weights_other: RiskWeights = serde_json::from_slice(&body_other).unwrap();
        assert_eq!(weights_other, RiskWeights::from_env());
    }

    /// #1296: `GET /v1/tenants/risk-escalation` returns the built-in default
    /// (5 denials / 60-minute window) when no per-tenant override exists.
    #[tokio::test]
    async fn get_tenant_risk_escalation_config_returns_defaults_when_unset() {
        let (state, tenant_id, _) = setup_state("risk_escalation_get_default").await;

        let response =
            get_tenant_risk_escalation_config(State(state.clone()), TenantId(tenant_id.clone()))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let config: RiskEscalationConfig = serde_json::from_slice(&body).unwrap();
        assert_eq!(config, RiskEscalationConfig::default());
    }

    /// #1296: `PUT /v1/tenants/risk-escalation` persists an override,
    /// tenant-scoped, and rejects non-positive values.
    #[tokio::test]
    async fn put_tenant_risk_escalation_config_round_trips_and_validates() {
        let (state, tenant_id, _) = setup_state("risk_escalation_put_roundtrip").await;

        let custom = RiskEscalationConfig {
            denial_threshold: 2,
            window_minutes: 15,
        };
        let response_put = put_tenant_risk_escalation_config(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(custom),
        )
        .await
        .into_response();
        assert_eq!(response_put.status(), StatusCode::OK);

        let response_get =
            get_tenant_risk_escalation_config(State(state.clone()), TenantId(tenant_id.clone()))
                .await
                .into_response();
        let body_get = to_bytes(response_get.into_body(), usize::MAX)
            .await
            .unwrap();
        let config_get: RiskEscalationConfig = serde_json::from_slice(&body_get).unwrap();
        assert_eq!(config_get, custom);

        let invalid = RiskEscalationConfig {
            denial_threshold: 0,
            window_minutes: 15,
        };
        let response_invalid = put_tenant_risk_escalation_config(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(invalid),
        )
        .await
        .into_response();
        assert_eq!(response_invalid.status(), StatusCode::BAD_REQUEST);
    }
}
