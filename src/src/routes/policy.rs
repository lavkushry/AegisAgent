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

async fn reload_policies_helper(
    state: &Arc<AppState>,
    tenant_id: &str,
) -> Result<(), aegis_common::errors::AegisError> {
    let db_policies = state.storage.list_policies(tenant_id).await?;
    state
        .policy_engine
        .reload_tenant_policies(tenant_id, &db_policies)
        .map_err(|e| aegis_common::errors::AegisError::Internal(e.to_string()))
}

/// #1312: append a hash-chained `policy_audit_log` entry for a policy
/// create/update/delete/rollback. `body` is the resulting policy body (the
/// body being deleted, for `action == "deleted"`) and is hashed into
/// `body_hash`, never stored verbatim. Best-effort: a failure here is logged
/// but never blocks the policy operation that triggered it.
pub(crate) async fn record_policy_audit_log(
    storage: &dyn aegis_storage::traits::StorageBackend,
    tenant_id: &str,
    policy_id: &str,
    policy_key: &str,
    action: &str,
    body: &str,
    diff_summary: String,
) {
    let tenant_id_str = tenant_id.to_string();
    let body_hash = format!("sha256:{}", sha256_hex(body.as_bytes()));
    let policy_id = policy_id.to_string();
    let policy_key = policy_key.to_string();
    let action = action.to_string();
    if let Err(e) = storage
        .append_policy_audit_log_entry_atomic(
            tenant_id,
            Box::new(move |prev_hash| {
                let mut rec = PolicyAuditLogRecord {
                    id: Uuid::new_v4().to_string(),
                    tenant_id: tenant_id_str,
                    policy_id,
                    policy_key,
                    action,
                    changed_by: None,
                    body_hash,
                    diff_summary,
                    prev_hash,
                    entry_hash: String::new(),
                    created_at: Utc::now(),
                };
                rec.entry_hash = compute_policy_audit_log_entry_hash(&rec);
                rec
            }),
        )
        .await
    {
        error!("Failed to append policy_audit_log entry: {:?}", e);
    }
}

pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    match state.storage.list_policies(&tenant_id).await {
        Ok(policies) => (StatusCode::OK, Json(policies)).into_response(),
        Err(e) => {
            error!("Failed to list policies: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<CreatePolicyRequest>,
) -> impl IntoResponse {
    // Validate Cedar compilation
    if let Err(e) = cedar_policy::PolicySet::from_str(&payload.body) {
        return StatusError::bad_request(format!("Cedar compilation error: {}", e)).into_response();
    }

    let policy_id = Uuid::new_v4().to_string();
    let record = PolicyRecord {
        id: policy_id,
        tenant_id: tenant_id.clone(),
        policy_key: payload.policy_key,
        name: payload.name,
        language: "cedar".to_string(),
        body: payload.body,
        version: 1,
        status: "active".to_string(),
        created_by: None,
        created_at: Utc::now(),
    };

    match state.storage.insert_policy(&record).await {
        Ok(_) => {
            // Trigger hot-reload
            if let Err(e) = reload_policies_helper(&state, &tenant_id).await {
                error!("Failed to reload policies after create: {:?}", e);
                let _ = state.storage.delete_policy(&tenant_id, &record.id).await;
                return StatusError::internal("Failed to hot-reload policy changes")
                    .into_response();
            }
            record_policy_audit_log(
                state.storage.as_ref(),
                &tenant_id,
                &record.id,
                &record.policy_key,
                "created",
                &record.body,
                format!(
                    "Policy '{}' created (version {})",
                    record.name, record.version
                ),
            )
            .await;
            (StatusCode::CREATED, Json(record)).into_response()
        }
        Err(e) => {
            error!("Failed to create policy: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(payload): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    let mut record = match state.storage.get_policy_by_id(&tenant_id, &id).await {
        Ok(Some(p)) => p,
        Ok(None) => return StatusError::not_found("Policy not found").into_response(),
        Err(e) => {
            error!("Failed to lookup policy for update: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    // TASK-0091 (#937): archive the pre-update row before overwriting it, so
    // operators can inspect/restore prior policy versions.
    let previous = record.clone();

    // #1312: track which fields changed for the transparency-log diff summary.
    let mut changed_fields: Vec<&str> = Vec::new();

    if let Some(policy_key) = payload.policy_key {
        if policy_key != record.policy_key {
            changed_fields.push("policy_key");
        }
        record.policy_key = policy_key;
    }
    if let Some(name) = payload.name {
        if name != record.name {
            changed_fields.push("name");
        }
        record.name = name;
    }
    if let Some(body) = payload.body {
        // Validate Cedar compilation
        if let Err(e) = cedar_policy::PolicySet::from_str(&body) {
            return StatusError::bad_request(format!("Cedar compilation error: {}", e))
                .into_response();
        }
        if body != record.body {
            changed_fields.push("body");
        }
        record.body = body;
    }
    if let Some(status) = payload.status {
        if status != record.status {
            changed_fields.push("status");
        }
        record.status = status;
    }
    record.version += 1;

    // Best-effort: a DB error archiving the previous version never blocks the update.
    if let Err(e) = state.storage.insert_policy_version(&previous).await {
        error!("Failed to archive previous policy version: {:?}", e);
    }

    match state.storage.update_policy(&record).await {
        Ok(_) => {
            // Trigger hot-reload
            if let Err(e) = reload_policies_helper(&state, &tenant_id).await {
                error!("Failed to reload policies after update: {:?}", e);
                // Roll back DB record to prior state
                let _ = state.storage.update_policy(&previous).await;
                return StatusError::internal("Failed to hot-reload policy changes")
                    .into_response();
            }
            let diff_summary = if changed_fields.is_empty() {
                format!(
                    "Policy '{}' updated to version {}",
                    record.name, record.version
                )
            } else {
                format!(
                    "Policy '{}' updated to version {} (changed: {})",
                    record.name,
                    record.version,
                    changed_fields.join(", ")
                )
            };
            record_policy_audit_log(
                state.storage.as_ref(),
                &tenant_id,
                &record.id,
                &record.policy_key,
                "updated",
                &record.body,
                diff_summary,
            )
            .await;
            (StatusCode::OK, Json(record)).into_response()
        }
        Err(e) => {
            error!("Failed to update policy: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1302: `POST /v1/policies/:id/rollback` restores the most recently
/// archived `policy_versions` row onto the live `policies` row.
///
/// Before restoring, the CURRENT live row is itself archived (same pattern
/// as `update_policy`) so the rollback is reversible — rolling back again
/// would restore the version being rolled back from. `version` is bumped to
/// `current_version + 1` (monotonically increasing, never reused) and a
/// `policy_rolled_back` audit event is emitted. The Cedar engine is
/// hot-reloaded for the tenant on success.
pub async fn rollback_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut record = match state.storage.get_policy_by_id(&tenant_id, &id).await {
        Ok(Some(p)) => p,
        Ok(None) => return StatusError::not_found("Policy not found").into_response(),
        Err(e) => {
            error!("Failed to lookup policy for rollback: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let versions = match state.storage.list_policy_versions(&tenant_id, &id).await {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to list policy versions for rollback: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let previous_version = match versions.into_iter().next() {
        Some(v) => v,
        None => {
            return StatusError::not_found("No previous version to roll back to").into_response()
        }
    };

    // Archive the CURRENT live row before overwriting it, so rollback itself
    // is reversible and doesn't lose the version being rolled back from.
    let current = record.clone();
    if let Err(e) = state.storage.insert_policy_version(&current).await {
        error!(
            "Failed to archive current policy version before rollback: {:?}",
            e
        );
    }

    // Restore the archived version's content onto the live row. `version`
    // is monotonically bumped from the CURRENT live version, never copied
    // from the archived row, so version numbers never decrease or repeat.
    record.policy_key = previous_version.policy_key.clone();
    record.name = previous_version.name.clone();
    record.language = previous_version.language.clone();
    record.body = previous_version.body.clone();
    record.status = previous_version.status.clone();
    record.version += 1;

    match state.storage.update_policy(&record).await {
        Ok(_) => {
            // Trigger hot-reload
            if let Err(e) = reload_policies_helper(&state, &tenant_id).await {
                error!("Failed to reload policies after rollback: {:?}", e);
                // Restore current back to live
                let _ = state.storage.update_policy(&current).await;
                return StatusError::internal("Failed to hot-reload policy changes")
                    .into_response();
            }

            let audit_record = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                event_type: "policy_rolled_back".to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: None,
                action: Some(record.policy_key.clone()),
                resource: Some(record.id.clone()),
                event_json: serde_json::to_string(&json!({
                    "policy_id": record.id,
                    "policy_key": record.policy_key,
                    "name": record.name,
                    "body": record.body,
                    "rolled_back_to_version": previous_version.version,
                    "new_version": record.version,
                }))
                .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at: Utc::now(),
            };
            if let Err(e) = state.storage.insert_audit_event(&audit_record).await {
                error!("Failed to write policy_rolled_back audit event: {:?}", e);
            }

            record_policy_audit_log(
                state.storage.as_ref(),
                &tenant_id,
                &record.id,
                &record.policy_key,
                "rolled_back",
                &record.body,
                format!(
                    "Policy '{}' rolled back to version {} (new version {})",
                    record.name, previous_version.version, record.version
                ),
            )
            .await;

            (StatusCode::OK, Json(record)).into_response()
        }
        Err(e) => {
            error!("Failed to roll back policy: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // #1312: fetch the policy before deleting so the transparency-log entry
    // can record its `policy_key` and a hash of the deleted body.
    let existing = match state.storage.get_policy_by_id(&tenant_id, &id).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to lookup policy for delete: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    match state.storage.delete_policy(&tenant_id, &id).await {
        Ok(true) => {
            // Trigger hot-reload
            if let Err(e) = reload_policies_helper(&state, &tenant_id).await {
                error!("Failed to reload policies after delete: {:?}", e);
                // Re-insert the deleted policy
                if let Some(ref policy) = existing {
                    let _ = state.storage.insert_policy(policy).await;
                }
                return StatusError::internal("Failed to hot-reload policy changes")
                    .into_response();
            }
            if let Some(policy) = existing {
                record_policy_audit_log(
                    state.storage.as_ref(),
                    &tenant_id,
                    &policy.id,
                    &policy.policy_key,
                    "deleted",
                    &policy.body,
                    format!(
                        "Policy '{}' (version {}) deleted",
                        policy.name, policy.version
                    ),
                )
                .await;
            }
            (
                StatusCode::OK,
                Json(json!({"message": "Policy successfully deleted"})),
            )
                .into_response()
        }
        Ok(false) => StatusError::not_found("Policy not found").into_response(),
        Err(e) => {
            error!("Failed to delete policy: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// #1312: GET /v1/policies/audit-log — tenant-scoped, paginated transparency
/// log of policy create/update/delete/rollback operations, newest first.
///
/// Query params:
///   `limit` (default 50, max 200), `offset` (default 0).
pub async fn list_policy_audit_log(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());

    match state
        .storage
        .list_policy_audit_log(&tenant_id, limit, offset)
        .await
    {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(e) => {
            error!("Failed to list policy audit log: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateWebhookSubscriptionRequest {
    pub url: String,
    /// Optional shared secret. Only `sha256(secret)` is persisted (#938) —
    /// mirrors `ApprovalCallback::secret`. Unrelated to the server-generated
    /// `delivery_secret` (#1285) that actually signs outbound deliveries.
    #[serde(default)]
    pub secret: Option<String>,
    /// Comma-separated SOC event types to receive, or `"*"` for all.
    #[serde(default = "default_webhook_event_types")]
    pub event_types: String,
    /// #1285: `"info"` or `"high"`. Defaults to `"info"` (receive everything
    /// the high-signal trigger policy surfaces).
    #[serde(default)]
    pub min_severity: Option<String>,
    /// #1285: `"json"` or `"cef"`. Defaults to `"json"`.
    #[serde(default)]
    pub format: Option<String>,
}

/// `POST /v1/policies/reload` — reloads the global Cedar policy file from
/// disk. #1159 (OBS-006): this is a configuration change, so a successful
/// reload writes a `config_change` audit event (`action: "policy_file_reload"`)
/// for the calling tenant, distinct from the tenant-scoped Cedar policy CRUD
/// trail in `policy_audit_log` (`record_policy_audit_log`).
pub async fn reload_global_policies(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    let policy_path =
        std::env::var("CEDAR_POLICY_PATH").unwrap_or_else(|_| "policies.cedar".into());
    match state.policy_engine.reload_file(&policy_path).await {
        Ok(_) => {
            let audit = AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                event_type: "config_change".to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: None,
                action: Some("policy_file_reload".to_string()),
                resource: None,
                event_json: serde_json::to_string(&json!({ "policy_path": policy_path }))
                    .unwrap_or_default(),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at: Utc::now(),
            };
            let _ = state.storage.insert_audit_event(&audit).await;

            (
                StatusCode::OK,
                Json(json!({"message": "Global policies successfully reloaded"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to reload global policy file: {:?}", e);
            StatusError::internal(format!("Failed to reload file: {}", e)).into_response()
        }
    }
}

/// A single Cedar policy within a [`PolicyBundleUploadRequest`] (#1280).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PolicyBundleEntry {
    pub policy_key: String,
    pub name: String,
    pub body: String,
}

/// `POST /v1/policies/bundles` body (#1280): a tamper-evident, Ed25519-signed
/// bundle of Cedar policies for tamper-proof policy distribution.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyBundleUploadRequest {
    pub policies: Vec<PolicyBundleEntry>,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    /// Hex-encoded Ed25519 signature, verified against
    /// `AppState::policy_signing_verifying_key` (`AEGIS_POLICY_SIGNING_KEY`).
    pub signature: String,
}

/// The signed portion of a [`PolicyBundleUploadRequest`] — every field
/// EXCEPT `signature` itself, since a signature can't cover its own bytes.
/// Field names and types must exactly mirror `PolicyBundleUploadRequest`
/// minus `signature`, so the external signer and this gateway compute the
/// same canonical bytes.
#[derive(Debug, serde::Serialize)]
struct PolicyBundleSignaturePayload<'a> {
    policies: &'a [PolicyBundleEntry],
    version: i64,
    created_at: DateTime<Utc>,
}

/// `aegis-jcs-1`-canonicalizes the signed portion of a bundle and SHA-256
/// hashes it — the message an external signer signs and this gateway
/// verifies. Changing any policy's key/name/body, the bundle version, or its
/// timestamp changes this hash, invalidating any prior signature over it.
fn policy_bundle_signed_hash(payload: &PolicyBundleUploadRequest) -> String {
    let unsigned = PolicyBundleSignaturePayload {
        policies: &payload.policies,
        version: payload.version,
        created_at: payload.created_at,
    };
    let canonical = aegis_canon::canonical_value_string(&unsigned);
    sha256_hex(canonical.as_bytes())
}

/// `POST /v1/policies/bundles` (#1280): upload a signed bundle of Cedar
/// policies, verified against `AEGIS_POLICY_SIGNING_KEY` before any policy in
/// it is loaded. Fails closed: with no verifying key configured, every
/// request is refused with `501` — there's no key to verify against, and
/// accepting a bundle unverified would defeat the feature's purpose.
///
/// Each entry is upserted by `policy_key` within the tenant: an existing
/// `policy_key` is updated (the prior version is archived first, exactly
/// like [`update_policy`]); an unseen `policy_key` is created. Every Cedar
/// body in the bundle is validated to compile BEFORE any of them is written,
/// so a single bad entry rejects the whole bundle rather than partially
/// applying it.
pub async fn upload_policy_bundle(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<PolicyBundleUploadRequest>,
) -> impl IntoResponse {
    let Some(verifying_key) = state.policy_signing_verifying_key.as_deref() else {
        return StatusError::not_implemented(
            "Policy bundle signing is not configured on this gateway (AEGIS_POLICY_SIGNING_KEY unset)",
        )
        .into_response();
    };

    let signed_hash = policy_bundle_signed_hash(&payload);
    if !sign::verify_signature(verifying_key, &signed_hash, &payload.signature) {
        return StatusError::forbidden("Invalid policy bundle signature").into_response();
    }

    if payload.policies.is_empty() {
        return StatusError::bad_request("Policy bundle must contain at least one policy")
            .into_response();
    }

    // Validate every Cedar body compiles BEFORE writing anything.
    for entry in &payload.policies {
        if let Err(e) = cedar_policy::PolicySet::from_str(&entry.body) {
            return StatusError::bad_request(format!(
                "Cedar compilation error in policy '{}': {}",
                entry.policy_key, e
            ))
            .into_response();
        }
    }

    let existing_policies = match state.storage.list_policies(&tenant_id).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to list policies for bundle upload: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let mut results = Vec::with_capacity(payload.policies.len());
    for entry in &payload.policies {
        let existing = existing_policies
            .iter()
            .find(|p| p.policy_key == entry.policy_key)
            .cloned();

        let record = match existing {
            Some(mut record) => {
                let previous = record.clone();
                record.name = entry.name.clone();
                record.body = entry.body.clone();
                record.version += 1;
                if let Err(e) = state.storage.insert_policy_version(&previous).await {
                    error!("Failed to archive previous policy version: {:?}", e);
                }
                if let Err(e) = state.storage.update_policy(&record).await {
                    error!("Failed to update policy from bundle: {:?}", e);
                    return StatusError::internal("Database error").into_response();
                }
                record_policy_audit_log(
                    state.storage.as_ref(),
                    &tenant_id,
                    &record.id,
                    &record.policy_key,
                    "updated",
                    &record.body,
                    format!(
                        "Policy '{}' updated to version {} via signed bundle",
                        record.name, record.version
                    ),
                )
                .await;
                record
            }
            None => {
                let record = PolicyRecord {
                    id: Uuid::new_v4().to_string(),
                    tenant_id: tenant_id.clone(),
                    policy_key: entry.policy_key.clone(),
                    name: entry.name.clone(),
                    language: "cedar".to_string(),
                    body: entry.body.clone(),
                    version: 1,
                    status: "active".to_string(),
                    created_by: None,
                    created_at: Utc::now(),
                };
                if let Err(e) = state.storage.insert_policy(&record).await {
                    error!("Failed to insert policy from bundle: {:?}", e);
                    return StatusError::internal("Database error").into_response();
                }
                record_policy_audit_log(
                    state.storage.as_ref(),
                    &tenant_id,
                    &record.id,
                    &record.policy_key,
                    "created",
                    &record.body,
                    format!(
                        "Policy '{}' created (version 1) via signed bundle",
                        record.name
                    ),
                )
                .await;
                record
            }
        };
        results.push(record);
    }

    if let Err(e) = reload_policies_helper(&state, &tenant_id).await {
        error!("Failed to reload policies after bundle upload: {:?}", e);
        return StatusError::internal("Failed to hot-reload policy changes").into_response();
    }

    (StatusCode::OK, Json(results)).into_response()
}

pub async fn compile_policy(
    State(_state): State<Arc<AppState>>,
    TenantId(_tenant_id): TenantId,
    body: String,
) -> impl IntoResponse {
    match aegis_policy::compiler::compile_yaml_to_cedar(&body) {
        Ok(cedar) => (StatusCode::OK, Json(json!({ "cedar": cedar }))).into_response(),
        Err(e) => StatusError::bad_request(e).into_response(),
    }
}

pub async fn list_policy_templates(
    State(_state): State<Arc<AppState>>,
    TenantId(_tenant_id): TenantId,
) -> impl IntoResponse {
    let templates = aegis_policy::compiler::get_templates();
    (StatusCode::OK, Json(templates)).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
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
    async fn test_compile_and_templates_routes() {
        let (state, tenant_id, _) = setup_state("compile_templates").await;

        // 1. Get templates
        let response = list_policy_templates(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let templates: Vec<aegis_policy::compiler::PolicyTemplate> =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(templates.len(), 10);
        assert_eq!(templates[0].key, "production-baseline");

        // 2. Compile valid YAML policy
        let yaml_policy = r#"kind: AgentGuardPolicy
metadata:
  name: test-policy
spec:
  unknownMcpTools: deny
  productionMutations: require_approval
"#;
        let response_compile = compile_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            yaml_policy.to_string(),
        )
        .await
        .into_response();
        assert_eq!(response_compile.status(), StatusCode::OK);
        let compile_body = to_bytes(response_compile.into_body(), usize::MAX)
            .await
            .unwrap();
        let compile_json: Value = serde_json::from_slice(&compile_body).unwrap();
        let cedar = compile_json["cedar"].as_str().unwrap();
        assert!(cedar.contains("context.is_mcp_tool_known == false"));

        // 3. Compile invalid YAML policy
        let invalid_yaml = r#"kind: InvalidKind
metadata:
  name: test-policy
spec: {}
"#;
        let response_compile_invalid = compile_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            invalid_yaml.to_string(),
        )
        .await
        .into_response();
        assert_eq!(response_compile_invalid.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_policy_crud_and_reload_route() {
        let (state, tenant_id, _) = setup_state("policy_crud_reload").await;

        // 1. List policies (initially empty)
        let response = list_policies(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());

        // 2. Create custom Cedar policy
        let payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
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
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();

        // 3. Create invalid policy (should return 400)
        let payload_invalid = CreatePolicyRequest {
            policy_key: "invalid".to_string(),
            name: "Invalid".to_string(),
            body: "permit (invalid syntax);".to_string(),
        };
        let response_invalid = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload_invalid),
        )
        .await
        .into_response();
        assert_eq!(response_invalid.status(), StatusCode::BAD_REQUEST);

        // 4. List policies (should contain 1 policy)
        let response_list = list_policies(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response_list.status(), StatusCode::OK);
        let body_list = to_bytes(response_list.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_list: Value = serde_json::from_slice(&body_list).unwrap();
        assert_eq!(json_list.as_array().unwrap().len(), 1);

        // 5. Update policy (change status to inactive)
        let payload_update = UpdatePolicyRequest {
            policy_key: None,
            name: None,
            body: None,
            status: Some("inactive".to_string()),
        };
        let response_update = update_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
            Json(payload_update),
        )
        .await
        .into_response();
        assert_eq!(response_update.status(), StatusCode::OK);

        // 6. Delete policy
        let response_delete = delete_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete.status(), StatusCode::OK);

        // 7. Delete non-existent policy (should return 404)
        let response_delete_404 = delete_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_delete_404.status(), StatusCode::NOT_FOUND);
    }

    /// #1159 (OBS-006): `POST /v1/policies/reload` must leave an audit
    /// trail — config changes (here, a global Cedar policy file reload)
    /// were previously silent.
    #[tokio::test]
    async fn reload_global_policies_emits_config_change_audit_event() {
        let (state, tenant_id, _) = setup_state("reload_global_policies_audit").await;

        let response = reload_global_policies(State(state.clone()), TenantId(tenant_id.clone()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let events = state
            .storage
            .get_audit_events(&tenant_id, None, None, None)
            .await
            .unwrap()
            .0;
        let event = events
            .iter()
            .find(|e| e.event_type == "config_change")
            .expect("expected a config_change audit event");
        assert_eq!(event.action.as_deref(), Some("policy_file_reload"));
        assert!(event.event_json.contains("policies.cedar"));
    }

    /// TASK-0091 (#937): `PUT /v1/policies/:id` overwrites the `policies` row
    /// in place after incrementing `version`, so the previous body would
    /// otherwise be lost. Each update must archive the pre-update row into
    /// `policy_versions`, tenant-scoped, giving operators an audit trail.
    #[tokio::test]
    async fn update_policy_archives_previous_version() {
        let (state, tenant_id, _) = setup_state("policy_version_archive").await;

        let create_payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(create_payload),
        )
        .await
        .into_response();
        assert_eq!(response_create.status(), StatusCode::CREATED);
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();
        assert_eq!(json_create["version"].as_i64(), Some(1));

        // No versions archived yet for a brand-new policy.
        let versions = state
            .storage
            .list_policy_versions(&tenant_id, &policy_id)
            .await
            .unwrap();
        assert!(versions.is_empty());

        // First update: v1 -> v2. The original v1 body must be archived.
        let update1 = UpdatePolicyRequest {
            policy_key: None,
            name: None,
            body: Some("forbid (principal, action, resource);".to_string()),
            status: None,
        };
        let response_update1 = update_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
            Json(update1),
        )
        .await
        .into_response();
        assert_eq!(response_update1.status(), StatusCode::OK);

        let versions = state
            .storage
            .list_policy_versions(&tenant_id, &policy_id)
            .await
            .unwrap();
        assert_eq!(versions.len(), 1, "v1 must be archived after first update");
        assert_eq!(versions[0].version, 1);
        assert_eq!(versions[0].body, "permit (principal, action, resource);");
        assert_eq!(versions[0].tenant_id, tenant_id);
        assert_eq!(versions[0].policy_id, policy_id);

        // Second update: v2 -> v3. The v2 body must also be archived, most
        // recent first.
        let update2 = UpdatePolicyRequest {
            policy_key: None,
            name: None,
            body: Some("permit (principal, action == Action::\"x\", resource);".to_string()),
            status: None,
        };
        let response_update2 = update_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
            Json(update2),
        )
        .await
        .into_response();
        assert_eq!(response_update2.status(), StatusCode::OK);

        let versions = state
            .storage
            .list_policy_versions(&tenant_id, &policy_id)
            .await
            .unwrap();
        assert_eq!(versions.len(), 2, "v2 must also be archived");
        assert_eq!(versions[0].version, 2, "most recent archived version first");
        assert_eq!(versions[0].body, "forbid (principal, action, resource);");
        assert_eq!(versions[1].version, 1);
    }

    /// #1302: `POST /v1/policies/:id/rollback` restores the most recently
    /// archived `policy_versions` row onto the live `policies` row, bumping
    /// `version` monotonically (never reusing/decreasing version numbers).
    #[tokio::test]
    async fn rollback_restores_previous_policy_version() {
        let (state, tenant_id, _) = setup_state("policy_rollback_restore").await;

        let create_payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(create_payload),
        )
        .await
        .into_response();
        assert_eq!(response_create.status(), StatusCode::CREATED);
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();
        let original_name = json_create["name"].as_str().unwrap().to_string();
        let original_body = json_create["body"].as_str().unwrap().to_string();
        assert_eq!(json_create["version"].as_i64(), Some(1));

        // Update: v1 -> v2, body/name changed.
        let update1 = UpdatePolicyRequest {
            policy_key: None,
            name: Some("Renamed Policy".to_string()),
            body: Some("forbid (principal, action, resource);".to_string()),
            status: None,
        };
        let response_update1 = update_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
            Json(update1),
        )
        .await
        .into_response();
        assert_eq!(response_update1.status(), StatusCode::OK);
        let body_update1 = to_bytes(response_update1.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_update1: Value = serde_json::from_slice(&body_update1).unwrap();
        assert_eq!(json_update1["version"].as_i64(), Some(2));
        assert_eq!(json_update1["name"].as_str().unwrap(), "Renamed Policy");

        // Rollback: restores the archived v1 body/name, bumps version to 3.
        let response_rollback = rollback_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_rollback.status(), StatusCode::OK);
        let body_rollback = to_bytes(response_rollback.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_rollback: Value = serde_json::from_slice(&body_rollback).unwrap();
        assert_eq!(
            json_rollback["body"].as_str().unwrap(),
            original_body,
            "rollback must restore the pre-update body"
        );
        assert_eq!(
            json_rollback["name"].as_str().unwrap(),
            original_name,
            "rollback must restore the pre-update name"
        );
        assert_eq!(
            json_rollback["version"].as_i64(),
            Some(3),
            "version must monotonically increase, never reuse the old version number"
        );

        // The live record in the DB must match too.
        let live = state
            .storage
            .get_policy_by_id(&tenant_id, &policy_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(live.body, original_body);
        assert_eq!(live.name, original_name);
        assert_eq!(live.version, 3);
    }

    /// #1302: rollback must archive the row it's rolling back FROM (so the
    /// rollback itself is reversible) and emit a `policy_rolled_back` audit
    /// event.
    #[tokio::test]
    async fn rollback_emits_policy_rolled_back_audit_event() {
        let (state, tenant_id, _) = setup_state("policy_rollback_audit").await;

        let create_payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(create_payload),
        )
        .await
        .into_response();
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();

        let update1 = UpdatePolicyRequest {
            policy_key: None,
            name: None,
            body: Some("forbid (principal, action, resource);".to_string()),
            status: None,
        };
        let response_update1 = update_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
            Json(update1),
        )
        .await
        .into_response();
        assert_eq!(response_update1.status(), StatusCode::OK);

        let response_rollback = rollback_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_rollback.status(), StatusCode::OK);

        let events = state
            .storage
            .get_audit_events(&tenant_id, None, None, None)
            .await
            .unwrap()
            .0;
        let rollback_event = events
            .iter()
            .find(|e| e.event_type == "policy_rolled_back")
            .expect("policy_rolled_back audit event must be emitted");
        assert_eq!(rollback_event.tenant_id, tenant_id);
        assert_eq!(rollback_event.resource.as_deref(), Some(policy_id.as_str()));

        // Rollback must also have archived the row it rolled back FROM (v2),
        // so two versions are now archived: v1 (from the update) and v2
        // (from the rollback).
        let versions = state
            .storage
            .list_policy_versions(&tenant_id, &policy_id)
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 2, "most recent archived first");
        assert_eq!(versions[1].version, 1);
    }

    /// #1302: rolling back a policy that has never been updated (no archived
    /// version exists) must fail rather than silently no-op.
    #[tokio::test]
    async fn rollback_without_prior_version_returns_error() {
        let (state, tenant_id, _) = setup_state("policy_rollback_no_prior").await;

        let create_payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(create_payload),
        )
        .await
        .into_response();
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();

        let response_rollback = rollback_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        let status = response_rollback.status();
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
            "expected 404 or 400, got {}",
            status
        );
        let body = to_bytes(response_rollback.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json["message"].as_str().is_some());
    }

    /// #1302: rolling back a nonexistent policy id returns 404, fail-closed.
    #[tokio::test]
    async fn rollback_nonexistent_policy_returns_404() {
        let (state, tenant_id, _) = setup_state("policy_rollback_missing").await;

        let response_rollback = rollback_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(Uuid::new_v4().to_string()),
        )
        .await
        .into_response();
        assert_eq!(response_rollback.status(), StatusCode::NOT_FOUND);
    }

    /// #1302: rollback is tenant-scoped — tenant B cannot roll back tenant
    /// A's policy via its id (CWE-284).
    #[tokio::test]
    async fn rollback_returns_404_cross_tenant() {
        let (state, tenant_id_a, _) = setup_state("policy_rollback_cross_tenant").await;
        let tenant_id_b = format!("tenant_b_{}", uuid::Uuid::new_v4().simple());
        register_tenant_helper(
            state.storage.as_ref(),
            &tenant_id_b,
            "Tenant B",
            "developer",
        )
        .await;

        let create_payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
            State(state.clone()),
            TenantId(tenant_id_a.clone()),
            Json(create_payload),
        )
        .await
        .into_response();
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();

        // Tenant B attempts to roll back tenant A's policy.
        let response_rollback = rollback_policy(
            State(state.clone()),
            TenantId(tenant_id_b.clone()),
            Path(policy_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_rollback.status(), StatusCode::NOT_FOUND);
    }

    /// #1302: `policy_versions` retains at most 10 rows per (tenant, policy),
    /// keeping the highest-numbered (most recent) versions.
    #[tokio::test]
    async fn policy_versions_capped_at_ten() {
        let (state, tenant_id, _) = setup_state("policy_versions_cap").await;

        let create_payload = CreatePolicyRequest {
            policy_key: "allow-all".to_string(),
            name: "Allow All".to_string(),
            body: "permit (principal, action, resource);".to_string(),
        };
        let response_create = create_policy(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(create_payload),
        )
        .await
        .into_response();
        let body_create = to_bytes(response_create.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_create: Value = serde_json::from_slice(&body_create).unwrap();
        let policy_id = json_create["id"].as_str().unwrap().to_string();

        // Archive 12 versions directly via the db helper.
        for v in 1..=12 {
            let record = PolicyRecord {
                id: policy_id.clone(),
                tenant_id: tenant_id.clone(),
                policy_key: "allow-all".to_string(),
                name: format!("Version {}", v),
                language: "cedar".to_string(),
                body: "permit (principal, action, resource);".to_string(),
                version: v,
                status: "active".to_string(),
                created_by: None,
                created_at: Utc::now(),
            };
            state.storage.insert_policy_version(&record).await.unwrap();
        }

        let versions = state
            .storage
            .list_policy_versions(&tenant_id, &policy_id)
            .await
            .unwrap();
        assert_eq!(versions.len(), 10, "must retain at most 10 versions");
        // Highest-numbered (most recent) versions retained: 12 down to 3.
        let kept_versions: Vec<i32> = versions.iter().map(|v| v.version).collect();
        assert_eq!(kept_versions, vec![12, 11, 10, 9, 8, 7, 6, 5, 4, 3]);
    }

    /// Fixed throwaway Ed25519 secret for bundle-signing tests (#1280) —
    /// never used outside this test module.
    fn test_signing_key() -> crate::sign::ReceiptSigner {
        crate::sign::ReceiptSigner::from_secret_hex(&"11".repeat(32)).unwrap()
    }

    fn sign_bundle(
        payload: &PolicyBundleUploadRequest,
        signer: &crate::sign::ReceiptSigner,
    ) -> String {
        signer.sign_hash(&policy_bundle_signed_hash(payload))
    }

    #[tokio::test]
    async fn upload_policy_bundle_rejects_when_signing_not_configured() {
        let (state, tenant_id, _) = setup_state("bundle_no_signing_key").await;
        let signer = test_signing_key();
        let mut payload = PolicyBundleUploadRequest {
            policies: vec![PolicyBundleEntry {
                policy_key: "bundle-policy-1".to_string(),
                name: "Bundle Policy 1".to_string(),
                body: "permit (principal, action, resource);".to_string(),
            }],
            version: 1,
            created_at: Utc::now(),
            signature: String::new(),
        };
        payload.signature = sign_bundle(&payload, &signer);

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn upload_policy_bundle_rejects_invalid_signature() {
        let signer = test_signing_key();
        let (state, tenant_id, _) =
            setup_state_with_policy_signing_key("bundle_invalid_sig", &signer.public_key_hex())
                .await;

        let payload = PolicyBundleUploadRequest {
            policies: vec![PolicyBundleEntry {
                policy_key: "bundle-policy-1".to_string(),
                name: "Bundle Policy 1".to_string(),
                body: "permit (principal, action, resource);".to_string(),
            }],
            version: 1,
            created_at: Utc::now(),
            signature: "deadbeef".repeat(16), // well-formed hex, but not a valid signature
        };

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn upload_policy_bundle_accepts_valid_signature_and_creates_policy() {
        let signer = test_signing_key();
        let (state, tenant_id, _) =
            setup_state_with_policy_signing_key("bundle_valid_create", &signer.public_key_hex())
                .await;

        let mut payload = PolicyBundleUploadRequest {
            policies: vec![PolicyBundleEntry {
                policy_key: "bundle-policy-1".to_string(),
                name: "Bundle Policy 1".to_string(),
                body: "permit (principal, action, resource);".to_string(),
            }],
            version: 1,
            created_at: Utc::now(),
            signature: String::new(),
        };
        payload.signature = sign_bundle(&payload, &signer);

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let policies = state.storage.list_policies(&tenant_id).await.unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].policy_key, "bundle-policy-1");
        assert_eq!(policies[0].version, 1);
    }

    #[tokio::test]
    async fn upload_policy_bundle_updates_existing_policy_and_bumps_version() {
        let signer = test_signing_key();
        let (state, tenant_id, _) =
            setup_state_with_policy_signing_key("bundle_update_existing", &signer.public_key_hex())
                .await;

        // Seed an existing policy directly.
        let existing = PolicyRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            policy_key: "bundle-policy-1".to_string(),
            name: "Original Name".to_string(),
            language: "cedar".to_string(),
            body: "forbid (principal, action, resource);".to_string(),
            version: 1,
            status: "active".to_string(),
            created_by: None,
            created_at: Utc::now(),
        };
        state.storage.insert_policy(&existing).await.unwrap();

        let mut payload = PolicyBundleUploadRequest {
            policies: vec![PolicyBundleEntry {
                policy_key: "bundle-policy-1".to_string(),
                name: "Updated Name".to_string(),
                body: "permit (principal, action, resource);".to_string(),
            }],
            version: 1,
            created_at: Utc::now(),
            signature: String::new(),
        };
        payload.signature = sign_bundle(&payload, &signer);

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let updated = state
            .storage
            .get_policy_by_id(&tenant_id, &existing.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.version, 2);
        assert_eq!(updated.name, "Updated Name");
        assert_eq!(updated.body, "permit (principal, action, resource);");

        let versions = state
            .storage
            .list_policy_versions(&tenant_id, &existing.id)
            .await
            .unwrap();
        assert_eq!(versions.len(), 1, "the prior version must be archived");
        assert_eq!(versions[0].body, "forbid (principal, action, resource);");
    }

    #[tokio::test]
    async fn upload_policy_bundle_rejects_invalid_cedar_body_without_partial_writes() {
        let signer = test_signing_key();
        let (state, tenant_id, _) =
            setup_state_with_policy_signing_key("bundle_invalid_cedar", &signer.public_key_hex())
                .await;

        let mut payload = PolicyBundleUploadRequest {
            policies: vec![
                PolicyBundleEntry {
                    policy_key: "bundle-policy-good".to_string(),
                    name: "Good".to_string(),
                    body: "permit (principal, action, resource);".to_string(),
                },
                PolicyBundleEntry {
                    policy_key: "bundle-policy-bad".to_string(),
                    name: "Bad".to_string(),
                    body: "permit (invalid syntax);".to_string(),
                },
            ],
            version: 1,
            created_at: Utc::now(),
            signature: String::new(),
        };
        payload.signature = sign_bundle(&payload, &signer);

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let policies = state.storage.list_policies(&tenant_id).await.unwrap();
        assert!(
            policies.is_empty(),
            "a bad entry must reject the WHOLE bundle, not partially apply it"
        );
    }

    #[tokio::test]
    async fn upload_policy_bundle_rejects_tampered_bundle() {
        let signer = test_signing_key();
        let (state, tenant_id, _) =
            setup_state_with_policy_signing_key("bundle_tampered", &signer.public_key_hex()).await;

        let mut payload = PolicyBundleUploadRequest {
            policies: vec![PolicyBundleEntry {
                policy_key: "bundle-policy-1".to_string(),
                name: "Bundle Policy 1".to_string(),
                body: "permit (principal, action, resource);".to_string(),
            }],
            version: 1,
            created_at: Utc::now(),
            signature: String::new(),
        };
        payload.signature = sign_bundle(&payload, &signer);

        // Tamper with the signed body AFTER signing — the signature no
        // longer covers this content.
        payload.policies[0].body = "forbid (principal, action, resource);".to_string();

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let policies = state.storage.list_policies(&tenant_id).await.unwrap();
        assert!(
            policies.is_empty(),
            "a tampered bundle must never be applied"
        );
    }

    #[tokio::test]
    async fn upload_policy_bundle_rejects_empty_policies_list() {
        let signer = test_signing_key();
        let (state, tenant_id, _) =
            setup_state_with_policy_signing_key("bundle_empty", &signer.public_key_hex()).await;

        let mut payload = PolicyBundleUploadRequest {
            policies: vec![],
            version: 1,
            created_at: Utc::now(),
            signature: String::new(),
        };
        payload.signature = sign_bundle(&payload, &signer);

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// #1328: signed bundle -> verified -> persisted -> hot-reloaded into the
    /// live `PolicyEngine` -> evaluated produces the SAME decision as loading
    /// that exact Cedar text standalone (no upload/signing involved at all).
    /// This is the "signed bundle round-trip" half of the issue's acceptance
    /// criteria — the other half (tampered bundle rejected) is already
    /// covered by `upload_policy_bundle_rejects_tampered_bundle` above.
    ///
    /// Uses an unconditional `forbid` keyed to a resource id nothing else in
    /// `policies.cedar` mentions, so the assertion isn't sensitive to
    /// whatever else the base policy set happens to decide for this
    /// tenant — a forbid wins regardless of what any other permit in the
    /// combined (base + bundle) policy set says.
    #[tokio::test]
    async fn upload_policy_bundle_evaluation_matches_standalone_cedar_load() {
        let signer = test_signing_key();
        let (state, tenant_id, _) =
            setup_state_with_policy_signing_key("bundle_roundtrip_eval", &signer.public_key_hex())
                .await;

        let cedar_body = "forbid (principal, action, resource == ToolAction::\"roundtrip_test_tool_dangerous_action\");".to_string();

        let mut payload = PolicyBundleUploadRequest {
            policies: vec![PolicyBundleEntry {
                policy_key: "roundtrip-forbid".to_string(),
                name: "Round-trip Forbid".to_string(),
                body: cedar_body.clone(),
            }],
            version: 1,
            created_at: Utc::now(),
            signature: String::new(),
        };
        payload.signature = sign_bundle(&payload, &signer);

        let response = upload_policy_bundle(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(payload),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let request = AuthorizeRequest {
            request_id: None,
            callback: None,
            nonce: None,
            timestamp: None,
            dry_run: None,
            agent: AuthorizeAgentContext {
                id: "roundtrip-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "roundtrip_test_tool".to_string(),
                action: "dangerous_action".to_string(),
                resource: None,
                mutates_state: false,
                parameters: json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: None,
        };

        // Evaluated through the tenant's live (base + uploaded bundle)
        // policy set — the same path `/v1/authorize` uses.
        let live_decision = state
            .policy_engine
            .authorize(&tenant_id, &request, "low", true, true)
            .unwrap()
            .decision;
        assert_eq!(live_decision, "deny");

        // Evaluated through a fresh `PolicyEngine` loaded with ONLY the
        // uploaded Cedar text — no base policy, no upload/signing pipeline.
        // `tempfile::Builder` (rather than a predictable path under the
        // shared `std::env::temp_dir()`) atomically creates a uniquely-named
        // file with restricted permissions and cleans it up on drop.
        let standalone_file = tempfile::Builder::new()
            .prefix("aegis-bundle-roundtrip-")
            .suffix(".cedar")
            .tempfile()
            .unwrap();
        tokio::fs::write(standalone_file.path(), &cedar_body)
            .await
            .unwrap();
        let standalone_engine = PolicyEngine::init(standalone_file.path()).await.unwrap();
        let standalone_decision = standalone_engine
            .authorize("any_tenant", &request, "low", true, true)
            .unwrap()
            .decision;
        assert_eq!(standalone_decision, "deny");

        assert_eq!(
            live_decision, standalone_decision,
            "a signed bundle's policy, once uploaded and hot-reloaded, must \
             evaluate identically to loading the same Cedar text directly"
        );
    }

    /// Guards against the exact regression this test was added to catch: the
    /// repo carries FOUR copies of the base Cedar policy set — the canonical
    /// root `policies.cedar`, `lib/policy/policies.cedar` (read by
    /// `aegis-policy`'s own unit tests), `src/policies.cedar` (read by
    /// `PolicyEngine::init("policies.cedar")` at gateway runtime/test time —
    /// the one that actually governs production behavior), and the Helm
    /// chart's deployment copy. These had silently drifted: `src/` and
    /// `helm/`'s copies were missing the "deny unknown MCP tools by default"
    /// forbid rule entirely, silently downgrading a fail-closed security
    /// default to "critical risk requires approval" for any unregistered MCP
    /// tool — a real security regression that two existing tests caught,
    /// but nothing explained *why* the rule that's plainly present in the
    /// root file wasn't taking effect. Byte-equality here turns "drift" into
    /// an immediate, obvious CI failure instead of a silent policy gap.
    #[test]
    fn policies_cedar_copies_stay_byte_identical() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let canonical = std::fs::read_to_string(format!("{manifest_dir}/../policies.cedar"))
            .expect("root policies.cedar must exist");

        for (label, path) in [
            (
                "src/policies.cedar",
                format!("{manifest_dir}/policies.cedar"),
            ),
            (
                "lib/policy/policies.cedar",
                format!("{manifest_dir}/../lib/policy/policies.cedar"),
            ),
            (
                "helm/aegis-gateway/files/policies.cedar",
                format!("{manifest_dir}/../helm/aegis-gateway/files/policies.cedar"),
            ),
        ] {
            let copy = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{label} must exist at {path}: {e}"));
            assert_eq!(
                copy, canonical,
                "{label} has drifted from the canonical root policies.cedar — \
                 every copy must be byte-identical, since the gateway loads \
                 {label} at runtime/test time, not the root copy"
            );
        }
    }
}
