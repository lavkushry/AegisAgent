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

        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
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
        let versions = db::list_policy_versions(&state.pool, &tenant_id, &policy_id)
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

        let versions = db::list_policy_versions(&state.pool, &tenant_id, &policy_id)
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

        let versions = db::list_policy_versions(&state.pool, &tenant_id, &policy_id)
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
        let live = db::get_policy_by_id(&state.pool, &tenant_id, &policy_id)
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

        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        let rollback_event = events
            .iter()
            .find(|e| e.event_type == "policy_rolled_back")
            .expect("policy_rolled_back audit event must be emitted");
        assert_eq!(rollback_event.tenant_id, tenant_id);
        assert_eq!(rollback_event.resource.as_deref(), Some(policy_id.as_str()));

        // Rollback must also have archived the row it rolled back FROM (v2),
        // so two versions are now archived: v1 (from the update) and v2
        // (from the rollback).
        let versions = db::list_policy_versions(&state.pool, &tenant_id, &policy_id)
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
        db::register_tenant(&state.pool, &tenant_id_b, "Tenant B", "developer")
            .await
            .unwrap();

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
            db::insert_policy_version(&state.pool, &record)
                .await
                .unwrap();
        }

        let versions = db::list_policy_versions(&state.pool, &tenant_id, &policy_id)
            .await
            .unwrap();
        assert_eq!(versions.len(), 10, "must retain at most 10 versions");
        // Highest-numbered (most recent) versions retained: 12 down to 3.
        let kept_versions: Vec<i32> = versions.iter().map(|v| v.version).collect();
        assert_eq!(kept_versions, vec![12, 11, 10, 9, 8, 7, 6, 5, 4, 3]);
    }
}
