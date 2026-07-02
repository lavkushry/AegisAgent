//! Phase 2.7 (runtime control plane): HTTP routes for agent bans, quarantine
//! records, and signed control commands. Wires the Phase 2.3-2.5 storage
//! (`control_commands`, `agent_bans`, `quarantine_records`) to the API.
//!
//! The gateway persists commands here as issued; it does not itself hold
//! sensor signing keys, so `signature` is supplied by the issuing caller
//! (the Control Command Protocol doc covers key management, which lands with
//! the sensor phase).

#![allow(unused_imports)]
use crate::error::StatusError;
use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::models::*;

use super::{parse_pagination, AppState, TenantId};

// ---------------------------------------------------------------------------
// Agent bans
// ---------------------------------------------------------------------------

/// Body for `POST /v1/bans`.
#[derive(Debug, Deserialize)]
pub struct CreateBanRequest {
    /// `agent` | `run` | `sandbox` | `fingerprint` | `destination` | `tool` | ...
    pub target_type: String,
    pub target_value: String,
    /// `run` | `agent` | `tenant` | `organization`.
    #[serde(default = "default_ban_scope")]
    pub scope: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub actor: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_ban_scope() -> String {
    "tenant".to_string()
}

/// POST /v1/bans — record a new ban. Tenant-scoped.
pub async fn create_ban(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<CreateBanRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let record = AgentBanRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        target_type: req.target_type,
        target_value: req.target_value,
        scope: req.scope,
        reason: req.reason,
        actor: req.actor,
        status: "active".to_string(),
        created_at: now,
        expires_at: req.expires_at,
        revoked_at: None,
        revoked_by: None,
    };
    match state.storage.insert_ban(&record).await {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            error!("Failed to create agent ban: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/bans/:id — fetch one ban. Tenant-scoped (404 cross-tenant).
pub async fn get_ban(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(ban_id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_ban(&tenant_id, &ban_id).await {
        Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
        Ok(None) => StatusError::not_found("ban not found").into_response(),
        Err(e) => {
            error!("Failed to get agent ban: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/bans — list the tenant's bans (paginated). Tenant-scoped.
pub async fn list_bans(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    match state.storage.list_bans(&tenant_id, limit, offset).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list agent bans: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/bans/:id/revoke`.
#[derive(Debug, Deserialize)]
pub struct RevokeBanRequest {
    pub revoked_by: String,
}

/// POST /v1/bans/:id/revoke — revoke an active ban. Tenant-scoped; idempotent
/// on an already-revoked ban.
pub async fn revoke_ban(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(ban_id): Path<String>,
    Json(req): Json<RevokeBanRequest>,
) -> impl IntoResponse {
    let existing = match state.storage.get_ban(&tenant_id, &ban_id).await {
        Ok(Some(b)) => b,
        Ok(None) => return StatusError::not_found("ban not found").into_response(),
        Err(e) => {
            error!("Failed to fetch ban for revoke: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    if existing.status == "revoked" {
        return (StatusCode::OK, Json(existing)).into_response();
    }

    let now = Utc::now();
    match state
        .storage
        .revoke_ban(&tenant_id, &ban_id, &req.revoked_by, now)
        .await
    {
        Ok(_) => match state.storage.get_ban(&tenant_id, &ban_id).await {
            Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
            Ok(None) => StatusError::not_found("ban not found").into_response(),
            Err(e) => {
                error!("Failed to re-fetch ban after revoke: {:?}", e);
                StatusError::internal("Database error").into_response()
            }
        },
        Err(e) => {
            error!("Failed to revoke ban: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

/// Body for `POST /v1/quarantine`.
#[derive(Debug, Deserialize)]
pub struct CreateQuarantineRequest {
    pub target_type: String,
    pub target_value: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub actor: String,
    #[serde(default)]
    pub incident_id: Option<String>,
}

/// POST /v1/quarantine — record a new quarantine. Tenant-scoped.
pub async fn create_quarantine(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<CreateQuarantineRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let record = QuarantineRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id,
        target_type: req.target_type,
        target_value: req.target_value,
        reason: req.reason,
        actor: req.actor,
        status: "active".to_string(),
        incident_id: req.incident_id,
        created_at: now,
        released_at: None,
        released_by: None,
    };
    match state.storage.insert_quarantine(&record).await {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            error!("Failed to create quarantine record: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/quarantine/:id — fetch one quarantine record. Tenant-scoped.
pub async fn get_quarantine(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_quarantine(&tenant_id, &id).await {
        Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
        Ok(None) => StatusError::not_found("quarantine record not found").into_response(),
        Err(e) => {
            error!("Failed to get quarantine record: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/quarantine — list the tenant's quarantine records (paginated).
pub async fn list_quarantine(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    match state
        .storage
        .list_quarantine(&tenant_id, limit, offset)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list quarantine records: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/quarantine/:id/release`.
#[derive(Debug, Deserialize)]
pub struct ReleaseQuarantineRequest {
    pub released_by: String,
    /// `released` | `deleted` (default `released`).
    #[serde(default = "default_release_status")]
    pub status: String,
}

fn default_release_status() -> String {
    "released".to_string()
}

/// POST /v1/quarantine/:id/release — release an active quarantine after
/// review. Tenant-scoped; idempotent on an already-released record.
pub async fn release_quarantine(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(req): Json<ReleaseQuarantineRequest>,
) -> impl IntoResponse {
    let existing = match state.storage.get_quarantine(&tenant_id, &id).await {
        Ok(Some(q)) => q,
        Ok(None) => return StatusError::not_found("quarantine record not found").into_response(),
        Err(e) => {
            error!("Failed to fetch quarantine record for release: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    if existing.status != "active" {
        return (StatusCode::OK, Json(existing)).into_response();
    }

    let now = Utc::now();
    match state
        .storage
        .release_quarantine(&tenant_id, &id, &req.status, &req.released_by, now)
        .await
    {
        Ok(_) => match state.storage.get_quarantine(&tenant_id, &id).await {
            Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
            Ok(None) => StatusError::not_found("quarantine record not found").into_response(),
            Err(e) => {
                error!(
                    "Failed to re-fetch quarantine record after release: {:?}",
                    e
                );
                StatusError::internal("Database error").into_response()
            }
        },
        Err(e) => {
            error!("Failed to release quarantine record: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Control commands
// ---------------------------------------------------------------------------

/// Body for `POST /v1/control/commands`. The gateway persists the command as
/// issued by the caller; it does not sign on the caller's behalf.
#[derive(Debug, Deserialize)]
pub struct IssueControlCommandRequest {
    pub target_type: String,
    pub target_id: String,
    pub action: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub issued_by: String,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
    #[serde(default)]
    pub requires_ack: bool,
    #[serde(default)]
    pub receipt_required: bool,
    pub signature: String,
}

/// POST /v1/control/commands — issue a signed control command. Tenant-scoped.
/// A replayed `(tenant, nonce)` is a 409 (unique-index conflict).
pub async fn issue_control_command(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<IssueControlCommandRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let record = ControlCommandRecord {
        command_id: Uuid::new_v4().to_string(),
        tenant_id,
        target_type: req.target_type,
        target_id: req.target_id,
        action: req.action,
        reason: req.reason,
        issued_by: req.issued_by,
        issued_at: now,
        expires_at: req.expires_at,
        nonce: req.nonce,
        requires_ack: req.requires_ack,
        receipt_required: req.receipt_required,
        signature: req.signature,
        status: "issued".to_string(),
        created_at: now,
    };
    match state.storage.insert_control_command(&record).await {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            // A duplicate (tenant, nonce) trips the unique index (replay).
            error!("Failed to issue control command: {:?}", e);
            StatusError::conflict("control command nonce already used").into_response()
        }
    }
}

/// GET /v1/control/commands/:id — fetch one command. Tenant-scoped.
pub async fn get_control_command(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(command_id): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .get_control_command(&tenant_id, &command_id)
        .await
    {
        Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
        Ok(None) => StatusError::not_found("control command not found").into_response(),
        Err(e) => {
            error!("Failed to get control command: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/control/commands — list the tenant's commands (paginated).
pub async fn list_control_commands(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    match state
        .storage
        .list_control_commands(&tenant_id, limit, offset)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list control commands: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/control/commands/:id/status`.
#[derive(Debug, Deserialize)]
pub struct UpdateControlCommandStatusRequest {
    /// `delivered` | `acked` | `nacked` | `executed` | `expired`.
    pub status: String,
}

/// POST /v1/control/commands/:id/status — transition a command's delivery
/// status (the sensor's ack/nack/executed callback). Tenant-scoped.
pub async fn update_control_command_status(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(command_id): Path<String>,
    Json(req): Json<UpdateControlCommandStatusRequest>,
) -> impl IntoResponse {
    let existing = match state
        .storage
        .get_control_command(&tenant_id, &command_id)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => return StatusError::not_found("control command not found").into_response(),
        Err(e) => {
            error!("Failed to fetch control command for status update: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    if existing.status == req.status {
        return (StatusCode::OK, Json(existing)).into_response();
    }

    match state
        .storage
        .update_control_command_status(&tenant_id, &command_id, &req.status)
        .await
    {
        Ok(_) => match state
            .storage
            .get_control_command(&tenant_id, &command_id)
            .await
        {
            Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
            Ok(None) => StatusError::not_found("control command not found").into_response(),
            Err(e) => {
                error!(
                    "Failed to re-fetch control command after status update: {:?}",
                    e
                );
                StatusError::internal("Database error").into_response()
            }
        },
        Err(e) => {
            error!("Failed to update control command status: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn create_ban_then_get_and_list_round_trip() {
        let (state, tenant_id, _agent_token) = setup_state("control_ban_create").await;

        let response = create_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateBanRequest {
                target_type: "fingerprint".to_string(),
                target_value: "fp-xyz".to_string(),
                scope: "tenant".to_string(),
                reason: Some("exfil attempt".to_string()),
                actor: "soc-analyst".to_string(),
                expires_at: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: AgentBanRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.status, "active");

        let response = get_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let response = list_bans(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<AgentBanRecord> = serde_json::from_slice(&body).unwrap();
        assert!(rows.iter().any(|b| b.id == created.id));
    }

    #[tokio::test]
    async fn revoke_ban_is_idempotent_and_tenant_scoped() {
        let (state, tenant_id, _agent_token) = setup_state("control_ban_revoke").await;

        let response = create_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateBanRequest {
                target_type: "agent".to_string(),
                target_value: "agent-1".to_string(),
                scope: "tenant".to_string(),
                reason: None,
                actor: "soc-analyst".to_string(),
                expires_at: None,
            }),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: AgentBanRecord = serde_json::from_slice(&body).unwrap();

        let response = revoke_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
            Json(RevokeBanRequest {
                revoked_by: "admin".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let revoked: AgentBanRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(revoked.status, "revoked");

        // Idempotent re-revoke.
        let response = revoke_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
            Json(RevokeBanRequest {
                revoked_by: "admin2".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let still_revoked: AgentBanRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(still_revoked.revoked_by.as_deref(), Some("admin"));

        // Unknown id -> 404.
        let response = revoke_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("does-not-exist".to_string()),
            Json(RevokeBanRequest {
                revoked_by: "admin".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_quarantine_then_release_round_trip() {
        let (state, tenant_id, _agent_token) = setup_state("control_quarantine").await;

        let response = create_quarantine(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateQuarantineRequest {
                target_type: "workspace".to_string(),
                target_value: "ws-1".to_string(),
                reason: Some("secret exfil detected".to_string()),
                actor: "soc-analyst".to_string(),
                incident_id: Some("inc-1".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: QuarantineRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.status, "active");

        let response = get_quarantine(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let response = list_quarantine(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let response = release_quarantine(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
            Json(ReleaseQuarantineRequest {
                released_by: "admin".to_string(),
                status: "released".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let released: QuarantineRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(released.status, "released");

        // Idempotent re-release keeps the original released_by.
        let response = release_quarantine(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
            Json(ReleaseQuarantineRequest {
                released_by: "admin2".to_string(),
                status: "released".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let still_released: QuarantineRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(still_released.released_by.as_deref(), Some("admin"));
    }

    fn sample_command_request(nonce: &str) -> IssueControlCommandRequest {
        IssueControlCommandRequest {
            target_type: "run".to_string(),
            target_id: "run-1".to_string(),
            action: "kill_run".to_string(),
            reason: Some("policy: exfil detected".to_string()),
            issued_by: "soc-analyst".to_string(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            nonce: nonce.to_string(),
            requires_ack: true,
            receipt_required: true,
            signature: "ed25519:deadbeef".to_string(),
        }
    }

    #[tokio::test]
    async fn issue_control_command_then_get_list_and_status_update() {
        let (state, tenant_id, _agent_token) = setup_state("control_command_issue").await;

        let response = issue_control_command(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_command_request("nonce-1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: ControlCommandRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.status, "issued");

        let response = get_control_command(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.command_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let response = list_control_commands(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let response = update_control_command_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.command_id.clone()),
            Json(UpdateControlCommandStatusRequest {
                status: "acked".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let updated: ControlCommandRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated.status, "acked");
    }

    #[tokio::test]
    async fn issue_control_command_rejects_replayed_nonce() {
        let (state, tenant_id, _agent_token) = setup_state("control_command_replay").await;

        let response = issue_control_command(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_command_request("dup-nonce")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = issue_control_command(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_command_request("dup-nonce")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
