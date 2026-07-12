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
use tracing::{error, warn};
use uuid::Uuid;

use crate::models::*;

use super::runtime::{issue_run_control_command, RunControlRequest};
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
    if let Err(e) = state.storage.insert_ban(&record).await {
        error!("Failed to create agent ban: {:?}", e);
        return StatusError::internal("Database error").into_response();
    }

    // Sensor/runner propagation: a ban is not only a gate on future calls —
    // an `agent` ban also reaches the agent's live workloads by issuing a
    // signed `kill_run` control command per non-terminal run, which the
    // sensor/cage-runner already knows how to verify and execute. Best-
    // effort by design: the ban row above is durable and every choke point
    // (authorize, broker, cage start, egress) enforces it regardless, so a
    // propagation failure is logged, never a reason to fail the ban itself.
    // No signing key ⇒ no command — the gateway never issues a command a
    // sensor can't verify.
    if record.target_type == "agent" {
        if state.command_signing_key.is_none() {
            warn!(
                "agent ban {} created without AEGIS_COMMAND_SIGNING_KEY; \
                 live runs of '{}' will not receive kill commands",
                record.id, record.target_value
            );
        } else {
            match state
                .storage
                .list_active_agent_runs_for_agent(&record.tenant_id, &record.target_value)
                .await
            {
                Ok(runs) => {
                    for run in runs {
                        let control_req = RunControlRequest {
                            actor: record.actor.clone(),
                            reason: record.reason.clone(),
                        };
                        if let Err(e) = issue_run_control_command(
                            &state,
                            &record.tenant_id,
                            &run.id,
                            "kill_run",
                            &control_req,
                        )
                        .await
                        {
                            error!(
                                "Failed to propagate ban {} as kill_run to run {}: {:?}",
                                record.id, run.id, e
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to list active runs for banned agent '{}': {:?}",
                        record.target_value, e
                    );
                }
            }
        }
    }

    (StatusCode::CREATED, Json(record)).into_response()
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
    use crate::routes::test_helpers::{setup_state, setup_state_with_command_signing_key};
    use axum::body::to_bytes;

    // Test-only material, not a real key (same convention as
    // routes/runtime.rs and routes/receipts.rs tests).
    const TEST_COMMAND_SIGNING_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    /// Insert an agent run directly at the storage layer with a chosen
    /// status — propagation tests need runs in specific lifecycle states.
    async fn insert_run_with_status(
        state: &Arc<AppState>,
        tenant_id: &str,
        run_id: &str,
        agent_id: &str,
        status: &str,
    ) {
        let now = Utc::now();
        state
            .storage
            .insert_agent_run(&AgentRunRecord {
                id: run_id.to_string(),
                tenant_id: tenant_id.to_string(),
                agent_id: Some(agent_id.to_string()),
                run_key: format!("key-{run_id}"),
                source_component: "sdk".to_string(),
                mode: "enforce".to_string(),
                status: status.to_string(),
                started_at: now,
                finished_at: None,
                root_trace_id: None,
                root_trust_level: None,
                policy_bundle_id: None,
                claimed_by: None,
                claimed_at: None,
                last_heartbeat_at: None,
                image_ref: None,
                image_digest: None,
                command_json: None,
                working_dir: None,
                resource_limits_json: None,
                network_spec_json: None,
                tooling_spec_json: None,
                environment_json: None,
                workspace_spec_json: None,
                controlled_mounts_json: None,
                exit_code: None,
                created_at: now,
            })
            .await
            .unwrap();
    }

    fn agent_ban_request(agent_id: &str) -> CreateBanRequest {
        CreateBanRequest {
            target_type: "agent".to_string(),
            target_value: agent_id.to_string(),
            scope: "tenant".to_string(),
            reason: Some("credential exfil".to_string()),
            actor: "soc-analyst".to_string(),
            expires_at: None,
        }
    }

    /// Banning an agent propagates to its live workloads: every non-terminal
    /// run of that agent gets a signed `kill_run` control command the
    /// sensor/runner will pick up — a ban is not only a gate on *future*
    /// calls.
    #[tokio::test]
    async fn create_agent_ban_issues_signed_kill_commands_for_active_runs() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "control_ban_propagates",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;

        insert_run_with_status(&state, &tenant_id, "run-live-1", "agent-mal", "started").await;
        insert_run_with_status(&state, &tenant_id, "run-live-2", "agent-mal", "running").await;
        insert_run_with_status(&state, &tenant_id, "run-done", "agent-mal", "finished").await;
        insert_run_with_status(&state, &tenant_id, "run-other", "agent-ok", "running").await;

        let response = create_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(agent_ban_request("agent-mal")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let commands = state
            .storage
            .list_control_commands(&tenant_id, 50, 0)
            .await
            .unwrap();
        let kills: Vec<_> = commands.iter().filter(|c| c.action == "kill_run").collect();
        let killed_targets: Vec<&str> = kills.iter().map(|c| c.target_id.as_str()).collect();
        assert!(
            killed_targets.contains(&"run-live-1") && killed_targets.contains(&"run-live-2"),
            "both live runs must get kill commands, got: {killed_targets:?}"
        );
        assert!(
            !killed_targets.contains(&"run-done"),
            "a finished run must not be killed"
        );
        assert!(
            !killed_targets.contains(&"run-other"),
            "another agent's run must not be killed"
        );
        assert!(
            kills.iter().all(|c| !c.signature.is_empty()),
            "propagated commands must be signed"
        );
        assert!(
            kills
                .iter()
                .all(|c| c.reason.as_deref() == Some("credential exfil")),
            "kill commands must carry the ban's reason"
        );
    }

    /// Without a command signing key the ban row still lands (choke-point
    /// enforcement doesn't depend on propagation) — but no unsigned command
    /// is ever issued.
    #[tokio::test]
    async fn create_agent_ban_without_signing_key_records_ban_without_commands() {
        let (state, tenant_id, _agent_token) = setup_state("control_ban_no_key").await;
        insert_run_with_status(&state, &tenant_id, "run-live", "agent-mal", "running").await;

        let response = create_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(agent_ban_request("agent-mal")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let commands = state
            .storage
            .list_control_commands(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(
            commands.is_empty(),
            "no signing key ⇒ no command may be issued (never unsigned)"
        );
        assert!(state
            .storage
            .is_banned(&tenant_id, "agent", "agent-mal", Utc::now())
            .await
            .unwrap());
    }

    /// A non-agent ban (e.g. a destination) never touches runs.
    #[tokio::test]
    async fn create_non_agent_ban_issues_no_commands() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "control_ban_non_agent",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        insert_run_with_status(&state, &tenant_id, "run-live", "agent-mal", "running").await;

        let response = create_ban(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateBanRequest {
                target_type: "destination_domain".to_string(),
                target_value: "evil.example.com".to_string(),
                scope: "tenant".to_string(),
                reason: None,
                actor: "soc-analyst".to_string(),
                expires_at: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let commands = state
            .storage
            .list_control_commands(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(commands.is_empty());
    }

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
