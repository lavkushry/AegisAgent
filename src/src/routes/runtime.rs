//! Phase 2.6 (runtime control plane): HTTP routes wiring the runtime data-plane
//! storage (agent_runs, runtime_events) to the API. Every handler is
//! tenant-scoped via the `TenantId` extractor and delegates to the tenant-scoped
//! `StorageBackend` methods. Ingest is idempotent (dedup on `event_id`).
//!
//! Phase 4.3 (this file also covers): cage-run control routes
//! (pause/resume/kill/quarantine). Each issues a gateway-signed control
//! command targeting the run (reusing the Phase 2.3/2.7 `control_commands`
//! store and the exact signature scheme `aegis-node-sensor`'s
//! `CommandReceiver` already verifies) rather than mutating the run
//! directly — the sensor/cage that actually executes it is the only thing
//! that gets to change what's really running.

#![allow(unused_imports)]
use crate::error::StatusError;
use crate::sign;
use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::models::*;

use super::{parse_pagination, AppState, TenantId};

/// How long a gateway-issued control command remains valid before a sensor
/// must treat it as expired — matches the example in
/// `docs/AegisAgent_Control_Command_Protocol.md`.
const CONTROL_COMMAND_EXPIRY_SECS: i64 = 300;

/// `start_run` gets a longer expiry than pause/resume/kill/quarantine: a
/// brief window of runner unavailability shouldn't strand a freshly created
/// run the way it might a live-intervention command.
const START_RUN_COMMAND_EXPIRY_SECS: i64 = 3600;

/// Host paths that must never be reachable from inside a sandbox. Mirrors
/// `aegis_cage_runner::spec::FORBIDDEN_MOUNT_PATH_PREFIXES` exactly — this
/// gateway-side copy is deliberate duplication across the network boundary
/// (the gateway doesn't depend on the `aegis-cage-runner` crate), not
/// independent design; keep the two lists in sync.
const FORBIDDEN_MOUNT_PATH_PREFIXES: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/root/.ssh",
    "/root/.aws",
    "/root/.kube",
    "/root/.config/gcloud",
    "/home",
    "/etc/kubernetes",
];

/// Mirrors `aegis_cage_runner::spec::FORBIDDEN_ENV_NAME_SUBSTRINGS`.
const FORBIDDEN_ENV_NAME_SUBSTRINGS: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "TOKEN",
    "API_KEY",
];

/// Mirrors `aegis_cage_runner::spec::is_explicitly_allowed_env_name`.
fn is_explicitly_allowed_env_name(name: &str) -> bool {
    matches!(
        name,
        "AEGIS_RUN_ID" | "AEGIS_SANDBOX_ID" | "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY"
    )
}

fn default_cage_working_dir() -> String {
    "/workspace".to_string()
}

/// Nested request DTOs mirroring `aegis_cage_runner::spec::SandboxSpec`'s
/// shape — deliberately duplicated rather than depending on the
/// `aegis-cage-runner` crate, matching the existing network-boundary-
/// duplication convention (`aegis-node-sensor`'s `gateway_client.rs` DTOs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageResourceLimitsRequest {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub process_limit: u32,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub max_stdout_bytes: Option<u64>,
    #[serde(default)]
    pub max_stderr_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CageWorkspaceSpecRequest {
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub max_bytes: u64,
    #[serde(default)]
    pub max_files: u64,
    #[serde(default)]
    pub preserve_on_failure: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CageNetworkSpecRequest {
    #[serde(default)]
    pub direct_internet: bool,
    #[serde(default)]
    pub egress_proxy_url: Option<String>,
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CageToolingSpecRequest {
    #[serde(default)]
    pub tool_broker_url: Option<String>,
    #[serde(default)]
    pub mcp_gateway_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CageMountSourceType {
    GitSnapshot,
    Artifact,
    SecretlessConfig,
    Tmpfs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageControlledMountRequest {
    pub mount_id: String,
    pub source_type: CageMountSourceType,
    pub target_path: String,
    #[serde(default = "default_true_bool")]
    pub read_only: bool,
    pub reason: String,
    pub approved_by: String,
}

fn default_true_bool() -> bool {
    true
}

/// Present only when the caller wants the gateway-integrated
/// `aegis-cage-runner` to execute this run — as opposed to an
/// SDK-integrated / non-cage run, which leaves this `None` (the existing,
/// unaffected case: no signing-key requirement, no command issued, plain
/// insert).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageRunSpecRequest {
    pub image_ref: String,
    #[serde(default)]
    pub image_digest: Option<String>,
    pub command: Vec<String>,
    #[serde(default = "default_cage_working_dir")]
    pub working_dir: String,
    pub resources: CageResourceLimitsRequest,
    #[serde(default)]
    pub workspace: CageWorkspaceSpecRequest,
    #[serde(default)]
    pub network: CageNetworkSpecRequest,
    #[serde(default)]
    pub tooling: CageToolingSpecRequest,
    #[serde(default)]
    pub environment: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub controlled_mounts: Vec<CageControlledMountRequest>,
}

/// Mirrors `aegis_cage_runner::spec::SandboxSpec::validate()`'s checks —
/// fails closed, before any DB write. Kept in sync with that function by
/// convention (deliberate duplication across the network boundary), not by
/// a shared dependency.
fn validate_cage_spec(spec: &CageRunSpecRequest) -> Result<(), String> {
    if spec.image_ref.trim().is_empty() {
        return Err("cage_spec.image_ref must not be empty".to_string());
    }
    // Defense in depth alongside aegis-cage-runner's `--` end-of-options
    // marker in docker_cli.rs: a leading `-` would otherwise let a spec
    // masquerade as a docker CLI flag (e.g. "--privileged").
    if spec.image_ref.starts_with('-') {
        return Err("cage_spec.image_ref must not start with '-'".to_string());
    }
    if spec.command.is_empty() {
        return Err("cage_spec.command must not be empty".to_string());
    }
    if spec.resources.timeout_seconds == 0 {
        return Err("cage_spec.resources.timeout_seconds must be greater than zero".to_string());
    }
    if spec.network.direct_internet {
        return Err(
            "cage_spec.network.direct_internet must be false — all egress goes through the egress proxy"
                .to_string(),
        );
    }
    let proxy = spec
        .network
        .egress_proxy_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if !spec.network.allowed_destinations.is_empty() && proxy.is_none() {
        return Err(
            "cage_spec.network.allowed_destinations requires egress_proxy_url \
             (allowlists are enforced at the egress proxy)"
                .to_string(),
        );
    }
    if let Some(url) = proxy {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(
                "cage_spec.network.egress_proxy_url must be an http:// or https:// URL".to_string(),
            );
        }
        if url.contains(char::is_whitespace) {
            return Err(
                "cage_spec.network.egress_proxy_url must not contain whitespace".to_string(),
            );
        }
    } else if spec
        .network
        .egress_proxy_url
        .as_ref()
        .is_some_and(|s| s.trim().is_empty())
    {
        return Err("cage_spec.network.egress_proxy_url must not be empty when set".to_string());
    }
    for mount in &spec.controlled_mounts {
        for forbidden in FORBIDDEN_MOUNT_PATH_PREFIXES {
            if mount.target_path.starts_with(forbidden) {
                return Err(format!(
                    "controlled mount {:?} targets forbidden path {:?}",
                    mount.mount_id, mount.target_path
                ));
            }
        }
    }
    for name in spec.environment.keys() {
        if is_explicitly_allowed_env_name(name) {
            continue;
        }
        let upper = name.to_ascii_uppercase();
        for forbidden in FORBIDDEN_ENV_NAME_SUBSTRINGS {
            if upper.contains(forbidden) {
                return Err(format!(
                    "environment variable {name:?} looks like a raw credential and cannot be injected directly"
                ));
            }
        }
    }
    Ok(())
}

/// Body for `POST /v1/agent-cage/runs`. Server assigns `id`, `status`,
/// `started_at`, and `created_at`; the caller supplies the run identity/context.
#[derive(Debug, Deserialize)]
pub struct CreateAgentRunRequest {
    pub run_key: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub source_component: String,
    /// `observe` | `enforce` | `lockdown` (default `observe`).
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub root_trace_id: Option<String>,
    #[serde(default)]
    pub root_trust_level: Option<String>,
    /// See [`CageRunSpecRequest`]. `None` (default) leaves this call
    /// byte-for-byte identical to pre-cage-runner behavior.
    #[serde(default)]
    pub cage_spec: Option<CageRunSpecRequest>,
}

/// POST /v1/agent-cage/runs — register a controlled agent run. Tenant-scoped.
/// A duplicate `run_key` for the tenant is a 409 (idempotency anchor).
///
/// When `cage_spec` is set, this also fails closed (503) if no
/// `AEGIS_COMMAND_SIGNING_KEY` is configured, validates the nested spec,
/// and atomically inserts a signed `start_run` control command alongside
/// the run record (`insert_agent_run_with_start_command`) — a runner
/// discovers and claims the run via that command, never by polling
/// `agent_runs` directly. When `cage_spec` is `None` (the default,
/// pre-existing SDK-integrated-run case), none of that applies: no signing
/// key requirement, no command issued, plain insert — unchanged from
/// before this feature existed.
pub async fn create_agent_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<CreateAgentRunRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let run_id = Uuid::new_v4().to_string();

    let mut image_ref = None;
    let mut image_digest = None;
    let mut command_json = None;
    let mut working_dir = None;
    let mut resource_limits_json = None;
    let mut network_spec_json = None;
    let mut tooling_spec_json = None;
    let mut environment_json = None;
    let mut workspace_spec_json = None;
    let mut controlled_mounts_json = None;
    let mut start_command = None;

    if let Some(spec) = req.cage_spec.as_ref() {
        let signing_key_hex = match state.command_signing_key.as_deref() {
            Some(k) => k,
            None => {
                return StatusError::service_unavailable(
                    "gateway command signing key not configured; cannot start cage-executed runs",
                )
                .into_response();
            }
        };
        if let Err(e) = validate_cage_spec(spec) {
            return StatusError::bad_request(e).into_response();
        }
        let signer = match sign::CommandSigner::from_env_value(signing_key_hex) {
            Ok(s) => s,
            Err(e) => {
                error!("AEGIS_COMMAND_SIGNING_KEY is set but invalid: {e}");
                return StatusError::service_unavailable(
                    "gateway command signing key is misconfigured; cannot start cage-executed runs",
                )
                .into_response();
            }
        };

        image_ref = Some(spec.image_ref.clone());
        image_digest = spec.image_digest.clone();
        command_json = serde_json::to_string(&spec.command).ok();
        working_dir = Some(spec.working_dir.clone());
        resource_limits_json = serde_json::to_string(&spec.resources).ok();
        network_spec_json = serde_json::to_string(&spec.network).ok();
        tooling_spec_json = serde_json::to_string(&spec.tooling).ok();
        environment_json = serde_json::to_string(&spec.environment).ok();
        workspace_spec_json = serde_json::to_string(&spec.workspace).ok();
        controlled_mounts_json = serde_json::to_string(&spec.controlled_mounts).ok();

        let mut command = ControlCommandRecord {
            command_id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            target_type: "run".to_string(),
            target_id: run_id.clone(),
            action: "start_run".to_string(),
            reason: None,
            issued_by: "gateway".to_string(),
            issued_at: now,
            expires_at: now + Duration::seconds(START_RUN_COMMAND_EXPIRY_SECS),
            nonce: Uuid::new_v4().to_string(),
            requires_ack: true,
            receipt_required: false,
            signature: String::new(),
            status: "issued".to_string(),
            created_at: now,
        };
        command.signature = signer.sign(&sign::canonical_command_bytes(&command));
        start_command = Some(command);
    }

    let record = AgentRunRecord {
        id: run_id,
        tenant_id: tenant_id.clone(),
        agent_id: req.agent_id,
        run_key: req.run_key,
        source_component: req.source_component,
        mode: req.mode.unwrap_or_else(|| "observe".to_string()),
        status: "started".to_string(),
        started_at: now,
        finished_at: None,
        root_trace_id: req.root_trace_id,
        root_trust_level: req.root_trust_level,
        policy_bundle_id: None,
        claimed_by: None,
        claimed_at: None,
        last_heartbeat_at: None,
        image_ref,
        image_digest,
        command_json,
        working_dir,
        resource_limits_json,
        network_spec_json,
        tooling_spec_json,
        environment_json,
        workspace_spec_json,
        controlled_mounts_json,
        created_at: now,
    };
    match state
        .storage
        .insert_agent_run_with_start_command(&record, start_command.as_ref())
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => {
            // A duplicate (tenant, run_key) trips the unique index.
            error!("Failed to create agent run: {:?}", e);
            StatusError::conflict("agent run already exists for this run_key").into_response()
        }
    }
}

/// Body for `POST /v1/agent-cage/runs/:id/{claim,heartbeat}`.
#[derive(Debug, Deserialize)]
pub struct RunnerIdRequest {
    pub runner_id: String,
}

/// POST /v1/agent-cage/runs/:id/claim — atomically claim a cage run
/// (`started` -> `claimed`). `409` if the run is already claimed (or in any
/// other non-`started` state) or has no `cage_spec` to execute; `404` if it
/// doesn't exist for this tenant.
pub async fn claim_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    Json(req): Json<RunnerIdRequest>,
) -> impl IntoResponse {
    match state
        .storage
        .claim_agent_run(&tenant_id, &run_id, &req.runner_id, Utc::now())
        .await
    {
        Ok(true) => match state.storage.get_agent_run(&tenant_id, &run_id).await {
            Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
            Ok(None) => StatusError::not_found("agent run not found").into_response(),
            Err(e) => {
                error!("Failed to fetch claimed agent run: {:?}", e);
                StatusError::internal("Database error").into_response()
            }
        },
        Ok(false) => match state.storage.get_agent_run(&tenant_id, &run_id).await {
            Ok(Some(_)) => StatusError::conflict(
                "run is not claimable (already claimed, not started, or has no cage_spec)",
            )
            .into_response(),
            Ok(None) => StatusError::not_found("agent run not found").into_response(),
            Err(e) => {
                error!("Failed to check agent run after failed claim: {:?}", e);
                StatusError::internal("Database error").into_response()
            }
        },
        Err(e) => {
            error!("Failed to claim agent run: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// POST /v1/agent-cage/runs/:id/heartbeat — refresh the claiming runner's
/// lease. `409` if the caller no longer holds the claim (lost to a
/// stall-sweep reclaim, never held it, or the run has reached a terminal
/// status).
pub async fn heartbeat_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    Json(req): Json<RunnerIdRequest>,
) -> impl IntoResponse {
    match state
        .storage
        .heartbeat_agent_run(&tenant_id, &run_id, &req.runner_id, Utc::now())
        .await
    {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => {
            StatusError::conflict("caller does not hold the claim on this run").into_response()
        }
        Err(e) => {
            error!("Failed to heartbeat agent run: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Statuses a runner is allowed to self-report via `POST .../status`.
/// `quarantined` is deliberately excluded — that transition is
/// gateway-authoritative only (see `quarantine_run`).
const RUNNER_REPORTABLE_STATUSES: &[&str] = &["running", "paused", "finished", "killed", "stalled"];

/// Body for `POST /v1/agent-cage/runs/:id/status`.
#[derive(Debug, Deserialize)]
pub struct UpdateRunStatusRequest {
    pub runner_id: String,
    pub status: String,
    #[serde(default)]
    pub finished_at: Option<chrono::DateTime<Utc>>,
}

/// POST /v1/agent-cage/runs/:id/status — the claiming runner reports a
/// status transition. `400` for a status value this endpoint doesn't
/// accept; `409` if the caller no longer holds the claim.
pub async fn update_run_status(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    Json(req): Json<UpdateRunStatusRequest>,
) -> impl IntoResponse {
    if !RUNNER_REPORTABLE_STATUSES.contains(&req.status.as_str()) {
        return StatusError::bad_request(format!(
            "status must be one of {RUNNER_REPORTABLE_STATUSES:?}"
        ))
        .into_response();
    }
    match state
        .storage
        .update_claimed_agent_run_status(
            &tenant_id,
            &run_id,
            &req.runner_id,
            &req.status,
            req.finished_at,
        )
        .await
    {
        Ok(true) => match state.storage.get_agent_run(&tenant_id, &run_id).await {
            Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
            Ok(None) => StatusError::not_found("agent run not found").into_response(),
            Err(e) => {
                error!("Failed to fetch agent run after status update: {:?}", e);
                StatusError::internal("Database error").into_response()
            }
        },
        Ok(false) => {
            StatusError::conflict("caller does not hold the claim on this run").into_response()
        }
        Err(e) => {
            error!("Failed to update agent run status: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/agent-cage/runs/:id — fetch one run. Tenant-scoped (404 cross-tenant).
pub async fn get_agent_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_agent_run(&tenant_id, &run_id).await {
        Ok(Some(r)) => (StatusCode::OK, Json(r)).into_response(),
        Ok(None) => StatusError::not_found("agent run not found").into_response(),
        Err(e) => {
            error!("Failed to get agent run: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/agent-cage/runs — list the tenant's runs (paginated). Tenant-scoped.
pub async fn list_agent_runs(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    match state
        .storage
        .list_agent_runs(&tenant_id, limit, offset)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list agent runs: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/ingest/runtime-events`. Producer-supplied envelope; server
/// assigns the internal row `id` and stamps `received_at`. Carries
/// hashes/identifiers only — never raw prompts/secrets/payloads.
#[derive(Debug, Deserialize)]
pub struct IngestRuntimeEventRequest {
    pub event_id: String,
    pub event_type: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub parent_event_id: Option<String>,
    pub source_component: String,
    #[serde(default)]
    pub source_trust: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub action_hash: Option<String>,
    #[serde(default)]
    pub prompt_hash: Option<String>,
    #[serde(default)]
    pub request_hash: Option<String>,
    #[serde(default)]
    pub response_hash: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub receipt_hash: Option<String>,
    #[serde(default)]
    pub prev_receipt_hash: Option<String>,
    #[serde(default)]
    pub canonical_version: Option<String>,
    #[serde(default)]
    pub redaction_status: Option<String>,
    /// RFC-3339; defaults to now if omitted.
    #[serde(default)]
    pub observed_at: Option<chrono::DateTime<Utc>>,
}

/// POST /v1/ingest/runtime-events — idempotent ingest of a single runtime event.
/// Tenant-scoped. Returns `{ "ingested": bool }` — `false` means the
/// `(tenant, event_id)` was already recorded (a retried/replayed event).
pub async fn ingest_runtime_event(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<IngestRuntimeEventRequest>,
) -> impl IntoResponse {
    let now = Utc::now();
    let record = RuntimeEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        event_id: req.event_id,
        event_type: req.event_type,
        severity: req.severity,
        agent_id: req.agent_id,
        run_id: req.run_id,
        sandbox_id: req.sandbox_id,
        trace_id: req.trace_id,
        parent_event_id: req.parent_event_id,
        source_component: req.source_component,
        source_trust: req.source_trust,
        decision: req.decision,
        reason: req.reason,
        action_hash: req.action_hash,
        prompt_hash: req.prompt_hash,
        request_hash: req.request_hash,
        response_hash: req.response_hash,
        receipt_id: req.receipt_id,
        receipt_hash: req.receipt_hash,
        prev_receipt_hash: req.prev_receipt_hash,
        canonical_version: req.canonical_version,
        redaction_status: req.redaction_status,
        schema_version: 1,
        observed_at: req.observed_at.unwrap_or(now),
        received_at: now,
    };
    match state.storage.insert_runtime_event(&record).await {
        Ok(ingested) => (StatusCode::OK, Json(json!({ "ingested": ingested }))).into_response(),
        Err(e) => {
            error!("Failed to ingest runtime event: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/runtime/runs/:id/events — the runtime-event timeline for one run,
/// oldest-first. Tenant-scoped.
pub async fn list_run_events(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, _offset) = parse_pagination(raw_query.as_deref());
    match state
        .storage
        .list_runtime_events_for_run(&tenant_id, &run_id, limit)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list run events: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/agent-cage/runs/:id/{pause,resume,kill,quarantine}`.
#[derive(Debug, Deserialize)]
pub struct RunControlRequest {
    pub actor: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Build, sign, and persist a control command targeting `run_id`. Fails
/// closed if no `AEGIS_COMMAND_SIGNING_KEY` is configured — the gateway
/// never issues a command it knows a sensor can't verify. 404s if the run
/// doesn't exist for this tenant.
async fn issue_run_control_command(
    state: &AppState,
    tenant_id: &str,
    run_id: &str,
    action: &str,
    req: &RunControlRequest,
) -> Result<ControlCommandRecord, StatusError> {
    match state.storage.get_agent_run(tenant_id, run_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(StatusError::not_found("agent run not found")),
        Err(e) => {
            error!("Failed to fetch agent run for control command: {:?}", e);
            return Err(StatusError::internal("Database error"));
        }
    }

    let signing_key_hex = state.command_signing_key.as_deref().ok_or_else(|| {
        StatusError::service_unavailable(
            "gateway command signing key not configured; cannot issue control commands",
        )
    })?;
    let signer = sign::CommandSigner::from_env_value(signing_key_hex).map_err(|e| {
        error!("AEGIS_COMMAND_SIGNING_KEY is set but invalid: {e}");
        StatusError::service_unavailable(
            "gateway command signing key is misconfigured; cannot issue control commands",
        )
    })?;

    let now = Utc::now();
    let mut record = ControlCommandRecord {
        command_id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        target_type: "run".to_string(),
        target_id: run_id.to_string(),
        action: action.to_string(),
        reason: req.reason.clone(),
        issued_by: req.actor.clone(),
        issued_at: now,
        expires_at: now + Duration::seconds(CONTROL_COMMAND_EXPIRY_SECS),
        nonce: Uuid::new_v4().to_string(),
        requires_ack: true,
        receipt_required: true,
        signature: String::new(),
        status: "issued".to_string(),
        created_at: now,
    };
    record.signature = signer.sign(&sign::canonical_command_bytes(&record));

    state
        .storage
        .insert_control_command(&record)
        .await
        .map_err(|e| {
            error!("Failed to persist control command: {:?}", e);
            StatusError::internal("Database error")
        })?;
    Ok(record)
}

/// POST /v1/agent-cage/runs/:id/pause
pub async fn pause_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    Json(req): Json<RunControlRequest>,
) -> impl IntoResponse {
    match issue_run_control_command(&state, &tenant_id, &run_id, "pause_run", &req).await {
        Ok(record) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// POST /v1/agent-cage/runs/:id/resume
pub async fn resume_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    Json(req): Json<RunControlRequest>,
) -> impl IntoResponse {
    match issue_run_control_command(&state, &tenant_id, &run_id, "resume_run", &req).await {
        Ok(record) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// POST /v1/agent-cage/runs/:id/kill
pub async fn kill_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    Json(req): Json<RunControlRequest>,
) -> impl IntoResponse {
    match issue_run_control_command(&state, &tenant_id, &run_id, "kill_run", &req).await {
        Ok(record) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// POST /v1/agent-cage/runs/:id/quarantine — issues a `quarantine_run`
/// signed command AND records a `quarantine_records` row (Phase 2.5/2.7),
/// so the run is both instructed to freeze evidence and durably marked
/// quarantined even if the sensor never manages to ACK.
pub async fn quarantine_run(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(run_id): Path<String>,
    Json(req): Json<RunControlRequest>,
) -> impl IntoResponse {
    let command = match issue_run_control_command(
        &state,
        &tenant_id,
        &run_id,
        "quarantine_run",
        &req,
    )
    .await
    {
        Ok(record) => record,
        Err(e) => return e.into_response(),
    };

    let now = Utc::now();
    let quarantine = QuarantineRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        target_type: "run".to_string(),
        target_value: run_id.clone(),
        reason: req.reason.clone(),
        actor: req.actor.clone(),
        status: "active".to_string(),
        incident_id: None,
        created_at: now,
        released_at: None,
        released_by: None,
    };
    if let Err(e) = state.storage.insert_quarantine(&quarantine).await {
        error!("Failed to record quarantine for run: {:?}", e);
        return StatusError::internal("Database error").into_response();
    }

    // Gateway-authoritative: quarantine must land in agent_runs.status even
    // if no runner ever cooperates (unlike pause/resume/kill, which only
    // become true once the runner itself reports back via
    // update_claimed_agent_run_status — see update_run_status). Not
    // ownership-scoped by claimed_by on purpose.
    if let Err(e) = state
        .storage
        .update_agent_run_status(&tenant_id, &run_id, "quarantined", None)
        .await
    {
        error!("Failed to mark agent run quarantined: {:?}", e);
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "control_command": command,
            "quarantine_record": quarantine,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::{
        register_tenant_helper, setup_state, setup_state_with_command_signing_key,
    };
    use axum::body::to_bytes;
    use axum::extract::RawQuery;

    #[tokio::test]
    async fn create_agent_run_then_get_and_list_round_trip() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_create_run").await;

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateAgentRunRequest {
                run_key: "run-abc".to_string(),
                agent_id: Some("agent-1".to_string()),
                source_component: "sdk".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
                cage_spec: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(created.run_key, "run-abc");
        assert_eq!(created.mode, "observe");
        assert_eq!(created.status, "started");

        let response = get_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let fetched: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched.id, created.id);

        let response = list_agent_runs(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<AgentRunRecord> = serde_json::from_slice(&body).unwrap();
        assert!(rows.iter().any(|r| r.id == created.id));
    }

    #[tokio::test]
    async fn create_agent_run_rejects_duplicate_run_key() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_dup_run_key").await;
        let req = || CreateAgentRunRequest {
            run_key: "dup-key".to_string(),
            agent_id: None,
            source_component: "sdk".to_string(),
            mode: None,
            root_trace_id: None,
            root_trust_level: None,
            cage_spec: None,
        };

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(req()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(req()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn get_agent_run_is_tenant_scoped() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_run_tenant_scope").await;
        let other_tenant_id = "tenant_runtime_other".to_string();
        register_tenant_helper(
            state.storage.as_ref(),
            &other_tenant_id,
            "Other",
            "developer",
        )
        .await;

        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateAgentRunRequest {
                run_key: "scoped-run".to_string(),
                agent_id: None,
                source_component: "sdk".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
                cage_spec: None,
            }),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let created: AgentRunRecord = serde_json::from_slice(&body).unwrap();

        let response = get_agent_run(
            State(state.clone()),
            TenantId(other_tenant_id),
            Path(created.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn sample_ingest_request(event_id: &str) -> IngestRuntimeEventRequest {
        IngestRuntimeEventRequest {
            event_id: event_id.to_string(),
            event_type: "tool_call".to_string(),
            severity: Some("info".to_string()),
            agent_id: None,
            run_id: None,
            sandbox_id: None,
            trace_id: None,
            parent_event_id: None,
            source_component: "sdk".to_string(),
            source_trust: None,
            decision: Some("allow".to_string()),
            reason: None,
            action_hash: None,
            prompt_hash: None,
            request_hash: None,
            response_hash: None,
            receipt_id: None,
            receipt_hash: None,
            prev_receipt_hash: None,
            canonical_version: None,
            redaction_status: None,
            observed_at: None,
        }
    }

    #[tokio::test]
    async fn ingest_runtime_event_dedupes_by_event_id() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_ingest_dedup").await;

        let response = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_ingest_request("evt-1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ingested"].as_bool(), Some(true));

        let response = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_ingest_request("evt-1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ingested"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn list_run_events_returns_only_events_for_that_run() {
        let (state, tenant_id, _agent_token) = setup_state("runtime_list_run_events").await;

        let mut ev_a = sample_ingest_request("evt-a");
        ev_a.run_id = Some("run-a".to_string());
        let mut ev_b = sample_ingest_request("evt-b");
        ev_b.run_id = Some("run-b".to_string());

        let _ = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(ev_a),
        )
        .await
        .into_response();
        let _ = ingest_runtime_event(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(ev_b),
        )
        .await
        .into_response();

        let response = list_run_events(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("run-a".to_string()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<RuntimeEventRecord> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "evt-a");
    }

    // Fixed 32-byte test secret (hex, bytes 0x01..0x20) — deterministic,
    // test-only material, not a real key. Matches the convention used for
    // receipt-signing tests (see routes/receipts.rs).
    const TEST_COMMAND_SIGNING_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    async fn create_run(state: &Arc<AppState>, tenant_id: &str, run_key: &str) -> AgentRunRecord {
        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.to_string()),
            Json(CreateAgentRunRequest {
                run_key: run_key.to_string(),
                agent_id: None,
                source_component: "sdk".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
                cage_spec: None,
            }),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn anonymous_run_start_has_no_agent_id() {
        let (state, tenant_id, _agent_token) = setup_state("cage_anon_run_start").await;
        let run = create_run(&state, &tenant_id, "run-anon-1").await;
        assert!(run.agent_id.is_none());
        assert_eq!(run.status, "started");
    }

    #[tokio::test]
    async fn control_routes_fail_closed_without_a_signing_key() {
        let (state, tenant_id, _agent_token) = setup_state("cage_control_no_key").await;
        let run = create_run(&state, &tenant_id, "run-no-key").await;

        let response = kill_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunControlRequest {
                actor: "soc-analyst".to_string(),
                reason: Some("suspicious activity".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn kill_run_issues_a_verifiable_signed_command() {
        let (state, tenant_id, _agent_token) =
            setup_state_with_command_signing_key("cage_kill_run", TEST_COMMAND_SIGNING_SECRET_HEX)
                .await;
        let run = create_run(&state, &tenant_id, "run-kill-1").await;

        let response = kill_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunControlRequest {
                actor: "soc-analyst".to_string(),
                reason: Some("suspicious activity".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let command: ControlCommandRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(command.action, "kill_run");
        assert_eq!(command.target_type, "run");
        assert_eq!(command.target_id, run.id);
        assert_eq!(command.status, "issued");

        // A sensor/cage mock verifies the exact same way
        // aegis-node-sensor's CommandReceiver does: signature over
        // canonical_command_bytes, checked against the signer's public key.
        let signer = sign::CommandSigner::from_secret_hex(TEST_COMMAND_SIGNING_SECRET_HEX).unwrap();
        let sig_bytes = hex::decode(&command.signature).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let pk_bytes = hex::decode(signer.public_key_hex()).unwrap();
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).unwrap();
        use ed25519_dalek::Verifier;
        assert!(verifying_key
            .verify_strict(&sign::canonical_command_bytes(&command), &signature)
            .is_ok());
    }

    #[tokio::test]
    async fn pause_and_resume_run_issue_signed_commands() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_pause_resume_run",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_run(&state, &tenant_id, "run-pause-1").await;
        let req = || RunControlRequest {
            actor: "operator".to_string(),
            reason: None,
        };

        let response = pause_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(req()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let command: ControlCommandRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(command.action, "pause_run");

        let response = resume_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(req()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let command: ControlCommandRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(command.action, "resume_run");
    }

    #[tokio::test]
    async fn control_routes_404_for_an_unknown_run() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_control_unknown_run",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;

        let response = kill_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("does-not-exist".to_string()),
            Json(RunControlRequest {
                actor: "operator".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn quarantine_run_creates_control_command_and_quarantine_record() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_quarantine_run",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_run(&state, &tenant_id, "run-quarantine-1").await;

        let response = quarantine_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunControlRequest {
                actor: "soc-analyst".to_string(),
                reason: Some("secret exfil detected".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["control_command"]["action"], "quarantine_run");
        assert_eq!(json["quarantine_record"]["target_type"], "run");
        assert_eq!(json["quarantine_record"]["target_value"], run.id);
        assert_eq!(json["quarantine_record"]["status"], "active");

        // The quarantine record is independently durable — verify it via
        // storage directly, not just the response body.
        let records = state
            .storage
            .list_quarantine(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(records.iter().any(|r| r.target_value == run.id));
    }

    #[tokio::test]
    async fn quarantine_run_also_flips_agent_run_status_to_quarantined() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_quarantine_status",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_run(&state, &tenant_id, "run-quarantine-status-1").await;

        let response = quarantine_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunControlRequest {
                actor: "soc-analyst".to_string(),
                reason: Some("secret exfil detected".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        let updated = state
            .storage
            .get_agent_run(&tenant_id, &run.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, "quarantined");
    }

    fn sample_cage_spec() -> CageRunSpecRequest {
        CageRunSpecRequest {
            image_ref: "alpine:latest".to_string(),
            image_digest: None,
            command: vec!["sleep".to_string(), "5".to_string()],
            working_dir: "/workspace".to_string(),
            resources: CageResourceLimitsRequest {
                cpu_millis: 500,
                memory_bytes: 268_435_456,
                process_limit: 32,
                timeout_seconds: 60,
                max_stdout_bytes: None,
                max_stderr_bytes: None,
            },
            workspace: CageWorkspaceSpecRequest::default(),
            network: CageNetworkSpecRequest::default(),
            tooling: CageToolingSpecRequest::default(),
            environment: std::collections::HashMap::new(),
            controlled_mounts: Vec::new(),
        }
    }

    async fn create_cage_run(
        state: &Arc<AppState>,
        tenant_id: &str,
        run_key: &str,
    ) -> AgentRunRecord {
        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.to_string()),
            Json(CreateAgentRunRequest {
                run_key: run_key.to_string(),
                agent_id: None,
                source_component: "cage-runner".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
                cage_spec: Some(sample_cage_spec()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn create_agent_run_with_cage_spec_requires_a_signing_key() {
        let (state, tenant_id, _agent_token) = setup_state("cage_spec_no_key").await;
        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateAgentRunRequest {
                run_key: "run-cage-no-key".to_string(),
                agent_id: None,
                source_component: "cage-runner".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
                cage_spec: Some(sample_cage_spec()),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Nothing must have been written.
        let list = state
            .storage
            .list_agent_runs(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn create_agent_run_with_cage_spec_issues_a_verifiable_start_run_command() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_spec_signed_command",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_cage_run(&state, &tenant_id, "run-cage-signed").await;
        assert_eq!(run.status, "started");
        assert_eq!(run.image_ref.as_deref(), Some("alpine:latest"));

        let commands = state
            .storage
            .list_control_commands(&tenant_id, 50, 0)
            .await
            .unwrap();
        let start_command = commands
            .iter()
            .find(|c| c.target_id == run.id && c.action == "start_run")
            .expect("a start_run command must have been issued");
        assert_eq!(start_command.target_type, "run");
        assert_eq!(start_command.status, "issued");

        let signer = sign::CommandSigner::from_secret_hex(TEST_COMMAND_SIGNING_SECRET_HEX).unwrap();
        let sig_bytes = hex::decode(&start_command.signature).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let pk_bytes = hex::decode(signer.public_key_hex()).unwrap();
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).unwrap();
        use ed25519_dalek::Verifier;
        assert!(verifying_key
            .verify_strict(&sign::canonical_command_bytes(start_command), &signature)
            .is_ok());
    }

    #[tokio::test]
    async fn create_agent_run_rejects_a_cage_spec_image_ref_starting_with_dash() {
        // Regression test for the argument-injection finding from the
        // cage-runner execution-loop security review: an `image_ref` like
        // "--privileged" must never reach the runner, since without a `--`
        // end-of-options marker it would be parsed as a docker CLI flag
        // instead of an image name.
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_spec_dash_image_ref",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let mut spec = sample_cage_spec();
        spec.image_ref = "--privileged".to_string();
        let response = create_agent_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateAgentRunRequest {
                run_key: "run-cage-dash-image-ref".to_string(),
                agent_id: None,
                source_component: "cage-runner".to_string(),
                mode: None,
                root_trace_id: None,
                root_trust_level: None,
                cage_spec: Some(spec),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let commands = state
            .storage
            .list_control_commands(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(
            commands.is_empty(),
            "no command should be issued for a rejected cage_spec"
        );
    }

    #[tokio::test]
    async fn create_agent_run_without_cage_spec_is_unchanged() {
        // Explicit regression pin: no signing key configured, yet a plain
        // (non-cage) run must still succeed exactly like before this
        // feature existed.
        let (state, tenant_id, _agent_token) = setup_state("cage_spec_regression").await;
        let run = create_run(&state, &tenant_id, "run-no-cage-spec").await;
        assert_eq!(run.status, "started");
        assert!(run.image_ref.is_none());

        let commands = state
            .storage
            .list_control_commands(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(
            commands.iter().all(|c| c.target_id != run.id),
            "no command should ever be issued for a non-cage run"
        );
    }

    #[tokio::test]
    async fn claim_run_then_second_claim_attempt_gets_conflict() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_claim_conflict",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_cage_run(&state, &tenant_id, "run-claim-conflict").await;

        let response = claim_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: "runner-1".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let claimed: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(claimed.status, "claimed");
        assert_eq!(claimed.claimed_by.as_deref(), Some("runner-1"));

        let response2 = claim_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: "runner-2".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response2.status(), StatusCode::CONFLICT);
    }

    /// Smoke: create (with signed start_run) → claim → heartbeat → status running → finished.
    /// Mirrors the gateway side of `aegis-cage-runner` without invoking Docker.
    #[tokio::test]
    async fn cage_run_lifecycle_create_claim_heartbeat_status() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_lifecycle_smoke",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_cage_run(&state, &tenant_id, "run-lifecycle-smoke").await;
        assert_eq!(run.status, "started");
        assert!(run.image_ref.is_some());

        let commands = state
            .storage
            .list_control_commands(&tenant_id, 50, 0)
            .await
            .unwrap();
        assert!(
            commands
                .iter()
                .any(|c| c.target_id == run.id && c.action == "start_run" && c.status == "issued"),
            "start_run command must be issued for cage_spec runs"
        );

        let runner = "smoke-runner-1";
        let response = claim_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: runner.to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let claimed: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(claimed.status, "claimed");
        assert_eq!(claimed.claimed_by.as_deref(), Some(runner));

        let hb = heartbeat_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: runner.to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(hb.status(), StatusCode::OK);

        let running = update_run_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(UpdateRunStatusRequest {
                runner_id: runner.to_string(),
                status: "running".to_string(),
                finished_at: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(running.status(), StatusCode::OK);
        let body = to_bytes(running.into_body(), usize::MAX).await.unwrap();
        let running_rec: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(running_rec.status, "running");

        let finished = update_run_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(UpdateRunStatusRequest {
                runner_id: runner.to_string(),
                status: "finished".to_string(),
                finished_at: Some(Utc::now()),
            }),
        )
        .await
        .into_response();
        assert_eq!(finished.status(), StatusCode::OK);
        let body = to_bytes(finished.into_body(), usize::MAX).await.unwrap();
        let done: AgentRunRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(done.status, "finished");
        assert!(done.finished_at.is_some());
    }

    #[tokio::test]
    async fn claim_run_404s_for_an_unknown_run() {
        let (state, tenant_id, _agent_token) = setup_state("cage_claim_unknown").await;
        let response = claim_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("does-not-exist".to_string()),
            Json(RunnerIdRequest {
                runner_id: "runner-1".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn heartbeat_and_status_routes_reject_a_non_claimant_runner_id() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_heartbeat_status_non_claimant",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_cage_run(&state, &tenant_id, "run-heartbeat-status").await;
        let _ = claim_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: "runner-1".to_string(),
            }),
        )
        .await;

        let hb_response = heartbeat_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: "runner-2".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(hb_response.status(), StatusCode::CONFLICT);

        let status_response = update_run_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(UpdateRunStatusRequest {
                runner_id: "runner-2".to_string(),
                status: "running".to_string(),
                finished_at: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(status_response.status(), StatusCode::CONFLICT);

        // The rightful claimant still succeeds.
        let hb_ok = heartbeat_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: "runner-1".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(hb_ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_route_rejects_an_invalid_status_value() {
        let (state, tenant_id, _agent_token) = setup_state_with_command_signing_key(
            "cage_status_invalid_value",
            TEST_COMMAND_SIGNING_SECRET_HEX,
        )
        .await;
        let run = create_cage_run(&state, &tenant_id, "run-status-invalid").await;
        let _ = claim_run(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(RunnerIdRequest {
                runner_id: "runner-1".to_string(),
            }),
        )
        .await;

        let response = update_run_status(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(run.id.clone()),
            Json(UpdateRunStatusRequest {
                runner_id: "runner-1".to_string(),
                status: "quarantined".to_string(),
                finished_at: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
