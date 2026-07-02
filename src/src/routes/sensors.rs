//! Phase 3.2 (Agent Cage): `aegis-node-sensor` registration + heartbeat
//! routes. Wires the Phase 3.2 storage (`sensors`) to the API. Tenant-scoped
//! via the same `TenantId` bearer-auth extractor every other route uses — a
//! sensor authenticates with a tenant-scoped credential like any other API
//! client, not a special sensor-only mechanism.

#![allow(unused_imports)]
use crate::error::StatusError;
use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tracing::error;

use crate::models::*;

use super::{parse_pagination, AppState, TenantId};

/// Fixed for now — dynamic per-tenant sensor config lands with a later phase.
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Body for `POST /v1/sensors/register`. `node_key` is the sensor's own
/// stable per-host identifier — re-registering with the same `node_key`
/// updates the existing sensor row rather than creating a duplicate.
#[derive(Debug, Deserialize)]
pub struct RegisterSensorRequest {
    pub node_key: String,
    pub hostname: String,
    #[serde(default)]
    pub environment: Option<String>,
    pub sensor_version: String,
    /// Hex-encoded Ed25519 public key — never a secret.
    pub public_key: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// `observe` | `enforce` | `lockdown` (default `observe`).
    #[serde(default)]
    pub mode: Option<String>,
}

fn is_valid_mode(mode: &str) -> bool {
    matches!(mode, "observe" | "enforce" | "lockdown")
}

/// POST /v1/sensors/register — register (or re-register) a sensor.
/// Tenant-scoped.
pub async fn register_sensor(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<RegisterSensorRequest>,
) -> impl IntoResponse {
    let mode = req.mode.unwrap_or_else(|| "observe".to_string());
    if !is_valid_mode(&mode) {
        return StatusError::bad_request("mode must be observe, enforce, or lockdown")
            .into_response();
    }
    let capabilities_json = match serde_json::to_string(&req.capabilities) {
        Ok(s) => s,
        Err(_) => return StatusError::bad_request("invalid capabilities").into_response(),
    };

    let now = Utc::now();
    let sensor_id = match state
        .storage
        .upsert_sensor(
            &tenant_id,
            &req.node_key,
            &req.hostname,
            req.environment.as_deref(),
            &req.sensor_version,
            &req.public_key,
            &capabilities_json,
            &mode,
            now,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to register sensor: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    match state.storage.get_sensor(&tenant_id, &sensor_id).await {
        Ok(Some(sensor)) => (
            StatusCode::CREATED,
            Json(json!({
                "sensor_id": sensor.id,
                "mode": sensor.mode,
                "config_version": sensor.config_version,
                "heartbeat_interval_secs": DEFAULT_HEARTBEAT_INTERVAL_SECS,
            })),
        )
            .into_response(),
        Ok(None) => {
            StatusError::internal("sensor vanished immediately after registration").into_response()
        }
        Err(e) => {
            error!("Failed to fetch sensor after registration: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/sensors/:id — fetch one sensor. Tenant-scoped (404 cross-tenant).
pub async fn get_sensor(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(sensor_id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_sensor(&tenant_id, &sensor_id).await {
        Ok(Some(sensor)) => (StatusCode::OK, Json(sensor)).into_response(),
        Ok(None) => StatusError::not_found("sensor not found").into_response(),
        Err(e) => {
            error!("Failed to get sensor: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// GET /v1/sensors — list the tenant's sensors (paginated).
pub async fn list_sensors(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    RawQuery(raw_query): RawQuery,
) -> impl IntoResponse {
    let (limit, offset) = parse_pagination(raw_query.as_deref());
    match state.storage.list_sensors(&tenant_id, limit, offset).await {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => {
            error!("Failed to list sensors: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

/// Body for `POST /v1/sensors/:id/heartbeat`.
#[derive(Debug, Deserialize)]
pub struct SensorHeartbeatRequest {
    /// `observe` | `enforce` | `lockdown`.
    pub mode: String,
    pub sensor_version: String,
    #[serde(default)]
    pub queue_depth_critical: Option<i64>,
    #[serde(default)]
    pub queue_depth_normal: Option<i64>,
    #[serde(default)]
    pub disk_usage_bytes: Option<i64>,
    #[serde(default)]
    pub active_cage_runs: Option<i64>,
    #[serde(default)]
    pub last_event_watermark: Option<String>,
    #[serde(default)]
    pub last_command_watermark: Option<String>,
    #[serde(default)]
    pub health_status: Option<String>,
}

/// POST /v1/sensors/:id/heartbeat — apply a heartbeat. Tenant-scoped; 404 on
/// an unknown or cross-tenant sensor id (the sensor should re-register).
pub async fn sensor_heartbeat(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(sensor_id): Path<String>,
    Json(req): Json<SensorHeartbeatRequest>,
) -> impl IntoResponse {
    if !is_valid_mode(&req.mode) {
        return StatusError::bad_request("mode must be observe, enforce, or lockdown")
            .into_response();
    }

    let now = Utc::now();
    let updated = match state
        .storage
        .heartbeat_sensor(
            &tenant_id,
            &sensor_id,
            &req.mode,
            &req.sensor_version,
            req.queue_depth_critical,
            req.queue_depth_normal,
            req.disk_usage_bytes,
            req.active_cage_runs,
            req.last_event_watermark.as_deref(),
            req.last_command_watermark.as_deref(),
            req.health_status.as_deref(),
            now,
        )
        .await
    {
        Ok(updated) => updated,
        Err(e) => {
            error!("Failed to apply sensor heartbeat: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    if !updated {
        return StatusError::not_found("sensor not found").into_response();
    }

    match state.storage.get_sensor(&tenant_id, &sensor_id).await {
        Ok(Some(sensor)) => (StatusCode::OK, Json(sensor)).into_response(),
        Ok(None) => StatusError::not_found("sensor not found").into_response(),
        Err(e) => {
            error!("Failed to re-fetch sensor after heartbeat: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;
    use axum::body::to_bytes;

    fn sample_register_request(node_key: &str) -> RegisterSensorRequest {
        RegisterSensorRequest {
            node_key: node_key.to_string(),
            hostname: "host-a".to_string(),
            environment: Some("production".to_string()),
            sensor_version: "0.1.0".to_string(),
            public_key: "deadbeef".to_string(),
            capabilities: vec!["cage_runner".to_string()],
            mode: None,
        }
    }

    #[tokio::test]
    async fn register_then_get_and_list_round_trip() {
        let (state, tenant_id, _agent_token) = setup_state("sensor_register_route").await;

        let response = register_sensor(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_register_request("node-1")),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let sensor_id = json["sensor_id"].as_str().unwrap().to_string();
        assert_eq!(json["mode"].as_str(), Some("observe"));

        let response = get_sensor(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(sensor_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let sensor: SensorRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(sensor.hostname, "host-a");
        assert_eq!(sensor.status, "registered");

        let response = list_sensors(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let rows: Vec<SensorRecord> = serde_json::from_slice(&body).unwrap();
        assert!(rows.iter().any(|s| s.id == sensor_id));
    }

    #[tokio::test]
    async fn re_registering_same_node_key_reuses_the_sensor_id() {
        let (state, tenant_id, _agent_token) = setup_state("sensor_reregister_route").await;

        let response = register_sensor(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_register_request("node-1")),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let first: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let mut second_req = sample_register_request("node-1");
        second_req.hostname = "host-a-renamed".to_string();
        let response = register_sensor(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(second_req),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let second: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(first["sensor_id"], second["sensor_id"]);
    }

    #[tokio::test]
    async fn register_rejects_invalid_mode() {
        let (state, tenant_id, _agent_token) = setup_state("sensor_register_bad_mode").await;
        let mut req = sample_register_request("node-1");
        req.mode = Some("yolo".to_string());

        let response =
            register_sensor(State(state.clone()), TenantId(tenant_id.clone()), Json(req))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn heartbeat_updates_sensor_and_is_tenant_scoped() {
        let (state, tenant_id, _agent_token) = setup_state("sensor_heartbeat_route").await;

        let response = register_sensor(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(sample_register_request("node-1")),
        )
        .await
        .into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let registered: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let sensor_id = registered["sensor_id"].as_str().unwrap().to_string();

        let heartbeat_req = SensorHeartbeatRequest {
            mode: "enforce".to_string(),
            sensor_version: "0.2.0".to_string(),
            queue_depth_critical: Some(1),
            queue_depth_normal: Some(5),
            disk_usage_bytes: Some(2048),
            active_cage_runs: Some(1),
            last_event_watermark: Some("evt-42".to_string()),
            last_command_watermark: None,
            health_status: Some("ok".to_string()),
        };
        let response = sensor_heartbeat(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(sensor_id.clone()),
            Json(heartbeat_req),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let sensor: SensorRecord = serde_json::from_slice(&body).unwrap();
        assert_eq!(sensor.status, "heartbeating");
        assert_eq!(sensor.mode, "enforce");
        assert_eq!(sensor.queue_depth_critical, Some(1));

        // Wrong tenant -> 404, not leaking cross-tenant existence.
        let response = sensor_heartbeat(
            State(state.clone()),
            TenantId("tenant_other_sensor".to_string()),
            Path(sensor_id.clone()),
            Json(SensorHeartbeatRequest {
                mode: "observe".to_string(),
                sensor_version: "0.2.0".to_string(),
                queue_depth_critical: None,
                queue_depth_normal: None,
                disk_usage_bytes: None,
                active_cage_runs: None,
                last_event_watermark: None,
                last_command_watermark: None,
                health_status: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn heartbeat_for_unknown_sensor_returns_404() {
        let (state, tenant_id, _agent_token) = setup_state("sensor_heartbeat_unknown_route").await;
        let response = sensor_heartbeat(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path("does-not-exist".to_string()),
            Json(SensorHeartbeatRequest {
                mode: "observe".to_string(),
                sensor_version: "0.1.0".to_string(),
                queue_depth_critical: None,
                queue_depth_normal: None,
                disk_usage_bytes: None,
                active_cage_runs: None,
                last_event_watermark: None,
                last_command_watermark: None,
                health_status: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
