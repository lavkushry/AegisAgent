//! #1627 — alerting settings REST handlers (contact points, policies, silences).

use axum::{
    extract::{Path, State},
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

use crate::error::StatusError;
use crate::models::*;
use crate::routes::authorize_canon::sha256_hex;
use crate::routes::webhooks::default_webhook_event_types;
use crate::routes::{paginated_response, parse_cursor, parse_pagination, AppState, TenantId};

async fn audit_alerting_event(
    state: &AppState,
    tenant_id: &str,
    event_type: &str,
    resource_id: &str,
    detail: serde_json::Value,
) {
    let audit = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: event_type.to_string(),
        agent_id: None,
        user_id: None,
        run_id: None,
        trace_id: None,
        span_id: None,
        skill: None,
        action: Some(event_type.to_string()),
        resource: Some(resource_id.to_string()),
        event_json: serde_json::to_string(&detail).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        decision_id: None,
        approval_id: None,
        created_at: Utc::now(),
    };
    let _ = state.storage.insert_audit_event(&audit).await;
}

// --- Contact points ---

#[derive(Debug, Deserialize)]
pub struct CreateContactPointRequest {
    pub name: String,
    pub channel_type: String,
    pub url: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub settings_json: Option<String>,
    #[serde(default)]
    pub event_types: Option<String>,
    #[serde(default)]
    pub min_severity: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateContactPointRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    pub settings_json: Option<String>,
    pub health_status: Option<String>,
}

pub async fn list_contact_points(
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
        .list_contact_points_cursor(&tenant_id, limit, offset, cursor)
        .await
    {
        Ok((items, next_cursor)) => paginated_response(&items, next_cursor),
        Err(e) => {
            error!("Failed to list contact points: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn create_contact_point(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<CreateContactPointRequest>,
) -> impl IntoResponse {
    if payload.name.trim().is_empty() {
        return StatusError::bad_request("name must not be empty").into_response();
    }
    let channel = payload.channel_type.to_ascii_lowercase();
    if channel == aegis_soc::alerting::CHANNEL_EMAIL {
        return StatusError::bad_request("email contact points are not supported yet")
            .into_response();
    }
    if !aegis_soc::alerting::channel_type_is_supported(&channel) {
        return StatusError::bad_request("unsupported channel_type").into_response();
    }

    let url = match payload.url.as_deref() {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            return StatusError::bad_request("url is required for this channel_type")
                .into_response()
        }
    };

    if channel != aegis_soc::alerting::CHANNEL_EMAIL {
        if let Err(msg) = aegis_soc::alerting::validate_destination_url(&url) {
            return StatusError::bad_request(msg).into_response();
        }
    }

    let settings_json = payload.settings_json.unwrap_or_else(|| "{}".to_string());
    let secret_hash = payload.secret.as_ref().map(|s| sha256_hex(s.as_bytes()));

    let mut webhook_subscription_id: Option<String> = None;
    let mut delivery_secret_once: Option<String> = None;
    let health_status = "unknown".to_string();

    if matches!(
        channel.as_str(),
        aegis_soc::alerting::CHANNEL_WEBHOOK | aegis_soc::alerting::CHANNEL_SLACK
    ) {
        let min_severity = payload.min_severity.unwrap_or_else(|| "info".to_string());
        if min_severity != "info" && min_severity != "high" {
            return StatusError::bad_request("min_severity must be 'info' or 'high'")
                .into_response();
        }
        let format = payload.format.unwrap_or_else(|| "json".to_string());
        if format != "json" && format != "cef" {
            return StatusError::bad_request("format must be 'json' or 'cef'").into_response();
        }
        let event_types = payload
            .event_types
            .unwrap_or_else(default_webhook_event_types);
        let delivery_secret = format!("whsec_{}", Uuid::new_v4().simple());
        match state
            .storage
            .insert_webhook_subscription(
                &tenant_id,
                &url,
                secret_hash.as_deref(),
                &event_types,
                &delivery_secret,
                &min_severity,
                &format,
            )
            .await
        {
            Ok(record) => {
                webhook_subscription_id = Some(record.id);
                delivery_secret_once = Some(delivery_secret);
            }
            Err(e) => {
                error!("Failed to create webhook for contact point: {:?}", e);
                return StatusError::internal("Database error").into_response();
            }
        }
    }

    match state
        .storage
        .insert_contact_point(
            &tenant_id,
            payload.name.trim(),
            &channel,
            Some(&url),
            secret_hash.as_deref(),
            webhook_subscription_id.as_deref(),
            &settings_json,
            &health_status,
        )
        .await
    {
        Ok(record) => {
            audit_alerting_event(
                &state,
                &tenant_id,
                "contact_point_created",
                &record.id,
                json!({ "name": record.name, "channel_type": record.channel_type }),
            )
            .await;
            let mut body = json!({ "contact_point": record });
            if let Some(ds) = delivery_secret_once {
                body["delivery_secret"] = json!(ds);
            }
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(e) => {
            error!("Failed to create contact point: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn update_contact_point(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(payload): Json<UpdateContactPointRequest>,
) -> impl IntoResponse {
    let mut record = match state.storage.get_contact_point_by_id(&tenant_id, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => return StatusError::not_found("Contact point not found").into_response(),
        Err(e) => {
            error!("Failed to fetch contact point: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    if let Some(name) = payload.name {
        if name.trim().is_empty() {
            return StatusError::bad_request("name must not be empty").into_response();
        }
        record.name = name.trim().to_string();
    }
    if let Some(url) = payload.url {
        if let Err(msg) = aegis_soc::alerting::validate_destination_url(url.trim()) {
            return StatusError::bad_request(msg).into_response();
        }
        record.url = Some(url.trim().to_string());
    }
    if let Some(settings) = payload.settings_json {
        record.settings_json = settings;
    }
    if let Some(health) = payload.health_status {
        record.health_status = health;
    }
    if payload.secret.is_some() {
        // Secret updates are write-only; hash stored but never returned.
        let hash = payload.secret.as_ref().map(|s| sha256_hex(s.as_bytes()));
        record.secret_hash = hash;
    }

    match state.storage.update_contact_point(&record).await {
        Ok(()) => {
            audit_alerting_event(
                &state,
                &tenant_id,
                "contact_point_updated",
                &id,
                json!({ "name": record.name }),
            )
            .await;
            (StatusCode::OK, Json(json!({ "contact_point": record }))).into_response()
        }
        Err(e) => {
            error!("Failed to update contact point: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn delete_contact_point(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let record = match state.storage.get_contact_point_by_id(&tenant_id, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => return StatusError::not_found("Contact point not found").into_response(),
        Err(e) => {
            error!("Failed to fetch contact point: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    if let Some(sub_id) = record.webhook_subscription_id.as_deref() {
        let _ = state
            .storage
            .delete_webhook_subscription(&tenant_id, sub_id)
            .await;
    }

    match state.storage.delete_contact_point(&tenant_id, &id).await {
        Ok(true) => {
            audit_alerting_event(
                &state,
                &tenant_id,
                "contact_point_deleted",
                &id,
                json!({ "name": record.name }),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({"message": "Contact point deleted"})),
            )
                .into_response()
        }
        Ok(false) => StatusError::not_found("Contact point not found").into_response(),
        Err(e) => {
            error!("Failed to delete contact point: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

// --- Notification policies ---

#[derive(Debug, Deserialize)]
pub struct CreateNotificationPolicyRequest {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub matchers_json: Option<String>,
    #[serde(default)]
    pub contact_point_ids_json: Option<String>,
    pub group_by: Option<String>,
    pub repeat_interval_secs: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNotificationPolicyRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub matchers_json: Option<String>,
    pub contact_point_ids_json: Option<String>,
    pub group_by: Option<String>,
    pub repeat_interval_secs: Option<i64>,
}

fn default_true() -> bool {
    true
}

pub async fn list_notification_policies(
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
        .list_notification_policies_cursor(&tenant_id, limit, offset, cursor)
        .await
    {
        Ok((items, next_cursor)) => paginated_response(&items, next_cursor),
        Err(e) => {
            error!("Failed to list notification policies: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn create_notification_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<CreateNotificationPolicyRequest>,
) -> impl IntoResponse {
    if payload.name.trim().is_empty() {
        return StatusError::bad_request("name must not be empty").into_response();
    }
    let matchers = payload.matchers_json.unwrap_or_else(|| "{}".to_string());
    let contact_ids = payload
        .contact_point_ids_json
        .unwrap_or_else(|| "[]".to_string());
    if serde_json::from_str::<serde_json::Value>(&matchers).is_err() {
        return StatusError::bad_request("matchers_json must be valid JSON").into_response();
    }
    if serde_json::from_str::<serde_json::Value>(&contact_ids).is_err() {
        return StatusError::bad_request("contact_point_ids_json must be valid JSON array")
            .into_response();
    }

    match state
        .storage
        .insert_notification_policy(
            &tenant_id,
            payload.name.trim(),
            payload.enabled,
            &matchers,
            &contact_ids,
            payload.group_by.as_deref(),
            payload.repeat_interval_secs,
        )
        .await
    {
        Ok(record) => {
            audit_alerting_event(
                &state,
                &tenant_id,
                "notification_policy_created",
                &record.id,
                json!({ "name": record.name }),
            )
            .await;
            (StatusCode::CREATED, Json(json!({ "policy": record }))).into_response()
        }
        Err(e) => {
            error!("Failed to create notification policy: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn update_notification_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
    Json(payload): Json<UpdateNotificationPolicyRequest>,
) -> impl IntoResponse {
    let mut record = match state
        .storage
        .get_notification_policy_by_id(&tenant_id, &id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return StatusError::not_found("Notification policy not found").into_response(),
        Err(e) => {
            error!("Failed to fetch notification policy: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    if let Some(name) = payload.name {
        if name.trim().is_empty() {
            return StatusError::bad_request("name must not be empty").into_response();
        }
        record.name = name.trim().to_string();
    }
    if let Some(enabled) = payload.enabled {
        record.enabled = enabled;
    }
    if let Some(matchers) = payload.matchers_json {
        if serde_json::from_str::<serde_json::Value>(&matchers).is_err() {
            return StatusError::bad_request("matchers_json must be valid JSON").into_response();
        }
        record.matchers_json = matchers;
    }
    if let Some(ids) = payload.contact_point_ids_json {
        if serde_json::from_str::<serde_json::Value>(&ids).is_err() {
            return StatusError::bad_request("contact_point_ids_json must be valid JSON array")
                .into_response();
        }
        record.contact_point_ids_json = ids;
    }
    if payload.group_by.is_some() {
        record.group_by = payload.group_by;
    }
    if payload.repeat_interval_secs.is_some() {
        record.repeat_interval_secs = payload.repeat_interval_secs;
    }

    match state.storage.update_notification_policy(&record).await {
        Ok(()) => {
            audit_alerting_event(
                &state,
                &tenant_id,
                "notification_policy_updated",
                &id,
                json!({ "name": record.name }),
            )
            .await;
            (StatusCode::OK, Json(json!({ "policy": record }))).into_response()
        }
        Err(e) => {
            error!("Failed to update notification policy: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn delete_notification_policy(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state
        .storage
        .delete_notification_policy(&tenant_id, &id)
        .await
    {
        Ok(true) => {
            audit_alerting_event(
                &state,
                &tenant_id,
                "notification_policy_deleted",
                &id,
                json!({}),
            )
            .await;
            (
                StatusCode::OK,
                Json(json!({"message": "Notification policy deleted"})),
            )
                .into_response()
        }
        Ok(false) => StatusError::not_found("Notification policy not found").into_response(),
        Err(e) => {
            error!("Failed to delete notification policy: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

// --- Silences ---

#[derive(Debug, Deserialize)]
pub struct CreateSilenceRequest {
    pub rule_key: Option<String>,
    pub agent_id: Option<String>,
    pub comment: Option<String>,
    pub starts_at: Option<String>,
    pub ends_at: String,
    pub created_by: Option<String>,
}

pub async fn list_silences(
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
        .list_alert_silences_cursor(&tenant_id, limit, offset, cursor)
        .await
    {
        Ok((items, next_cursor)) => paginated_response(&items, next_cursor),
        Err(e) => {
            error!("Failed to list silences: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

fn parse_rfc3339(field: &str, raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|| {
            tracing::debug!(field, raw, "invalid RFC3339 timestamp");
            None
        })
}

pub async fn create_silence(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(payload): Json<CreateSilenceRequest>,
) -> impl IntoResponse {
    if payload.rule_key.is_none() && payload.agent_id.is_none() {
        return StatusError::bad_request("rule_key or agent_id is required").into_response();
    }
    let starts_at = match payload.starts_at.as_deref() {
        Some(s) => match parse_rfc3339("starts_at", s) {
            Some(v) => v,
            None => return StatusError::bad_request("invalid starts_at timestamp").into_response(),
        },
        None => Utc::now(),
    };
    let ends_at = match parse_rfc3339("ends_at", &payload.ends_at) {
        Some(v) => v,
        None => return StatusError::bad_request("invalid ends_at timestamp").into_response(),
    };
    if ends_at <= starts_at {
        return StatusError::bad_request("ends_at must be after starts_at").into_response();
    }

    match state
        .storage
        .insert_alert_silence(
            &tenant_id,
            payload.rule_key.as_deref(),
            payload.agent_id.as_deref(),
            payload.comment.as_deref(),
            starts_at,
            ends_at,
            payload.created_by.as_deref(),
        )
        .await
    {
        Ok(record) => {
            audit_alerting_event(
                &state,
                &tenant_id,
                "alert_silence_created",
                &record.id,
                json!({
                    "rule_key": record.rule_key,
                    "agent_id": record.agent_id,
                    "ends_at": record.ends_at,
                }),
            )
            .await;
            (StatusCode::CREATED, Json(json!({ "silence": record }))).into_response()
        }
        Err(e) => {
            error!("Failed to create silence: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

pub async fn delete_silence(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.delete_alert_silence(&tenant_id, &id).await {
        Ok(true) => {
            audit_alerting_event(&state, &tenant_id, "alert_silence_deleted", &id, json!({})).await;
            (StatusCode::OK, Json(json!({"message": "Silence deleted"}))).into_response()
        }
        Ok(false) => StatusError::not_found("Silence not found").into_response(),
        Err(e) => {
            error!("Failed to delete silence: {:?}", e);
            StatusError::internal("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;

    #[tokio::test]
    async fn silences_api_crud_and_ssrf_rejection() {
        let (state, tenant_id, _token) = setup_state("alerting_silences_api").await;

        let bad_cp = create_contact_point(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateContactPointRequest {
                name: "bad".into(),
                channel_type: "webhook".into(),
                url: Some("https://127.0.0.1/hook".into()),
                secret: None,
                settings_json: None,
                event_types: None,
                min_severity: None,
                format: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(bad_cp.status(), StatusCode::BAD_REQUEST);

        let silence_resp = create_silence(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(CreateSilenceRequest {
                rule_key: Some("test_rule".into()),
                agent_id: None,
                comment: Some("test".into()),
                starts_at: None,
                ends_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                created_by: Some("analyst".into()),
            }),
        )
        .await;
        let silence_resp = silence_resp.into_response();
        assert_eq!(silence_resp.status(), StatusCode::CREATED);

        let list = list_silences(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("limit=10".into())),
        )
        .await
        .into_response();
        assert_eq!(list.status(), StatusCode::OK);
    }
}
