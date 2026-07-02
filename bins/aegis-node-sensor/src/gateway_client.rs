//! Phase 3.2 (Agent Cage): the sensor's HTTP client for the gateway's
//! `/v1/sensors/*` registration and heartbeat endpoints. The sensor
//! authenticates like any other API client — `Authorization: Bearer
//! <api_token>` — there is no sensor-specific auth mechanism.
//!
//! These request/response shapes are deliberately duplicated from the
//! gateway's route handlers rather than imported from a shared crate: this
//! is a network boundary, and the sensor binary stays independent of the
//! gateway's internal model crate (`aegis-api` pulls in proto/build.rs
//! tooling this small binary doesn't need).

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum GatewayClientError {
    #[error("request to gateway failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("gateway rejected the request with status {status}: {body}")]
    RejectedRequest {
        status: reqwest::StatusCode,
        body: String,
    },
}

#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub node_key: String,
    pub hostname: String,
    pub environment: Option<String>,
    pub sensor_version: String,
    pub public_key: String,
    pub capabilities: Vec<String>,
    pub mode: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    pub sensor_id: String,
    pub mode: String,
    pub config_version: i64,
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct HeartbeatRequest {
    pub mode: String,
    pub sensor_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_depth_critical: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_depth_normal: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_cage_runs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_watermark: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_command_watermark: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_status: Option<String>,
}

pub struct GatewayClient {
    http: reqwest::Client,
    base_url: Url,
    api_token: String,
}

impl GatewayClient {
    pub fn new(base_url: Url, api_token: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            api_token,
        }
    }

    pub async fn register(
        &self,
        req: &RegisterRequest,
    ) -> Result<RegisterResponse, GatewayClientError> {
        let url = self
            .base_url
            .join("/v1/sensors/register")
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(req)
            .send()
            .await?;
        Self::parse_response(response).await
    }

    /// Send one heartbeat. The gateway's response body (the updated sensor
    /// record) isn't needed yet, so this only reports success/failure.
    pub async fn heartbeat(
        &self,
        sensor_id: &str,
        req: &HeartbeatRequest,
    ) -> Result<(), GatewayClientError> {
        let url = self
            .base_url
            .join(&format!("/v1/sensors/{sensor_id}/heartbeat"))
            .expect("gateway_url + fixed path is always a valid URL");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(req)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GatewayClientError::RejectedRequest { status, body })
        }
    }

    async fn parse_response<T: for<'de> Deserialize<'de>>(
        response: reqwest::Response,
    ) -> Result<T, GatewayClientError> {
        if response.status().is_success() {
            Ok(response.json::<T>().await?)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(GatewayClientError::RejectedRequest { status, body })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use std::sync::{Arc, Mutex};

    fn sample_register_request() -> RegisterRequest {
        RegisterRequest {
            node_key: "node-1".to_string(),
            hostname: "host-a".to_string(),
            environment: Some("production".to_string()),
            sensor_version: "0.1.0".to_string(),
            public_key: "deadbeef".to_string(),
            capabilities: vec!["cage_runner".to_string()],
            mode: "observe".to_string(),
        }
    }

    #[tokio::test]
    async fn register_reports_connection_error_against_an_unreachable_host() {
        let client = GatewayClient::new(
            Url::parse("http://127.0.0.1:1").unwrap(), // port 1: nothing listens here
            "tok".to_string(),
        );
        let err = client
            .register(&sample_register_request())
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayClientError::Request(_)));
    }

    #[tokio::test]
    async fn register_surfaces_a_rejected_request() {
        let app = Router::new().route(
            "/v1/sensors/register",
            post(|| async { (axum::http::StatusCode::UNAUTHORIZED, "bad token") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "bad-token".to_string(),
        );
        let err = client
            .register(&sample_register_request())
            .await
            .unwrap_err();
        match err {
            GatewayClientError::RejectedRequest { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
            }
            other => panic!("expected RejectedRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_parses_a_successful_response() {
        let received_auth = Arc::new(Mutex::new(None));
        let received_auth_clone = received_auth.clone();
        let app = Router::new().route(
            "/v1/sensors/register",
            post(
                move |headers: axum::http::HeaderMap, Json(_body): Json<serde_json::Value>| {
                    let received_auth = received_auth_clone.clone();
                    async move {
                        *received_auth.lock().unwrap() = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        Json(serde_json::json!({
                            "sensor_id": "sensor-123",
                            "mode": "observe",
                            "config_version": 1,
                            "heartbeat_interval_secs": 30,
                        }))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok_abc".to_string(),
        );
        let resp = client.register(&sample_register_request()).await.unwrap();
        assert_eq!(resp.sensor_id, "sensor-123");
        assert_eq!(resp.heartbeat_interval_secs, 30);
        assert_eq!(
            received_auth.lock().unwrap().as_deref(),
            Some("Bearer tok_abc")
        );
    }

    #[tokio::test]
    async fn heartbeat_succeeds_against_a_200_response() {
        let app = Router::new().route(
            "/v1/sensors/:id/heartbeat",
            post(|| async { Json(serde_json::json!({"status": "heartbeating"})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let req = HeartbeatRequest {
            mode: "observe".to_string(),
            sensor_version: "0.1.0".to_string(),
            ..Default::default()
        };
        assert!(client.heartbeat("sensor-123", &req).await.is_ok());
    }

    #[tokio::test]
    async fn heartbeat_surfaces_a_404_for_unknown_sensor() {
        let app = Router::new().route(
            "/v1/sensors/:id/heartbeat",
            post(|| async { (axum::http::StatusCode::NOT_FOUND, "sensor not found") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = GatewayClient::new(
            Url::parse(&format!("http://{addr}")).unwrap(),
            "tok".to_string(),
        );
        let req = HeartbeatRequest {
            mode: "observe".to_string(),
            sensor_version: "0.1.0".to_string(),
            ..Default::default()
        };
        let err = client.heartbeat("does-not-exist", &req).await.unwrap_err();
        match err {
            GatewayClientError::RejectedRequest { status, .. } => {
                assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            }
            other => panic!("expected RejectedRequest, got {other:?}"),
        }
    }
}
