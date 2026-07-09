//! Ships finished model-call lineage to the control plane
//! (`POST /v1/ingest/model-calls`, Phase 7.1). Request/response shapes are
//! deliberately duplicated from the gateway route handlers rather than
//! imported from `aegis-api` — this binary stays independent of the gateway
//! crate graph (same pattern as `aegis-node-sensor`).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::LlmGatewayError;

/// Body for `POST /v1/ingest/model-calls`. Hashes/metadata only — never a
/// raw request or response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelCallIngestPayload {
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub provider: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_counts: Option<Value>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction_status: Option<String>,
}

/// Body for `POST /v1/ingest/prompt-events`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptEventIngestPayload {
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub prompt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_prompt_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_trust: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction_status: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestResponse {
    pub ingested: bool,
}

#[async_trait]
pub trait LineageClient: Send + Sync {
    async fn ingest_model_call(
        &self,
        payload: &ModelCallIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError>;

    async fn ingest_prompt_event(
        &self,
        payload: &PromptEventIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError>;
}

/// No-op client used when no gateway URL is configured (local-only capture).
#[derive(Debug, Default)]
pub struct NullLineageClient;

#[async_trait]
impl LineageClient for NullLineageClient {
    async fn ingest_model_call(
        &self,
        _payload: &ModelCallIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError> {
        Ok(IngestResponse { ingested: true })
    }

    async fn ingest_prompt_event(
        &self,
        _payload: &PromptEventIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError> {
        Ok(IngestResponse { ingested: true })
    }
}

/// In-memory capture for tests.
#[derive(Debug, Default)]
pub struct RecordingLineageClient {
    model_calls: std::sync::Mutex<Vec<ModelCallIngestPayload>>,
    prompt_events: std::sync::Mutex<Vec<PromptEventIngestPayload>>,
}

impl RecordingLineageClient {
    pub fn model_calls(&self) -> Vec<ModelCallIngestPayload> {
        match self.model_calls.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    pub fn prompt_events(&self) -> Vec<PromptEventIngestPayload> {
        match self.prompt_events.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }
}

#[async_trait]
impl LineageClient for RecordingLineageClient {
    async fn ingest_model_call(
        &self,
        payload: &ModelCallIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError> {
        match self.model_calls.lock() {
            Ok(mut g) => g.push(payload.clone()),
            Err(p) => p.into_inner().push(payload.clone()),
        }
        Ok(IngestResponse { ingested: true })
    }

    async fn ingest_prompt_event(
        &self,
        payload: &PromptEventIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError> {
        match self.prompt_events.lock() {
            Ok(mut g) => g.push(payload.clone()),
            Err(p) => p.into_inner().push(payload.clone()),
        }
        Ok(IngestResponse { ingested: true })
    }
}

/// HTTP client for the AegisAgent control-plane ingest APIs.
pub struct HttpLineageClient {
    client: reqwest::Client,
    base_url: String,
    api_token: String,
}

impl HttpLineageClient {
    pub fn new(base_url: impl Into<String>, api_token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_token: api_token.into(),
        }
    }

    async fn post_json<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<IngestResponse, LlmGatewayError> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.client.post(&url).json(body);
        if !self.api_token.is_empty() {
            req = req.bearer_auth(&self.api_token);
        }
        let response = req
            .send()
            .await
            .map_err(|e| LlmGatewayError::GatewayIngest(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(LlmGatewayError::GatewayIngest(format!(
                "status {status}: {body}"
            )));
        }
        response
            .json::<IngestResponse>()
            .await
            .map_err(|e| LlmGatewayError::GatewayIngest(e.to_string()))
    }
}

#[async_trait]
impl LineageClient for HttpLineageClient {
    async fn ingest_model_call(
        &self,
        payload: &ModelCallIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError> {
        self.post_json("/v1/ingest/model-calls", payload).await
    }

    async fn ingest_prompt_event(
        &self,
        payload: &PromptEventIngestPayload,
    ) -> Result<IngestResponse, LlmGatewayError> {
        self.post_json("/v1/ingest/prompt-events", payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_client_stores_model_call_payload_without_raw_bodies() {
        let client = RecordingLineageClient::default();
        let payload = ModelCallIngestPayload {
            event_id: "e1".into(),
            run_id: Some("run-1".into()),
            trace_id: None,
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            request_hash: Some("a".repeat(64)),
            response_hash: Some("b".repeat(64)),
            started_at: None,
            finished_at: None,
            token_counts: Some(serde_json::json!({"prompt_tokens": 3})),
            status: "success".into(),
            redaction_status: Some("redacted".into()),
        };
        client.ingest_model_call(&payload).await.unwrap();
        let stored = client.model_calls();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].status, "success");
        // Structural guarantee: the payload type has no body field to fill.
        let serialized = serde_json::to_value(&stored[0]).unwrap();
        assert!(serialized.get("request_body").is_none());
        assert!(serialized.get("response_body").is_none());
        assert!(serialized.get("prompt").is_none());
    }
}
