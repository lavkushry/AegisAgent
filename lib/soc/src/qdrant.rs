//! Qdrant async semantic audit indexing implementation.
//!
//! Provides the `EmbeddingModel` trait and two implementations:
//! 1. `HttpEmbeddingModel` (targets cloud OpenAI or local Ollama endpoints).
//! 2. `LocalEmbeddingModel` (targets in-process ONNX models via `fastembed` under `local-embeddings` feature).
//!
//! DECISIONS and events are vectorized asynchronously out-of-band to prevent slowing down the inline paths.

#![allow(deprecated)]

use async_trait::async_trait;
use qdrant_client::qdrant::{
    CreateCollection, Distance, PointId, PointStruct, UpsertPoints, VectorParams, VectorsConfig,
};
use qdrant_client::{Payload, Qdrant};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;

#[async_trait]
pub trait EmbeddingModel: Send + Sync {
    async fn generate_embedding(
        &self,
        text: &str,
    ) -> Result<Vec<f32>, Box<dyn std::error::Error + Send + Sync>>;
    fn dimension(&self) -> usize;
}

// 1. HTTP API implementation (compatible with OpenAI and local Ollama)
pub struct HttpEmbeddingModel {
    pub client: reqwest::Client,
    pub url: String,
    pub key: Option<String>,
    pub model: String,
    pub dimension: usize,
}

#[derive(Serialize)]
struct EmbeddingRequest {
    input: String,
    model: String,
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

#[async_trait]
impl EmbeddingModel for HttpEmbeddingModel {
    async fn generate_embedding(
        &self,
        text: &str,
    ) -> Result<Vec<f32>, Box<dyn std::error::Error + Send + Sync>> {
        let req_body = EmbeddingRequest {
            input: text.to_string(),
            model: self.model.clone(),
        };

        let mut req = self.client.post(&self.url).json(&req_body);
        if let Some(ref api_key) = self.key {
            req = req.bearer_auth(api_key);
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Embedding API error: status={}, body={}", status, text).into());
        }

        let body: EmbeddingResponse = resp.json().await?;
        let vector = body
            .data
            .first()
            .map(|d| d.embedding.clone())
            .ok_or("Empty data in embedding response")?;

        Ok(vector)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

// 2. Local ONNX implementation (compiled only when feature "local-embeddings" is active)
#[cfg(feature = "local-embeddings")]
pub struct LocalEmbeddingModel {
    pub model: fastembed::TextEmbedding,
    pub dimension: usize,
}

#[cfg(feature = "local-embeddings")]
#[async_trait]
impl EmbeddingModel for LocalEmbeddingModel {
    async fn generate_embedding(
        &self,
        text: &str,
    ) -> Result<Vec<f32>, Box<dyn std::error::Error + Send + Sync>> {
        // fastembed's embed() takes a Vec of strings and runs ONNX inference.
        // It is a blocking CPU-bound task, so we run it using spawn_blocking to avoid blocking tokio executor threads.
        let model = self.model.clone();
        let query = format!("query: {}", text); // recommend query prefix for best retrieval performance
        let vector = tokio::task::spawn_blocking(move || model.embed(vec![&query], None)).await??;

        let res = vector
            .first()
            .cloned()
            .ok_or("Local model returned empty embedding")?;
        Ok(res)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }
}

// Qdrant exporter wrapper
pub struct QdrantExporter {
    pub client: Qdrant,
    pub model: Arc<dyn EmbeddingModel>,
    pub collection_name: String,
}

impl QdrantExporter {
    pub fn new(client: Qdrant, model: Arc<dyn EmbeddingModel>, collection_name: String) -> Self {
        Self {
            client,
            model,
            collection_name,
        }
    }

    /// Initializes the Qdrant collection if it doesn't already exist.
    pub async fn init_collection(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self
            .client
            .collection_exists(self.collection_name.as_str())
            .await?
        {
            info!(
                collection = %self.collection_name,
                dimension = %self.model.dimension(),
                "Creating Qdrant collection for semantic audit indexing"
            );
            self.client
                .create_collection(CreateCollection {
                    collection_name: self.collection_name.clone(),
                    vectors_config: Some(VectorsConfig {
                        config: Some(qdrant_client::qdrant::vectors_config::Config::Params(
                            VectorParams {
                                size: self.model.dimension() as u64,
                                distance: Distance::Cosine as i32,
                                hnsw_config: None,
                                quantization_config: None,
                                on_disk: None,
                                ..Default::default()
                            },
                        )),
                    }),
                    ..Default::default()
                })
                .await?;
        } else {
            debug!(
                collection = %self.collection_name,
                "Qdrant collection already exists"
            );
        }
        Ok(())
    }

    /// Vectorizes and exports one AseEvent to Qdrant asynchronously.
    pub async fn export_event(
        &self,
        event: crate::events::AseEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Construct the semantic text payload to represent the audit event
        let text_representation = format!(
            "tool: {} | action: {} | agent: {} | tenant: {} | reason: {} | decision: {} | risk: {}",
            event.tool,
            event.action,
            event.agent_id,
            event.tenant_id,
            event.reason,
            event.decision,
            event.risk_score
        );

        // Generate embedding vector
        let vector = self.model.generate_embedding(&text_representation).await?;

        // Deterministic UUID based on event_id ensures idempotency / replay prevention
        let point_uuid = Uuid::new_v5(&Uuid::NAMESPACE_DNS, event.event_id.as_bytes());
        let point_id = PointId::from(point_uuid.to_string());

        // Prepare payload properties matching metadata
        let mut payload = serde_json::Map::new();
        payload.insert(
            "event_id".to_string(),
            serde_json::Value::String(event.event_id),
        );
        payload.insert(
            "occurred_at".to_string(),
            serde_json::Value::String(event.occurred_at),
        );
        payload.insert(
            "tenant_id".to_string(),
            serde_json::Value::String(event.tenant_id),
        );
        payload.insert("kind".to_string(), serde_json::Value::String(event.kind));
        payload.insert(
            "agent_id".to_string(),
            serde_json::Value::String(event.agent_id),
        );
        payload.insert(
            "decision".to_string(),
            serde_json::Value::String(event.decision),
        );
        payload.insert("tool".to_string(), serde_json::Value::String(event.tool));
        payload.insert(
            "action".to_string(),
            serde_json::Value::String(event.action),
        );
        if let Some(res) = event.resource {
            payload.insert("resource".to_string(), serde_json::Value::String(res));
        }
        payload.insert(
            "risk_score".to_string(),
            serde_json::Value::Number(event.risk_score.into()),
        );
        payload.insert(
            "reason".to_string(),
            serde_json::Value::String(event.reason),
        );
        if let Some(r_id) = event.run_id {
            payload.insert("run_id".to_string(), serde_json::Value::String(r_id));
        }
        if let Some(t_id) = event.trace_id {
            payload.insert("trace_id".to_string(), serde_json::Value::String(t_id));
        }
        payload.insert(
            "matched_policies".to_string(),
            serde_json::Value::Array(
                event
                    .matched_policies
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );

        let point = PointStruct::new(point_id, vector, Payload::from(payload));

        self.client
            .upsert_points(UpsertPoints {
                collection_name: self.collection_name.clone(),
                points: vec![point],
                ..Default::default()
            })
            .await?;

        debug!(point_id = %point_uuid, "successfully indexed event to Qdrant");
        Ok(())
    }

    /// Performs a semantic search querying similar events in Qdrant, filtered by tenant_id.
    pub async fn search_similar_events(
        &self,
        tenant_id: &str,
        query_text: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Generate query embedding vector
        let vector = self.model.generate_embedding(query_text).await?;

        // 2. Build multi-tenant filter condition
        let filter =
            qdrant_client::qdrant::Filter::all([qdrant_client::qdrant::Condition::matches(
                "tenant_id",
                tenant_id.to_string(),
            )]);

        // 3. Construct SearchPoints request
        let req = qdrant_client::qdrant::SearchPoints {
            collection_name: self.collection_name.clone(),
            vector,
            filter: Some(filter),
            limit: limit as u64,
            with_payload: Some(true.into()),
            ..Default::default()
        };

        // 4. Perform search
        let response = self.client.search_points(req).await?;

        // 5. Convert points back to JSON, appending similarity score
        let mut results = Vec::new();
        for point in response.result {
            let mut payload = serde_json::to_value(Payload::from(point.payload))
                .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));

            if let serde_json::Value::Object(ref mut map) = payload {
                map.insert(
                    "similarity_score".to_string(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(point.score as f64)
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    ),
                );
            }
            results.push(payload);
        }

        Ok(results)
    }
}
