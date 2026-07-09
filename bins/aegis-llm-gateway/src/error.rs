//! Error types for the LLM gateway adapter.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LlmGatewayError {
    #[error("malformed model request: {0}")]
    MalformedRequest(String),
    #[error("upstream request failed: {0}")]
    Upstream(String),
    #[error("gateway ingest failed: {0}")]
    GatewayIngest(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
