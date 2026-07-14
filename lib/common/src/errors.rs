use thiserror::Error;

#[derive(Error, Debug)]
pub enum AegisError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),
}

impl AegisError {
    /// True when the error is a connection-pool acquire timeout.
    ///
    /// Adapters map this to HTTP 503 / gRPC Unavailable without depending on
    /// sqlx error variants outside the storage boundary.
    pub fn is_pool_exhausted(&self) -> bool {
        matches!(self, AegisError::Database(sqlx::Error::PoolTimedOut))
    }
}
