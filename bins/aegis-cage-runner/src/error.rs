//! Phase 4.1 (Agent Cage): cage-runner error type.

#[derive(Debug, thiserror::Error)]
pub enum CageError {
    #[error("sandbox spec is invalid: {0}")]
    InvalidSpec(String),
    #[error("runtime backend error: {0}")]
    Runtime(String),
    #[error("sandbox not found: {0}")]
    NotFound(String),
}
