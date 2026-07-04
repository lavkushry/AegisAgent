#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed proxy request: {0}")]
    MalformedRequest(String),
}
