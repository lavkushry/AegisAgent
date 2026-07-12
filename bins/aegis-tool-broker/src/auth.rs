//! Bearer-token auth for the one privileged route (`POST /v1/execute`).
//!
//! Unlike the gateway's optional admin key (which treats a loopback bind as
//! evidence of safe operator intent), this binary's entire surface *is* the
//! privileged action it guards — there is no "safe to leave open" mode, so
//! the token is a required CLI/env field (`Cli::api_token` has no
//! `default_value`) and every `/v1/execute` call is checked unconditionally.

use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// SHA-256 digest equality rather than a raw `==` — mirrors the gateway's
/// `admin_decision` rationale: a timing side-channel on a raw string
/// comparison can leak the configured token one byte at a time.
pub fn tokens_match(configured: &str, provided: &str) -> bool {
    fn hash(token: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(token.as_bytes()))
    }
    hash(configured) == hash(provided)
}

pub async fn require_bearer_token(
    State(configured_token): State<Arc<String>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if tokens_match(&configured_token, token) => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "invalid or missing bearer token").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_tokens_are_equal() {
        assert!(tokens_match("secret-token", "secret-token"));
    }

    #[test]
    fn mismatched_tokens_are_not_equal() {
        assert!(!tokens_match("secret-token", "wrong-token"));
    }

    #[test]
    fn empty_provided_token_never_matches_a_configured_one() {
        assert!(!tokens_match("secret-token", ""));
    }

    #[test]
    fn two_empty_tokens_are_equal_but_the_server_never_configures_an_empty_one() {
        // Documents the invariant this relies on: Cli::api_token has no
        // default_value, so an empty configured token is unreachable in
        // production -- clap itself refuses to start the process.
        assert!(tokens_match("", ""));
    }
}
