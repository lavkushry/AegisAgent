//! Generic HTTP connector — Phase 6.3. The broker owns credential handling
//! end to end: the resolved credential goes into the outbound
//! `Authorization` header, and callers are *forbidden* from supplying their
//! own `Authorization` header — otherwise an agent could smuggle a
//! credential it isn't supposed to have (or exfiltrate one via a
//! reflection endpoint) through "just parameters".
//!
//! HTTPS-only by default; [`HttpConnector::allowing_plain_http`] exists for
//! tests and explicitly-configured internal targets.
//!
//! Method mapping follows the mutation contract: `GET`/`HEAD` are
//! non-mutating; `POST`/`PUT`/`PATCH`/`DELETE` require
//! `mutates_state: true` so they can't dodge the executor's approval gate.

use async_trait::async_trait;
use serde_json::{json, Value};

use aegis_tool_broker_core::{BrokerAction, Connector, ConnectorError, ConnectorOutput, Secret};

/// Response bodies larger than this are truncated before they leave the
/// connector — the broker is a choke point, not a bulk data plane.
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct HttpConnector {
    allow_plain_http: bool,
    client: reqwest::Client,
}

impl Default for HttpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpConnector {
    /// HTTPS-only — the production configuration.
    pub fn new() -> Self {
        Self {
            allow_plain_http: false,
            client: reqwest::Client::new(),
        }
    }

    /// Also permits `http://` targets. For tests and explicitly-configured
    /// internal endpoints; never the default.
    pub fn allowing_plain_http() -> Self {
        Self {
            allow_plain_http: true,
            client: reqwest::Client::new(),
        }
    }
}

fn method_for(action: &BrokerAction) -> Result<reqwest::Method, ConnectorError> {
    let name = action
        .parameters
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let (method, mutating) = match name.as_str() {
        "GET" => (reqwest::Method::GET, false),
        "HEAD" => (reqwest::Method::HEAD, false),
        "POST" => (reqwest::Method::POST, true),
        "PUT" => (reqwest::Method::PUT, true),
        "PATCH" => (reqwest::Method::PATCH, true),
        "DELETE" => (reqwest::Method::DELETE, true),
        other => {
            return Err(ConnectorError::UnsupportedAction {
                connector: "http".to_string(),
                action: format!("method {other}"),
            })
        }
    };
    if mutating && !action.mutates_state {
        return Err(ConnectorError::ExecutionFailed(format!(
            "http {name} requests must set mutates_state: true"
        )));
    }
    Ok(method)
}

#[async_trait]
impl Connector for HttpConnector {
    fn connector_type(&self) -> &'static str {
        "http"
    }

    async fn execute(
        &self,
        action: &BrokerAction,
        credential: Option<&Secret>,
    ) -> Result<ConnectorOutput, ConnectorError> {
        let url = action
            .parameters
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ConnectorError::ExecutionFailed("http actions require parameters.url".to_string())
            })?;
        let scheme_ok =
            url.starts_with("https://") || (self.allow_plain_http && url.starts_with("http://"));
        if !scheme_ok {
            return Err(ConnectorError::ExecutionFailed(format!(
                "url scheme not allowed (https required): {url}"
            )));
        }
        let method = method_for(action)?;

        let mut request = self.client.request(method, url);
        if let Some(headers) = action.parameters.get("headers").and_then(Value::as_object) {
            for (name, value) in headers {
                // The broker owns auth. A caller-supplied Authorization header
                // is either credential smuggling or credential exfiltration.
                if name.eq_ignore_ascii_case("authorization") {
                    return Err(ConnectorError::ExecutionFailed(
                        "callers may not set the Authorization header; credentials are broker-managed"
                            .to_string(),
                    ));
                }
                let value = value.as_str().ok_or_else(|| {
                    ConnectorError::ExecutionFailed(format!("header {name} must be a string"))
                })?;
                request = request.header(name, value);
            }
        }
        if let Some(body) = action.parameters.get("body") {
            request = request.json(body);
        }
        // The one audited place the raw credential is used.
        if let Some(secret) = credential {
            request = request.header("Authorization", format!("Bearer {}", secret.expose()));
        }

        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::ExecutionFailed(format!("http request: {e}")))?;
        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| ConnectorError::ExecutionFailed(format!("http body: {e}")))?;
        let truncated = text.len() > MAX_BODY_BYTES;
        let body: String = text.chars().take(MAX_BODY_BYTES).collect();
        Ok(ConnectorOutput::new(json!({
            "status": status,
            "body": body,
            "truncated": truncated,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn action(params: Value, mutates: bool) -> BrokerAction {
        BrokerAction {
            tool: "http".to_string(),
            action: "request".to_string(),
            resource: None,
            mutates_state: mutates,
            parameters: params,
        }
    }

    /// One-shot HTTP/1.1 server: reads a request, replies 200 echoing the
    /// raw request head in the body (so auth-header handling is observable).
    async fn echo_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.expect("read");
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = format!("echo:{head}");
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn plain_http_is_rejected_unless_explicitly_allowed() {
        let err = HttpConnector::new()
            .execute(
                &action(json!({"url": "http://internal.example/status"}), false),
                None,
            )
            .await
            .expect_err("https-only connector must reject http://");
        assert!(err.to_string().contains("https required"));
    }

    #[tokio::test]
    async fn caller_supplied_authorization_headers_are_refused() {
        let err = HttpConnector::new()
            .execute(
                &action(
                    json!({
                        "url": "https://api.example/thing",
                        "headers": {"AUTHORIZATION": "Bearer stolen"},
                    }),
                    false,
                ),
                None,
            )
            .await
            .expect_err("caller Authorization must be refused");
        assert!(err.to_string().contains("broker-managed"));
    }

    #[tokio::test]
    async fn mutating_methods_require_mutates_state() {
        let err = HttpConnector::new()
            .execute(
                &action(
                    json!({"url": "https://api.example/thing", "method": "DELETE"}),
                    false,
                ),
                None,
            )
            .await
            .expect_err("DELETE without mutates_state must fail");
        assert!(err.to_string().contains("mutates_state"));
    }

    #[tokio::test]
    async fn the_credential_rides_the_auth_header_and_sanitize_scrubs_the_echo() {
        let (base_url, server) = echo_server().await;
        let secret = Secret::new("tok_live_supersecret");
        let raw = HttpConnector::allowing_plain_http()
            .execute(&action(json!({"url": base_url}), false), Some(&secret))
            .await
            .expect("request against local echo server");
        // The wire really carried the bearer token (the echo proves it)…
        assert!(raw.output["body"]
            .as_str()
            .expect("body")
            .contains("authorization: Bearer tok_live_supersecret"));
        // …and sanitize removes every trace before anything leaves the broker.
        let sanitized = raw.sanitize(&[&secret]);
        assert!(!sanitized.to_string().contains("tok_live_supersecret"));
        server.await.expect("server task");
    }
}
