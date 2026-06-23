#![recursion_limit = "512"]

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use uuid::Uuid;

use gateway::admission;
use gateway::audit_batch;
use gateway::db;
use gateway::error::StatusError;
use gateway::events;
use gateway::gh_checks;
use gateway::gh_comment;
use gateway::jobs;
use gateway::metrics;
use gateway::mtls;
use gateway::otel;
use gateway::policy;
use gateway::policy_watcher;
use gateway::qdrant;
use gateway::routes;
use gateway::splunk_export;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use routes::AppState;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use tokio_rustls::TlsAcceptor;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Gateway version — kept in sync with Cargo.toml.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build-time git hash (set by CI or defaults to "dev").
fn build_hash() -> &'static str {
    match option_env!("AEGIS_BUILD_HASH") {
        Some(h) => h,
        None => "dev",
    }
}

/// GET /health — readiness probe. Pings the database (`SELECT 1`) so the result
/// reflects real serviceability: `200 healthy` only when the DB answers, else
/// `503 unhealthy` (fail-closed, so an orchestrator won't route traffic to a
/// gateway that can't reach its store).
async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.storage.health_check().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "healthy",
                "version": VERSION,
                "db": "up",
            })),
        ),
        Err(e) => {
            tracing::warn!("health check DB ping failed: {:?}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "unhealthy",
                    "version": VERSION,
                    "db": "down",
                })),
            )
        }
    }
}

/// GET /livez — Kubernetes liveness probe (#1208). Always returns 200 if the
/// HTTP server is able to handle requests at all; an orchestrator should
/// restart the pod if this stops responding. Deliberately does no I/O (no DB,
/// no locks) so a wedged dependency cannot make a healthy process look dead.
async fn livez_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "alive"})))
}

/// GET /readyz — Kubernetes readiness probe (#1208). Returns 200 only when the
/// database is reachable and every tracked background task (#1152: event
/// drain, audit-batch writer, periodic jobs) is still running, so an
/// orchestrator stops routing traffic to a gateway that can't serve requests
/// or has silently lost a background subsystem (fail-closed).
async fn readyz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let audit_writer_status = if state
        .audit_writer_unhealthy
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        "down"
    } else {
        "up"
    };
    let dead_background_tasks: Vec<&str> = {
        let lock = state
            .background_task_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        lock.iter()
            .filter(|(_, handle)| handle.is_finished())
            .map(|(name, _)| *name)
            .collect()
    };
    let background_tasks_status = if dead_background_tasks.is_empty() {
        "up"
    } else {
        "down"
    };

    match state.storage.health_check().await {
        Ok(()) if dead_background_tasks.is_empty() => (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "db": "up",
                "audit_writer": audit_writer_status,
                "background_tasks": background_tasks_status,
            })),
        ),
        Ok(()) => {
            tracing::error!(
                "readyz check found dead background tasks: {:?}",
                dead_background_tasks
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "db": "up",
                    "audit_writer": audit_writer_status,
                    "background_tasks": background_tasks_status,
                    "dead_background_tasks": dead_background_tasks,
                })),
            )
        }
        Err(e) => {
            tracing::warn!("readyz check DB ping failed: {:?}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "db": "down",
                    "audit_writer": audit_writer_status,
                    "background_tasks": background_tasks_status,
                    "dead_background_tasks": dead_background_tasks,
                })),
            )
        }
    }
}

/// GET /startupz — Kubernetes startup probe (#1208). Returns 200 once initial
/// startup (DB pool + migrations + policy engine + background jobs) has
/// completed; until then returns 503 so slow-starting instances aren't killed
/// by the liveness probe before they finish initializing.
async fn startupz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state
        .startup_complete
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        (StatusCode::OK, Json(json!({"status": "started"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "starting"})),
        )
    }
}

/// GET /v1/version — build metadata for deployment verification.
async fn version_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "version": VERSION,
            "build_hash": build_hash(),
            "name": "aegis-gateway",
        })),
    )
}

/// Builds the panic handler for [`CatchPanicLayer::custom`] (#1153). Logs the
/// panic payload at ERROR level, increments `aegis_handler_panics_total`, and
/// returns a structured 500 JSON body instead of dropping the connection.
fn panic_response(
    state: Arc<AppState>,
) -> impl Fn(Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response + Clone {
    move |err: Box<dyn std::any::Any + Send + 'static>| {
        let detail = if let Some(s) = err.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = err.downcast_ref::<&str>() {
            s.to_string()
        } else {
            "unknown panic".to_string()
        };
        error!("handler panicked: {}", detail);
        state.metrics.inc_handler_panic();

        StatusError::internal("Internal server error").into_response()
    }
}

/// Error handler for the load-shed layer (#911): `tower::load_shed::LoadShedLayer`
/// wraps `tower::limit::ConcurrencyLimitLayer`, so the only error this ever
/// sees in practice is `tower::load_shed::error::Overloaded` once
/// `AEGIS_MAX_CONCURRENT_REQUESTS` in-flight requests are already being
/// served — converted to a structured `503` instead of axum's bare-string
/// default. `BoxError` is intentionally treated as a catch-all "unavailable"
/// rather than propagating the inner debug string, which could leak
/// implementation details.
async fn handle_overload_error(_err: tower::BoxError) -> impl IntoResponse {
    StatusError::service_unavailable(
        "Server is at capacity (AEGIS_MAX_CONCURRENT_REQUESTS); try again shortly",
    )
}

/// GET /metrics — Prometheus text exposition of process-wide security counters.
/// Bound only on the existing 127.0.0.1 listener; no new bind, no public exposure.
/// Labels are omitted to avoid leaking tenant/agent identifiers.
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut body = state.metrics.render_prometheus();
    // REL-004 (#1150): point-in-time pool gauges, read directly from the live
    // pool at scrape time — no separate sampling/storage needed for these two
    // (unlike `db_pool_acquire_wait_seconds`, which needs a timed probe and is
    // rendered as part of `render_prometheus` above).
    let idle = state.storage.get_pool().num_idle() as u32;
    let active = state.storage.get_pool().size().saturating_sub(idle);
    body.push_str(&format!(
        "# HELP db_pool_connections_active Number of SQLite pool connections currently checked out\n\
         # TYPE db_pool_connections_active gauge\n\
         db_pool_connections_active {active}\n\
         # HELP db_pool_connections_idle Number of SQLite pool connections currently idle\n\
         # TYPE db_pool_connections_idle gauge\n\
         db_pool_connections_idle {idle}\n"
    ));
    // #1286: Splunk HEC export connection health — advisory only, mirrors
    // the pool gauges above (read directly from live process state, no
    // separate sampling). Reports zero values when Splunk export is not
    // configured at all, same as an export job that simply hasn't run yet.
    let splunk_health = splunk_export::global_health();
    body.push_str(&format!(
        "# HELP splunk_hec_export_consecutive_failures Consecutive failed Splunk HEC batch dispatches\n\
         # TYPE splunk_hec_export_consecutive_failures gauge\n\
         splunk_hec_export_consecutive_failures {}\n\
         # HELP splunk_hec_export_last_success_unix_secs Unix timestamp of the last successful Splunk HEC batch dispatch (0 if never)\n\
         # TYPE splunk_hec_export_last_success_unix_secs gauge\n\
         splunk_hec_export_last_success_unix_secs {}\n",
        splunk_health.consecutive_failures(),
        splunk_health.last_success_unix_secs(),
    ));
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// First-call-wins approximation of process start, used only to compute the
/// scheduler utilization ratio on `GET /debug/runtime` — a few milliseconds
/// of skew between actual process start and the first request doesn't matter
/// for a debug endpoint, and avoids threading a new field through every
/// `AppState` construction site (14 across gateway/src, mostly test helpers)
/// just for this one derived metric.
static RUNTIME_METRICS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// GET /debug/runtime (#1160) — Tokio runtime introspection, mirroring
/// Kubernetes' `/debug/pprof` convention for an in-process diagnostics
/// endpoint. Bound only on the existing 127.0.0.1 listener; no new bind, no
/// public exposure (same invariant as `/metrics`). Requires the
/// `tokio_unstable` cfg (set repo-wide via `.cargo/config.toml`) for
/// per-worker poll/busy-duration counters — `num_alive_tasks`/
/// `global_queue_depth` alone are stable, but "total polls" and "scheduler
/// utilization" are not derivable without it.
async fn debug_runtime_handler() -> impl IntoResponse {
    let start = *RUNTIME_METRICS_START.get_or_init(std::time::Instant::now);
    let metrics = tokio::runtime::Handle::current().metrics();
    let workers_count = metrics.num_workers();

    let mut total_poll_count: u64 = 0;
    let mut total_busy_duration = std::time::Duration::ZERO;
    for worker in 0..workers_count {
        total_poll_count += metrics.worker_poll_count(worker);
        total_busy_duration += metrics.worker_total_busy_duration(worker);
    }

    let elapsed = start.elapsed();
    let scheduler_utilization = if elapsed.is_zero() || workers_count == 0 {
        0.0
    } else {
        (total_busy_duration.as_secs_f64() / (elapsed.as_secs_f64() * workers_count as f64))
            .clamp(0.0, 1.0)
    };

    Json(json!({
        "active_tasks_count": metrics.num_alive_tasks(),
        "workers_count": workers_count,
        "total_poll_count": total_poll_count,
        "global_queue_depth": metrics.global_queue_depth(),
        "scheduler_utilization": scheduler_utilization,
        "uptime_secs": elapsed.as_secs_f64(),
    }))
}

/// Middleware: propagate or generate X-Request-ID on every request/response.
/// If the client sends an `X-Request-ID` header, it is forwarded through the
/// response. Otherwise a new UUID v4 is generated and attached. This enables
/// distributed tracing and log correlation across SDK ↔ gateway calls.
async fn request_id_middleware(mut request: Request<Body>, next: Next) -> impl IntoResponse {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Inject into request extensions so handlers can access it if needed.
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert("x-request-id", val);
    }

    let mut response = next.run(request).await;

    // Propagate the same ID on the response for client correlation.
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }
    response
}

/// Middleware: reject non-GET requests that send a body without a JSON Content-Type.
/// GET, HEAD, OPTIONS, and DELETE requests without a body are exempt. This ensures
/// that POST/PUT/PATCH payloads are always JSON (defense against content-type confusion).
async fn content_type_validation_middleware(
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let method = request.method().clone();
    let has_body = !matches!(
        method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE
    );

    if has_body {
        let content_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Allow JSON and empty content types (for requests with no body)
        let content_length = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        // #1276: Slack interactive-component callbacks POST
        // `application/x-www-form-urlencoded`, not JSON — exempt this one
        // path (its own HMAC signature check, not this content-type gate, is
        // what authenticates the request).
        let is_slack_callback = request.uri().path() == "/v1/callbacks/slack"
            && content_type.contains("application/x-www-form-urlencoded");

        if content_length > 0 && !content_type.contains("application/json") && !is_slack_callback {
            return StatusError::unsupported_media_type("Content-Type must be application/json")
                .into_response();
        }
    }

    next.run(request).await.into_response()
}

/// Bodies larger than this fail closed with a 500 rather than being hashed.
/// Every current GET handler already bounds its output via an explicit
/// `LIMIT` (see `database_migration.md`'s tenant-scoped pagination
/// guidance), so in practice no real response approaches this cap — it
/// exists to bound memory use, not to special-case a body the gateway
/// actually expects to produce. Once `axum::body::to_bytes` exceeds its
/// limit the underlying stream is already partially consumed, so there is
/// no safe "pass the original body through untouched" fallback to fall back
/// to; failing the request outright is the honest behavior.
const ETAG_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Middleware: ETag-based conditional caching for GET endpoints (#1141).
///
/// Hashes the response body (SHA-256) and sets it as a quoted `ETag`. A
/// request whose `If-None-Match` matches gets a `304 Not Modified` with an
/// empty body instead of the full payload. Applies generically to every GET
/// route rather than an endpoint-specific allow-list — any GET response
/// benefits, and there's no per-route logic to keep in sync as routes are
/// added.
///
/// Scoped to GET + a 200 response only: POST/PUT/PATCH/DELETE are mutating
/// and must not be cached, and non-200 responses (errors, the `/v1/ws/events`
/// 101 upgrade) are passed through untouched. Placed before the compression
/// layer in the middleware stack so the hash covers the canonical
/// (uncompressed) body, not compression-algorithm-dependent bytes.
async fn etag_middleware(request: Request<Body>, next: Next) -> impl IntoResponse {
    let is_get = request.method() == Method::GET;
    let if_none_match = request
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let response = next.run(request).await;

    if !is_get || response.status() != StatusCode::OK {
        return response;
    }

    let (parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, ETAG_MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return StatusError::internal("Internal server error").into_response();
        }
    };

    use sha2::{Digest, Sha256};
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&bytes)));

    if if_none_match.as_deref() == Some(etag.as_str()) {
        let mut not_modified = axum::response::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        if let Ok(val) = HeaderValue::from_str(&etag) {
            not_modified.headers_mut().insert(header::ETAG, val);
        }
        return not_modified;
    }

    let mut response = axum::response::Response::from_parts(parts, Body::from(bytes));
    if let Ok(val) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, val);
    }
    response
}

/// Build the CORS layer from AEGIS_CORS_ORIGINS env var.
/// - If unset: no CORS headers (default, most restrictive).
/// - If set: parse comma-separated origins (e.g. "http://localhost:3000,https://app.example.com").
///
/// Wildcard origins ("*") are intentionally NOT supported — per security guidelines,
/// only trusted, specific origins may access resources.
fn cors_layer() -> CorsLayer {
    let origins_env = std::env::var("AEGIS_CORS_ORIGINS").unwrap_or_default();
    if origins_env.is_empty() {
        return CorsLayer::new(); // No CORS headers = most restrictive default
    }

    let origins: Vec<HeaderValue> = origins_env
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed == "*" {
                // Security: reject wildcard origins per mandatory-secure-web-skills
                tracing::warn!(
                    "AEGIS_CORS_ORIGINS contains wildcard '*' — ignored for security. \
                     Specify exact origins instead."
                );
                None
            } else {
                trimmed.parse().ok()
            }
        })
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::HeaderName::from_static("x-request-id"),
            header::HeaderName::from_static("x-aegis-tenant-id"),
        ])
}

use std::io::{self, Write};

pub struct RedactingWriter<W> {
    inner: W,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            let redacted = redact_secrets(s);
            self.inner.write_all(redacted.as_bytes())?;
            Ok(buf.len())
        } else {
            self.inner.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct RedactingMakeWriter<M> {
    inner: M,
}

impl<'a, M> tracing_subscriber::fmt::writer::MakeWriter<'a> for RedactingMakeWriter<M>
where
    M: tracing_subscriber::fmt::writer::MakeWriter<'a> + 'static,
{
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
        }
    }
}

fn redact_secrets(input: &str) -> String {
    // 1. Try to parse the entire input as JSON.
    if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(input) {
        redact_json_value(&mut json_val);
        if let Ok(serialized) = serde_json::to_string(&json_val) {
            return serialized;
        }
    }

    // 2. If it is not valid JSON, or JSON serialization/parsing failed,
    // do plain text / URL / pattern redaction.
    redact_plain_text(input)
}

fn redact_json_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(obj) => {
            for (key, value) in obj.iter_mut() {
                let key_lower = key.to_lowercase();
                if is_sensitive_key(&key_lower) {
                    redact_sensitive_json_value(value);
                } else {
                    redact_json_value(value);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_value(item);
            }
        }
        serde_json::Value::String(s) => {
            // Even if the key was not sensitive, the string itself might contain
            // Bearer tokens or URL query parameters (e.g., in a URL string or log message).
            *s = redact_plain_text(s);
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key,
        "agent_token"
            | "api_key"
            | "password"
            | "secret_key"
            | "client_secret"
            | "authorization"
            | "token"
    )
}

fn redact_sensitive_json_value(val: &mut serde_json::Value) {
    *val = serde_json::Value::String("[REDACTED]".to_string());
}

fn redact_plain_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    let sensitive_keys = [
        "client_secret",
        "agent_token",
        "secret_key",
        "authorization",
        "api_key",
        "password",
        "token",
    ];

    while i < chars.len() {
        // 1. Check for "Bearer " or "Basic " (case-insensitive)
        let mut is_auth_prefix = false;
        let mut prefix_len = 0;
        if i + 7 <= chars.len()
            && chars[i..i + 7].iter().collect::<String>().to_lowercase() == "bearer "
        {
            is_auth_prefix = true;
            prefix_len = 7;
        } else if i + 6 <= chars.len()
            && chars[i..i + 6].iter().collect::<String>().to_lowercase() == "basic "
        {
            is_auth_prefix = true;
            prefix_len = 6;
        }

        if is_auth_prefix {
            output.push_str(&chars[i..i + prefix_len].iter().collect::<String>());
            i += prefix_len;
            // Skip spaces/quotes
            while i < chars.len()
                && (chars[i] == ' ' || chars[i] == '\t' || chars[i] == '"' || chars[i] == '\'')
            {
                output.push(chars[i]);
                i += 1;
            }
            let mut redacted = false;
            while i < chars.len() {
                let c = chars[i];
                if c == ' '
                    || c == '\t'
                    || c == ','
                    || c == '"'
                    || c == '\''
                    || c == '\n'
                    || c == '\r'
                    || c == '}'
                    || c == ']'
                    || c == ')'
                    || c == '\\'
                {
                    break;
                }
                if !redacted {
                    output.push_str("[REDACTED]");
                    redacted = true;
                }
                i += 1;
            }
            continue;
        }

        // 2. Check for sensitive keys
        let mut matched = false;
        for key in &sensitive_keys {
            if let Some(after_key) = match_key_at(&chars, i, key) {
                // We found a match for the key. Let's see if it's followed by : or =
                let mut j = after_key;
                // Skip spaces or closing quotes
                while j < chars.len()
                    && (chars[j] == ' ' || chars[j] == '\t' || chars[j] == '"' || chars[j] == '\'')
                {
                    j += 1;
                }
                if j < chars.len() && (chars[j] == ':' || chars[j] == '=') {
                    // It is followed by a separator! Let's find the value
                    j += 1; // skip separator
                    let mut value_start = j;
                    // Skip spaces or opening quotes/backslashes
                    while value_start < chars.len() {
                        let c = chars[value_start];
                        if c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '\\' {
                            value_start += 1;
                        } else {
                            break;
                        }
                    }

                    // Check if value starts with bearer or basic (case-insensitive)
                    if value_start + 7 <= chars.len()
                        && chars[value_start..value_start + 7]
                            .iter()
                            .collect::<String>()
                            .to_lowercase()
                            == "bearer "
                    {
                        value_start += 7;
                        while value_start < chars.len() && chars[value_start] == ' ' {
                            value_start += 1;
                        }
                    } else if value_start + 6 <= chars.len()
                        && chars[value_start..value_start + 6]
                            .iter()
                            .collect::<String>()
                            .to_lowercase()
                            == "basic "
                    {
                        value_start += 6;
                        while value_start < chars.len() && chars[value_start] == ' ' {
                            value_start += 1;
                        }
                    }

                    let mut value_end = value_start;
                    while value_end < chars.len() {
                        let c = chars[value_end];
                        if c == ' '
                            || c == '\t'
                            || c == '&'
                            || c == '#'
                            || c == ','
                            || c == '}'
                            || c == ']'
                            || c == ')'
                            || c == '"'
                            || c == '\''
                            || c == '\n'
                            || c == '\r'
                            || c == '\\'
                        {
                            break;
                        }
                        value_end += 1;
                    }

                    if value_end > value_start {
                        // Push key and separators/quotes up to value_start
                        output.push_str(&chars[i..value_start].iter().collect::<String>());
                        output.push_str("[REDACTED]");
                        i = value_end;
                        matched = true;
                        break;
                    }
                }
            }
        }

        if matched {
            continue;
        }

        output.push(chars[i]);
        i += 1;
    }
    output
}

fn match_key_at(chars: &[char], i: usize, key: &str) -> Option<usize> {
    if i + key.len() > chars.len() {
        return None;
    }
    for (offset, c) in key.chars().enumerate() {
        if chars[i + offset].to_lowercase().next() != c.to_lowercase().next() {
            return None;
        }
    }
    Some(i + key.len())
}

fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Registrations
        .route("/agents/register", post(routes::register_agent))
        .route("/agents", get(routes::list_agents))
        .route(
            "/agents/risk-scoreboard",
            get(routes::get_agent_risk_scoreboard),
        )
        .route(
            "/agents/:id",
            get(routes::get_agent)
                .patch(routes::patch_agent)
                .delete(routes::delete_agent),
        )
        .route("/tools", post(routes::register_tool))
        .route(
            "/mcp/servers",
            get(routes::list_mcp_servers).post(routes::register_mcp_server),
        )
        .route(
            "/mcp/servers/:server_key",
            get(routes::get_mcp_server)
                .put(routes::update_mcp_server)
                .delete(routes::delete_mcp_server),
        )
        .route(
            "/mcp/servers/:server_key/tools",
            get(routes::get_mcp_tool_manifest).post(routes::discover_mcp_tools),
        )
        .route(
            "/mcp/servers/:server_key/tools/:tool_key/approve",
            post(routes::approve_mcp_tool),
        )
        .route(
            "/mcp/servers/:server_key/tools/:tool_key/disable",
            post(routes::disable_mcp_tool),
        )
        .route(
            "/mcp/servers/:server_key/inspect",
            post(routes::inspect_mcp_response),
        )
        .route(
            "/mcp/servers/:server_key/manifest-history",
            get(routes::get_mcp_manifest_history),
        )
        // Policy / Interception
        .route("/authorize", post(routes::authorize_action))
        // SOC-004 (#1187): agentless ingestion of external event sources
        .route("/ingest", post(routes::ingest_event))
        // #1381: dedicated GitHub App webhook receiver with HMAC-SHA256 verification
        .route("/webhooks/github", post(routes::receive_github_webhook))
        .route("/decisions", get(routes::list_decisions))
        .route("/decisions/:id", get(routes::get_decision))
        .route(
            "/policies",
            get(routes::list_policies).post(routes::create_policy),
        )
        .route(
            "/policies/:id",
            put(routes::update_policy).delete(routes::delete_policy),
        )
        .route("/policies/:id/rollback", post(routes::rollback_policy))
        .route("/policies/reload", post(routes::reload_global_policies))
        .route("/policies/audit-log", get(routes::list_policy_audit_log))
        .route("/policies/bundles", post(routes::upload_policy_bundle))
        .route(
            "/tenants/risk-weights",
            get(routes::get_tenant_risk_weights).put(routes::put_tenant_risk_weights),
        )
        .route(
            "/tenants/risk-escalation",
            get(routes::get_tenant_risk_escalation_config)
                .put(routes::put_tenant_risk_escalation_config),
        )
        .route(
            "/webhook_subscriptions",
            get(routes::list_webhook_subscriptions).post(routes::create_webhook_subscription),
        )
        .route(
            "/webhook_subscriptions/:id",
            delete(routes::delete_webhook_subscription),
        )
        .route(
            "/detection_rules",
            get(routes::list_detection_rules).post(routes::upsert_detection_rule),
        )
        .route(
            "/detection_rules/:id",
            delete(routes::delete_detection_rule),
        )
        .route(
            "/soc/rules",
            get(routes::get_soc_rules).post(routes::create_soc_rule),
        )
        .route("/soc/rules/reload", post(routes::reload_soc_rules))
        .route(
            "/soc/rules/:rule_key/backtest",
            post(routes::backtest_soc_rule),
        )
        // #1272: Evidence Graph Query API
        .route("/graph/run/:run_id", get(routes::get_graph_for_run))
        .route(
            "/graph/incident/:incident_id",
            get(routes::get_graph_for_incident),
        )
        .route("/graph/agent/:agent_id", get(routes::get_graph_for_agent))
        .route(
            "/api_keys",
            get(routes::list_api_keys).post(routes::create_api_key),
        )
        .route("/api_keys/:id/revoke", post(routes::revoke_api_key))
        // Approvals
        .route("/approvals", get(routes::list_approvals))
        .route("/approvals/:id", get(routes::get_approval))
        .route("/approvals/:id/approve", post(routes::approve_approval))
        .route("/approvals/:id/reject", post(routes::reject_approval))
        .route("/approvals/:id/edit", post(routes::edit_approval))
        .route("/approvals/:id/consume", post(routes::consume_approval))
        // Slack interactive-component callback (#1276)
        .route("/callbacks/slack", post(routes::slack_callback))
        // Audits
        .route("/runs/:id/timeline", get(routes::get_timeline))
        .route("/audit/events", get(routes::get_audit_events))
        // Verifiable action receipts
        .route("/receipts", get(routes::list_receipts))
        .route("/receipts/:id", get(routes::get_receipt))
        .route("/receipts/:id/verify", get(routes::verify_receipt))
        .route("/receipts/verify-chain", post(routes::verify_receipt_chain))
        // SOC Phase 5: Indexer Query API — paginated, tenant-scoped SOC views
        .route("/alerts", get(routes::list_alerts))
        .route("/incidents", get(routes::list_incidents))
        // SOC query layer: incident detail + aggregate summary
        .route("/incidents/:id", get(routes::get_incident))
        .route("/soc/summary", get(routes::soc_summary))
        .route("/soc/semantic-search", get(routes::semantic_search))
        // SOC Phase 6: Incident lifecycle — close an open incident
        .route("/incidents/:id/close", post(routes::close_incident))
        // SOC Phase 6: RCA Narrator
        .route("/incidents/:id/narrate", get(routes::narrate_incident))
        // SOC-006 (#1189): per-incident compliance evidence pack export
        .route(
            "/incidents/:id/evidence-pack",
            get(routes::get_incident_evidence_pack),
        )
        // SOC Phase 4: Response API — agent freeze/revoke/quarantine, MCP quarantine
        .route("/agents/:id/freeze", post(routes::freeze_agent))
        .route("/agents/:id/unfreeze", post(routes::unfreeze_agent))
        .route("/agents/:id/revoke", post(routes::revoke_agent))
        .route("/agents/:id/restore", post(routes::restore_agent))
        // #1295: agent token rotation (manual + leak-report auto-rotation)
        .route("/agents/:id/rotate-token", post(routes::rotate_agent_token))
        .route(
            "/agents/:id/report-leaked-token",
            post(routes::report_leaked_agent_token),
        )
        .route(
            "/agents/:id/permissions",
            get(routes::list_agent_tool_permissions).post(routes::grant_agent_tool_permission),
        )
        .route(
            "/agents/:id/permissions/:tool_key",
            delete(routes::revoke_agent_tool_permission),
        )
        .route(
            "/mcp/servers/:server_key/quarantine",
            post(routes::quarantine_mcp_server),
        )
        .route(
            "/mcp/servers/:server_key/restore",
            post(routes::restore_mcp_server),
        )
        // Tenants
        .route("/tenants", post(routes::create_tenant))
        .route(
            "/tenants/:id",
            get(routes::get_tenant).delete(routes::delete_tenant),
        )
        .route("/tenants/:id/export", get(routes::export_tenant))
        // Compliance Evidence Pack (#1298)
        .route("/compliance/evidence-pack", get(routes::get_evidence_pack))
        // WebSocket live event stream
        .route("/ws/events", get(routes::ws_events))
        // Statistics
        .route("/stats", get(routes::get_tenant_stats))
        .route("/admin/db-stats", get(routes::get_db_stats))
        .route("/admin/backup", post(routes::create_db_backup))
        // OpenAPI Specification
        .route("/openapi.json", get(routes::get_openapi_spec))
        .route("/version", get(version_handler))
}

fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_private_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No private key found"))?;
    Ok(key)
}

/// #1310: defensive strip of any client-supplied mTLS-CN header on the
/// plain-HTTP serving path, which has no TLS handshake to verify a
/// certificate against and therefore nothing legitimate to put there.
async fn strip_mtls_cn_header(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    req.headers_mut().remove(mtls::MTLS_CN_HEADER);
    next.run(req).await
}

/// Self-healthcheck for the distroless runtime image (#1207): no shell, no
/// `curl`, no package manager in `gcr.io/distroless/cc-debian12` — Docker's
/// `HEALTHCHECK` directive instead execs this binary with `--healthcheck`,
/// which GETs the already-running gateway's own `/livez` and exits 0/1.
async fn check_liveness(bind_addr: &str) -> bool {
    let url = format!("http://{bind_addr}/livez");
    matches!(
        reqwest::Client::new().get(&url).send().await,
        Ok(resp) if resp.status().is_success()
    )
}
#[tokio::main]
#[allow(deprecated)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `--healthcheck` short-circuits before any of the normal startup (DB
    // connect, migrations, tracing) — see `check_liveness` above. Not a
    // security/identity decision (Semgrep's generic argv rule is about
    // trusting argv[0] as a path/identity, which this isn't) — it only
    // selects which of two equally-unprivileged code paths to run; the
    // healthcheck path itself does nothing but GET its own /livez.
    // nosemgrep: rust.lang.security.args.args
    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        let bind_addr =
            std::env::var("AEGIS_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        std::process::exit(if check_liveness(&bind_addr).await {
            0
        } else {
            1
        });
    }

    // #1156: distributed tracing, gated on AEGIS_OTLP_ENDPOINT. `None` when
    // unset — entirely inert, see `otel::init_tracer_provider`'s doc comment.
    let otel_tracer_provider = otel::init_tracer_provider();
    let otel_layer = otel::tracing_layer(&otel_tracer_provider);

    // Initialize tracing with structured JSON logging and log redaction
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,gateway=debug,sqlx=info".into()),
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(RedactingMakeWriter {
                    inner: std::io::stdout,
                }),
        )
        .with(otel_layer);

    tracing::subscriber::set_global_default(subscriber).expect("Unable to set global subscriber");

    info!("Starting AegisAgent Control Plane v{}...", VERSION);

    // Validate JWT secret requirements. AEGIS_JWT_SECRET may be a single
    // secret or a comma-separated list (#1211: zero-downtime rotation — set
    // "new_secret,old_secret" during a rotation window, drop the old entry
    // once it's no longer needed); `jwt_secret_candidates` filters out
    // empty/"default_secret" entries so only real keys count here.
    let jwt_required = std::env::var("AEGIS_JWT_REQUIRED")
        .map(|v| v == "true")
        .unwrap_or(false);
    if jwt_required {
        let jwt_secret = std::env::var("AEGIS_JWT_SECRET").map_err(|_| {
            "AEGIS_JWT_SECRET environment variable must be set when AEGIS_JWT_REQUIRED is true."
        })?;
        if routes::jwt_secret_candidates(&jwt_secret).is_empty() {
            return Err("AEGIS_JWT_SECRET cannot be empty or 'default_secret' when AEGIS_JWT_REQUIRED is true.".into());
        }
    } else if let Ok(jwt_secret) = std::env::var("AEGIS_JWT_SECRET") {
        if routes::jwt_secret_candidates(&jwt_secret).is_empty() {
            tracing::warn!("AEGIS_JWT_SECRET is set to an empty or default value ('default_secret'). JWT validation will be disabled for security.");
        }
    } else {
        tracing::warn!("AEGIS_JWT_SECRET is not set. JWT validation will be disabled.");
    }

    // Database setup (local SQLite file)
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://aegis.db".into());
    info!("Initializing SQLite database pool at: {} ...", db_url);
    // #1164 (TEST-004, AC #3): a corrupted/unreadable database file must be
    // logged before the startup error propagates, not just silently bubble
    // up via `?` — this is the only place `init_db`'s error is first seen.
    let pool = db::init_db(&db_url).await.map_err(|e| {
        tracing::error!("Failed to initialize database pool at {}: {:?}", db_url, e);
        e
    })?;

    // Load Cedar Policy engine from file
    let policy_path =
        std::env::var("CEDAR_POLICY_PATH").unwrap_or_else(|_| "policies.cedar".into());
    info!("Loading Cedar policies from: {} ...", policy_path);
    let policy_engine = policy::PolicyEngine::init(&policy_path).await?;

    // Optional Qdrant exporter initialization
    let qdrant_exporter = if let Ok(qdrant_url) = std::env::var("AEGIS_QDRANT_URL") {
        info!(
            "Qdrant URL set to: {}. Initializing semantic indexing exporter...",
            qdrant_url
        );

        let qdrant_api_key = std::env::var("AEGIS_QDRANT_API_KEY").ok();
        let collection_name = std::env::var("AEGIS_QDRANT_COLLECTION")
            .unwrap_or_else(|_| "aegis_audit_events".to_string());

        let strategy =
            std::env::var("AEGIS_EMBEDDING_STRATEGY").unwrap_or_else(|_| "api".to_string());

        let model_name = std::env::var("AEGIS_EMBEDDING_MODEL")
            .unwrap_or_else(|_| "text-embedding-3-small".to_string());

        let dimension = std::env::var("AEGIS_EMBEDDING_DIMENSION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1536);

        // Build embedding model strategy
        let embedding_model: Arc<dyn qdrant::EmbeddingModel> = if strategy == "local" {
            #[cfg(feature = "local-embeddings")]
            {
                info!(
                    "Using in-process ONNX local embedding model: {}",
                    model_name
                );
                let fastembed_model = fastembed::TextEmbedding::try_new(
                    fastembed::InitOptions::new(fastembed::EmbeddingModel::AllMiniLML6V2)
                        .with_show_download_progress(false),
                )?;
                Arc::new(qdrant::LocalEmbeddingModel {
                    model: fastembed_model,
                    dimension,
                })
            }
            #[cfg(not(feature = "local-embeddings"))]
            {
                return Err("AEGIS_EMBEDDING_STRATEGY is set to 'local', but 'local-embeddings' feature was not compiled.".into());
            }
        } else {
            // API strategy
            let embedding_url = std::env::var("AEGIS_EMBEDDING_URL")
                .unwrap_or_else(|_| "https://api.openai.com/v1/embeddings".to_string());
            let embedding_key = std::env::var("AEGIS_EMBEDDING_KEY").ok();
            info!(
                "Using OpenAI-compatible HTTP embedding client (URL: {}, Model: {})",
                embedding_url, model_name
            );

            Arc::new(qdrant::HttpEmbeddingModel {
                client: reqwest::Client::new(),
                url: embedding_url,
                key: embedding_key,
                model: model_name,
                dimension,
            })
        };

        // Build Qdrant client
        let mut builder = qdrant_client::Qdrant::from_url(&qdrant_url);
        if let Some(ref api_key) = qdrant_api_key {
            builder = builder.api_key(api_key.as_str());
        }
        let qdrant_client = builder.build()?;

        let exporter = qdrant::QdrantExporter::new(qdrant_client, embedding_model, collection_name);

        // Initialize Qdrant collection
        if let Err(e) = exporter.init_collection().await {
            tracing::error!("Failed to initialize Qdrant collection: {:?}", e);
            return Err(e as Box<dyn std::error::Error>);
        }

        Some(Arc::new(exporter))
    } else {
        None
    };

    // Async SOC event stream (Phase 0 keystone): the authorize hot path emits
    // non-blocking onto this channel; a background task drains it. Every later
    // SOC phase (detection, correlation, response, indexing) consumes this one
    // stream and never touches the inline path.
    // Phase 5: pass pool.clone() so the drain can persist alerts + incidents.
    let metrics = Arc::new(metrics::SecurityMetrics::new());

    // #1287: OTLP metrics export, gated on the same AEGIS_OTLP_ENDPOINT as
    // tracing above. `None` when unset — entirely inert, see
    // `otel::init_meter_provider`'s doc comment.
    let otel_meter_provider = otel::init_meter_provider(metrics.clone());

    let (events, events_rx) = events::EventSink::channel(events::DEFAULT_CAPACITY, metrics.clone());
    let drain_handle = tokio::spawn(events::drain(
        events_rx,
        pool.clone(),
        metrics.clone(),
        qdrant_exporter.clone(),
    ));
    let drain_abort_handle = drain_handle.abort_handle();

    // #1315: audit-event write batching. The authorize hot path hands
    // non-critical `audit_events` rows to this sink; a background task
    // flushes them in bulk via `insert_audit_events_batch` once `batch_size`
    // rows are buffered or `flush_interval` elapses. `audit_writer_unhealthy`
    // is shared (`Arc`) so a failed flush surfaces on GET /readyz exactly
    // like a failed synchronous write.
    let audit_writer_unhealthy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (audit_batch, audit_batch_rx) =
        audit_batch::AuditBatchSink::channel(audit_batch::DEFAULT_CAPACITY);
    let audit_batch_handle = tokio::spawn(audit_batch::run_audit_batch_writer(
        pool.clone(),
        audit_batch_rx,
        audit_batch::batch_size_from_env(),
        audit_batch::flush_interval_from_env(),
        audit_writer_unhealthy.clone(),
    ));
    let audit_batch_abort_handle = audit_batch_handle.abort_handle();

    // REL-003 (#1149): SQLite advisory-lock-based leader election so multiple
    // gateway instances sharing one DB don't all run the maintenance jobs
    // below concurrently. `is_leader` starts false (fail-safe: no instance
    // runs maintenance work until the first election tick confirms it).
    let is_leader = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let instance_id = Uuid::new_v4().to_string();
    let leader_election_interval_secs: u64 = std::env::var("AEGIS_LEADER_ELECTION_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_LEADER_ELECTION_INTERVAL_SECS);
    let leader_lease_secs: i64 = std::env::var("AEGIS_LEADER_LEASE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_LEADER_LEASE_SECS);
    let leader_election_abort_handle = tokio::spawn(jobs::run_leader_election_loop(
        pool.clone(),
        instance_id,
        is_leader.clone(),
        leader_election_interval_secs,
        chrono::Duration::seconds(leader_lease_secs),
    ))
    .abort_handle();

    // #0107: periodic receipt chain integrity check across all tenants. Any
    // broken link or hash mismatch is recorded as a critical SOC alert.
    // Gated on is_leader (#1149) — see run_leader_election_loop above.
    let receipt_integrity_interval_secs: u64 =
        std::env::var("AEGIS_RECEIPT_INTEGRITY_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(jobs::DEFAULT_INTERVAL_SECS);
    let receipt_integrity_abort_handle = tokio::spawn(jobs::run_receipt_chain_integrity_job(
        pool.clone(),
        receipt_integrity_interval_secs,
        is_leader.clone(),
    ))
    .abort_handle();

    // #0106: periodically archive old audit_events rows into
    // audit_events_archive to keep the live table bounded. Gated on
    // is_leader (#1149).
    let audit_archival_interval_secs: u64 = std::env::var("AEGIS_AUDIT_ARCHIVAL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_AUDIT_ARCHIVAL_INTERVAL_SECS);
    let audit_retention_days: i64 = std::env::var("AEGIS_AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_AUDIT_RETENTION_DAYS);
    let audit_archival_abort_handle = tokio::spawn(jobs::run_audit_event_archival_job(
        pool.clone(),
        audit_archival_interval_secs,
        audit_retention_days,
        is_leader.clone(),
    ))
    .abort_handle();

    // #0105: periodically delete stale approvals (decided, or expired and
    // never decided) to keep the approvals table bounded. Gated on is_leader
    // (#1149).
    let approval_cleanup_interval_secs: u64 = std::env::var("AEGIS_APPROVAL_CLEANUP_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_APPROVAL_CLEANUP_INTERVAL_SECS);
    let approval_retention_days: i64 = std::env::var("AEGIS_APPROVAL_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_APPROVAL_RETENTION_DAYS);
    let approval_cleanup_abort_handle = tokio::spawn(jobs::run_approval_cleanup_job(
        pool.clone(),
        approval_cleanup_interval_secs,
        approval_retention_days,
        is_leader.clone(),
    ))
    .abort_handle();

    // #0061: periodically VACUUM the database to reclaim free space left
    // behind by the audit-event archival and approval-cleanup jobs' deletes.
    // Gated on is_leader (#1149).
    let vacuum_interval_secs: u64 = std::env::var("AEGIS_VACUUM_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_VACUUM_INTERVAL_SECS);
    let vacuum_abort_handle = tokio::spawn(jobs::run_vacuum_job(
        pool.clone(),
        vacuum_interval_secs,
        is_leader.clone(),
    ))
    .abort_handle();

    // REL-004 (#1150): periodically sample DB connection-pool acquire
    // latency and log a warning when the pool is over 80% busy.
    let pool_health_sample_interval_secs: u64 =
        std::env::var("AEGIS_POOL_HEALTH_SAMPLE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(jobs::DEFAULT_POOL_HEALTH_SAMPLE_INTERVAL_SECS);
    let pool_health_sampler_abort_handle = tokio::spawn(jobs::run_pool_health_sampler(
        pool.clone(),
        pool_health_sample_interval_secs,
        metrics.clone(),
    ))
    .abort_handle();

    // #1286: optional Splunk HTTP Event Collector export — only spawned when
    // both AEGIS_SPLUNK_HEC_URL and AEGIS_SPLUNK_HEC_TOKEN are configured.
    // Gated on is_leader like the other maintenance jobs above, since
    // multiple gateway instances sharing one DB must not each forward the
    // same events to Splunk redundantly.
    let splunk_export_abort_handle = splunk_export::SplunkHecConfig::from_env().map(|config| {
        info!(
            "Splunk HEC export enabled (batch interval: {}s)",
            config.batch_interval_secs
        );
        tokio::spawn(jobs::run_splunk_export_job(
            pool.clone(),
            config,
            is_leader.clone(),
        ))
        .abort_handle()
    });

    // #1511: debounces the `last_seen_at` heartbeat write off the
    // `/v1/authorize` hot path — see `routes::HeartbeatDebouncer` for why
    // this is `Arc`-shared with (not leader-gated, unlike the maintenance
    // jobs above) `jobs::run_heartbeat_flush_job`.
    let heartbeat_debouncer = Arc::new(routes::HeartbeatDebouncer::new());
    // #1512: tracks fire-and-forget background writes spawned off the
    // `/v1/authorize` hot path (historical risk-score sample, verifiable
    // receipt) — see `routes::DeferredWriteTracker`. Drained (not aborted)
    // during graceful shutdown below so a deferred write is never silently
    // lost mid-flight.
    let deferred_write_tracker = Arc::new(routes::DeferredWriteTracker::new());
    let heartbeat_flush_interval_secs: u64 = std::env::var("AEGIS_HEARTBEAT_FLUSH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_HEARTBEAT_FLUSH_INTERVAL_SECS);
    let heartbeat_flush_abort_handle = tokio::spawn(jobs::run_heartbeat_flush_job(
        pool.clone(),
        heartbeat_debouncer.clone(),
        heartbeat_flush_interval_secs,
    ))
    .abort_handle();

    // #1152: zero-I/O liveness tracking for the fire-and-forget background
    // tasks above — `AbortHandle::is_finished()` reports whether a task
    // panicked and stopped running, surfaced on GET /readyz. `drain_handle`
    // and `audit_batch_handle` themselves stay owned by this function (they
    // are awaited further down during graceful shutdown); abort handles are
    // a non-owning, freely cloneable view that doesn't interfere with that.
    let mut background_task_handles = vec![
        ("event_drain", drain_abort_handle),
        ("audit_batch_writer", audit_batch_abort_handle),
        ("leader_election_loop", leader_election_abort_handle),
        (
            "receipt_chain_integrity_job",
            receipt_integrity_abort_handle,
        ),
        ("audit_event_archival_job", audit_archival_abort_handle),
        ("approval_cleanup_job", approval_cleanup_abort_handle),
        ("vacuum_job", vacuum_abort_handle),
        ("pool_health_sampler", pool_health_sampler_abort_handle),
        ("heartbeat_flush_job", heartbeat_flush_abort_handle),
    ];
    if let Some(handle) = splunk_export_abort_handle {
        background_task_handles.push(("splunk_export_job", handle));
    }

    // Read configurable approval TTL from env (default 30 minutes = 1800 seconds)
    let approval_ttl_secs: i64 = std::env::var("AEGIS_APPROVAL_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1800);
    info!("Approval TTL: {}s", approval_ttl_secs);

    // Read rate limiting configuration
    let rate_limit_capacity: f64 = std::env::var("AEGIS_RATE_LIMIT_CAPACITY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100.0);
    let rate_limit_refill_rate: f64 = std::env::var("AEGIS_RATE_LIMIT_REFILL_RATE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10.0);
    info!(
        "Rate Limiter - Capacity: {}, Refill Rate: {} tokens/s",
        rate_limit_capacity, rate_limit_refill_rate
    );
    let rate_limiter = routes::RateLimiter::new(rate_limit_capacity, rate_limit_refill_rate);

    // Read quota configuration
    let quota_limit: u64 = std::env::var("AEGIS_QUOTA_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0); // 0 means disabled
    let quota_window_secs: u64 = std::env::var("AEGIS_QUOTA_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(86400); // 24 hours default
    if quota_limit > 0 {
        info!(
            "Request Quota: {} requests per {}s",
            quota_limit, quota_window_secs
        );
    } else {
        info!("Request Quota tracking: disabled");
    }
    let quota_manager = routes::QuotaManager::new(quota_limit, quota_window_secs);

    // Per-source-IP rate limiter for approval-decision callbacks (#1307,
    // AC#1): POST /v1/approvals/:id/{approve,reject,edit}. Defaults to the
    // issue's "max 10 attempts per IP per minute" (10 tokens, refilling at
    // 10/60 tokens/sec), configurable for tests/ops.
    let approval_callback_ip_limit_capacity: f64 =
        std::env::var("AEGIS_APPROVAL_CALLBACK_IP_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10.0);
    let approval_callback_ip_limiter = routes::RateLimiter::new(
        approval_callback_ip_limit_capacity,
        approval_callback_ip_limit_capacity / 60.0,
    );

    // Per-approval_id failed-attempt tracker for approval-decision callbacks
    // (#1307, AC#2): max 5 failed (4xx) attempts per approval_id per hour.
    let approval_attempt_limit: u64 = std::env::var("AEGIS_APPROVAL_ATTEMPT_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let approval_attempt_window_secs: u64 = std::env::var("AEGIS_APPROVAL_ATTEMPT_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    let approval_attempt_tracker =
        routes::ApprovalAttemptTracker::new(approval_attempt_limit, approval_attempt_window_secs);

    // Read-through cache for registered-action metadata (#899). Bounded LRU;
    // AEGIS_SKILL_CACHE_CAPACITY == 0 disables it.
    let skill_cache_capacity: usize = std::env::var("AEGIS_SKILL_CACHE_CAPACITY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);
    let skill_cache = routes::SkillActionCache::new(skill_cache_capacity);

    // In-memory LRU dedup cache for opt-in /v1/authorize replay-protection
    // nonces (#1306). AEGIS_REPLAY_NONCE_CACHE_CAPACITY == 0 disables it
    // (every nonce treated as unseen, i.e. no replay rejection).
    let replay_nonce_cache_capacity: usize = std::env::var("AEGIS_REPLAY_NONCE_CACHE_CAPACITY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let replay_nonce_cache = routes::ReplayNonceCache::new(replay_nonce_cache_capacity);

    // #1513: TTL cache for per-tenant composite-risk-score weights, avoiding
    // a SQLite read on (effectively) every `/v1/authorize` call for a value
    // that only changes via the rare, operator-driven
    // PUT /v1/tenants/risk-weights (which invalidates the relevant entry).
    let risk_weight_cache_ttl_secs: u64 = std::env::var("AEGIS_RISK_WEIGHTS_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(routes::DEFAULT_RISK_WEIGHTS_CACHE_TTL_SECS);
    let risk_weight_cache =
        routes::RiskWeightsCache::new(std::time::Duration::from_secs(risk_weight_cache_ttl_secs));

    // Opt-in HMAC-SHA256 secret for verifying `X-Hub-Signature-256` on
    // POST /v1/ingest requests with source: "github_webhook" (#1339). When
    // unset, signature verification is skipped (pre-#1339 behavior).
    let github_webhook_secret = std::env::var("AEGIS_GITHUB_WEBHOOK_SECRET").ok();
    if github_webhook_secret.is_none() {
        info!(
            "AEGIS_GITHUB_WEBHOOK_SECRET is not set. GitHub webhook signature \
             verification is disabled for POST /v1/ingest (source: github_webhook)."
        );
    }

    // Ed25519 verifying (public) key for POST /v1/policies/bundles (#1280).
    // When unset, the endpoint refuses every request with 501 (fail closed —
    // there's no key to verify against, so accepting a bundle unverified
    // would defeat the feature's purpose).
    let policy_signing_verifying_key = std::env::var("AEGIS_POLICY_SIGNING_KEY").ok();
    if policy_signing_verifying_key.is_none() {
        info!(
            "AEGIS_POLICY_SIGNING_KEY is not set. POST /v1/policies/bundles \
             will refuse all requests with 501."
        );
    }

    // HMAC-SHA256 signing secret for verifying X-Slack-Signature on
    // POST /v1/callbacks/slack (#1276). When unset, the endpoint refuses every
    // request with 404 (fail closed).
    let slack_signing_secret = std::env::var("AEGIS_SLACK_SIGNING_SECRET").ok();
    if slack_signing_secret.is_none() {
        info!(
            "AEGIS_SLACK_SIGNING_SECRET is not set. POST /v1/callbacks/slack \
             will refuse all requests with 404."
        );
    }

    // Optional GitHub App installation token for posting deny comments on PRs
    // (#1382). When set, a background task posts a comment on GitHub PRs when
    // an agent's PR-related action is denied. When unset, PR comments are
    // silently skipped.
    let github_pr_commenter = std::env::var("AEGIS_GITHUB_APP_TOKEN").ok().map(|token| {
        info!("AEGIS_GITHUB_APP_TOKEN set: GitHub PR deny comments are enabled.");
        std::sync::Arc::new(gh_comment::GhPrCommenter::new(token))
    });
    if github_pr_commenter.is_none() {
        info!("AEGIS_GITHUB_APP_TOKEN is not set. GitHub PR deny comments are disabled.");
    }

    // Optional GitHub Checks API client (#1383). Reuses the same installation
    // token as `github_pr_commenter` — every authorize decision on a
    // PR-related GitHub action updates an "Aegis Security Gate" check run.
    let github_checks_client = std::env::var("AEGIS_GITHUB_APP_TOKEN").ok().map(|token| {
        info!("AEGIS_GITHUB_APP_TOKEN set: GitHub check runs are enabled.");
        std::sync::Arc::new(gh_checks::GhChecksClient::new(token))
    });
    if github_checks_client.is_none() {
        info!("AEGIS_GITHUB_APP_TOKEN is not set. GitHub check runs are disabled.");
    }

    // Optional pre-authorize admission webhook (#1143, API-004). When
    // AEGIS_ADMISSION_WEBHOOK_URL is unset, every /v1/authorize call is
    // unaffected — no extra network call at all.
    let admission_webhook = admission::AdmissionWebhookClient::from_env().map(Arc::new);
    if admission_webhook.is_none() {
        info!("AEGIS_ADMISSION_WEBHOOK_URL is not set. Admission webhooks are disabled.");
    } else {
        info!("AEGIS_ADMISSION_WEBHOOK_URL set: admission webhooks are enabled.");
    }

    // Shared state (metrics are zero-initialised atomics; no heap beyond the struct)
    let state = Arc::new(AppState {
        storage: Arc::new(aegis_storage::sqlite::SqliteStorage::new(pool)),
        policy_engine,
        events,
        metrics,
        approval_ttl_secs,
        rate_limiter,
        quota_manager,
        approval_callback_ip_limiter,
        approval_attempt_tracker,
        skill_cache,
        replay_nonce_cache,
        risk_weight_cache,
        heartbeat_debouncer: heartbeat_debouncer.clone(),
        deferred_write_tracker: deferred_write_tracker.clone(),
        startup_complete: std::sync::atomic::AtomicBool::new(false),
        audit_writer_unhealthy: audit_writer_unhealthy.clone(),
        audit_batch,
        github_webhook_secret,
        policy_signing_verifying_key,
        slack_signing_secret,
        github_pr_commenter,
        github_checks_client,
        qdrant_exporter,
        admission_webhook,
        background_task_handles: std::sync::Mutex::new(background_task_handles),
    });

    // #883: Cedar policy hot-reload — opt-in background watcher that calls
    // the same reload `POST /v1/policies/reload` triggers, automatically,
    // whenever `policy_path` changes on disk. Inert unless
    // AEGIS_POLICY_HOT_RELOAD=true.
    if let Some(handle) =
        policy_watcher::spawn_policy_hot_reload_watcher(state.clone(), policy_path.clone().into())
    {
        if let Ok(mut handles) = state.background_task_handles.lock() {
            handles.push(("policy_hot_reload_watcher", handle.abort_handle()));
        }
    }

    // Read request body size limit (default 1MB)
    let body_limit = std::env::var("AEGIS_MAX_BODY_LIMIT_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1048576); // 1MB default
    info!("Request body size limit: {} bytes", body_limit);

    // Read global request timeout (default 30 seconds)
    let request_timeout_secs = std::env::var("AEGIS_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    info!("Global request timeout: {}s", request_timeout_secs);

    // #911: max in-flight requests before the load-shed layer rejects new
    // ones with 503 instead of queuing them indefinitely.
    let max_concurrent_requests: usize = std::env::var("AEGIS_MAX_CONCURRENT_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    info!(
        "Max concurrent requests (load shed): {}",
        max_concurrent_requests
    );

    // Construct Axum router with middleware layers
    let app = Router::new()
        .merge(SwaggerUi::new("/v1/docs").url("/v1/docs/openapi.json", routes::ApiDoc::openapi()))
        .nest(
            "/v1",
            api_routes().layer(middleware::from_fn(routes::deprecation_middleware)),
        )
        .nest("/v2", api_routes())
        // Dashboard Console static serving (unversioned)
        .route(
            "/dashboard",
            get(|| async { axum::response::Redirect::permanent("/dashboard/") }),
        )
        .route("/dashboard/", get(routes::serve_dashboard_index))
        .route("/dashboard/app.js", get(routes::serve_dashboard_js))
        .route("/dashboard/aegis.css", get(routes::serve_dashboard_css))
        // Health and probes (unversioned)
        .route("/health", get(health_handler))
        // Kubernetes-native probes (#1208): liveness, readiness, startup
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler))
        .route("/startupz", get(startupz_handler))
        // Security metrics (Prometheus text, 127.0.0.1 only — same listener)
        .route("/metrics", get(metrics_handler))
        // Tokio runtime introspection (#1160, 127.0.0.1 only — same listener)
        .route("/debug/runtime", get(debug_runtime_handler))
        .with_state(state.clone())
        // Middleware stack (outermost = first to run):
        // 1. CORS — must be outermost to handle preflight OPTIONS
        .layer(cors_layer())
        // 1b. Load shed (#911): once AEGIS_MAX_CONCURRENT_REQUESTS requests
        // are already in flight, reject new ones immediately with 503
        // instead of queuing (which would just push back the same overload
        // onto the timeout layer further in). LoadShedLayer only sheds when
        // wrapped around something that signals backpressure via
        // `poll_ready` — that's the concurrency limiter's job here; axum
        // handlers alone are always immediately `Ready`. HandleErrorLayer
        // converts the resulting `Overloaded` error into a structured 503
        // (`Router::layer` requires `Error = Infallible`).
        //
        // Deliberately `GlobalConcurrencyLimitLayer`, not the plain
        // `ServiceBuilder::concurrency_limit()` convenience (which wraps
        // `ConcurrencyLimitLayer`): for a `.route(path, get(handler))`
        // registration, axum defers the handler->Route conversion and
        // re-applies every outer `.layer()` fresh on each incoming request
        // (`axum::boxed::Map::call_with_state`) rather than once at startup.
        // `ConcurrencyLimitLayer::layer()` allocates a brand new
        // `Arc<Semaphore>` on every call, so under that path every request
        // would see its own private, always-free permit and shedding would
        // never trigger. `GlobalConcurrencyLimitLayer` stores one
        // `Arc<Semaphore>` on the layer value itself and only ever clones
        // that `Arc` from `.layer()`, so the permit count stays shared no
        // matter how many times axum reapplies the layer.
        .layer(
            tower::ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(
                    handle_overload_error,
                ))
                .load_shed()
                .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
                    max_concurrent_requests,
                )),
        )
        // 2. X-Request-ID propagation — correlates logs across SDK ↔ gateway
        .layer(middleware::from_fn(request_id_middleware))
        // 3. Content-Type validation — rejects non-JSON bodies on POST/PUT/PATCH
        .layer(middleware::from_fn(content_type_validation_middleware))
        // 3b. CSRF protection (#1308) — rejects state-changing requests if CSRF cookie is present but token mismatches
        .layer(middleware::from_fn(routes::csrf_validation_middleware))
        // 4. ETag conditional caching (#1141) — must run before compression
        // so the hash covers the canonical uncompressed body.
        .layer(middleware::from_fn(etag_middleware))
        // 5. Response Compression (Gzip/Brotli/Deflate)
        .layer(tower_http::compression::CompressionLayer::new())
        // 6. Request size limit
        .layer(axum::extract::DefaultBodyLimit::max(body_limit))
        // 7. Global request timeout
        .layer(tower_http::timeout::TimeoutLayer::new(
            std::time::Duration::from_secs(request_timeout_secs),
        ))
        // 8. CatchPanic — outermost, so a panic anywhere in the stack returns
        // a structured 500 instead of dropping the connection (#1153).
        .layer(CatchPanicLayer::custom(panic_response(state.clone())));

    let bind_addr =
        std::env::var("AEGIS_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    // Check for TLS cert and key environment variables
    let cert_env = std::env::var("AEGIS_TLS_CERT").ok();
    let key_env = std::env::var("AEGIS_TLS_KEY").ok();

    let use_tls = match (cert_env, key_env) {
        (Some(cert_path), Some(key_path)) => Some((cert_path, key_path)),
        (Some(_), None) => {
            tracing::warn!(
                "AEGIS_TLS_CERT is set, but AEGIS_TLS_KEY is not set. Falling back to plain HTTP."
            );
            None
        }
        (None, Some(_)) => {
            tracing::warn!(
                "AEGIS_TLS_KEY is set, but AEGIS_TLS_CERT is not set. Falling back to plain HTTP."
            );
            None
        }
        (None, None) => None,
    };

    // Startup is complete: DB pool + migrations, policy engine, and background
    // jobs are all initialized. /startupz now reports ready (#1208).
    state
        .startup_complete
        .store(true, std::sync::atomic::Ordering::Relaxed);

    // Spawn gRPC server on separate task (default port 6334)
    let grpc_bind_addr =
        std::env::var("AEGIS_GRPC_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:6334".to_string());
    if let Ok(grpc_addr) = grpc_bind_addr.parse::<SocketAddr>() {
        let grpc_state = state.clone();
        let grpc_handle = tokio::spawn(async move {
            if let Err(e) = gateway::grpc::start_grpc_server(grpc_state, grpc_addr).await {
                tracing::error!("gRPC server error: {:?}", e);
            }
        });
        if let Ok(mut handles) = state.background_task_handles.lock() {
            handles.push(("grpc_server", grpc_handle.abort_handle()));
        }
    } else {
        tracing::error!("Failed to parse AEGIS_GRPC_BIND_ADDR: {}", grpc_bind_addr);
    }
    if let Some((cert_path, key_path)) = use_tls {
        info!("Loading TLS certificates from {} ...", cert_path);
        let certs = load_certs(&cert_path)?;
        info!("Loading TLS private key from {} ...", key_path);
        let key = load_private_key(&key_path)?;

        // Ensure a default crypto provider is installed for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        // #1310: agent-to-gateway mTLS. When AEGIS_MTLS_CA_CERT is set, the
        // gateway requires every client to present a certificate signed by
        // that CA (optionally checked against AEGIS_MTLS_CRL_PATH for
        // revocation) instead of the default no-client-auth TLS config.
        // Unset (the common case): behavior is unchanged from before this
        // feature existed, and agents authenticate with bearer tokens.
        let mtls_ca_cert_path = std::env::var("AEGIS_MTLS_CA_CERT").ok();
        let mtls_crl_path = std::env::var("AEGIS_MTLS_CRL_PATH").ok();
        if mtls_crl_path.is_some() && mtls_ca_cert_path.is_none() {
            tracing::warn!(
                "AEGIS_MTLS_CRL_PATH is set without AEGIS_MTLS_CA_CERT; mTLS is not enabled, ignoring the CRL path."
            );
        }

        let server_config_builder = rustls::ServerConfig::builder();
        let mut tls_config = if let Some(ca_cert_path) = mtls_ca_cert_path {
            info!(
                "mTLS enabled: loading client CA certificate from {} ...",
                ca_cert_path
            );
            let client_cert_verifier =
                mtls::build_client_cert_verifier(&ca_cert_path, mtls_crl_path.as_deref())?;
            server_config_builder
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(certs, key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
        } else {
            server_config_builder
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
        };

        // Enforce minimum TLS 1.2 and support HTTP/1.1 and HTTP/2
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!(
            "AegisAgent Listening on https://{} (with same-port HTTP->HTTPS redirect)",
            listener.local_addr()?
        );

        let (close_tx, mut close_rx) = tokio::sync::mpsc::channel::<()>(1);

        loop {
            tokio::select! {
                res = listener.accept() => {
                    let (socket, _) = match res {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::error!("accept error: {:?}", e);
                            continue;
                        }
                    };

                    let tls_acceptor = tls_acceptor.clone();
                    let app = app.clone();
                    let close_tx_clone = close_tx.clone();

                    tokio::spawn(async move {
                        let _keep_alive = close_tx_clone;
                        let client_addr = socket.peer_addr().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));

                        // Peek the first byte to see if it's TLS Client Hello (0x16)
                        let mut peek_buf = [0u8; 1];
                        let peek_res = tokio::time::timeout(std::time::Duration::from_secs(5), socket.peek(&mut peek_buf)).await;
                        match peek_res {
                            Ok(Ok(1)) if peek_buf[0] == 0x16 => {
                                // TLS Client Hello detected
                                match tls_acceptor.accept(socket).await {
                                    Ok(tls_stream) => {
                                        // #1310: extract the verified client cert's Subject CN
                                        // (if mTLS is configured and the client presented one)
                                        // BEFORE the stream is consumed by TokioIo, so it can be
                                        // attributed to an agent identity downstream.
                                        let mtls_cn = tls_stream
                                            .get_ref()
                                            .1
                                            .peer_certificates()
                                            .and_then(mtls::extract_cn_from_certs);
                                        let io = TokioIo::new(tls_stream);
                                        let service = hyper::service::service_fn(move |req: axum::http::Request<hyper::body::Incoming>| {
                                            let mut router = app.clone();
                                            let mut req = req.map(Body::new);
                                            req.extensions_mut().insert(axum::extract::ConnectInfo(client_addr));
                                            // Always strip any client-supplied value first: this
                                            // header is only ever trustworthy when set here, right
                                            // after a successful TLS handshake (#1310).
                                            req.headers_mut().remove(mtls::MTLS_CN_HEADER);
                                            if let Some(cn) = mtls_cn.as_deref() {
                                                if let Ok(value) = axum::http::HeaderValue::from_str(cn) {
                                                    req.headers_mut().insert(mtls::MTLS_CN_HEADER, value);
                                                }
                                            }
                                            async move {
                                                use tower::Service;
                                                router.call(req).await
                                            }
                                        });

                                        if let Err(err) = auto::Builder::new(TokioExecutor::new())
                                            .serve_connection(io, service)
                                            .await
                                        {
                                            tracing::debug!("failed to serve TLS connection: {:?}", err);
                                        }
                                    }
                                    Err(err) => {
                                        tracing::debug!("TLS handshake failed: {:?}", err);
                                    }
                                }
                            }
                            Ok(Ok(1)) => {
                                // Plain HTTP detected, redirect to HTTPS
                                let io = TokioIo::new(socket);
                                let redirect_service = hyper::service::service_fn(move |req: axum::http::Request<hyper::body::Incoming>| {
                                    let host = req.headers()
                                        .get(axum::http::header::HOST)
                                        .and_then(|h| h.to_str().ok())
                                        .unwrap_or("");
                                    let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("");
                                    let redirect_url = format!("https://{}{}", host, path_and_query);

                                    let response = match axum::http::Response::builder()
                                        .status(axum::http::StatusCode::PERMANENT_REDIRECT)
                                        .header(axum::http::header::LOCATION, redirect_url)
                                        .body(Body::empty())
                                    {
                                        Ok(res) => res,
                                        Err(e) => {
                                            tracing::error!("Failed to build redirect response: {:?}", e);
                                            let mut fallback = axum::http::Response::new(Body::empty());
                                            *fallback.status_mut() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
                                            fallback
                                        }
                                    };
                                    async move {
                                        Ok::<_, std::convert::Infallible>(response)
                                    }
                                });

                                if let Err(err) = auto::Builder::new(TokioExecutor::new())
                                    .serve_connection(io, redirect_service)
                                    .await
                                  {
                                    tracing::debug!("failed to serve HTTP redirect: {:?}", err);
                                }
                            }
                            _ => {}
                        }
                    });
                }
                _ = shutdown_signal() => {
                    info!("Received shutdown signal, stopping accept loop...");
                    break;
                }
            }
        }

        // Drop the original sender so the receiver can eventually resolve
        drop(close_tx);
        // Wait for all connections to finish (with a timeout, e.g., same AEGIS_DRAIN_TIMEOUT_SECS)
        let drain_timeout = std::env::var("AEGIS_DRAIN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(drain_timeout),
            close_rx.recv(),
        )
        .await;
    } else {
        // Fallback to plain HTTP serving. Unlike the manual TLS accept loop
        // above, nothing here ever has a verified client certificate to
        // attribute, so defensively strip any client-supplied mTLS-CN
        // header before it can reach `authorize_action` (#1310).
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        info!("AegisAgent Listening on http://{}", listener.local_addr()?);

        let plain_http_app = app.layer(axum::middleware::from_fn(strip_mtls_cn_header));
        axum::serve(
            listener,
            plain_http_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    info!("AegisAgent HTTP server stopped. Draining background event channel...");

    // #1511: flush any heartbeats buffered since the last periodic tick so
    // graceful shutdown never silently drops a pending last_seen_at write.
    jobs::flush_heartbeats(state.storage.get_pool(), &state.heartbeat_debouncer).await;

    // #1512: wait for any deferred (fire-and-forget) risk-score/receipt
    // writes spawned during the inline authorize path to land before the
    // process exits, so graceful shutdown never silently drops one. Bounded
    // by AEGIS_DEFERRED_WRITE_DRAIN_TIMEOUT_SECS (default 5s) — these are
    // best-effort writes, so a slow drain should not hold up shutdown
    // indefinitely.
    let deferred_write_drain_timeout = std::env::var("AEGIS_DEFERRED_WRITE_DRAIN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(5));
    if !state
        .deferred_write_tracker
        .drain(deferred_write_drain_timeout)
        .await
    {
        tracing::warn!(
            "Deferred-write drain timed out during shutdown. Some risk-score/receipt writes may not have completed."
        );
    }

    drop(state);

    // Wait for the drain task to finish with a timeout (default 10s)
    let drain_timeout = std::env::var("AEGIS_DRAIN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    match tokio::time::timeout(std::time::Duration::from_secs(drain_timeout), drain_handle).await {
        Ok(Ok(n)) => info!("Drained {} events during shutdown", n),
        Ok(Err(e)) => tracing::error!("SOC event channel drain task panicked: {:?}", e),
        Err(_) => {
            tracing::warn!("SOC event channel drain timed out. Some events may have been lost.")
        }
    }

    // #1315: flush any audit_events rows still buffered by the batch writer.
    // Dropping `state` above dropped the last `AuditBatchSink` clone, closing
    // the channel so `run_audit_batch_writer` flushes and returns.
    match tokio::time::timeout(
        std::time::Duration::from_secs(drain_timeout),
        audit_batch_handle,
    )
    .await
    {
        Ok(Ok(n)) => info!("Flushed {} audit events during shutdown", n),
        Ok(Err(e)) => tracing::error!("Audit batch writer task panicked: {:?}", e),
        Err(_) => tracing::warn!(
            "Audit batch writer drain timed out. Some audit events may have been lost."
        ),
    }

    // #1156: flush any spans still buffered in the OTel batch processor.
    if let Some(provider) = otel_tracer_provider {
        otel::shutdown_tracer_provider(&provider);
    }
    // #1287: flush any metrics still buffered before the periodic exporter's
    // next tick would otherwise have run.
    if let Some(provider) = otel_meter_provider {
        otel::shutdown_meter_provider(&provider);
    }

    info!("AegisAgent shut down gracefully.");
    Ok(())
}

/// Wait for a shutdown signal (Ctrl-C or SIGTERM on Unix).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received Ctrl-C, starting graceful shutdown..."); },
        _ = terminate => { info!("Received SIGTERM, starting graceful shutdown..."); },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secrets_bearer() {
        let log = "Received request with Authorization: Bearer secret_token_123 in headers";
        let redacted = redact_secrets(log);
        assert_eq!(
            redacted,
            "Received request with Authorization: Bearer [REDACTED] in headers"
        );
    }

    #[test]
    fn test_redact_secrets_json() {
        let log =
            r#"{"agent_token":"agent_tok_secret","api_key":"api_key_secret","other":"field"}"#;
        let redacted = redact_secrets(log);
        assert_eq!(
            redacted,
            r#"{"agent_token":"[REDACTED]","api_key":"[REDACTED]","other":"field"}"#
        );
    }

    #[test]
    fn test_redact_secrets_bearer_basic_case_insensitive() {
        let log = "Authorization: bearer Token_123, auth: Basic base64_data_here";
        let redacted = redact_secrets(log);
        assert_eq!(
            redacted,
            "Authorization: bearer [REDACTED], auth: Basic [REDACTED]"
        );
    }

    #[test]
    fn test_redact_secrets_nested_json() {
        let log = r#"{"level":"info","fields":{"nested":{"password":"my_pwd","secret_key":"k1"},"client_secret":"cs_val","authorization":"Bearer super_secret","message":"some auth: Bearer normal_token"}}"#;
        let redacted = redact_secrets(log);
        assert_eq!(
            redacted,
            r#"{"level":"info","fields":{"nested":{"password":"[REDACTED]","secret_key":"[REDACTED]"},"client_secret":"[REDACTED]","authorization":"[REDACTED]","message":"some auth: Bearer [REDACTED]"}}"#
        );
    }

    #[test]
    fn test_redact_secrets_url_query_parameters() {
        let log = "http://localhost/path?api_key=my_key&token=my_token&normal=123";
        let redacted = redact_secrets(log);
        assert_eq!(
            redacted,
            "http://localhost/path?api_key=[REDACTED]&token=[REDACTED]&normal=123"
        );
    }

    #[test]
    fn test_redact_secrets_various_casings_and_formats() {
        let log = "Password=supersecret, CLIENT_SECRET : \"my-secret\", secret_key=some-key";
        let redacted = redact_secrets(log);
        assert_eq!(
            redacted,
            "Password=[REDACTED], CLIENT_SECRET : \"[REDACTED]\", secret_key=[REDACTED]"
        );
    }

    #[tokio::test]
    async fn test_graceful_shutdown_drains_events() {
        let db_url = format!(
            "sqlite://target/test_shutdown_{}.db",
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();

        // Setup the channel
        let metrics = Arc::new(metrics::SecurityMetrics::new());
        let (events_sink, events_rx) =
            events::EventSink::channel(events::DEFAULT_CAPACITY, metrics.clone());
        let drain_handle = tokio::spawn(events::drain(
            events_rx,
            pool.clone(),
            metrics.clone(),
            None,
        ));

        // Emit an event
        let event = events::AseEvent {
            event_id: "evt_test_shutdown".to_string(),
            occurred_at: "2026-06-10T12:00:00Z".to_string(),
            tenant_id: "tenant_shutdown_test".to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: "agent_shutdown_test".to_string(),
            decision: "deny".to_string(),
            tool: "some_tool".to_string(),
            action: "some_action".to_string(),
            resource: None,
            risk_score: 100,
            reason: "policy_denied".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec!["critical_policy".to_string()],
            redacted_fields: vec![],
            schema_version: 1,
        };
        events_sink.emit(event);

        // Drop the events sink (closing the sender)
        drop(events_sink);

        // Await the drain task to complete (should finish and return the count of processed events)
        let drain_timeout = std::time::Duration::from_secs(5);
        let run_result = tokio::time::timeout(drain_timeout, drain_handle).await;

        match run_result {
            Ok(Ok(count)) => {
                assert_eq!(count, 1);
            }
            other => panic!("Drain task failed to finish gracefully: {:?}", other),
        }

        // Verify that the event was persisted to the database as an alert.
        // SOC-007 (#1190) also fires a `behavioral_anomaly_new_tool` info
        // alert for this agent's first-ever call, alongside `critical_deny`.
        let alerts = db::list_soc_alerts(&pool, "tenant_shutdown_test", 10, 0, None, None)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 2);
        let critical_deny = alerts
            .iter()
            .find(|a| a.rule == "critical_deny")
            .expect("expected a critical_deny alert");
        assert_eq!(critical_deny.source_event_id, "evt_test_shutdown");

        // Clean up DB file
        let db_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
    }

    /// #1153: a panicking handler must not drop the connection — the
    /// CatchPanicLayer should convert it into a structured 500 JSON
    /// response and increment `aegis_handler_panics_total`.
    #[tokio::test]
    async fn catch_panic_layer_returns_500_and_increments_metric() {
        use axum::routing::get;
        use tower::ServiceExt;

        let db_url = format!(
            "sqlite://target/test_catch_panic_{}.db",
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();
        let policy_engine = crate::policy::PolicyEngine::init("policies.cedar")
            .await
            .unwrap();
        let metrics = Arc::new(crate::metrics::SecurityMetrics::new());
        let (events, _events_rx) =
            events::EventSink::channel(events::DEFAULT_CAPACITY, metrics.clone());
        let state = Arc::new(routes::AppState {
            storage: Arc::new(aegis_storage::sqlite::SqliteStorage::new(pool)),
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: routes::RateLimiter::new(1000.0, 1000.0),
            quota_manager: routes::QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: routes::RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: routes::ApprovalAttemptTracker::new(5, 3600),
            skill_cache: routes::SkillActionCache::new(1024),
            risk_weight_cache: routes::RiskWeightsCache::new(std::time::Duration::from_secs(
                routes::DEFAULT_RISK_WEIGHTS_CACHE_TTL_SECS,
            )),
            heartbeat_debouncer: Arc::new(routes::HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(routes::DeferredWriteTracker::new()),
            replay_nonce_cache: routes::ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: gateway::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            policy_signing_verifying_key: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        let app = Router::new()
            .route(
                "/boom",
                get(|| async {
                    panic!("boom");
                    #[allow(unreachable_code)]
                    ""
                }),
            )
            .with_state(state.clone())
            .layer(CatchPanicLayer::custom(panic_response(state.clone())));

        let response = app
            .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["message"], "Internal server error");

        assert_eq!(
            state
                .metrics
                .handler_panics_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        let db_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
    }

    /// #911: a load-shed layer wrapping a concurrency-limit-of-1 must reject
    /// a second concurrent request with `503` instead of queuing it behind
    /// the first — proving the layer combination actually sheds load rather
    /// than (as `LoadShedLayer` alone would, with no concurrency limiter to
    /// signal backpressure) being a silent no-op. Deliberately registers the
    /// route via `get(handler)` (not `route_service`) and applies the layer
    /// via `Router::layer` — that combination is what defeats a plain
    /// `ConcurrencyLimitLayer` (axum re-applies outer layers fresh per
    /// request for handler-based routes, see the comment on the production
    /// middleware stack), so this guards the specific regression rather than
    /// just the generic tower mechanism.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn load_shed_layer_returns_503_when_concurrency_limit_exceeded() {
        use axum::routing::get;
        use std::sync::Arc as StdArc;
        use tokio::sync::Notify;
        use tower::ServiceExt;

        // Signaled by the handler itself once it has actually started
        // running, so the test never has to guess a sleep duration long
        // enough for the spawned first request to reach the handler.
        let entered = StdArc::new(Notify::new());
        let entered_clone = entered.clone();

        let app = Router::new()
            .route(
                "/slow",
                get(move || {
                    let entered = entered_clone.clone();
                    async move {
                        entered.notify_one();
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        "slow"
                    }
                }),
            )
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::error_handling::HandleErrorLayer::new(
                        handle_overload_error,
                    ))
                    .load_shed()
                    .layer(tower::limit::GlobalConcurrencyLimitLayer::new(1)),
            );

        let first = app
            .clone()
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap());
        let first_handle = tokio::spawn(first);

        // Wait for the handler to actually start (and thus hold the sole
        // concurrency permit) before firing the second request.
        entered.notified().await;

        let second_response = app
            .clone()
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(second_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(second_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["reason"], "ServiceUnavailable");

        let first_response = first_handle.await.unwrap().unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);
    }

    /// Builds a tiny router with a fixed-body GET route, a fixed-body POST
    /// route, and a 404 route, all wrapped in just `etag_middleware` — no DB
    /// or other state needed since the middleware doesn't touch either.
    fn etag_test_app() -> Router {
        use axum::routing::{get, post};

        Router::new()
            .route("/get", get(|| async { Json(json!({"hello": "world"})) }))
            .route("/post", post(|| async { Json(json!({"hello": "world"})) }))
            .route(
                "/missing",
                get(|| async { (StatusCode::NOT_FOUND, "not found") }),
            )
            .layer(middleware::from_fn(etag_middleware))
    }

    /// #1141: a GET response gets an `ETag` header, and a repeat request
    /// carrying that exact `If-None-Match` value gets a `304` with an empty
    /// body instead of the full payload.
    #[tokio::test]
    async fn etag_middleware_returns_304_on_matching_if_none_match() {
        use tower::ServiceExt;

        let app = etag_test_app();

        let first = app
            .clone()
            .oneshot(Request::builder().uri("/get").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let etag = first
            .headers()
            .get(header::ETAG)
            .expect("ETag header should be set")
            .to_str()
            .unwrap()
            .to_string();
        assert!(etag.starts_with('"') && etag.ends_with('"'));
        let first_body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(first_body, axum::body::Bytes::from(r#"{"hello":"world"}"#));

        let second = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/get")
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            second
                .headers()
                .get(header::ETAG)
                .unwrap()
                .to_str()
                .unwrap(),
            etag
        );
        let second_body = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(second_body.is_empty());
    }

    /// A non-matching `If-None-Match` still gets the full 200 response with
    /// the (unchanged, since the route always returns the same body) ETag.
    #[tokio::test]
    async fn etag_middleware_returns_full_body_on_mismatched_if_none_match() {
        use tower::ServiceExt;

        let app = etag_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/get")
                    .header(header::IF_NONE_MATCH, "\"not-the-real-etag\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::ETAG).is_some());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, axum::body::Bytes::from(r#"{"hello":"world"}"#));
    }

    /// POST responses are mutating and must never be cached — no ETag, and
    /// the body is always returned in full regardless of `If-None-Match`.
    #[tokio::test]
    async fn etag_middleware_does_not_apply_to_non_get_requests() {
        use tower::ServiceExt;

        let app = etag_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/post")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::ETAG).is_none());
    }

    /// Non-200 GET responses (errors) are passed through untouched — no
    /// ETag is computed for a 404/4xx/5xx body.
    #[tokio::test]
    async fn etag_middleware_does_not_apply_to_non_200_responses() {
        use tower::ServiceExt;

        let app = etag_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get(header::ETAG).is_none());
    }

    /// Build a minimal AppState + Router exposing only the /livez, /readyz,
    /// and /startupz probes (#1208), with a fresh SQLite DB. Returns the
    /// router, the state (so tests can flip `startup_complete`), and the
    /// db_url for cleanup.
    async fn probe_test_app(test_name: &str) -> (Router, Arc<routes::AppState>, String) {
        let db_url = format!(
            "sqlite://target/test_probes_{}_{}.db",
            test_name,
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();
        let policy_engine = crate::policy::PolicyEngine::init("policies.cedar")
            .await
            .unwrap();
        let metrics = Arc::new(crate::metrics::SecurityMetrics::new());
        let (events, _events_rx) =
            events::EventSink::channel(events::DEFAULT_CAPACITY, metrics.clone());
        let state = Arc::new(routes::AppState {
            storage: Arc::new(aegis_storage::sqlite::SqliteStorage::new(pool)),
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: routes::RateLimiter::new(1000.0, 1000.0),
            quota_manager: routes::QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: routes::RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: routes::ApprovalAttemptTracker::new(5, 3600),
            skill_cache: routes::SkillActionCache::new(1024),
            risk_weight_cache: routes::RiskWeightsCache::new(std::time::Duration::from_secs(
                routes::DEFAULT_RISK_WEIGHTS_CACHE_TTL_SECS,
            )),
            heartbeat_debouncer: Arc::new(routes::HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(routes::DeferredWriteTracker::new()),
            replay_nonce_cache: routes::ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(false),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: gateway::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            policy_signing_verifying_key: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(Vec::new()),
        });

        let app = Router::new()
            .nest(
                "/v1",
                api_routes().layer(middleware::from_fn(routes::deprecation_middleware)),
            )
            .nest("/v2", api_routes())
            .route("/health", get(health_handler))
            .route("/livez", get(livez_handler))
            .route("/readyz", get(readyz_handler))
            .route("/startupz", get(startupz_handler))
            .route("/metrics", get(metrics_handler))
            .route("/debug/runtime", get(debug_runtime_handler))
            .with_state(state.clone());

        (app, state, db_url)
    }

    fn cleanup_db(db_url: &str) {
        let db_path = db_url.strip_prefix("sqlite://").unwrap_or(db_url);
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
    }

    #[tokio::test]
    async fn livez_always_returns_200() {
        use tower::ServiceExt;

        let (app, _state, db_url) = probe_test_app("livez").await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/livez")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "alive");

        cleanup_db(&db_url);
    }

    /// #1160: `GET /debug/runtime` returns Tokio runtime introspection
    /// stats. Asserts presence and basic sanity of the fields the issue's
    /// acceptance criteria call out (active task count, total polls,
    /// scheduler utilization) rather than exact values, since those are
    /// inherently nondeterministic under `#[tokio::test]`.
    #[tokio::test]
    async fn debug_runtime_returns_tokio_metrics() {
        use tower::ServiceExt;

        let (app, _state, db_url) = probe_test_app("debug_runtime").await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/debug/runtime")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["active_tasks_count"].as_u64().is_some());
        assert!(parsed["workers_count"].as_u64().unwrap() >= 1);
        assert!(parsed["total_poll_count"].as_u64().is_some());
        assert!(parsed["global_queue_depth"].as_u64().is_some());
        let utilization = parsed["scheduler_utilization"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&utilization));

        cleanup_db(&db_url);
    }

    /// #1164 (TEST-004, AC #1): when the DB pool is closed (simulating the
    /// database becoming unreachable), `/health` must degrade to `503` with
    /// `db: "down"` instead of panicking or hanging — fail-closed, matching
    /// the readiness-probe contract Kubernetes relies on.
    #[tokio::test]
    async fn health_returns_503_when_db_pool_closed() {
        use tower::ServiceExt;

        let (app, state, db_url) = probe_test_app("health_pool_closed").await;
        state.storage.get_pool().close().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "unhealthy");
        assert_eq!(parsed["db"], "down");

        cleanup_db(&db_url);
    }

    /// #1207: `check_liveness` is what `--healthcheck` calls inside the
    /// distroless runtime image (no curl/shell available there) — verifies
    /// it correctly reports true against a real listening gateway's
    /// `/livez` and false against an address nothing is listening on.
    #[tokio::test]
    async fn check_liveness_true_when_livez_reachable_false_otherwise() {
        let (app, _state, db_url) = probe_test_app("check_liveness").await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        assert!(check_liveness(&addr.to_string()).await);

        // Bind-then-drop to get a port nothing is listening on, rather than
        // guessing an arbitrary "probably free" port number.
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);
        assert!(!check_liveness(&closed_addr.to_string()).await);

        cleanup_db(&db_url);
    }

    #[tokio::test]
    async fn readyz_returns_200_when_db_reachable() {
        use tower::ServiceExt;

        let (app, _state, db_url) = probe_test_app("readyz").await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "ready");
        assert_eq!(parsed["db"], "up");

        cleanup_db(&db_url);
    }

    #[tokio::test]
    async fn startupz_returns_503_until_marked_complete_then_200() {
        use tower::ServiceExt;

        let (app, state, db_url) = probe_test_app("startupz").await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/startupz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "starting");

        state
            .startup_complete
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/startupz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "started");

        cleanup_db(&db_url);
    }

    /// #1299: GET /readyz reports `audit_writer: "down"` once a decision/audit
    /// write has failed, and `"up"` otherwise.
    #[tokio::test]
    async fn readyz_reports_audit_writer_down_after_write_failure() {
        use tower::ServiceExt;

        let (app, state, db_url) = probe_test_app("readyz_audit_writer").await;

        // Healthy by default.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["audit_writer"], "up");

        // Simulate a prior decision/audit write failure.
        state
            .audit_writer_unhealthy
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["audit_writer"], "down");
        assert_eq!(parsed["db"], "up");

        cleanup_db(&db_url);
    }

    /// #1152: a background task (event drain, audit-batch writer, periodic
    /// job) that panics simply stops running forever — unlike a transient DB
    /// blip, it never self-heals. `GET /readyz` must report this and gate the
    /// status code, since routing traffic to a gateway with a permanently
    /// dead subsystem is exactly what readiness probes exist to prevent.
    #[tokio::test]
    async fn readyz_reports_dead_background_task_as_not_ready() {
        use tower::ServiceExt;

        let db_url = format!(
            "sqlite://target/test_probes_readyz_dead_task_{}.db",
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();
        let policy_engine = crate::policy::PolicyEngine::init("policies.cedar")
            .await
            .unwrap();
        let metrics = Arc::new(crate::metrics::SecurityMetrics::new());
        let (events, _events_rx) =
            events::EventSink::channel(events::DEFAULT_CAPACITY, metrics.clone());

        // A task that we immediately abort, simulating a panicked background task.
        let doomed_handle = tokio::spawn(std::future::pending::<()>());
        let doomed_abort_handle = doomed_handle.abort_handle();
        doomed_abort_handle.abort();
        // Let the runtime actually mark the task finished before asserting on it.
        tokio::task::yield_now().await;
        assert!(doomed_abort_handle.is_finished());

        let state = Arc::new(routes::AppState {
            storage: Arc::new(aegis_storage::sqlite::SqliteStorage::new(pool)),
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: routes::RateLimiter::new(1000.0, 1000.0),
            quota_manager: routes::QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: routes::RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: routes::ApprovalAttemptTracker::new(5, 3600),
            skill_cache: routes::SkillActionCache::new(1024),
            risk_weight_cache: routes::RiskWeightsCache::new(std::time::Duration::from_secs(
                routes::DEFAULT_RISK_WEIGHTS_CACHE_TTL_SECS,
            )),
            heartbeat_debouncer: Arc::new(routes::HeartbeatDebouncer::new()),
            deferred_write_tracker: Arc::new(routes::DeferredWriteTracker::new()),
            replay_nonce_cache: routes::ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(false),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: gateway::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            policy_signing_verifying_key: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: std::sync::Mutex::new(vec![(
                "doomed_task",
                doomed_abort_handle,
            )]),
        });

        let app = Router::new()
            .route("/readyz", get(readyz_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "not_ready");
        assert_eq!(parsed["db"], "up");
        assert_eq!(parsed["background_tasks"], "down");
        assert_eq!(parsed["dead_background_tasks"][0], "doomed_task");

        cleanup_db(&db_url);
    }

    /// #1150: `GET /metrics` exposes point-in-time DB connection-pool gauges.
    #[tokio::test]
    async fn metrics_endpoint_exposes_db_pool_gauges() {
        use tower::ServiceExt;

        let (app, _state, db_url) = probe_test_app("metrics_pool_gauges").await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("# TYPE db_pool_connections_active gauge"));
        assert!(text.contains("# TYPE db_pool_connections_idle gauge"));
        assert!(text.contains("# TYPE db_pool_acquire_wait_seconds gauge"));

        cleanup_db(&db_url);
    }

    /// #1286: `GET /metrics` exposes Splunk HEC export connection-health
    /// gauges even when Splunk export isn't configured (advisory zero values).
    #[tokio::test]
    async fn metrics_endpoint_exposes_splunk_hec_export_gauges() {
        use tower::ServiceExt;

        let (app, _state, db_url) = probe_test_app("metrics_splunk_gauges").await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("# TYPE splunk_hec_export_consecutive_failures gauge"));
        assert!(text.contains("# TYPE splunk_hec_export_last_success_unix_secs gauge"));

        cleanup_db(&db_url);
    }

    /// Test prefix routing, version endpoint, and deprecation/sunset headers.
    #[tokio::test]
    async fn test_api_versioning_and_deprecation_headers() {
        use tower::ServiceExt;

        let (app, _state, db_url) = probe_test_app("api_versioning").await;

        // 1. Test /v1/version returns Sunset and Deprecation headers
        let req_v1 = Request::builder()
            .uri("/v1/version")
            .body(Body::empty())
            .unwrap();
        let resp_v1 = app.clone().oneshot(req_v1).await.unwrap();
        assert_eq!(resp_v1.status(), StatusCode::OK);

        let headers_v1 = resp_v1.headers();
        assert_eq!(
            headers_v1.get("deprecation").unwrap().to_str().unwrap(),
            "true"
        );
        assert_eq!(
            headers_v1.get("sunset").unwrap().to_str().unwrap(),
            "Wed, 31 Dec 2026 23:59:59 GMT"
        );

        let body_v1 = axum::body::to_bytes(resp_v1.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_v1: serde_json::Value = serde_json::from_slice(&body_v1).unwrap();
        assert_eq!(json_v1["name"], "aegis-gateway");
        assert!(json_v1["version"].is_string());

        // 2. Test /v2/version does NOT return Sunset or Deprecation headers
        let req_v2 = Request::builder()
            .uri("/v2/version")
            .body(Body::empty())
            .unwrap();
        let resp_v2 = app.clone().oneshot(req_v2).await.unwrap();
        assert_eq!(resp_v2.status(), StatusCode::OK);

        let headers_v2 = resp_v2.headers();
        assert!(headers_v2.get("deprecation").is_none());
        assert!(headers_v2.get("sunset").is_none());

        let body_v2 = axum::body::to_bytes(resp_v2.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_v2: serde_json::Value = serde_json::from_slice(&body_v2).unwrap();
        assert_eq!(json_v2["name"], "aegis-gateway");
        assert_eq!(json_v2["version"], json_v1["version"]);

        // 3. Test unversioned /livez does NOT return Sunset or Deprecation headers
        let req_livez = Request::builder()
            .uri("/livez")
            .body(Body::empty())
            .unwrap();
        let resp_livez = app.clone().oneshot(req_livez).await.unwrap();
        assert_eq!(resp_livez.status(), StatusCode::OK);

        let headers_livez = resp_livez.headers();
        assert!(headers_livez.get("deprecation").is_none());
        assert!(headers_livez.get("sunset").is_none());

        cleanup_db(&db_url);
    }
}
