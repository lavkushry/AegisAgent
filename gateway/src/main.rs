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

use gateway::audit_batch;
use gateway::db;
use gateway::events;
use gateway::gh_checks;
use gateway::gh_comment;
use gateway::jobs;
use gateway::metrics;
use gateway::policy;
use gateway::routes;

use routes::AppState;

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
    match db::health_check(&state.pool).await {
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
/// database is reachable, so an orchestrator stops routing traffic to a
/// gateway that can't serve requests (fail-closed).
async fn readyz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let audit_writer_status = if state
        .audit_writer_unhealthy
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        "down"
    } else {
        "up"
    };
    match db::health_check(&state.pool).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"status": "ready", "db": "up", "audit_writer": audit_writer_status})),
        ),
        Err(e) => {
            tracing::warn!("readyz check DB ping failed: {:?}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(
                    json!({"status": "not_ready", "db": "down", "audit_writer": audit_writer_status}),
                ),
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

        let body = Json(json!({"error": "Internal server error"}));
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

/// GET /metrics — Prometheus text exposition of process-wide security counters.
/// Bound only on the existing 127.0.0.1 listener; no new bind, no public exposure.
/// Labels are omitted to avoid leaking tenant/agent identifiers.
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = state.metrics.render_prometheus();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
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
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(json!({"error": "Content-Type must be application/json"})),
            )
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal server error"})),
            )
                .into_response();
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        );

    tracing::subscriber::set_global_default(subscriber).expect("Unable to set global subscriber");

    info!("Starting AegisAgent Control Plane v{}...", VERSION);

    // Validate JWT secret requirements
    let jwt_required = std::env::var("AEGIS_JWT_REQUIRED")
        .map(|v| v == "true")
        .unwrap_or(false);
    if jwt_required {
        let jwt_secret = std::env::var("AEGIS_JWT_SECRET").map_err(|_| {
            "AEGIS_JWT_SECRET environment variable must be set when AEGIS_JWT_REQUIRED is true."
        })?;
        if jwt_secret.trim().is_empty() || jwt_secret == "default_secret" {
            return Err("AEGIS_JWT_SECRET cannot be empty or 'default_secret' when AEGIS_JWT_REQUIRED is true.".into());
        }
    } else if let Ok(jwt_secret) = std::env::var("AEGIS_JWT_SECRET") {
        if jwt_secret.trim().is_empty() || jwt_secret == "default_secret" {
            tracing::warn!("AEGIS_JWT_SECRET is set to an empty or default value ('default_secret'). JWT validation will be disabled for security.");
        }
    } else {
        tracing::warn!("AEGIS_JWT_SECRET is not set. JWT validation will be disabled.");
    }

    // Database setup (local SQLite file)
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://aegis.db".into());
    info!("Initializing SQLite database pool at: {} ...", db_url);
    let pool = db::init_db(&db_url).await?;

    // Load Cedar Policy engine from file
    let policy_path =
        std::env::var("CEDAR_POLICY_PATH").unwrap_or_else(|_| "policies.cedar".into());
    info!("Loading Cedar policies from: {} ...", policy_path);
    let policy_engine = policy::PolicyEngine::init(&policy_path).await?;

    // Async SOC event stream (Phase 0 keystone): the authorize hot path emits
    // non-blocking onto this channel; a background task drains it. Every later
    // SOC phase (detection, correlation, response, indexing) consumes this one
    // stream and never touches the inline path.
    // Phase 5: pass pool.clone() so the drain can persist alerts + incidents.
    let metrics = Arc::new(metrics::SecurityMetrics::new());
    let (events, events_rx) = events::EventSink::channel(events::DEFAULT_CAPACITY, metrics.clone());
    let drain_handle = tokio::spawn(events::drain(events_rx, pool.clone(), metrics.clone()));

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

    // #0107: periodic receipt chain integrity check across all tenants. Any
    // broken link or hash mismatch is recorded as a critical SOC alert.
    let receipt_integrity_interval_secs: u64 =
        std::env::var("AEGIS_RECEIPT_INTEGRITY_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(jobs::DEFAULT_INTERVAL_SECS);
    tokio::spawn(jobs::run_receipt_chain_integrity_job(
        pool.clone(),
        receipt_integrity_interval_secs,
    ));

    // #0106: periodically archive old audit_events rows into
    // audit_events_archive to keep the live table bounded.
    let audit_archival_interval_secs: u64 = std::env::var("AEGIS_AUDIT_ARCHIVAL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_AUDIT_ARCHIVAL_INTERVAL_SECS);
    let audit_retention_days: i64 = std::env::var("AEGIS_AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_AUDIT_RETENTION_DAYS);
    tokio::spawn(jobs::run_audit_event_archival_job(
        pool.clone(),
        audit_archival_interval_secs,
        audit_retention_days,
    ));

    // #0105: periodically delete stale approvals (decided, or expired and
    // never decided) to keep the approvals table bounded.
    let approval_cleanup_interval_secs: u64 = std::env::var("AEGIS_APPROVAL_CLEANUP_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_APPROVAL_CLEANUP_INTERVAL_SECS);
    let approval_retention_days: i64 = std::env::var("AEGIS_APPROVAL_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(jobs::DEFAULT_APPROVAL_RETENTION_DAYS);
    tokio::spawn(jobs::run_approval_cleanup_job(
        pool.clone(),
        approval_cleanup_interval_secs,
        approval_retention_days,
    ));

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

    // Shared state (metrics are zero-initialised atomics; no heap beyond the struct)
    let state = Arc::new(AppState {
        pool,
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
        startup_complete: std::sync::atomic::AtomicBool::new(false),
        audit_writer_unhealthy: audit_writer_unhealthy.clone(),
        audit_batch,
        github_webhook_secret,
        slack_signing_secret,
        github_pr_commenter,
        github_checks_client,
    });

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

    // Construct Axum router with middleware layers
    let app = Router::new()
        // Registrations
        .route("/v1/agents/register", post(routes::register_agent))
        .route("/v1/agents", get(routes::list_agents))
        .route(
            "/v1/agents/:id",
            get(routes::get_agent)
                .patch(routes::patch_agent)
                .delete(routes::delete_agent),
        )
        .route("/v1/tools", post(routes::register_tool))
        .route(
            "/v1/mcp/servers",
            get(routes::list_mcp_servers).post(routes::register_mcp_server),
        )
        .route(
            "/v1/mcp/servers/:server_key",
            get(routes::get_mcp_server).put(routes::update_mcp_server),
        )
        .route(
            "/v1/mcp/servers/:server_key/tools",
            get(routes::get_mcp_tool_manifest).post(routes::discover_mcp_tools),
        )
        .route(
            "/v1/mcp/servers/:server_key/tools/:tool_key/approve",
            post(routes::approve_mcp_tool),
        )
        .route(
            "/v1/mcp/servers/:server_key/tools/:tool_key/disable",
            post(routes::disable_mcp_tool),
        )
        .route(
            "/v1/mcp/servers/:server_key/inspect",
            post(routes::inspect_mcp_response),
        )
        // Policy / Interception
        .route("/v1/authorize", post(routes::authorize_action))
        // SOC-004 (#1187): agentless ingestion of external event sources
        .route("/v1/ingest", post(routes::ingest_event))
        // #1381: dedicated GitHub App webhook receiver with HMAC-SHA256 verification
        .route("/v1/webhooks/github", post(routes::receive_github_webhook))
        .route("/v1/decisions", get(routes::list_decisions))
        .route("/v1/decisions/:id", get(routes::get_decision))
        .route(
            "/v1/policies",
            get(routes::list_policies).post(routes::create_policy),
        )
        .route(
            "/v1/policies/:id",
            put(routes::update_policy).delete(routes::delete_policy),
        )
        .route("/v1/policies/:id/rollback", post(routes::rollback_policy))
        .route("/v1/policies/reload", post(routes::reload_global_policies))
        .route("/v1/policies/audit-log", get(routes::list_policy_audit_log))
        .route(
            "/v1/tenants/risk-weights",
            get(routes::get_tenant_risk_weights).put(routes::put_tenant_risk_weights),
        )
        .route(
            "/v1/tenants/risk-escalation",
            get(routes::get_tenant_risk_escalation_config)
                .put(routes::put_tenant_risk_escalation_config),
        )
        .route(
            "/v1/webhook_subscriptions",
            get(routes::list_webhook_subscriptions).post(routes::create_webhook_subscription),
        )
        .route(
            "/v1/webhook_subscriptions/:id",
            axum::routing::delete(routes::delete_webhook_subscription),
        )
        .route(
            "/v1/detection_rules",
            get(routes::list_detection_rules).post(routes::upsert_detection_rule),
        )
        .route(
            "/v1/detection_rules/:id",
            axum::routing::delete(routes::delete_detection_rule),
        )
        .route(
            "/v1/soc/rules",
            get(routes::get_soc_rules).post(routes::create_soc_rule),
        )
        .route("/v1/soc/rules/reload", post(routes::reload_soc_rules))
        .route(
            "/v1/soc/rules/:rule_key/backtest",
            post(routes::backtest_soc_rule),
        )
        // #1272: Evidence Graph Query API
        .route("/v1/graph/run/:run_id", get(routes::get_graph_for_run))
        .route(
            "/v1/graph/incident/:incident_id",
            get(routes::get_graph_for_incident),
        )
        .route(
            "/v1/graph/agent/:agent_id",
            get(routes::get_graph_for_agent),
        )
        .route(
            "/v1/api_keys",
            get(routes::list_api_keys).post(routes::create_api_key),
        )
        .route("/v1/api_keys/:id/revoke", post(routes::revoke_api_key))
        // Approvals
        .route("/v1/approvals", get(routes::list_approvals))
        .route("/v1/approvals/:id", get(routes::get_approval))
        .route("/v1/approvals/:id/approve", post(routes::approve_approval))
        .route("/v1/approvals/:id/reject", post(routes::reject_approval))
        .route("/v1/approvals/:id/edit", post(routes::edit_approval))
        .route("/v1/approvals/:id/consume", post(routes::consume_approval))
        // Slack interactive-component callback (#1276): HMAC-verified, not
        // tenant-scoped via the Authorization header — tenant comes from the
        // signed callback payload itself.
        .route("/v1/callbacks/slack", post(routes::slack_callback))
        // Audits
        .route("/v1/runs/:id/timeline", get(routes::get_timeline))
        .route("/v1/audit/events", get(routes::get_audit_events))
        // Verifiable action receipts
        .route("/v1/receipts", get(routes::list_receipts))
        .route("/v1/receipts/:id", get(routes::get_receipt))
        .route("/v1/receipts/:id/verify", get(routes::verify_receipt))
        .route(
            "/v1/receipts/verify-chain",
            post(routes::verify_receipt_chain),
        )
        // SOC Phase 5: Indexer Query API — paginated, tenant-scoped SOC views
        .route("/v1/alerts", get(routes::list_alerts))
        .route("/v1/incidents", get(routes::list_incidents))
        // SOC query layer: incident detail + aggregate summary
        .route("/v1/incidents/:id", get(routes::get_incident))
        .route("/v1/soc/summary", get(routes::soc_summary))
        // SOC Phase 6: Incident lifecycle — close an open incident
        .route("/v1/incidents/:id/close", post(routes::close_incident))
        // SOC Phase 6: RCA Narrator — on-demand, human-triggered, LAW-2 compliant
        .route("/v1/incidents/:id/narrate", get(routes::narrate_incident))
        // SOC Phase 4: Response API — agent freeze/revoke/quarantine, MCP quarantine
        .route("/v1/agents/:id/freeze", post(routes::freeze_agent))
        .route("/v1/agents/:id/unfreeze", post(routes::unfreeze_agent))
        .route("/v1/agents/:id/revoke", post(routes::revoke_agent))
        .route("/v1/agents/:id/restore", post(routes::restore_agent))
        // #1295: agent token rotation (manual + leak-report auto-rotation)
        .route(
            "/v1/agents/:id/rotate-token",
            post(routes::rotate_agent_token),
        )
        .route(
            "/v1/agents/:id/report-leaked-token",
            post(routes::report_leaked_agent_token),
        )
        .route(
            "/v1/agents/:id/permissions",
            get(routes::list_agent_tool_permissions).post(routes::grant_agent_tool_permission),
        )
        .route(
            "/v1/agents/:id/permissions/:tool_key",
            delete(routes::revoke_agent_tool_permission),
        )
        .route(
            "/v1/mcp/servers/:server_key/quarantine",
            post(routes::quarantine_mcp_server),
        )
        .route(
            "/v1/mcp/servers/:server_key/restore",
            post(routes::restore_mcp_server),
        )
        // Tenants
        .route("/v1/tenants", post(routes::create_tenant))
        .route(
            "/v1/tenants/:id",
            get(routes::get_tenant).delete(routes::delete_tenant),
        )
        .route("/v1/tenants/:id/export", get(routes::export_tenant))
        // Compliance Evidence Pack (#1298): SOC 2 Type II / EU AI Act Art. 14
        .route(
            "/v1/compliance/evidence-pack",
            get(routes::get_evidence_pack),
        )
        // WebSocket live event stream
        .route("/v1/ws/events", get(routes::ws_events))
        // Statistics
        .route("/v1/stats", get(routes::get_tenant_stats))
        .route("/v1/admin/db-stats", get(routes::get_db_stats))
        .route("/v1/admin/backup", post(routes::create_db_backup))
        // SOC Console Dashboard static serving
        .route(
            "/dashboard",
            get(|| async { axum::response::Redirect::permanent("/dashboard/") }),
        )
        .route("/dashboard/", get(routes::serve_dashboard_index))
        .route("/dashboard/app.js", get(routes::serve_dashboard_js))
        .route("/dashboard/aegis.css", get(routes::serve_dashboard_css))
        // OpenAPI Specification
        .route("/v1/openapi.json", get(routes::get_openapi_spec))
        // Health and version
        .route("/health", get(health_handler))
        // Kubernetes-native probes (#1208): liveness, readiness, startup
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler))
        .route("/startupz", get(startupz_handler))
        .route("/v1/version", get(version_handler))
        // Security metrics (Prometheus text, 127.0.0.1 only — same listener)
        .route("/metrics", get(metrics_handler))
        .with_state(state.clone())
        // Middleware stack (outermost = first to run):
        // 1. CORS — must be outermost to handle preflight OPTIONS
        .layer(cors_layer())
        // 2. X-Request-ID propagation — correlates logs across SDK ↔ gateway
        .layer(middleware::from_fn(request_id_middleware))
        // 3. Content-Type validation — rejects non-JSON bodies on POST/PUT/PATCH
        .layer(middleware::from_fn(content_type_validation_middleware))
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

    // Bind address — configurable via AEGIS_BIND_ADDR, defaults to 127.0.0.1:8080
    // for security (local-only in dev/test). Production deployments should set this
    // to 0.0.0.0:<port> behind a reverse proxy.
    let bind_addr =
        std::env::var("AEGIS_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("AegisAgent Listening on http://{}", listener.local_addr()?);

    // Startup is complete: DB pool + migrations, policy engine, and background
    // jobs are all initialized and the listener is bound. /startupz now reports
    // ready (#1208).
    state
        .startup_complete
        .store(true, std::sync::atomic::Ordering::Relaxed);

    // Graceful shutdown: listen for SIGTERM (container orchestrators) and Ctrl-C.
    // In-flight requests are drained before the process exits.
    //
    // `into_make_service_with_connect_info::<SocketAddr>()` makes the
    // client's source address available via the `ConnectInfo<SocketAddr>`
    // extractor (#1307: per-IP rate limiting on approval-decision
    // callbacks).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("AegisAgent HTTP server stopped. Draining background event channel...");
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
        let drain_handle = tokio::spawn(events::drain(events_rx, pool.clone(), metrics.clone()));

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
            pool,
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: routes::RateLimiter::new(1000.0, 1000.0),
            quota_manager: routes::QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: routes::RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: routes::ApprovalAttemptTracker::new(5, 3600),
            skill_cache: routes::SkillActionCache::new(1024),
            replay_nonce_cache: routes::ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: gateway::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
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
        assert_eq!(parsed["error"], "Internal server error");

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
            pool,
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: routes::RateLimiter::new(1000.0, 1000.0),
            quota_manager: routes::QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: routes::RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: routes::ApprovalAttemptTracker::new(5, 3600),
            skill_cache: routes::SkillActionCache::new(1024),
            replay_nonce_cache: routes::ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(false),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: gateway::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
        });

        let app = Router::new()
            .route("/livez", get(livez_handler))
            .route("/readyz", get(readyz_handler))
            .route("/startupz", get(startupz_handler))
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
}
