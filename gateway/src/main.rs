#![recursion_limit = "512"]

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use uuid::Uuid;

mod correlate;
mod db;
mod detect;
mod events;
mod jobs;
mod metrics;
mod models;
mod narrate;
mod notify;
mod policy;
mod routes;
mod sign;

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

        if content_length > 0 && !content_type.contains("application/json") {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(json!({"error": "Content-Type must be application/json"})),
            )
                .into_response();
        }
    }

    next.run(request).await.into_response()
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
    let mut output = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // 1. Check for "Bearer "
        if i + 7 <= chars.len() && chars[i..i + 7].iter().collect::<String>() == "Bearer " {
            output.push_str("Bearer ");
            i += 7;
            let mut skipped = false;
            while i < chars.len() {
                let c = chars[i];
                if c == ' '
                    || c == ','
                    || c == '"'
                    || c == '\n'
                    || c == '\r'
                    || c == '}'
                    || c == '\\'
                    || c == ']'
                {
                    break;
                }
                if !skipped {
                    output.push_str("[REDACTED]");
                    skipped = true;
                }
                i += 1;
            }
            continue;
        }

        // 2. Check for "agent_token"
        if i + 11 <= chars.len() && chars[i..i + 11].iter().collect::<String>() == "agent_token" {
            output.push_str("agent_token");
            i += 11;
            redact_next_word(&chars, &mut i, &mut output);
            continue;
        }

        // 3. Check for "api_key"
        if i + 7 <= chars.len() && chars[i..i + 7].iter().collect::<String>() == "api_key" {
            output.push_str("api_key");
            i += 7;
            redact_next_word(&chars, &mut i, &mut output);
            continue;
        }

        output.push(chars[i]);
        i += 1;
    }
    output
}

fn redact_next_word(chars: &[char], i: &mut usize, output: &mut String) {
    let mut j = *i;
    let mut found_colon = false;
    while j < chars.len() {
        let c = chars[j];
        if c == ':' {
            found_colon = true;
            break;
        }
        if c == '\n' || c == '\r' || c == '}' {
            break;
        }
        j += 1;
    }

    if found_colon {
        output.push_str(&chars[*i..=j].iter().collect::<String>());
        *i = j + 1;

        while *i < chars.len() {
            let c = chars[*i];
            if c == ' ' || c == '"' || c == '\\' || c == '\'' {
                output.push(c);
                *i += 1;
            } else {
                break;
            }
        }

        let mut redacted = false;
        while *i < chars.len() {
            let c = chars[*i];
            if c.is_alphanumeric() || c == '_' || c == '-' {
                if !redacted {
                    output.push_str("[REDACTED]");
                    redacted = true;
                }
                *i += 1;
            } else {
                break;
            }
        }
    }
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
    } else {
        if let Ok(jwt_secret) = std::env::var("AEGIS_JWT_SECRET") {
            if jwt_secret.trim().is_empty() || jwt_secret == "default_secret" {
                tracing::warn!("AEGIS_JWT_SECRET is set to an empty or default value ('default_secret'). JWT validation will be disabled for security.");
            }
        } else {
            tracing::warn!("AEGIS_JWT_SECRET is not set. JWT validation will be disabled.");
        }
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
    let (events, events_rx) = events::EventSink::channel(events::DEFAULT_CAPACITY);
    let drain_handle = tokio::spawn(events::drain(events_rx, pool.clone()));

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

    // Read-through cache for registered-action metadata (#899). Bounded LRU;
    // AEGIS_SKILL_CACHE_CAPACITY == 0 disables it.
    let skill_cache_capacity: usize = std::env::var("AEGIS_SKILL_CACHE_CAPACITY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);
    let skill_cache = routes::SkillActionCache::new(skill_cache_capacity);

    // Shared state (metrics are zero-initialised atomics; no heap beyond the struct)
    let state = Arc::new(AppState {
        pool,
        policy_engine,
        events,
        metrics: metrics::SecurityMetrics::new(),
        approval_ttl_secs,
        rate_limiter,
        quota_manager,
        skill_cache,
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
        // Policy / Interception
        .route("/v1/authorize", post(routes::authorize_action))
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
        .route("/v1/policies/reload", post(routes::reload_global_policies))
        // Approvals
        .route("/v1/approvals", get(routes::list_approvals))
        .route("/v1/approvals/:id", get(routes::get_approval))
        .route("/v1/approvals/:id/approve", post(routes::approve_approval))
        .route("/v1/approvals/:id/reject", post(routes::reject_approval))
        .route("/v1/approvals/:id/edit", post(routes::edit_approval))
        .route("/v1/approvals/:id/consume", post(routes::consume_approval))
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
        // SOC Phase 4: Response API — agent freeze/revoke, MCP quarantine
        .route("/v1/agents/:id/freeze", post(routes::freeze_agent))
        .route("/v1/agents/:id/unfreeze", post(routes::unfreeze_agent))
        .route("/v1/agents/:id/revoke", post(routes::revoke_agent))
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
        // WebSocket live event stream
        .route("/v1/ws/events", get(routes::ws_events))
        // Statistics
        .route("/v1/stats", get(routes::get_tenant_stats))
        .route("/v1/admin/db-stats", get(routes::get_db_stats))
        .route("/v1/admin/backup", post(routes::create_db_backup))
        // OpenAPI Specification
        .route("/v1/openapi.json", get(routes::get_openapi_spec))
        // Health and version
        .route("/health", get(health_handler))
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
        // 4. Response Compression (Gzip/Brotli/Deflate)
        .layer(tower_http::compression::CompressionLayer::new())
        // 5. Request size limit
        .layer(axum::extract::DefaultBodyLimit::max(body_limit))
        // 6. Global request timeout
        .layer(tower_http::timeout::TimeoutLayer::new(
            std::time::Duration::from_secs(request_timeout_secs),
        ));

    // Bind address — configurable via AEGIS_BIND_ADDR, defaults to 127.0.0.1:8080
    // for security (local-only in dev/test). Production deployments should set this
    // to 0.0.0.0:<port> behind a reverse proxy.
    let bind_addr =
        std::env::var("AEGIS_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("AegisAgent Listening on http://{}", listener.local_addr()?);

    // Graceful shutdown: listen for SIGTERM (container orchestrators) and Ctrl-C.
    // In-flight requests are drained before the process exits.
    axum::serve(listener, app)
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

    #[tokio::test]
    async fn test_graceful_shutdown_drains_events() {
        let db_url = format!(
            "sqlite://target/test_shutdown_{}.db",
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();

        // Setup the channel
        let (events_sink, events_rx) = events::EventSink::channel(events::DEFAULT_CAPACITY);
        let drain_handle = tokio::spawn(events::drain(events_rx, pool.clone()));

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

        // Verify that the event was persisted to the database as an alert
        let alerts = db::list_soc_alerts(&pool, "tenant_shutdown_test", 10, 0, None, None)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "critical_deny");
        assert_eq!(alerts[0].source_event_id, "evt_test_shutdown");

        // Clean up DB file
        let db_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::remove_file(format!("{}-shm", db_path));
        let _ = std::fs::remove_file(format!("{}-wal", db_path));
    }
}
