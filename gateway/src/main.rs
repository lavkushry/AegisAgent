use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod db;
mod events;
mod metrics;
mod models;
mod policy;
mod routes;

use routes::AppState;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,gateway=debug,sqlx=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting AegisAgent Control Plane...");

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
    // SOC phase consumes this one stream and never touches the inline path.
    let (events, events_rx) = events::EventSink::channel(events::DEFAULT_CAPACITY);
    tokio::spawn(events::drain(events_rx));

    // Shared state (metrics are zero-initialised atomics; no heap beyond the struct)
    let state = Arc::new(AppState {
        pool,
        policy_engine,
        events,
        metrics: metrics::SecurityMetrics::new(),
    });

    // Construct Axum router
    let app = Router::new()
        // Registrations
        .route("/v1/agents/register", post(routes::register_agent))
        .route("/v1/tools", post(routes::register_tool))
        .route("/v1/mcp/servers", post(routes::register_mcp_server))
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
        // Approvals
        .route("/v1/approvals/:id", get(routes::get_approval))
        .route("/v1/approvals/:id/approve", post(routes::approve_approval))
        .route("/v1/approvals/:id/reject", post(routes::reject_approval))
        .route("/v1/approvals/:id/edit", post(routes::edit_approval))
        .route("/v1/approvals/:id/consume", post(routes::consume_approval))
        // Audits
        .route("/v1/runs/:id/timeline", get(routes::get_timeline))
        .route("/v1/audit/events", get(routes::get_audit_events))
        // Verifiable action receipts
        .route("/v1/receipts/:id/verify", get(routes::verify_receipt))
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
        // Fallback or health check
        .route("/health", get(|| async { "healthy" }))
        // Security metrics (Prometheus text, 127.0.0.1 only — same listener)
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    // Bind strictly to 127.0.0.1 for security testing, matching rules in mandatory-secure-web-skills
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    info!("AegisAgent Listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}
