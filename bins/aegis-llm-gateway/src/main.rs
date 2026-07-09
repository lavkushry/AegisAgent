//! `aegis-llm-gateway` binary entry point (Phase 7.3).
//!
//! OpenAI-compatible reverse proxy that captures model-call lineage and
//! ships hashes/token metadata to the AegisAgent control plane. Loopback
//! bind by default — exposing wider is a deliberate deployment choice.

use std::sync::Arc;

use clap::Parser;
use tracing::info;

use aegis_llm_gateway::events::TracingEventSink;
use aegis_llm_gateway::gateway_client::{HttpLineageClient, LineageClient, NullLineageClient};
use aegis_llm_gateway::proxy::ProxyState;

/// AegisAgent LLM gateway adapter: OpenAI-compatible reverse proxy that
/// captures model-call metadata (request/response hashes, token counts)
/// and ships lineage events to POST /v1/ingest/model-calls. Raw prompt
/// bodies never leave the process toward the control plane.
#[derive(Debug, Parser)]
#[command(name = "aegis-llm-gateway", version)]
struct Cli {
    /// Listen address. Loopback by default — exposing the proxy wider is a
    /// deliberate deployment decision, not a default.
    #[arg(long, default_value = "127.0.0.1:8090")]
    listen: String,

    /// Upstream model provider base URL (e.g. https://api.openai.com).
    #[arg(
        long,
        env = "AEGIS_LLM_UPSTREAM",
        default_value = "https://api.openai.com"
    )]
    upstream: String,

    /// Provider label stored on lineage events (openai, anthropic, azure, …).
    #[arg(long, default_value = "openai")]
    provider: String,

    /// Gateway base URL (e.g. http://127.0.0.1:8080). When set, finished
    /// model calls are POSTed to /v1/ingest/model-calls. When unset, only
    /// local tracing events are emitted.
    #[arg(long, env = "AEGIS_GATEWAY_URL")]
    gateway_url: Option<String>,

    /// Bearer token for the gateway. Read from AEGIS_API_TOKEN.
    #[arg(
        long,
        env = "AEGIS_API_TOKEN",
        default_value = "",
        hide_env_values = true
    )]
    api_token: String,

    /// Optional run/trace correlation IDs stamped on every capture.
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    trace_id: Option<String>,

    /// Trust label for prompt lineage (defaults to unknown if unset).
    #[arg(long)]
    source_trust: Option<String>,

    /// Disable shipping prompt lineage events (model-call capture remains on).
    #[arg(long)]
    no_capture_prompts: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let lineage: Arc<dyn LineageClient> = match &cli.gateway_url {
        Some(url) => {
            info!(%url, "model-call lineage via gateway /v1/ingest/model-calls");
            Arc::new(HttpLineageClient::new(url, cli.api_token.clone()))
        }
        None => {
            info!("no gateway URL set; local capture only (no lineage ship)");
            Arc::new(NullLineageClient)
        }
    };

    let state = ProxyState {
        upstream_base: cli.upstream.clone(),
        provider: cli.provider.clone(),
        run_id: cli.run_id.clone(),
        trace_id: cli.trace_id.clone(),
        source_trust: cli.source_trust.clone(),
        capture_prompts: !cli.no_capture_prompts,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?,
        sink: Arc::new(TracingEventSink),
        lineage,
    };

    let app = state.router();
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    info!(
        listen = %cli.listen,
        upstream = %cli.upstream,
        provider = %cli.provider,
        "aegis-llm-gateway listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
