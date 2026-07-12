//! `aegis-tool-broker` binary entry point (Phase 1 extraction).
//!
//! Standalone tool-broker execution engine: resolves credentials and runs
//! connectors in its own process, so the gateway never links this crate's
//! connectors or holds a real provider credential. See `lib.rs` for the
//! full scope note.

use clap::Parser;
use tracing::info;

use aegis_tool_broker::executor_config::build_broker_executor;
use aegis_tool_broker::handlers::router;

/// AegisAgent standalone tool-broker: resolves credentials and executes
/// connector actions the gateway has already authorized and (for mutating
/// actions) consumed an approval for.
#[derive(Debug, Parser)]
#[command(name = "aegis-tool-broker", version)]
struct Cli {
    /// Listen address. Loopback by default — exposing wider is a deliberate
    /// deployment decision, not a default.
    #[arg(long, default_value = "127.0.0.1:8899")]
    listen: String,

    /// Shared service-to-service bearer token the gateway must present on
    /// every `POST /v1/execute`. Required — this binary's entire surface
    /// *is* the privileged action it guards, so unlike the gateway's
    /// optional admin key there is no safe-default "unset" state.
    #[arg(long, env = "AEGIS_TOOL_BROKER_API_TOKEN", hide_env_values = true)]
    api_token: String,

    /// Print nothing, connect to our own /livez, and exit 0/1 — used as the
    /// Docker `HEALTHCHECK` command instead of pulling in a curl/wget binary
    /// into the distroless final image.
    #[arg(long)]
    healthcheck: bool,
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

    if cli.healthcheck {
        let url = format!("http://{}/livez", cli.listen);
        return match reqwest::get(&url).await {
            Ok(resp) if resp.status().is_success() => Ok(()),
            _ => std::process::exit(1),
        };
    }

    let executor = build_broker_executor();
    let app = router(executor, cli.api_token.clone());
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    info!(listen = %cli.listen, "aegis-tool-broker listening");
    axum::serve(listener, app).await?;
    Ok(())
}
