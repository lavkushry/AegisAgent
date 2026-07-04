use std::sync::Arc;

use aegis_egress::EgressRule;
use clap::Parser;
use ipnet::IpNet;
use tracing::info;

use aegis_egress_proxy::decider::{EgressDecider, GatewayDecider, PolicyDecider};
use aegis_egress_proxy::events::TracingEventSink;
use aegis_egress_proxy::proxy::{ProxyConfig, ProxyServer};

/// AegisAgent egress proxy: HTTP CONNECT/forward proxy gating every
/// outbound connection on an egress decision. Deny-by-default unless
/// explicitly relaxed.
#[derive(Debug, Parser)]
#[command(name = "aegis-egress-proxy", version)]
struct Cli {
    /// Listen address. Loopback by default — exposing the proxy wider is a
    /// deliberate deployment decision, not a default.
    #[arg(long, default_value = "127.0.0.1:8888")]
    listen: String,

    /// Gateway base URL (e.g. http://127.0.0.1:8080). When set, every
    /// check goes through POST /v1/egress/check (bans, quarantine, durable
    /// evidence); when unset, the local rules below decide standalone.
    #[arg(long)]
    gateway_url: Option<String>,

    /// Bearer token for the gateway. Read from AEGIS_API_TOKEN.
    #[arg(
        long,
        env = "AEGIS_API_TOKEN",
        default_value = "",
        hide_env_values = true
    )]
    api_token: String,

    /// Allow a domain and all of its subdomains. Repeatable.
    #[arg(long = "allow-domain")]
    allow_domains: Vec<String>,

    /// Deny a domain and all of its subdomains. Repeatable.
    #[arg(long = "deny-domain")]
    deny_domains: Vec<String>,

    /// Allow a CIDR range (e.g. 10.0.0.0/8). Repeatable.
    #[arg(long = "allow-cidr")]
    allow_cidrs: Vec<IpNet>,

    /// Deny a CIDR range. Repeatable.
    #[arg(long = "deny-cidr")]
    deny_cidrs: Vec<IpNet>,

    /// Allow destinations no rule matches. Off (deny-by-default) unless
    /// explicitly set — the fail-closed posture.
    #[arg(long)]
    allow_by_default: bool,

    /// Identify the workload for gateway checks (quarantine scoping).
    #[arg(long)]
    agent_id: Option<String>,
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    sandbox_id: Option<String>,

    /// Upload bytes per connection beyond which a large-upload event fires.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    large_upload_threshold_bytes: u64,

    /// Disable closing CONNECT tunnels whose TLS SNI contradicts the
    /// CONNECT host.
    #[arg(long)]
    no_enforce_sni_match: bool,
}

impl Cli {
    fn rules(&self) -> Vec<EgressRule> {
        let mut rules = Vec::new();
        for domain in &self.deny_domains {
            rules.push(EgressRule::deny_domain_suffix(domain.clone()));
        }
        for net in &self.deny_cidrs {
            rules.push(EgressRule::deny_cidr(*net));
        }
        for domain in &self.allow_domains {
            rules.push(EgressRule::allow_domain_suffix(domain.clone()));
        }
        for net in &self.allow_cidrs {
            rules.push(EgressRule::allow_cidr(*net));
        }
        rules
    }
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
    let deny_by_default = !cli.allow_by_default;
    let rules = cli.rules();

    let decider: Arc<dyn EgressDecider> = match &cli.gateway_url {
        Some(gateway_url) => {
            let mut decider = GatewayDecider::new(
                gateway_url,
                cli.api_token.clone(),
                rules,
                Vec::new(),
                deny_by_default,
            );
            decider.agent_id = cli.agent_id.clone();
            decider.run_id = cli.run_id.clone();
            decider.sandbox_id = cli.sandbox_id.clone();
            info!(%gateway_url, "egress decisions via gateway /v1/egress/check");
            Arc::new(decider)
        }
        None => {
            info!(
                deny_by_default,
                rule_count = rules.len(),
                "egress decisions via local standalone policy"
            );
            Arc::new(PolicyDecider::new(deny_by_default, &rules, &[]))
        }
    };

    let config = ProxyConfig {
        large_upload_threshold_bytes: cli.large_upload_threshold_bytes,
        enforce_sni_match: !cli.no_enforce_sni_match,
    };
    let server =
        ProxyServer::bind(&cli.listen, decider, Arc::new(TracingEventSink), config).await?;
    info!(listen = %cli.listen, "aegis-egress-proxy listening");
    server.run().await?;
    Ok(())
}
