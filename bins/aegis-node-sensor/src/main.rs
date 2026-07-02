//! `aegis-node-sensor` — the local runtime sensor described in the Agent Cage
//! architecture (`docs/AegisAgent_Agent_Cage.md`). Deliberately a separate
//! binary from the gateway: the gateway is the brain and must never run
//! untrusted agent code or live on the same host boundary as one.
//!
//! Phase 3.1 scope (this file): config + CLI + identity key handling, enough
//! to start, validate, and idle. Registration, heartbeat, the durable local
//! queue, the event shipper, and signed command receipt are separate PRs
//! (3.2-3.6) — this binary does not yet talk to the gateway.

mod config;
mod identity;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use config::{CliOverrides, RawSensorConfig, SensorConfig};
use identity::SensorIdentity;

#[derive(Parser, Debug)]
#[command(
    name = "aegis-node-sensor",
    about = "AegisAgent runtime sensor: local telemetry and signed command enforcement, kept outside the gateway process."
)]
struct Cli {
    /// Path to the sensor's TOML config file. Missing is fine as long as
    /// --gateway-url and --tenant-id are both supplied.
    #[arg(long, default_value = "aegis-sensor.toml")]
    config: PathBuf,

    #[arg(long)]
    gateway_url: Option<String>,

    #[arg(long)]
    tenant_id: Option<String>,

    /// observe | enforce | lockdown
    #[arg(long)]
    mode: Option<String>,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
}

fn load_raw_config(path: &PathBuf) -> Result<RawSensorConfig, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            toml::from_str(&contents).map_err(|e| format!("failed to parse {path:?}: {e}"))
        }
        // A missing config file is fine — CLI flags may supply everything.
        // Any other read failure (permissions, not-a-file) is not silently
        // ignored the same way, since that usually indicates misconfiguration
        // rather than "first run, no file yet".
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RawSensorConfig::default()),
        Err(e) => Err(format!("failed to read {path:?}: {e}")),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let raw = match load_raw_config(&cli.config) {
        Ok(raw) => raw,
        Err(msg) => {
            tracing::error!(error = %msg, "failed to load sensor config — failing closed");
            return ExitCode::FAILURE;
        }
    };

    let overrides = CliOverrides {
        gateway_url: cli.gateway_url,
        tenant_id: cli.tenant_id,
        mode: cli.mode,
    };

    let config = match SensorConfig::resolve(raw, overrides) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, "invalid sensor configuration — failing closed");
            return ExitCode::FAILURE;
        }
    };

    let identity = match SensorIdentity::load_or_generate(&config.identity_key_path) {
        Ok(identity) => identity,
        Err(e) => {
            tracing::error!(error = %e, "failed to load or generate sensor identity — failing closed");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        gateway_url = %config.gateway_url,
        tenant_id = %config.tenant_id,
        mode = %config.mode,
        spool_dir = %config.spool_dir.display(),
        heartbeat_interval_secs = config.heartbeat_interval_secs,
        sensor_public_key = %identity.public_key_hex(),
        "aegis-node-sensor starting (Phase 3.1 skeleton — registration/heartbeat/queue/shipper land in later phases)"
    );

    tokio::signal::ctrl_c().await.ok();
    tracing::info!("aegis-node-sensor shutting down");
    ExitCode::SUCCESS
}
