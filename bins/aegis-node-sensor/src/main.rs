//! `aegis-node-sensor` CLI entry point. Thin by design — see `lib.rs` for
//! why this is a lib+bin crate. Phase 3.1: config + CLI + identity key
//! handling. Phase 3.2: registers with the gateway on startup and
//! heartbeats on an interval. Phase 3.3: a durable local spool is opened.
//! Phase 3.4: the spool is drained to the gateway's ingest endpoint on its
//! own tick. Phase 3.5 (this file also covers): polls for signed control
//! commands addressed to this sensor, verifies and executes them, and
//! ACK/NACKs the result. Sensor modes (observe/enforce/lockdown behavior
//! beyond just tagging outgoing requests) are Phase 3.6.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use aegis_node_sensor::command_receiver::{CommandReceiver, ExecutionOutcome};
use aegis_node_sensor::config::{CliOverrides, RawSensorConfig, SensorConfig};
use aegis_node_sensor::gateway_client::{GatewayClient, HeartbeatRequest, RegisterRequest};
use aegis_node_sensor::identity::SensorIdentity;
use aegis_node_sensor::shipper::EventShipper;
use aegis_node_sensor::spool::{Lane, SpoolQueue};

/// How often the shipper attempts to drain the spool. Independent of (and
/// much shorter than) the heartbeat interval — events shouldn't sit queued
/// for a full heartbeat cycle just because that's the only tick available.
const SHIP_TICK_INTERVAL: Duration = Duration::from_secs(2);

/// How often the sensor polls the gateway for commands addressed to it.
const COMMAND_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Registration is retried with linear backoff before giving up — the
/// gateway may not be reachable yet on a fresh deployment (container
/// ordering, DNS propagation). Indefinite retry/buffering while running is
/// explicitly Phase 3.4 scope; this is just startup patience.
const REGISTRATION_MAX_ATTEMPTS: u32 = 5;
const REGISTRATION_RETRY_DELAY: Duration = Duration::from_secs(3);

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

    #[arg(long)]
    api_token: Option<String>,

    /// observe | enforce | lockdown
    #[arg(long)]
    mode: Option<String>,

    /// Stable per-host identifier; re-registering with the same value
    /// updates this sensor's existing gateway record instead of creating a
    /// duplicate. Defaults to the machine's hostname.
    #[arg(long)]
    node_key: Option<String>,
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
        api_token: cli.api_token,
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

    let spool = match SpoolQueue::open(&config.spool_dir, config.spool_max_bytes_per_lane) {
        Ok(spool) => spool,
        Err(e) => {
            tracing::error!(error = %e, "failed to open durable local spool — failing closed");
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
        "aegis-node-sensor starting"
    );

    let node_key = cli
        .node_key
        .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        .unwrap_or_else(|| "unknown-host".to_string());
    let hostname = node_key.clone();

    let client = GatewayClient::new(config.gateway_url.clone(), config.api_token.clone());
    let register_req = RegisterRequest {
        node_key,
        hostname,
        environment: None,
        sensor_version: env!("CARGO_PKG_VERSION").to_string(),
        public_key: identity.public_key_hex(),
        capabilities: Vec::new(),
        mode: config.mode.to_string(),
    };

    let registration = match register_with_retries(&client, &register_req).await {
        Ok(registration) => registration,
        Err(e) => {
            tracing::error!(error = %e, "failed to register with gateway after retries — failing closed");
            return ExitCode::FAILURE;
        }
    };
    let sensor_id = registration.sensor_id;
    tracing::info!(
        sensor_id = %sensor_id,
        confirmed_mode = %registration.mode,
        config_version = registration.config_version,
        heartbeat_interval_secs = registration.heartbeat_interval_secs,
        "registered with gateway"
    );

    // The gateway's confirmed interval is authoritative — it may differ from
    // the sensor's local default if the operator has tuned it per tenant.
    let heartbeat_interval = Duration::from_secs(registration.heartbeat_interval_secs);
    let shipper = EventShipper::new(&client);
    let command_receiver = CommandReceiver::new(
        config.gateway_public_key_hex.as_deref(),
        config.tenant_id.clone(),
    );
    if config.gateway_public_key_hex.is_none() {
        tracing::warn!(
            "no gateway_public_key_hex configured — all incoming control commands will be rejected fail-closed"
        );
    }
    let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);
    let mut ship_tick = tokio::time::interval(SHIP_TICK_INTERVAL);
    let mut command_poll_tick = tokio::time::interval(COMMAND_POLL_INTERVAL);
    let mut shutdown = std::pin::pin!(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = heartbeat_tick.tick() => {
                let req = HeartbeatRequest {
                    mode: config.mode.to_string(),
                    sensor_version: env!("CARGO_PKG_VERSION").to_string(),
                    queue_depth_critical: spool.pending_bytes(Lane::Critical).ok().map(|b| b as i64),
                    queue_depth_normal: spool.pending_bytes(Lane::Normal).ok().map(|b| b as i64),
                    ..Default::default()
                };
                if let Err(e) = client.heartbeat(&sensor_id, &req).await {
                    // Transient heartbeat failures don't crash the sensor — the
                    // gateway will simply see a stale last_heartbeat_at until
                    // the next attempt succeeds. The spool durably buffers
                    // events regardless of heartbeat health.
                    tracing::warn!(error = %e, "heartbeat failed, will retry next interval");
                } else {
                    tracing::debug!("heartbeat ok");
                }
            }
            _ = ship_tick.tick() => {
                for lane in [Lane::Critical, Lane::Normal] {
                    match shipper.ship_lane(&spool, lane).await {
                        Ok(0) => {}
                        Ok(n) => tracing::debug!(lane = ?lane, shipped = n, "shipped events"),
                        Err(e) => tracing::warn!(lane = ?lane, error = %e, "ship tick failed"),
                    }
                }
            }
            _ = command_poll_tick.tick() => {
                poll_and_process_commands(&client, &command_receiver, &sensor_id).await;
            }
            _ = &mut shutdown => break,
        }
    }

    tracing::info!("aegis-node-sensor shutting down");
    ExitCode::SUCCESS
}

/// Fetch commands, filter to the ones addressed to this sensor and still
/// awaiting action, then verify/execute/ACK-or-NACK each. The gateway's
/// `status` filter (only `"issued"` commands are re-fetched) is what makes
/// this safe to call on an unbounded interval, including after a sensor
/// restart — a command this sensor already ACKed won't come back.
async fn poll_and_process_commands(
    client: &GatewayClient,
    receiver: &CommandReceiver,
    sensor_id: &str,
) {
    let commands = match client.list_control_commands().await {
        Ok(commands) => commands,
        Err(e) => {
            tracing::warn!(error = %e, "failed to poll control commands, will retry next tick");
            return;
        }
    };

    for cmd in commands
        .into_iter()
        .filter(|c| c.target_type == "sensor" && c.target_id == sensor_id && c.status == "issued")
    {
        let now = chrono::Utc::now();
        let new_status = match receiver.verify(&cmd, now) {
            Ok(()) => match receiver.execute(&cmd) {
                ExecutionOutcome::Acked => {
                    tracing::info!(command_id = %cmd.command_id, action = %cmd.action, "command executed");
                    "acked"
                }
                ExecutionOutcome::Nacked(reason) => {
                    tracing::warn!(command_id = %cmd.command_id, reason = %reason, "command execution nacked");
                    "nacked"
                }
            },
            Err(e) => {
                tracing::warn!(command_id = %cmd.command_id, error = %e, "command verification failed, rejecting");
                "nacked"
            }
        };

        if let Err(e) = client
            .update_command_status(&cmd.command_id, new_status)
            .await
        {
            tracing::warn!(
                command_id = %cmd.command_id,
                error = %e,
                "failed to report command status back to gateway"
            );
        }
    }
}

async fn register_with_retries(
    client: &GatewayClient,
    req: &RegisterRequest,
) -> Result<
    aegis_node_sensor::gateway_client::RegisterResponse,
    aegis_node_sensor::gateway_client::GatewayClientError,
> {
    let mut last_err = None;
    for attempt in 1..=REGISTRATION_MAX_ATTEMPTS {
        match client.register(req).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::warn!(
                    attempt,
                    max_attempts = REGISTRATION_MAX_ATTEMPTS,
                    error = %e,
                    "registration attempt failed"
                );
                last_err = Some(e);
                if attempt < REGISTRATION_MAX_ATTEMPTS {
                    tokio::time::sleep(REGISTRATION_RETRY_DELAY).await;
                }
            }
        }
    }
    Err(last_err.expect("loop runs at least once"))
}
