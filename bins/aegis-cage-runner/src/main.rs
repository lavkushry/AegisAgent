//! `aegis-cage-runner` CLI entry point — the gateway-integrated execution
//! loop that makes `/v1/agent-cage/runs` functional end-to-end: polls the
//! gateway for `start_run` commands, atomically claims the target run,
//! executes it via `SandboxRuntime`/`DockerRuntime`, reports status back,
//! and handles kill/pause/resume via the same signed control-command
//! mechanism `aegis-node-sensor` uses.
//!
//! Architectural note: `docs/AegisAgent_Agent_Cage.md` intends
//! `Sensor -> Runner` (this binary never talks to the gateway directly,
//! only via the node sensor). But there is no IPC between the two
//! processes today — `aegis-node-sensor`'s own `CommandReceiver::execute()`
//! is a stub that only acks `kill_run` as a no-op, explicitly deferring
//! "real process control" to this crate. Building a new sensor<->runner
//! transport would be new, unreviewed protocol surface in an already
//! security-sensitive change, so this binary talks to the gateway
//! directly instead, reusing the exact `Authorization: Bearer <api_token>`
//! tenant-bearer-token pattern `aegis-node-sensor`/`aegis-egress-proxy`
//! already use. A deliberate, documented deviation, not an oversight.
//!
//! Single-run-in-flight by design (matches the project's "narrow initial
//! PR" convention) — horizontal scaling is more runner replicas
//! independently racing to claim different runs via the atomic
//! `claim_agent_run` compare-and-swap, not concurrency within one process.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use uuid::Uuid;

use aegis_cage_runner::command_receiver::{CommandReceiver, ExecutionOutcome};
use aegis_cage_runner::config::{CliOverrides, RawRunnerConfig, RunnerConfig};
use aegis_cage_runner::docker_runtime::DockerRuntime;
use aegis_cage_runner::error::CageError;
use aegis_cage_runner::gateway_client::{AgentRunPayload, GatewayClient, GatewayClientError};
use aegis_cage_runner::http_event_sink::HttpEventSink;
use aegis_cage_runner::runtime::{KillReason, SandboxHandle, SandboxRuntime, SandboxStatus};

#[derive(Parser, Debug)]
#[command(
    name = "aegis-cage-runner",
    about = "AegisAgent disposable sandbox executor: claims and executes gateway-registered cage runs."
)]
struct Cli {
    /// Path to the runner's TOML config file. Missing is fine as long as
    /// the required fields are supplied via flags.
    #[arg(long, default_value = "aegis-cage-runner.toml")]
    config: PathBuf,

    #[arg(long)]
    gateway_url: Option<String>,

    #[arg(long)]
    tenant_id: Option<String>,

    #[arg(long)]
    api_token: Option<String>,

    #[arg(long)]
    runner_id: Option<String>,

    #[arg(long)]
    gateway_public_key_hex: Option<String>,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
}

fn load_raw_config(path: &PathBuf) -> Result<RawRunnerConfig, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            toml::from_str(&contents).map_err(|e| format!("failed to parse {path:?}: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RawRunnerConfig::default()),
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
            tracing::error!(error = %msg, "failed to load runner config — failing closed");
            return ExitCode::FAILURE;
        }
    };

    let overrides = CliOverrides {
        gateway_url: cli.gateway_url,
        tenant_id: cli.tenant_id,
        api_token: cli.api_token,
        runner_id: cli.runner_id,
        gateway_public_key_hex: cli.gateway_public_key_hex,
    };

    let config = match RunnerConfig::resolve(raw, overrides) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, "invalid runner configuration — failing closed");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = std::fs::create_dir_all(&config.workspace_root) {
        tracing::error!(error = %e, "failed to create workspace root — failing closed");
        return ExitCode::FAILURE;
    }

    tracing::info!(
        gateway_url = %config.gateway_url,
        tenant_id = %config.tenant_id,
        runner_id = %config.runner_id,
        workspace_root = %config.workspace_root.display(),
        "aegis-cage-runner starting"
    );

    let client = Arc::new(GatewayClient::new(
        config.gateway_url.clone(),
        config.api_token.clone(),
    ));
    let receiver = Arc::new(CommandReceiver::new(
        Some(&config.gateway_public_key_hex),
        config.tenant_id.clone(),
    ));
    let event_sink = Arc::new(HttpEventSink::new(client.clone()));
    let runtime = Arc::new(DockerRuntime::with_event_sink(
        config.workspace_root.clone(),
        event_sink,
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    let mut claim_poll_tick =
        tokio::time::interval(Duration::from_secs(config.claim_poll_interval_secs));
    let mut shutdown_rx_outer = shutdown_rx.clone();
    loop {
        tokio::select! {
            _ = claim_poll_tick.tick() => {
                if let Some(run) = find_and_claim_a_run(&client, &receiver, &config.runner_id).await {
                    run_one(
                        runtime.clone(),
                        client.clone(),
                        receiver.clone(),
                        run,
                        config.runner_id.clone(),
                        Duration::from_secs(config.heartbeat_interval_secs),
                        Duration::from_secs(config.control_poll_interval_secs),
                        shutdown_rx.clone(),
                    )
                    .await;
                }
            }
            _ = shutdown_rx_outer.changed() => {
                if *shutdown_rx_outer.borrow() {
                    break;
                }
            }
        }
    }

    tracing::info!("aegis-cage-runner shutting down");
    ExitCode::SUCCESS
}

/// Poll for `start_run` commands, verify each, and attempt to claim the
/// target run. Losing the claim race (another runner instance got there
/// first) is a routine, expected outcome — logged at `debug!`, not
/// `warn!`. Both a lost race and a verify failure still ack/nack the
/// command so it isn't rescanned forever.
async fn find_and_claim_a_run(
    client: &GatewayClient,
    receiver: &CommandReceiver,
    runner_id: &str,
) -> Option<AgentRunPayload> {
    let commands = match client.list_control_commands().await {
        Ok(commands) => commands,
        Err(e) => {
            tracing::warn!(error = %e, "failed to poll control commands, will retry next tick");
            return None;
        }
    };

    for cmd in commands
        .into_iter()
        .filter(|c| c.target_type == "run" && c.action == "start_run" && c.status == "issued")
    {
        let now = chrono::Utc::now();
        if let Err(e) = receiver.verify(&cmd, now) {
            tracing::warn!(command_id = %cmd.command_id, error = %e, "start_run command verification failed, rejecting");
            let _ = client
                .update_command_status(&cmd.command_id, "nacked")
                .await;
            continue;
        }

        match client.claim_run(&cmd.target_id, runner_id).await {
            Ok(run) => {
                let _ = client.update_command_status(&cmd.command_id, "acked").await;
                tracing::info!(run_id = %run.id, "claimed run");
                return Some(run);
            }
            Err(GatewayClientError::ClaimLost) => {
                tracing::debug!(run_id = %cmd.target_id, "lost the claim race for this run");
                let _ = client.update_command_status(&cmd.command_id, "acked").await;
            }
            Err(e) => {
                tracing::warn!(run_id = %cmd.target_id, error = %e, "failed to claim run, will retry next tick");
            }
        }
    }
    None
}

/// Execute one claimed run to completion: create -> start -> (heartbeat +
/// control-command polling + wait-or-timeout, raced) -> destroy -> final
/// status report. Never returns early leaving a live, unsupervised
/// container behind — every exit path attempts `destroy` first.
#[allow(clippy::too_many_arguments)]
async fn run_one(
    runtime: Arc<DockerRuntime>,
    client: Arc<GatewayClient>,
    receiver: Arc<CommandReceiver>,
    run: AgentRunPayload,
    runner_id: String,
    heartbeat_interval: Duration,
    control_poll_interval: Duration,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let sandbox_id = Uuid::new_v4().to_string();
    let spec = match run.build_sandbox_spec(&sandbox_id) {
        Ok(spec) => spec,
        Err(e) => {
            tracing::error!(run_id = %run.id, error = %e, "failed to build sandbox spec from run, aborting");
            let _ = client
                .update_run_status(&run.id, &runner_id, "killed", Some(chrono::Utc::now()))
                .await;
            return;
        }
    };
    let timeout_secs = spec.resources.timeout_seconds;

    let handle = match runtime.create(&spec).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(run_id = %run.id, error = %e, "failed to create sandbox, aborting");
            let _ = client
                .update_run_status(&run.id, &runner_id, "killed", Some(chrono::Utc::now()))
                .await;
            return;
        }
    };

    if let Err(e) = runtime.start(&handle).await {
        tracing::error!(run_id = %run.id, error = %e, "failed to start sandbox, cleaning up");
        let _ = runtime.destroy(&handle).await;
        let _ = client
            .update_run_status(&run.id, &runner_id, "killed", Some(chrono::Utc::now()))
            .await;
        return;
    }
    if let Err(e) = client
        .update_run_status(&run.id, &runner_id, "running", None)
        .await
    {
        tracing::warn!(run_id = %run.id, error = %e, "failed to report running status");
    }

    let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);
    let mut control_tick = tokio::time::interval(control_poll_interval);
    let wait_future = runtime.wait_or_kill_on_timeout(&handle, Duration::from_secs(timeout_secs));
    tokio::pin!(wait_future);
    // Set by signed kill/quarantine so the final status report is not
    // collapsed to "finished" when Docker only exposes "exited".
    let control_terminal: Arc<std::sync::Mutex<Option<&'static str>>> =
        Arc::new(std::sync::Mutex::new(None));

    let final_state = loop {
        tokio::select! {
            biased;
            state = &mut wait_future => break state,
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!(run_id = %run.id, "shutdown requested mid-run, killing sandbox");
                    let _ = runtime.kill(&handle, KillReason::OperatorRequest { actor: "runner-shutdown".to_string() }).await;
                    let _ = runtime.destroy(&handle).await;
                    let _ = client.update_run_status(&run.id, &runner_id, "killed", Some(chrono::Utc::now())).await;
                    return;
                }
            }
            _ = heartbeat_tick.tick() => {
                match client.heartbeat_run(&run.id, &runner_id).await {
                    Ok(()) => tracing::debug!(run_id = %run.id, "heartbeat ok"),
                    Err(GatewayClientError::RejectedRequest { status, .. }) if status == reqwest::StatusCode::CONFLICT => {
                        tracing::warn!(run_id = %run.id, "lost the claim lease — killing sandbox locally");
                        let _ = runtime.kill(&handle, KillReason::OperatorRequest { actor: "lease-lost".to_string() }).await;
                        let _ = runtime.destroy(&handle).await;
                        return;
                    }
                    Err(e) => tracing::warn!(run_id = %run.id, error = %e, "heartbeat failed, will retry next interval"),
                }
            }
            _ = control_tick.tick() => {
                poll_and_process_run_commands(
                    &client,
                    &receiver,
                    &runtime,
                    &handle,
                    &run.id,
                    &runner_id,
                    &control_terminal,
                )
                .await;
            }
        }
    };

    let control_status = control_terminal.lock().ok().and_then(|g| *g);
    let (status_str, finished_at) = if let Some(status) = control_status {
        (status, Some(chrono::Utc::now()))
    } else {
        match final_state {
            Ok(state) => {
                let status_str = match state.status {
                    SandboxStatus::Killed | SandboxStatus::TimedOut => "killed",
                    _ => "finished",
                };
                (status_str, Some(chrono::Utc::now()))
            }
            Err(e) => {
                tracing::error!(run_id = %run.id, error = %e, "error waiting on sandbox");
                ("killed", Some(chrono::Utc::now()))
            }
        }
    };

    if let Err(e) = runtime.destroy(&handle).await {
        tracing::warn!(run_id = %run.id, error = %e, "failed to destroy sandbox");
    }
    if let Err(e) = client
        .update_run_status(&run.id, &runner_id, status_str, finished_at)
        .await
    {
        tracing::warn!(run_id = %run.id, error = %e, "failed to report final run status");
    }
}

/// Poll for kill/pause/resume/quarantine commands addressed to this
/// specific run, verify each, and map it onto the corresponding
/// `SandboxRuntime` method. Successful kill/quarantine also records a
/// terminal status override so the outer loop does not report `finished`.
async fn poll_and_process_run_commands(
    client: &GatewayClient,
    receiver: &CommandReceiver,
    runtime: &DockerRuntime,
    handle: &SandboxHandle,
    run_id: &str,
    runner_id: &str,
    control_terminal: &std::sync::Mutex<Option<&'static str>>,
) {
    let commands = match client.list_control_commands().await {
        Ok(commands) => commands,
        Err(e) => {
            tracing::warn!(run_id = %run_id, error = %e, "failed to poll control commands, will retry next tick");
            return;
        }
    };

    for cmd in commands.into_iter().filter(|c| {
        c.target_type == "run"
            && c.target_id == run_id
            && c.action != "start_run"
            && c.status == "issued"
    }) {
        let now = chrono::Utc::now();
        if let Err(e) = receiver.verify(&cmd, now) {
            tracing::warn!(command_id = %cmd.command_id, error = %e, "command verification failed, rejecting");
            let _ = client
                .update_command_status(&cmd.command_id, "nacked")
                .await;
            continue;
        }

        let outcome = match receiver.execute(&cmd) {
            ExecutionOutcome::Nacked(reason) => {
                tracing::warn!(command_id = %cmd.command_id, reason = %reason, "command not recognized");
                Err(reason)
            }
            ExecutionOutcome::Acked => match cmd.action.as_str() {
                "pause_run" => runtime.pause(handle).await.map_err(|e| e.to_string()),
                "resume_run" => runtime.resume(handle).await.map_err(|e| e.to_string()),
                "kill_run" => runtime
                    .kill(
                        handle,
                        KillReason::SignedCommand {
                            command_id: cmd.command_id.clone(),
                        },
                    )
                    .await
                    .map_err(|e: CageError| e.to_string()),
                "quarantine_run" => runtime
                    .kill(
                        handle,
                        KillReason::PolicyViolation {
                            reason: cmd.reason.clone().unwrap_or_default(),
                        },
                    )
                    .await
                    .map_err(|e: CageError| e.to_string()),
                other => Err(format!("unrecognized run action: {other}")),
            },
        };

        let new_status = match outcome {
            Ok(()) => {
                tracing::info!(command_id = %cmd.command_id, action = %cmd.action, "command executed");
                // Report run lifecycle status so operators/e2e see the control
                // outcome, not only the Docker "exited" → finished path from
                // wait_or_kill_on_timeout (which cannot distinguish a signed
                // kill from a clean process exit).
                match cmd.action.as_str() {
                    "pause_run" => {
                        let _ = client
                            .update_run_status(run_id, runner_id, "paused", None)
                            .await;
                    }
                    "resume_run" => {
                        let _ = client
                            .update_run_status(run_id, runner_id, "running", None)
                            .await;
                    }
                    "kill_run" | "quarantine_run" => {
                        let terminal = if cmd.action == "quarantine_run" {
                            "quarantined"
                        } else {
                            "killed"
                        };
                        if let Ok(mut slot) = control_terminal.lock() {
                            *slot = Some(terminal);
                        }
                        let _ = client
                            .update_run_status(
                                run_id,
                                runner_id,
                                terminal,
                                Some(chrono::Utc::now()),
                            )
                            .await;
                    }
                    _ => {}
                }
                "acked"
            }
            Err(reason) => {
                tracing::warn!(command_id = %cmd.command_id, reason = %reason, "command execution failed");
                "nacked"
            }
        };
        let _ = client
            .update_command_status(&cmd.command_id, new_status)
            .await;
    }
}
