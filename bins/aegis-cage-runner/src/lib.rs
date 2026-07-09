//! `aegis-cage-runner` — the disposable sandbox executor for unknown/
//! untrusted agents (`docs/AegisAgent_Agent_Cage.md`). A separate binary
//! from the gateway: the gateway issues signed commands and reads
//! receipts/events, it never runs agent code itself.
//!
//! Phase 4.1: the `SandboxRuntime` trait every backend implements,
//! `SandboxSpec` and its forbidden-mount/forbidden-credential validation.
//! Phase 4.2 (this crate also covers): the first concrete backend, Docker,
//! plus isolated per-sandbox workspace management. Phase 4.4 (this crate
//! also covers): the `agent_run_started`/`process_started`/
//! `process_exited`/`agent_run_finished` runtime event stream ([`events`]).
//!
//! The gateway-integrated execution loop (this crate's `main.rs`): polls
//! the gateway for `start_run` commands, atomically claims the target run,
//! executes it via [`runtime::SandboxRuntime`]/
//! [`docker_runtime::DockerRuntime`], reports status back, and handles
//! kill/pause/resume via the same signed control-command mechanism
//! `aegis-node-sensor` uses. Talks to the gateway directly (not via the
//! node sensor) — see `main.rs`'s module doc comment for why.

pub mod command_receiver;
pub mod config;
pub mod docker_cli;
pub mod docker_runtime;
pub mod error;
pub mod events;
pub mod gateway_client;
pub mod http_event_sink;
pub mod runtime;
pub mod spec;
pub mod workspace;
