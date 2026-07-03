//! `aegis-cage-runner` — the disposable sandbox executor for unknown/
//! untrusted agents (`docs/AegisAgent_Agent_Cage.md`). A separate binary
//! from the gateway: the gateway issues signed commands and reads
//! receipts/events, it never runs agent code itself.
//!
//! Phase 4.1: the `SandboxRuntime` trait every backend implements,
//! `SandboxSpec` and its forbidden-mount/forbidden-credential validation.
//! Phase 4.2 (this crate also covers): the first concrete backend, Docker,
//! plus isolated per-sandbox workspace management. Still no `main.rs` — the
//! gateway-facing wiring (Phase 4.3) is what will actually invoke this.

pub mod docker_cli;
pub mod docker_runtime;
pub mod error;
pub mod runtime;
pub mod spec;
pub mod workspace;
