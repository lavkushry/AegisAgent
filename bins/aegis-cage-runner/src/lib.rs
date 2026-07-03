//! `aegis-cage-runner` — the disposable sandbox executor for unknown/
//! untrusted agents (`docs/AegisAgent_Agent_Cage.md`). A separate binary
//! from the gateway: the gateway issues signed commands and reads
//! receipts/events, it never runs agent code itself.
//!
//! Phase 4.1 scope: the `SandboxRuntime` trait every backend implements,
//! `SandboxSpec` and its forbidden-mount/forbidden-credential validation.
//! No real backend yet — the Docker implementation is Phase 4.2, and this
//! crate has no `main.rs` until there's something for one to run.

pub mod error;
pub mod runtime;
pub mod spec;
