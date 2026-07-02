//! `aegis-node-sensor` — the local runtime sensor described in the Agent
//! Cage architecture (`docs/AegisAgent_Agent_Cage.md`). Deliberately a
//! separate binary from the gateway: the gateway is the brain and must
//! never run untrusted agent code or live on the same host boundary as one.
//!
//! Library target so each module's public API can be built out ahead of
//! `main.rs` wiring it up (mirrors the gateway crate's own `lib.rs`/`main.rs`
//! split) — a binary-only crate flags not-yet-called `pub` items as dead
//! code, since nothing outside the crate could ever call them either.

pub mod command_receiver;
pub mod config;
pub mod gateway_client;
pub mod identity;
pub mod shipper;
pub mod spool;
