#![recursion_limit = "512"]

//! Library crate for the AegisAgent gateway.
//!
//! This thin `lib.rs` exists so that integration benchmarks (`benches/`) and
//! any future integration tests can exercise the real Axum handlers
//! end-to-end (e.g. `routes::authorize_action`) against a real SQLite pool,
//! without re-implementing gateway internals. The `main.rs` binary is a thin
//! wrapper that uses this library crate.
//!
//! TASK-1313: added to support the `/v1/authorize` criterion benchmark
//! (`benches/authorize_benchmark.rs`), which needs `routes::AppState`,
//! `routes::authorize_action`, and the `db`/`policy`/`events`/`models`
//! helpers used to seed a test database.

pub mod audit_batch;
pub mod baseline;
pub mod correlate;
pub mod db;
pub mod detect;
pub mod events;
pub mod graph;
pub mod ingest;
pub mod jobs;
pub mod metrics;
pub mod models;
pub mod narrate;
pub mod notify;
pub mod policy;
pub mod respond;
pub mod risk;
pub mod routes;
pub mod rule_dsl;
pub mod sign;
