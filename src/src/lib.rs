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

// Re-exported from workspace libraries
pub use aegis_storage::audit_batch;
pub use aegis_storage::db;
pub use aegis_storage::risk_escalation;

pub use aegis_soc::backtest;
pub use aegis_soc::baseline;
pub use aegis_soc::correlate;
pub use aegis_soc::detect;
pub use aegis_soc::events;
pub use aegis_soc::ingest;
pub use aegis_soc::mcp_inspect;
pub use aegis_soc::narrate;
pub use aegis_soc::notify;
pub use aegis_soc::qdrant;
pub use aegis_soc::respond;
pub use aegis_soc::rule_dsl;
pub use aegis_soc::webhook_export;

pub use aegis_policy::cedar as policy;
pub use aegis_policy::risk;
pub use aegis_policy::trust_chain;

pub use aegis_api::models;

pub use aegis_common::metrics;

// Binary-specific modules
pub mod gh_checks;
pub mod gh_comment;
pub mod graph;
pub mod grpc;
pub mod jobs;
pub mod routes;
pub mod sign;
