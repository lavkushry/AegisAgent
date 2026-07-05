//! `aegis-tool-broker-connectors` — Phase 6.3 (`docs/AegisAgent_Phased_PR_Plan.md`,
//! section 8, PR 6.3): the initial [`Connector`] implementations plus the
//! broker execution engine that drives them.
//!
//! Connectors (the four from the plan):
//!
//! - [`github::GithubConnector`] — GitHub in mock or real (app/token) mode.
//! - [`http::HttpConnector`] — generic HTTPS requests; the credential goes
//!   into the `Authorization` header and nowhere else, and callers may not
//!   supply their own `Authorization` header.
//! - [`filesystem::FilesystemConnector`] — file read/write/list scoped to a
//!   workspace root; traversal out of the root is rejected.
//! - [`shell::ShellConnector`] — cage commands run with a *scrubbed*
//!   environment inside the workspace; the credential is deliberately never
//!   exported to the child process.
//!
//! The engine ([`executor::BrokerExecutor`]) is where the Phase 6 guarantees
//! meet: a disabled tool fails closed, a state-mutating action requires a
//! consumed approval bound to the exact `action_hash`, credentials resolve
//! fail-closed through the Phase 6.1 [`aegis_tool_broker_core::CredentialResolver`],
//! and **only sanitized output ever leaves** — an anonymous agent never
//! receives a raw credential, not even through an error message.
//!
//! The gateway's `POST /v1/broker/execute` route (next PR) is a thin adapter
//! over [`executor::BrokerExecutor`]: it consumes the approval atomically via
//! storage, then delegates here.

pub mod executor;
pub mod filesystem;
pub mod github;
pub mod http;
pub mod registry;
pub mod shell;

pub use executor::{BrokerExecutor, BrokerToolBinding, ConsumedApproval, ExecuteError};
pub use filesystem::FilesystemConnector;
pub use github::{GithubConnector, GithubMode};
pub use http::HttpConnector;
pub use registry::ConnectorRegistry;
pub use shell::ShellConnector;

// Re-export the core seam so downstream users (the gateway) need only one
// connector-side dependency.
pub use aegis_tool_broker_core::{Connector, ConnectorError, ConnectorOutput};
