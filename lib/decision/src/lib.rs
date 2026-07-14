//! Protocol-neutral authorization decision seam (`aegis-decision`).
//!
//! Repository law (`docs/architecture.md` §4–§5, `ARCHITECTURE.md` §17)
//! places deterministic authorization evaluation in a library crate below
//! protocol adapters. Adapters must:
//!
//! ```text
//! authenticate/parse → typed service call → typed error/response mapping
//! ```
//!
//! ## Status
//!
//! **Current (this crate):**
//! - transport-neutral request context ([`Transport`], [`AuthCredential`],
//!   [`AuthorizeContext`]);
//! - [`AuthorizeService`] trait and protocol-neutral [`DecisionOutcome`];
//! - [`DecisionRuntime`] ports;
//! - library-owned **admit** ([`admit_authorize`]);
//! - library-owned **preflight** ([`preflight_authorize`]);
//! - library-owned **guard** ([`guard_authorize`]) — frozen/revoked, admission
//!   webhook, action hash, ban/quarantine with durable early denials;
//! - pure risk helpers ([`risk_score_for_level`], …).
//!
//! Skill/MCP metadata resolution, Cedar evaluation, approvals, and receipts
//! still run in the gateway after guard succeeds. Those stages move here
//! behind the same runtime ports in follow-on commits.
//!
//! This crate has **no** dependency on Axum, tonic, SQLx, or the gateway
//! binary. It depends on `aegis-policy` for trust-chain, environment, and
//! identifier normalization (target DAG: Decision → Policy).

#![forbid(unsafe_code)]

mod admit;
mod agent;
mod context;
mod error_map;
mod guard;
mod outcome;
mod preflight;
mod risk;
mod runtime;
mod service;
mod write;

pub use admit::{admit_authorize, AdmittedAuthorize};
pub use agent::AuthorizeAgent;
pub use context::{AuthCredential, AuthorizeContext, Transport};
pub use guard::{guard_authorize, mcp_server_key_from_tool, GuardedAuthorize};
pub use outcome::{DecisionBody, DecisionFailure, DecisionFailureClass, DecisionOutcome};
pub use preflight::{preflight_authorize, PreflightTerminal, PreflightedAuthorize};
pub use risk::{is_high_risk_for_audit, risk_level_for_score, risk_score_for_level};
pub use runtime::{AdmissionEffect, DecisionRuntime, EnforcementStatus};
pub use service::AuthorizeService;
pub use write::DecisionAuditWrite;
