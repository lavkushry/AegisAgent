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
//! - library-owned **admit** ([`admit_authorize`]) — agent resolve, signature,
//!   environment;
//! - library-owned **preflight** ([`preflight_authorize`]) — tool permission,
//!   replay, idempotency lookup, rate limit, quota, heartbeat;
//! - pure risk helpers ([`risk_score_for_level`], …).
//!
//! Cedar evaluation, decision persistence, approvals, and receipts still run
//! in the gateway binary after preflight succeeds. Those stages move here
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
mod outcome;
mod preflight;
mod risk;
mod runtime;
mod service;

pub use admit::{admit_authorize, AdmittedAuthorize};
pub use agent::AuthorizeAgent;
pub use context::{AuthCredential, AuthorizeContext, Transport};
pub use outcome::{DecisionBody, DecisionFailure, DecisionFailureClass, DecisionOutcome};
pub use preflight::{preflight_authorize, PreflightTerminal, PreflightedAuthorize};
pub use risk::{is_high_risk_for_audit, risk_level_for_score, risk_score_for_level};
pub use runtime::DecisionRuntime;
pub use service::AuthorizeService;
