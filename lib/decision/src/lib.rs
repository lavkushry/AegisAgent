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
//! **Current (this crate):** full authorize pipeline orchestration behind
//! [`DecisionRuntime`] ports. Prefer [`run_authorize_pipeline`] from adapters:
//!
//! ```text
//! admit → preflight → guard → metadata → evaluate
//! ```
//!
//! Host (`GatewayDecisionRuntime`) supplies storage, Cedar, caches, SOC sinks,
//! and GitHub side effects. Pure helpers (risk scores, durable-receipt rules)
//! live here; adapters only map [`DecisionOutcome`] to REST/gRPC.
//!
//! This crate has **no** dependency on Axum, tonic, SQLx, or the gateway
//! binary. It depends on `aegis-policy` for trust-chain, environment,
//! identifier normalization, and decision overrides (target DAG:
//! Decision → Policy).
//!
//! ## Public surface
//!
//! **Adapter path (preferred):** [`run_authorize_pipeline`], [`AuthorizeContext`],
//! [`DecisionOutcome`], [`DecisionRuntime`], [`AuthorizeService`],
//! [`EvaluateConfig`], risk helpers.
//!
//! **Stage APIs** (`admit_authorize`, `preflight_authorize`, …) remain public for
//! unit testing and gradual host migration; production adapters should call the
//! unified pipeline.

#![forbid(unsafe_code)]

mod admit;
mod agent;
mod context;
mod error_map;
mod evaluate;
mod guard;
mod metadata;
mod outcome;
mod pipeline;
mod preflight;
mod risk;
mod runtime;
mod service;
mod write;

#[cfg(test)]
mod test_runtime;

pub use admit::{admit_authorize, AdmittedAuthorize};
pub use agent::AuthorizeAgent;
pub use context::{AuthCredential, AuthorizeContext, Transport};
pub use evaluate::{evaluate_authorize, EvaluateConfig};
pub use guard::{guard_authorize, mcp_server_key_from_tool, GuardedAuthorize};
pub use metadata::{metadata_authorize, MetadataAuthorize};
pub use outcome::{DecisionBody, DecisionFailure, DecisionFailureClass, DecisionOutcome};
pub use pipeline::{authorize_response_from_decision_record, run_authorize_pipeline};
pub use preflight::{preflight_authorize, PreflightTerminal, PreflightedAuthorize};
pub use risk::{
    decision_requires_durable_receipt, is_high_risk_for_audit, risk_level_for_score,
    risk_score_for_level,
};
pub use runtime::{
    AdmissionEffect, ApprovalCreateParams, DecisionRuntime, EnforcementStatus, McpToolMeta,
    PolicyDecisionView, RegisteredActionMeta,
};
pub use service::AuthorizeService;
pub use write::DecisionAuditWrite;
