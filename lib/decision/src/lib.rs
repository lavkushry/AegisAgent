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
//! **Current (this crate):** transport-neutral request context types
//! ([`Transport`], [`AuthCredential`], [`AuthorizeContext`]) that REST and
//! gRPC adapters construct after authentication. The gateway binary still
//! owns evaluation (`authorize_action_impl`) and wire mapping (`StatusError`,
//! tonic codes, Axum responses).
//!
//! **Target:** move evaluation into this crate behind [`AuthorizeService`]
//! so the gateway only composes storage/policy handles and maps outcomes.
//! That cutover requires a protocol-neutral outcome type that does not
//! depend on Axum `Response` or gateway-only error types — tracked in
//! `ROADMAP.md` Week 3 follow-on.
//!
//! This crate has **no** dependency on Axum, tonic, or the gateway binary.

#![forbid(unsafe_code)]

mod context;
mod service;

pub use context::{AuthCredential, AuthorizeContext, Transport};
pub use service::AuthorizeService;
