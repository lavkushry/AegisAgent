//! Target service trait for authorization evaluation.
//!
//! The gateway currently implements evaluation in
//! `routes::authorize_action_impl`. This trait documents the long-term
//! boundary: a library-owned service that takes protocol-neutral inputs and
//! returns a domain outcome without Axum or tonic types.

use aegis_api::models::AuthorizeRequest;
use aegis_common::errors::AegisError;

use crate::AuthorizeContext;

/// Protocol-neutral authorization evaluation.
///
/// # Contract
///
/// - Input [`AuthorizeContext`] is already authenticated; the service must not
///   re-read HTTP headers or gRPC metadata for tenant authority.
/// - Output is a domain result; adapters map to REST/gRPC wire forms.
/// - Fail-closed: any evaluation failure that is not an explicit policy
///   `deny`/`require_approval` decision should surface as an error the adapter
///   maps to a client-visible failure class.
///
/// # Current implementors
///
/// None in this crate yet. Gateway evaluation will implement this trait (or a
/// richer outcome type) when `authorize_action_impl` is extracted.
#[async_trait::async_trait]
pub trait AuthorizeService: Send + Sync {
    /// Evaluate one authorization request.
    ///
    /// The default associated outcome type is deliberately minimal
    /// (`AuthorizeResponse` or error). Gateway's richer
    /// `AuthorizedOutcome` (StatusError envelopes + partial JSON denials)
    /// will collapse into this shape or a successor enum during extraction.
    async fn authorize(
        &self,
        ctx: AuthorizeContext,
        request: AuthorizeRequest,
    ) -> Result<aegis_api::models::AuthorizeResponse, AegisError>;
}
