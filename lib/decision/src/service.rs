//! Protocol-neutral [`AuthorizeService`] trait.
//!
//! Evaluation is implemented by [`crate::run_authorize_pipeline`] behind
//! [`crate::DecisionRuntime`] ports. Gateway adapters implement this trait
//! (see `GatewayAuthorizeService`) so REST/gRPC share one typed entry.

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
/// # Implementors
///
/// - Gateway: `GatewayAuthorizeService` — calls [`crate::run_authorize_pipeline`]
///   via `GatewayDecisionRuntime`. Prefer that type's `evaluate` method when
///   adapters need StatusError / partial-JSON fidelity (`AuthorizedOutcome`).
#[async_trait::async_trait]
pub trait AuthorizeService: Send + Sync {
    /// Evaluate one authorization request.
    ///
    /// Success is a full [`aegis_api::models::AuthorizeResponse`] (including
    /// policy `allow` / `deny` / `require_approval` on HTTP 200 paths). Auth,
    /// rate-limit, and similar failures map to [`AegisError`].
    async fn authorize(
        &self,
        ctx: AuthorizeContext,
        request: AuthorizeRequest,
    ) -> Result<aegis_api::models::AuthorizeResponse, AegisError>;
}
