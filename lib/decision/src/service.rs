//! Target service trait for authorization evaluation.
//!
//! Gateway implements this trait via `GatewayAuthorizeService` (see the
//! gateway `authorize_service` module). Evaluation still runs in the gateway
//! binary; this trait is the stable library boundary for adapters and future
//! extraction of `authorize_action_impl` into this crate.

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
/// - Gateway: `GatewayAuthorizeService` — full evaluation today; richer wire
///   outcomes (`AuthorizedOutcome`) are available on that type's `evaluate`
///   method for REST/gRPC adapters that need StatusError/partial-JSON fidelity.
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
