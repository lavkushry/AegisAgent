//! Ports the decision crate needs from the host (storage, metrics, lockout).
//!
//! Evaluation orchestration lives in this crate; durable I/O and gateway
//! process state stay behind this trait so `aegis-decision` never depends on
//! Axum, SQLx, or the gateway binary. Target DAG: Decision → Policy/Canon;
//! storage remains a binary-composed dependency of the runtime implementor.

use aegis_common::errors::AegisError;
use std::net::SocketAddr;

use crate::agent::AuthorizeAgent;

/// Side-effect ports used by admit/evaluate.
///
/// The gateway implements this over `AppState` / `StorageBackend`. Future
/// control-store cutover reimplements the same ports without changing
/// evaluation code.
#[async_trait::async_trait]
pub trait DecisionRuntime: Send + Sync {
    /// Resolve an active agent by bearer token hash/plaintext lookup.
    ///
    /// Fail-closed: quarantined/deleted agents must return `Ok(None)`.
    async fn get_agent_by_token(
        &self,
        tenant_id: &str,
        token: &str,
    ) -> Result<Option<AuthorizeAgent>, AegisError>;

    /// Resolve an active agent by verified mTLS client-certificate CN.
    async fn get_agent_by_mtls_cn(
        &self,
        tenant_id: &str,
        cn: &str,
    ) -> Result<Option<AuthorizeAgent>, AegisError>;

    /// Whether this client+tenant is currently locked out for auth failures.
    fn auth_failure_blocked(&self, client_addr: SocketAddr, tenant_id: &str) -> bool;

    /// Record one failed agent authentication attempt (lockout accounting).
    fn record_auth_failure(&self, client_addr: SocketAddr, tenant_id: &str);
}
