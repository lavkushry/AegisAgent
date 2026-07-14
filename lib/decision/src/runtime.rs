//! Ports the decision crate needs from the host (storage, metrics, lockout).
//!
//! Evaluation orchestration lives in this crate; durable I/O and gateway
//! process state stay behind this trait so `aegis-decision` never depends on
//! Axum, SQLx, or the gateway binary. Target DAG: Decision → Policy/Canon;
//! storage remains a binary-composed dependency of the runtime implementor.

use aegis_api::models::DecisionRecord;
use aegis_common::errors::AegisError;
use chrono::{DateTime, Utc};
use std::net::SocketAddr;

use crate::agent::AuthorizeAgent;

/// Side-effect ports used by admit/preflight/evaluate.
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

    /// Agent-to-tool permission (#1390). `true` = allowed (or unrestricted).
    async fn agent_tool_permitted(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool: &str,
    ) -> Result<bool, AegisError>;

    /// Idempotency lookup (#0072). `None` when no prior decision exists.
    async fn get_decision_by_request_id(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<DecisionRecord>, AegisError>;

    /// Replay-nonce check (#1306). Returns `true` if this nonce is a replay.
    /// Host chooses in-memory vs durable store. Fail closed on store errors.
    async fn check_and_record_nonce(
        &self,
        tenant_id: &str,
        agent_id: &str,
        nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AegisError>;

    /// Per-tenant authorize rate limit. `true` = allow this request.
    async fn check_rate_limit(&self, tenant_id: &str) -> bool;

    /// Per-tenant request quota. `true` = allow this request.
    fn check_quota(&self, tenant_id: &str) -> bool;

    /// Debounced last-seen heartbeat for the agent (no durable write required).
    fn touch_heartbeat(&self, tenant_id: &str, agent_id: &str);
}
