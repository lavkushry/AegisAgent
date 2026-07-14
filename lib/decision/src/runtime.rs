//! Ports the decision crate needs from the host (storage, metrics, lockout).
//!
//! Evaluation orchestration lives in this crate; durable I/O and gateway
//! process state stay behind this trait so `aegis-decision` never depends on
//! Axum, SQLx, or the gateway binary. Target DAG: Decision → Policy/Canon;
//! storage remains a binary-composed dependency of the runtime implementor.

use aegis_api::models::{
    ApprovalResponseInfo, AuthorizeRequest, AuthorizeToolCall, DecisionRecord, ReceiptIdentity,
};
use aegis_common::errors::AegisError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::agent::AuthorizeAgent;
use crate::write::DecisionAuditWrite;

/// Result of the optional admission webhook (#1143).
#[derive(Debug, Clone)]
pub enum AdmissionEffect {
    /// Webhook not configured — no network call.
    Disabled,
    /// Allow the request unchanged.
    Pass,
    /// Replace `tool_call.parameters` before hashing / Cedar.
    Mutate(Value),
    /// Deny with this reason (persisted as a decision).
    Reject(String),
}

/// Ban / quarantine-record enforcement outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStatus {
    Clear,
    AgentBanned,
    ToolBanned,
    AgentQuarantined,
}

/// Registered skill-action metadata used for risk scoring / defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredActionMeta {
    pub risk: String,
    pub mutates_state: bool,
    pub approval_required: bool,
    pub default_decision: String,
}

/// MCP tool row fields needed on the authorize path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolMeta {
    pub risk: String,
    pub approval_required: bool,
    pub status: String,
}

/// Cedar evaluation result (mirrors `aegis_policy::AuthorizeDecision`).
#[derive(Debug, Clone)]
pub struct PolicyDecisionView {
    pub decision: String,
    pub matched_policies: Vec<String>,
    pub approver_group: Option<String>,
    pub reason: String,
    pub redacted_fields: Vec<String>,
}

/// Inputs for creating a `require_approval` row.
#[derive(Debug, Clone)]
pub struct ApprovalCreateParams {
    pub decision_id: Uuid,
    pub action_hash: String,
    pub approver_group: Option<String>,
    pub callback_url: Option<String>,
    pub callback_secret: Option<String>,
    pub approval_ttl_secs: i64,
}

/// Side-effect ports used by admit/preflight/guard/evaluate.
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

    /// Persist a decision + audit (or dry-run score-only). Returns composite risk score.
    async fn write_decision_and_audit(
        &self,
        write: DecisionAuditWrite<'_>,
    ) -> Result<i32, AegisError>;

    /// Optional admission webhook. Return [`AdmissionEffect::Disabled`] when unset.
    async fn call_admission_webhook(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<AdmissionEffect, AegisError>;

    /// Canonical action hash for the (post-mutation) tool call.
    fn compute_action_hash(
        &self,
        tenant_id: &str,
        request_id: Option<&str>,
        tool_call: &AuthorizeToolCall,
    ) -> String;

    /// Active ban / quarantine-record check for agent and tool.
    async fn enforcement_status(
        &self,
        tenant_id: &str,
        agent_id: &str,
        normalized_tool: &str,
    ) -> Result<EnforcementStatus, AegisError>;

    /// Registered skill-action metadata (risk / approval defaults), if any.
    /// Host owns cache read-through.
    async fn skill_action_meta(
        &self,
        tenant_id: &str,
        normalized_tool: &str,
        normalized_action: &str,
    ) -> Result<Option<RegisteredActionMeta>, AegisError>;

    /// Agent-to-MCP-server permission (#1766). `true` = allowed / unrestricted.
    async fn agent_mcp_server_permitted(
        &self,
        tenant_id: &str,
        agent_id: &str,
        server_key: &str,
    ) -> Result<bool, AegisError>;

    /// MCP server lifecycle status (`active`, `quarantined`, …), if registered.
    async fn mcp_server_status(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Option<String>, AegisError>;

    /// MCP tool metadata for the action key, if registered. Host owns cache.
    async fn mcp_tool_meta(
        &self,
        tenant_id: &str,
        server_key: &str,
        normalized_action: &str,
    ) -> Result<Option<McpToolMeta>, AegisError>;

    /// Load tenant Cedar policies into the engine if not already present.
    async fn ensure_policies_loaded(&self, tenant_id: &str) -> Result<(), AegisError>;

    /// Evaluate Cedar for this request (server-side risk_tier only).
    async fn evaluate_cedar(
        &self,
        tenant_id: &str,
        request: &AuthorizeRequest,
        agent_risk_tier: &str,
        is_tool_known: bool,
        is_mtls: bool,
    ) -> Result<PolicyDecisionView, AegisError>;

    /// Metric: provenance_denials_total.
    fn record_provenance_denial(&self);

    /// Whether the SOC event stream can accept more events (#1299).
    fn audit_stream_has_capacity(&self) -> bool;

    /// Mark audit writer healthy/unhealthy for readiness.
    fn set_audit_writer_healthy(&self, healthy: bool);

    /// Durable receipt for protected decisions.
    async fn emit_receipt_durable(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        decision_id: Uuid,
        decision: &str,
        action_hash: &str,
    ) -> Result<ReceiptIdentity, AegisError>;

    /// Best-effort async receipt for low-risk allow.
    async fn emit_receipt_best_effort(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        decision_id: Uuid,
        decision: &str,
        action_hash: &str,
    );

    /// Set agent status to quarantined (Cedar quarantine decision).
    async fn quarantine_agent(&self, tenant_id: &str, agent_id: &str) -> Result<(), AegisError>;

    /// Out-of-band SOC event after quarantine.
    fn emit_agent_quarantined(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        risk_score: i32,
        reason: &str,
        matched_policies: &[String],
    );

    /// Persist approval + creation audit; validate callback URL.
    async fn create_approval(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        params: ApprovalCreateParams,
    ) -> Result<ApprovalResponseInfo, AegisError>;

    /// Auto-escalate agent risk tier after repeated denials.
    /// Returns `Some((old, new))` when escalated.
    async fn maybe_escalate_risk_tier(
        &self,
        tenant_id: &str,
        agent_id: &str,
        current_tier: &str,
    ) -> Result<Option<(String, String)>, AegisError>;

    /// SOC event + audit after risk escalation (await so audit row is durable).
    #[allow(clippy::too_many_arguments)]
    async fn emit_risk_escalated(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        decision: &str,
        decision_id: Uuid,
        risk_score: i32,
        old_tier: &str,
        new_tier: &str,
        matched_policies: &[String],
    );

    /// Fire-and-forget GitHub PR comment / check updates (Law 3).
    fn notify_github_decision(
        &self,
        request: &AuthorizeRequest,
        decision: &str,
        reason: &str,
        risk_score: i32,
        decision_id: Uuid,
        matched_policies: &[String],
    );
}
