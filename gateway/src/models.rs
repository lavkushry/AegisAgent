use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- API Request and Response Structures ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAgentRequest {
    pub agent_key: String,
    pub name: String,
    pub owner_team: Option<String>,
    pub environment: String,
    pub framework: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub risk_tier: String,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAgentResponse {
    pub id: Uuid,
    pub agent_key: String,
    pub agent_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterToolAction {
    pub action_key: String,
    pub description: Option<String>,
    pub risk: String,
    pub mutates_state: bool,
    pub data_access: Option<String>,
    pub approval_required: bool,
    pub default_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterToolRequest {
    pub skill_key: String,
    pub name: String,
    pub r#type: String, // e.g. "static" or "mcp"
    pub auth_type: Option<String>,
    pub owner_team: Option<String>,
    pub default_risk: Option<String>,
    pub actions: Vec<RegisterToolAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMcpServerRequest {
    pub server_key: String,
    pub name: String,
    pub owner_team: Option<String>,
    pub transport: String,
    pub source: Option<String>,
    pub trust_level: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMcpServerResponse {
    pub server_id: String,
    pub server_key: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolManifestItem {
    pub tool_key: String,
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
    pub risk: String,
    pub mutates_state: bool,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverMcpToolsRequest {
    pub tools: Vec<McpToolManifestItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolStatusResponse {
    pub server_key: String,
    pub tool_key: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeAgentContext {
    pub id: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeUserContext {
    pub id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeToolCall {
    pub tool: String,
    pub action: String,
    pub resource: Option<String>,
    pub mutates_state: bool,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeDynamicContext {
    pub source_trust: String,
    pub contains_sensitive_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeTraceContext {
    pub run_id: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub request_id: Option<String>,
    pub agent: AuthorizeAgentContext,
    pub user: Option<AuthorizeUserContext>,
    pub tool_call: AuthorizeToolCall,
    pub context: AuthorizeDynamicContext,
    pub trace: Option<AuthorizeTraceContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponseInfo {
    pub approval_id: Uuid,
    pub status: String,
    pub approver_group: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub action_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub decision_id: Uuid,
    pub decision: String, // allow, deny, require_approval, quarantine, log_only
    pub risk_score: i32,
    pub risk_level: String,
    pub reason: String,
    pub matched_policies: Vec<String>,
    pub approval: Option<ApprovalResponseInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveRequest {
    pub approver_user_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditApprovalRequest {
    pub approver_user_id: String,
    pub edited_tool_call: AuthorizeToolCall,
    pub reason: Option<String>,
}

// --- Database Entity Structs ---

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct TenantRecord {
    pub id: String,
    pub name: String,
    pub plan: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct AgentRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_key: String,
    pub agent_token: String,
    pub name: String,
    pub owner_team: Option<String>,
    pub owner_email: Option<String>,
    pub environment: String,
    pub framework: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub purpose: Option<String>,
    pub risk_tier: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SkillRecord {
    pub id: String,
    pub tenant_id: String,
    pub skill_key: String,
    pub name: String,
    pub r#type: String,
    pub auth_type: Option<String>,
    pub owner_team: Option<String>,
    pub default_risk: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SkillActionRecord {
    pub id: String,
    pub skill_id: String,
    pub action_key: String,
    pub description: Option<String>,
    pub risk: String,
    pub mutates_state: bool,
    pub data_access: Option<String>,
    pub approval_required: bool,
    pub default_decision: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct McpServerRecord {
    pub id: String,
    pub tenant_id: String,
    pub server_key: String,
    pub name: String,
    pub owner_team: Option<String>,
    pub transport: String,
    pub source: Option<String>,
    pub trust_level: String,
    pub endpoint: String,
    pub version: Option<String>,
    pub status: String,
    /// Pinned MCP tool-manifest hash (scheme `mcp-manifest-1`). Empty until the
    /// first discovery pins it; re-pinned on drift. Surfaced so operators can see
    /// the current manifest fingerprint alongside the server's status.
    #[serde(default)]
    pub manifest_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct McpToolRecord {
    pub id: String,
    pub tenant_id: String,
    pub server_id: String,
    pub tool_key: String,
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<String>,
    pub risk: String,
    pub mutates_state: bool,
    pub approval_required: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PolicyRecord {
    pub id: String,
    pub tenant_id: String,
    pub policy_key: String,
    pub name: String,
    pub language: String,
    pub body: String,
    pub version: i32,
    pub status: String,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub user_id: Option<String>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub skill: String,
    pub action: String,
    pub resource: Option<String>,
    pub input_json: String,
    pub decision: String,
    pub risk_score: Option<i32>,
    pub reason: Option<String>,
    pub matched_policy_ids: Option<String>, // Serialized comma-separated or JSON
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: String,
    pub tenant_id: String,
    pub decision_id: String,
    pub status: String,
    pub approver_group: Option<String>,
    pub approver_user_id: Option<String>,
    pub reason: Option<String>,
    pub original_skill_call: String, // JSON
    pub original_call_hash: String,
    pub edited_skill_call: Option<String>, // JSON
    pub expires_at: Option<DateTime<Utc>>,
    pub decided_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct AuditEventRecord {
    pub id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub skill: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub event_json: String,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// SOC Phase 5 — persisted detection alert (one rule fired on one event).
/// Stores identifiers, summary and severity only — never raw payloads or secrets
/// (redaction invariant). Tenant-scoped; `source_event_id` links back to the ASE
/// event that triggered the alert.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct SocAlertRecord {
    pub id: String,
    pub tenant_id: String,
    pub rule: String,
    pub severity: String,
    pub agent_id: String,
    pub source_event_id: String,
    pub summary: String,
    pub created_at: String,
}

/// SOC Phase 5 — persisted correlation incident (multi-event pattern detected).
/// `source_event_ids` is a JSON array of contributing event IDs. Stores identifiers
/// and summary only — never payloads or secrets (redaction invariant). Tenant-scoped.
///
/// Phase 6 lifecycle: `status` is `"open"` on creation and flips to `"closed"` via
/// `POST /v1/incidents/:id/close`. `closed_at` is set to the RFC-3339 close timestamp
/// at that point (NULL while open). The RCA narrator is gated on closed incidents.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct SocIncidentRecord {
    pub id: String,
    pub tenant_id: String,
    pub kind: String,
    pub severity: String,
    pub agent_id: String,
    pub summary: String,
    pub source_event_ids: String, // JSON array
    pub opened_at: String,
    /// Lifecycle status: `"open"` (default) or `"closed"`.
    pub status: String,
    /// RFC-3339 timestamp when the incident was closed; NULL while open.
    pub closed_at: Option<String>,
}

/// SOC query layer — tenant-scoped aggregate counts for `GET /v1/soc/summary`.
/// All counts are derived from parameterized COUNT queries bound to `tenant_id` —
/// no cross-tenant leakage (CWE-284). `alerts_high` = severity='high';
/// `incidents_open` / `incidents_closed` split on the lifecycle `status` column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocSummary {
    pub alerts_total: i64,
    pub alerts_high: i64,
    pub incidents_total: i64,
    pub incidents_open: i64,
    pub incidents_closed: i64,
}

/// Tamper-evident, hash-chained action receipt. The hashed body is every field
/// here EXCEPT `receipt_hash` and `created_at` (see routes::receipt_body_value),
/// with the previous link (`prev_receipt_hash`) inside the body. Scheme aegis-jcs-1.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct ActionReceiptRecord {
    pub id: String,
    pub tenant_id: String,
    pub decision_id: Option<String>,
    pub ts: String,
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub tool: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub source_trust: String,
    pub decision: String,
    pub approver: Option<String>,
    pub action_hash: Option<String>,
    pub prev_receipt_hash: String,
    pub receipt_hash: String,
    /// Optional Ed25519 signature (lowercase hex) computed OVER `receipt_hash`.
    /// Additive metadata — NOT part of the canonical body or `receipt_hash`.
    /// NULL when receipt signing is not configured (hermetic default = unsigned).
    pub signature: Option<String>,
    /// Lowercase-hex Ed25519 public key of the signer, so a third party can verify
    /// the `signature` without contacting the gateway. NULL when unsigned.
    pub signer_public_key: Option<String>,
    pub created_at: DateTime<Utc>,
}
