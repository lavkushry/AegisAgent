use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

// --- API Request and Response Structures ---

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
    /// Optional HMAC-SHA256 signing key (#1403). When set, every
    /// `/v1/authorize` call must carry `X-Aegis-Request-Signature: sha256=<hmac-hex>`.
    #[serde(default)]
    pub signing_key: Option<String>,
    /// Environments this agent is permitted to call from (#1391).
    /// `None` or empty = unrestricted. Stored as JSON in the DB.
    #[serde(default)]
    pub allowed_environments: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterAgentResponse {
    pub id: Uuid,
    pub agent_key: String,
    pub agent_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PatchAgentRequest {
    pub name: Option<String>,
    pub owner_team: Option<String>,
    pub owner_email: Option<String>,
    pub environment: Option<String>,
    pub framework: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub purpose: Option<String>,
    pub risk_tier: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterToolAction {
    pub action_key: String,
    pub description: Option<String>,
    pub risk: String,
    pub mutates_state: bool,
    pub data_access: Option<String>,
    pub approval_required: bool,
    pub default_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterToolRequest {
    pub skill_key: String,
    pub name: String,
    pub r#type: String, // e.g. "static" or "mcp"
    pub auth_type: Option<String>,
    pub owner_team: Option<String>,
    pub default_risk: Option<String>,
    pub actions: Vec<RegisterToolAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterMcpServerRequest {
    pub server_key: String,
    pub name: String,
    pub owner_team: Option<String>,
    pub transport: String,
    pub source: Option<String>,
    pub trust_level: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterMcpServerResponse {
    pub server_id: String,
    pub server_key: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpToolManifestItem {
    pub tool_key: String,
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
    pub risk: String,
    pub mutates_state: bool,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiscoverMcpToolsRequest {
    pub tools: Vec<McpToolManifestItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpToolStatusResponse {
    pub server_key: String,
    pub tool_key: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeAgentContext {
    pub id: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeUserContext {
    pub id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeToolCall {
    pub tool: String,
    pub action: String,
    pub resource: Option<String>,
    pub mutates_state: bool,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeDynamicContext {
    pub source_trust: String,
    pub contains_sensitive_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeTraceContext {
    pub run_id: String,
    pub trace_id: String,
    /// #1293: the run_id of the upstream agent that triggered this call, if
    /// this is a hop in a multi-agent chain (A -> B -> C). `None` for a
    /// chain's first hop. Recorded on the decision for audit/evidence-graph
    /// reconstruction; not itself used in trust computation.
    #[serde(default)]
    pub parent_run_id: Option<String>,
    /// #1293: the most-restrictive (tighten-only) trust level accumulated by
    /// the upstream caller's chain so far, e.g. returned to Agent A in its
    /// own `/v1/authorize` response and forwarded here by Agent A when it
    /// triggers Agent B. `None` for a chain's first hop, in which case this
    /// hop's effective trust is simply its own `context.source_trust`.
    #[serde(default)]
    pub root_trust_level: Option<String>,
}

/// Optional webhook callback (#1187/TASK-0082-0083) requested by the caller
/// for a `require_approval` decision. If set, the resulting approval row
/// stores `callback_url` verbatim and `sha256(secret)` as
/// `callback_secret_hash` — the plaintext secret is never persisted
/// (redaction invariant). A future dispatcher can sign callback payloads with
/// `sha256(secret)` as the HMAC key, which the receiver can re-derive from
/// the secret it already holds.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalCallback {
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    pub request_id: Option<String>,
    pub agent: AuthorizeAgentContext,
    pub user: Option<AuthorizeUserContext>,
    pub tool_call: AuthorizeToolCall,
    pub context: AuthorizeDynamicContext,
    pub trace: Option<AuthorizeTraceContext>,
    /// Optional approval-callback registration (#1187/TASK-0082-0083).
    #[serde(default)]
    pub callback: Option<ApprovalCallback>,
    /// Opt-in replay-protection nonce (#1306). When present, the gateway
    /// rejects a repeat of the same `(tenant, agent, nonce)` with 409
    /// `replay_nonce_reused`. `None` skips all replay checks (backwards
    /// compatible). This is a distinct mechanism from `request_id`
    /// idempotency above: `request_id` *replays the original decision*,
    /// while `nonce` *rejects* the repeat outright.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Optional client-supplied timestamp paired with `nonce` (#1306). If
    /// older than the replay window (5 minutes), the gateway rejects with
    /// 409 `replay_timestamp_expired`. Ignored if `nonce` is `None`.
    #[serde(default)]
    pub timestamp: Option<DateTime<Utc>>,
    /// Dry-run / simulation mode (#1281): evaluate the decision (Cedar +
    /// risk scoring) but skip every persistence and side-effecting path —
    /// no `decisions`/`audit_events`/`approvals`/`action_receipts` rows, no
    /// SOC event, no agent quarantine, no GitHub PR comment/check update.
    /// `None`/`Some(false)` is the normal persisted path.
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalResponseInfo {
    pub approval_id: Uuid,
    pub status: String,
    pub approver_group: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub action_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeResponse {
    pub decision_id: Uuid,
    pub decision: String, // allow, deny, require_approval, quarantine, redact, log_only
    pub risk_score: i32,
    pub risk_level: String,
    /// Advisory composite risk score (#1289), `0..=100`. Display metadata
    /// only — never gates `decision` (Law 1).
    pub composite_risk_score: i32,
    pub reason: String,
    pub matched_policies: Vec<String>,
    pub approval: Option<ApprovalResponseInfo>,
    /// Fields to strip from the tool-call parameters before execution (#1385).
    /// Non-empty only when `decision == "redact"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
    /// #1293: the effective (tighten-only) trust level used to gate this
    /// decision — the most restrictive of this hop's own `context.source_trust`
    /// and any inherited `trace.root_trust_level`. The caller should forward
    /// this value as `trace.root_trust_level` if it triggers a downstream
    /// agent, so trust propagates correctly through multi-hop chains.
    pub root_trust_level: String,
    /// #1281: true if this response was produced by a dry-run request
    /// (`AuthorizeRequest.dry_run == Some(true)`) — nothing was persisted.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApproveRequest {
    pub approver_user_id: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EditApprovalRequest {
    pub approver_user_id: String,
    pub edited_tool_call: AuthorizeToolCall,
    pub reason: Option<String>,
}

// --- Database Entity Structs ---

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct TenantRecord {
    pub id: String,
    pub name: String,
    pub plan: String,
    pub created_at: DateTime<Utc>,
    /// Whether the SOC Response Engine (Phase 4, #1184) may automatically
    /// take containment actions (freeze agents, force approval) for this
    /// tenant's incidents. Defaults to `true` (additive migration).
    #[serde(default = "default_true")]
    pub auto_respond_enabled: bool,
    /// #1295: whether `POST /v1/agents/:id/report-leaked-token` may actually
    /// rotate the agent's token when a leak is reported. `false` still
    /// records the leak detection (audit + SOC event) but leaves the
    /// existing token valid. Defaults to `true` (additive migration).
    #[serde(default = "default_true")]
    pub auto_rotate_token_on_leak_enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct AgentRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_key: String,
    /// SHA-256 hash of the agent's bearer token (CWE-200, #1326): `GET
    /// /v1/agents`/`GET /v1/agents/:id` previously serialized this whole
    /// struct directly, leaking the hash over the management API even though
    /// it's never needed there — the plaintext token is returned exactly
    /// once, at registration/rotation time, via a distinct response shape.
    #[serde(default, skip_serializing)]
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
    /// Timestamp of the most recent successful `/v1/authorize` call by this agent
    /// (heartbeat). NULL if the agent has never made a request. Additive (#0080).
    #[serde(default)]
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Operator-supplied reason for the most recent freeze, surfaced in the SOC UI
    /// and audit trail. Cleared on unfreeze. Additive (#0079).
    #[serde(default)]
    pub frozen_reason: Option<String>,
    /// Timestamp the agent was placed into `quarantined` status. NULL while not
    /// quarantined; cleared when the status changes away from `quarantined`.
    /// Additive (#0078).
    #[serde(default)]
    pub quarantined_at: Option<DateTime<Utc>>,
    /// Set by the SOC Response Engine (Phase 4, #1184) when a `trust_escalation`
    /// incident is detected: forces every subsequent `allow` decision for this
    /// agent into `require_approval` until an operator clears it. Additive.
    #[serde(default)]
    pub force_approval: bool,
    /// HMAC-SHA256 signing key for request-body integrity verification (#1403).
    /// `None` = opt-out (backwards compatible). When set, every `/v1/authorize`
    /// call must carry a valid `X-Aegis-Request-Signature: sha256=<hex>` header.
    /// Unlike `agent_token` this is a live plaintext shared secret (not a
    /// hash) — never serialize it over the API (CWE-522, #1326).
    #[serde(default, skip_serializing)]
    pub signing_key: Option<String>,
    /// JSON-encoded list of environments this agent may call from (#1391), e.g.
    /// `["production","staging"]`. `None` = unrestricted (backwards-compatible).
    #[serde(default)]
    pub allowed_environments: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A single agent-to-tool permission binding (#1390).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct AgentToolPermission {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub tool_key: String,
    pub created_at: DateTime<Utc>,
}

/// Request body for `POST /v1/agents/:id/permissions` (#1390).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct GrantToolPermissionRequest {
    pub tool_key: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow, ToSchema)]
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
#[derive(Debug, Clone, sqlx::FromRow, ToSchema)]
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

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
    /// Timestamp of the most recent `POST /v1/mcp/servers/:server_key/tools`
    /// discovery call. `None` if the server has never had a discovery run.
    #[serde(default)]
    pub last_discovery_at: Option<DateTime<Utc>>,
    /// #1333: per-server opt-in toggle for MCP response inspection. Defaults
    /// to `false` — inspection only runs once explicitly enabled.
    #[serde(default)]
    pub inspection_enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// TASK-0090 (#936): one row per MCP tool-manifest discovery call, capturing
/// the computed `mcp-manifest-1` hash and the raw discovered tool list so
/// manifest drift can be diffed after the fact. #1336: also read in production
/// by `discover_mcp_tools` to classify drift severity against the prior snapshot.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct McpManifestSnapshotRecord {
    pub id: String,
    pub tenant_id: String,
    pub server_key: String,
    pub manifest_hash: String,
    pub manifest_json: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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

/// TASK-0091 (#937): an archived prior version of a [`PolicyRecord`], written
/// by `routes::update_policy` before the `policies` row is overwritten in
/// place — gives operators an audit trail of every prior policy version.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct PolicyVersionRecord {
    pub id: String,
    pub tenant_id: String,
    pub policy_id: String,
    pub policy_key: String,
    pub name: String,
    pub language: String,
    pub body: String,
    pub version: i32,
    pub status: String,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub archived_at: DateTime<Utc>,
}

/// TASK-0089 (#935): a historical risk-score sample, written for every
/// `/v1/authorize` decision so operators can see an agent's risk trend over
/// time rather than only its latest decision's score.
#[cfg(test)]
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct AgentRiskScoreRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub decision_id: String,
    pub score: i32,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
    /// Caller-supplied idempotency key (#0072), copied from
    /// `AuthorizeRequest.request_id`. NULL if the caller didn't supply one. A
    /// repeat `/v1/authorize` call with the same `(tenant_id, agent_id,
    /// request_id)` returns this decision unchanged instead of re-evaluating.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Wall-clock time in milliseconds spent evaluating this `/v1/authorize`
    /// call, from agent resolution through the final decision (excludes the
    /// HTTP framing itself). NULL on rows written before this column existed,
    /// and on idempotent replays (#0072), which intentionally skip
    /// re-evaluation. Additive (#0081) — surfaced for SOC/perf dashboards.
    #[serde(default)]
    pub latency_ms: Option<i64>,
    /// Advisory composite risk score (#1289), `0..=100`. Computed by
    /// `risk::compute_composite_risk_score` and never used to gate the
    /// `decision` itself (Law 1). NULL on rows written before this column
    /// existed and on idempotent replays that predate it.
    #[serde(default)]
    pub composite_risk_score: Option<i32>,
    /// #1293: the effective (tighten-only) trust level this decision was
    /// gated on. NULL on rows written before this column existed.
    #[serde(default)]
    pub root_trust_level: Option<String>,
    /// #1293: the upstream run_id that triggered this hop, if part of a
    /// multi-agent chain. NULL for a chain's first hop or rows written
    /// before this column existed.
    #[serde(default)]
    pub parent_run_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
    /// Optional webhook URL to notify when this approval is decided
    /// (#1187/TASK-0082). `#[sqlx(default)]` so existing `SELECT` column
    /// lists that predate this column still deserialize.
    #[sqlx(default)]
    pub callback_url: Option<String>,
    /// `sha256(secret)` for the callback above — the plaintext secret is
    /// never stored (#1187/TASK-0083).
    #[sqlx(default)]
    pub callback_secret_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// TASK-0092 (#938): a tenant-managed webhook subscription, registered via
/// `/v1/webhook_subscriptions` to receive SOC notifications (alerts/incidents)
/// at an operator-supplied endpoint. `secret_hash` is `sha256(secret)` — the
/// plaintext secret is never persisted, mirroring `ApprovalRecord::callback_secret_hash`.
///
/// #1285 adds real delivery on top of this CRUD scaffold. `delivery_secret`
/// is a separate, server-generated plaintext secret (returned once at
/// creation, like `agent_token`) used to HMAC-sign outbound deliveries —
/// `secret_hash` above is a one-way hash and cannot be used for that.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct WebhookSubscriptionRecord {
    pub id: String,
    pub tenant_id: String,
    pub url: String,
    pub secret_hash: Option<String>,
    pub event_types: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    /// #1285: never serialized — the one-time creation response carries it
    /// explicitly instead of relying on this struct's `Serialize` impl, so a
    /// future `SELECT *`-backed listing/get endpoint can never leak it.
    #[serde(skip_serializing, default)]
    pub delivery_secret: Option<String>,
    /// #1285: `"info"` or `"high"` — events below this severity are not
    /// delivered to this subscription.
    pub min_severity: String,
    /// #1285: `"json"` or `"cef"`.
    pub format: String,
    /// #1285: `"healthy"` | `"degraded"` | `"dead"`, derived from
    /// `consecutive_failures` after each delivery attempt. Distinct from the
    /// legacy `status` column above, which TASK-0092 always set to `"active"`
    /// and nothing else ever read or wrote.
    pub delivery_status: String,
    pub consecutive_failures: i64,
    pub last_delivery_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
}

/// TASK-0088 (#934): a tenant-managed detection rule. First step toward
/// SOC-003 (#1186) — `condition` and `summary_template` hold a YAML rule
/// body that will eventually be loaded by `detect.rs` to replace the
/// hardcoded Rust detection functions. `enabled` lets operators turn a rule
/// off without deleting it.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct DetectionRuleRecord {
    pub id: String,
    pub tenant_id: String,
    pub rule_key: String,
    pub name: String,
    pub severity: String,
    pub condition: String,
    pub summary_template: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// TASK-0093 (#939): a tenant-managed API key. `key_hash` is `sha256(key)` —
/// the plaintext key is returned exactly once at creation and never persisted.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyRecord {
    pub id: String,
    pub tenant_id: String,
    pub key_hash: String,
    pub name: String,
    pub status: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
    /// #1301: links this audit event back to the authorization decision that
    /// produced it, so operators/compliance can correlate the full trail for
    /// a single decision.
    pub decision_id: Option<String>,
    /// #1301: for approval-lifecycle events (`approval_created`,
    /// `approval_decided`, etc.), the approval this event relates to.
    pub approval_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// GDPR data-portability bundle (#946): the complete set of a single tenant's
/// records, assembled tenant-scoped for `GET /v1/tenants/:id/export`. Serialized
/// to JSON; every list is filtered by `tenant_id`, so it never crosses tenants.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantExport {
    /// Format tag so consumers can version the export shape.
    pub schema: String,
    pub tenant_id: String,
    /// RFC 3339 UTC time the export was produced.
    pub exported_at: String,
    pub tenant: Option<TenantRecord>,
    pub agents: Vec<AgentRecord>,
    pub decisions: Vec<DecisionRecord>,
    pub approvals: Vec<ApprovalRecord>,
    pub action_receipts: Vec<ActionReceiptRecord>,
    pub audit_events: Vec<AuditEventRecord>,
    pub mcp_servers: Vec<McpServerRecord>,
}

/// SOC Phase 5 — persisted detection alert (one rule fired on one event).
/// Stores identifiers, summary and severity only — never raw payloads or secrets
/// (redaction invariant). Tenant-scoped; `source_event_id` links back to the ASE
/// event that triggered the alert.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
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
    /// Canonicalization scheme that produced `action_hash` / `receipt_hash` (e.g.
    /// `aegis-jcs-1`). Additive metadata so each receipt is self-describing and a
    /// future scheme bump stays migratable — NOT part of the canonical body or
    /// `receipt_hash` (the byte-parity-locked chain is untouched).
    #[serde(default)]
    pub canon_version: String,
    /// Optional Ed25519 signature (lowercase hex) computed OVER `receipt_hash`.
    /// Additive metadata — NOT part of the canonical body or `receipt_hash`.
    /// NULL when receipt signing is not configured (hermetic default = unsigned).
    pub signature: Option<String>,
    /// Lowercase-hex Ed25519 public key of the signer, so a third party can verify
    /// the `signature` without contacting the gateway. NULL when unsigned.
    pub signer_public_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// #1312: tamper-evident, append-only transparency-log entry for a policy
/// change (create/update/delete/rollback). Hash-chained like
/// [`ActionReceiptRecord`] — `entry_hash` covers `prev_hash`, so the chain can
/// be re-verified end-to-end (see `routes::policy_audit_log_entry_value`).
/// The `policy_audit_log` table additionally has SQLite triggers that abort
/// any `UPDATE`/`DELETE`, making it append-only at the database level.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct PolicyAuditLogRecord {
    pub id: String,
    pub tenant_id: String,
    pub policy_id: String,
    pub policy_key: String,
    /// One of `created` | `updated` | `deleted` | `rolled_back`.
    pub action: String,
    /// Identity of the actor that made the change, if known.
    pub changed_by: Option<String>,
    /// `sha256:<hex>` of the resulting policy body (the body being deleted,
    /// for `deleted`).
    pub body_hash: String,
    /// Short human-readable description of what changed.
    pub diff_summary: String,
    /// `entry_hash` of the previous entry in this tenant's chain, or `""` for
    /// the chain's genesis entry.
    pub prev_hash: String,
    pub entry_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    pub id: String,
    pub name: String,
    pub plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateMcpServerRequest {
    pub name: Option<String>,
    pub owner_team: Option<Option<String>>,
    pub transport: Option<String>,
    pub source: Option<Option<String>>,
    pub trust_level: Option<String>,
    pub endpoint: Option<String>,
    pub status: Option<String>,
    /// #1333: opt-in toggle for MCP response inspection.
    pub inspection_enabled: Option<bool>,
}

/// `POST /v1/mcp/servers/:server_key/inspect` (#1333) request body. The SDK
/// submits this *after* executing an MCP-routed tool call — the gateway
/// itself never observes tool responses on the `/v1/authorize` path.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InspectMcpResponseRequest {
    pub agent_id: String,
    pub tool_key: String,
    /// The raw tool response to scan. Never persisted — only the resulting
    /// finding categories/counts are stored (redaction invariant).
    pub response_text: String,
    /// Optional correlation ids, if the caller has them.
    pub decision_id: Option<String>,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TenantStats {
    pub total_decisions: i64,
    pub decisions_allow: i64,
    pub decisions_deny: i64,
    pub decisions_require_approval: i64,
    pub total_agents: i64,
    pub total_receipts: i64,
    /// #1294: per-`root_trust_level` decision counts, for the dashboard's
    /// Trust Level Distribution chart and "% from untrusted sources" stat.
    /// Rows predating the #1293 trust-chain migration have a `NULL`
    /// `root_trust_level`, grouped here under `"unknown"`.
    #[serde(default)]
    pub trust_level_breakdown: Vec<TrustLevelCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TrustLevelCount {
    pub trust_level: String,
    pub count: i64,
}

/// #1290: one row of the dashboard's Agent Risk Scoreboard — the rolling
/// 24h average `composite_risk_score` per agent, ranked highest-first, with
/// a trend relative to the prior 24h window (24-48h ago).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct AgentRiskScoreboardEntry {
    pub agent_id: String,
    pub agent_key: String,
    pub current_avg_risk_score: f64,
    pub decision_count_24h: i64,
    /// `"rising"`, `"falling"`, or `"stable"` — see
    /// [`crate::db::get_agent_risk_scoreboard`] for the threshold and the
    /// no-baseline-data fallback.
    pub trend: String,
}

/// Row count for a single table, part of `DbStats` (#950).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TableRowCount {
    pub table: String,
    pub row_count: i64,
}

/// Operational database-level monitoring stats (#949, #950): on-disk size of
/// the SQLite database file, and a per-table row count breakdown. Global
/// (not tenant-scoped) — reflects the whole DB file shared by all tenants.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DbStats {
    pub size_bytes: i64,
    pub tables: Vec<TableRowCount>,
}

/// Request body for `POST /v1/admin/backup` (#945). `filename` is a bare
/// filename (no path separators) for the backup copy, written under the
/// directory configured by `AEGIS_BACKUP_DIR` (default `backups`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateBackupRequest {
    pub filename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateBackupResponse {
    pub path: String,
    pub size_bytes: i64,
}
