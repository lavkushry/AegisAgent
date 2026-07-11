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
    /// Bind this agent to a client certificate Subject CN for mTLS
    /// authentication (#1310). `Some` sets/rebinds; omit the field to leave
    /// the current binding unchanged. Revoke access for a compromised
    /// certificate via the CA's CRL (`AEGIS_MTLS_CRL_PATH`), not by clearing
    /// this field.
    pub mtls_cn: Option<String>,
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
    /// Optional Ed25519 public key (hex) to pin for this server's manifest
    /// discovery calls from registration onward. See
    /// [`McpServerRecord::manifest_signing_public_key`].
    #[serde(default)]
    pub manifest_signing_public_key: Option<String>,
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
    /// Hex-encoded Ed25519 signature over the order-independent canonical
    /// hash of `tools` (see `mcp_manifest_signed_hash`). Required and
    /// verified against the server's `manifest_signing_public_key` if one is
    /// pinned; ignored (and may be omitted) if the server has no pinned key.
    #[serde(default)]
    pub manifest_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Default)]
pub struct ActiveResponseRequest {
    /// Operator-supplied audit reason for a containment/control action.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional alias accepted for UI clients that label the field as a comment.
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ActiveResponseStatusResponse {
    pub status: String,
    pub action: String,
    pub reason_recorded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_key: Option<String>,
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
    /// PR2 (receipt durability): identity of the hash-chained receipt durably
    /// written for this decision. Present for *protected* decisions (mutating,
    /// high/critical risk, or any non-`allow`), whose receipt is written
    /// synchronously before this response is returned — so a client holds
    /// verifiable evidence the action was authorized. `None` for low-risk
    /// read-only `allow`s (their receipt is written best-effort/async) and for
    /// dry-runs (nothing persisted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReceiptIdentity>,
}

/// Identity of a durably-written action receipt, returned inline on protected
/// authorize decisions (PR2) so callers can verify/anchor evidence without a
/// follow-up `GET /v1/receipts/:id`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReceiptIdentity {
    pub receipt_id: String,
    pub receipt_hash: String,
    pub prev_receipt_hash: String,
    pub canon_version: String,
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
    /// #1277: Slack approver group for interactive callbacks. `None` = any
    /// Slack user may approve. Comma-separated `U…` IDs = static allowlist.
    /// `S…` prefix = Slack usergroup (requires `AEGIS_SLACK_BOT_TOKEN`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slack_approver_group: Option<String>,
}

/// #1277: tenant Slack approver-group configuration payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SlackApproverGroupRequest {
    /// `null` clears the restriction (any Slack user may approve).
    pub slack_approver_group: Option<String>,
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
    /// Client certificate Subject CN bound to this agent for mTLS
    /// authentication (#1310). `None` = mTLS not bound; bearer-token auth via
    /// `agent_token` is the only path (backwards-compatible).
    #[serde(default)]
    pub mtls_cn: Option<String>,
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

/// A single agent-to-MCP-server permission binding (#1766).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct AgentMcpServerPermission {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub server_key: String,
    pub created_at: DateTime<Utc>,
}

/// A repo's configured sensitivity label for the GitHub App protection
/// layer (#1380). No row for a repo means "low" (see the migration).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct RepoSensitivityLabel {
    pub id: String,
    pub tenant_id: String,
    pub repo_full_name: String,
    pub sensitivity_label: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request body for `PUT /v1/github/repos/:repo/sensitivity` (#1380).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetRepoSensitivityLabelRequest {
    pub sensitivity_label: String,
}

/// Request body for `POST /v1/agents/:id/mcp-permissions` (#1766).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct GrantMcpServerPermissionRequest {
    pub server_key: String,
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
    /// Optional Ed25519 public key (hex) pinned for this server's manifest
    /// discovery calls. `None` (default) = unsigned, trust-on-first-use
    /// discovery, unchanged from pre-existing behavior. Once set, `POST
    /// /v1/mcp/servers/:server_key/tools` requires a valid
    /// `manifest_signature` on every discovery call for this server and
    /// fails closed (403) on a missing/invalid one.
    #[serde(default)]
    pub manifest_signing_public_key: Option<String>,
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

/// Phase 2.1 (runtime control plane): one controlled execution of an agent.
/// The spine that runtime events, control commands, bans, and quarantine records
/// reference. `agent_id` is `None` for anonymous/cage runs; `policy_bundle_id`
/// is `None` until a versioned policy bundle is bound. Tenant-scoped.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct AgentRunRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: Option<String>,
    /// Caller-stable idempotency key, unique per tenant.
    pub run_key: String,
    /// Which component started/owns the run (e.g. `sdk`, `cage-runner`, `gateway`).
    pub source_component: String,
    /// Sensor enforcement posture for the run: `observe` | `enforce` | `lockdown`.
    pub mode: String,
    /// Lifecycle: `started` | `claimed` | `running` | `paused` | `killed` |
    /// `finished` | `quarantined` | `stalled`. `started` means "created, not
    /// yet claimed by a runner" for cage runs (`claimed`/`running` are new
    /// values -- see aegis-cage-runner's execution loop); non-cage
    /// (SDK-integrated) runs are unaffected and never transition past
    /// `started` today.
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub root_trace_id: Option<String>,
    pub root_trust_level: Option<String>,
    pub policy_bundle_id: Option<String>,
    /// Opaque id (e.g. hostname/config-supplied string) of the
    /// aegis-cage-runner process that currently holds the claim on this
    /// run. `None` until claimed. Not a security boundary -- the tenant
    /// bearer token used to reach these endpoints already is one.
    #[serde(default)]
    pub claimed_by: Option<String>,
    #[serde(default)]
    pub claimed_at: Option<DateTime<Utc>>,
    /// Refreshed by the claiming runner's heartbeat; a lease-expiry sweep
    /// (`mark_stale_agent_runs_stalled`) flips a run to `stalled` if this
    /// (or `claimed_at`, before the first heartbeat) goes too stale.
    #[serde(default)]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    /// The remaining fields mirror `aegis_cage_runner::spec::SandboxSpec`'s
    /// nested shapes and are populated only when the run was created with
    /// `CreateAgentRunRequest.cage_spec` set (`None` for the existing,
    /// unaffected SDK-integrated-run case). Nested shapes are raw JSON text
    /// (`_json` suffix), matching this schema's existing convention
    /// (`manifest_json`, `steps_json`, `settings_json`, etc.) rather than a
    /// new one; the gateway route layer and the cage-runner binary each
    /// serialize/deserialize independently at this boundary.
    #[serde(default)]
    pub image_ref: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub command_json: Option<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub resource_limits_json: Option<String>,
    #[serde(default)]
    pub network_spec_json: Option<String>,
    #[serde(default)]
    pub tooling_spec_json: Option<String>,
    #[serde(default)]
    pub environment_json: Option<String>,
    #[serde(default)]
    pub workspace_spec_json: Option<String>,
    #[serde(default)]
    pub controlled_mounts_json: Option<String>,
    /// Process/container exit code reported by the claiming runner on
    /// terminal status (`finished` / `killed`). `None` until reported.
    #[serde(default)]
    pub exit_code: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Phase 2.2 (runtime control plane): one runtime event shipped by the node
/// sensor / cage / SDK. `event_id` is the producer-assigned id; ingest dedupes
/// on `(tenant_id, event_id)`. Hashes/identifiers only — never raw prompts,
/// secrets, or payloads. `#[sqlx(default)]` on the optional tail so future
/// columns and partial SELECTs stay compatible.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct RuntimeEventRecord {
    pub id: String,
    pub tenant_id: String,
    pub event_id: String,
    pub event_type: String,
    pub severity: Option<String>,
    pub agent_id: Option<String>,
    pub run_id: Option<String>,
    pub sandbox_id: Option<String>,
    pub trace_id: Option<String>,
    pub parent_event_id: Option<String>,
    pub source_component: String,
    pub source_trust: Option<String>,
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub action_hash: Option<String>,
    pub prompt_hash: Option<String>,
    pub request_hash: Option<String>,
    pub response_hash: Option<String>,
    pub receipt_id: Option<String>,
    pub receipt_hash: Option<String>,
    pub prev_receipt_hash: Option<String>,
    pub canonical_version: Option<String>,
    pub redaction_status: Option<String>,
    pub schema_version: i64,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

/// Phase 7.1 (prompt/model capture): lineage record for one observed prompt.
/// `event_id` is the producer-assigned id; ingest dedupes on
/// `(tenant_id, event_id)`. Stores a hash and a caller-redacted preview —
/// never a raw prompt. See `docs/AegisAgent_World_Class_LLD.md` section 5.2.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct PromptEventRecord {
    pub id: String,
    pub tenant_id: String,
    pub event_id: String,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub prompt_hash: String,
    pub redacted_prompt_preview: Option<String>,
    pub role: Option<String>,
    pub source_trust: Option<String>,
    pub model_provider: Option<String>,
    pub retention_policy: Option<String>,
    pub redaction_status: String,
    pub created_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

/// Phase 7.1 (prompt/model capture): lineage record for one model call.
/// `event_id` is the producer-assigned id; ingest dedupes on
/// `(tenant_id, event_id)`. Stores hashes of the request/response, never the
/// bodies themselves.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct ModelCallEventRecord {
    pub id: String,
    pub tenant_id: String,
    pub event_id: String,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub provider: String,
    pub model: String,
    pub request_hash: Option<String>,
    pub response_hash: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub token_counts_json: Option<String>,
    pub status: String,
    pub redaction_status: String,
    pub received_at: DateTime<Utc>,
}

/// Phase 2.3 (runtime control plane): a signed gateway->sensor control command.
/// The sensor verifies `signature` (over the canonical command bytes), tenant
/// binding, `expires_at`, and `nonce` before executing idempotently and ACKing.
/// `(tenant_id, nonce)` is unique for replay protection. No raw secrets here.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct ControlCommandRecord {
    pub command_id: String,
    pub tenant_id: String,
    /// `agent` | `run` | `sandbox` | `fingerprint` | `destination` | `tool` |
    /// `mcp_server` | `sensor` (see the Control Command Protocol doc).
    pub target_type: String,
    pub target_id: String,
    pub action: String,
    pub reason: Option<String>,
    pub issued_by: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
    pub requires_ack: bool,
    pub receipt_required: bool,
    pub signature: String,
    /// `issued` | `delivered` | `acked` | `nacked` | `executed` | `expired`.
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Phase 2.4 (runtime control plane): a first-class ban. Blocks a `target_value`
/// of a given `target_type` (agent / fingerprint / image_digest / mcp_server /
/// tool / destination_domain / destination_ip / prompt_hash / behavior_signature
/// / ...) at every enforcement point. NULL `expires_at` = permanent /
/// until-manual-review. Every ban/revoke carries `actor` + `reason` for the
/// audit/receipt trail. Tenant-scoped.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct AgentBanRecord {
    pub id: String,
    pub tenant_id: String,
    pub target_type: String,
    pub target_value: String,
    /// `run` | `agent` | `tenant` | `organization`.
    pub scope: String,
    pub reason: Option<String>,
    pub actor: String,
    /// `active` | `revoked`.
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
}

/// OIDC console login: a self-service link between one external identity
/// (`issuer` + `subject`, from a verified ID token) and exactly one tenant.
/// `UNIQUE(issuer, subject)` at the DB layer -- there is no auto-provisioning,
/// an unrecognized identity at login fails closed rather than guessing a
/// tenant or creating one.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct OidcIdentityRecord {
    pub id: String,
    pub tenant_id: String,
    pub issuer: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

/// Phase 2.5 (runtime control plane): a quarantine. Preserves evidence while
/// freezing a target (agent / run / workspace / file / mcp_server / tool /
/// credential / destination / prompt_lineage) for review; optionally linked to
/// an incident. Lifecycle `active` -> `released` | `deleted` after review.
/// Every quarantine/release carries `actor` + `reason`. Tenant-scoped.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct QuarantineRecord {
    pub id: String,
    pub tenant_id: String,
    pub target_type: String,
    pub target_value: String,
    pub reason: Option<String>,
    pub actor: String,
    /// `active` | `released` | `deleted`.
    pub status: String,
    pub incident_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub released_by: Option<String>,
}

/// Phase 3.2 (Agent Cage): a registered `aegis-node-sensor` instance.
/// `node_key` is the sensor's own stable per-host identifier — re-registering
/// with the same `(tenant_id, node_key)` updates this row instead of creating
/// a duplicate, so a restarted sensor keeps its identity. `capabilities` is a
/// raw JSON-array string (no enforcement logic reads it yet). `public_key` is
/// the sensor's Ed25519 identity key (hex), used to verify signed ACK/NACK
/// results in a later phase — never a secret. Tenant-scoped.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct SensorRecord {
    pub id: String,
    pub tenant_id: String,
    pub node_key: String,
    pub hostname: String,
    pub environment: Option<String>,
    pub sensor_version: String,
    pub public_key: String,
    pub capabilities: String,
    /// `observe` | `enforce` | `lockdown`.
    pub mode: String,
    /// `registered` | `heartbeating` | `degraded` | `lockdown` | `draining`.
    pub status: String,
    pub config_version: i64,
    pub queue_depth_critical: Option<i64>,
    pub queue_depth_normal: Option<i64>,
    pub disk_usage_bytes: Option<i64>,
    pub active_cage_runs: Option<i64>,
    pub last_event_watermark: Option<String>,
    pub last_command_watermark: Option<String>,
    pub health_status: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Phase 6.2 (tool broker): a registered broker tool. Binds a
/// tenant-visible `tool_name` to a connector type and an *opaque*
/// `credential_ref` — the credential itself is never stored here and never
/// leaves the broker (Phase 6.1 `CredentialResolver` resolves the ref at
/// execution time). `allowed_scopes` is a raw JSON-array string. Execution
/// fails closed on any `status` other than `active`. Tenant-scoped;
/// `(tenant_id, tool_name)` is unique.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct BrokerToolRecord {
    pub id: String,
    pub tenant_id: String,
    pub tool_name: String,
    pub connector_type: String,
    /// Opaque reference (e.g. `env:GITHUB_TOKEN`) — never a secret value.
    pub credential_ref: String,
    pub allowed_scopes: String,
    /// `active` | `disabled`.
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    /// Set when the approval has been edited (#approval-edit-lifecycle): the
    /// hash of the edited tool call. `original_call_hash` is preserved as the
    /// agent's original action; the *effective* hash an approve/consume binds to
    /// is `effective_call_hash` when present, else `original_call_hash`. NULL =
    /// not edited. `#[sqlx(default)]` so SELECTs predating this column still
    /// deserialize.
    #[sqlx(default)]
    pub effective_call_hash: Option<String>,
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

impl ApprovalRecord {
    /// The hash an approve/consume binds to: the edited action's hash once the
    /// approval has been edited, otherwise the agent's original action hash.
    /// (#approval-edit-lifecycle) Editing re-points the binding without losing
    /// the original, so a consume with the *original* hash of an edited approval
    /// fails — the human approved the edited action, not the original.
    pub fn effective_action_hash(&self) -> &str {
        self.effective_call_hash
            .as_deref()
            .unwrap_or(&self.original_call_hash)
    }

    /// Whether this approval has been edited from the agent's original action.
    pub fn is_edited(&self) -> bool {
        self.effective_call_hash.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalQueueItem {
    pub approval_id: String,
    pub decision_id: String,
    pub status: String,
    pub approver_group: Option<String>,
    pub approver_user_id: Option<String>,
    pub reason: Option<String>,
    pub decision_reason: Option<String>,
    pub matched_policies: Vec<String>,
    pub risk_score: Option<i32>,
    pub risk_level: Option<String>,
    pub composite_risk_score: Option<i32>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub parent_run_id: Option<String>,
    pub resource: Option<String>,
    pub source_trust: String,
    pub root_trust_level: String,
    pub action_hash: String,
    pub original_action_hash: String,
    pub edited_action_hash: Option<String>,
    pub effective_action_hash: String,
    pub is_edited: bool,
    pub tool_call: Option<AuthorizeToolCall>,
    pub edited_tool_call: Option<AuthorizeToolCall>,
    pub agent_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub decided_at: Option<DateTime<Utc>>,
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
    /// JSON blob produced by the sandboxed triage agent (#1393). Advisory only —
    /// never gates enforcement. `NULL` until triage runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triage_recommendation: Option<String>,
}

/// Advisory triage output for a SOC alert (#1393). Stored as JSON on
/// `soc_alerts.triage_recommendation`; surfaced via `GET /v1/alerts/:id/triage`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct TriageRecommendation {
    /// `maintain`, `escalate`, or `de_escalate` relative to the alert's current severity.
    pub priority_adjustment: String,
    /// Suggested priority label after triage (`low` | `medium` | `high` | `critical`).
    pub suggested_priority: String,
    /// Human-readable category for SOC queue routing.
    pub category_label: String,
    /// Recommended analyst action (advisory — not auto-executed).
    pub recommended_action: String,
    /// Count of prior alerts with the same rule for this agent (excludes current).
    pub similar_past_alerts: u32,
    /// Count of alerts for this agent in the last 24 hours (includes current).
    pub agent_recent_alerts: u32,
    pub generated_at: String,
    /// `template` (default) or `claude` when the optional LLM path is enabled.
    pub agent: String,
}

/// Advisory threat hunt finding from proactive anomaly search (#1395).
/// Stored in `threat_hunt_findings`; informational only — never enforcement.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ThreatHuntFindingRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    /// `off_hours_activity` | `unusual_tool_combo` | `privilege_escalation`
    pub finding_type: String,
    /// Dedup key (e.g. run_id or window label) while status is `open`.
    pub fingerprint: String,
    /// `info` | `medium` | `high`
    pub severity: String,
    pub title: String,
    pub summary: String,
    /// JSON evidence links: decision_ids, run_ids, metrics (no secrets).
    pub evidence_json: String,
    /// `open` | `acknowledged` | `dismissed`
    pub status: String,
    /// `template` (default) or `claude` when the optional LLM path is enabled.
    pub hunter_agent: String,
    pub generated_at: String,
    pub created_at: String,
}

/// Advisory policy recommendation from denied-action analysis (#1394).
/// Stored in `policy_recommendations`; never auto-applied to Cedar.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PolicyRecommendationRecord {
    pub id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub tool_key: String,
    pub action_key: String,
    pub deny_count: i64,
    pub window_days: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_reason: Option<String>,
    pub draft_cedar: String,
    pub rationale: String,
    /// `pending` | `approved` | `rejected`
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_note: Option<String>,
    pub generated_at: String,
    /// `template` (default) or `claude` when the optional LLM path is enabled.
    pub advisor_agent: String,
    pub created_at: String,
}

/// Advisory investigation playbook for a SOC incident (#1392).
/// Stored in `investigation_playbooks`; never triggers enforcement actions.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct InvestigationPlaybookRecord {
    pub id: String,
    pub tenant_id: String,
    pub incident_id: String,
    pub kind: String,
    pub severity: String,
    pub agent_id: String,
    pub summary: String,
    /// JSON array of ordered investigation steps (title, action, api_hint).
    pub steps_json: String,
    /// JSON object of suggested evidence API endpoints and graph entry points.
    pub evidence_hints_json: String,
    /// `active` — one playbook per incident.
    pub status: String,
    /// `template` (default) or `claude` when the optional LLM path is enabled.
    pub investigator_agent: String,
    pub generated_at: String,
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
    pub agents_total: i64,
    pub approvals_pending: i64,
    pub decisions_today: i64,
    pub denies_today: i64,
    pub deny_rate_today: f64,
    pub risk_posture: String,
    pub hourly_decisions_24h: Vec<i64>,
}

/// Structured filter for `POST /v1/soc/query`.
///
/// The gateway accepts a fixed allowlist only. Unknown fields are rejected
/// before execution so clients cannot smuggle raw SQL/operators into the query
/// builder.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SocQueryFilters {
    pub event_type: Option<String>,
    pub severity: Option<String>,
    pub agent_id: Option<String>,
    pub decision: Option<String>,
    pub source_trust: Option<String>,
    pub skill: Option<String>,
    /// Public alias for the legacy `skill` storage field.
    pub tool: Option<String>,
    pub source_component: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub action_hash: Option<String>,
    pub receipt_hash: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub q: Option<String>,
}

/// Request body for `POST /v1/soc/query`.
///
/// `entity` and `aggregate` are validated by the gateway against fixed
/// allowlists. This REST contract is intentionally flat and storage-neutral so
/// the same datasource can back Explore tables, dashboard stats, and
/// count-over-time panels.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SocQueryRequest {
    /// Public query-contract version. Currently only version 1 is accepted.
    #[serde(default = "soc_query_version_one")]
    pub version: u32,
    pub entity: String,
    #[serde(default)]
    pub filters: SocQueryFilters,
    /// `none`/omitted for paginated rows, `count`, or `count_over_time`.
    pub aggregate: Option<String>,
    /// Bucket for `count_over_time`: `minute`, `hour`, or `day`.
    pub interval: Option<String>,
    /// Allowlisted field for the `count_by` aggregate.
    pub group_by: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<i64>,
}

const fn soc_query_version_one() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SocQueryFieldDescriptor {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub facetable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SocQueryMeta {
    pub total: Option<i64>,
    pub cursor: Option<String>,
}

/// DataFrame-compatible response envelope used by every SOC query shape.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SocQueryResponse {
    pub version: u32,
    pub entity: String,
    pub aggregate: Option<String>,
    pub group_by: Option<String>,
    pub rows: Vec<serde_json::Value>,
    pub field_descriptors: Vec<SocQueryFieldDescriptor>,
    pub meta: SocQueryMeta,
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
    /// Optional human-readable identifier for the key that produced `signature`
    /// (#1211, parsed from an optional `"key_id:"` prefix on
    /// `AEGIS_RECEIPT_SIGNING_KEY`) — audit/operator convenience only.
    /// Verification never depends on this: `signer_public_key` is embedded
    /// per-receipt, so receipts stay verifiable after the active key rotates.
    #[serde(default)]
    pub signer_key_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Phase 8.3 (investigation evidence export): a checkpoint over a contiguous
/// range of the tenant's hash-chained action receipts. Stores only hashes —
/// the Merkle root of `receipt_hash` values plus the chain head — so an
/// evidence pack can prove range integrity without re-emitting raw bodies.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct ReceiptCheckpointRecord {
    pub id: String,
    pub tenant_id: String,
    /// Inclusive 0-based index into the tenant's chain-ordered receipts at
    /// the time the checkpoint was cut.
    pub sequence_start: i64,
    /// Inclusive end index (same indexing as `sequence_start`).
    pub sequence_end: i64,
    /// `receipt_hash` of the last receipt in the range (chain head).
    pub chain_head_hash: String,
    /// Merkle root over the range's `receipt_hash` values (SHA-256 hex).
    pub merkle_root: String,
    pub receipt_count: i64,
    pub signature: Option<String>,
    pub signer_key_id: Option<String>,
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
    /// Pin/rotate/clear the per-server manifest-signing public key.
    /// `Some(None)` clears it (reverting the server to unsigned discovery);
    /// `Some(Some(hex))` sets/rotates it; field absent from the patch leaves
    /// it untouched.
    pub manifest_signing_public_key: Option<Option<String>>,
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

/// Per-tenant configurable weights. Defaults come from `AEGIS_RISK_*` env vars
/// (see [`RiskWeights::from_env`]) and may be overridden per-tenant via
/// `tenant_risk_weights` (see `db::get_risk_weights`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct RiskWeights {
    /// Added when `RiskInputs::mutates_state` is true.
    pub environment_weight_mutating: i32,
    pub context_trust_penalty_trusted_internal_signed: i32,
    pub context_trust_penalty_trusted_internal_unsigned: i32,
    pub context_trust_penalty_semi_trusted_customer: i32,
    pub context_trust_penalty_untrusted_external: i32,
    pub context_trust_penalty_malicious_suspected: i32,
    pub context_trust_penalty_unknown: i32,
    /// Added when `RiskInputs::is_mcp_call` is true.
    pub mcp_trust_penalty: i32,
    /// Percentage (0-100+) applied to `RiskInputs::anomaly_score` before adding it.
    pub anomaly_weight_pct: i32,
    /// Subtracted when `RiskInputs::had_prior_approval` is true.
    pub approval_credit: i32,
}

impl RiskWeights {
    /// Built-in defaults, used when no env var or per-tenant DB row overrides
    /// them. Penalties increase with how untrusted the triggering content is —
    /// mirroring the 6 trust levels in `cedar_policy_authoring.md`.
    pub const DEFAULT: RiskWeights = RiskWeights {
        environment_weight_mutating: 15,
        context_trust_penalty_trusted_internal_signed: 0,
        context_trust_penalty_trusted_internal_unsigned: 5,
        context_trust_penalty_semi_trusted_customer: 15,
        context_trust_penalty_untrusted_external: 30,
        context_trust_penalty_malicious_suspected: 50,
        context_trust_penalty_unknown: 20,
        mcp_trust_penalty: 10,
        anomaly_weight_pct: 100,
        approval_credit: 10,
    };

    /// Reads each weight from `AEGIS_RISK_<FIELD>` (e.g.
    /// `AEGIS_RISK_ENVIRONMENT_WEIGHT_MUTATING`), falling back to
    /// [`RiskWeights::DEFAULT`] for any var that is unset or not a valid `i32`.
    pub fn from_env() -> RiskWeights {
        RiskWeights {
            environment_weight_mutating: env_i32(
                "AEGIS_RISK_ENVIRONMENT_WEIGHT_MUTATING",
                RiskWeights::DEFAULT.environment_weight_mutating,
            ),
            context_trust_penalty_trusted_internal_signed: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_TRUSTED_INTERNAL_SIGNED",
                RiskWeights::DEFAULT.context_trust_penalty_trusted_internal_signed,
            ),
            context_trust_penalty_trusted_internal_unsigned: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_TRUSTED_INTERNAL_UNSIGNED",
                RiskWeights::DEFAULT.context_trust_penalty_trusted_internal_unsigned,
            ),
            context_trust_penalty_semi_trusted_customer: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_SEMI_TRUSTED_CUSTOMER",
                RiskWeights::DEFAULT.context_trust_penalty_semi_trusted_customer,
            ),
            context_trust_penalty_untrusted_external: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_UNTRUSTED_EXTERNAL",
                RiskWeights::DEFAULT.context_trust_penalty_untrusted_external,
            ),
            context_trust_penalty_malicious_suspected: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_MALICIOUS_SUSPECTED",
                RiskWeights::DEFAULT.context_trust_penalty_malicious_suspected,
            ),
            context_trust_penalty_unknown: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_UNKNOWN",
                RiskWeights::DEFAULT.context_trust_penalty_unknown,
            ),
            mcp_trust_penalty: env_i32(
                "AEGIS_RISK_MCP_TRUST_PENALTY",
                RiskWeights::DEFAULT.mcp_trust_penalty,
            ),
            anomaly_weight_pct: env_i32(
                "AEGIS_RISK_ANOMALY_WEIGHT_PCT",
                RiskWeights::DEFAULT.anomaly_weight_pct,
            ),
            approval_credit: env_i32(
                "AEGIS_RISK_APPROVAL_CREDIT",
                RiskWeights::DEFAULT.approval_credit,
            ),
        }
    }

    /// The configured penalty for a `source_trust` value. Unrecognized values
    /// (forward-compat for new trust levels) fall back to the `unknown` penalty.
    pub fn context_trust_penalty(&self, source_trust: &str) -> i32 {
        match source_trust {
            "trusted_internal_signed" => self.context_trust_penalty_trusted_internal_signed,
            "trusted_internal_unsigned" => self.context_trust_penalty_trusted_internal_unsigned,
            "semi_trusted_customer" => self.context_trust_penalty_semi_trusted_customer,
            "untrusted_external" => self.context_trust_penalty_untrusted_external,
            "malicious_suspected" => self.context_trust_penalty_malicious_suspected,
            _ => self.context_trust_penalty_unknown,
        }
    }
}

impl Default for RiskWeights {
    fn default() -> Self {
        RiskWeights::DEFAULT
    }
}

fn env_i32(key: &str, default: i32) -> i32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(default)
}

/// Per-tenant configuration for [`maybe_escalate_agent_risk_tier`]. Falls
/// back to [`Default`] when a tenant has no override row.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct RiskEscalationConfig {
    /// Escalate once more than this many `deny` decisions land within the window.
    pub denial_threshold: i64,
    pub window_minutes: i64,
}

impl Default for RiskEscalationConfig {
    fn default() -> Self {
        Self {
            denial_threshold: 5,
            window_minutes: 60,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct PlaybookRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub trigger_kind: String,
    pub trigger_severity: String, // stored as JSON array in sqlite
    pub trigger_agent_id: Option<String>,
    pub trigger_environment: Option<String>,
    pub steps_json: String, // stored as JSON array in sqlite
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// #1634: tenant-owned dashboard schema persisted by `/v1/soc/dashboards`.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct SocDashboardRecord {
    pub id: String,
    pub tenant_id: String,
    pub uid: String,
    pub title: String,
    pub schema_version: i64,
    pub schema_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// #1627: tenant-managed SOC contact point (Slack/webhook/PagerDuty/email routing).
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct ContactPointRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub channel_type: String,
    pub url: Option<String>,
    /// Write-only at rest — never returned in list/get responses.
    #[serde(skip_serializing, default)]
    #[sqlx(default)]
    pub secret_hash: Option<String>,
    pub webhook_subscription_id: Option<String>,
    pub settings_json: String,
    pub health_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// #1627: tenant-managed notification routing policy.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct NotificationPolicyRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub enabled: bool,
    pub matchers_json: String,
    pub contact_point_ids_json: String,
    pub group_by: Option<String>,
    pub repeat_interval_secs: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// #1627: tenant-scoped alert silence (deterministic expiry).
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, ToSchema)]
pub struct AlertSilenceRecord {
    pub id: String,
    pub tenant_id: String,
    pub rule_key: Option<String>,
    pub agent_id: Option<String>,
    pub comment: Option<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}
