#![allow(clippy::too_many_arguments)]

use crate::db::DbPool;
use aegis_api::models::*;
use aegis_common::errors::AegisError;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Optional, parameterized filters for [`StorageBackend::list_decisions`].
/// Bundled into one struct so call sites name each filter (no positional
/// `Option<&str>` transposition risk) and new filters don't ripple through
/// every signature. All bounds are exact equality except `from`/`to`, which
/// are inclusive `created_at` range bounds in the DB timestamp format.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecisionListFilters<'a> {
    pub agent_id: Option<&'a str>,
    pub decision: Option<&'a str>,
    pub q: Option<&'a str>,
    pub source_trust: Option<&'a str>,
    pub skill: Option<&'a str>,
    pub action: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub trace_id: Option<&'a str>,
    pub action_hash: Option<&'a str>,
    pub receipt_hash: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
}

/// Optional, parameterized filters for durable Agent Security Events.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeEventListFilters<'a> {
    pub event_type: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub agent_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub trace_id: Option<&'a str>,
    pub source_component: Option<&'a str>,
    pub source_trust: Option<&'a str>,
    pub decision: Option<&'a str>,
    pub action_hash: Option<&'a str>,
    pub receipt_hash: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub q: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEventGroupField {
    EventType,
    Severity,
    AgentId,
    SourceComponent,
    SourceTrust,
    Decision,
}

impl RuntimeEventGroupField {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "event_type" => Some(Self::EventType),
            "severity" => Some(Self::Severity),
            "agent_id" => Some(Self::AgentId),
            "source_component" | "tool" => Some(Self::SourceComponent),
            "source_trust" => Some(Self::SourceTrust),
            "decision" => Some(Self::Decision),
            _ => None,
        }
    }

    pub fn sql_column(self) -> &'static str {
        match self {
            Self::EventType => "event_type",
            Self::Severity => "severity",
            Self::AgentId => "agent_id",
            Self::SourceComponent => "source_component",
            Self::SourceTrust => "source_trust",
            Self::Decision => "decision",
        }
    }
}

/// Time-bucket granularity for `count_decisions_over_time`. A closed
/// allowlist — the bucket is chosen server-side and never interpolated from
/// raw user input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimeBucket {
    Minute,
    #[default]
    Hour,
    Day,
}

impl TimeBucket {
    pub fn parse(raw: &str) -> Self {
        match raw {
            "minute" => Self::Minute,
            "day" => Self::Day,
            _ => Self::Hour,
        }
    }

    /// SQLite `strftime` format string for this bucket.
    pub fn sqlite_fmt(self) -> &'static str {
        match self {
            Self::Minute => "%Y-%m-%d %H:%M:00",
            Self::Hour => "%Y-%m-%d %H:00:00",
            Self::Day => "%Y-%m-%d",
        }
    }

    /// PostgreSQL `date_trunc` unit for this bucket.
    pub fn pg_unit(self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }
}

/// Closed allowlist for SOC decision group-by queries. The SQL column is
/// selected from this enum only; client-provided strings are never interpolated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionGroupField {
    AgentId,
    Decision,
    SourceTrust,
    Skill,
    Action,
}

impl DecisionGroupField {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "agent_id" => Some(Self::AgentId),
            "decision" => Some(Self::Decision),
            "source_trust" => Some(Self::SourceTrust),
            "tool" | "skill" => Some(Self::Skill),
            "action" => Some(Self::Action),
            _ => None,
        }
    }

    pub fn sql_column(self) -> &'static str {
        match self {
            Self::AgentId => "agent_id",
            Self::Decision => "decision",
            Self::SourceTrust => "root_trust_level",
            Self::Skill => "skill",
            Self::Action => "action",
        }
    }
}

#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    // Agents & Skills
    async fn rotate_agent_token(
        &self,
        tenant_id: &str,
        agent_id: &str,
        new_token_hash: &str,
    ) -> Result<(), AegisError>;
    async fn get_agent_by_token(
        &self,
        tenant_id: &str,
        token_hash: &str,
    ) -> Result<Option<AgentRecord>, AegisError>;
    async fn get_agent_by_key(
        &self,
        tenant_id: &str,
        agent_key: &str,
    ) -> Result<Option<AgentRecord>, AegisError>;
    /// Resolve an agent by its bound mTLS client-certificate Subject CN (#1310).
    async fn get_agent_by_mtls_cn(
        &self,
        tenant_id: &str,
        cn: &str,
    ) -> Result<Option<AgentRecord>, AegisError>;
    async fn list_agents(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
        status_filter: Option<&str>,
    ) -> Result<Vec<AgentRecord>, AegisError>;
    async fn get_agent_by_id(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Option<AgentRecord>, AegisError>;
    async fn get_agent_by_id_any_status(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Option<AgentRecord>, AegisError>;
    async fn get_agent_risk_scoreboard(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AgentRiskScoreboardEntry>, AegisError>;
    async fn insert_agent(&self, record: &AgentRecord) -> Result<(), AegisError>;
    async fn update_agent(&self, record: &AgentRecord) -> Result<(), AegisError>;
    async fn insert_skill(
        &self,
        record: &SkillRecord,
        actions: &[SkillActionRecord],
    ) -> Result<String, AegisError>;
    async fn insert_skill_action(&self, record: &SkillActionRecord) -> Result<(), AegisError>;
    async fn get_skill_action(
        &self,
        tenant_id: &str,
        skill_key: &str,
        action_key: &str,
    ) -> Result<Option<SkillActionRecord>, AegisError>;
    async fn set_agent_status(
        &self,
        tenant_id: &str,
        agent_id: &str,
        status: &str,
    ) -> Result<bool, AegisError>;
    async fn set_agent_frozen_reason(
        &self,
        tenant_id: &str,
        agent_id: &str,
        reason: Option<&str>,
    ) -> Result<(), AegisError>;
    async fn set_agent_force_approval(
        &self,
        tenant_id: &str,
        agent_id: &str,
        force: bool,
    ) -> Result<(), AegisError>;
    async fn touch_agent_last_seen(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<(), AegisError>;
    async fn is_agent_active(&self, tenant_id: &str, agent_id: &str) -> Result<bool, AegisError>;
    async fn maybe_escalate_agent_risk_tier(
        &self,
        tenant_id: &str,
        agent_id: &str,
        current_tier: &str,
    ) -> Result<Option<(String, String)>, AegisError>;
    async fn grant_agent_tool_permission(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
    ) -> Result<AgentToolPermission, AegisError>;
    async fn get_agent_tool_permissions(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Vec<AgentToolPermission>, AegisError>;
    async fn revoke_agent_tool_permission(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
    ) -> Result<bool, AegisError>;
    async fn agent_tool_permission_status(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
    ) -> Result<bool, AegisError>;

    // Approvals
    async fn consume_approval(
        &self,
        tenant_id: &str,
        approval_id: &str,
        claimed_action_hash: Option<&str>,
    ) -> Result<bool, AegisError>;
    async fn approval_is_still_consumable(
        &self,
        tenant_id: &str,
        approval_id: &str,
    ) -> Result<bool, AegisError>;
    async fn list_approvals_in_range(
        &self,
        tenant_id: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Result<Vec<ApprovalRecord>, AegisError>;
    async fn get_approval_by_decision_id(
        &self,
        tenant_id: &str,
        decision_id: &str,
    ) -> Result<Option<ApprovalRecord>, AegisError>;
    async fn list_approvals_by_decision_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<HashMap<String, ApprovalRecord>, AegisError>;
    async fn insert_approval(&self, record: &ApprovalRecord) -> Result<(), AegisError>;
    async fn list_pending_approvals(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ApprovalRecord>, AegisError>;
    async fn get_approval_by_id(
        &self,
        tenant_id: &str,
        approval_id: &str,
    ) -> Result<Option<ApprovalRecord>, AegisError>;
    async fn update_approval_edit(
        &self,
        tenant_id: &str,
        approval_id: &str,
        approver: &str,
        reason: Option<&str>,
        edited_call: &str,
        new_hash: &str,
    ) -> Result<bool, AegisError>;
    async fn update_approval_status(
        &self,
        tenant_id: &str,
        approval_id: &str,
        status: &str,
        approver: &str,
        reason: Option<&str>,
        decided_at: Option<DateTime<Utc>>,
    ) -> Result<bool, AegisError>;
    async fn delete_expired_approvals_older_than(
        &self,
        ts: DateTime<Utc>,
    ) -> Result<i64, AegisError>;

    // Decisions
    async fn get_decision_by_id(
        &self,
        tenant_id: &str,
        decision_id: &str,
    ) -> Result<Option<DecisionRecord>, AegisError>;
    async fn get_decision_by_request_id(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<DecisionRecord>, AegisError>;
    async fn insert_decision(&self, record: &DecisionRecord) -> Result<(), AegisError>;
    async fn insert_agent_risk_score(
        &self,
        tenant_id: &str,
        agent_id: &str,
        decision_id: &str,
        score: i32,
        reason: &str,
    ) -> Result<(), AegisError>;
    async fn list_decisions(
        &self,
        tenant_id: &str,
        limit: i64,
        cursor: Option<i64>,
        filters: DecisionListFilters<'_>,
    ) -> Result<(Vec<DecisionRecord>, Option<i64>), AegisError>;
    async fn get_decision_count_24h_for_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<i64, AegisError>;
    async fn count_decisions_by_outcome(
        &self,
        tenant_id: &str,
    ) -> Result<(i64, i64, i64, i64), AegisError>;
    /// Decision counts bucketed over time (for timeseries panels). Returns
    /// `(bucket_label, count)` ascending. Tenant-scoped and parameterized.
    async fn count_decisions_over_time(
        &self,
        tenant_id: &str,
        bucket: TimeBucket,
        filters: DecisionListFilters<'_>,
    ) -> Result<Vec<(String, i64)>, AegisError>;
    async fn count_decisions_grouped(
        &self,
        tenant_id: &str,
        field: DecisionGroupField,
        filters: DecisionListFilters<'_>,
        limit: i64,
    ) -> Result<Vec<(String, i64)>, AegisError>;
    async fn list_decisions_by_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<Vec<DecisionRecord>, AegisError>;

    // MCP Servers
    async fn register_mcp_server(&self, record: &McpServerRecord) -> Result<(), AegisError>;
    async fn get_mcp_server_by_key(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Option<McpServerRecord>, AegisError>;
    async fn list_mcp_servers(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<McpServerRecord>, AegisError>;
    /// #1193: soft delete (sets `deleted_at`) — see `db::mcp::delete_mcp_server`.
    async fn delete_mcp_server(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<bool, AegisError>;
    async fn update_mcp_server(
        &self,
        tenant_id: &str,
        server_key: &str,
        name: Option<&str>,
        owner_team: Option<Option<&str>>,
        transport: Option<&str>,
        source: Option<Option<&str>>,
        trust_level: Option<&str>,
        endpoint: Option<&str>,
        status: Option<&str>,
        inspection_enabled: Option<bool>,
    ) -> Result<Option<McpServerRecord>, AegisError>;
    async fn get_mcp_server_by_id(
        &self,
        tenant_id: &str,
        server_id: &str,
    ) -> Result<Option<McpServerRecord>, AegisError>;
    async fn insert_mcp_manifest_snapshot(
        &self,
        record: &McpManifestSnapshotRecord,
    ) -> Result<(), AegisError>;
    async fn get_last_mcp_manifest_snapshot(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Option<McpManifestSnapshotRecord>, AegisError>;
    async fn list_mcp_manifest_snapshots(
        &self,
        tenant_id: &str,
        server_key: &str,
        limit: i64,
    ) -> Result<Vec<McpManifestSnapshotRecord>, AegisError>;
    async fn set_mcp_tool_status(
        &self,
        tenant_id: &str,
        server_key: &str,
        tool_key: &str,
        status: &str,
    ) -> Result<bool, AegisError>;
    async fn discover_mcp_tools(
        &self,
        tenant_id: &str,
        server_key: &str,
        tools: &[McpToolManifestItem],
        new_hash: &str,
    ) -> Result<Vec<McpToolRecord>, AegisError>;
    async fn list_mcp_tools(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Vec<McpToolRecord>, AegisError>;
    async fn set_mcp_server_manifest_hash(
        &self,
        tenant_id: &str,
        server_key: &str,
        manifest_hash: &str,
    ) -> Result<(), AegisError>;
    async fn touch_mcp_server_discovery(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<(), AegisError>;
    async fn get_mcp_tool_by_key(
        &self,
        tenant_id: &str,
        server_id: &str,
        tool_key: &str,
    ) -> Result<Option<McpToolRecord>, AegisError>;

    // Policies
    async fn list_policies(&self, tenant_id: &str) -> Result<Vec<PolicyRecord>, AegisError>;
    async fn get_policy_by_id(
        &self,
        tenant_id: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, AegisError>;
    async fn insert_policy(&self, record: &PolicyRecord) -> Result<(), AegisError>;
    async fn update_policy(&self, record: &PolicyRecord) -> Result<(), AegisError>;
    async fn insert_policy_version(&self, record: &PolicyRecord) -> Result<(), AegisError>;
    async fn list_policy_versions(
        &self,
        tenant_id: &str,
        policy_id: &str,
    ) -> Result<Vec<PolicyVersionRecord>, AegisError>;
    async fn delete_policy(&self, tenant_id: &str, policy_id: &str) -> Result<bool, AegisError>;
    async fn list_policy_audit_log(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PolicyAuditLogRecord>, AegisError>;
    async fn append_policy_audit_log_entry_atomic(
        &self,
        tenant_id: &str,
        build: Box<dyn FnOnce(String) -> PolicyAuditLogRecord + Send>,
    ) -> Result<PolicyAuditLogRecord, AegisError>;

    // Receipts
    async fn list_action_receipts_in_range(
        &self,
        tenant_id: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Result<Vec<ActionReceiptRecord>, AegisError>;
    async fn get_action_receipt_by_id(
        &self,
        tenant_id: &str,
        receipt_id: &str,
    ) -> Result<Option<ActionReceiptRecord>, AegisError>;
    async fn list_action_receipts_cursor(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<ActionReceiptRecord>, Option<i64>), AegisError>;
    async fn list_action_receipts_chain_order(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ActionReceiptRecord>, AegisError>;
    async fn get_action_receipt_by_decision_id(
        &self,
        tenant_id: &str,
        decision_id: &str,
    ) -> Result<Option<ActionReceiptRecord>, AegisError>;
    async fn list_action_receipts_by_decision_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<HashMap<String, ActionReceiptRecord>, AegisError>;
    async fn get_latest_action_receipt(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ActionReceiptRecord>, AegisError>;
    async fn insert_action_receipt(&self, record: &ActionReceiptRecord) -> Result<(), AegisError>;
    async fn append_action_receipt_atomic(
        &self,
        tenant_id: &str,
        record: ActionReceiptRecord,
    ) -> Result<ActionReceiptRecord, AegisError>;
    async fn count_receipts(&self, tenant_id: &str) -> Result<i64, AegisError>;

    // Replay nonces (PR8: durable, multi-instance-safe replay protection)
    /// Atomically record a `(tenant, agent, nonce)` triple. Returns `true` if it
    /// is a replay (already present and unexpired), `false` if first-seen now.
    async fn check_and_insert_replay_nonce(
        &self,
        tenant_id: &str,
        agent_id: &str,
        nonce: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, AegisError>;
    /// Delete replay-nonce rows whose window has elapsed; returns rows removed.
    async fn delete_expired_replay_nonces(&self, now: DateTime<Utc>) -> Result<u64, AegisError>;

    // Agent runs (Phase 2.1: runtime control-plane spine)
    async fn insert_agent_run(&self, record: &AgentRunRecord) -> Result<(), AegisError>;
    async fn get_agent_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<Option<AgentRunRecord>, AegisError>;
    async fn update_agent_run_status(
        &self,
        tenant_id: &str,
        run_id: &str,
        status: &str,
        finished_at: Option<DateTime<Utc>>,
    ) -> Result<bool, AegisError>;
    async fn list_agent_runs(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AgentRunRecord>, AegisError>;

    // Runtime events (Phase 2.2: idempotent ingest substrate)
    /// Idempotently append a runtime event; `true` = newly inserted, `false` =
    /// deduped (the `(tenant_id, event_id)` was already present).
    async fn insert_runtime_event(&self, record: &RuntimeEventRecord) -> Result<bool, AegisError>;
    async fn list_runtime_events_for_run(
        &self,
        tenant_id: &str,
        run_id: &str,
        limit: i64,
    ) -> Result<Vec<RuntimeEventRecord>, AegisError>;
    async fn list_runtime_events(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RuntimeEventRecord>, AegisError>;
    async fn query_runtime_events(
        &self,
        tenant_id: &str,
        limit: i64,
        cursor: Option<i64>,
        filters: RuntimeEventListFilters<'_>,
    ) -> Result<(Vec<RuntimeEventRecord>, Option<i64>), AegisError>;
    async fn count_runtime_events_over_time(
        &self,
        tenant_id: &str,
        bucket: TimeBucket,
        filters: RuntimeEventListFilters<'_>,
    ) -> Result<Vec<(String, i64)>, AegisError>;
    async fn count_runtime_events_grouped(
        &self,
        tenant_id: &str,
        field: RuntimeEventGroupField,
        filters: RuntimeEventListFilters<'_>,
        limit: i64,
    ) -> Result<Vec<(String, i64)>, AegisError>;

    // Control commands (Phase 2.3: signed gateway->sensor commands)
    async fn insert_control_command(&self, record: &ControlCommandRecord)
        -> Result<(), AegisError>;
    async fn get_control_command(
        &self,
        tenant_id: &str,
        command_id: &str,
    ) -> Result<Option<ControlCommandRecord>, AegisError>;
    async fn update_control_command_status(
        &self,
        tenant_id: &str,
        command_id: &str,
        status: &str,
    ) -> Result<bool, AegisError>;
    async fn list_control_commands(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ControlCommandRecord>, AegisError>;

    // Bans (Phase 2.4: first-class ban store)
    async fn insert_ban(&self, record: &AgentBanRecord) -> Result<(), AegisError>;
    /// Hot enforcement lookup: is `(target_type, target_value)` under an active,
    /// unrevoked, unexpired ban for this tenant as of `now`?
    async fn is_banned(
        &self,
        tenant_id: &str,
        target_type: &str,
        target_value: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AegisError>;
    async fn get_ban(
        &self,
        tenant_id: &str,
        ban_id: &str,
    ) -> Result<Option<AgentBanRecord>, AegisError>;
    async fn revoke_ban(
        &self,
        tenant_id: &str,
        ban_id: &str,
        revoked_by: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AegisError>;
    async fn list_bans(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AgentBanRecord>, AegisError>;

    // SOC (alerts, incidents, baseline, hourly counts)
    async fn list_soc_alerts(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        severity: Option<&str>,
        limit: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<SocAlertRecord>, Option<i64>), AegisError>;
    async fn insert_soc_alert(&self, record: &SocAlertRecord) -> Result<(), AegisError>;
    async fn get_incident_by_id(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<Option<SocIncidentRecord>, AegisError>;
    async fn list_soc_incidents(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        severity: Option<&str>,
        status: Option<&str>,
        kind: Option<&str>,
        limit: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<SocIncidentRecord>, Option<i64>), AegisError>;
    async fn insert_soc_incident(&self, record: &SocIncidentRecord) -> Result<(), AegisError>;
    async fn close_soc_incident(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<bool, AegisError>;
    async fn get_soc_summary(&self, tenant_id: &str) -> Result<SocSummary, AegisError>;
    async fn get_action_count_last_24h(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<i64, AegisError>;
    async fn get_agent_hourly_action_counts_7d(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Vec<(String, i64)>, AegisError>;
    async fn increment_agent_hourly_action_count(
        &self,
        tenant_id: &str,
        agent_id: &str,
        hour_bucket: &str,
    ) -> Result<(), AegisError>;
    async fn record_agent_known_tool_action(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
        action_key: &str,
        first_seen_at: &str,
    ) -> Result<bool, AegisError>;
    async fn get_agent_known_tool_actions(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Vec<(String, String)>, AegisError>;

    // Tenants
    async fn get_tenant_by_id(&self, tenant_id: &str) -> Result<Option<TenantRecord>, AegisError>;
    async fn insert_tenant(&self, record: &TenantRecord) -> Result<(), AegisError>;
    async fn list_tenants(&self) -> Result<Vec<TenantRecord>, AegisError>;
    async fn delete_tenant_by_id(&self, tenant_id: &str) -> Result<bool, AegisError>;
    async fn export_tenant_data(&self, tenant_id: &str) -> Result<TenantExport, AegisError>;
    async fn delete_tenant_data(&self, tenant_id: &str) -> Result<(), AegisError>;
    async fn set_tenant_auto_respond(
        &self,
        tenant_id: &str,
        enabled: bool,
    ) -> Result<(), AegisError>;
    async fn set_tenant_auto_rotate_token_on_leak(
        &self,
        tenant_id: &str,
        enabled: bool,
    ) -> Result<(), AegisError>;
    async fn get_tenant_risk_weights(
        &self,
        tenant_id: &str,
    ) -> Result<Option<RiskWeights>, AegisError>;
    async fn get_tenant_risk_escalation_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<(i32, i32)>, AegisError>;
    async fn put_tenant_risk_weights(
        &self,
        tenant_id: &str,
        weights: &RiskWeights,
    ) -> Result<(), AegisError>;
    async fn put_tenant_risk_escalation_config(
        &self,
        tenant_id: &str,
        threshold: i32,
        window_minutes: i32,
    ) -> Result<(), AegisError>;

    // Webhooks
    async fn list_webhook_subscriptions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<WebhookSubscriptionRecord>, AegisError>;
    /// #1142: cursor-paginated variant of `list_webhook_subscriptions`.
    async fn list_webhook_subscriptions_cursor(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<WebhookSubscriptionRecord>, Option<i64>), AegisError>;
    async fn get_webhook_subscription(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<WebhookSubscriptionRecord>, AegisError>;
    async fn insert_webhook_subscription(
        &self,
        tenant_id: &str,
        url: &str,
        secret_hash: Option<&str>,
        event_types: &str,
        delivery_secret: &str,
        min_severity: &str,
        format: &str,
    ) -> Result<WebhookSubscriptionRecord, AegisError>;
    async fn update_webhook_subscription(
        &self,
        record: &WebhookSubscriptionRecord,
    ) -> Result<(), AegisError>;
    async fn delete_webhook_subscription(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<bool, AegisError>;
    async fn get_active_webhook_subscriptions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<WebhookSubscriptionRecord>, AegisError>;
    async fn record_webhook_delivery_attempt(
        &self,
        tenant_id: &str,
        subscription_id: &str,
        success: bool,
    ) -> Result<(), AegisError>;

    // Audit Events
    async fn insert_audit_event(&self, record: &AuditEventRecord) -> Result<(), AegisError>;
    async fn get_audit_events(
        &self,
        tenant_id: &str,
        decision_id: Option<&str>,
        cursor: Option<i64>,
        q: Option<&str>,
    ) -> Result<(Vec<AuditEventRecord>, Option<i64>), AegisError>;
    async fn archive_audit_events_older_than(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<i64, AegisError>;
    async fn insert_audit_events_batch(
        &self,
        records: &[AuditEventRecord],
    ) -> Result<(), AegisError>;
    async fn get_audit_events_in_range(
        &self,
        tenant_id: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<AuditEventRecord>, AegisError>;
    async fn get_audit_events_by_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<Vec<AuditEventRecord>, AegisError>;
    async fn get_audit_event_decision_id(
        &self,
        tenant_id: &str,
        event_id: &str,
    ) -> Result<Option<String>, AegisError>;
    async fn list_audit_events_by_decision_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<Vec<AuditEventRecord>, AegisError>;

    // API Keys
    async fn get_api_key_by_id(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<ApiKeyRecord>, AegisError>;
    async fn list_api_keys(&self, tenant_id: &str) -> Result<Vec<ApiKeyRecord>, AegisError>;
    /// #1142: cursor-paginated variant of `list_api_keys`.
    async fn list_api_keys_cursor(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<ApiKeyRecord>, Option<i64>), AegisError>;
    async fn insert_api_key(&self, record: &ApiKeyRecord) -> Result<(), AegisError>;
    async fn revoke_api_key(&self, tenant_id: &str, id: &str) -> Result<bool, AegisError>;
    async fn is_active_api_key(&self, tenant_id: &str, key_hash: &str) -> Result<bool, AegisError>;
    async fn create_api_key(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<(String, String), AegisError>;
    async fn list_soc_incidents_in_range(
        &self,
        tenant_id: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<SocIncidentRecord>, AegisError>;
    async fn get_tenant_stats(&self, tenant_id: &str) -> Result<TenantStats, AegisError>;
    async fn get_db_stats(&self) -> Result<DbStats, AegisError>;
    async fn upsert_detection_rule(
        &self,
        tenant_id: &str,
        rule_key: &str,
        name: &str,
        severity: &str,
        condition: &str,
        summary_template: &str,
        enabled: bool,
    ) -> Result<DetectionRuleRecord, AegisError>;
    async fn list_detection_rules(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<DetectionRuleRecord>, AegisError>;
    async fn delete_detection_rule(&self, tenant_id: &str, id: &str) -> Result<bool, AegisError>;

    // Playbooks
    #[allow(clippy::too_many_arguments)]
    async fn insert_playbook(
        &self,
        tenant_id: &str,
        name: &str,
        trigger_kind: &str,
        trigger_severity: &[String],
        trigger_agent_id: Option<&str>,
        trigger_environment: Option<&str>,
        steps_json: &str,
    ) -> Result<PlaybookRecord, AegisError>;
    async fn list_playbooks(&self, tenant_id: &str) -> Result<Vec<PlaybookRecord>, AegisError>;
    /// #1142: cursor-paginated variant of `list_playbooks`.
    async fn list_playbooks_cursor(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<PlaybookRecord>, Option<i64>), AegisError>;
    async fn get_playbook_by_id(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<PlaybookRecord>, AegisError>;
    async fn delete_playbook(&self, tenant_id: &str, id: &str) -> Result<bool, AegisError>;
    async fn set_playbook_enabled(
        &self,
        tenant_id: &str,
        id: &str,
        enabled: bool,
    ) -> Result<bool, AegisError>;
    async fn list_soc_alerts_by_source_event_ids(
        &self,
        tenant_id: &str,
        event_ids: &[String],
    ) -> Result<Vec<SocAlertRecord>, AegisError>;
    async fn list_decisions_by_run_id(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<Vec<DecisionRecord>, AegisError>;
    async fn list_decisions_in_range(
        &self,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<DecisionRecord>, AegisError>;
    async fn list_soc_alerts_since(
        &self,
        tenant_id: &str,
        since_rowid: i64,
        severity: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<Vec<(SocAlertRecord, i64)>, AegisError>;
    async fn list_soc_incidents_since(
        &self,
        tenant_id: &str,
        since_rowid: i64,
        status_filter: Option<&str>,
        severity: Option<&str>,
        agent_id: Option<&str>,
        kind: Option<&str>,
    ) -> Result<Vec<(SocIncidentRecord, i64)>, AegisError>;
    async fn list_decisions_since(
        &self,
        tenant_id: &str,
        since_rowid: i64,
    ) -> Result<Vec<(DecisionRecord, i64)>, AegisError>;
    async fn max_decision_rowid(&self, tenant_id: &str) -> Result<i64, AegisError>;
    async fn max_soc_alert_rowid(&self, tenant_id: &str) -> Result<i64, AegisError>;
    async fn max_soc_incident_rowid(&self, tenant_id: &str) -> Result<i64, AegisError>;

    // General & System
    async fn health_check(&self) -> Result<(), AegisError>;
    async fn get_database_size_bytes(&self) -> Result<i64, AegisError>;
    async fn get_table_row_counts(&self) -> Result<Vec<TableRowCount>, AegisError>;
    async fn backup_database_to(&self, dest_path: &str) -> Result<(), AegisError>;
    fn get_pool(&self) -> &DbPool;
    fn get_pool_metrics(&self) -> (u32, u32);
    async fn close(&self);
}
