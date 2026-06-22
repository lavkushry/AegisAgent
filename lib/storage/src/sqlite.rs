use crate::db;
use crate::traits::StorageBackend;
use aegis_api::models::*;
use aegis_common::errors::AegisError;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use std::collections::HashMap;

pub struct SqliteStorage {
    pub pool: SqlitePool,
}

impl SqliteStorage {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl StorageBackend for SqliteStorage {
    // Agents & Skills
    async fn rotate_agent_token(
        &self,
        tenant_id: &str,
        agent_id: &str,
        new_token_hash: &str,
    ) -> Result<(), AegisError> {
        db::rotate_agent_token(&self.pool, tenant_id, agent_id, new_token_hash)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_agent_by_token(
        &self,
        tenant_id: &str,
        token_hash: &str,
    ) -> Result<Option<AgentRecord>, AegisError> {
        db::get_agent_by_token(&self.pool, tenant_id, token_hash)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_agent_by_key(
        &self,
        tenant_id: &str,
        agent_key: &str,
    ) -> Result<Option<AgentRecord>, AegisError> {
        db::get_agent_by_key(&self.pool, tenant_id, agent_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_agent_by_mtls_cn(
        &self,
        tenant_id: &str,
        cn: &str,
    ) -> Result<Option<AgentRecord>, AegisError> {
        db::get_agent_by_mtls_cn(&self.pool, tenant_id, cn)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_agents(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
        status_filter: Option<&str>,
    ) -> Result<Vec<AgentRecord>, AegisError> {
        db::list_agents(&self.pool, tenant_id, limit, offset, status_filter)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_agent_by_id(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Option<AgentRecord>, AegisError> {
        db::get_agent_by_id(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_agent_risk_scoreboard(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AgentRiskScoreboardEntry>, AegisError> {
        db::get_agent_risk_scoreboard(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_agent(&self, record: &AgentRecord) -> Result<(), AegisError> {
        db::insert_agent(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn update_agent(&self, record: &AgentRecord) -> Result<(), AegisError> {
        db::update_agent(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_skill(
        &self,
        record: &SkillRecord,
        actions: &[SkillActionRecord],
    ) -> Result<String, AegisError> {
        let skill_id = db::insert_skill(
            &self.pool,
            &record.tenant_id,
            &record.skill_key,
            &record.name,
            &record.r#type,
            record.auth_type.as_deref(),
            record.owner_team.as_deref(),
            record.default_risk.as_deref(),
        )
        .await
        .map_err(AegisError::Database)?;

        for action in actions {
            db::insert_skill_action(
                &self.pool,
                &skill_id,
                &action.action_key,
                action.description.as_deref(),
                &action.risk,
                action.mutates_state,
                action.data_access.as_deref(),
                action.approval_required,
                &action.default_decision,
            )
            .await
            .map_err(AegisError::Database)?;
        }
        Ok(skill_id)
    }

    async fn insert_skill_action(&self, record: &SkillActionRecord) -> Result<(), AegisError> {
        db::insert_skill_action(
            &self.pool,
            &record.skill_id,
            &record.action_key,
            record.description.as_deref(),
            &record.risk,
            record.mutates_state,
            record.data_access.as_deref(),
            record.approval_required,
            &record.default_decision,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn get_skill_action(
        &self,
        tenant_id: &str,
        skill_key: &str,
        action_key: &str,
    ) -> Result<Option<SkillActionRecord>, AegisError> {
        db::get_skill_action(&self.pool, tenant_id, skill_key, action_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn set_agent_status(
        &self,
        tenant_id: &str,
        agent_id: &str,
        status: &str,
    ) -> Result<bool, AegisError> {
        db::set_agent_status(&self.pool, tenant_id, agent_id, status)
            .await
            .map_err(AegisError::Database)
    }

    async fn set_agent_frozen_reason(
        &self,
        tenant_id: &str,
        agent_id: &str,
        reason: Option<&str>,
    ) -> Result<(), AegisError> {
        db::set_agent_frozen_reason(&self.pool, tenant_id, agent_id, reason)
            .await
            .map_err(AegisError::Database)
    }

    async fn set_agent_force_approval(
        &self,
        tenant_id: &str,
        agent_id: &str,
        force: bool,
    ) -> Result<(), AegisError> {
        db::set_agent_force_approval(&self.pool, tenant_id, agent_id, force)
            .await
            .map_err(AegisError::Database)
    }

    async fn touch_agent_last_seen(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<(), AegisError> {
        db::touch_agent_last_seen(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn is_agent_active(&self, tenant_id: &str, agent_id: &str) -> Result<bool, AegisError> {
        db::is_agent_active(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn maybe_escalate_agent_risk_tier(
        &self,
        tenant_id: &str,
        agent_id: &str,
        current_tier: &str,
    ) -> Result<Option<(String, String)>, AegisError> {
        crate::risk_escalation::maybe_escalate_agent_risk_tier(
            &self.pool,
            tenant_id,
            agent_id,
            current_tier,
        )
        .await
    }

    async fn grant_agent_tool_permission(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
    ) -> Result<AgentToolPermission, AegisError> {
        db::grant_agent_tool_permission(&self.pool, tenant_id, agent_id, tool_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_agent_tool_permissions(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Vec<AgentToolPermission>, AegisError> {
        db::get_agent_tool_permissions(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn revoke_agent_tool_permission(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
    ) -> Result<bool, AegisError> {
        db::revoke_agent_tool_permission(&self.pool, tenant_id, agent_id, tool_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn agent_tool_permission_status(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
    ) -> Result<bool, AegisError> {
        db::agent_tool_permission_status(&self.pool, tenant_id, agent_id, tool_key)
            .await
            .map(|opt| opt.unwrap_or(true))
            .map_err(AegisError::Database)
    }

    // Approvals
    async fn consume_approval(
        &self,
        tenant_id: &str,
        approval_id: &str,
    ) -> Result<bool, AegisError> {
        db::consume_approval(&self.pool, tenant_id, approval_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_approvals_in_range(
        &self,
        tenant_id: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Result<Vec<ApprovalRecord>, AegisError> {
        db::list_approvals_in_range(&self.pool, tenant_id, start, end)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_approval_by_decision_id(
        &self,
        tenant_id: &str,
        decision_id: &str,
    ) -> Result<Option<ApprovalRecord>, AegisError> {
        db::get_approval_by_decision_id(&self.pool, tenant_id, decision_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_approvals_by_decision_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<HashMap<String, ApprovalRecord>, AegisError> {
        db::list_approvals_by_decision_ids(&self.pool, tenant_id, decision_ids)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_approval(&self, record: &ApprovalRecord) -> Result<(), AegisError> {
        db::insert_approval(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_pending_approvals(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ApprovalRecord>, AegisError> {
        db::list_pending_approvals(&self.pool, tenant_id, limit, offset)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_approval_by_id(
        &self,
        tenant_id: &str,
        approval_id: &str,
    ) -> Result<Option<ApprovalRecord>, AegisError> {
        db::get_approval_by_id(&self.pool, tenant_id, approval_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn update_approval_edit(
        &self,
        tenant_id: &str,
        approval_id: &str,
        approver: &str,
        reason: Option<&str>,
        edited_call: &str,
        new_hash: &str,
    ) -> Result<bool, AegisError> {
        db::update_approval_edit(
            &self.pool,
            tenant_id,
            approval_id,
            approver,
            reason,
            edited_call,
            new_hash,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn update_approval_status(
        &self,
        tenant_id: &str,
        approval_id: &str,
        status: &str,
        approver: &str,
        reason: Option<&str>,
        decided_at: Option<DateTime<Utc>>,
    ) -> Result<bool, AegisError> {
        db::update_approval_status(
            &self.pool,
            tenant_id,
            approval_id,
            status,
            approver,
            reason,
            decided_at,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn delete_expired_approvals_older_than(
        &self,
        ts: DateTime<Utc>,
    ) -> Result<i64, AegisError> {
        db::delete_expired_approvals_older_than(&self.pool, ts)
            .await
            .map(|count| count as i64)
            .map_err(AegisError::Database)
    }

    // Decisions
    async fn get_decision_by_id(
        &self,
        tenant_id: &str,
        decision_id: &str,
    ) -> Result<Option<DecisionRecord>, AegisError> {
        db::get_decision_by_id(&self.pool, tenant_id, decision_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_decision_by_request_id(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<DecisionRecord>, AegisError> {
        db::get_decision_by_request_id(&self.pool, tenant_id, agent_id, request_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_decision(&self, record: &DecisionRecord) -> Result<(), AegisError> {
        db::retry_on_busy(3, || db::insert_decision(&self.pool, record))
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_agent_risk_score(
        &self,
        tenant_id: &str,
        agent_id: &str,
        decision_id: &str,
        score: i32,
        reason: &str,
    ) -> Result<(), AegisError> {
        db::insert_agent_risk_score(&self.pool, tenant_id, agent_id, decision_id, score, reason)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_decisions(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        decision_filter: Option<&str>,
        limit: i64,
        cursor: Option<i64>,
        q: Option<&str>,
    ) -> Result<(Vec<DecisionRecord>, Option<i64>), AegisError> {
        db::list_decisions_cursor(
            &self.pool,
            tenant_id,
            limit,
            0,
            cursor,
            agent_id,
            decision_filter,
            q,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn get_decision_count_24h_for_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<i64, AegisError> {
        db::get_decision_count_24h_for_agent(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn count_decisions_by_outcome(
        &self,
        tenant_id: &str,
    ) -> Result<(i64, i64, i64, i64), AegisError> {
        db::count_decisions_by_outcome(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_decisions_by_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<Vec<DecisionRecord>, AegisError> {
        db::list_decisions_by_ids(&self.pool, tenant_id, decision_ids)
            .await
            .map(|m| m.into_values().collect())
            .map_err(AegisError::Database)
    }

    // MCP Servers
    async fn register_mcp_server(&self, record: &McpServerRecord) -> Result<(), AegisError> {
        db::register_mcp_server(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_mcp_server_by_key(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Option<McpServerRecord>, AegisError> {
        db::get_mcp_server_by_key(&self.pool, tenant_id, server_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_mcp_servers(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<McpServerRecord>, AegisError> {
        db::list_mcp_servers(&self.pool, tenant_id, limit, offset)
            .await
            .map_err(AegisError::Database)
    }

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
    ) -> Result<Option<McpServerRecord>, AegisError> {
        db::update_mcp_server(
            &self.pool,
            tenant_id,
            server_key,
            name,
            owner_team,
            transport,
            source,
            trust_level,
            endpoint,
            status,
        )
        .await
        .map_err(AegisError::Database)?;
        if let Some(enabled) = inspection_enabled {
            db::set_mcp_server_inspection_enabled(&self.pool, tenant_id, server_key, enabled)
                .await
                .map_err(AegisError::Database)?;
        }
        db::get_mcp_server_by_key(&self.pool, tenant_id, server_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_mcp_server_by_id(
        &self,
        tenant_id: &str,
        server_id: &str,
    ) -> Result<Option<McpServerRecord>, AegisError> {
        db::get_mcp_server_by_id(&self.pool, tenant_id, server_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_mcp_manifest_snapshot(
        &self,
        record: &McpManifestSnapshotRecord,
    ) -> Result<(), AegisError> {
        db::insert_mcp_manifest_snapshot(
            &self.pool,
            &record.tenant_id,
            &record.server_key,
            &record.manifest_hash,
            &record.manifest_json,
        )
        .await
        .map(|_| ())
        .map_err(AegisError::Database)
    }

    async fn get_last_mcp_manifest_snapshot(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Option<McpManifestSnapshotRecord>, AegisError> {
        db::get_last_mcp_manifest_snapshot(&self.pool, tenant_id, server_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_mcp_manifest_snapshots(
        &self,
        tenant_id: &str,
        server_key: &str,
        limit: i64,
    ) -> Result<Vec<McpManifestSnapshotRecord>, AegisError> {
        db::list_mcp_manifest_snapshots(&self.pool, tenant_id, server_key, limit)
            .await
            .map_err(AegisError::Database)
    }

    async fn set_mcp_tool_status(
        &self,
        tenant_id: &str,
        server_key: &str,
        tool_key: &str,
        status: &str,
    ) -> Result<bool, AegisError> {
        db::set_mcp_tool_status(&self.pool, tenant_id, server_key, tool_key, status)
            .await
            .map_err(AegisError::Database)
    }

    async fn discover_mcp_tools(
        &self,
        tenant_id: &str,
        server_key: &str,
        tools: &[McpToolManifestItem],
        new_hash: &str,
    ) -> Result<Vec<McpToolRecord>, AegisError> {
        db::discover_mcp_tools(&self.pool, tenant_id, server_key, tools, new_hash)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_mcp_tools(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Vec<McpToolRecord>, AegisError> {
        db::list_mcp_tools(&self.pool, tenant_id, server_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn set_mcp_server_manifest_hash(
        &self,
        tenant_id: &str,
        server_key: &str,
        manifest_hash: &str,
    ) -> Result<(), AegisError> {
        db::set_mcp_server_manifest_hash(&self.pool, tenant_id, server_key, manifest_hash)
            .await
            .map_err(AegisError::Database)
    }

    async fn touch_mcp_server_discovery(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<(), AegisError> {
        db::touch_mcp_server_discovery(&self.pool, tenant_id, server_key)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_mcp_tool_by_key(
        &self,
        tenant_id: &str,
        server_id: &str,
        tool_key: &str,
    ) -> Result<Option<McpToolRecord>, AegisError> {
        db::get_mcp_tool_by_key(&self.pool, tenant_id, server_id, tool_key)
            .await
            .map_err(AegisError::Database)
    }

    // Policies
    async fn list_policies(&self, tenant_id: &str) -> Result<Vec<PolicyRecord>, AegisError> {
        db::list_policies(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_policy_by_id(
        &self,
        tenant_id: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyRecord>, AegisError> {
        db::get_policy_by_id(&self.pool, tenant_id, policy_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_policy(&self, record: &PolicyRecord) -> Result<(), AegisError> {
        db::insert_policy(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn update_policy(&self, record: &PolicyRecord) -> Result<(), AegisError> {
        db::update_policy(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_policy_version(&self, record: &PolicyRecord) -> Result<(), AegisError> {
        db::insert_policy_version(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_policy_versions(
        &self,
        tenant_id: &str,
        policy_id: &str,
    ) -> Result<Vec<PolicyVersionRecord>, AegisError> {
        db::list_policy_versions(&self.pool, tenant_id, policy_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn delete_policy(&self, tenant_id: &str, policy_id: &str) -> Result<bool, AegisError> {
        db::delete_policy(&self.pool, tenant_id, policy_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_policy_audit_log(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PolicyAuditLogRecord>, AegisError> {
        db::list_policy_audit_log(&self.pool, tenant_id, limit, offset)
            .await
            .map_err(AegisError::Database)
    }

    async fn append_policy_audit_log_entry_atomic(
        &self,
        tenant_id: &str,
        build: Box<dyn FnOnce(String) -> PolicyAuditLogRecord + Send>,
    ) -> Result<PolicyAuditLogRecord, AegisError> {
        db::append_policy_audit_log_entry_atomic(&self.pool, tenant_id, build)
            .await
            .map_err(AegisError::Database)
    }

    // Receipts
    async fn list_action_receipts_in_range(
        &self,
        tenant_id: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Result<Vec<ActionReceiptRecord>, AegisError> {
        db::list_action_receipts_in_range(&self.pool, tenant_id, start, end)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_action_receipt_by_id(
        &self,
        tenant_id: &str,
        receipt_id: &str,
    ) -> Result<Option<ActionReceiptRecord>, AegisError> {
        db::get_action_receipt_by_id(&self.pool, tenant_id, receipt_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_action_receipts_cursor(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<ActionReceiptRecord>, Option<i64>), AegisError> {
        db::list_action_receipts_cursor(&self.pool, tenant_id, limit, offset, cursor)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_action_receipts_chain_order(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ActionReceiptRecord>, AegisError> {
        db::list_action_receipts_chain_order(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_action_receipt_by_decision_id(
        &self,
        tenant_id: &str,
        decision_id: &str,
    ) -> Result<Option<ActionReceiptRecord>, AegisError> {
        db::get_action_receipt_by_decision_id(&self.pool, tenant_id, decision_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_action_receipts_by_decision_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<HashMap<String, ActionReceiptRecord>, AegisError> {
        db::list_action_receipts_by_decision_ids(&self.pool, tenant_id, decision_ids)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_latest_action_receipt(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ActionReceiptRecord>, AegisError> {
        db::get_latest_action_receipt(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_action_receipt(&self, record: &ActionReceiptRecord) -> Result<(), AegisError> {
        db::insert_action_receipt(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn append_action_receipt_atomic(
        &self,
        tenant_id: &str,
        mut record: ActionReceiptRecord,
    ) -> Result<ActionReceiptRecord, AegisError> {
        db::append_action_receipt_atomic(&self.pool, tenant_id, move |prev_receipt_hash| {
            record.prev_receipt_hash = prev_receipt_hash;
            record.receipt_hash = db::compute_receipt_hash(&record);
            if let Some(signer) = aegis_common::hash::global_signer() {
                record.signature = Some(signer.sign_hash(&record.receipt_hash));
                record.signer_public_key = Some(signer.public_key_hex());
                record.signer_key_id = signer.key_id().map(str::to_string);
            }
            record
        })
        .await
        .map_err(AegisError::Database)
    }

    async fn count_receipts(&self, tenant_id: &str) -> Result<i64, AegisError> {
        db::count_receipts(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    // SOC (alerts, incidents, baseline, hourly counts)
    async fn list_soc_alerts(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        severity: Option<&str>,
        limit: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<SocAlertRecord>, Option<i64>), AegisError> {
        db::list_soc_alerts_cursor(&self.pool, tenant_id, limit, 0, severity, agent_id, cursor)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_soc_alert(&self, record: &SocAlertRecord) -> Result<(), AegisError> {
        db::insert_soc_alert(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_incident_by_id(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<Option<SocIncidentRecord>, AegisError> {
        db::get_soc_incident(&self.pool, tenant_id, incident_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_soc_incidents(
        &self,
        tenant_id: &str,
        agent_id: Option<&str>,
        severity: Option<&str>,
        status: Option<&str>,
        kind: Option<&str>,
        limit: i64,
        cursor: Option<i64>,
    ) -> Result<(Vec<SocIncidentRecord>, Option<i64>), AegisError> {
        db::list_soc_incidents_cursor(
            &self.pool, tenant_id, limit, 0, status, severity, agent_id, kind, cursor,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn insert_soc_incident(&self, record: &SocIncidentRecord) -> Result<(), AegisError> {
        db::insert_soc_incident(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn close_soc_incident(
        &self,
        tenant_id: &str,
        incident_id: &str,
    ) -> Result<bool, AegisError> {
        db::close_soc_incident(&self.pool, tenant_id, incident_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_soc_summary(&self, tenant_id: &str) -> Result<SocSummary, AegisError> {
        db::soc_summary(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_action_count_last_24h(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<i64, AegisError> {
        db::get_action_count_last_24h(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_agent_hourly_action_counts_7d(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Vec<(String, i64)>, AegisError> {
        db::get_agent_hourly_action_counts_7d(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn increment_agent_hourly_action_count(
        &self,
        tenant_id: &str,
        agent_id: &str,
        hour_bucket: &str,
    ) -> Result<(), AegisError> {
        db::increment_agent_hourly_count(&self.pool, tenant_id, agent_id, hour_bucket)
            .await
            .map(|_| ())
            .map_err(AegisError::Database)
    }

    async fn record_agent_known_tool_action(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool_key: &str,
        action_key: &str,
        first_seen_at: &str,
    ) -> Result<bool, AegisError> {
        db::record_known_tool_action(
            &self.pool,
            tenant_id,
            agent_id,
            tool_key,
            action_key,
            first_seen_at,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn get_agent_known_tool_actions(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Vec<(String, String)>, AegisError> {
        db::get_agent_known_tool_actions(&self.pool, tenant_id, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    // Tenants
    async fn get_tenant_by_id(&self, tenant_id: &str) -> Result<Option<TenantRecord>, AegisError> {
        db::get_tenant_by_id(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_tenant(&self, record: &TenantRecord) -> Result<(), AegisError> {
        db::insert_tenant(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_tenants(&self) -> Result<Vec<TenantRecord>, AegisError> {
        db::list_tenants(&self.pool)
            .await
            .map_err(AegisError::Database)
    }

    async fn delete_tenant_by_id(&self, tenant_id: &str) -> Result<bool, AegisError> {
        db::delete_tenant_by_id(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn export_tenant_data(&self, tenant_id: &str) -> Result<TenantExport, AegisError> {
        db::export_tenant_data(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn delete_tenant_data(&self, tenant_id: &str) -> Result<(), AegisError> {
        db::delete_tenant_data(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn set_tenant_auto_respond(
        &self,
        tenant_id: &str,
        enabled: bool,
    ) -> Result<(), AegisError> {
        db::set_tenant_auto_respond(&self.pool, tenant_id, enabled)
            .await
            .map_err(AegisError::Database)
    }

    async fn set_tenant_auto_rotate_token_on_leak(
        &self,
        tenant_id: &str,
        enabled: bool,
    ) -> Result<(), AegisError> {
        db::set_tenant_auto_rotate_token_on_leak(&self.pool, tenant_id, enabled)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_tenant_risk_weights(
        &self,
        tenant_id: &str,
    ) -> Result<Option<RiskWeights>, AegisError> {
        let weights = db::get_risk_weights(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)?;
        Ok(Some(weights))
    }

    async fn get_tenant_risk_escalation_config(
        &self,
        tenant_id: &str,
    ) -> Result<Option<(i32, i32)>, AegisError> {
        let config = db::get_risk_escalation_config(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)?;
        Ok(Some((
            config.denial_threshold as i32,
            config.window_minutes as i32,
        )))
    }

    async fn put_tenant_risk_weights(
        &self,
        tenant_id: &str,
        weights: &RiskWeights,
    ) -> Result<(), AegisError> {
        db::upsert_risk_weights(&self.pool, tenant_id, weights)
            .await
            .map_err(AegisError::Database)
    }

    async fn put_tenant_risk_escalation_config(
        &self,
        tenant_id: &str,
        threshold: i32,
        window_minutes: i32,
    ) -> Result<(), AegisError> {
        let config = aegis_api::models::RiskEscalationConfig {
            denial_threshold: threshold as i64,
            window_minutes: window_minutes as i64,
        };
        db::upsert_risk_escalation_config(&self.pool, tenant_id, &config)
            .await
            .map_err(AegisError::Database)
    }

    // Webhooks
    async fn list_webhook_subscriptions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<WebhookSubscriptionRecord>, AegisError> {
        db::list_webhook_subscriptions(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_webhook_subscription(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<WebhookSubscriptionRecord>, AegisError> {
        db::get_webhook_subscription(&self.pool, tenant_id, id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_webhook_subscription(
        &self,
        tenant_id: &str,
        url: &str,
        secret_hash: Option<&str>,
        event_types: &str,
        delivery_secret: &str,
        min_severity: &str,
        format: &str,
    ) -> Result<WebhookSubscriptionRecord, AegisError> {
        db::insert_webhook_subscription(
            &self.pool,
            tenant_id,
            url,
            secret_hash,
            event_types,
            delivery_secret,
            min_severity,
            format,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn update_webhook_subscription(
        &self,
        record: &WebhookSubscriptionRecord,
    ) -> Result<(), AegisError> {
        db::update_webhook_subscription(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn delete_webhook_subscription(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<bool, AegisError> {
        db::delete_webhook_subscription(&self.pool, tenant_id, id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_active_webhook_subscriptions(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<WebhookSubscriptionRecord>, AegisError> {
        db::get_active_webhook_subscriptions(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn record_webhook_delivery_attempt(
        &self,
        tenant_id: &str,
        subscription_id: &str,
        success: bool,
    ) -> Result<(), AegisError> {
        db::record_webhook_delivery_result(&self.pool, tenant_id, subscription_id, success)
            .await
            .map_err(AegisError::Database)
    }

    // Audit Events
    async fn insert_audit_event(&self, record: &AuditEventRecord) -> Result<(), AegisError> {
        db::insert_audit_event(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_audit_events(
        &self,
        tenant_id: &str,
        decision_id: Option<&str>,
        cursor: Option<i64>,
        q: Option<&str>,
    ) -> Result<(Vec<AuditEventRecord>, Option<i64>), AegisError> {
        db::get_all_audit_events_cursor(&self.pool, tenant_id, decision_id, cursor, q)
            .await
            .map_err(AegisError::Database)
    }

    async fn archive_audit_events_older_than(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<i64, AegisError> {
        db::archive_audit_events_older_than(&self.pool, cutoff)
            .await
            .map(|count| count as i64)
            .map_err(AegisError::Database)
    }

    async fn insert_audit_events_batch(
        &self,
        records: &[AuditEventRecord],
    ) -> Result<(), AegisError> {
        db::insert_audit_events_batch(&self.pool, records)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_audit_events_in_range(
        &self,
        tenant_id: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<AuditEventRecord>, AegisError> {
        db::get_audit_events_in_range(&self.pool, tenant_id, from, to)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_audit_events_by_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<Vec<AuditEventRecord>, AegisError> {
        db::get_audit_events_by_run(&self.pool, tenant_id, run_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_audit_event_decision_id(
        &self,
        tenant_id: &str,
        event_id: &str,
    ) -> Result<Option<String>, AegisError> {
        db::get_audit_event_decision_id(&self.pool, tenant_id, event_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_audit_events_by_decision_ids(
        &self,
        tenant_id: &str,
        decision_ids: &[String],
    ) -> Result<Vec<AuditEventRecord>, AegisError> {
        db::list_audit_events_by_decision_ids(&self.pool, tenant_id, decision_ids)
            .await
            .map_err(AegisError::Database)
    }

    // API Keys
    async fn get_api_key_by_id(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<ApiKeyRecord>, AegisError> {
        db::get_api_key_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_api_keys(&self, tenant_id: &str) -> Result<Vec<ApiKeyRecord>, AegisError> {
        db::list_api_keys(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn insert_api_key(&self, record: &ApiKeyRecord) -> Result<(), AegisError> {
        db::insert_api_key(&self.pool, record)
            .await
            .map_err(AegisError::Database)
    }

    async fn revoke_api_key(&self, tenant_id: &str, id: &str) -> Result<bool, AegisError> {
        db::revoke_api_key(&self.pool, tenant_id, id)
            .await
            .map_err(AegisError::Database)
    }

    async fn is_active_api_key(&self, tenant_id: &str, key_hash: &str) -> Result<bool, AegisError> {
        db::is_active_api_key(&self.pool, tenant_id, key_hash)
            .await
            .map_err(AegisError::Database)
    }

    async fn create_api_key(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> Result<(String, String), AegisError> {
        db::create_api_key(&self.pool, tenant_id, name)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_soc_incidents_in_range(
        &self,
        tenant_id: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<SocIncidentRecord>, AegisError> {
        db::list_soc_incidents_in_range(&self.pool, tenant_id, from, to)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_tenant_stats(&self, tenant_id: &str) -> Result<TenantStats, AegisError> {
        db::get_tenant_stats(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_db_stats(&self) -> Result<DbStats, AegisError> {
        db::get_db_stats(&self.pool)
            .await
            .map_err(AegisError::Database)
    }

    async fn upsert_detection_rule(
        &self,
        tenant_id: &str,
        rule_key: &str,
        name: &str,
        severity: &str,
        condition: &str,
        summary_template: &str,
        enabled: bool,
    ) -> Result<DetectionRuleRecord, AegisError> {
        db::upsert_detection_rule(
            &self.pool,
            tenant_id,
            rule_key,
            name,
            severity,
            condition,
            summary_template,
            enabled,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn list_detection_rules(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<DetectionRuleRecord>, AegisError> {
        db::list_detection_rules(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn delete_detection_rule(&self, tenant_id: &str, id: &str) -> Result<bool, AegisError> {
        db::delete_detection_rule(&self.pool, tenant_id, id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_soc_alerts_by_source_event_ids(
        &self,
        tenant_id: &str,
        event_ids: &[String],
    ) -> Result<Vec<SocAlertRecord>, AegisError> {
        db::list_soc_alerts_by_source_event_ids(&self.pool, tenant_id, event_ids)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_decisions_by_run_id(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<Vec<DecisionRecord>, AegisError> {
        db::list_decisions_by_run_id(&self.pool, tenant_id, run_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_decisions_in_range(
        &self,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<DecisionRecord>, AegisError> {
        db::list_decisions_in_range(&self.pool, tenant_id, from, to)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_soc_alerts_since(
        &self,
        tenant_id: &str,
        since_rowid: i64,
        severity: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<Vec<(SocAlertRecord, i64)>, AegisError> {
        db::list_soc_alerts_since(&self.pool, tenant_id, since_rowid, severity, agent_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn list_soc_incidents_since(
        &self,
        tenant_id: &str,
        since_rowid: i64,
        status_filter: Option<&str>,
        severity: Option<&str>,
        agent_id: Option<&str>,
        kind: Option<&str>,
    ) -> Result<Vec<(SocIncidentRecord, i64)>, AegisError> {
        db::list_soc_incidents_since(
            &self.pool,
            tenant_id,
            since_rowid,
            status_filter,
            severity,
            agent_id,
            kind,
        )
        .await
        .map_err(AegisError::Database)
    }

    async fn list_decisions_since(
        &self,
        tenant_id: &str,
        since_rowid: i64,
    ) -> Result<Vec<(DecisionRecord, i64)>, AegisError> {
        db::list_decisions_since(&self.pool, tenant_id, since_rowid)
            .await
            .map_err(AegisError::Database)
    }

    async fn max_decision_rowid(&self, tenant_id: &str) -> Result<i64, AegisError> {
        db::max_decision_rowid(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn max_soc_alert_rowid(&self, tenant_id: &str) -> Result<i64, AegisError> {
        db::max_soc_alert_rowid(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    async fn max_soc_incident_rowid(&self, tenant_id: &str) -> Result<i64, AegisError> {
        db::max_soc_incident_rowid(&self.pool, tenant_id)
            .await
            .map_err(AegisError::Database)
    }

    // General & System
    async fn health_check(&self) -> Result<(), AegisError> {
        db::health_check(&self.pool)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_database_size_bytes(&self) -> Result<i64, AegisError> {
        db::get_database_size_bytes(&self.pool)
            .await
            .map_err(AegisError::Database)
    }

    async fn get_table_row_counts(&self) -> Result<Vec<TableRowCount>, AegisError> {
        db::get_table_row_counts(&self.pool)
            .await
            .map_err(AegisError::Database)
    }

    async fn backup_database_to(&self, dest_path: &str) -> Result<(), AegisError> {
        db::backup_database_to(&self.pool, dest_path)
            .await
            .map_err(AegisError::Database)
    }

    fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }
}
