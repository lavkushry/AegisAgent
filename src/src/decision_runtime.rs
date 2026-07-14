//! Gateway implementation of [`aegis_decision::DecisionRuntime`].
//!
//! Owns storage, Cedar, caches, SOC sinks, and GitHub side effects so
//! `aegis-decision` stays free of Axum/SQLx. Used by the authorize pipeline
//! in [`crate::authorize_service`].

use std::sync::Arc;

use crate::models::{AuthorizeRequest, AuthorizeResponse};
use crate::routes::AppState;
use aegis_decision::{
    authorize_response_from_decision_record, AdmissionEffect, ApprovalCreateParams, AuthorizeAgent,
    DecisionAuditWrite, DecisionRuntime, EnforcementStatus, McpToolMeta, PolicyDecisionView,
    RegisteredActionMeta,
};

/// Gateway [`DecisionRuntime`] over [`AppState`] (storage + auth-failure lockout).
pub struct GatewayDecisionRuntime {
    state: Arc<AppState>,
}

impl GatewayDecisionRuntime {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

fn agent_record_to_authorize_agent(a: crate::models::AgentRecord) -> AuthorizeAgent {
    AuthorizeAgent {
        id: a.id,
        tenant_id: a.tenant_id,
        agent_key: a.agent_key,
        status: a.status,
        risk_tier: a.risk_tier,
        force_approval: a.force_approval,
        signing_key: a.signing_key,
        allowed_environments: a.allowed_environments,
    }
}

#[async_trait::async_trait]
impl DecisionRuntime for GatewayDecisionRuntime {
    async fn get_agent_by_token(
        &self,
        tenant_id: &str,
        token: &str,
    ) -> Result<Option<AuthorizeAgent>, aegis_common::errors::AegisError> {
        let agent = self
            .state
            .storage
            .get_agent_by_token(tenant_id, token)
            .await?;
        Ok(agent.map(agent_record_to_authorize_agent))
    }

    async fn get_agent_by_mtls_cn(
        &self,
        tenant_id: &str,
        cn: &str,
    ) -> Result<Option<AuthorizeAgent>, aegis_common::errors::AegisError> {
        let agent = self
            .state
            .storage
            .get_agent_by_mtls_cn(tenant_id, cn)
            .await?;
        Ok(agent.map(agent_record_to_authorize_agent))
    }

    fn auth_failure_blocked(&self, client_addr: std::net::SocketAddr, tenant_id: &str) -> bool {
        let key = crate::routes::auth_failure_tracker_key(&client_addr, tenant_id);
        if self.state.auth_failure_tracker.is_blocked(&key) {
            self.state.metrics.inc_auth_failure_lockout();
            true
        } else {
            false
        }
    }

    fn record_auth_failure(&self, client_addr: std::net::SocketAddr, tenant_id: &str) {
        let key = crate::routes::auth_failure_tracker_key(&client_addr, tenant_id);
        self.state.auth_failure_tracker.record_failure(&key);
        self.state.metrics.inc_auth_failure_attempt();
    }

    async fn agent_tool_permitted(
        &self,
        tenant_id: &str,
        agent_id: &str,
        tool: &str,
    ) -> Result<bool, aegis_common::errors::AegisError> {
        self.state
            .storage
            .agent_tool_permission_status(tenant_id, agent_id, tool)
            .await
    }

    async fn get_decision_by_request_id(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<crate::models::DecisionRecord>, aegis_common::errors::AegisError> {
        self.state
            .storage
            .get_decision_by_request_id(tenant_id, agent_id, request_id)
            .await
    }

    async fn check_and_record_nonce(
        &self,
        tenant_id: &str,
        agent_id: &str,
        nonce: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, aegis_common::errors::AegisError> {
        // Mirror the 5-minute window used by timestamp validation and the
        // historical REPLAY_NONCE_WINDOW_SECS in authorize.rs.
        const REPLAY_NONCE_WINDOW_SECS: i64 = 300;
        if self.state.replay_store_db {
            let expires_at = now + chrono::Duration::seconds(REPLAY_NONCE_WINDOW_SECS);
            self.state
                .storage
                .check_and_insert_replay_nonce(tenant_id, agent_id, nonce, expires_at)
                .await
        } else {
            let nonce_key = crate::routes::ReplayNonceCache::cache_key(tenant_id, agent_id, nonce);
            Ok(self
                .state
                .replay_nonce_cache
                .check_and_insert(&nonce_key, now))
        }
    }

    async fn check_rate_limit(&self, tenant_id: &str) -> bool {
        self.state.rate_limiter.check_rate_limit(tenant_id).await
    }

    fn check_quota(&self, tenant_id: &str) -> bool {
        self.state.quota_manager.check_quota(tenant_id)
    }

    fn touch_heartbeat(&self, tenant_id: &str, agent_id: &str) {
        self.state.heartbeat_debouncer.touch(tenant_id, agent_id);
    }

    async fn write_decision_and_audit(
        &self,
        write: DecisionAuditWrite<'_>,
    ) -> Result<i32, aegis_common::errors::AegisError> {
        crate::routes::write_decision_and_audit(
            &self.state.storage,
            &self.state.deferred_write_tracker,
            &self.state.events,
            &self.state.metrics,
            &self.state.audit_batch,
            &self.state.risk_weight_cache,
            write.tenant_id,
            write.agent_id,
            write.request,
            write.decision_id,
            write.decision,
            write.risk_score,
            write.reason,
            write.matched_policies,
            write.audit_event_type,
            write.started_at,
            write.dry_run,
            write.action_hash,
            write.root_trust_level,
        )
        .await
    }

    async fn call_admission_webhook(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<AdmissionEffect, aegis_common::errors::AegisError> {
        match self.state.admission_webhook.as_ref() {
            None => Ok(AdmissionEffect::Disabled),
            Some(webhook) => match webhook.call(request).await {
                crate::admission::AdmissionOutcome::Pass => Ok(AdmissionEffect::Pass),
                crate::admission::AdmissionOutcome::Mutate(params) => {
                    Ok(AdmissionEffect::Mutate(params))
                }
                crate::admission::AdmissionOutcome::Reject(reason) => {
                    Ok(AdmissionEffect::Reject(reason))
                }
            },
        }
    }

    fn compute_action_hash(
        &self,
        tenant_id: &str,
        request_id: Option<&str>,
        tool_call: &crate::models::AuthorizeToolCall,
    ) -> String {
        crate::routes::hash_tool_call_cached(self.state.as_ref(), tenant_id, request_id, tool_call)
    }

    async fn enforcement_status(
        &self,
        tenant_id: &str,
        agent_id: &str,
        normalized_tool: &str,
    ) -> Result<EnforcementStatus, aegis_common::errors::AegisError> {
        let ban_now = chrono::Utc::now();
        let (agent_banned, tool_banned, agent_quarantined) = tokio::join!(
            self.state
                .storage
                .is_banned(tenant_id, "agent", agent_id, ban_now),
            self.state
                .storage
                .is_banned(tenant_id, "tool", normalized_tool, ban_now),
            self.state
                .storage
                .is_quarantined(tenant_id, "agent", agent_id),
        );
        match (agent_banned, tool_banned, agent_quarantined) {
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
            (Ok(true), _, _) => Ok(EnforcementStatus::AgentBanned),
            (_, Ok(true), _) => Ok(EnforcementStatus::ToolBanned),
            (_, _, Ok(true)) => Ok(EnforcementStatus::AgentQuarantined),
            (Ok(false), Ok(false), Ok(false)) => Ok(EnforcementStatus::Clear),
        }
    }

    async fn skill_action_meta(
        &self,
        tenant_id: &str,
        normalized_tool: &str,
        normalized_action: &str,
    ) -> Result<Option<RegisteredActionMeta>, aegis_common::errors::AegisError> {
        let skill_cache_key = crate::routes::SkillActionCache::cache_key(
            tenant_id,
            normalized_tool,
            normalized_action,
        );
        if let Some(meta) = self.state.skill_cache.get(&skill_cache_key).await {
            return Ok(Some(RegisteredActionMeta {
                risk: meta.0,
                mutates_state: meta.1,
                approval_required: meta.2,
                default_decision: meta.3,
            }));
        }
        match self
            .state
            .storage
            .get_skill_action(tenant_id, normalized_tool, normalized_action)
            .await?
        {
            Some(record) => {
                let meta = (
                    record.risk.clone(),
                    record.mutates_state,
                    record.approval_required,
                    record.default_decision.clone(),
                );
                self.state
                    .skill_cache
                    .insert(skill_cache_key, meta.clone())
                    .await;
                Ok(Some(RegisteredActionMeta {
                    risk: meta.0,
                    mutates_state: meta.1,
                    approval_required: meta.2,
                    default_decision: meta.3,
                }))
            }
            None => Ok(None),
        }
    }

    async fn agent_mcp_server_permitted(
        &self,
        tenant_id: &str,
        agent_id: &str,
        server_key: &str,
    ) -> Result<bool, aegis_common::errors::AegisError> {
        self.state
            .storage
            .agent_mcp_server_permission_status(tenant_id, agent_id, server_key)
            .await
    }

    async fn mcp_server_status(
        &self,
        tenant_id: &str,
        server_key: &str,
    ) -> Result<Option<String>, aegis_common::errors::AegisError> {
        let cache_key = crate::routes::McpServerCache::cache_key(tenant_id, server_key);
        if let Some(server) = self.state.mcp_server_cache.get(&cache_key) {
            return Ok(Some(server.status));
        }
        match self
            .state
            .storage
            .get_mcp_server_by_key(tenant_id, server_key)
            .await?
        {
            Some(server) => {
                let status = server.status.clone();
                self.state.mcp_server_cache.insert(cache_key, server);
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    async fn mcp_tool_meta(
        &self,
        tenant_id: &str,
        server_key: &str,
        normalized_action: &str,
    ) -> Result<Option<McpToolMeta>, aegis_common::errors::AegisError> {
        let cache_key =
            crate::routes::McpToolCache::cache_key(tenant_id, server_key, normalized_action);
        if let Some(tool) = self.state.mcp_tool_cache.get(&cache_key) {
            return Ok(Some(McpToolMeta {
                risk: tool.risk,
                approval_required: tool.approval_required,
                status: tool.status,
            }));
        }
        match self
            .state
            .storage
            .get_mcp_tool_by_key(tenant_id, server_key, normalized_action)
            .await?
        {
            Some(tool) => {
                let meta = McpToolMeta {
                    risk: tool.risk.clone(),
                    approval_required: tool.approval_required,
                    status: tool.status.clone(),
                };
                self.state.mcp_tool_cache.insert(cache_key, tool);
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    async fn ensure_policies_loaded(
        &self,
        tenant_id: &str,
    ) -> Result<(), aegis_common::errors::AegisError> {
        if self.state.policy_engine.has_tenant(tenant_id) {
            return Ok(());
        }
        let db_policies = self.state.storage.list_policies(tenant_id).await?;
        self.state
            .policy_engine
            .reload_tenant_policies(tenant_id, &db_policies)
            .map_err(|e| {
                aegis_common::errors::AegisError::Internal(format!(
                    "Failed to load tenant policies: {e}"
                ))
            })
    }

    async fn evaluate_cedar(
        &self,
        tenant_id: &str,
        request: &AuthorizeRequest,
        agent_risk_tier: &str,
        is_tool_known: bool,
        is_mtls: bool,
    ) -> Result<PolicyDecisionView, aegis_common::errors::AegisError> {
        let d = self
            .state
            .policy_engine
            .authorize(tenant_id, request, agent_risk_tier, is_tool_known, is_mtls)
            .map_err(|e| {
                aegis_common::errors::AegisError::Internal(format!("Policy engine failure: {e}"))
            })?;
        Ok(PolicyDecisionView {
            decision: d.decision,
            matched_policies: d.matched_policies,
            approver_group: d.approver_group,
            reason: d.reason,
            redacted_fields: d.redacted_fields,
        })
    }

    fn record_provenance_denial(&self) {
        self.state.metrics.inc_provenance_denial();
    }

    fn audit_stream_has_capacity(&self) -> bool {
        self.state.events.has_capacity()
    }

    fn set_audit_writer_healthy(&self, healthy: bool) {
        self.state
            .audit_writer_unhealthy
            .store(!healthy, std::sync::atomic::Ordering::Relaxed);
    }

    async fn emit_receipt_durable(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        decision_id: uuid::Uuid,
        decision: &str,
        action_hash: &str,
    ) -> Result<crate::models::ReceiptIdentity, aegis_common::errors::AegisError> {
        let receipt = crate::routes::emit_action_receipt_durable(
            &self.state.storage,
            tenant_id,
            agent_id,
            request,
            decision_id,
            decision,
            action_hash,
        )
        .await?;
        Ok(crate::models::ReceiptIdentity {
            receipt_id: receipt.id,
            receipt_hash: receipt.receipt_hash,
            prev_receipt_hash: receipt.prev_receipt_hash,
            canon_version: receipt.canon_version,
        })
    }

    async fn emit_receipt_best_effort(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        decision_id: uuid::Uuid,
        decision: &str,
        action_hash: &str,
    ) {
        crate::routes::emit_action_receipt(
            &self.state.receipt_batch,
            &self.state.storage,
            tenant_id,
            agent_id,
            request,
            decision_id,
            decision,
            action_hash,
        )
        .await;
    }

    async fn quarantine_agent(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<(), aegis_common::errors::AegisError> {
        self.state
            .storage
            .set_agent_status(tenant_id, agent_id, "quarantined")
            .await
            .map(|_| ())
    }

    fn emit_agent_quarantined(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        risk_score: i32,
        reason: &str,
        matched_policies: &[String],
    ) {
        use crate::events::AseEvent;
        self.state.events.emit(AseEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            occurred_at: chrono::Utc::now().to_rfc3339(),
            tenant_id: tenant_id.to_string(),
            kind: "agent_quarantined".to_string(),
            agent_id: agent_id.to_string(),
            decision: "quarantine".to_string(),
            tool: request.tool_call.tool.clone(),
            action: request.tool_call.action.clone(),
            resource: request.tool_call.resource.clone(),
            risk_score,
            reason: reason.to_string(),
            run_id: request.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: request.trace.as_ref().map(|t| t.trace_id.clone()),
            matched_policies: matched_policies.to_vec(),
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
            prompt_injection: None,
            rag_poisoning: None,
        });
    }

    async fn create_approval(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        params: ApprovalCreateParams,
    ) -> Result<crate::models::ApprovalResponseInfo, aegis_common::errors::AegisError> {
        use crate::models::{ApprovalRecord, ApprovalResponseInfo, AuditEventRecord};
        use crate::routes::sha256_hex;

        if let Some(ref url) = params.callback_url {
            if let Err(e) = aegis_common::ssrf::validate_callback_url(url) {
                return Err(aegis_common::errors::AegisError::BadRequest(format!(
                    "Invalid callback URL: {e}"
                )));
            }
        }

        let approval_id = uuid::Uuid::new_v4();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(params.approval_ttl_secs);
        let callback_secret_hash = params
            .callback_secret
            .as_ref()
            .map(|s| sha256_hex(s.as_bytes()));

        let approval_record = ApprovalRecord {
            id: approval_id.to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: params.decision_id.to_string(),
            status: "created".to_string(),
            approver_group: params.approver_group.clone(),
            approver_user_id: None,
            reason: None,
            original_skill_call: serde_json::to_string(&request.tool_call).unwrap_or_default(),
            original_call_hash: params.action_hash.clone(),
            edited_skill_call: None,
            effective_call_hash: None,
            expires_at: Some(expires_at),
            decided_at: None,
            callback_url: params.callback_url,
            callback_secret_hash,
            created_at: chrono::Utc::now(),
        };

        self.state
            .storage
            .insert_approval(&approval_record)
            .await
            .map_err(|_| {
                aegis_common::errors::AegisError::Internal(
                    "Failed to create approval request".into(),
                )
            })?;

        let audit_app_record = AuditEventRecord {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            event_type: "approval_created".to_string(),
            agent_id: Some(agent_id.to_string()),
            user_id: request.user.as_ref().map(|u| u.id.clone()),
            run_id: request.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: request.trace.as_ref().map(|t| t.trace_id.clone()),
            span_id: None,
            skill: Some(request.tool_call.tool.clone()),
            action: Some(request.tool_call.action.clone()),
            resource: request.tool_call.resource.clone(),
            event_json: serde_json::to_string(&approval_record).unwrap_or_default(),
            input_hash: Some(params.action_hash.clone()),
            output_hash: None,
            decision_id: Some(params.decision_id.to_string()),
            approval_id: Some(approval_id.to_string()),
            created_at: chrono::Utc::now(),
        };
        let _ = self
            .state
            .storage
            .insert_audit_event(&audit_app_record)
            .await;

        Ok(ApprovalResponseInfo {
            approval_id,
            status: "created".to_string(),
            approver_group: params.approver_group,
            expires_at,
            action_hash: params.action_hash,
        })
    }

    async fn maybe_escalate_risk_tier(
        &self,
        tenant_id: &str,
        agent_id: &str,
        current_tier: &str,
    ) -> Result<Option<(String, String)>, aegis_common::errors::AegisError> {
        self.state
            .storage
            .maybe_escalate_agent_risk_tier(tenant_id, agent_id, current_tier)
            .await
    }

    async fn emit_risk_escalated(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request: &AuthorizeRequest,
        decision: &str,
        decision_id: uuid::Uuid,
        risk_score: i32,
        old_tier: &str,
        new_tier: &str,
        matched_policies: &[String],
    ) {
        use crate::events::AseEvent;
        use crate::models::AuditEventRecord;

        let audit = AuditEventRecord {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            event_type: "agent_risk_escalated".to_string(),
            agent_id: Some(agent_id.to_string()),
            user_id: None,
            run_id: None,
            trace_id: None,
            span_id: None,
            skill: None,
            action: None,
            resource: None,
            event_json: serde_json::to_string(&serde_json::json!({
                "old_risk_tier": old_tier,
                "new_risk_tier": new_tier
            }))
            .unwrap_or_default(),
            input_hash: None,
            output_hash: None,
            decision_id: Some(decision_id.to_string()),
            approval_id: None,
            created_at: chrono::Utc::now(),
        };
        let _ = self.state.storage.insert_audit_event(&audit).await;

        self.state.events.emit(AseEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            occurred_at: chrono::Utc::now().to_rfc3339(),
            tenant_id: tenant_id.to_string(),
            kind: "agent_risk_escalated".to_string(),
            agent_id: agent_id.to_string(),
            decision: decision.to_string(),
            tool: request.tool_call.tool.clone(),
            action: request.tool_call.action.clone(),
            resource: request.tool_call.resource.clone(),
            risk_score,
            reason: format!("risk_tier escalated {old_tier} -> {new_tier} after repeated denials"),
            run_id: request.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: request.trace.as_ref().map(|t| t.trace_id.clone()),
            matched_policies: matched_policies.to_vec(),
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
            prompt_injection: None,
            rag_poisoning: None,
        });
    }

    fn notify_github_decision(
        &self,
        request: &AuthorizeRequest,
        decision: &str,
        reason: &str,
        risk_score: i32,
        decision_id: uuid::Uuid,
        matched_policies: &[String],
    ) {
        if decision == "deny" {
            if let Some(commenter) = self.state.github_pr_commenter.as_ref() {
                if request.tool_call.tool == "github" {
                    if let Some(resource) = request.tool_call.resource.as_deref() {
                        if let Some((repo, pr_number)) = crate::gh_comment::extract_pr_ref(resource)
                        {
                            let comment_body = crate::gh_comment::format_deny_comment(
                                reason,
                                matched_policies,
                                risk_score,
                                &decision_id.to_string(),
                                &request.tool_call.tool,
                                &request.tool_call.action,
                            );
                            crate::gh_comment::spawn_pr_comment(
                                std::sync::Arc::clone(commenter),
                                repo,
                                pr_number,
                                comment_body,
                            );
                        }
                    }
                }
            }
        }

        if let Some(checks_client) = self.state.github_checks_client.as_ref() {
            if request.tool_call.tool == "github" {
                if let Some(resource) = request.tool_call.resource.as_deref() {
                    if let Some((repo, pr_number)) = crate::gh_comment::extract_pr_ref(resource) {
                        crate::gh_checks::spawn_record_decision(
                            std::sync::Arc::clone(checks_client),
                            repo,
                            pr_number,
                            crate::gh_checks::DecisionInfo {
                                tool: request.tool_call.tool.clone(),
                                action: request.tool_call.action.clone(),
                                decision: decision.to_string(),
                                reason: reason.to_string(),
                                risk_score,
                            },
                        );
                    }
                }
            }
        }
    }

    async fn idempotent_replay(
        &self,
        record: crate::models::DecisionRecord,
    ) -> Result<AuthorizeResponse, aegis_common::errors::AegisError> {
        use crate::models::ApprovalResponseInfo;
        use uuid::Uuid;

        let tenant_id = record.tenant_id.clone();
        let mut approval = None;
        if record.decision == "require_approval" {
            if let Ok(Some(app)) = self
                .state
                .storage
                .get_approval_by_decision_id(&tenant_id, &record.id)
                .await
            {
                approval = Some(ApprovalResponseInfo {
                    approval_id: Uuid::parse_str(&app.id).unwrap_or_else(|_| Uuid::nil()),
                    status: app.status,
                    approver_group: app.approver_group,
                    expires_at: app.expires_at.unwrap_or(record.created_at),
                    action_hash: app.original_call_hash,
                });
            }
        }
        Ok(authorize_response_from_decision_record(record, approval))
    }
}
