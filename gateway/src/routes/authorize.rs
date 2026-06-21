#![allow(unused_imports)]
use crate::error::StatusError;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::{is_untrusted_provenance, SecurityMetrics};
use crate::models::*;
use crate::policy::PolicyEngine;
use crate::sign;

use super::*;

// Re-export helpers from sub-modules so existing call sites are unaffected.
pub(crate) use super::authorize_canon::*;
pub(crate) use super::authorize_decision::*;
pub(crate) use super::authorize_receipts::*;

/// Idempotent replay (#0072): rebuild the `AuthorizeResponse` for a previously
/// recorded decision instead of re-evaluating Cedar / writing duplicate audit
/// events, approvals, or receipts. For `require_approval` decisions, the
/// associated approval (if any) is looked up so the caller still sees its
/// current `status` (e.g. an approval created by the first call may since have
/// been approved/rejected).
pub(crate) async fn idempotent_replay_response(
    state: &Arc<AppState>,
    tenant_id: &str,
    record: DecisionRecord,
) -> axum::response::Response {
    let decision_id = match Uuid::parse_str(&record.id) {
        Ok(id) => id,
        Err(_) => Uuid::nil(),
    };
    let risk_score = record.risk_score.unwrap_or(0);
    let composite_risk_score = record.composite_risk_score.unwrap_or(risk_score);
    let matched_policies: Vec<String> = record
        .matched_policy_ids
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let mut approval = None;
    if record.decision == "require_approval" {
        if let Ok(Some(app)) =
            db::get_approval_by_decision_id(&state.pool, tenant_id, &record.id).await
        {
            approval = Some(ApprovalResponseInfo {
                approval_id: Uuid::parse_str(&app.id).unwrap_or(Uuid::nil()),
                status: app.status,
                approver_group: app.approver_group,
                expires_at: app.expires_at.unwrap_or(record.created_at),
                action_hash: app.original_call_hash,
            });
        }
    }

    (
        StatusCode::OK,
        Json(AuthorizeResponse {
            decision_id,
            decision: record.decision,
            risk_score,
            risk_level: risk_level_for_score(risk_score),
            composite_risk_score,
            reason: record.reason.unwrap_or_default(),
            matched_policies,
            approval,
            redacted_fields: vec![],
            root_trust_level: record
                .root_trust_level
                .unwrap_or_else(|| "unknown".to_string()),
            // Idempotency replays only ever read a previously-persisted real
            // decision — dry-run requests bypass idempotency entirely (#1281).
            dry_run: false,
        }),
    )
        .into_response()
}

// Authorize Action Handler
pub async fn authorize_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // #0081: wall-clock time for this evaluation, persisted on the decision row
    // for SOC/perf dashboards. Captured first so it covers agent resolution too.
    let started_at = std::time::Instant::now();

    // Parse JSON from raw bytes — keeping bytes for HMAC signature verification (#1403).
    let mut payload: AuthorizeRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return StatusError::bad_request("Invalid JSON body").into_response(),
    };

    // #1281: dry-run / simulation mode — evaluate but persist nothing. Read
    // once up front so every branch below can gate its side effects on it.
    let dry_run = payload.dry_run.unwrap_or(false);

    // #1293: trust propagation across agent chains — the effective (tighten-only)
    // trust level for this hop, combining any inherited `trace.root_trust_level`
    // with this hop's own declared `context.source_trust`. Computed once up front
    // so every response path (including early-return denies before Cedar
    // evaluation) reports the same value. `policy::PolicyEngine::authorize`
    // independently derives the identical value (pure function of the same
    // inputs) for Cedar's `context.trust_level`/`context.root_trust_level`.
    let root_trust_level = crate::trust_chain::propagate(
        payload
            .trace
            .as_ref()
            .and_then(|t| t.root_trust_level.as_deref()),
        &payload.context.source_trust,
    );

    // Resolve agent from Bearer agent_token
    let auth_header = match headers.get("Authorization").and_then(|h| h.to_str().ok()) {
        Some(h) if h.starts_with("Bearer ") => &h["Bearer ".len()..],
        _ => return StatusError::unauthorized("Missing agent token").into_response(),
    };

    let runtime_tenant_id = match get_runtime_tenant_from_headers(&headers) {
        Some(tid) => tid,
        None => {
            return StatusError::bad_request("Missing X-Aegis-Tenant-ID or X-Tenant-ID header")
                .into_response()
        }
    };
    let agent = match db::get_agent_by_token(&state.pool, &runtime_tenant_id, auth_header).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return StatusError::unauthorized("Invalid or quarantined agent token").into_response()
        }
        Err(e) => {
            error!("Database lookup error: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let tenant_id = agent.tenant_id.clone();
    let agent_id = agent.id.clone();

    // Request signing (#1403, opt-in): verify X-Aegis-Request-Signature header
    // when the agent has a signing key registered. Missing or incorrect
    // signature is a hard 401 — fail-closed so a forged body can't bypass
    // policy. Agents without a signing key are unaffected (backwards compat).
    if let Some(ref signing_key) = agent.signing_key {
        let sig_header = match headers
            .get("x-aegis-request-signature")
            .and_then(|h| h.to_str().ok())
        {
            Some(s) => s.to_string(),
            None => {
                warn!(
                    "Request signature missing for agent={} tenant={}",
                    agent_id, tenant_id
                );
                return StatusError::unauthorized("missing_request_signature").into_response();
            }
        };
        if !db::verify_request_signature(signing_key, &body, &sig_header) {
            warn!(
                "Request signature invalid for agent={} tenant={}",
                agent_id, tenant_id
            );
            return StatusError::unauthorized("invalid_request_signature").into_response();
        }
    }

    // Environment restriction (#1391): deny if the agent is not permitted
    // to operate in the environment the caller declares. NULL = unrestricted.
    if let Some(ref env_json) = agent.allowed_environments {
        if let Ok(allowed) = serde_json::from_str::<Vec<String>>(env_json) {
            if !allowed.is_empty() && !allowed.contains(&payload.agent.environment) {
                warn!(
                    "Environment restriction: agent={} tenant={} env={} not in allowed={:?}",
                    agent_id, tenant_id, payload.agent.environment, allowed
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "decision": "deny",
                        "reason": format!(
                            "agent not permitted in environment '{}'",
                            payload.agent.environment
                        )
                    })),
                )
                    .into_response();
            }
        }
    }

    // Agent-to-tool permission check (#1390, opt-in fail-closed): if the agent
    // has any explicit tool bindings, only those tools may be called. No
    // bindings = unrestricted (backwards-compatible with pre-#1390 agents).
    match db::agent_tool_permission_status(
        &state.pool,
        &tenant_id,
        &agent_id,
        &payload.tool_call.tool,
    )
    .await
    {
        Ok(Some(false)) => {
            warn!(
                "Tool permission denied: agent={} tenant={} tool={}",
                agent_id, tenant_id, payload.tool_call.tool
            );
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "decision": "deny",
                    "reason": format!(
                        "agent not permitted to call tool '{}'",
                        payload.tool_call.tool
                    )
                })),
            )
                .into_response();
        }
        Ok(_) => {} // None = unrestricted; Some(true) = permitted
        Err(e) => {
            error!("DB error checking tool permissions: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    }

    // Replay protection (#1306, opt-in): only runs when the caller supplies
    // `nonce`. Placed after agent-token authentication (fail-closed: an
    // attacker without a valid token can't probe nonce/timestamp state) but
    // before any policy evaluation or DB writes, so a replayed request is
    // rejected as cheaply as possible.
    if let Some(nonce) = payload.nonce.as_deref().filter(|n| !n.is_empty()) {
        let now = Utc::now();

        // Timestamp window check (AC #3): a `timestamp` more than 5 minutes
        // in the past is treated as a stale/replayed request. We also reject
        // timestamps more than 5 minutes in the *future*, since a clock-skew
        // window that large is itself suspicious and the same bound keeps
        // the check simple/symmetric; legitimate clients should always send
        // a current timestamp.
        if let Some(ts) = payload.timestamp {
            let age_secs = (now - ts).num_seconds().abs();
            if age_secs > 300 {
                warn!(
                    "Replay protection: rejecting request with stale timestamp for tenant={} agent={} (age={}s)",
                    tenant_id, agent_id, age_secs
                );
                return StatusError::conflict("Request timestamp outside the acceptable window")
                    .with_details(serde_json::json!({"reason": "replay_timestamp_expired"}))
                    .into_response();
            }
        }

        // Nonce dedup check (AC #2/#4/#6): scoped per (tenant, agent) so two
        // different agents (or tenants) reusing the same nonce string don't
        // collide. Backed by a capacity-bounded in-memory LRU rather than a
        // strict 5-minute store -- see `ReplayNonceCache` for why this, in
        // combination with the timestamp check above, approximates the
        // 5-minute replay window from the issue.
        let nonce_key = ReplayNonceCache::cache_key(&tenant_id, &agent_id, nonce);
        if state.replay_nonce_cache.check_and_insert(&nonce_key, now) {
            warn!(
                "Replay protection: rejecting duplicate nonce for tenant={} agent={}",
                tenant_id, agent_id
            );
            return StatusError::conflict("Duplicate nonce: possible replay attack")
                .with_details(serde_json::json!({"reason": "replay_nonce_reused"}))
                .into_response();
        }
    }

    // #1335: normalized forms of the tool/action identifiers, used for every
    // authorization lookup (MCP server/tool resolution, skill_action lookup)
    // so percent-encoding/Unicode-form/case variations can't dodge the
    // deny-by-default "unknown tool" checks. The action_hash / canonicalized
    // payload below always uses the original `payload.tool_call` values.
    let normalized_tool = normalize_tool_identifier(&payload.tool_call.tool);
    let normalized_action = normalize_tool_identifier(&payload.tool_call.action);

    // Idempotency (#0072): a repeat call with the same request_id returns the
    // original decision unchanged instead of re-evaluating Cedar and writing
    // duplicate audit events / approvals / receipts. Dry-run requests never
    // touch idempotency state (#1281) — skip both the lookup and any replay.
    if !dry_run {
        if let Some(request_id) = payload.request_id.as_deref().filter(|r| !r.is_empty()) {
            match db::get_decision_by_request_id(&state.pool, &tenant_id, &agent_id, request_id)
                .await
            {
                Ok(Some(record)) => {
                    return idempotent_replay_response(&state, &tenant_id, record).await;
                }
                Ok(None) => {}
                Err(e) => {
                    error!("Idempotency lookup failed: {:?}", e);
                    return StatusError::internal("Database error").into_response();
                }
            }
        }

        // Heartbeat (#0080): record this contact as the agent's most recent activity.
        // Best-effort — never fails the request. Skipped for dry-run (#1281).
        let _ = db::touch_agent_last_seen(&state.pool, &tenant_id, &agent_id).await;
    } // !dry_run (idempotency + heartbeat)

    // Check Rate Limiting (TASK-0012)
    if !state.rate_limiter.check_rate_limit(&tenant_id) {
        return StatusError::too_many_requests("Too many requests. Rate limit exceeded.")
            .into_response();
    }

    // Check Request Quota (TASK-0013)
    if !state.quota_manager.check_quota(&tenant_id) {
        return StatusError::too_many_requests("Request quota exceeded.").into_response();
    }

    // Check if the agent is frozen or revoked (TASK-0014)
    if agent.status == "frozen" || agent.status == "revoked" {
        let decision_id = Uuid::new_v4();
        let reason = format!(
            "Agent '{}' is {}; all tool calls are denied (fail-closed).",
            agent.agent_key, agent.status
        );
        let matched_policies = vec![format!("agent_{}", agent.status)];
        let risk_score = 100;
        let risk_level = "critical".to_string();

        let audit_event_type = if mcp_server_key_from_tool(&normalized_tool).is_some() {
            "mcp_tool_called"
        } else {
            "tool_call_intercepted"
        };

        let composite_risk_score = match write_decision_and_audit(
            &state.pool,
            &state.events,
            &state.metrics,
            &state.audit_batch,
            &tenant_id,
            &agent_id,
            &payload,
            decision_id,
            "deny",
            risk_score,
            &reason,
            &matched_policies,
            audit_event_type,
            started_at,
            dry_run,
        )
        .await
        {
            Ok(score) => score,
            Err(e) => {
                error!("Failed to write agent-frozen denial: {:?}", e);
                return StatusError::internal("Database error").into_response();
            }
        };

        return (
            StatusCode::OK,
            Json(AuthorizeResponse {
                decision_id,
                decision: "deny".to_string(),
                risk_score,
                risk_level,
                composite_risk_score,
                reason,
                matched_policies,
                approval: None,
                redacted_fields: vec![],
                root_trust_level: root_trust_level.clone(),
                dry_run,
            }),
        )
            .into_response();
    }

    // Admission webhook (#1143, API-004): optional pre-authorize hook letting
    // an external system pass, reject, or mutate this request before any
    // risk/MCP/Cedar evaluation below. Fully opt-in — `state.admission_webhook`
    // is `None` (no extra network call) unless AEGIS_ADMISSION_WEBHOOK_URL is set.
    if let Some(ref webhook) = state.admission_webhook {
        match webhook.call(&payload).await {
            crate::admission::AdmissionOutcome::Pass => {}
            crate::admission::AdmissionOutcome::Mutate(new_params) => {
                payload.tool_call.parameters = new_params;
            }
            crate::admission::AdmissionOutcome::Reject(reason) => {
                let decision_id = Uuid::new_v4();
                let matched_policies = vec!["admission_webhook_reject".to_string()];
                let risk_score = 100;
                let risk_level = "critical".to_string();

                let audit_event_type = if mcp_server_key_from_tool(&normalized_tool).is_some() {
                    "mcp_tool_called"
                } else {
                    "tool_call_intercepted"
                };

                let composite_risk_score = match write_decision_and_audit(
                    &state.pool,
                    &state.events,
                    &state.metrics,
                    &state.audit_batch,
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    "deny",
                    risk_score,
                    &reason,
                    &matched_policies,
                    audit_event_type,
                    started_at,
                    dry_run,
                )
                .await
                {
                    Ok(score) => score,
                    Err(e) => {
                        error!("Failed to write admission-webhook denial: {:?}", e);
                        return StatusError::internal("Database error").into_response();
                    }
                };

                return (
                    StatusCode::OK,
                    Json(AuthorizeResponse {
                        decision_id,
                        decision: "deny".to_string(),
                        risk_score,
                        risk_level,
                        composite_risk_score,
                        reason,
                        matched_policies,
                        approval: None,
                        redacted_fields: vec![],
                        root_trust_level: root_trust_level.clone(),
                        dry_run,
                    }),
                )
                    .into_response();
            }
        }
    }

    // Map risk levels based on DB registered action, falling back to policy engine defaults.
    let mut risk_score = 10;
    let mut risk_level = "low".to_string();
    let mut action_approval_required = false;
    let mut action_default_decision = "policy".to_string();

    // Read-through cache (#899): registered-action metadata is static between
    // registrations, so serve it from the LRU and fall back to the DB on a miss.
    let skill_cache_key =
        SkillActionCache::cache_key(&tenant_id, &normalized_tool, &normalized_action);
    let action_meta = match state.skill_cache.get(&skill_cache_key) {
        Some(meta) => Some(meta),
        None => match db::get_skill_action(
            &state.pool,
            &tenant_id,
            &normalized_tool,
            &normalized_action,
        )
        .await
        {
            Ok(Some(meta)) => {
                // Cache only positive hits; unknown actions keep missing to the DB.
                state
                    .skill_cache
                    .insert(skill_cache_key.clone(), meta.clone());
                Some(meta)
            }
            Ok(None) => None,
            Err(e) => {
                error!("Failed to look up registered action: {:?}", e);
                return StatusError::internal("Database error").into_response();
            }
        },
    };

    if let Some((risk, _, approval_required, default_decision)) = action_meta {
        risk_level = risk;
        risk_score = risk_score_for_level(&risk_level);
        action_approval_required = approval_required;
        action_default_decision = default_decision;
    }

    let mcp_server_key = mcp_server_key_from_tool(&normalized_tool).map(str::to_string);
    let is_mcp_call = mcp_server_key.is_some();

    if let Some(server_key) = mcp_server_key.as_deref() {
        // Fail-closed server-level gate (Phase 4 response enforcement). A
        // quarantined MCP server — whether quarantined by an operator or
        // auto-quarantined on tool-manifest drift — denies ALL of its tool calls
        // inline, regardless of any tool's prior approved status. Without this,
        // quarantine was recorded but never enforced on the authorize hot path.
        match db::get_mcp_server_by_key(&state.pool, &tenant_id, server_key).await {
            Ok(Some(server)) if server.status == "quarantined" => {
                let decision_id = Uuid::new_v4();
                let reason = format!(
                    "MCP server '{}' is quarantined; all tool calls are denied (fail-closed).",
                    server_key
                );
                let matched_policies = vec!["mcp_server_quarantined".to_string()];
                risk_level = "critical".to_string();
                risk_score = 100;

                let composite_risk_score = match write_decision_and_audit(
                    &state.pool,
                    &state.events,
                    &state.metrics,
                    &state.audit_batch,
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    "deny",
                    risk_score,
                    &reason,
                    &matched_policies,
                    "mcp_tool_called",
                    started_at,
                    dry_run,
                )
                .await
                {
                    Ok(score) => score,
                    Err(e) => {
                        error!("Failed to write quarantined-server denial: {:?}", e);
                        return StatusError::internal("Database error").into_response();
                    }
                };

                return (
                    StatusCode::OK,
                    Json(AuthorizeResponse {
                        decision_id,
                        decision: "deny".to_string(),
                        risk_score,
                        risk_level,
                        composite_risk_score,
                        reason,
                        matched_policies,
                        approval: None,
                        redacted_fields: vec![],
                        root_trust_level: root_trust_level.clone(),
                        dry_run,
                    }),
                )
                    .into_response();
            }
            Ok(_) => {}
            Err(e) => {
                error!("Failed to look up MCP server status: {:?}", e);
                return StatusError::internal("Database error").into_response();
            }
        }

        match db::get_mcp_tool_by_key(&state.pool, &tenant_id, server_key, &normalized_action).await
        {
            Ok(Some(tool)) => {
                risk_level = tool.risk.clone();
                risk_score = risk_score_for_level(&risk_level);
                action_approval_required = action_approval_required || tool.approval_required;

                if tool.status != "approved" {
                    let decision_id = Uuid::new_v4();
                    let reason = format!(
                        "MCP tool '{}' on server '{}' is not approved (status: {}).",
                        payload.tool_call.action, server_key, tool.status
                    );
                    let matched_policies = vec!["mcp_tool_status".to_string()];

                    let composite_risk_score = match write_decision_and_audit(
                        &state.pool,
                        &state.events,
                        &state.metrics,
                        &state.audit_batch,
                        &tenant_id,
                        &agent_id,
                        &payload,
                        decision_id,
                        "deny",
                        risk_score,
                        &reason,
                        &matched_policies,
                        "mcp_tool_called",
                        started_at,
                        dry_run,
                    )
                    .await
                    {
                        Ok(score) => score,
                        Err(e) => {
                            error!("Failed to write MCP denial decision: {:?}", e);
                            return StatusError::internal("Database error").into_response();
                        }
                    };

                    return (
                        StatusCode::OK,
                        Json(AuthorizeResponse {
                            decision_id,
                            decision: "deny".to_string(),
                            risk_score,
                            risk_level,
                            composite_risk_score,
                            reason,
                            matched_policies,
                            approval: None,
                            redacted_fields: vec![],
                            root_trust_level: root_trust_level.clone(),
                            dry_run,
                        }),
                    )
                        .into_response();
                }
            }
            Ok(None) => {
                let decision_id = Uuid::new_v4();
                let reason = format!(
                    "Unknown MCP tool '{}' for server '{}' is denied by default.",
                    payload.tool_call.action, server_key
                );
                let matched_policies = vec!["mcp_unknown_tool".to_string()];
                risk_level = "critical".to_string();
                risk_score = 100;

                let composite_risk_score = match write_decision_and_audit(
                    &state.pool,
                    &state.events,
                    &state.metrics,
                    &state.audit_batch,
                    &tenant_id,
                    &agent_id,
                    &payload,
                    decision_id,
                    "deny",
                    risk_score,
                    &reason,
                    &matched_policies,
                    "mcp_tool_called",
                    started_at,
                    dry_run,
                )
                .await
                {
                    Ok(score) => score,
                    Err(e) => {
                        error!("Failed to write unknown MCP denial decision: {:?}", e);
                        return StatusError::internal("Database error").into_response();
                    }
                };

                return (
                    StatusCode::OK,
                    Json(AuthorizeResponse {
                        decision_id,
                        decision: "deny".to_string(),
                        risk_score,
                        risk_level,
                        composite_risk_score,
                        reason,
                        matched_policies,
                        approval: None,
                        redacted_fields: vec![],
                        root_trust_level: root_trust_level.clone(),
                        dry_run,
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Failed to look up MCP tool: {:?}", e);
                return StatusError::internal("Database error").into_response();
            }
        }
    }

    // Ensure policies for the tenant are loaded into the engine.
    if !state.policy_engine.has_tenant(&tenant_id) {
        let _ = state
            .policy_engine
            .reload_tenant_policies(&state.pool, &tenant_id)
            .await;
    }

    // Call policy engine to evaluate Cedar rules. `agent.risk_tier` is the
    // trusted server-side value (#1296) — never the client-supplied request
    // body — so a self-reported tier can't dodge the stricter policies an
    // auto-escalated agent should be subject to.
    let policy_decision =
        match state
            .policy_engine
            .authorize(&tenant_id, &payload, &agent.risk_tier)
        {
            Ok(d) => d,
            Err(e) => {
                error!("Policy engine error: {:?}", e);
                return StatusError::internal(format!("Policy engine failure: {}", e))
                    .into_response();
            }
        };

    let decision_id = Uuid::new_v4();
    let mut decision_str = policy_decision.decision.clone();
    let mut reason = policy_decision.reason.clone();
    let mut matched_policies = policy_decision.matched_policies.clone();
    // #1385: redacted_fields is non-empty only when Cedar decision == "redact".
    // Routes-layer escalations (critical risk, force_approval, etc.) that override
    // the Cedar decision to require_approval/deny also clear this list so callers
    // never receive stale redact metadata when the decision changed.
    let mut redacted_fields = policy_decision.redacted_fields.clone();

    // Security metric: provenance_denials_total — count Cedar-level denials driven by
    // untrusted/malicious/unknown provenance on a mutating action (anti-confused-deputy).
    if decision_str == "deny"
        && payload.tool_call.mutates_state
        && is_untrusted_provenance(&payload.context.source_trust)
    {
        state.metrics.inc_provenance_denial();
    }

    if decision_str == "allow" {
        if action_default_decision == "deny" {
            decision_str = "deny".to_string();
            reason = "Registered action default decision is deny.".to_string();
            matched_policies.push("registered_action_default_deny".to_string());
        } else if action_default_decision == "require_approval" || action_approval_required {
            decision_str = "require_approval".to_string();
            reason = "Registered action requires approval.".to_string();
            matched_policies.push("registered_action_approval_required".to_string());
        }
    }

    // Enforce secure defaults (fail-closed)
    // If decision returns allow but action risk is critical, enforce require_approval by default if not set otherwise.
    if decision_str == "allow" && risk_level == "critical" {
        decision_str = "require_approval".to_string();
        reason = "Critical-risk action requires approval by default.".to_string();
        matched_policies.push("critical_risk_requires_approval".to_string());
    }

    // SOC Response Engine (#1184, Phase 4): a prior trust_escalation incident
    // set agents.force_approval for this agent. Downgrade allow -> require_approval
    // for every subsequent action until an operator clears it.
    if decision_str == "allow" && agent.force_approval {
        decision_str = "require_approval".to_string();
        reason = "Agent requires approval for all actions following a trust escalation incident."
            .to_string();
        matched_policies.push("soc_response_force_approval".to_string());
    }

    let audit_event_type = if is_mcp_call {
        "mcp_tool_called"
    } else {
        "tool_call_intercepted"
    };

    // Audit-writer health pre-flight (#1299): if the SOC event channel is
    // already full, audit observability for this decision is about to be
    // dropped. For high-risk/mutating actions that is itself the
    // "audit unavailable" condition — fail closed before attempting the DB
    // write at all. Dry-run never writes, so this gate doesn't apply (#1281).
    if !dry_run
        && is_high_risk_for_audit(&risk_level, payload.tool_call.mutates_state)
        && !state.events.has_capacity()
    {
        return (
            StatusCode::OK,
            Json(AuthorizeResponse {
                decision_id,
                decision: "deny".to_string(),
                risk_score,
                risk_level,
                composite_risk_score: risk_score,
                reason: "Audit writer unavailable (SOC event stream full): action denied (audit_writer_unavailable, fail-closed).".to_string(),
                matched_policies: vec!["audit_writer_unavailable".to_string()],
                approval: None,
                redacted_fields: vec![],
                root_trust_level: root_trust_level.clone(),
                dry_run,
            }),
        )
            .into_response();
    }

    let composite_risk_score = match write_decision_and_audit(
        &state.pool,
        &state.events,
        &state.metrics,
        &state.audit_batch,
        &tenant_id,
        &agent_id,
        &payload,
        decision_id,
        &decision_str,
        risk_score,
        &reason,
        &matched_policies,
        audit_event_type,
        started_at,
        dry_run,
    )
    .await
    {
        Ok(score) => {
            state
                .audit_writer_unhealthy
                .store(false, std::sync::atomic::Ordering::Relaxed);
            score
        }
        Err(e) => {
            error!(
                "Failed to write decision/audit record (audit writer unavailable): {:?}",
                e
            );
            state
                .audit_writer_unhealthy
                .store(true, std::sync::atomic::Ordering::Relaxed);

            if is_high_risk_for_audit(&risk_level, payload.tool_call.mutates_state) {
                return (
                    StatusCode::OK,
                    Json(AuthorizeResponse {
                        decision_id,
                        decision: "deny".to_string(),
                        risk_score,
                        risk_level,
                        composite_risk_score: risk_score,
                        reason: "Audit writer unavailable (database write failed): action denied (audit_writer_unavailable, fail-closed).".to_string(),
                        matched_policies: vec!["audit_writer_unavailable".to_string()],
                        approval: None,
                        redacted_fields: vec![],
                        root_trust_level: root_trust_level.clone(),
                        dry_run,
                    }),
                )
                    .into_response();
            }

            // Low-risk, non-mutating action: degrade gracefully — allow without a
            // persisted audit record, but log a warning so operators can see the gap.
            tracing::warn!(
                tool = %payload.tool_call.tool,
                action = %payload.tool_call.action,
                "Audit writer unavailable for low-risk action; allowing without persisted audit record"
            );
            return (
                StatusCode::OK,
                Json(AuthorizeResponse {
                    decision_id,
                    decision: decision_str,
                    risk_score,
                    risk_level,
                    composite_risk_score: risk_score,
                    reason,
                    matched_policies,
                    approval: None,
                    redacted_fields: vec![],
                    root_trust_level: root_trust_level.clone(),
                    dry_run,
                }),
            )
                .into_response();
        }
    };

    // Emit a verifiable, hash-chained receipt for this decision (non-fatal).
    // Skipped for dry-run (#1281) — no decision was persisted to chain from.
    if !dry_run {
        emit_action_receipt(
            &state.pool,
            &tenant_id,
            &agent_id,
            &payload,
            decision_id,
            &decision_str,
        )
        .await;
    }

    // Cedar @decision("quarantine"): quarantine the agent after the decision has
    // been recorded so the triggering action is auditable. Subsequent authorize
    // calls from this agent are auto-denied because `get_agent_by_token` filters
    // `status != 'quarantined'` (fail-closed). Best-effort: a DB error is logged
    // but never changes the returned decision. Dry-run must never actually
    // quarantine the agent for a hypothetical decision (#1281).
    if !dry_run && decision_str == "quarantine" {
        match db::set_agent_status(&state.pool, &tenant_id, &agent_id, "quarantined").await {
            Ok(_) => {
                info!(
                    agent_id = %agent_id,
                    tenant_id = %tenant_id,
                    "Agent quarantined by Cedar policy"
                );
                // Emit SOC event out-of-band (Law 3 — never blocks authorize path).
                state.events.emit(AseEvent {
                    event_id: Uuid::new_v4().to_string(),
                    occurred_at: Utc::now().to_rfc3339(),
                    tenant_id: tenant_id.clone(),
                    kind: "agent_quarantined".to_string(),
                    agent_id: agent_id.clone(),
                    decision: "quarantine".to_string(),
                    tool: payload.tool_call.tool.clone(),
                    action: payload.tool_call.action.clone(),
                    resource: payload.tool_call.resource.clone(),
                    risk_score,
                    reason: reason.clone(),
                    run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
                    trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
                    matched_policies: matched_policies.clone(),
                    redacted_fields: vec![],
                    schema_version: 1,
                });
            }
            Err(e) => {
                error!(
                    "Failed to quarantine agent {} after Cedar policy decision: {:?}",
                    agent_id, e
                );
            }
        }
    }

    let mut approval_info = None;

    // No real approval is created for a dry-run (#1281) — `decision ==
    // "require_approval"` already tells the caller what would happen, and a
    // fabricated approval_id would be unusable (nothing to approve).
    if !dry_run && decision_str == "require_approval" {
        let approval_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::seconds(state.approval_ttl_secs);
        let original_call_hash = hash_tool_call(&payload.tool_call);

        // #1187/TASK-0082-0083: optional approval-callback registration. The
        // plaintext secret is hashed immediately and never persisted
        // (redaction invariant) — only `callback_url` and
        // `sha256(secret)` are stored.
        let (callback_url, callback_secret_hash) = match &payload.callback {
            Some(cb) => (
                Some(cb.url.clone()),
                cb.secret.as_ref().map(|s| sha256_hex(s.as_bytes())),
            ),
            None => (None, None),
        };

        let approval_record = ApprovalRecord {
            id: approval_id.to_string(),
            tenant_id: tenant_id.clone(),
            decision_id: decision_id.to_string(),
            status: "created".to_string(),
            approver_group: policy_decision.approver_group.clone(),
            approver_user_id: None,
            reason: None,
            original_skill_call: serde_json::to_string(&payload.tool_call).unwrap_or_default(),
            original_call_hash: original_call_hash.clone(),
            edited_skill_call: None,
            expires_at: Some(expires_at),
            decided_at: None,
            callback_url,
            callback_secret_hash,
            created_at: Utc::now(),
        };

        if let Err(e) = db::insert_approval(&state.pool, &approval_record).await {
            error!("Failed to create approval request: {:?}", e);
            return StatusError::internal("Failed to create approval request").into_response();
        }

        // Write audit event for approval creation
        let audit_app_record = AuditEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            event_type: "approval_created".to_string(),
            agent_id: Some(agent_id.clone()),
            user_id: payload.user.as_ref().map(|u| u.id.clone()),
            run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
            trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
            span_id: None,
            skill: Some(payload.tool_call.tool.clone()),
            action: Some(payload.tool_call.action.clone()),
            resource: payload.tool_call.resource.clone(),
            event_json: serde_json::to_string(&approval_record).unwrap_or_default(),
            input_hash: Some(original_call_hash.clone()),
            output_hash: None,
            decision_id: Some(decision_id.to_string()),
            approval_id: Some(approval_id.to_string()),
            created_at: Utc::now(),
        };
        let _ = db::insert_audit_event(&state.pool, &audit_app_record).await;

        approval_info = Some(ApprovalResponseInfo {
            approval_id,
            status: "created".to_string(),
            approver_group: policy_decision.approver_group,
            expires_at,
            action_hash: original_call_hash,
        });
    }

    // #1296: repeated denials within a rolling window auto-escalate the
    // agent's risk_tier (low -> medium -> high). Unlike the advisory
    // composite_risk_score (Law 1), risk_tier is real authorization state
    // that future Cedar evaluations branch on — so this runs inline (fast,
    // local SQLite only) immediately after the deny decision is recorded,
    // guaranteeing the very next call from this agent sees the tightened
    // tier. Never escalate for a hypothetical dry-run decision (#1281).
    if !dry_run && decision_str == "deny" {
        match crate::risk_escalation::maybe_escalate_agent_risk_tier(
            &state.pool,
            &tenant_id,
            &agent_id,
            &agent.risk_tier,
        )
        .await
        {
            Ok(Some((old_tier, new_tier))) => {
                info!(
                    agent_id = %agent_id,
                    tenant_id = %tenant_id,
                    old_tier = %old_tier,
                    new_tier = %new_tier,
                    "Agent risk tier auto-escalated after repeated denials"
                );
                let audit = AuditEventRecord {
                    id: Uuid::new_v4().to_string(),
                    tenant_id: tenant_id.clone(),
                    event_type: "agent_risk_escalated".to_string(),
                    agent_id: Some(agent_id.clone()),
                    user_id: None,
                    run_id: None,
                    trace_id: None,
                    span_id: None,
                    skill: None,
                    action: None,
                    resource: None,
                    event_json: serde_json::to_string(
                        &json!({ "old_risk_tier": old_tier, "new_risk_tier": new_tier }),
                    )
                    .unwrap_or_default(),
                    input_hash: None,
                    output_hash: None,
                    decision_id: Some(decision_id.to_string()),
                    approval_id: None,
                    created_at: Utc::now(),
                };
                let _ = db::insert_audit_event(&state.pool, &audit).await;

                // Emit SOC event out-of-band (Law 3 — never blocks authorize path).
                state.events.emit(AseEvent {
                    event_id: Uuid::new_v4().to_string(),
                    occurred_at: Utc::now().to_rfc3339(),
                    tenant_id: tenant_id.clone(),
                    kind: "agent_risk_escalated".to_string(),
                    agent_id: agent_id.clone(),
                    decision: decision_str.clone(),
                    tool: payload.tool_call.tool.clone(),
                    action: payload.tool_call.action.clone(),
                    resource: payload.tool_call.resource.clone(),
                    risk_score,
                    reason: format!(
                        "risk_tier escalated {old_tier} -> {new_tier} after repeated denials"
                    ),
                    run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
                    trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
                    matched_policies: matched_policies.clone(),
                    redacted_fields: vec![],
                    schema_version: 1,
                });
            }
            Ok(None) => {}
            Err(e) => {
                error!(
                    "Failed to evaluate risk tier escalation for agent {}: {:?}",
                    agent_id, e
                );
            }
        }
    }

    // #1382: when a PR-related GitHub action is denied and the PR commenter is
    // configured, spawn a background task to post an explanatory comment. This
    // is fire-and-forget — it never blocks the authorize path or changes the
    // decision (Law 3: SOC/notification work is always out-of-band). Never
    // post a real PR comment for a hypothetical dry-run decision (#1281).
    if !dry_run && decision_str == "deny" {
        if let Some(commenter) = state.github_pr_commenter.as_ref() {
            if payload.tool_call.tool == "github" {
                if let Some(resource) = payload.tool_call.resource.as_deref() {
                    if let Some((repo, pr_number)) = crate::gh_comment::extract_pr_ref(resource) {
                        let comment_body = crate::gh_comment::format_deny_comment(
                            &reason,
                            &matched_policies,
                            risk_score,
                            &decision_id.to_string(),
                            &payload.tool_call.tool,
                            &payload.tool_call.action,
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

    // #1383: every decision on a PR-related GitHub action updates the Aegis
    // check run for that PR (create on first call, update thereafter). Like
    // the #1382 deny-comment block, this is fire-and-forget — it never
    // blocks the authorize path or changes the decision (Law 3). Never touch
    // a real PR check run for a hypothetical dry-run decision (#1281).
    if !dry_run {
        if let Some(checks_client) = state.github_checks_client.as_ref() {
            if payload.tool_call.tool == "github" {
                if let Some(resource) = payload.tool_call.resource.as_deref() {
                    if let Some((repo, pr_number)) = crate::gh_comment::extract_pr_ref(resource) {
                        crate::gh_checks::spawn_record_decision(
                            std::sync::Arc::clone(checks_client),
                            repo,
                            pr_number,
                            crate::gh_checks::DecisionInfo {
                                tool: payload.tool_call.tool.clone(),
                                action: payload.tool_call.action.clone(),
                                decision: decision_str.clone(),
                                reason: reason.clone(),
                                risk_score,
                            },
                        );
                    }
                }
            }
        }
    } // !dry_run (GitHub checks update)

    // #1385: if the decision changed away from "redact" via any route-layer override,
    // clear the field list so callers never receive stale redact metadata.
    if decision_str != "redact" {
        redacted_fields.clear();
    }

    (
        StatusCode::OK,
        Json(AuthorizeResponse {
            decision_id,
            decision: decision_str,
            risk_score,
            risk_level,
            composite_risk_score,
            reason,
            matched_policies,
            approval: approval_info,
            redacted_fields,
            root_trust_level,
            dry_run,
        }),
    )
        .into_response()
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::db;
    use crate::events;
    use crate::metrics::SecurityMetrics;
    use crate::models::*;
    use crate::policy::PolicyEngine;
    use crate::routes::test_helpers::*;
    use axum::body::{to_bytes, Bytes};
    use axum::extract::{FromRequestParts, Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;
    #[tokio::test]
    async fn test_jwt_tenant_extraction() {
        let _guard = get_env_lock().lock().await;
        use jsonwebtoken::{encode, EncodingKey, Header};

        let secret = "test_jwt_secret_1234567890";
        std::env::set_var("AEGIS_JWT_SECRET", secret);
        std::env::set_var("AEGIS_JWT_REQUIRED", "true");

        let claims = Claims {
            sub: "tenant_from_sub".to_string(),
            tenant_id: Some("tenant_from_claim".to_string()),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        // Test validate_jwt helper directly
        let extracted = validate_jwt(&token);
        assert_eq!(extracted, Some("tenant_from_claim".to_string()));

        // Test validate_jwt with sub fallback
        let claims_sub_only = Claims {
            sub: "tenant_from_sub_fallback".to_string(),
            tenant_id: None,
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };
        let token_sub = encode(
            &Header::default(),
            &claims_sub_only,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let extracted_sub = validate_jwt(&token_sub);
        assert_eq!(extracted_sub, Some("tenant_from_sub_fallback".to_string()));

        // Test validate_jwt with wrong secret
        let wrong_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("wrong_secret".as_bytes()),
        )
        .unwrap();
        assert_eq!(validate_jwt(&wrong_token), None);

        let (state, _, _) = setup_state("jwt_tenant_extraction").await;
        db::register_tenant(&state.pool, "tenant_from_claim", "JWT Tenant", "developer")
            .await
            .unwrap();

        // Test extractor
        let request = axum::http::Request::builder()
            .header("Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap();

        let (mut parts, _) = request.into_parts();
        let tenant = TenantId::from_request_parts(&mut parts, &state)
            .await
            .unwrap();
        assert_eq!(tenant.0, "tenant_from_claim");

        // Test extractor with invalid token when JWT is required
        let request_invalid = axum::http::Request::builder()
            .header("Authorization", "Bearer invalid_token")
            .body(())
            .unwrap();
        let (mut parts_invalid, _) = request_invalid.into_parts();
        let res = TenantId::from_request_parts(&mut parts_invalid, &state).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.code, StatusCode::UNAUTHORIZED.as_u16());

        // Clean up env vars
        std::env::remove_var("AEGIS_JWT_SECRET");
        std::env::remove_var("AEGIS_JWT_REQUIRED");
    }

    #[tokio::test]
    async fn test_hardened_tenant_and_jwt_rules() {
        let _guard = get_env_lock().lock().await;
        let (state, _, _) = setup_state("hardened_tenant").await;
        db::register_tenant(
            &state.pool,
            "tenant_custom_id",
            "Custom Tenant",
            "developer",
        )
        .await
        .unwrap();

        // 1. Ensure validate_jwt returns None when AEGIS_JWT_SECRET is unset
        std::env::remove_var("AEGIS_JWT_SECRET");
        assert_eq!(validate_jwt("any_token"), None);

        // 2. Ensure validate_jwt returns None when AEGIS_JWT_SECRET is "default_secret"
        std::env::set_var("AEGIS_JWT_SECRET", "default_secret");
        assert_eq!(validate_jwt("any_token"), None);

        // 3. Ensure TenantId extractor rejects token not starting with "tenant_" when JWT not required
        std::env::remove_var("AEGIS_JWT_SECRET"); // make sure validate_jwt fails
        std::env::remove_var("AEGIS_JWT_REQUIRED");
        let request_bad_heuristic = axum::http::Request::builder()
            .header("Authorization", "Bearer not_starting_with_tenant")
            .body(())
            .unwrap();
        let (mut parts_bad, _) = request_bad_heuristic.into_parts();
        let res_bad = TenantId::from_request_parts(&mut parts_bad, &state).await;
        assert!(res_bad.is_err());
        let err_bad = res_bad.unwrap_err();
        assert_eq!(err_bad.code, StatusCode::UNAUTHORIZED.as_u16());
        assert_eq!(
            err_bad.message,
            "Invalid token. Bearer token must start with 'tenant_' when JWT is not required"
        );

        // 4. Ensure TenantId extractor allows token starting with "tenant_" when JWT not required
        let request_good_heuristic = axum::http::Request::builder()
            .header("Authorization", "Bearer tenant_custom_id")
            .body(())
            .unwrap();
        let (mut parts_good, _) = request_good_heuristic.into_parts();
        let res_good = TenantId::from_request_parts(&mut parts_good, &state).await;
        assert!(res_good.is_ok());
        assert_eq!(res_good.unwrap().0, "tenant_custom_id");
    }

    #[tokio::test]
    async fn test_authorize_action_requires_tenant_header() {
        let (state, _tenant_id, agent_token) = setup_state("missing_header_test").await;
        let request = mcp_authorize_request("filesystem", "read_file");

        // Build headers with ONLY Authorization and NO X-Aegis-Tenant-ID / X-Tenant-ID
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", agent_token).parse().unwrap(),
        );

        let response = authorize_action(
            State(state),
            headers,
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            json["message"],
            "Missing X-Aegis-Tenant-ID or X-Tenant-ID header"
        );
    }

    /// #1164 (TEST-004, AC #1): when the DB pool is closed (simulating the
    /// database becoming unreachable), `authorize_action`'s agent-token
    /// lookup must surface as a graceful `500` (`StatusError::internal`)
    /// rather than panicking — fail-closed, and the caller gets a clean
    /// error instead of a crashed worker.
    #[tokio::test]
    async fn authorize_action_returns_500_when_db_pool_closed() {
        let (state, tenant_id, agent_token) = setup_state("authorize_pool_closed").await;
        let request = mcp_authorize_request("filesystem", "read_file");
        let headers = agent_headers(&agent_token, &tenant_id);

        state.pool.close().await;

        let response = authorize_action(
            State(state),
            headers,
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["message"], "Database error");
    }

    /// #1143 (API-004, AC #3): a `reject` admission-webhook decision denies
    /// the request before it ever reaches Cedar, carrying the webhook's own
    /// reason through to the response.
    #[tokio::test]
    async fn authorize_action_denied_by_admission_webhook_reject() {
        use axum::{routing::post, Json as AxumJson, Router};

        let app = Router::new().route(
            "/admit",
            post(|| async {
                AxumJson(serde_json::json!({
                    "decision": "reject",
                    "reason": "blocked by external policy"
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let (state, tenant_id, agent_token) = setup_state_with_admission_webhook(
            "admission_reject",
            &format!("http://{addr}/admit"),
            true,
        )
        .await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "deny");
        assert_eq!(response.reason, "blocked by external policy");
        assert_eq!(response.matched_policies, vec!["admission_webhook_reject"]);
    }

    /// #1143 (API-004, AC #3): a `mutate` admission-webhook decision replaces
    /// `tool_call.parameters` before Cedar evaluation — proven here by
    /// mutating `base_branch` from a non-"main" value to `"main"`, which
    /// flips the production-GitHub-merge policy from allow to
    /// `require_approval` (see `policies.cedar`). The bound approval's
    /// enriched `tool_call` (#1326) is asserted to carry the *mutated*
    /// parameters, not the agent's original ones.
    #[tokio::test]
    async fn authorize_action_mutated_by_admission_webhook_before_cedar() {
        use axum::{routing::post, Json as AxumJson, Router};

        let app = Router::new().route(
            "/admit",
            post(|| async {
                AxumJson(serde_json::json!({
                    "decision": "mutate",
                    "parameters": {"base_branch": "main"}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let (state, tenant_id, agent_token) = setup_state_with_admission_webhook(
            "admission_mutate",
            &format!("http://{addr}/admit"),
            true,
        )
        .await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/42".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "develop"});

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(
            response.decision, "require_approval",
            "mutated base_branch=main must trigger the production-merge approval policy"
        );

        let approval = response.approval.expect("approval info should be present");
        let status_response = get_approval(
            State(state),
            TenantId(tenant_id.to_string()),
            Path(approval.approval_id),
        )
        .await
        .into_response();
        let body = to_bytes(status_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            status_json["tool_call"]["parameters"]["base_branch"], "main",
            "the bound approval must carry the mutated parameters, not the agent's original ones"
        );
    }

    /// #1143 (API-004): a `pass` admission-webhook decision must leave the
    /// decision byte-for-byte identical to the same request with no
    /// admission webhook configured at all — proving `pass` is a true no-op.
    #[tokio::test]
    async fn authorize_action_unaffected_by_admission_webhook_pass() {
        use axum::{routing::post, Json as AxumJson, Router};

        let app = Router::new().route(
            "/admit",
            post(|| async { AxumJson(serde_json::json!({"decision": "pass"})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let (state_with_webhook, tenant_id, agent_token) = setup_state_with_admission_webhook(
            "admission_pass",
            &format!("http://{addr}/admit"),
            true,
        )
        .await;
        let response_with_webhook = call_authorize(
            state_with_webhook,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;

        let (state_baseline, tenant_id_baseline, agent_token_baseline) =
            setup_state("admission_pass_baseline").await;
        let response_baseline = call_authorize(
            state_baseline,
            &tenant_id_baseline,
            &agent_token_baseline,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;

        assert_eq!(response_with_webhook.decision, response_baseline.decision);
        assert_eq!(
            response_with_webhook.risk_score,
            response_baseline.risk_score
        );
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(2.0, 10.0);
        assert!(limiter.check_rate_limit("t1"));
        assert!(limiter.check_rate_limit("t1"));
        assert!(!limiter.check_rate_limit("t1")); // bucket exhausted

        // Different tenant has its own bucket
        assert!(limiter.check_rate_limit("t2"));

        // Refill check
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        assert!(limiter.check_rate_limit("t1")); // refilled at least 1 token
    }

    #[tokio::test]
    async fn test_quota_manager() {
        let quota = QuotaManager::new(2, 1); // limit 2 requests per 1 second
        assert!(quota.check_quota("t1"));
        assert!(quota.check_quota("t1"));
        assert!(!quota.check_quota("t1")); // quota exceeded

        // Different tenant has its own quota
        assert!(quota.check_quota("t2"));

        // Reset check after window passes
        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
        assert!(quota.check_quota("t1")); // window reset
    }

    #[tokio::test]
    async fn test_authorize_action_rate_limiting_and_quota() {
        let (state_raw, tenant_id, agent_token, events_rx) =
            setup_state_with_events("limit_test").await;
        // Drain events in background
        tokio::spawn(events::drain(
            events_rx,
            state_raw.pool.clone(),
            state_raw.metrics.clone(),
            None,
        ));

        // Create a custom app state with rate limit capacity = 1
        let policy_engine1 = PolicyEngine::init("policies.cedar").await.unwrap();
        let state = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            policy_engine: policy_engine1,
            events: state_raw.events.clone(),
            metrics: state_raw.metrics.clone(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1.0, 1.0),
            quota_manager: QuotaManager::new(0, 86400), // quota disabled
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: Vec::new(),
        });

        let request = mcp_authorize_request("mcp:server:tool", "read");
        let headers = agent_headers(&agent_token, &tenant_id);

        // First request is allowed through rate limiter
        let resp1 = authorize_action(
            State(state.clone()),
            headers.clone(),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        // Since we don't have "mcp:server:tool" registered/approved in the database for this test setup,
        // it will be denied (403 or similar) or return require_approval/etc., but NOT 429!
        assert_ne!(resp1.status(), StatusCode::TOO_MANY_REQUESTS);

        // Immediate second request is blocked by rate limiter (429)
        let resp2 = authorize_action(
            State(state.clone()),
            headers.clone(),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        // Now test quota
        let policy_engine2 = PolicyEngine::init("policies.cedar").await.unwrap();
        let state_quota = Arc::new(AppState {
            pool: state_raw.pool.clone(),
            policy_engine: policy_engine2,
            events: state_raw.events.clone(),
            metrics: state_raw.metrics.clone(),
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(100.0, 100.0), // high rate limit
            quota_manager: QuotaManager::new(1, 86400),   // quota limit 1
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: Vec::new(),
        });

        // First request is allowed through quota
        let resp3 = authorize_action(
            State(state_quota.clone()),
            headers.clone(),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        assert_ne!(resp3.status(), StatusCode::TOO_MANY_REQUESTS);

        // Second request is blocked by quota (429)
        let resp4 = authorize_action(
            State(state_quota.clone()),
            headers.clone(),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp4.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn authorize_emits_security_event() {
        // Phase 0 keystone: every authorize decision must feed the async SOC
        // stream, non-blocking. We keep the receiver and assert the decision
        // surfaces as exactly one AseEvent — the spine every later SOC phase
        // (detection, correlation, response, indexing) consumes.
        let (state, tenant_id, agent_token, mut events_rx) =
            setup_state_with_events("emits_security_event").await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let event = events_rx
            .try_recv()
            .expect("authorize must emit exactly one ASE event onto the SOC stream");
        assert_eq!(event.kind, "authorize_decision");
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.decision, response.decision);
        assert_eq!(event.tool, "filesystem");
        assert_eq!(event.action, "read_file");
        assert_eq!(event.run_id.as_deref(), Some("run_routes"));
    }

    #[test]
    fn canonical_action_matches_shared_corpus() {
        // Locks the gateway side of the cross-language canonicalization contract to
        // the same corpus the Python SDK test pins. If both sides match the corpus
        // string, their SHA-256 action hashes are equal by construction, which is
        // what makes the fail-closed approval guarantee sound across languages.
        let corpus_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/canonical_action_vectors.json"
        );
        let raw = std::fs::read_to_string(corpus_path)
            .expect("shared canonical corpus must exist at tests/canonical_action_vectors.json");
        let corpus: Value = serde_json::from_str(&raw).expect("corpus must be valid JSON");

        assert_eq!(
            corpus["canon_version"].as_str(),
            Some(CANON_VERSION),
            "corpus canon_version must match gateway CANON_VERSION"
        );

        let vectors = corpus["vectors"].as_array().expect("vectors array");
        for vector in vectors {
            let name = vector["name"].as_str().unwrap_or("<unnamed>");
            let tool_call: AuthorizeToolCall = serde_json::from_value(vector["tool_call"].clone())
                .unwrap_or_else(|e| panic!("vector {name}: tool_call must deserialize: {e}"));

            let produced = canonical_action_string(&tool_call);
            let expected = vector["canonical"].as_str().unwrap();
            assert_eq!(
                produced, expected,
                "vector {name}: canonical string mismatch"
            );

            // Hash must equal SHA-256 of the corpus canonical string.
            let expected_hash = sha256_hex(expected.as_bytes());
            assert_eq!(
                hash_tool_call(&tool_call),
                expected_hash,
                "vector {name}: action_hash mismatch"
            );
        }
    }

    /// TASK-0153 (#999): canonicalization must handle large (~10MB)
    /// `parameters` payloads — deterministically (same input -> same canonical
    /// string/hash, regardless of key insertion order) and without panicking
    /// (no recursion-depth blowup, no truncation of large arrays/strings).
    #[test]
    fn canonicalization_handles_large_10mb_payload() {
        // Build a large, deeply-nested-ish payload: 20,000 entries with
        // out-of-order keys, plus one large string field, totaling >10MB of
        // JSON when serialized.
        let big_string = "x".repeat(11 * 1024 * 1024); // 11MB string
        let mut items = Vec::with_capacity(20_000);
        for i in 0..20_000 {
            items.push(json!({
                "zeta": i,
                "alpha": format!("item-{i}"),
                "nested": { "b": 2, "a": 1 },
            }));
        }
        let parameters = json!({
            "large_blob": big_string,
            "items": items,
            "z_field": "last",
            "a_field": "first",
        });

        let tool_call = AuthorizeToolCall {
            tool: "filesystem".to_string(),
            action: "write_file".to_string(),
            resource: Some("/tmp/large.bin".to_string()),
            mutates_state: true,
            parameters,
        };

        let serialized_len = serde_json::to_string(&tool_call.parameters)
            .expect("parameters must serialize")
            .len();
        assert!(
            serialized_len > 10 * 1024 * 1024,
            "payload must exceed 10MB to exercise the large-payload path, got {serialized_len} bytes"
        );

        // Canonicalization must be deterministic across repeated runs.
        let canonical1 = canonical_action_string(&tool_call);
        let canonical2 = canonical_action_string(&tool_call.clone());
        assert_eq!(
            canonical1, canonical2,
            "canonicalization must be deterministic"
        );

        // Top-level object keys must be sorted by Unicode code point.
        let canonicalized = canonicalize_json(json!({
            "z_field": "last",
            "a_field": "first",
            "large_blob": "y",
        }));
        let keys: Vec<&str> = canonicalized
            .as_object()
            .expect("must remain an object")
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(keys, vec!["a_field", "large_blob", "z_field"]);

        // Hashing must succeed and be stable/repeatable for a large payload.
        let hash1 = hash_tool_call(&tool_call);
        let hash2 = hash_tool_call(&tool_call);
        assert_eq!(
            hash1, hash2,
            "action_hash must be stable across repeated calls"
        );
        assert_eq!(hash1.len(), 64, "SHA-256 hex digest must be 64 chars");
    }

    /// TASK-0155 (#1002): canonicalization must handle an empty `parameters`
    /// object (`{}`) and a `None` resource — the most common shape for
    /// read-only/no-argument tool calls — producing a stable, well-formed
    /// canonical string and hash.
    #[test]
    fn canonicalization_handles_empty_parameters() {
        let tool_call = AuthorizeToolCall {
            tool: "filesystem".to_string(),
            action: "list_dir".to_string(),
            resource: None,
            mutates_state: false,
            parameters: json!({}),
        };

        let canonical = canonical_action_string(&tool_call);
        assert_eq!(
            canonical,
            r#"{"action":"list_dir","mutates_state":false,"parameters":{},"resource":null,"tool":"filesystem"}"#
        );

        // Deterministic hash, well-formed 64-char SHA-256 hex digest.
        let hash = hash_tool_call(&tool_call);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, sha256_hex(canonical.as_bytes()));
        assert_eq!(hash, hash_tool_call(&tool_call));
    }

    #[test]
    fn approval_is_expired_detects_past_window() {
        assert!(approval_is_expired(&make_test_approval(
            Some(Utc::now() - Duration::minutes(1)),
            "created"
        )));
        assert!(!approval_is_expired(&make_test_approval(
            Some(Utc::now() + Duration::minutes(30)),
            "created"
        )));
        // No expiry set -> never expired.
        assert!(!approval_is_expired(&make_test_approval(None, "created")));
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let (state, tenant_id, agent_token) = setup_state("consume_single_use").await;

        // Create an approval (merge to main) and approve it.
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/9".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        // First consume succeeds.
        let first = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        // Second consume is rejected — single-use.
        let second = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    /// #1004: two concurrent `consume_approval` calls for the same approved,
    /// single-use approval race against each other. The atomic
    /// `UPDATE ... WHERE consumed_at IS NULL` in `db::consume_approval`
    /// guarantees exactly one wins (200 OK) and the other is rejected (409
    /// CONFLICT) — never both succeeding (which would allow replay).
    #[tokio::test]
    async fn consume_approval_concurrent_race_only_one_succeeds() {
        let (state, tenant_id, agent_token) = setup_state("consume_concurrent_race").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/77".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let (a, b) = tokio::join!(
            consume_approval(
                State(state.clone()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                None,
            ),
            consume_approval(
                State(state.clone()),
                TenantId(tenant_id.clone()),
                Path(approval_id),
                None,
            ),
        );

        let statuses = [a.into_response().status(), b.into_response().status()];
        let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
        let conflict_count = statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count();
        assert_eq!(ok_count, 1, "exactly one consume must succeed");
        assert_eq!(conflict_count, 1, "exactly one consume must be rejected");
    }

    /// #1168: 50 concurrent `consume_approval` calls for the same approved,
    /// single-use approval. Exactly one must win (200 OK) and the other 49
    /// must be rejected (409 CONFLICT) — and the receipt chain produced by
    /// the resulting tamper-attempt receipts must remain a single unbroken
    /// chain (no fork), per `crate::jobs::verify_tenant_receipt_chain`.
    #[tokio::test]
    async fn consume_approval_50_concurrent_only_one_succeeds_and_chain_unforked() {
        let (state, tenant_id, agent_token) = setup_state("consume_concurrent_50").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/78".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let mut handles = Vec::new();
        for _ in 0..50 {
            let state = state.clone();
            let tenant_id = tenant_id.clone();
            handles.push(tokio::spawn(async move {
                consume_approval(State(state), TenantId(tenant_id), Path(approval_id), None)
                    .await
                    .into_response()
                    .status()
            }));
        }

        let mut ok_count = 0;
        let mut conflict_count = 0;
        for handle in handles {
            match handle.await.unwrap() {
                StatusCode::OK => ok_count += 1,
                StatusCode::CONFLICT => conflict_count += 1,
                other => panic!("unexpected status: {other}"),
            }
        }
        assert_eq!(ok_count, 1, "exactly one of 50 consumes must succeed");
        assert_eq!(conflict_count, 49, "the other 49 consumes must be rejected");

        crate::jobs::verify_tenant_receipt_chain(&state.pool, &tenant_id)
            .await
            .expect("receipt chain must remain a single unbroken chain (no fork)");
    }

    /// #0133: consume_approval rejects an APPROVED approval whose expiry window
    /// has already passed (fail-closed) — a single-use approval that ages out
    /// before execution must not be consumable.
    #[tokio::test]
    async fn consume_approval_rejects_expired_approval() {
        let (state, tenant_id, agent_token) = setup_state("consume_rejects_expired").await;
        let (approval_id, _hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "23").await;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        // Age the approval out after it was granted.
        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        let consume = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(consume.status(), StatusCode::CONFLICT);
    }

    /// #0134: consume_approval returns the original action_hash that the
    /// approval was bound to, so the SDK can re-verify it before executing.
    #[tokio::test]
    async fn consume_approval_returns_bound_action_hash() {
        let (state, tenant_id, agent_token) = setup_state("consume_returns_hash").await;
        let (approval_id, bound_hash) =
            create_pending_approval(&state, &tenant_id, &agent_token, "24").await;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let consume = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(consume.status(), StatusCode::OK);

        let body = to_bytes(consume.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["action_hash"].as_str(), Some(bound_hash.as_str()));
    }

    #[tokio::test]
    async fn authorize_emits_verifiable_receipt() {
        let (state, tenant_id, agent_token) = setup_state("emit_receipt").await;

        // Any decision (here a read-only allow) must emit a receipt.
        let mut request = mcp_authorize_request("github", "read_issue");
        request.tool_call.mutates_state = false;
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let (receipt_id,): (String,) = sqlx::query_as(
            "SELECT id FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .expect("a receipt should have been emitted for the decision");

        // The /verify endpoint recomputes the hash and confirms integrity.
        let response = verify_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(receipt_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verified"].as_bool(), Some(true));
        assert_eq!(json["receipt_id"].as_str(), Some(receipt_id.as_str()));
        // Hermetic default: no signing key configured → unsigned.
        // signature_verified is null and `signed` is false; hash `verified` unchanged.
        assert_eq!(json["signed"].as_bool(), Some(false));
        assert!(json["signature_verified"].is_null());
    }

    /// #930: every emitted receipt records the canonicalization scheme that hashed
    /// it, and that field is additive — the byte-parity-locked `receipt_hash` is the
    /// same whether or not `canon_version` is set.
    #[tokio::test]
    async fn emitted_receipt_records_canon_version() {
        let (state, tenant_id, agent_token) = setup_state("receipt_canon_version").await;

        let request = mcp_authorize_request("github", "read_issue");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        let (receipt_id,): (String,) = sqlx::query_as(
            "SELECT id FROM action_receipts WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .unwrap();

        let receipt = db::get_action_receipt_by_id(&state.pool, &tenant_id, &receipt_id)
            .await
            .unwrap()
            .expect("emitted receipt should be retrievable");

        // The scheme is recorded and self-describing.
        assert_eq!(receipt.canon_version, CANON_VERSION);
        assert_eq!(receipt.canon_version, "aegis-jcs-1");

        // Byte-parity guard: canon_version is additive metadata, NOT folded into the
        // hash — recomputing the hash over the same body still matches.
        assert_eq!(receipt.receipt_hash, compute_receipt_hash(&receipt));
    }

    #[tokio::test]
    async fn expired_approval_is_reported_and_cannot_be_approved() {
        let (state, tenant_id, agent_token) = setup_state("approve_expired").await;

        // Create a real require_approval via authorize (merge to main).
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/7".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        // Force the approval past its window.
        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        // get_approval reports EXPIRED for the still-pending, past-window approval.
        let get_resp = get_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
        )
        .await
        .into_response();
        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "EXPIRED");

        // approve_approval refuses to grant an expired approval.
        let approve_resp = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve_resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn authorize_denies_unknown_mcp_tools_by_default() {
        let (state, tenant_id, agent_token) = setup_state("unknown_mcp_tool").await;
        let response = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "unknown_tool"),
        )
        .await;

        assert_eq!(response.decision, "deny");
        assert_eq!(response.risk_level, "critical");
        assert_eq!(response.risk_score, 100);
        assert!(response
            .matched_policies
            .contains(&"mcp_unknown_tool".to_string()));
    }

    /// #1335: percent-encoding, Unicode form, or letter-case variation in the
    /// `tool`/`action` identifiers must not let an unregistered MCP server or
    /// tool slip past the deny-by-default "unknown MCP tool" check (e.g. by
    /// disguising the `mcp:` prefix so `mcp_server_key_from_tool` misses it
    /// and the MCP-specific checks are skipped entirely). After normalization
    /// (URL-decode, NFC, lowercase) each of these must resolve the same as
    /// `mcp:github-mcp` / `unknown_tool` and be denied as an unknown MCP tool.
    #[tokio::test]
    async fn authorize_denies_unknown_mcp_tool_with_encoded_or_cased_identifier() {
        let (state, tenant_id, agent_token) = setup_state("unknown_mcp_tool_encoded").await;

        for (tool, action) in [
            ("MCP:github-mcp", "unknown_tool"),
            ("mcp%3Agithub-mcp", "unknown_tool"),
            ("mcp:github-mcp", "Unknown_Tool"),
            ("mcp:github-mcp", "unknown%5Ftool"),
        ] {
            let response = call_authorize(
                state.clone(),
                &tenant_id,
                &agent_token,
                mcp_authorize_request(tool, action),
            )
            .await;

            assert_eq!(response.decision, "deny", "tool={tool}, action={action}");
            assert_eq!(response.risk_level, "critical");
            assert_eq!(response.risk_score, 100);
            assert!(
                response
                    .matched_policies
                    .contains(&"mcp_unknown_tool".to_string()),
                "tool={tool}, action={action}"
            );
        }
    }

    /// #1335: an approved MCP tool must still be recognized when the caller's
    /// `tool`/`action` identifiers use a different letter case or
    /// percent-encoding than the registered `tool_key` — normalization makes
    /// `Create_Issue` and `create%5Fissue` resolve to the registered
    /// `create_issue` tool.
    #[tokio::test]
    async fn authorize_allows_approved_mcp_tool_with_encoded_or_cased_identifier() {
        let (state, tenant_id, agent_token) = setup_state("approved_mcp_tool_encoded").await;
        let server_id = db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();
        let tool = McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create issue".to_string(),
            description: None,
            input_schema: None,
            risk: "medium".to_string(),
            mutates_state: false,
            approval_required: false,
        };
        db::upsert_mcp_tool(&state.pool, &tenant_id, &server_id, &tool)
            .await
            .unwrap();
        db::set_mcp_tool_status(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "create_issue",
            "approved",
        )
        .await
        .unwrap();

        for (tool, action) in [
            ("MCP:GitHub-Mcp", "Create_Issue"),
            ("mcp:github-mcp", "create%5Fissue"),
        ] {
            let response = call_authorize(
                state.clone(),
                &tenant_id,
                &agent_token,
                mcp_authorize_request(tool, action),
            )
            .await;

            assert_eq!(response.decision, "allow", "tool={tool}, action={action}");
            assert_eq!(response.risk_level, "medium");
            assert_eq!(response.risk_score, 40);
        }
    }

    /// #0117: a non-mutating ("read-only") action on a registered low-risk
    /// skill is allowed, with the registered risk level/score reflected back.
    #[tokio::test]
    async fn authorize_allows_read_only_action() {
        let (state, tenant_id, agent_token) = setup_state("authorize_read_only").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "allow");
        assert_eq!(response.risk_level, "low");
        assert_eq!(response.risk_score, 10);
    }

    /// TASK-0089 (#935): every `/v1/authorize` decision writes a historical
    /// risk-score sample to `agent_risk_scores`, linked to the decision that
    /// produced it.
    #[tokio::test]
    async fn authorize_records_agent_risk_score() {
        let (state, tenant_id, agent_token) = setup_state("authorize_risk_score").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "allow");
        assert_eq!(response.risk_score, 10);

        let decisions = db::list_decisions(&state.pool, &tenant_id, 10, 0, None, None)
            .await
            .unwrap();
        let decision = decisions.first().expect("expected a decision row");

        let scores = db::list_agent_risk_scores(&state.pool, &tenant_id, &decision.agent_id)
            .await
            .unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].decision_id, decision.id);
        assert_eq!(scores[0].score, 10);
    }

    /// #1293: end-to-end 3-hop trust propagation through `/v1/authorize`.
    /// A (untrusted_external, no root) -> B (declares trusted_internal_signed
    /// but inherits A's effective trust as root_trust_level) -> C (declares
    /// semi_trusted_customer but inherits B's effective trust). Every hop's
    /// `root_trust_level` in the response must reflect the most restrictive
    /// trust seen anywhere in the chain so far, and a mutating action at any
    /// hop must be denied because untrusted_external never loosens.
    #[tokio::test]
    async fn authorize_three_hop_chain_propagates_most_restrictive_trust() {
        let (state, tenant_id, agent_token) = setup_state("trust_chain_three_hop").await;

        // Hop A: chain's first call, no inherited root.
        let mut request_a = mcp_authorize_request("filesystem", "read_file");
        request_a.tool_call.mutates_state = true;
        request_a.context.source_trust = "untrusted_external".to_string();
        request_a.trace = Some(AuthorizeTraceContext {
            run_id: "run_a".to_string(),
            trace_id: "trace_a".to_string(),
            parent_run_id: None,
            root_trust_level: None,
        });
        let response_a = call_authorize(state.clone(), &tenant_id, &agent_token, request_a).await;
        assert_eq!(response_a.decision, "deny");
        assert_eq!(response_a.root_trust_level, "untrusted_external");

        // Hop B: inherits A's effective root_trust_level, declares its own
        // trigger as trusted_internal_signed — must still be tightened to
        // untrusted_external and denied.
        let mut request_b = mcp_authorize_request("filesystem", "read_file");
        request_b.tool_call.mutates_state = true;
        request_b.context.source_trust = "trusted_internal_signed".to_string();
        request_b.trace = Some(AuthorizeTraceContext {
            run_id: "run_b".to_string(),
            trace_id: "trace_b".to_string(),
            parent_run_id: Some("run_a".to_string()),
            root_trust_level: Some(response_a.root_trust_level.clone()),
        });
        let response_b = call_authorize(state.clone(), &tenant_id, &agent_token, request_b).await;
        assert_eq!(response_b.decision, "deny");
        assert_eq!(response_b.root_trust_level, "untrusted_external");

        // Hop C: inherits B's effective root_trust_level, declares
        // semi_trusted_customer — untrusted_external is still more
        // restrictive, so C inherits it too.
        let mut request_c = mcp_authorize_request("filesystem", "read_file");
        request_c.tool_call.mutates_state = true;
        request_c.context.source_trust = "semi_trusted_customer".to_string();
        request_c.trace = Some(AuthorizeTraceContext {
            run_id: "run_c".to_string(),
            trace_id: "trace_c".to_string(),
            parent_run_id: Some("run_b".to_string()),
            root_trust_level: Some(response_b.root_trust_level.clone()),
        });
        let response_c = call_authorize(state.clone(), &tenant_id, &agent_token, request_c).await;
        assert_eq!(response_c.decision, "deny");
        assert_eq!(response_c.root_trust_level, "untrusted_external");
    }

    /// #1293: the decision record persisted to the `decisions` table captures
    /// `root_trust_level` and `parent_run_id` for audit/evidence-graph
    /// reconstruction of multi-agent chains.
    #[tokio::test]
    async fn authorize_persists_root_trust_level_and_parent_run_id_on_decision() {
        let (state, tenant_id, agent_token) = setup_state("trust_chain_persisted").await;

        let mut request = mcp_authorize_request("filesystem", "read_file");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();
        request.trace = Some(AuthorizeTraceContext {
            run_id: "run_child".to_string(),
            trace_id: "trace_child".to_string(),
            parent_run_id: Some("run_parent".to_string()),
            root_trust_level: Some("semi_trusted_customer".to_string()),
        });

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.root_trust_level, "semi_trusted_customer");

        let record =
            db::get_decision_by_id(&state.pool, &tenant_id, &response.decision_id.to_string())
                .await
                .unwrap()
                .expect("decision row must exist");
        assert_eq!(
            record.root_trust_level,
            Some("semi_trusted_customer".to_string())
        );
        assert_eq!(record.parent_run_id, Some("run_parent".to_string()));
    }

    /// #0118: a mutating action whose triggering content has untrusted
    /// provenance is denied outright (anti-confused-deputy gate), regardless
    /// of the registered action's risk level.
    #[tokio::test]
    async fn authorize_denies_untrusted_mutation() {
        let (state, tenant_id, agent_token) = setup_state("authorize_untrusted_mutation").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "untrusted_external".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "deny");
    }

    /// #0122: every authorize decision writes a corresponding row to
    /// `audit_events`, retrievable via `GET /v1/audit/events` with the
    /// matching tool/action/decision details embedded in `event_json`.
    #[tokio::test]
    async fn authorize_emits_audit_event() {
        let (state, tenant_id, agent_token) = setup_state("authorize_audit_event").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "allow");

        let audit_response = get_audit_events(
            State(state),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(audit_response.status(), StatusCode::OK);

        let body = to_bytes(audit_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        let event = events
            .iter()
            .find(|e| e.event_type == "tool_call_intercepted")
            .expect("authorize must write a tool_call_intercepted audit event");
        assert_eq!(event.tenant_id, tenant_id);
        assert_eq!(event.skill.as_deref(), Some("deployer"));
        assert_eq!(event.action.as_deref(), Some("ship"));

        let event_json: serde_json::Value = serde_json::from_str(&event.event_json).unwrap();
        assert_eq!(event_json["decision"], "allow");
        assert_eq!(event_json["id"], response.decision_id.to_string());

        // #1301: the audit event must carry the decision_id of the decision
        // that produced it, matching `AuthorizeResponse.decision_id`.
        assert_eq!(
            event.decision_id.as_deref(),
            Some(response.decision_id.to_string().as_str()),
            "tool_call_intercepted audit event must link back to its decision_id"
        );
    }

    /// #1301: a `require_approval` decision must write an `approval_created`
    /// audit event carrying both the `decision_id` and `approval_id` of the
    /// resulting decision/approval pair.
    #[tokio::test]
    async fn approval_created_audit_event_has_decision_and_approval_ids() {
        let (state, tenant_id, agent_token) = setup_state("authorize_approval_audit_linkage").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "semi_trusted_customer".to_string();

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");
        let approval = response.approval.expect("approval info should be present");

        let audit_response = get_audit_events(
            State(state),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(audit_response.status(), StatusCode::OK);

        let body = to_bytes(audit_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        let event = events
            .iter()
            .find(|e| e.event_type == "approval_created")
            .expect("require_approval decision must write an approval_created audit event");

        assert_eq!(
            event.decision_id.as_deref(),
            Some(response.decision_id.to_string().as_str()),
            "approval_created audit event must link back to its decision_id"
        );
        assert_eq!(
            event.approval_id.as_deref(),
            Some(approval.approval_id.to_string().as_str()),
            "approval_created audit event must link back to its approval_id"
        );
    }

    /// #1301: `GET /v1/audit/events?decision_id=<id>` filters audit events to
    /// only those linked to the given decision, while remaining
    /// tenant-scoped.
    #[tokio::test]
    async fn get_audit_events_filters_by_decision_id() {
        let (state, tenant_id, agent_token) = setup_state("authorize_audit_decision_filter").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request1 = mcp_authorize_request("deployer", "ship");
        request1.tool_call.mutates_state = false;
        request1.context.source_trust = "trusted_internal_signed".to_string();
        let response1 = call_authorize(state.clone(), &tenant_id, &agent_token, request1).await;
        assert_eq!(response1.decision, "allow");

        let mut request2 = mcp_authorize_request("deployer", "ship");
        request2.tool_call.mutates_state = false;
        request2.context.source_trust = "trusted_internal_signed".to_string();
        let response2 = call_authorize(state.clone(), &tenant_id, &agent_token, request2).await;
        assert_eq!(response2.decision, "allow");

        assert_ne!(response1.decision_id, response2.decision_id);

        let filter = format!("decision_id={}", response1.decision_id);
        let audit_response = get_audit_events(
            State(state),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some(filter)),
        )
        .await
        .into_response();
        assert_eq!(audit_response.status(), StatusCode::OK);

        let body = to_bytes(audit_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        assert!(!events.is_empty(), "expected at least one matching event");
        for event in &events {
            assert_eq!(event.tenant_id, tenant_id);
            assert_eq!(
                event.decision_id.as_deref(),
                Some(response1.decision_id.to_string().as_str()),
                "filtered results must only contain events for the requested decision_id"
            );
        }
    }

    /// TASK-0160 (#1006): `GET /v1/audit/events` must (a) only return the
    /// caller's own tenant's events, never another tenant's, and (b) cap the
    /// result at 100 rows (`db::get_all_audit_events`'s `LIMIT 100`) even
    /// when more rows exist.
    #[tokio::test]
    async fn get_audit_events_respects_tenant_scope_and_limit() {
        let (state, tenant_id, _agent_token) = setup_state("audit_events_scope_limit").await;
        let other_tenant = "audit_events_scope_limit_other";
        db::register_tenant(&state.pool, other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();

        fn audit_event(tenant_id: &str, n: usize) -> AuditEventRecord {
            AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                event_type: "test_event".to_string(),
                agent_id: None,
                user_id: None,
                run_id: None,
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: Some(format!("item-{n}")),
                event_json: "{}".to_string(),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at: Utc::now(),
            }
        }

        // 105 events for the caller's tenant (exceeds the 100-row cap) and one
        // for another tenant (must never be returned).
        for n in 0..105 {
            db::insert_audit_event(&state.pool, &audit_event(&tenant_id, n))
                .await
                .unwrap();
        }
        db::insert_audit_event(&state.pool, &audit_event(other_tenant, 0))
            .await
            .unwrap();

        let response = get_audit_events(
            State(state),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        assert_eq!(events.len(), 100, "result must be capped at 100 rows");
        assert!(
            events.iter().all(|e| e.tenant_id == tenant_id),
            "must never return another tenant's audit events"
        );
    }

    /// TASK-0159 (#1005): `GET /v1/runs/:id/timeline` must return events for the
    /// requested run in chronological (`created_at ASC`) order, regardless of
    /// the order they were inserted, and must exclude events from other runs.
    #[tokio::test]
    async fn get_timeline_returns_events_in_chronological_order() {
        let (state, tenant_id, _agent_token) = setup_state("timeline_chronological_order").await;
        let run_id = "run-timeline-1";

        fn timeline_event(
            tenant_id: &str,
            run_id: &str,
            label: &str,
            age_secs: i64,
        ) -> AuditEventRecord {
            AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                event_type: "test_event".to_string(),
                agent_id: None,
                user_id: None,
                run_id: Some(run_id.to_string()),
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: Some(label.to_string()),
                event_json: "{}".to_string(),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at: Utc::now() - Duration::seconds(age_secs),
            }
        }

        // insert_audit_event relies on the column's DEFAULT CURRENT_TIMESTAMP and
        // does not bind `created_at`, so set the desired timestamps directly
        // after each insert to exercise ORDER BY created_at ASC deterministically.
        async fn insert_with_created_at(pool: &sqlx::SqlitePool, event: &AuditEventRecord) {
            db::insert_audit_event(pool, event).await.unwrap();
            sqlx::query("UPDATE audit_events SET created_at = ? WHERE id = ?")
                .bind(event.created_at)
                .bind(&event.id)
                .execute(pool)
                .await
                .unwrap();
        }

        // Insert out of chronological order: "third" (oldest) last.
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, run_id, "first", 10),
        )
        .await;
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, run_id, "second", 5),
        )
        .await;
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, run_id, "third", 20),
        )
        .await;
        // A different run — must not appear in this run's timeline.
        insert_with_created_at(
            &state.pool,
            &timeline_event(&tenant_id, "run-timeline-other", "other-run", 1),
        )
        .await;

        let response = get_timeline(
            State(state),
            TenantId(tenant_id.clone()),
            Path(run_id.to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();

        let resources: Vec<&str> = events
            .iter()
            .map(|e| e.resource.as_deref().unwrap())
            .collect();
        assert_eq!(
            resources,
            vec!["third", "first", "second"],
            "events must be ordered oldest-first by created_at, regardless of insertion order"
        );
    }

    /// #1303: `insert_audit_event` must persist the caller-supplied
    /// `created_at` (microsecond precision) instead of relying on the
    /// column's `DEFAULT CURRENT_TIMESTAMP` (second precision, assigned at
    /// insert time). Without this, two events emitted within the same wall-
    /// clock second always sort by insertion order rather than their actual
    /// logical timestamps, which can put them out of chronological order on
    /// the timeline.
    #[tokio::test]
    async fn insert_audit_event_persists_microsecond_created_at_for_chronological_ordering() {
        let (state, tenant_id, _agent_token) =
            setup_state("audit_event_microsecond_created_at").await;
        let run_id = "run-microsecond-order";

        fn event_at(
            tenant_id: &str,
            run_id: &str,
            label: &str,
            created_at: DateTime<Utc>,
        ) -> AuditEventRecord {
            AuditEventRecord {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                event_type: "test_event".to_string(),
                agent_id: None,
                user_id: None,
                run_id: Some(run_id.to_string()),
                trace_id: None,
                span_id: None,
                skill: None,
                action: None,
                resource: Some(label.to_string()),
                event_json: "{}".to_string(),
                input_hash: None,
                output_hash: None,
                decision_id: None,
                approval_id: None,
                created_at,
            }
        }

        // All three events fall within the same wall-clock second but have
        // distinct logical timestamps (microseconds apart). Insert them in a
        // scrambled order — "first" (earliest) is inserted last.
        let base = Utc::now();
        db::insert_audit_event(
            &state.pool,
            &event_at(
                &tenant_id,
                run_id,
                "second",
                base + Duration::microseconds(2000),
            ),
        )
        .await
        .unwrap();
        db::insert_audit_event(
            &state.pool,
            &event_at(
                &tenant_id,
                run_id,
                "third",
                base + Duration::microseconds(3000),
            ),
        )
        .await
        .unwrap();
        db::insert_audit_event(
            &state.pool,
            &event_at(
                &tenant_id,
                run_id,
                "first",
                base + Duration::microseconds(1000),
            ),
        )
        .await
        .unwrap();

        let response = get_timeline(
            State(state),
            TenantId(tenant_id.clone()),
            Path(run_id.to_string()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let events: Vec<AuditEventRecord> = serde_json::from_slice(&body).unwrap();
        let resources: Vec<&str> = events
            .iter()
            .map(|e| e.resource.as_deref().unwrap())
            .collect();
        assert_eq!(
            resources,
            vec!["first", "second", "third"],
            "events within the same wall-clock second must still sort by their \
             microsecond-precision created_at, not by insertion order"
        );
    }

    /// #0119: a mutating action whose triggering content has
    /// `semi_trusted_customer` provenance is paused for human review rather
    /// than auto-allowed or auto-denied.
    #[tokio::test]
    async fn authorize_requires_approval_for_customer_context() {
        let (state, tenant_id, agent_token) = setup_state("authorize_customer_context").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "semi_trusted_customer".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "require_approval");
        let approval = response.approval.expect("approval info should be present");
        assert_eq!(
            approval.approver_group.as_deref(),
            Some("security-reviewers")
        );
    }

    /// #1187/TASK-0082-0083: an optional `callback` on the authorize request
    /// is persisted on the resulting approval as `callback_url` (verbatim)
    /// and `callback_secret_hash` (sha256 of the secret) — the plaintext
    /// secret itself is never stored.
    #[tokio::test]
    async fn authorize_persists_approval_callback_with_hashed_secret() {
        let (state, tenant_id, agent_token) = setup_state("authorize_callback").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "semi_trusted_customer".to_string();
        request.callback = Some(crate::models::ApprovalCallback {
            url: "https://example.com/aegis-callback".to_string(),
            secret: Some("topsecret".to_string()),
        });

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");
        let approval_id = response.approval.expect("approval info").approval_id;

        let stored = db::get_approval_by_id(&state.pool, &tenant_id, &approval_id.to_string())
            .await
            .unwrap()
            .expect("approval row should exist");

        assert_eq!(
            stored.callback_url.as_deref(),
            Some("https://example.com/aegis-callback")
        );
        assert_eq!(
            stored.callback_secret_hash.as_deref(),
            Some(sha256_hex(b"topsecret").as_str())
        );
        // The plaintext secret never appears in the persisted row.
        assert_ne!(stored.callback_secret_hash.as_deref(), Some("topsecret"));
    }

    /// #0120: the `risk_score` returned by `/v1/authorize` matches the
    /// registered action's risk level via `risk_score_for_level`.
    #[tokio::test]
    async fn authorize_returns_correct_risk_score() {
        let (state, tenant_id, agent_token) = setup_state("authorize_risk_score").await;
        register_ship_action(&state, &tenant_id, "high").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.risk_level, "high");
        assert_eq!(response.risk_score, 75);
    }

    /// #0121: a critical-risk registered action that would otherwise be
    /// allowed has `matched_policies` annotated with the secure-default that
    /// downgraded it to `require_approval`.
    #[tokio::test]
    async fn authorize_returns_correct_matched_policies() {
        let (state, tenant_id, agent_token) = setup_state("authorize_matched_policies").await;
        register_ship_action(&state, &tenant_id, "critical").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = false;
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(response.decision, "require_approval");
        assert_eq!(response.risk_score, 95);
        assert!(response
            .matched_policies
            .contains(&"critical_risk_requires_approval".to_string()));
    }

    #[tokio::test]
    async fn approval_flow_binds_original_action_hash() {
        let (state, tenant_id, agent_token) = setup_state("approval_action_hash").await;
        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/42".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");

        let approval = response.approval.expect("approval info should be present");
        assert_eq!(approval.action_hash.len(), 64);
        assert!(approval
            .action_hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit()));

        let status_response = get_approval(
            State(state),
            TenantId("tenant_routes".to_string()),
            Path(approval.approval_id),
        )
        .await
        .into_response();
        assert_eq!(status_response.status(), StatusCode::OK);

        let body = to_bytes(status_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status_json["action_hash"], approval.action_hash);
    }

    /// #0072: a repeat `/v1/authorize` call with the same `request_id` returns the
    /// original decision unchanged — for an `allow` decision, and for a
    /// `require_approval` decision it must NOT create a second approval (the
    /// replayed response carries the same `approval_id`/`action_hash`).
    #[tokio::test]
    async fn authorize_is_idempotent_for_repeated_request_id() {
        let (state, tenant_id, agent_token) = setup_state("idempotency_key").await;

        // Allow path
        let mut allow_request = mcp_authorize_request("filesystem", "read_file");
        allow_request.request_id = Some("req-allow-1".to_string());
        let first = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            allow_request.clone(),
        )
        .await;
        assert_eq!(first.decision, "allow");

        let second = call_authorize(state.clone(), &tenant_id, &agent_token, allow_request).await;
        assert_eq!(second.decision, first.decision);
        assert_eq!(second.decision_id, first.decision_id);
        assert_eq!(second.risk_score, first.risk_score);

        // Only one decision row was written for this request_id.
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let stored =
            db::get_decision_by_request_id(&state.pool, &tenant_id, &agent.id, "req-allow-1")
                .await
                .unwrap()
                .unwrap();
        assert_eq!(stored.id, first.decision_id.to_string());

        // require_approval path: the second call must replay the SAME approval.
        let mut approval_request = mcp_authorize_request("github", "merge_pull_request");
        approval_request.tool_call.mutates_state = true;
        approval_request.tool_call.resource = Some("repo/example/pull/7".to_string());
        approval_request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        approval_request.request_id = Some("req-approval-1".to_string());

        let first = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            approval_request.clone(),
        )
        .await;
        assert_eq!(first.decision, "require_approval");
        let first_approval = first.approval.expect("approval info expected");

        let second =
            call_authorize(state.clone(), &tenant_id, &agent_token, approval_request).await;
        assert_eq!(second.decision, "require_approval");
        let second_approval = second.approval.expect("approval info expected on replay");
        assert_eq!(second_approval.approval_id, first_approval.approval_id);
        assert_eq!(second_approval.action_hash, first_approval.action_hash);

        // Still exactly one pending approval for this decision.
        let approvals = db::list_pending_approvals(&state.pool, &tenant_id, 50, 0)
            .await
            .unwrap();
        assert_eq!(
            approvals
                .iter()
                .filter(|a| a.id == first_approval.approval_id.to_string())
                .count(),
            1
        );
    }

    /// #0081: every decision row records the wall-clock time spent evaluating
    /// the `/v1/authorize` request, for SOC/perf dashboards.
    #[tokio::test]
    async fn authorize_records_decision_latency_ms() {
        let (state, tenant_id, agent_token) = setup_state("decision_latency_ms").await;

        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;
        assert_eq!(response.decision, "allow");

        let stored =
            db::get_decision_by_id(&state.pool, &tenant_id, &response.decision_id.to_string())
                .await
                .unwrap()
                .unwrap();
        let latency = stored.latency_ms.expect("latency_ms should be populated");
        assert!(latency >= 0);
    }

    /// #1306: a normal `/v1/authorize` call with no `nonce`/`timestamp`
    /// fields is completely unaffected by replay protection (opt-in,
    /// backwards compatible, AC #5).
    #[tokio::test]
    async fn authorize_without_nonce_is_unaffected() {
        let (state, tenant_id, agent_token) = setup_state("replay_no_nonce").await;

        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;
        assert_eq!(response.decision, "allow");

        // A second, identical call (still no nonce) is also unaffected --
        // no 409 from replay protection.
        let response2 = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;
        assert_eq!(response2.decision, "allow");
    }

    /// #1306 AC #2/#6: a replayed request with a duplicate nonce is
    /// rejected with 409 Conflict + `reason: replay_nonce_reused`.
    #[tokio::test]
    async fn authorize_rejects_duplicate_nonce() {
        let (state, tenant_id, agent_token) = setup_state("replay_dup_nonce").await;

        let mut request = mcp_authorize_request("filesystem", "read_file");
        request.nonce = Some("nonce-abc-123".to_string());
        request.timestamp = Some(Utc::now());

        // First request succeeds normally.
        let first = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        // Replaying the exact same nonce is rejected.
        let second = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::CONFLICT);

        let body = to_bytes(second.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["details"]["reason"], "replay_nonce_reused");
    }

    /// #1306 AC #3: a request with `nonce` set and a `timestamp` more than 5
    /// minutes old is rejected with 409 Conflict + `reason:
    /// replay_timestamp_expired`, before the nonce dedup check even runs.
    #[tokio::test]
    async fn authorize_rejects_stale_timestamp() {
        let (state, tenant_id, agent_token) = setup_state("replay_stale_timestamp").await;

        let mut request = mcp_authorize_request("filesystem", "read_file");
        request.nonce = Some("nonce-stale-1".to_string());
        request.timestamp = Some(Utc::now() - Duration::seconds(301));

        let response = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&request).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["details"]["reason"], "replay_timestamp_expired");
    }

    /// #1306: two requests with different nonces (both fresh timestamps) are
    /// both allowed through -- proves the dedup cache isn't over-broad.
    #[tokio::test]
    async fn authorize_allows_different_nonces() {
        let (state, tenant_id, agent_token) = setup_state("replay_diff_nonces").await;

        let mut request1 = mcp_authorize_request("filesystem", "read_file");
        request1.nonce = Some("nonce-one".to_string());
        request1.timestamp = Some(Utc::now());

        let mut request2 = mcp_authorize_request("filesystem", "read_file");
        request2.nonce = Some("nonce-two".to_string());
        request2.timestamp = Some(Utc::now());

        let first = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&request1).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let second = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&request2).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(second.status(), StatusCode::OK);
    }

    // --- request signing (#1403) ---

    /// Compute `X-Aegis-Request-Signature: sha256=<hex>` for test helpers.
    fn signing_header(key: &str, body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Register an agent with a signing key and return (state, tenant_id, agent_token).
    async fn setup_state_with_signing_key(
        test_name: &str,
        signing_key: &str,
    ) -> (Arc<AppState>, String, String) {
        let (state, tenant_id, agent_token) = setup_state(test_name).await;

        // Update the agent's signing_key column directly.
        sqlx::query("UPDATE agents SET signing_key = ? WHERE tenant_id = ?")
            .bind(signing_key)
            .bind(&tenant_id)
            .execute(&state.pool)
            .await
            .unwrap();

        (state, tenant_id, agent_token)
    }

    #[tokio::test]
    async fn request_signing_valid_signature_allows() {
        let key = "test-signing-key-valid";
        let (state, tenant_id, agent_token) =
            setup_state_with_signing_key("signing_valid", key).await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let body = Bytes::from(serde_json::to_vec(&request).unwrap());
        let sig = signing_header(key, &body);

        let mut headers = agent_headers(&agent_token, &tenant_id);
        headers.insert("x-aegis-request-signature", sig.parse().unwrap());

        let resp = authorize_action(State(state), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn request_signing_missing_header_returns_401() {
        let key = "test-signing-key-missing";
        let (state, tenant_id, agent_token) =
            setup_state_with_signing_key("signing_missing", key).await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let body = Bytes::from(serde_json::to_vec(&request).unwrap());

        // No X-Aegis-Request-Signature header
        let headers = agent_headers(&agent_token, &tenant_id);

        let resp = authorize_action(State(state), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["message"], "missing_request_signature");
    }

    #[tokio::test]
    async fn request_signing_invalid_signature_returns_401() {
        let key = "test-signing-key-invalid";
        let (state, tenant_id, agent_token) =
            setup_state_with_signing_key("signing_invalid", key).await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let body = Bytes::from(serde_json::to_vec(&request).unwrap());

        let mut headers = agent_headers(&agent_token, &tenant_id);
        // Forged signature (wrong key)
        let forged = signing_header("wrong-key", &body);
        headers.insert("x-aegis-request-signature", forged.parse().unwrap());

        let resp = authorize_action(State(state), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["message"], "invalid_request_signature");
    }

    #[tokio::test]
    async fn request_signing_forged_body_returns_401() {
        let key = "test-signing-key-forged-body";
        let (state, tenant_id, agent_token) =
            setup_state_with_signing_key("signing_forged_body", key).await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let original_body = Bytes::from(serde_json::to_vec(&request).unwrap());
        let sig = signing_header(key, &original_body);

        // Sign the original body, but send a tampered body
        let mut tampered = request.clone();
        tampered.tool_call.action = "delete_all".to_string();
        let tampered_body = Bytes::from(serde_json::to_vec(&tampered).unwrap());

        let mut headers = agent_headers(&agent_token, &tenant_id);
        headers.insert("x-aegis-request-signature", sig.parse().unwrap());

        let resp = authorize_action(State(state), headers, tampered_body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["message"], "invalid_request_signature");
    }

    #[tokio::test]
    async fn request_signing_unsigned_agent_does_not_require_signature() {
        // Agents without a signing key registered are unaffected (opt-in).
        let (state, tenant_id, agent_token) = setup_state("signing_unsigned_agent_ok").await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let body = Bytes::from(serde_json::to_vec(&request).unwrap());

        // No signature header — should still pass since agent has no signing_key
        let headers = agent_headers(&agent_token, &tenant_id);
        let resp = authorize_action(State(state), headers, body)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn request_signing_db_verify_helper_accepts_valid_signature() {
        let key = "unit-test-key";
        let body = b"hello world";
        let sig = signing_header(key, body);
        assert!(db::verify_request_signature(key, body, &sig));
    }

    #[tokio::test]
    async fn request_signing_db_verify_helper_rejects_wrong_key() {
        let body = b"hello world";
        let sig = signing_header("correct-key", body);
        assert!(!db::verify_request_signature("wrong-key", body, &sig));
    }

    #[tokio::test]
    async fn request_signing_db_verify_helper_rejects_tampered_body() {
        let key = "integrity-key";
        let sig = signing_header(key, b"original body");
        assert!(!db::verify_request_signature(key, b"tampered body", &sig));
    }

    #[tokio::test]
    async fn request_signing_db_verify_helper_rejects_malformed_header() {
        let key = "format-key";
        // No sha256= prefix
        assert!(!db::verify_request_signature(
            key,
            b"body",
            "not-a-valid-sig"
        ));
        // Non-hex after prefix
        assert!(!db::verify_request_signature(key, b"body", "sha256=ZZZZ"));
    }

    #[tokio::test]
    async fn authorize_requires_mcp_tool_approval() {
        let (state, tenant_id, agent_token) = setup_state("mcp_tool_approval").await;
        let server_id = db::upsert_mcp_server(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();
        let tool = McpToolManifestItem {
            tool_key: "create_issue".to_string(),
            name: "Create issue".to_string(),
            description: None,
            input_schema: None,
            risk: "medium".to_string(),
            mutates_state: false,
            approval_required: false,
        };
        db::upsert_mcp_tool(&state.pool, &tenant_id, &server_id, &tool)
            .await
            .unwrap();

        let pending_response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(pending_response.decision, "deny");
        assert!(pending_response
            .matched_policies
            .contains(&"mcp_tool_status".to_string()));

        let updated = db::set_mcp_tool_status(
            &state.pool,
            &tenant_id,
            "github-mcp",
            "create_issue",
            "approved",
        )
        .await
        .unwrap();
        assert!(updated);

        let approved_response = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("mcp:github-mcp", "create_issue"),
        )
        .await;
        assert_eq!(approved_response.decision, "allow");
        assert_eq!(approved_response.risk_level, "medium");
        assert_eq!(approved_response.risk_score, 40);
    }

    // T-D hardening (b): a consume of an already-used approval is a replay attack on
    // the evidence chain. The gateway must record a tamper-attempt receipt (hashes
    // only, no payloads) so the chain captures the attempt, and still return 409.
    #[tokio::test]
    async fn replay_consume_emits_tamper_receipt() {
        let (state, tenant_id, agent_token) = setup_state("tamper_consume").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/11".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let first = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        let (before,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ?",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(before, 0);

        let replay = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        let recs: Vec<ActionReceiptRecord> = sqlx::query_as(
            "SELECT * FROM action_receipts WHERE tenant_id = ? AND decision = ? ORDER BY rowid ASC",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_all(&state.pool)
        .await
        .unwrap();
        assert_eq!(recs.len(), 1, "exactly one tamper receipt for the replay");
        let tamper = &recs[0];
        assert_eq!(tamper.receipt_hash, compute_receipt_hash(tamper));
        assert!(!tamper.prev_receipt_hash.is_empty(), "must chain onto head");
        assert_eq!(tamper.tool.as_deref(), Some("consume_not_consumable"));
        assert_eq!(
            tamper.resource.as_deref(),
            Some(format!("approval:{}", approval_id).as_str())
        );

        let (audit_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND event_type = 'tamper_attempt'",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);
    }

    // Integrity→SOC loop: a replay (consume of an already-consumed approval) must
    // STILL return 409 and STILL write exactly one tamper receipt (unchanged) AND
    // now ALSO emit a `replay_attempt` AseEvent onto the SOC stream so the detector
    // can raise a HIGH alert. We keep the receiver (no drain spawned) and assert the
    // event lands — mirroring `authorize_emits_security_event`.
    #[tokio::test]
    async fn replay_consume_emits_replay_attempt_security_event() {
        let (state, tenant_id, agent_token, mut events_rx) =
            setup_state_with_events("tamper_consume_soc").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/13".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        let first = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        assert_eq!(first.status(), StatusCode::OK);

        // The replay: a second consume of the now-used approval.
        let replay = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            None,
        )
        .await
        .into_response();
        // 409 response is UNCHANGED.
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        // The tamper receipt is UNCHANGED — exactly one written for the replay.
        let (receipt_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ? AND tool = 'consume_not_consumable'",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            receipt_count, 1,
            "exactly one tamper receipt for the replay"
        );

        // NEW: a `replay_attempt` AseEvent must have landed on the SOC stream. Drain
        // the receiver (the earlier authorize_decision event is also queued since no
        // drain task consumes it in this harness) and find the replay event.
        let mut found_replay = false;
        while let Ok(ev) = events_rx.try_recv() {
            if ev.kind == "replay_attempt" {
                assert_eq!(ev.decision, "deny");
                assert_eq!(ev.tenant_id, tenant_id);
                assert_eq!(ev.tool, "consume_not_consumable");
                assert_eq!(
                    ev.resource.as_deref(),
                    Some(format!("approval:{}", approval_id).as_str())
                );
                found_replay = true;
            }
        }
        assert!(
            found_replay,
            "replay must emit a replay_attempt AseEvent onto the SOC stream"
        );
    }

    // T-D hardening (b): approving an expired approval is a detected integrity
    // violation; it must likewise leave a tamper-attempt receipt and return 409.
    #[tokio::test]
    async fn approve_expired_emits_tamper_receipt() {
        let (state, tenant_id, agent_token) = setup_state("tamper_approve_expired").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/12".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        sqlx::query("UPDATE approvals SET expires_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(Utc::now() - Duration::minutes(5))
            .bind(tenant_id.as_str())
            .bind(approval_id.to_string())
            .execute(&state.pool)
            .await
            .unwrap();

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::CONFLICT);

        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM action_receipts WHERE tenant_id = ? AND decision = ? AND tool = 'approve_expired'",
        )
        .bind(tenant_id.as_str())
        .bind(TAMPER_DECISION)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            count, 1,
            "an expired-approval grant attempt must be recorded"
        );
    }

    /// OBS-001 (#1154): every `/v1/authorize` call records one observation on
    /// `aegis_authorize_duration_seconds`, exposed as a Prometheus histogram
    /// with `_bucket`/`_sum`/`_count` series.
    #[tokio::test]
    async fn authorize_records_duration_histogram() {
        let (state, tenant_id, agent_token) = setup_state("authorize_duration_histogram").await;

        assert_eq!(
            state.metrics.authorize_duration.count(),
            0,
            "histogram count must start at zero"
        );

        let request = mcp_authorize_request("github", "read_file");
        let _ = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;

        assert_eq!(
            state.metrics.authorize_duration.count(),
            1,
            "one authorize call must record exactly one observation"
        );

        let metrics_text = state.metrics.render_prometheus();
        assert!(
            metrics_text.contains("# TYPE aegis_authorize_duration_seconds histogram"),
            "metrics text must declare the histogram TYPE"
        );
        assert!(
            metrics_text.contains("aegis_authorize_duration_seconds_bucket{le=\"+Inf\"} 1"),
            "the +Inf bucket must include the one observation"
        );
        assert!(
            metrics_text.contains("aegis_authorize_duration_seconds_count 1"),
            "metrics text must include the observation count"
        );
        assert!(
            metrics_text.contains("aegis_authorize_duration_seconds_sum "),
            "metrics text must include the cumulative sum"
        );
    }

    // ── Security metrics tests ────────────────────────────────────────────────

    /// A mutating action from an untrusted-external source is denied by Cedar's
    /// "untrusted-mutation-forbid" rule AND increments `provenance_denials_total`.
    #[tokio::test]
    async fn provenance_denial_increments_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_denial_counter").await;

        let mut request = mcp_authorize_request("github", "push_commit");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "untrusted_external".to_string();

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            0,
            "counter must start at zero"
        );

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(
            response.decision, "deny",
            "untrusted mutating action must be denied"
        );

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            1,
            "provenance_denials_total must be 1 after one denied provenance"
        );

        let metrics_text = state.metrics.render_prometheus();
        assert!(
            metrics_text.contains("provenance_denials_total 1\n"),
            "metrics text must include updated counter value"
        );
        assert!(
            metrics_text.contains("# TYPE provenance_denials_total counter"),
            "metrics text must include TYPE declaration"
        );
    }

    /// All three untrusted levels increment the same counter.
    #[tokio::test]
    async fn provenance_denial_counter_accumulates() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_denial_accumulates").await;

        for trust in &["untrusted_external", "malicious_suspected", "unknown"] {
            let mut req = mcp_authorize_request("github", "delete_branch");
            req.tool_call.mutates_state = true;
            req.context.source_trust = (*trust).to_string();
            let resp = call_authorize(state.clone(), &tenant_id, &agent_token, req).await;
            assert_eq!(resp.decision, "deny");
        }

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            3,
            "all three untrusted trust levels must increment the counter"
        );
    }

    /// A trusted-internal mutating action that is ALLOWED must NOT increment the counter.
    #[tokio::test]
    async fn trusted_mutating_action_does_not_increment_provenance_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("provenance_no_increment").await;

        let mut req = mcp_authorize_request("github", "push_commit");
        req.tool_call.mutates_state = true;
        req.context.source_trust = "trusted_internal_signed".to_string();
        let resp = call_authorize(state.clone(), &tenant_id, &agent_token, req).await;
        assert_ne!(resp.decision, "deny");

        assert_eq!(
            state
                .metrics
                .provenance_denials_total
                .load(Ordering::Relaxed),
            0,
            "trusted mutating actions must not touch the provenance counter"
        );
    }

    /// Hash mismatch on consume_approval increments approval_hash_mismatch_total
    /// and returns 409 CONFLICT, blocking execution (approve-then-swap defence).
    #[tokio::test]
    async fn hash_mismatch_on_consume_increments_counter() {
        use std::sync::atomic::Ordering;

        let (state, tenant_id, agent_token) = setup_state("hash_mismatch_counter").await;

        let mut request = mcp_authorize_request("github", "merge_pull_request");
        request.tool_call.mutates_state = true;
        request.tool_call.resource = Some("repo/example/pull/99".to_string());
        request.tool_call.parameters = serde_json::json!({"base_branch": "main"});
        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        let approval_id = response.approval.expect("approval created").approval_id;

        let approve = approve_approval(
            State(state.clone()),
            ConnectInfo(test_conn_info()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            HeaderMap::new(),
            Json(ApproveRequest {
                approver_user_id: "reviewer".to_string(),
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(approve.status(), StatusCode::OK);

        assert_eq!(
            state
                .metrics
                .approval_hash_mismatch_total
                .load(Ordering::Relaxed),
            0
        );

        let mismatch_resp = consume_approval(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(approval_id),
            Some(Json(ConsumeApprovalBody {
                claimed_action_hash: Some(
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ),
            })),
        )
        .await
        .into_response();
        assert_eq!(
            mismatch_resp.status(),
            StatusCode::CONFLICT,
            "hash mismatch must return 409"
        );

        assert_eq!(
            state
                .metrics
                .approval_hash_mismatch_total
                .load(Ordering::Relaxed),
            1,
            "approval_hash_mismatch_total must be 1 after one swap attempt"
        );
    }

    // ── SOC Phase 5: Indexer route tests ─────────────────────────────────────

    /// parse_pagination caps limit at SOC_MAX_LIMIT and defaults correctly.
    #[test]
    fn parse_pagination_caps_and_defaults() {
        // No query string → defaults
        let (limit, offset) = parse_pagination(None);
        assert_eq!(limit, db::SOC_DEFAULT_LIMIT);
        assert_eq!(offset, 0);

        // Explicit small limit and offset
        let (limit, offset) = parse_pagination(Some("limit=10&offset=5"));
        assert_eq!(limit, 10);
        assert_eq!(offset, 5);

        // Exceeding max cap
        let (limit, _) = parse_pagination(Some("limit=99999"));
        assert_eq!(limit, db::SOC_MAX_LIMIT);

        // Zero limit → clamped to 1
        let (limit, _) = parse_pagination(Some("limit=0"));
        assert_eq!(limit, 1);

        // Negative offset → clamped to 0
        let (_, offset) = parse_pagination(Some("offset=-5"));
        assert_eq!(offset, 0);
    }

    // ── SOC Phase 6: narrate_incident route tests ─────────────────────────────

    /// Setup helper for environment restriction tests (#1391): creates a standard
    /// agent then sets `allowed_environments` to a JSON-encoded list. An empty
    /// slice writes `[]`, which the gateway treats as unrestricted (same as NULL).
    async fn setup_state_with_env_restriction(
        test_name: &str,
        envs: &[&str],
    ) -> (Arc<AppState>, String, String) {
        let (state, tenant_id, agent_token) = setup_state(test_name).await;
        let json = serde_json::to_string(&envs).unwrap();
        sqlx::query("UPDATE agents SET allowed_environments = ? WHERE tenant_id = ?")
            .bind(&json)
            .bind(&tenant_id)
            .execute(&state.pool)
            .await
            .unwrap();
        (state, tenant_id, agent_token)
    }

    /// #1391: agent restricted to ["production"] — request from "staging" is
    /// denied 403 FORBIDDEN before Cedar evaluation.
    #[tokio::test]
    async fn authorize_action_denies_agent_in_wrong_environment() {
        let (state, tenant_id, agent_token) =
            setup_state_with_env_restriction("env_deny", &["production"]).await;

        let mut req = mcp_authorize_request("filesystem", "read_file");
        req.agent.environment = "staging".to_string();

        let response = authorize_action(
            State(state),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "deny");
        assert!(
            json["reason"].as_str().unwrap().contains("staging"),
            "reason should name the rejected environment"
        );
    }

    /// #1391: same agent restricted to ["production"] — request from "production"
    /// passes the env check and Cedar decides (allow or require_approval).
    #[tokio::test]
    async fn authorize_action_allows_agent_in_correct_environment() {
        let (state, tenant_id, agent_token) =
            setup_state_with_env_restriction("env_allow", &["production"]).await;

        // mcp_authorize_request defaults to environment = "production".
        let resp = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;
        assert!(
            resp.decision == "allow" || resp.decision == "require_approval",
            "expected allow or require_approval, got: {}",
            resp.decision
        );
    }

    /// #1391: agent with NULL allowed_environments is unrestricted — any
    /// environment passes (backwards-compatible with pre-#1391 agents).
    #[tokio::test]
    async fn authorize_action_unrestricted_agent_allows_any_environment() {
        let (state, tenant_id, agent_token) = setup_state("env_unrestricted").await;

        let mut req = mcp_authorize_request("filesystem", "read_file");
        req.agent.environment = "any_environment_whatsoever".to_string();

        let resp = call_authorize(state, &tenant_id, &agent_token, req).await;
        assert!(
            resp.decision == "allow" || resp.decision == "require_approval",
            "unrestricted agent must pass env check for any environment"
        );
    }

    // ── Agent-to-tool permission binding tests (#1390) ───────────────────────

    /// Grant a permission then list it — `GET /v1/agents/:id/permissions`
    /// returns exactly the binding that was just created.
    #[tokio::test]
    async fn grant_and_list_tool_permissions() {
        let (state, tenant_id, _agent_token) = setup_state("perm_grant_list").await;
        let agent_id = db::get_agent_by_token(&state.pool, &tenant_id, &_agent_token)
            .await
            .unwrap()
            .unwrap()
            .id;

        db::grant_agent_tool_permission(&state.pool, &tenant_id, &agent_id, "github")
            .await
            .unwrap();
        db::grant_agent_tool_permission(&state.pool, &tenant_id, &agent_id, "filesystem")
            .await
            .unwrap();

        let perms = db::get_agent_tool_permissions(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap();
        assert_eq!(perms.len(), 2);
        let keys: Vec<&str> = perms.iter().map(|p| p.tool_key.as_str()).collect();
        assert!(keys.contains(&"github"));
        assert!(keys.contains(&"filesystem"));
    }

    /// Revoking a permission removes it from the list; duplicate revoke → false.
    #[tokio::test]
    async fn revoke_tool_permission_removes_binding() {
        let (state, tenant_id, agent_token) = setup_state("perm_revoke").await;
        let agent_id = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap()
            .id;

        db::grant_agent_tool_permission(&state.pool, &tenant_id, &agent_id, "github")
            .await
            .unwrap();

        let deleted =
            db::revoke_agent_tool_permission(&state.pool, &tenant_id, &agent_id, "github")
                .await
                .unwrap();
        assert!(deleted, "first revoke must return true");

        let deleted2 =
            db::revoke_agent_tool_permission(&state.pool, &tenant_id, &agent_id, "github")
                .await
                .unwrap();
        assert!(!deleted2, "duplicate revoke must return false");

        let perms = db::get_agent_tool_permissions(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap();
        assert!(perms.is_empty());
    }

    /// Agent has explicit permissions but NOT for the requested tool → 403 deny.
    #[tokio::test]
    async fn authorize_action_denies_tool_not_in_permission_list() {
        let (state, tenant_id, agent_token) = setup_state("perm_deny_tool").await;
        let agent_id = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap()
            .id;
        // Grant only "github"; request will use "filesystem".
        db::grant_agent_tool_permission(&state.pool, &tenant_id, &agent_id, "github")
            .await
            .unwrap();

        let req = mcp_authorize_request("filesystem", "read_file");
        let response = authorize_action(
            State(state),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["decision"], "deny");
        assert!(
            json["reason"].as_str().unwrap().contains("filesystem"),
            "reason should name the rejected tool"
        );
    }

    /// Agent has a permission for the requested tool → env/perm checks pass,
    /// Cedar decides (allow or require_approval).
    #[tokio::test]
    async fn authorize_action_allows_tool_in_permission_list() {
        let (state, tenant_id, agent_token) = setup_state("perm_allow_tool").await;
        let agent_id = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap()
            .id;
        db::grant_agent_tool_permission(&state.pool, &tenant_id, &agent_id, "filesystem")
            .await
            .unwrap();

        let resp = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;
        assert!(
            resp.decision == "allow" || resp.decision == "require_approval",
            "expected allow or require_approval, got: {}",
            resp.decision
        );
    }

    /// Agent with no permission rows is unrestricted — any tool is allowed
    /// (backwards-compatible with pre-#1390 agents).
    #[tokio::test]
    async fn authorize_action_unrestricted_agent_allows_any_tool() {
        let (state, tenant_id, agent_token) = setup_state("perm_unrestricted").await;
        // No db::grant_agent_tool_permission calls → unrestricted.
        let resp = call_authorize(
            state,
            &tenant_id,
            &agent_token,
            mcp_authorize_request("filesystem", "read_file"),
        )
        .await;
        assert!(
            resp.decision == "allow" || resp.decision == "require_approval",
            "unrestricted agent must pass tool permission check"
        );
    }

    // ── Cedar @decision("quarantine") tests (#1386) ──────────────────────────

    /// Calling the quarantine canary endpoint returns `decision: "quarantine"`
    /// and sets the agent's DB status to `quarantined`.
    #[tokio::test]
    async fn authorize_action_quarantine_decision_quarantines_agent() {
        let (state, tenant_id, agent_token) = setup_state("cedar_quarantine_trigger").await;

        // quarantine_canary / trigger → ToolAction::"quarantine_canary_trigger"
        // matches the @decision("quarantine") canary policy in policies.cedar.
        let req = mcp_authorize_request("quarantine_canary", "trigger");
        let resp = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["decision"], "quarantine",
            "response must surface quarantine decision"
        );

        // Agent row must now be quarantined in the DB.
        // Use a raw query instead of get_agent_by_token (which filters quarantined agents).
        let agent_id: String =
            sqlx::query_scalar("SELECT id FROM agents WHERE tenant_id = ? AND agent_token = ?")
                .bind(&tenant_id)
                .bind(db::hash_token(&agent_token))
                .fetch_one(&state.pool)
                .await
                .unwrap();
        // get_agent_by_id only filters `status != 'deleted'`, so quarantined rows are returned.
        let agent_record = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent_record.status, "quarantined");
    }

    /// After quarantine, subsequent authorize calls from the same agent are
    /// auto-denied (401) — `get_agent_by_token` filters `status != 'quarantined'`.
    #[tokio::test]
    async fn authorize_action_quarantined_agent_subsequent_calls_denied() {
        let (state, tenant_id, agent_token) = setup_state("cedar_quarantine_subsequent").await;

        // First call: trigger quarantine.
        let req = mcp_authorize_request("quarantine_canary", "trigger");
        let _ = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await;

        // Second call: any tool — must be 401 (agent no longer resolvable).
        let req2 = mcp_authorize_request("filesystem", "read_file");
        let resp2 = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req2).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    }

    /// `POST /v1/agents/:id/report-leaked-token` rotates by default (tenant's
    /// `auto_rotate_token_on_leak_enabled` defaults to `true`).
    #[tokio::test]
    async fn report_leaked_token_auto_rotates_by_default() {
        let (state, tenant_id, old_token) = setup_state("leak_report_default").await;
        let agent_id: String =
            sqlx::query_scalar("SELECT id FROM agents WHERE tenant_id = ? AND agent_token = ?")
                .bind(&tenant_id)
                .bind(db::hash_token(&old_token))
                .fetch_one(&state.pool)
                .await
                .unwrap();

        let resp = report_leaked_agent_token(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
            Json(ReportLeakedTokenRequest {
                reason: "found in public GitHub repo".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["rotated"], true);
        let new_token = json["agent_token"].as_str().unwrap().to_string();
        assert_ne!(new_token, old_token);

        // Old token now rejected.
        let req = mcp_authorize_request("filesystem", "read_file");
        let resp_old = authorize_action(
            State(state.clone()),
            agent_headers(&old_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_old.status(), StatusCode::UNAUTHORIZED);
    }

    /// When a tenant has disabled `auto_rotate_token_on_leak_enabled`, the
    /// leak report is recorded but the existing token remains valid.
    #[tokio::test]
    async fn report_leaked_token_skips_rotation_when_tenant_disabled() {
        let (state, tenant_id, token) = setup_state("leak_report_disabled").await;
        let agent_id: String =
            sqlx::query_scalar("SELECT id FROM agents WHERE tenant_id = ? AND agent_token = ?")
                .bind(&tenant_id)
                .bind(db::hash_token(&token))
                .fetch_one(&state.pool)
                .await
                .unwrap();

        sqlx::query("UPDATE tenants SET auto_rotate_token_on_leak_enabled = 0 WHERE id = ?")
            .bind(&tenant_id)
            .execute(&state.pool)
            .await
            .unwrap();

        let resp = report_leaked_agent_token(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(agent_id.clone()),
            Json(ReportLeakedTokenRequest {
                reason: "found in public GitHub repo".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["rotated"], false);
        assert!(json["agent_token"].is_null());

        // Original token still works.
        let req = mcp_authorize_request("filesystem", "read_file");
        let resp_after = authorize_action(
            State(state.clone()),
            agent_headers(&token, &tenant_id),
            Bytes::from(serde_json::to_vec(&req).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_after.status(), StatusCode::OK);

        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        assert!(events
            .iter()
            .any(|e| e.event_type == "agent_token_leak_detected_no_rotation"));
    }

    #[tokio::test]
    async fn report_leaked_token_unknown_agent_returns_404() {
        let (state, tenant_id, _) = setup_state("leak_report_404").await;

        let resp = report_leaked_agent_token(
            State(state.clone()),
            TenantId(tenant_id),
            Path("nonexistent-agent".to_string()),
            Json(ReportLeakedTokenRequest {
                reason: "test".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // --- #1384: normalize_tool_identifier unit tests ---

    /// #1384: Sending a mixed-case tool name via the authorize endpoint must
    /// produce the same Cedar decision as the lowercase canonical form.
    /// Without normalization `GitHub`/`Merge_Pull_Request` builds a Cedar UID
    /// `ToolAction::"GitHub_Merge_Pull_Request"` that fails to match the policy
    /// targeting `ToolAction::"github_merge_pull_request"`, silently bypassing
    /// the approval gate.
    #[tokio::test]
    async fn authorize_mixed_case_tool_resolves_to_same_cedar_decision() {
        let (state, tenant_id, agent_token) = setup_state("normalize_cedar_bypass").await;

        // Lowercase — Cedar policy requires approval for github/merge_pull_request
        // with base_branch == "main".
        let canonical_payload = serde_json::json!({
            "agent": { "id": "test-agent", "environment": "production" },
            "tool_call": {
                "tool": "github",
                "action": "merge_pull_request",
                "mutates_state": true,
                "parameters": { "base_branch": "main" }
            },
            "context": {
                "source_trust": "trusted_internal_signed",
                "contains_sensitive_data": false
            }
        });

        // Mixed-case variant — should resolve to the same decision.
        let mixed_case_payload = serde_json::json!({
            "agent": { "id": "test-agent", "environment": "production" },
            "tool_call": {
                "tool": "GitHub",
                "action": "Merge_Pull_Request",
                "mutates_state": true,
                "parameters": { "base_branch": "main" }
            },
            "context": {
                "source_trust": "trusted_internal_signed",
                "contains_sensitive_data": false
            }
        });

        let resp_canonical = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&canonical_payload).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_canonical.status(), StatusCode::OK);
        let body_canonical: serde_json::Value = serde_json::from_slice(
            &to_bytes(resp_canonical.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let decision_canonical = body_canonical["decision"].as_str().unwrap().to_string();

        let resp_mixed = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&mixed_case_payload).unwrap()),
        )
        .await
        .into_response();
        assert_eq!(resp_mixed.status(), StatusCode::OK);
        let body_mixed: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp_mixed.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let decision_mixed = body_mixed["decision"].as_str().unwrap().to_string();

        assert_eq!(
            decision_mixed, decision_canonical,
            "mixed-case tool/action must resolve to the same Cedar decision as lowercase"
        );
        // Both should require approval per the github_merge_pull_request policy.
        assert_eq!(decision_canonical, "require_approval");
    }

    // --- #1385: redact decision type integration tests ---

    /// Calling the `secrets/rotate_credential` canary returns `decision: "redact"`
    /// with a non-empty `redacted_fields` list populated from `@redact_fields`.
    #[tokio::test]
    async fn authorize_redact_decision_returns_fields() {
        let (state, tenant_id, agent_token) = setup_state("redact_decision_fields").await;

        let payload = serde_json::json!({
            "agent": { "id": "test-agent", "environment": "production" },
            "tool_call": {
                "tool": "secrets",
                "action": "rotate_credential",
                "mutates_state": false,
                "parameters": { "api_key": "sk-secret", "name": "my-cred" }
            },
            "context": {
                "source_trust": "trusted_internal_signed",
                "contains_sensitive_data": false
            }
        });

        let resp = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();

        assert_eq!(body["decision"], "redact");
        let fields = body["redacted_fields"]
            .as_array()
            .expect("redacted_fields must be an array");
        assert!(!fields.is_empty(), "redacted_fields must not be empty");
        // The policy declares @redact_fields("api_key,password,secret,token")
        assert!(
            fields.iter().any(|f| f == "api_key"),
            "api_key must be in redacted_fields"
        );
    }

    /// Non-redact decisions must never include `redacted_fields` in the response
    /// (the field should be absent or empty — `skip_serializing_if = "Vec::is_empty"`).
    #[tokio::test]
    async fn authorize_non_redact_decision_has_no_redacted_fields() {
        let (state, tenant_id, agent_token) = setup_state("redact_field_absent").await;

        let payload = serde_json::json!({
            "agent": { "id": "test-agent", "environment": "production" },
            "tool_call": {
                "tool": "filesystem",
                "action": "read_file",
                "mutates_state": false,
                "parameters": {}
            },
            "context": {
                "source_trust": "trusted_internal_signed",
                "contains_sensitive_data": false
            }
        });

        let resp = authorize_action(
            State(state.clone()),
            agent_headers(&agent_token, &tenant_id),
            Bytes::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();

        assert_eq!(body["decision"], "allow");
        // Field should be absent (skip_serializing_if = "Vec::is_empty") or empty array.
        match body.get("redacted_fields") {
            None => {}
            Some(v) => assert_eq!(
                v.as_array().map(|a| a.is_empty()),
                Some(true),
                "redacted_fields must be absent or empty for non-redact decisions"
            ),
        }
    }

    #[tokio::test]
    async fn authorize_action_denies_frozen_and_revoked_agent() {
        let (state, tenant_id, agent_token) = setup_state("agent_frozen_revoked").await;

        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        // Baseline: active agent should be allowed
        let request = mcp_authorize_request("filesystem", "read_file");
        let allowed =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(allowed.decision, "allow");

        // Freeze the agent
        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "frozen")
                .await
                .unwrap()
        );

        // Frozen agent should be denied
        let frozen_denied =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(frozen_denied.decision, "deny");
        assert!(frozen_denied
            .matched_policies
            .contains(&"agent_frozen".to_string()));

        // Revoke the agent
        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent_id, "revoked")
                .await
                .unwrap()
        );

        // Revoked agent should be denied
        let revoked_denied =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(revoked_denied.decision, "deny");
        assert!(revoked_denied
            .matched_policies
            .contains(&"agent_revoked".to_string()));
    }

    /// #1315: non-critical decisions hand their `audit_events` row to the
    /// batch sink instead of inserting synchronously. With a writer
    /// configured to flush only every 60s, the row is not yet in the table
    /// immediately after the response returns, but appears once the
    /// flush-interval timer fires.
    #[tokio::test]
    async fn non_critical_decision_audit_row_is_batched_not_immediate() {
        let (state, tenant_id, agent_token) = setup_state_with_audit_batch_writer(
            "audit_batch_non_critical",
            100,
            std::time::Duration::from_millis(50),
        )
        .await;

        let request = mcp_authorize_request("filesystem", "read_file");
        let allowed = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(allowed.decision, "allow");

        // The decision row is written synchronously...
        assert!(
            db::get_decision_by_id(&state.pool, &tenant_id, &allowed.decision_id.to_string())
                .await
                .unwrap()
                .is_some()
        );
        // ...but the matching audit_events row is sitting in the batch
        // channel, not yet flushed to the table.
        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        assert!(events
            .iter()
            .all(|e| e.decision_id.as_deref() != Some(allowed.decision_id.to_string().as_str())));

        // Once the flush-interval timer fires, the batch writer flushes the
        // buffered row to the table.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        assert!(events
            .iter()
            .any(|e| e.decision_id.as_deref() == Some(allowed.decision_id.to_string().as_str())));
    }

    /// #1315: critical denials (risk_score >= 95) bypass the batch sink and
    /// write their `audit_events` row synchronously, so it is visible
    /// immediately — even with nothing draining the batch channel.
    #[tokio::test]
    async fn critical_denial_audit_row_is_written_synchronously() {
        let (state, tenant_id, agent_token) = setup_state("audit_batch_critical").await;

        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        assert!(
            db::set_agent_status(&state.pool, &tenant_id, &agent.id, "frozen")
                .await
                .unwrap()
        );

        let request = mcp_authorize_request("filesystem", "read_file");
        let denied = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(denied.decision, "deny");

        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        assert!(events
            .iter()
            .any(|e| e.decision_id.as_deref() == Some(denied.decision_id.to_string().as_str())));
    }

    /// #1184 (Phase 4 response engine completion): once `agents.force_approval`
    /// is set (e.g. by the SOC Response Engine after a `trust_escalation`
    /// incident), every otherwise-`allow` decision for that agent is downgraded
    /// to `require_approval` until an operator clears it.
    #[tokio::test]
    async fn force_approval_agent_downgrades_allow_to_require_approval() {
        let (state, tenant_id, agent_token) = setup_state("agent_force_approval").await;

        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let request = mcp_authorize_request("filesystem", "read_file");

        // Baseline: active agent, normally-allowed action.
        let allowed =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(allowed.decision, "allow");

        // Simulate the Response Engine setting force_approval after a
        // trust_escalation incident.
        db::set_agent_force_approval(&state.pool, &tenant_id, &agent_id, true)
            .await
            .unwrap();

        let downgraded =
            call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        assert_eq!(downgraded.decision, "require_approval");
        assert!(downgraded
            .matched_policies
            .contains(&"soc_response_force_approval".to_string()));

        // Clearing force_approval restores the normal allow decision.
        db::set_agent_force_approval(&state.pool, &tenant_id, &agent_id, false)
            .await
            .unwrap();
        let restored = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(restored.decision, "allow");
    }

    #[tokio::test]
    async fn test_list_and_get_decisions_route() {
        let (state, tenant_id, agent_token) = setup_state("list_get_decisions").await;
        let agent = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        let agent_id = agent.id;

        let agent_id2 = Uuid::new_v4().to_string();
        let agent2 = AgentRecord {
            id: agent_id2.clone(),
            tenant_id: tenant_id.clone(),
            agent_key: "second-agent".to_string(),
            agent_token: "tok_2".to_string(),
            name: "Second Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&state.pool, &agent2).await.unwrap();

        let decision_id2 = Uuid::new_v4().to_string();
        let record2 = DecisionRecord {
            id: decision_id2.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id2.clone(),
            user_id: Some("user_2".to_string()),
            run_id: Some("run_2".to_string()),
            trace_id: Some("trace_2".to_string()),
            skill: "http".to_string(),
            action: "get".to_string(),
            resource: Some("http://example.com".to_string()),
            input_json: "{}".to_string(),
            decision: "deny".to_string(),
            risk_score: Some(10),
            reason: Some("bad site".to_string()),
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            composite_risk_score: None,
            root_trust_level: None,
            parent_run_id: None,
            created_at: Utc::now() - Duration::seconds(10),
        };
        db::insert_decision(&state.pool, &record2).await.unwrap();

        let decision_id1 = Uuid::new_v4().to_string();
        let record1 = DecisionRecord {
            id: decision_id1.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            user_id: Some("user_1".to_string()),
            run_id: Some("run_1".to_string()),
            trace_id: Some("trace_1".to_string()),
            skill: "fs".to_string(),
            action: "read".to_string(),
            resource: Some("foo.txt".to_string()),
            input_json: "{}".to_string(),
            decision: "allow".to_string(),
            risk_score: Some(1),
            reason: Some("ok".to_string()),
            matched_policy_ids: None,
            request_id: None,
            latency_ms: None,
            composite_risk_score: None,
            root_trust_level: None,
            parent_run_id: None,
            created_at: Utc::now(),
        };
        db::insert_decision(&state.pool, &record1).await.unwrap();

        // 1. List decisions without filters
        let response = list_decisions(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = json.as_array().unwrap();
        assert_eq!(list.len(), 2);
        // Order is newest first, so record1 (created Utc::now()) should be first
        assert_eq!(list[0]["id"].as_str(), Some(decision_id1.as_str()));
        assert_eq!(list[1]["id"].as_str(), Some(decision_id2.as_str()));

        // Keyset Pagination tests (#1142)
        // A. Limit=1: should return first page with x-next-cursor header
        let response_page1 = list_decisions(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("limit=1".to_string())),
        )
        .await
        .into_response();
        assert_eq!(response_page1.status(), StatusCode::OK);
        let cursor_header = response_page1.headers().get("x-next-cursor").cloned();
        assert!(
            cursor_header.is_some(),
            "x-next-cursor header should be present"
        );
        let cursor_val = cursor_header.unwrap().to_str().unwrap().to_string();

        let body_page1 = to_bytes(response_page1.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_page1: serde_json::Value = serde_json::from_slice(&body_page1).unwrap();
        let list_page1 = json_page1.as_array().unwrap();
        assert_eq!(list_page1.len(), 1);
        assert_eq!(list_page1[0]["id"].as_str(), Some(decision_id1.as_str()));
        let response_page2 = list_decisions(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some(format!("limit=2&cursor={}", cursor_val))),
        )
        .await
        .into_response();
        assert_eq!(response_page2.status(), StatusCode::OK);
        assert!(
            response_page2.headers().get("x-next-cursor").is_none(),
            "x-next-cursor should not be present at the end of the pages"
        );

        let body_page2 = to_bytes(response_page2.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_page2: serde_json::Value = serde_json::from_slice(&body_page2).unwrap();
        let list_page2 = json_page2.as_array().unwrap();
        assert_eq!(list_page2.len(), 1);
        assert_eq!(list_page2[0]["id"].as_str(), Some(decision_id2.as_str()));

        // C. Invalid cursor: should fail with 400 Bad Request
        let response_invalid_cursor = list_decisions(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some("cursor=invalid_hex_token".to_string())),
        )
        .await
        .into_response();
        assert_eq!(response_invalid_cursor.status(), StatusCode::BAD_REQUEST);

        // 2. List decisions with filter: agent_id
        let response_filter = list_decisions(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(Some(format!("agent_id={}", agent_id2))),
        )
        .await
        .into_response();
        assert_eq!(response_filter.status(), StatusCode::OK);
        let body_filter = to_bytes(response_filter.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_filter: serde_json::Value = serde_json::from_slice(&body_filter).unwrap();
        let list_filter = json_filter.as_array().unwrap();
        assert_eq!(list_filter.len(), 1);
        assert_eq!(list_filter[0]["id"].as_str(), Some(decision_id2.as_str()));

        // 3. Get decision detail success
        let response_detail = get_decision(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(decision_id1.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_detail.status(), StatusCode::OK);
        let body_detail = to_bytes(response_detail.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_detail: serde_json::Value = serde_json::from_slice(&body_detail).unwrap();
        assert_eq!(json_detail["id"].as_str(), Some(decision_id1.as_str()));

        // 4. Get decision detail cross-tenant (should return 404)
        let other_tenant = "tenant_other_decisions";
        db::register_tenant(&state.pool, other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();
        let response_cross = get_decision(
            State(state.clone()),
            TenantId(other_tenant.to_string()),
            Path(decision_id1.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_and_get_receipts_route() {
        let (state, tenant_id, _) = setup_state("list_get_receipts").await;

        let rec = db::append_action_receipt_atomic(&state.pool, &tenant_id, |prev| {
            let mut r = unsigned_receipt_template(&tenant_id);
            r.prev_receipt_hash = prev;
            r.receipt_hash = compute_receipt_hash(&r);
            r
        })
        .await
        .unwrap();

        // 1. List receipts
        let response = list_receipts(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            axum::extract::RawQuery(None),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = json.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"].as_str(), Some(rec.id.as_str()));

        // 2. Get receipt detail success
        let response_detail = get_receipt(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_detail.status(), StatusCode::OK);
        let body_detail = to_bytes(response_detail.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_detail: serde_json::Value = serde_json::from_slice(&body_detail).unwrap();
        assert_eq!(json_detail["id"].as_str(), Some(rec.id.as_str()));

        // 3. Get receipt detail cross-tenant (should return 404)
        let other_tenant = "tenant_other_receipts";
        db::register_tenant(&state.pool, other_tenant, "Other Tenant", "developer")
            .await
            .unwrap();
        let response_cross = get_receipt(
            State(state.clone()),
            TenantId(other_tenant.to_string()),
            Path(rec.id.clone()),
        )
        .await
        .into_response();
        assert_eq!(response_cross.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_event_sink_broadcasting() {
        let (sink, _rx) = EventSink::channel(100, Arc::new(crate::metrics::SecurityMetrics::new()));
        let mut sub = sink.subscribe();

        let event = AseEvent {
            event_id: "evt_test".to_string(),
            occurred_at: "2026-06-02T12:00:00Z".to_string(),
            tenant_id: "tenant_abc".to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: "agent_abc".to_string(),
            decision: "allow".to_string(),
            tool: "github".to_string(),
            action: "read".to_string(),
            resource: None,
            risk_score: 10,
            reason: "test".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec![],
            redacted_fields: vec![],
            schema_version: 1,
        };

        sink.emit(event.clone());

        let received = sub.recv().await.unwrap();
        assert_eq!(received.event_id, "evt_test");
        assert_eq!(received.tenant_id, "tenant_abc");
    }

    #[tokio::test]
    async fn test_request_size_limit() {
        use axum::http::{Request, StatusCode};
        use axum::{extract::DefaultBodyLimit, routing::post, Router};
        use tower::ServiceExt;

        // Create a test app with a body limit of 10 bytes
        let app = Router::new()
            .route("/", post(|body: String| async { body }))
            .layer(DefaultBodyLimit::max(10));

        // Send a request with a small body (8 bytes)
        let request_small = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "text/plain")
            .body(axum::body::Body::from("12345678"))
            .unwrap();
        let response_small = app.clone().oneshot(request_small).await.unwrap();
        assert_eq!(response_small.status(), StatusCode::OK);

        // Send a request with a large body (12 bytes)
        let request_large = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "text/plain")
            .body(axum::body::Body::from("123456789012"))
            .unwrap();
        let response_large = app.oneshot(request_large).await.unwrap();
        assert_eq!(response_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_request_timeout() {
        use axum::http::{Request, StatusCode};
        use axum::{routing::get, Router};
        use std::time::Duration;
        use tower::ServiceExt;
        use tower_http::timeout::TimeoutLayer;

        // Create a test app with a timeout of 50ms
        let app = Router::new()
            .route("/fast", get(|| async { "fast" }))
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    "slow"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(50)));

        // Fast request should succeed
        let req_fast = Request::builder()
            .uri("/fast")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp_fast = app.clone().oneshot(req_fast).await.unwrap();
        assert_eq!(resp_fast.status(), StatusCode::OK);

        // Slow request should time out
        let req_slow = Request::builder()
            .uri("/slow")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp_slow = app.oneshot(req_slow).await.unwrap();
        assert!(
            resp_slow.status() == StatusCode::REQUEST_TIMEOUT
                || resp_slow.status() == StatusCode::GATEWAY_TIMEOUT
                || resp_slow.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "expected timeout status, got: {:?}",
            resp_slow.status()
        );
    }

    #[tokio::test]
    async fn test_response_compression() {
        use axum::http::{header, Request, StatusCode};
        use axum::{routing::get, Router};
        use tower::ServiceExt;
        use tower_http::compression::CompressionLayer;

        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    let large_body = "hello compression ".repeat(200);
                    ([(header::CONTENT_TYPE, "text/plain")], large_body)
                }),
            )
            .layer(CompressionLayer::new());

        // Request with Accept-Encoding: gzip
        let req = Request::builder()
            .uri("/")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_encoding = resp.headers().get(header::CONTENT_ENCODING);
        assert!(
            content_encoding.is_some(),
            "Content-Encoding header missing"
        );
        assert_eq!(content_encoding.unwrap(), "gzip");
    }

    #[test]
    fn skill_action_cache_hit_evict_invalidate_and_disabled() {
        let meta = |r: &str| (r.to_string(), false, false, "policy".to_string());
        let cache = SkillActionCache::new(2);
        let k1 = SkillActionCache::cache_key("t1", "s", "a1");
        let k2 = SkillActionCache::cache_key("t1", "s", "a2");
        let k3 = SkillActionCache::cache_key("t1", "s", "a3");

        cache.insert(k1.clone(), meta("low"));
        assert_eq!(cache.get(&k1), Some(meta("low"))); // hit
                                                       // Tenant-scoped: same skill/action under another tenant is a distinct key.
        assert_eq!(
            cache.get(&SkillActionCache::cache_key("t2", "s", "a1")),
            None
        );

        // LRU eviction at capacity 2: k1 is most-recently-used, so inserting k3
        // over capacity evicts the least-recent (k2).
        cache.insert(k2.clone(), meta("low"));
        let _ = cache.get(&k1);
        cache.insert(k3.clone(), meta("low"));
        assert_eq!(cache.get(&k2), None);
        assert!(cache.get(&k1).is_some());
        assert!(cache.get(&k3).is_some());

        cache.invalidate(&k1);
        assert_eq!(cache.get(&k1), None);

        // Capacity 0 disables the cache entirely.
        let disabled = SkillActionCache::new(0);
        disabled.insert(k1.clone(), meta("low"));
        assert_eq!(disabled.get(&k1), None);
    }

    async fn register_ship_action(state: &Arc<AppState>, tenant_id: &str, risk: &str) {
        let req = RegisterToolRequest {
            skill_key: "deployer".to_string(),
            name: "Deployer".to_string(),
            r#type: "static".to_string(),
            auth_type: None,
            owner_team: None,
            default_risk: None,
            actions: vec![RegisterToolAction {
                action_key: "ship".to_string(),
                description: None,
                risk: risk.to_string(),
                mutates_state: false,
                data_access: None,
                approval_required: false,
                default_decision: "policy".to_string(),
            }],
        };
        let resp = register_tool(
            State(state.clone()),
            TenantId(tenant_id.to_string()),
            Json(req),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Fail-closed staleness guard: after a cached authorize, re-registering the
    /// same action with a STRICTER risk must be reflected on the next authorize
    /// (the registration invalidates the cache — no stale looser metadata).
    #[tokio::test]
    async fn authorize_skill_cache_invalidated_on_reregister() {
        let (state, tenant_id, agent_token) = setup_state("skill_cache_reregister").await;

        register_ship_action(&state, &tenant_id, "low").await;
        let r1 = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("deployer", "ship"),
        )
        .await;
        assert_eq!(r1.risk_level, "low"); // populates the cache

        register_ship_action(&state, &tenant_id, "critical").await; // invalidates
        let r2 = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            mcp_authorize_request("deployer", "ship"),
        )
        .await;
        assert_eq!(
            r2.risk_level, "critical",
            "re-registration must invalidate the cache (no stale low-risk metadata)"
        );
    }

    #[tokio::test]
    async fn test_unregistered_tenant_returns_404() {
        use axum::http::Request;
        use tower::ServiceExt;

        let _guard = get_env_lock().lock().await;
        let (state, _tenant_id, _) = setup_state("unregistered_tenant").await;
        let app = register_agent_router(state);

        // Make a request with a tenant ID that does not exist in the database
        let request = Request::builder()
            .method("POST")
            .uri("/v1/agents/register")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer tenant_nonexistent_xyz")
            .body(axum::body::Body::from(
                register_agent_payload("new-agent").to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Tenant 'tenant_nonexistent_xyz' not found");
    }

    /// #1167: 100 tenants are created concurrently, each with its own agent,
    /// decision, pending approval, and action receipt. No tenant's list
    /// endpoints (`/v1/agents`, `/v1/decisions`, `/v1/approvals`,
    /// `/v1/receipts`) may return another tenant's rows.
    #[tokio::test]
    async fn cross_tenant_isolation_stress_100_tenants() {
        const N: usize = 100;
        let (state, _tenant_id, _agent_token) = setup_state("cross_tenant_stress").await;

        let mut handles = Vec::new();
        for i in 0..N {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                let tenant_id = format!("tenant_stress_{i}");
                db::register_tenant(
                    &state.pool,
                    &tenant_id,
                    &format!("Stress Tenant {i}"),
                    "developer",
                )
                .await
                .unwrap();

                let agent_token = format!("agent_tok_stress_{i}_{}", Uuid::new_v4().simple());
                let agent = AgentRecord {
                    id: Uuid::new_v4().to_string(),
                    tenant_id: tenant_id.clone(),
                    agent_key: "routes-agent".to_string(),
                    agent_token: db::hash_token(&agent_token),
                    name: format!("Stress Agent {i}"),
                    owner_team: Some("platform".to_string()),
                    owner_email: None,
                    environment: "production".to_string(),
                    framework: None,
                    model_provider: None,
                    model_name: None,
                    purpose: None,
                    risk_tier: "high".to_string(),
                    status: "active".to_string(),
                    last_seen_at: None,
                    frozen_reason: None,
                    force_approval: false,
                    quarantined_at: None,
                    signing_key: None,
                    allowed_environments: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };
                db::insert_agent(&state.pool, &agent).await.unwrap();

                // Creates a decision row, a pending approval, and an action receipt
                // all bound to this tenant.
                create_pending_approval(&state, &tenant_id, &agent_token, &format!("{i}")).await;

                tenant_id
            }));
        }

        let mut tenant_ids = Vec::with_capacity(N);
        for handle in handles {
            tenant_ids.push(handle.await.unwrap());
        }

        for tenant_id in &tenant_ids {
            let agents: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_agents(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(agents.len(), 1, "tenant {tenant_id} sees != 1 agent");
            assert_eq!(agents[0]["tenant_id"], json!(tenant_id));

            let decisions: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_decisions(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(decisions.len(), 1, "tenant {tenant_id} sees != 1 decision");
            assert_eq!(decisions[0]["tenant_id"], json!(tenant_id));

            let approvals: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_approvals(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(approvals.len(), 1, "tenant {tenant_id} sees != 1 approval");

            let receipts: Vec<serde_json::Value> = serde_json::from_slice(
                &to_bytes(
                    list_receipts(
                        State(state.clone()),
                        TenantId(tenant_id.clone()),
                        axum::extract::RawQuery(None),
                    )
                    .await
                    .into_response()
                    .into_body(),
                    usize::MAX,
                )
                .await
                .unwrap(),
            )
            .unwrap();
            assert_eq!(receipts.len(), 1, "tenant {tenant_id} sees != 1 receipt");
            assert_eq!(receipts[0]["tenant_id"], json!(tenant_id));
        }
    }

    /// #1402 — tenant isolation across `audit_events`, `soc_alerts`,
    /// `soc_incidents`, and `decisions/:id`. The 100-tenant stress above
    /// already covers `agents`/`decisions`/`approvals`/`receipts` list
    /// endpoints; this test covers the remaining list and point-lookup
    /// endpoints that were not yet systematically stress-tested for
    /// cross-tenant data leakage (CWE-284).
    #[tokio::test]
    async fn tenant_isolation_audit_events_alerts_incidents_and_decision_by_id() {
        let (state, _unused, _) = setup_state("iso_audit_soc").await;

        // ── Tenant A ──────────────────────────────────────────────────────────
        let tenant_a = "iso_tenant_a".to_string();
        let tenant_b = "iso_tenant_b".to_string();
        for (tid, name) in [(&tenant_a, "Iso Tenant A"), (&tenant_b, "Iso Tenant B")] {
            db::register_tenant(&state.pool, tid, name, "developer")
                .await
                .unwrap();
        }

        // Seed agents for each tenant (needed as FK for decisions / alerts /
        // incidents).
        let agent_a = Uuid::new_v4().to_string();
        let agent_b = Uuid::new_v4().to_string();
        let tok_a = format!("tok_iso_a_{}", Uuid::new_v4().simple());
        let tok_b = format!("tok_iso_b_{}", Uuid::new_v4().simple());
        for (tid, aid, tok) in [(&tenant_a, &agent_a, &tok_a), (&tenant_b, &agent_b, &tok_b)] {
            db::insert_agent(
                &state.pool,
                &AgentRecord {
                    id: aid.clone(),
                    tenant_id: tid.clone(),
                    agent_key: "iso-agent".to_string(),
                    agent_token: db::hash_token(tok),
                    name: format!("Iso Agent {tid}"),
                    owner_team: None,
                    owner_email: None,
                    environment: "production".to_string(),
                    framework: None,
                    model_provider: None,
                    model_name: None,
                    purpose: None,
                    risk_tier: "low".to_string(),
                    status: "active".to_string(),
                    last_seen_at: None,
                    frozen_reason: None,
                    force_approval: false,
                    quarantined_at: None,
                    signing_key: None,
                    allowed_environments: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        }

        // Produce a decision + audit event for each tenant via authorize so
        // `decisions` and `audit_events` both have real rows.
        let decision_a_id = call_authorize(
            state.clone(),
            &tenant_a,
            &tok_a,
            low_risk_authorize_request(),
        )
        .await
        .decision_id
        .to_string();
        let decision_b_id = call_authorize(
            state.clone(),
            &tenant_b,
            &tok_b,
            low_risk_authorize_request(),
        )
        .await
        .decision_id
        .to_string();

        // Seed a SOC alert and incident for each tenant directly (bypassing
        // event pipeline to keep the test fast and deterministic).
        let alert_a_id = Uuid::new_v4().to_string();
        let alert_b_id = Uuid::new_v4().to_string();
        for (tid, aid, alert_id) in [
            (&tenant_a, &agent_a, &alert_a_id),
            (&tenant_b, &agent_b, &alert_b_id),
        ] {
            db::insert_soc_alert(
                &state.pool,
                &crate::models::SocAlertRecord {
                    id: alert_id.clone(),
                    tenant_id: tid.clone(),
                    rule: "iso_test_rule".to_string(),
                    severity: "medium".to_string(),
                    agent_id: aid.clone(),
                    source_event_id: Uuid::new_v4().to_string(),
                    summary: format!("Iso alert for {tid}"),
                    created_at: Utc::now().to_rfc3339(),
                },
            )
            .await
            .unwrap();
        }

        let incident_a_id = Uuid::new_v4().to_string();
        let incident_b_id = Uuid::new_v4().to_string();
        for (tid, aid, incident_id) in [
            (&tenant_a, &agent_a, &incident_a_id),
            (&tenant_b, &agent_b, &incident_b_id),
        ] {
            db::insert_soc_incident(
                &state.pool,
                &crate::models::SocIncidentRecord {
                    id: incident_id.clone(),
                    tenant_id: tid.clone(),
                    kind: "iso_test_incident".to_string(),
                    severity: "high".to_string(),
                    agent_id: aid.clone(),
                    summary: format!("Iso incident for {tid}"),
                    source_event_ids: "[]".to_string(),
                    opened_at: Utc::now().to_rfc3339(),
                    status: "open".to_string(),
                    closed_at: None,
                },
            )
            .await
            .unwrap();
        }

        // ── Isolation assertions for Tenant A ─────────────────────────────────

        let events_a: Vec<serde_json::Value> = serde_json::from_slice(
            &to_bytes(
                get_audit_events(
                    State(state.clone()),
                    TenantId(tenant_a.clone()),
                    axum::extract::RawQuery(None),
                )
                .await
                .into_response()
                .into_body(),
                usize::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert!(
            events_a.iter().all(|e| e["tenant_id"] == json!(tenant_a)),
            "audit_events for tenant_a leaked tenant_b rows"
        );
        assert!(
            !events_a.iter().any(|e| e["tenant_id"] == json!(tenant_b)),
            "audit_events for tenant_a contains tenant_b rows"
        );

        let alerts_a: Vec<serde_json::Value> = serde_json::from_slice(
            &to_bytes(
                list_alerts(
                    State(state.clone()),
                    TenantId(tenant_a.clone()),
                    axum::extract::RawQuery(None),
                )
                .await
                .into_response()
                .into_body(),
                usize::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        // The events drain may produce additional alerts from detection rules
        // firing on the authorize calls above; assert isolation semantics
        // (no tenant_b data leaks) rather than an exact count.
        assert!(
            !alerts_a.is_empty(),
            "tenant_a should see at least the seeded alert"
        );
        assert!(
            alerts_a.iter().all(|a| a["tenant_id"] == json!(tenant_a)),
            "list_alerts for tenant_a leaked tenant_b rows"
        );
        assert!(
            alerts_a.iter().any(|a| a["id"] == json!(alert_a_id)),
            "seeded alert_a_id must appear in tenant_a's list"
        );
        assert!(
            !alerts_a.iter().any(|a| a["tenant_id"] == json!(tenant_b)),
            "list_alerts for tenant_a must not contain tenant_b rows"
        );

        let incidents_a: Vec<serde_json::Value> = serde_json::from_slice(
            &to_bytes(
                list_incidents(
                    State(state.clone()),
                    TenantId(tenant_a.clone()),
                    axum::extract::RawQuery(None),
                )
                .await
                .into_response()
                .into_body(),
                usize::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert!(
            !incidents_a.is_empty(),
            "tenant_a should see at least the seeded incident"
        );
        assert!(
            incidents_a
                .iter()
                .all(|i| i["tenant_id"] == json!(tenant_a)),
            "list_incidents for tenant_a leaked tenant_b rows"
        );
        assert!(
            incidents_a.iter().any(|i| i["id"] == json!(incident_a_id)),
            "seeded incident_a_id must appear in tenant_a's list"
        );
        assert!(
            !incidents_a
                .iter()
                .any(|i| i["tenant_id"] == json!(tenant_b)),
            "list_incidents for tenant_a must not contain tenant_b rows"
        );

        // Tenant A must not be able to fetch Tenant B's decision by ID.
        let cross_resp = get_decision(
            State(state.clone()),
            TenantId(tenant_a.clone()),
            Path(decision_b_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(
            cross_resp.status(),
            StatusCode::NOT_FOUND,
            "cross-tenant GET /v1/decisions/:id must return 404"
        );

        // Sanity: Tenant A can still fetch its OWN decision by ID.
        let own_resp = get_decision(
            State(state.clone()),
            TenantId(tenant_a.clone()),
            Path(decision_a_id.clone()),
        )
        .await
        .into_response();
        assert_eq!(own_resp.status(), StatusCode::OK);
    }

    /// #1299: helper building an authorize request for a registered,
    /// mutating, high-risk action ("deployer"/"ship").
    fn high_risk_authorize_request() -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
            dry_run: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "deployer".to_string(),
                action: "ship".to_string(),
                resource: None,
                mutates_state: true,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: Some(AuthorizeTraceContext {
                run_id: "run_routes".to_string(),
                trace_id: "trace_routes".to_string(),
                parent_run_id: None,
                root_trust_level: None,
            }),
        }
    }

    /// #1299: register "deployer"/"ship" as a high-risk, mutating action for
    /// the given tenant via the standard registration handler.
    async fn register_high_risk_action(state: Arc<AppState>) {
        use axum::http::Request;
        use tower::ServiceExt;

        let app = register_tool_router(state);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer tenant_routes")
            .body(axum::body::Body::from(
                register_tool_payload("deployer", "high").to_string(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// #1299: an authorize request for a registered, non-mutating, low-risk
    /// read-only action ("deployer"/"status").
    fn low_risk_authorize_request() -> AuthorizeRequest {
        AuthorizeRequest {
            request_id: None,
            callback: None,
            dry_run: None,
            nonce: None,
            timestamp: None,
            agent: AuthorizeAgentContext {
                id: "routes-agent".to_string(),
                environment: "production".to_string(),
            },
            user: None,
            tool_call: AuthorizeToolCall {
                tool: "deployer".to_string(),
                action: "status".to_string(),
                resource: None,
                mutates_state: false,
                parameters: serde_json::json!({}),
            },
            context: AuthorizeDynamicContext {
                source_trust: "trusted_internal_signed".to_string(),
                contains_sensitive_data: false,
            },
            trace: Some(AuthorizeTraceContext {
                run_id: "run_routes".to_string(),
                trace_id: "trace_routes".to_string(),
                parent_run_id: None,
                root_trust_level: None,
            }),
        }
    }

    /// #1299: register "deployer"/"status" as a low-risk, non-mutating
    /// read-only action for the given tenant.
    async fn register_low_risk_action(state: Arc<AppState>) {
        use axum::http::Request;
        use tower::ServiceExt;

        let app = register_tool_router(state);
        let payload = json!({
            "skill_key": "deployer",
            "name": "Deployer",
            "type": "static",
            "auth_type": null,
            "owner_team": "platform",
            "default_risk": "low",
            "actions": [
                {
                    "action_key": "status",
                    "description": "Check deploy status",
                    "risk": "low",
                    "mutates_state": false,
                    "data_access": "read",
                    "approval_required": false,
                    "default_decision": "policy"
                }
            ]
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/tools")
            .header("content-type", "application/json")
            .header("Authorization", "Bearer tenant_routes")
            .body(axum::body::Body::from(payload.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// #1299 acceptance criteria: when the SOC event channel is full (no
    /// spare capacity), a high-risk/mutating action must be denied with
    /// `audit_writer_unavailable` rather than executing without an audit
    /// trail.
    #[tokio::test]
    async fn authorize_denies_high_risk_action_when_event_channel_is_full() {
        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/routes_audit_full_channel_{}.db",
            Uuid::new_v4().simple()
        );
        let pool = db::init_db(&db_url).await.unwrap();
        let tenant_id = "tenant_routes".to_string();
        db::register_tenant(&pool, &tenant_id, "Routes Tenant", "developer")
            .await
            .unwrap();

        let agent_id = Uuid::new_v4().to_string();
        let agent_token = format!("agent_tok_{}", Uuid::new_v4().simple());
        let agent = AgentRecord {
            id: agent_id,
            tenant_id: tenant_id.clone(),
            agent_key: "routes-agent".to_string(),
            agent_token: db::hash_token(&agent_token),
            name: "Routes Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&pool, &agent).await.unwrap();

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let metrics = Arc::new(crate::metrics::SecurityMetrics::new());
        // Capacity 1: one emit fills it completely (capacity() == 0 afterwards).
        let (events, _events_rx) = EventSink::channel(1, metrics.clone());
        let state = Arc::new(AppState {
            pool,
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,

            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: Vec::new(),
        });

        register_high_risk_action(state.clone()).await;

        // Fill the event channel so has_capacity() returns false.
        state.events.emit(AseEvent {
            event_id: "evt_fill".to_string(),
            occurred_at: Utc::now().to_rfc3339(),
            tenant_id: tenant_id.clone(),
            kind: "authorize_decision".to_string(),
            agent_id: "agent_fill".to_string(),
            decision: "allow".to_string(),
            tool: "filler".to_string(),
            action: "noop".to_string(),
            resource: None,
            risk_score: 0,
            reason: "fill".to_string(),
            run_id: None,
            trace_id: None,
            matched_policies: vec![],
            redacted_fields: vec![],
            schema_version: 1,
        });
        assert!(!state.events.has_capacity());

        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            high_risk_authorize_request(),
        )
        .await;

        assert_eq!(response.decision, "deny");
        assert!(
            response.reason.contains("audit_writer_unavailable"),
            "reason was: {}",
            response.reason
        );
        assert!(response
            .matched_policies
            .contains(&"audit_writer_unavailable".to_string()));
    }

    /// #1299 acceptance criteria: when the audit-record DB write fails (pool
    /// closed), a critical/high-risk mutating action must be denied with
    /// `audit_writer_unavailable` rather than executing without an audit
    /// trail.
    #[tokio::test]
    async fn authorize_denies_high_risk_action_when_audit_db_write_fails() {
        let (state, tenant_id, agent_token) = setup_state("audit_db_failure_high_risk").await;

        register_high_risk_action(state.clone()).await;

        // Simulate a DB write failure for the audit/decision record only:
        // drop the `decisions` table so `insert_decision` fails while agent
        // and registered-action lookups (SELECTs against other tables)
        // still succeed.
        sqlx::query("DROP TABLE decisions")
            .execute(&state.pool)
            .await
            .unwrap();

        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            high_risk_authorize_request(),
        )
        .await;

        assert_eq!(response.decision, "deny");
        assert!(
            response.reason.contains("audit_writer_unavailable"),
            "reason was: {}",
            response.reason
        );
        assert!(response
            .matched_policies
            .contains(&"audit_writer_unavailable".to_string()));
        assert!(state
            .audit_writer_unhealthy
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    /// #1299 acceptance criteria: when the audit-record DB write fails for a
    /// low-risk, non-mutating (read-only) action, the gateway degrades
    /// gracefully and still allows the action (with a warning logged) rather
    /// than denying it.
    #[tokio::test]
    async fn authorize_allows_low_risk_action_with_warning_when_audit_db_write_fails() {
        let (state, tenant_id, agent_token) = setup_state("audit_db_failure_low_risk").await;

        register_low_risk_action(state.clone()).await;

        // Simulate a DB write failure for the audit/decision record only:
        // drop the `decisions` table so `insert_decision` fails while agent
        // and registered-action lookups (SELECTs against other tables)
        // still succeed.
        sqlx::query("DROP TABLE decisions")
            .execute(&state.pool)
            .await
            .unwrap();

        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            low_risk_authorize_request(),
        )
        .await;

        assert_eq!(response.decision, "allow");
    }

    /// #1399 chaos test (AC3 + AC5): a `SQLITE_BUSY` on the decision write is
    /// retried via `retry_on_busy`; once retries exhaust with the lock still
    /// held, a high-risk/mutating action is denied with
    /// `audit_writer_unavailable` (fail-closed). Once the lock is released,
    /// normal operations resume and `audit_writer_unhealthy` resets to `false`.
    #[tokio::test]
    async fn authorize_denies_high_risk_action_when_db_locked_then_recovers() {
        use std::time::Duration;

        std::fs::create_dir_all("target").unwrap();
        let db_url = format!(
            "sqlite://target/routes_audit_busy_{}.db",
            Uuid::new_v4().simple()
        );
        // busy_timeout(0) → any concurrent writer lock surfaces as an
        // immediate SQLITE_BUSY instead of SQLite's own multi-second
        // busy-wait, so the test stays fast and deterministic.
        let pool = db::init_db_with_busy_timeout(&db_url, Duration::from_millis(0))
            .await
            .unwrap();
        let tenant_id = "tenant_routes".to_string();
        db::register_tenant(&pool, &tenant_id, "Routes Tenant", "developer")
            .await
            .unwrap();

        let agent_id = Uuid::new_v4().to_string();
        let agent_token = format!("agent_tok_{}", Uuid::new_v4().simple());
        let agent = AgentRecord {
            id: agent_id,
            tenant_id: tenant_id.clone(),
            agent_key: "routes-agent".to_string(),
            agent_token: db::hash_token(&agent_token),
            name: "Routes Agent".to_string(),
            owner_team: Some("platform".to_string()),
            owner_email: None,
            environment: "production".to_string(),
            framework: None,
            model_provider: None,
            model_name: None,
            purpose: None,
            risk_tier: "high".to_string(),
            status: "active".to_string(),
            last_seen_at: None,
            frozen_reason: None,
            force_approval: false,
            quarantined_at: None,
            signing_key: None,
            allowed_environments: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db::insert_agent(&pool, &agent).await.unwrap();

        let policy_engine = PolicyEngine::init("policies.cedar").await.unwrap();
        let metrics = Arc::new(crate::metrics::SecurityMetrics::new());
        let (events, _events_rx) = EventSink::channel(events::DEFAULT_CAPACITY, metrics.clone());
        let state = Arc::new(AppState {
            pool,
            policy_engine,
            events,
            metrics,
            approval_ttl_secs: 1800,
            rate_limiter: RateLimiter::new(1000.0, 1000.0),
            quota_manager: QuotaManager::new(0, 86400),
            approval_callback_ip_limiter: RateLimiter::new(10.0, 10.0 / 60.0),
            approval_attempt_tracker: ApprovalAttemptTracker::new(5, 3600),
            skill_cache: SkillActionCache::new(1024),
            replay_nonce_cache: ReplayNonceCache::new(10_000),
            startup_complete: std::sync::atomic::AtomicBool::new(true),
            audit_writer_unhealthy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audit_batch: crate::audit_batch::AuditBatchSink::channel(1024).0,
            github_webhook_secret: None,
            slack_signing_secret: None,
            github_pr_commenter: None,
            github_checks_client: None,
            qdrant_exporter: None,
            admission_webhook: None,
            background_task_handles: Vec::new(),
        });

        register_high_risk_action(state.clone()).await;

        // Hold an exclusive write lock via a second connection so that
        // INSERT into `decisions` from state.pool fails with SQLITE_BUSY
        // immediately (busy_timeout=0 on state.pool).
        let lock_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&lock_pool)
            .await
            .unwrap();

        // AC3: deny while locked, flag set.
        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            high_risk_authorize_request(),
        )
        .await;
        assert_eq!(response.decision, "deny");
        assert!(
            response.reason.contains("audit_writer_unavailable"),
            "reason was: {}",
            response.reason
        );
        assert!(state
            .audit_writer_unhealthy
            .load(std::sync::atomic::Ordering::Relaxed));

        // AC5: release lock — normal operations and flag reset.
        sqlx::query("ROLLBACK").execute(&lock_pool).await.unwrap();
        drop(lock_pool);

        let response = call_authorize(
            state.clone(),
            &tenant_id,
            &agent_token,
            high_risk_authorize_request(),
        )
        .await;
        assert_ne!(response.decision, "deny");
        assert!(!response.reason.contains("audit_writer_unavailable"));
        assert!(!state
            .audit_writer_unhealthy
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    // ── #1298: Compliance Evidence Pack ─────────────────────────────────────

    /// #1289: every `/v1/authorize` response carries an advisory
    /// `composite_risk_score` in `0..=100`, computed *after* the Cedar
    /// decision and never gating it (Law 1).
    #[tokio::test]
    async fn authorize_allow_response_has_composite_risk_score() {
        let (state, tenant_id, agent_token) = setup_state("composite_risk_allow").await;

        let mut request = mcp_authorize_request("filesystem", "read_file");
        request.context.source_trust = "trusted_internal_signed".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "allow");
        assert!((0..=100).contains(&response.composite_risk_score));
    }

    /// #1289: a denied decision (here, an untrusted mutating action) still
    /// carries a `composite_risk_score` — the score is display metadata and
    /// does not influence the `deny` outcome.
    #[tokio::test]
    async fn authorize_deny_response_has_composite_risk_score() {
        let (state, tenant_id, agent_token) = setup_state("composite_risk_deny").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "untrusted_external".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "deny");
        assert!((0..=100).contains(&response.composite_risk_score));
    }

    /// #1289: a `require_approval` decision carries a `composite_risk_score`
    /// that reflects the untrusted-provenance penalty (semi_trusted_customer
    /// is penalized less than untrusted_external, but more than
    /// trusted_internal_signed for an otherwise-identical action).
    #[tokio::test]
    async fn authorize_require_approval_response_has_composite_risk_score() {
        let (state, tenant_id, agent_token) = setup_state("composite_risk_approval").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "semi_trusted_customer".to_string();

        let response = call_authorize(state, &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");
        assert!((0..=100).contains(&response.composite_risk_score));
        // semi_trusted_customer + mutating > a plain trusted_internal_signed,
        // non-mutating read carries less risk.
        assert!(response.composite_risk_score > 0);
    }

    /// #1289: an idempotent replay (`request_id` reuse) returns the same
    /// `composite_risk_score` as the original decision.
    #[tokio::test]
    async fn authorize_idempotent_replay_preserves_composite_risk_score() {
        let (state, tenant_id, agent_token) = setup_state("composite_risk_replay").await;

        let mut request = mcp_authorize_request("filesystem", "read_file");
        request.context.source_trust = "trusted_internal_signed".to_string();
        request.request_id = Some("composite-risk-replay-1".to_string());

        let first = call_authorize(state.clone(), &tenant_id, &agent_token, request.clone()).await;
        let second = call_authorize(state, &tenant_id, &agent_token, request).await;

        assert_eq!(first.decision, second.decision);
        assert_eq!(first.composite_risk_score, second.composite_risk_score);
    }

    // ── #1281: Policy Dry-Run / Simulation Mode ─────────────────────────────

    /// `AuthorizeRequest.dry_run = Some(true)` evaluates the decision exactly
    /// like a normal call but persists nothing: no `decisions` row, no
    /// `audit_events` row. The response still reports the would-be decision
    /// and is flagged `dry_run: true`.
    #[tokio::test]
    async fn authorize_dry_run_allow_persists_nothing() {
        let (state, tenant_id, agent_token) = setup_state("dry_run_allow").await;

        let mut request = mcp_authorize_request("filesystem", "read_file");
        request.context.source_trust = "trusted_internal_signed".to_string();
        request.dry_run = Some(true);

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "allow");
        assert!(response.dry_run);

        let decisions = db::list_decisions(&state.pool, &tenant_id, 100, 0, None, None)
            .await
            .unwrap();
        assert!(
            decisions.is_empty(),
            "dry-run must not write a decisions row"
        );
        let audit_events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        assert!(
            audit_events.is_empty(),
            "dry-run must not write an audit_events row"
        );
    }

    /// A dry-run that would require approval reports `decision ==
    /// "require_approval"` but creates no real `approvals` row — there is
    /// nothing for an approver to act on, since nothing happened.
    #[tokio::test]
    async fn authorize_dry_run_require_approval_creates_no_approval() {
        let (state, tenant_id, agent_token) = setup_state("dry_run_approval").await;
        register_ship_action(&state, &tenant_id, "low").await;

        let mut request = mcp_authorize_request("deployer", "ship");
        request.tool_call.mutates_state = true;
        request.context.source_trust = "semi_trusted_customer".to_string();
        request.dry_run = Some(true);

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "require_approval");
        assert!(response.dry_run);
        assert!(
            response.approval.is_none(),
            "dry-run must not fabricate a real approval"
        );

        let pending = db::list_pending_approvals(&state.pool, &tenant_id, 100, 0)
            .await
            .unwrap();
        assert!(
            pending.is_empty(),
            "dry-run must not create an approvals row"
        );
    }

    /// A dry-run that would trigger a Cedar `@decision("quarantine")` rule
    /// must NOT actually quarantine the agent — only a persisted decision
    /// should be able to change agent state.
    #[tokio::test]
    async fn authorize_dry_run_quarantine_does_not_quarantine_agent() {
        let (state, tenant_id, agent_token) = setup_state("dry_run_quarantine").await;

        let mut request = mcp_authorize_request("quarantine_canary", "trigger");
        request.dry_run = Some(true);

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "quarantine");
        assert!(response.dry_run);

        let agent_id: String =
            sqlx::query_scalar("SELECT id FROM agents WHERE tenant_id = ? AND agent_token = ?")
                .bind(&tenant_id)
                .bind(db::hash_token(&agent_token))
                .fetch_one(&state.pool)
                .await
                .unwrap();
        let agent_record = db::get_agent_by_id(&state.pool, &tenant_id, &agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            agent_record.status, "active",
            "dry-run must not actually quarantine the agent"
        );
    }

    /// Omitting `dry_run` (the default) persists exactly as before #1281 —
    /// a regression guard against the new field changing default behavior.
    #[tokio::test]
    async fn authorize_dry_run_unset_persists_normally() {
        let (state, tenant_id, agent_token) = setup_state("dry_run_unset").await;

        let mut request = mcp_authorize_request("filesystem", "read_file");
        request.context.source_trust = "trusted_internal_signed".to_string();
        assert!(request.dry_run.is_none());

        let response = call_authorize(state.clone(), &tenant_id, &agent_token, request).await;
        assert_eq!(response.decision, "allow");
        assert!(!response.dry_run);

        let decisions = db::list_decisions(&state.pool, &tenant_id, 100, 0, None, None)
            .await
            .unwrap();
        assert_eq!(decisions.len(), 1);
    }

    /// #1296: repeated denials past the tenant's threshold auto-escalate the
    /// agent's `risk_tier` and write an `agent_risk_escalated` audit event —
    /// end to end through the real `/v1/authorize` path.
    #[tokio::test]
    async fn authorize_auto_escalates_risk_tier_after_repeated_denials() {
        let (state, tenant_id, agent_token) = setup_state("risk_escalation_e2e").await;
        let agent_id = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap()
            .id;
        // The test fixture agent defaults to risk_tier "high" (already maxed
        // out); reset to "low" so this test can observe an escalation.
        db::update_agent_risk_tier(&state.pool, &tenant_id, &agent_id, "low")
            .await
            .unwrap();
        db::upsert_risk_escalation_config(
            &state.pool,
            &tenant_id,
            &crate::risk_escalation::RiskEscalationConfig {
                denial_threshold: 1,
                window_minutes: 60,
            },
        )
        .await
        .unwrap();

        let mut deny_request = mcp_authorize_request("github", "merge_pull_request");
        deny_request.tool_call.mutates_state = true;
        deny_request.context.source_trust = "untrusted_external".to_string();

        for _ in 0..2 {
            let response = call_authorize(
                state.clone(),
                &tenant_id,
                &agent_token,
                deny_request.clone(),
            )
            .await;
            assert_eq!(response.decision, "deny");
        }

        let agent_record = db::get_agent_by_token(&state.pool, &tenant_id, &agent_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(agent_record.risk_tier, "medium");

        let events = db::get_all_audit_events(&state.pool, &tenant_id, None)
            .await
            .unwrap();
        assert!(events
            .iter()
            .any(|e| e.event_type == "agent_risk_escalated"));
    }

    // ── #1272: Evidence Graph Query API ──
}
