//! Decision writing and risk-level helpers for the authorization pipeline.
//!
//! Extracted from `authorize.rs` for clarity. All functions are `pub(crate)` and
//! re-exported via `routes/mod.rs` so existing call sites are unaffected.

use chrono::Utc;
use serde_json::json;
use tracing::error;
use uuid::Uuid;

use crate::db;
use crate::events::{AseEvent, EventSink};
use crate::mcp_inspect;
use crate::metrics::SecurityMetrics;
use crate::models::*;

use super::normalize_tool_identifier;

pub(crate) fn risk_score_for_level(risk_level: &str) -> i32 {
    match risk_level {
        "low" => 10,
        "medium" => 40,
        "high" => 75,
        "critical" => 95,
        _ => 10,
    }
}

/// Inverse of [`risk_score_for_level`] — used to reconstruct `risk_level` for an
/// idempotent replay (#0072), where only `risk_score` was persisted on the
/// original [`DecisionRecord`]. Bucketed by threshold so it tolerates any score
/// `risk_score_for_level` could have produced.
pub(crate) fn risk_level_for_score(risk_score: i32) -> String {
    match risk_score {
        s if s >= 95 => "critical",
        s if s >= 75 => "high",
        s if s >= 40 => "medium",
        _ => "low",
    }
    .to_string()
}

/// True if a write-decision/audit failure for this action must fail closed
/// (deny) rather than degrade to allow-with-warning (#1299). Mutating
/// actions and anything risk-level "medium"/"high"/"critical" are
/// high-risk; only non-mutating, risk-level "low" actions may proceed
/// without a persisted audit record.
pub(crate) fn is_high_risk_for_audit(risk_level: &str, mutates_state: bool) -> bool {
    mutates_state || risk_level != "low"
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_decision_and_audit(
    pool: &sqlx::SqlitePool,
    events: &EventSink,
    metrics: &SecurityMetrics,
    audit_batch: &crate::audit_batch::AuditBatchSink,
    tenant_id: &str,
    agent_id: &str,
    payload: &AuthorizeRequest,
    decision_id: Uuid,
    decision: &str,
    risk_score: i32,
    reason: &str,
    matched_policies: &[String],
    audit_event_type: &str,
    started_at: std::time::Instant,
    dry_run: bool,
) -> Result<i32, sqlx::Error> {
    // #1289: advisory composite risk score (Law 1 — never gates `decision`,
    // computed only for display/audit metadata). Per-tenant weight overrides
    // fall back to env-configured defaults inside `db::get_risk_weights`.
    let composite_risk_score = {
        let weights = db::get_risk_weights(pool, tenant_id)
            .await
            .unwrap_or_default();
        let is_mcp_call =
            super::mcp_server_key_from_tool(&normalize_tool_identifier(&payload.tool_call.tool))
                .is_some();
        crate::risk::compute_composite_risk_score(
            &crate::risk::RiskInputs {
                base_action_risk: risk_score,
                mutates_state: payload.tool_call.mutates_state,
                source_trust: &payload.context.source_trust,
                is_mcp_call,
                anomaly_score: 0,
                had_prior_approval: false,
            },
            &weights,
        )
    };

    // #1281: dry-run evaluates the decision (above) but persists nothing —
    // no decision/audit row, no risk-score sample, no metrics. Mirrors the
    // "what would happen" contract without touching the audit trail.
    if dry_run {
        return Ok(composite_risk_score);
    }

    // OBS-001 (#1154): record the inline /v1/authorize latency on the
    // Prometheus histogram. Recorded here (once per decision write) rather
    // than as middleware, so it shares the exact `started_at` already used
    // for `decision_record.latency_ms`.
    metrics.authorize_duration.observe(started_at.elapsed());
    // OBS-002 (#1155): per-outcome decision counter.
    metrics.inc_decision(decision);

    let decision_record = DecisionRecord {
        id: decision_id.to_string(),
        tenant_id: tenant_id.to_string(),
        agent_id: agent_id.to_string(),
        user_id: payload.user.as_ref().map(|u| u.id.clone()),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        skill: payload.tool_call.tool.clone(),
        action: payload.tool_call.action.clone(),
        resource: payload.tool_call.resource.clone(),
        input_json: serde_json::to_string(&payload.tool_call.parameters).unwrap_or_default(),
        decision: decision.to_string(),
        risk_score: Some(risk_score),
        reason: Some(reason.to_string()),
        matched_policy_ids: Some(matched_policies.join(",")),
        request_id: payload.request_id.clone(),
        latency_ms: Some(started_at.elapsed().as_millis() as i64),
        composite_risk_score: Some(composite_risk_score),
        // #1293: effective (tighten-only) trust level + upstream run_id, for
        // multi-agent chain reconstruction and audit visibility.
        root_trust_level: Some(crate::trust_chain::propagate(
            payload
                .trace
                .as_ref()
                .and_then(|t| t.root_trust_level.as_deref()),
            &payload.context.source_trust,
        )),
        parent_run_id: payload.trace.as_ref().and_then(|t| t.parent_run_id.clone()),
        created_at: Utc::now(),
    };

    // #1399: retry on transient SQLITE_BUSY/LOCKED before treating the audit
    // write as failed (fail-closed only after retries are exhausted).
    db::retry_on_busy(3, || db::insert_decision(pool, &decision_record)).await?;

    // TASK-0089 (#935): best-effort historical risk-score sample, so
    // operators can see an agent's risk trend over time. Never blocks the
    // decision response.
    if let Err(e) = db::insert_agent_risk_score(
        pool,
        tenant_id,
        agent_id,
        &decision_id.to_string(),
        risk_score,
        reason,
    )
    .await
    {
        error!("Failed to record agent risk score: {:?}", e);
    }

    let audit_record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        event_type: audit_event_type.to_string(),
        agent_id: Some(agent_id.to_string()),
        user_id: payload.user.as_ref().map(|u| u.id.clone()),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        span_id: None,
        skill: Some(payload.tool_call.tool.clone()),
        action: Some(payload.tool_call.action.clone()),
        resource: payload.tool_call.resource.clone(),
        event_json: serde_json::to_string(&decision_record).unwrap_or_default(),
        input_hash: None,
        output_hash: None,
        decision_id: Some(decision_id.to_string()),
        approval_id: None,
        created_at: Utc::now(),
    };
    // #1315: critical denials are written synchronously so they are visible
    // immediately (audit trail for the highest-severity decisions must never
    // wait on a batch flush); everything else goes through the non-blocking
    // batch sink.
    if decision == "deny" && risk_level_for_score(risk_score) == "critical" {
        db::insert_audit_event(pool, &audit_record).await?;
    } else {
        audit_batch.emit(pool, audit_record).await?;
    }

    // Phase 0 keystone: feed the async SOC stream. Non-blocking — the inline
    // decision has already been recorded above; emission never delays the caller.
    events.emit(AseEvent {
        event_id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        tenant_id: tenant_id.to_string(),
        kind: "authorize_decision".to_string(),
        agent_id: agent_id.to_string(),
        decision: decision.to_string(),
        tool: payload.tool_call.tool.clone(),
        action: payload.tool_call.action.clone(),
        resource: payload.tool_call.resource.clone(),
        risk_score,
        reason: reason.to_string(),
        run_id: payload.trace.as_ref().map(|t| t.run_id.clone()),
        trace_id: payload.trace.as_ref().map(|t| t.trace_id.clone()),
        matched_policies: matched_policies.to_vec(),
        redacted_fields: vec![],
        schema_version: 1,
    });

    Ok(composite_risk_score)
}
