//! End-to-end authorize pipeline (library-owned).
//!
//! Chains admit → preflight → guard → metadata → evaluate behind a single
//! entry point so gateway adapters only build context and map outcomes.

use aegis_api::models::{ApprovalResponseInfo, AuthorizeResponse, DecisionRecord};
use uuid::Uuid;

use crate::context::AuthorizeContext;
use crate::evaluate::{evaluate_authorize, EvaluateConfig};
use crate::guard::guard_authorize;
use crate::metadata::metadata_authorize;
use crate::outcome::DecisionOutcome;
use crate::preflight::{preflight_authorize, PreflightTerminal};
use crate::risk::risk_level_for_score;
use crate::runtime::DecisionRuntime;

/// Rebuild an [`AuthorizeResponse`] for an idempotent decision replay (#0072).
pub fn authorize_response_from_decision_record(
    record: DecisionRecord,
    approval: Option<ApprovalResponseInfo>,
) -> AuthorizeResponse {
    let decision_id = Uuid::parse_str(&record.id).unwrap_or_else(|_| Uuid::nil());
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

    AuthorizeResponse {
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
        // The original decision already wrote its durable receipt; a replay
        // returns the cached decision and does not re-emit one.
        receipt: None,
    }
}

/// Run the full authorize pipeline for one already-authenticated context.
///
/// Callers must have built [`AuthorizeContext`] (tenant + credential + peer).
/// Returns a protocol-neutral [`DecisionOutcome`]; adapters map to REST/gRPC.
pub async fn run_authorize_pipeline(
    runtime: &dyn DecisionRuntime,
    ctx: &AuthorizeContext,
    raw_body: &[u8],
    started_at: std::time::Instant,
    config: EvaluateConfig,
) -> DecisionOutcome {
    let admitted = match crate::admit_authorize(runtime, ctx, raw_body).await {
        Ok(a) => a,
        Err(outcome) => return outcome,
    };

    let preflighted = match preflight_authorize(runtime, admitted).await {
        Ok(p) => p,
        Err(PreflightTerminal::Outcome(outcome)) => return outcome,
        Err(PreflightTerminal::IdempotentReplay(record)) => {
            return match runtime.idempotent_replay(*record).await {
                Ok(resp) => DecisionOutcome::decision(resp),
                Err(e) => crate::error_map::aegis_err_to_outcome(e),
            };
        }
    };

    let guarded = match guard_authorize(runtime, preflighted, started_at).await {
        Ok(g) => g,
        Err(outcome) => return outcome,
    };

    let meta = match metadata_authorize(runtime, guarded, started_at).await {
        Ok(m) => m,
        Err(outcome) => return outcome,
    };

    evaluate_authorize(runtime, meta, started_at, config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn response_from_record_maps_fields() {
        let record = DecisionRecord {
            id: Uuid::nil().to_string(),
            tenant_id: "t1".into(),
            agent_id: "a1".into(),
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: "echo".into(),
            action: "run".into(),
            resource: None,
            input_json: "{}".into(),
            decision: "allow".into(),
            risk_score: Some(10),
            reason: Some("ok".into()),
            matched_policy_ids: Some("p1,p2".into()),
            request_id: Some("r1".into()),
            latency_ms: None,
            composite_risk_score: Some(12),
            root_trust_level: Some("trusted_internal_unsigned".into()),
            parent_run_id: None,
            created_at: Utc::now(),
        };
        let resp = authorize_response_from_decision_record(record, None);
        assert_eq!(resp.decision, "allow");
        assert_eq!(resp.risk_score, 10);
        assert_eq!(resp.composite_risk_score, 12);
        assert_eq!(resp.matched_policies, vec!["p1", "p2"]);
        assert!(!resp.dry_run);
        assert!(resp.receipt.is_none());
    }
}
