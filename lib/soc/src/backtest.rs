//! #1283 — detection rule backtesting: test a rule against historical
//! decisions before deploying it, without creating any real alerts.
//!
//! Reuses [`crate::rule_dsl::YamlRule::matches`] — the exact same per-event
//! predicate `events::drain` evaluates live — against synthetic
//! [`AseEvent`]s reconstructed from historical [`DecisionRecord`] rows. Pure
//! read + in-memory evaluation: nothing here writes to `soc_alerts` or
//! `soc_incidents`, so a backtest can never affect the live SOC pipeline.

use crate::events::AseEvent;
use crate::rule_dsl::YamlRule;
use aegis_api::models::DecisionRecord;
use chrono::{DateTime, Utc};

/// Reconstructs the [`AseEvent`] shape a historical decision would have
/// produced at the time `events::drain` first saw it. `kind` is always
/// `"authorize_decision"` — the only kind `decisions` rows ever represent;
/// `event_id` is synthesized since the original (transient, never
/// persisted) event id isn't recoverable. `redacted_fields` is always
/// empty: `decisions` doesn't persist the redact-fields list, and no
/// shipped default or custom rule condition inspects it.
pub fn decision_to_ase_event(decision: &DecisionRecord, tenant_id: &str) -> AseEvent {
    AseEvent {
        event_id: format!("backtest_{}", decision.id),
        occurred_at: decision.created_at.to_rfc3339(),
        tenant_id: tenant_id.to_string(),
        kind: "authorize_decision".to_string(),
        agent_id: decision.agent_id.clone(),
        decision: decision.decision.clone(),
        tool: decision.skill.clone(),
        action: decision.action.clone(),
        resource: decision.resource.clone(),
        risk_score: decision.risk_score.unwrap_or(0),
        reason: decision.reason.clone().unwrap_or_default(),
        run_id: decision.run_id.clone(),
        trace_id: decision.trace_id.clone(),
        matched_policies: decision
            .matched_policy_ids
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        redacted_fields: vec![],
        schema_version: 1,
        evidence: None,
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BacktestResult {
    pub rule_key: String,
    pub source: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub decisions_scanned: usize,
    pub match_count: usize,
    pub matched_decision_ids: Vec<String>,
    /// `match_count` projected to a per-day rate over `[from, to]` — the
    /// volume an operator should expect if this rule were live. `0.0` for a
    /// zero-or-negative-width range (avoids dividing by zero) rather than
    /// erroring: a malformed range is still a valid (if uninformative)
    /// backtest result.
    pub estimated_daily_alert_volume: f64,
}

/// Runs `rule` against every `decisions` row in `decisions` (already
/// fetched for `[from, to]`), without creating any real alert or touching
/// the SOC pipeline.
pub fn run_backtest(
    rule: &YamlRule,
    source: &'static str,
    tenant_id: &str,
    decisions: &[DecisionRecord],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> BacktestResult {
    let matched_decision_ids: Vec<String> = decisions
        .iter()
        .filter(|d| rule.matches(&decision_to_ase_event(d, tenant_id)))
        .map(|d| d.id.clone())
        .collect();

    let range_days = (to - from).num_seconds() as f64 / 86_400.0;
    let estimated_daily_alert_volume = if range_days > 0.0 {
        matched_decision_ids.len() as f64 / range_days
    } else {
        0.0
    };

    BacktestResult {
        rule_key: rule.rule_key.clone(),
        source: source.to_string(),
        from,
        to,
        decisions_scanned: decisions.len(),
        match_count: matched_decision_ids.len(),
        matched_decision_ids,
        estimated_daily_alert_volume,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_dsl::RuleCondition;
    use chrono::Duration;

    fn make_decision(id: &str, decision: &str, tool: &str, action: &str) -> DecisionRecord {
        DecisionRecord {
            id: id.to_string(),
            tenant_id: "tenant_1".to_string(),
            agent_id: "agent_1".to_string(),
            user_id: None,
            run_id: None,
            trace_id: None,
            skill: tool.to_string(),
            action: action.to_string(),
            resource: None,
            input_json: "{}".to_string(),
            decision: decision.to_string(),
            risk_score: Some(10),
            reason: Some("test reason".to_string()),
            matched_policy_ids: Some("policy_a,policy_b".to_string()),
            request_id: None,
            latency_ms: None,
            composite_risk_score: None,
            root_trust_level: None,
            parent_run_id: None,
            created_at: Utc::now(),
        }
    }

    fn deny_rule() -> YamlRule {
        YamlRule {
            rule_key: "test_deny_rule".to_string(),
            name: "test_deny_rule".to_string(),
            severity: "high".to_string(),
            condition: RuleCondition {
                event_type: None,
                decision: Some("deny".to_string()),
                tool: None,
                action: None,
                context_trust: None,
                mutating: None,
                min_risk_score: None,
                max_risk_score: None,
                matched_policy_contains: None,
            },
            summary_template: "{tool}.{action} denied".to_string(),
        }
    }

    #[test]
    fn decision_to_ase_event_splits_matched_policy_ids_on_comma() {
        let decision = make_decision("d1", "deny", "github", "merge");
        let event = decision_to_ase_event(&decision, "tenant_1");
        assert_eq!(event.matched_policies, vec!["policy_a", "policy_b"]);
        assert_eq!(event.kind, "authorize_decision");
        assert_eq!(event.tenant_id, "tenant_1");
    }

    #[test]
    fn decision_to_ase_event_handles_missing_matched_policy_ids() {
        let mut decision = make_decision("d1", "deny", "github", "merge");
        decision.matched_policy_ids = None;
        let event = decision_to_ase_event(&decision, "tenant_1");
        assert!(event.matched_policies.is_empty());
    }

    #[test]
    fn run_backtest_counts_only_matching_decisions() {
        let decisions = vec![
            make_decision("d1", "deny", "github", "merge"),
            make_decision("d2", "allow", "github", "merge"),
            make_decision("d3", "deny", "filesystem", "read_file"),
        ];
        let now = Utc::now();
        let result = run_backtest(
            &deny_rule(),
            "default",
            "tenant_1",
            &decisions,
            now - Duration::days(7),
            now,
        );
        assert_eq!(result.match_count, 2);
        assert_eq!(result.decisions_scanned, 3);
        assert_eq!(result.matched_decision_ids, vec!["d1", "d3"]);
    }

    #[test]
    fn run_backtest_projects_daily_volume_over_the_range() {
        let decisions: Vec<DecisionRecord> = (0..14)
            .map(|i| make_decision(&format!("d{i}"), "deny", "github", "merge"))
            .collect();
        let now = Utc::now();
        let result = run_backtest(
            &deny_rule(),
            "default",
            "tenant_1",
            &decisions,
            now - Duration::days(7),
            now,
        );
        assert_eq!(result.match_count, 14);
        assert!((result.estimated_daily_alert_volume - 2.0).abs() < 0.01);
    }

    #[test]
    fn run_backtest_zero_width_range_does_not_divide_by_zero() {
        let decisions = vec![make_decision("d1", "deny", "github", "merge")];
        let now = Utc::now();
        let result = run_backtest(&deny_rule(), "default", "tenant_1", &decisions, now, now);
        assert_eq!(result.estimated_daily_alert_volume, 0.0);
    }

    #[test]
    fn run_backtest_never_creates_real_alerts_pure_function() {
        // Compile-time/structural guarantee: `run_backtest` takes no
        // `SqlitePool`/`EventSink` and returns a plain serializable struct —
        // there is no handle through which it could write to soc_alerts.
        let decisions = vec![make_decision("d1", "deny", "github", "merge")];
        let now = Utc::now();
        let _ = run_backtest(
            &deny_rule(),
            "default",
            "tenant_1",
            &decisions,
            now - Duration::days(1),
            now,
        );
    }
}
