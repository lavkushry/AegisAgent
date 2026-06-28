//! Phase 1 — the deterministic detection rule engine (the SOC's "rules").
//!
//! The Phase 0 [`crate::events::drain`] consumer feeds every [`AseEvent`] through
//! a [`Detector`]. Each rule is a [`crate::rule_dsl::YamlRule`] — a pure,
//! deterministic match against one already-decided event, producing at most one
//! [`Alert`] per rule. The engine obeys the Agent-SOC design laws:
//!
//! * **Law 1 — deterministic only.** Rules match on the Cedar verdict and policy
//!   identifiers, never on a tunable score. `risk_score` is read only where Cedar
//!   itself already pinned it to a critical tier; it never *gates* a decision (the
//!   decision was already made inline). A score never decides allow/deny here.
//! * **Law 2 — no model in the path.** Pure string/field matching; no LLM.
//! * **Law 3 — stays in the async drain.** This module is invoked only from the
//!   background [`crate::events::drain`] task, never the inline authorize budget.
//! * **No stateful correlation.** Each rule sees one event in isolation; frequency
//!   / sequence / window correlation is Phase 3, deliberately out of scope here.
//!
//! Alerts carry identifiers and a human summary only — never raw payloads or
//! secrets (the moat's redaction invariant).
//!
//! #1282: the rule set is now YAML-driven ([`crate::rule_dsl`]). The
//! gateway's built-in rules ([`crate::rule_dsl::default_rules`]) are the YAML
//! equivalents of the original hardcoded Rust functions; tenant-custom rules
//! loaded from `detection_rules` are evaluated the same way.

use crate::events::AseEvent;
use crate::rule_dsl::YamlRule;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A detection result: one rule fired on one event. Contains identifiers and a
/// summary only — no secrets, no raw parameters (redaction invariant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    /// Unique id for this alert.
    pub alert_id: String,
    /// RFC 3339 UTC timestamp — carried straight from the source event.
    pub occurred_at: String,
    /// Owning tenant — every alert stays tenant-scoped.
    pub tenant_id: String,
    /// Stable rule identifier that fired (e.g. `"confused_deputy_block"`).
    pub rule: String,
    /// `"high"` | `"medium"` | `"low"` | `"info"`.
    pub severity: String,
    pub agent_id: String,
    /// Human-readable, secret-free description of why the rule fired.
    pub summary: String,
    /// The `event_id` of the [`AseEvent`] that triggered this alert (evidence link).
    pub source_event_id: String,
}

impl Alert {
    /// Build an alert from the triggering event and the [`YamlRule`] that
    /// matched, inheriting the event's tenant, agent, timestamp, and id as
    /// immutable evidence references.
    fn from_match(event: &AseEvent, rule: &YamlRule) -> Self {
        Alert {
            alert_id: Uuid::new_v4().to_string(),
            occurred_at: event.occurred_at.clone(),
            tenant_id: event.tenant_id.clone(),
            rule: rule.name.clone(),
            severity: rule.severity.clone(),
            agent_id: event.agent_id.clone(),
            summary: rule.render_summary(event),
            source_event_id: event.event_id.clone(),
        }
    }
}

/// The deterministic detection engine. Evaluates the built-in
/// [`crate::rule_dsl::default_rules`] (cached once) plus any tenant-custom
/// rules passed to [`Detector::evaluate`].
pub struct Detector {
    default_rules: Vec<YamlRule>,
}

impl Default for Detector {
    fn default() -> Self {
        Detector {
            default_rules: crate::rule_dsl::default_rules(),
        }
    }
}

impl Detector {
    /// Run the built-in rules plus `tenant_rules` over one event, collecting
    /// every alert that fires. Pure: no I/O, no shared state, no correlation
    /// across events (Laws 1-3).
    ///
    /// Alerts are deduplicated by `(rule_name, source_event_id)`, keeping the
    /// first match — this preserves the pre-#1282 semantics where
    /// `critical_deny` and `mcp_manifest_drift` each fired at most once per
    /// event even though multiple conditions could independently match.
    pub fn evaluate(&self, event: &AseEvent, tenant_rules: &[YamlRule]) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = Vec::new();
        let mut seen_rule_names: Vec<&str> = Vec::new();
        for rule in self.default_rules.iter().chain(tenant_rules.iter()) {
            if !rule.matches(event) {
                continue;
            }
            if seen_rule_names.contains(&rule.name.as_str()) {
                continue;
            }
            seen_rule_names.push(&rule.name);
            alerts.push(Alert::from_match(event, rule));
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> AseEvent {
        AseEvent {
            event_id: "evt_test_1".to_string(),
            occurred_at: "2026-06-06T12:00:00Z".to_string(),
            tenant_id: "tenant_123".to_string(),
            kind: "authorize_decision".to_string(),
            agent_id: "coding-agent-prod".to_string(),
            decision: "allow".to_string(),
            tool: "github".to_string(),
            action: "merge_pull_request".to_string(),
            resource: Some("payments-service/pull/482".to_string()),
            risk_score: 40,
            reason: "Permitted by policy".to_string(),
            run_id: Some("run_456".to_string()),
            trace_id: None,
            matched_policies: vec![],
            redacted_fields: vec![],
            schema_version: 1,
            evidence: None,
        }
    }

    // --- confused_deputy_block ---

    #[test]
    fn mutating_deny_with_untrusted_provenance_fires_confused_deputy() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "Mutating action from untrusted_external content".to_string();
        ev.matched_policies = vec!["forbid-untrusted-mutation".to_string()];

        let alerts = det.evaluate(&ev, &[]);
        let alert = alerts
            .iter()
            .find(|a| a.rule == "confused_deputy_block")
            .expect("rule should fire");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.tenant_id, "tenant_123");
        assert_eq!(alert.agent_id, "coding-agent-prod");
        assert_eq!(alert.source_event_id, "evt_test_1");
        assert_eq!(alert.occurred_at, "2026-06-06T12:00:00Z");
    }

    #[test]
    fn malicious_suspected_mutation_fires_confused_deputy() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "denied".to_string();
        ev.matched_policies = vec!["forbid-malicious-mutation".to_string()];
        let alerts = det.evaluate(&ev, &[]);
        assert!(alerts.iter().any(|a| a.rule == "confused_deputy_block"));
    }

    #[test]
    fn allow_decision_never_fires_confused_deputy() {
        let det = Detector::default();
        let ev = base_event(); // decision == "allow"
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .all(|a| a.rule != "confused_deputy_block"));
    }

    #[test]
    fn deny_without_untrusted_provenance_does_not_fire_confused_deputy() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "Mutating action denied (critical tier)".to_string();
        ev.matched_policies = vec!["forbid-critical".to_string()];
        // mutating but no untrusted/malicious provenance signal -> not confused deputy
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .all(|a| a.rule != "confused_deputy_block"));
    }

    #[test]
    fn deny_untrusted_but_non_mutating_does_not_fire_confused_deputy() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "untrusted_external read denied".to_string();
        ev.matched_policies = vec!["forbid-untrusted-read".to_string()];
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .all(|a| a.rule != "confused_deputy_block"));
    }

    // --- approval_required_surface ---

    #[test]
    fn require_approval_fires_info_surface() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "require_approval".to_string();
        let alerts = det.evaluate(&ev, &[]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "approval_required_surface");
        assert_eq!(alerts[0].severity, "info");
    }

    #[test]
    fn allow_does_not_fire_approval_surface() {
        let det = Detector::default();
        let ev = base_event();
        assert!(det.evaluate(&ev, &[]).is_empty());
    }

    // --- critical_deny ---

    #[test]
    fn unknown_mcp_tool_fires_critical_deny_high() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.tool = "unknown-mcp".to_string();
        ev.reason = "Unknown MCP tool".to_string();
        ev.matched_policies = vec!["mcp_unknown_tool".to_string()];
        let alerts = det.evaluate(&ev, &[]);
        let alert = alerts
            .iter()
            .find(|a| a.rule == "critical_deny")
            .expect("rule should fire");
        assert_eq!(alert.severity, "high");
    }

    #[test]
    fn critical_risk_score_fires_critical_deny() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.risk_score = 100;
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .any(|a| a.rule == "critical_deny"));
    }

    #[test]
    fn critical_policy_substring_fires_critical_deny() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.matched_policies = vec!["forbid-critical-action".to_string()];
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .any(|a| a.rule == "critical_deny"));
    }

    #[test]
    fn non_critical_allow_does_not_fire_critical_deny() {
        let det = Detector::default();
        let ev = base_event(); // risk 40, no critical/mcp policy
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .all(|a| a.rule != "critical_deny"));
    }

    #[test]
    fn risk_score_and_policy_both_matching_fires_critical_deny_once() {
        // Both `critical_deny_risk_score` and `critical_deny_policy` could
        // independently match — dedup by rule name keeps this at one alert,
        // preserving pre-#1282 single-alert semantics.
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.risk_score = 100;
        ev.matched_policies = vec!["mcp_unknown_tool".to_string()];
        let all_alerts = det.evaluate(&ev, &[]);
        let alerts: Vec<&Alert> = all_alerts
            .iter()
            .filter(|a| a.rule == "critical_deny")
            .collect();
        assert_eq!(alerts.len(), 1);
    }

    // --- Detector::evaluate (all rules) ---

    #[test]
    fn evaluate_allow_produces_no_alerts() {
        let det = Detector::default();
        let ev = base_event();
        assert!(det.evaluate(&ev, &[]).is_empty());
    }

    #[test]
    fn evaluate_require_approval_produces_single_info_alert() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "require_approval".to_string();
        let alerts = det.evaluate(&ev, &[]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "approval_required_surface");
        assert_eq!(alerts[0].severity, "info");
    }

    #[test]
    fn evaluate_confused_deputy_produces_high_alert() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "Mutating action from untrusted_external content".to_string();
        ev.matched_policies = vec!["forbid-untrusted-mutation".to_string()];
        let alerts = det.evaluate(&ev, &[]);
        assert!(alerts
            .iter()
            .any(|a| a.rule == "confused_deputy_block" && a.severity == "high"));
    }

    #[test]
    fn evaluate_unknown_mcp_critical_produces_high_alert() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "Unknown MCP tool".to_string();
        ev.matched_policies = vec!["mcp_unknown_tool".to_string()];
        let alerts = det.evaluate(&ev, &[]);
        assert!(alerts
            .iter()
            .any(|a| a.rule == "critical_deny" && a.severity == "high"));
    }

    // --- replay_attempt ---

    #[test]
    fn replay_attempt_event_fires_high_alert() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.kind = "replay_attempt".to_string();
        ev.decision = "deny".to_string();
        ev.tool = "consume_not_consumable".to_string();
        ev.action = "tamper_attempt".to_string();
        let alerts = det.evaluate(&ev, &[]);
        let alert = alerts
            .iter()
            .find(|a| a.rule == "replay_attempt")
            .expect("rule should fire");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.tenant_id, "tenant_123");
        assert_eq!(alert.source_event_id, "evt_test_1");
    }

    #[test]
    fn authorize_decision_does_not_fire_replay_attempt() {
        let det = Detector::default();
        let ev = base_event(); // kind == "authorize_decision"
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .all(|a| a.rule != "replay_attempt"));
    }

    #[test]
    fn evaluate_replay_attempt_produces_single_high_alert() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.kind = "replay_attempt".to_string();
        ev.decision = "deny".to_string();
        ev.tool = "consume_not_consumable".to_string();
        ev.action = "tamper_attempt".to_string();
        let alerts = det.evaluate(&ev, &[]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "replay_attempt");
        assert_eq!(alerts[0].severity, "high");
    }

    #[test]
    fn evaluate_normal_authorize_decision_does_not_fire_replay_attempt() {
        let det = Detector::default();
        let ev = base_event(); // kind == "authorize_decision", decision == "allow"
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .all(|a| a.rule != "replay_attempt"));
    }

    // --- mcp_manifest_drift ---

    fn drift_event() -> AseEvent {
        let mut ev = base_event();
        ev.kind = "mcp_manifest_drift".to_string();
        ev.decision = "flag".to_string();
        ev.tool = "mcp:github".to_string();
        ev.action = "discover".to_string();
        ev.resource = Some("github".to_string());
        // #1336: tool_added/tool_removed classification — high severity.
        ev.risk_score = 75;
        ev.reason = "MCP tool-manifest drift on server 'github' (tool_added): pinned \
                      sha256:aaa != observed sha256:bbb — tools added: create_issue"
            .to_string();
        ev
    }

    #[test]
    fn mcp_manifest_drift_event_fires_high_alert() {
        let det = Detector::default();
        let ev = drift_event();
        let alerts = det.evaluate(&ev, &[]);
        let alert = alerts
            .iter()
            .find(|a| a.rule == "mcp_manifest_drift")
            .expect("rule should fire");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.tenant_id, "tenant_123");
        assert_eq!(alert.source_event_id, "evt_test_1");
        assert!(alert.summary.contains("github"));
    }

    #[test]
    fn authorize_decision_does_not_fire_mcp_manifest_drift() {
        let det = Detector::default();
        let ev = base_event(); // kind == "authorize_decision"
        assert!(det
            .evaluate(&ev, &[])
            .iter()
            .all(|a| a.rule != "mcp_manifest_drift"));
    }

    #[test]
    fn evaluate_mcp_manifest_drift_produces_single_high_alert() {
        let det = Detector::default();
        let alerts = det.evaluate(&drift_event(), &[]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "mcp_manifest_drift");
        assert_eq!(alerts[0].severity, "high");
    }

    /// #1336: a `tool_modified` drift (e.g. a new optional parameter on an
    /// existing tool) is encoded as `risk_score: 40` and must surface as a
    /// medium-severity alert, not the flat "high" of every prior drift.
    #[test]
    fn mcp_manifest_drift_tool_modified_fires_medium_alert() {
        let det = Detector::default();
        let mut ev = drift_event();
        ev.risk_score = 40;
        ev.reason = "MCP tool-manifest drift on server 'github' (tool_modified): pinned \
                      sha256:aaa != observed sha256:bbb — tools modified: create_issue"
            .to_string();
        let alerts = det.evaluate(&ev, &[]);
        let alert = alerts
            .iter()
            .find(|a| a.rule == "mcp_manifest_drift")
            .expect("rule should fire");
        assert_eq!(alert.severity, "medium");
    }

    /// #1336: a `metadata_changed` drift (description-only change) is encoded as
    /// `risk_score: 10` and must surface as a low-severity alert.
    #[test]
    fn mcp_manifest_drift_metadata_changed_fires_low_alert() {
        let det = Detector::default();
        let mut ev = drift_event();
        ev.risk_score = 10;
        ev.reason = "MCP tool-manifest drift on server 'github' (metadata_changed): pinned \
                      sha256:aaa != observed sha256:bbb — metadata changed: create_issue"
            .to_string();
        let alerts = det.evaluate(&ev, &[]);
        let alert = alerts
            .iter()
            .find(|a| a.rule == "mcp_manifest_drift")
            .expect("rule should fire");
        assert_eq!(alert.severity, "low");
    }

    #[test]
    fn evaluate_critical_untrusted_mutation_can_produce_two_alerts() {
        // A deny that is BOTH untrusted-mutating AND critical-tier fires two
        // independent rules — each rule is evaluated in isolation.
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.risk_score = 100;
        ev.reason = "Mutating action from untrusted_external content".to_string();
        ev.matched_policies = vec!["forbid-untrusted-critical-mutation".to_string()];
        let alerts = det.evaluate(&ev, &[]);
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().any(|a| a.rule == "confused_deputy_block"));
        assert!(alerts.iter().any(|a| a.rule == "critical_deny"));
    }

    // --- tenant-custom rules ---

    #[test]
    fn tenant_custom_rule_fires_alongside_default_rules() {
        let det = Detector::default();
        let custom = YamlRule {
            rule_key: "custom_github_deny".to_string(),
            name: "custom_github_deny".to_string(),
            severity: "medium".to_string(),
            condition: crate::rule_dsl::RuleCondition {
                decision: Some("deny".to_string()),
                tool: Some("github".to_string()),
                ..Default::default()
            },
            summary_template: "Custom rule: {tool}.{action} denied".to_string(),
        };
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        let alerts = det.evaluate(&ev, &[custom]);
        assert!(alerts.iter().any(|a| a.rule == "custom_github_deny"));
    }

    #[test]
    fn tenant_custom_rule_with_same_name_as_default_does_not_duplicate() {
        let det = Detector::default();
        // Same `name` as the built-in approval_required_surface rule —
        // dedup keeps the default's alert and skips this one.
        let custom = YamlRule {
            rule_key: "custom_dup".to_string(),
            name: "approval_required_surface".to_string(),
            severity: "high".to_string(),
            condition: crate::rule_dsl::RuleCondition {
                decision: Some("require_approval".to_string()),
                ..Default::default()
            },
            summary_template: "duplicate".to_string(),
        };
        let mut ev = base_event();
        ev.decision = "require_approval".to_string();
        let alerts = det.evaluate(&ev, &[custom]);
        let matching: Vec<&Alert> = alerts
            .iter()
            .filter(|a| a.rule == "approval_required_surface")
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].severity, "info"); // default's severity wins
    }
}
