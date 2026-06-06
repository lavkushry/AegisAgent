//! Phase 1 — the deterministic detection rule engine (the SOC's "rules").
//!
//! The Phase 0 [`crate::events::drain`] consumer feeds every [`AseEvent`] through
//! a [`Detector`]. Each rule is a **pure, atomic** function
//! `(&AseEvent) -> Option<Alert>` — it inspects exactly one already-decided event
//! and emits at most one [`Alert`]. The engine obeys the Agent-SOC design laws:
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

use crate::events::AseEvent;
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
    /// `"high"` | `"info"`.
    pub severity: String,
    pub agent_id: String,
    /// Human-readable, secret-free description of why the rule fired.
    pub summary: String,
    /// The `event_id` of the [`AseEvent`] that triggered this alert (evidence link).
    pub source_event_id: String,
}

impl Alert {
    /// Build an alert from the triggering event, inheriting its tenant, agent,
    /// timestamp, and id as immutable evidence references.
    fn from_event(event: &AseEvent, rule: &str, severity: &str, summary: String) -> Self {
        Alert {
            alert_id: Uuid::new_v4().to_string(),
            occurred_at: event.occurred_at.clone(),
            tenant_id: event.tenant_id.clone(),
            rule: rule.to_string(),
            severity: severity.to_string(),
            agent_id: event.agent_id.clone(),
            summary,
            source_event_id: event.event_id.clone(),
        }
    }
}

/// `risk_score` the gateway pins to the `critical` registered tier
/// (`routes::risk_score_for_level`). Used only to recognize an already-critical
/// Cedar decision — never to gate one (Law 1).
const CRITICAL_RISK_SCORE: i32 = 100;

/// True if any matched policy or the decision reason carries a substring (ASCII
/// case-insensitive). Deterministic field matching only.
fn signals(event: &AseEvent, needles: &[&str]) -> bool {
    let reason = event.reason.to_ascii_lowercase();
    let policies: Vec<String> = event
        .matched_policies
        .iter()
        .map(|p| p.to_ascii_lowercase())
        .collect();
    needles.iter().any(|needle| {
        let n = needle.to_ascii_lowercase();
        reason.contains(&n) || policies.iter().any(|p| p.contains(&n))
    })
}

/// Rule (a) `confused_deputy_block` — HIGH.
///
/// A `deny` whose matched policy / reason shows the trigger came from untrusted or
/// malicious-suspected provenance and the action mutates state. This is the
/// confused-deputy / indirect-prompt-injection signature (ATLAS AML.T0051 /
/// OWASP LLM01): external content drove a mutating action and Cedar denied it.
pub fn confused_deputy_block(event: &AseEvent) -> Option<Alert> {
    if event.decision != "deny" {
        return None;
    }
    let untrusted_provenance = signals(event, &["untrusted", "malicious"]);
    let mutating = signals(event, &["mutat", "mutation"]);
    if untrusted_provenance && mutating {
        return Some(Alert::from_event(
            event,
            "confused_deputy_block",
            "high",
            format!(
                "Mutating action {}/{} denied: triggered by untrusted/malicious provenance \
                 (confused-deputy / indirect prompt injection)",
                event.tool, event.action
            ),
        ));
    }
    None
}

/// Rule (b) `approval_required_surface` — INFO.
///
/// Surfaces every `require_approval` decision so the SOC console / notify sink
/// can show a human-in-the-loop gate was hit. Informational only.
pub fn approval_required_surface(event: &AseEvent) -> Option<Alert> {
    if event.decision != "require_approval" {
        return None;
    }
    Some(Alert::from_event(
        event,
        "approval_required_surface",
        "info",
        format!(
            "Human approval required for {}/{}",
            event.tool, event.action
        ),
    ))
}

/// Rule (c) `critical_deny` — HIGH.
///
/// A decision Cedar already pinned to the critical tier (`risk_score >= 100`) or
/// one matched against a critical / unknown-MCP-tool policy. Catches
/// fail-closed denials of unknown MCP tools (ATLAS AML.T0010 / OWASP LLM03) and
/// any critical-tier action. The score is only *recognized* here, never used to
/// decide — the inline Cedar verdict already stands (Law 1).
pub fn critical_deny(event: &AseEvent) -> Option<Alert> {
    let critical_score = event.risk_score >= CRITICAL_RISK_SCORE;
    let critical_policy = signals(event, &["mcp_unknown_tool", "critical"]);
    if critical_score || critical_policy {
        return Some(Alert::from_event(
            event,
            "critical_deny",
            "high",
            format!(
                "Critical-tier or unknown-MCP-tool action {}/{} (decision={})",
                event.tool, event.action, event.decision
            ),
        ));
    }
    None
}

/// Rule (d) `replay_attempt` — HIGH.
///
/// An approval-integrity violation surfaced off the inline authorize path: a
/// consume of an already-used / expired approval (replay, T-A3 / T-D), or an
/// attempt to grant an expired approval. The gateway's tamper path
/// (`routes::emit_tamper_attempt_receipt`) records a tamper-evident receipt and
/// also emits an `AseEvent` with `kind == "replay_attempt"`. This rule closes the
/// integrity→SOC loop: every such attempt becomes a HIGH SOC alert visible in
/// `GET /v1/alerts`, not only in the receipt chain. Deterministic field match on
/// the event kind only (Laws 1–2); carries ids + violation tag, no payloads.
pub fn replay_attempt(event: &AseEvent) -> Option<Alert> {
    if event.kind != "replay_attempt" {
        return None;
    }
    Some(Alert::from_event(
        event,
        "replay_attempt",
        "high",
        format!(
            "Approval-integrity violation ({}/{}) — replay/tamper attempt: {}",
            event.tool, event.action, event.reason
        ),
    ))
}

/// MCP tool-manifest drift: an MCP server's advertised tool manifest changed
/// versus the hash pinned at an earlier discovery. The gateway recomputes a
/// server-integrity hash on every `discover_mcp_tools` and emits an `AseEvent`
/// with `kind == "mcp_manifest_drift"` when it diverges from the pin. Drift is a
/// supply-chain / tool-hijack signal — the manifest the operator approved is not
/// the one now being advertised — so this raises a HIGH SOC alert pointing at the
/// affected server. Deterministic field match on the event kind only (Laws 1–2);
/// carries the server key + hashes, no payloads.
pub fn mcp_manifest_drift(event: &AseEvent) -> Option<Alert> {
    if event.kind != "mcp_manifest_drift" {
        return None;
    }
    Some(Alert::from_event(
        event,
        "mcp_manifest_drift",
        "high",
        format!(
            "MCP tool-manifest drift on '{}' — advertised manifest differs from the pinned hash: {}",
            event.resource.as_deref().unwrap_or(event.tool.as_str()),
            event.reason
        ),
    ))
}

/// The deterministic detection engine. Holds the ordered list of atomic rules and
/// runs every one over each event.
pub struct Detector {
    rules: Vec<fn(&AseEvent) -> Option<Alert>>,
}

impl Default for Detector {
    fn default() -> Self {
        Detector {
            rules: vec![
                confused_deputy_block,
                approval_required_surface,
                critical_deny,
                replay_attempt,
                mcp_manifest_drift,
            ],
        }
    }
}

impl Detector {
    /// Run every atomic rule over one event, collecting all alerts that fire.
    /// Pure: no I/O, no shared state, no correlation across events (Laws 1–3).
    pub fn evaluate(&self, event: &AseEvent) -> Vec<Alert> {
        self.rules.iter().filter_map(|rule| rule(event)).collect()
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
        }
    }

    // --- Rule (a): confused_deputy_block ---

    #[test]
    fn mutating_deny_with_untrusted_provenance_fires_confused_deputy() {
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "Mutating action from untrusted_external content".to_string();
        ev.matched_policies = vec!["forbid-untrusted-mutation".to_string()];

        let alert = confused_deputy_block(&ev).expect("rule should fire");
        assert_eq!(alert.rule, "confused_deputy_block");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.tenant_id, "tenant_123");
        assert_eq!(alert.agent_id, "coding-agent-prod");
        assert_eq!(alert.source_event_id, "evt_test_1");
        assert_eq!(alert.occurred_at, "2026-06-06T12:00:00Z");
    }

    #[test]
    fn malicious_suspected_mutation_fires_confused_deputy() {
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "denied".to_string();
        ev.matched_policies = vec!["forbid-malicious-mutation".to_string()];
        assert!(confused_deputy_block(&ev).is_some());
    }

    #[test]
    fn allow_decision_never_fires_confused_deputy() {
        let ev = base_event(); // decision == "allow"
        assert!(confused_deputy_block(&ev).is_none());
    }

    #[test]
    fn deny_without_untrusted_provenance_does_not_fire_confused_deputy() {
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "Mutating action denied (critical tier)".to_string();
        ev.matched_policies = vec!["forbid-critical".to_string()];
        // mutating but no untrusted/malicious provenance signal -> not confused deputy
        assert!(confused_deputy_block(&ev).is_none());
    }

    #[test]
    fn deny_untrusted_but_non_mutating_does_not_fire_confused_deputy() {
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.reason = "untrusted_external read denied".to_string();
        ev.matched_policies = vec!["forbid-untrusted-read".to_string()];
        assert!(confused_deputy_block(&ev).is_none());
    }

    // --- Rule (b): approval_required_surface ---

    #[test]
    fn require_approval_fires_info_surface() {
        let mut ev = base_event();
        ev.decision = "require_approval".to_string();
        let alert = approval_required_surface(&ev).expect("rule should fire");
        assert_eq!(alert.rule, "approval_required_surface");
        assert_eq!(alert.severity, "info");
    }

    #[test]
    fn allow_does_not_fire_approval_surface() {
        let ev = base_event();
        assert!(approval_required_surface(&ev).is_none());
    }

    // --- Rule (c): critical_deny ---

    #[test]
    fn unknown_mcp_tool_fires_critical_deny_high() {
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.tool = "unknown-mcp".to_string();
        ev.reason = "Unknown MCP tool".to_string();
        ev.matched_policies = vec!["mcp_unknown_tool".to_string()];
        let alert = critical_deny(&ev).expect("rule should fire");
        assert_eq!(alert.rule, "critical_deny");
        assert_eq!(alert.severity, "high");
    }

    #[test]
    fn critical_risk_score_fires_critical_deny() {
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.risk_score = 100;
        assert!(critical_deny(&ev).is_some());
    }

    #[test]
    fn critical_policy_substring_fires_critical_deny() {
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.matched_policies = vec!["forbid-critical-action".to_string()];
        assert!(critical_deny(&ev).is_some());
    }

    #[test]
    fn non_critical_allow_does_not_fire_critical_deny() {
        let ev = base_event(); // risk 40, no critical/mcp policy
        assert!(critical_deny(&ev).is_none());
    }

    // --- Detector::evaluate (all rules) ---

    #[test]
    fn evaluate_allow_produces_no_alerts() {
        let det = Detector::default();
        let ev = base_event();
        assert!(det.evaluate(&ev).is_empty());
    }

    #[test]
    fn evaluate_require_approval_produces_single_info_alert() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "require_approval".to_string();
        let alerts = det.evaluate(&ev);
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
        let alerts = det.evaluate(&ev);
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
        let alerts = det.evaluate(&ev);
        assert!(alerts
            .iter()
            .any(|a| a.rule == "critical_deny" && a.severity == "high"));
    }

    // --- Rule (d): replay_attempt ---

    #[test]
    fn replay_attempt_event_fires_high_alert() {
        let mut ev = base_event();
        ev.kind = "replay_attempt".to_string();
        ev.decision = "deny".to_string();
        ev.tool = "consume_not_consumable".to_string();
        ev.action = "tamper_attempt".to_string();
        let alert = replay_attempt(&ev).expect("rule should fire");
        assert_eq!(alert.rule, "replay_attempt");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.tenant_id, "tenant_123");
        assert_eq!(alert.source_event_id, "evt_test_1");
    }

    #[test]
    fn authorize_decision_does_not_fire_replay_attempt() {
        let ev = base_event(); // kind == "authorize_decision"
        assert!(replay_attempt(&ev).is_none());
    }

    #[test]
    fn evaluate_replay_attempt_produces_single_high_alert() {
        let det = Detector::default();
        let mut ev = base_event();
        ev.kind = "replay_attempt".to_string();
        ev.decision = "deny".to_string();
        ev.tool = "consume_not_consumable".to_string();
        ev.action = "tamper_attempt".to_string();
        let alerts = det.evaluate(&ev);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "replay_attempt");
        assert_eq!(alerts[0].severity, "high");
    }

    #[test]
    fn evaluate_normal_authorize_decision_does_not_fire_replay_attempt() {
        let det = Detector::default();
        let ev = base_event(); // kind == "authorize_decision", decision == "allow"
        assert!(det.evaluate(&ev).iter().all(|a| a.rule != "replay_attempt"));
    }

    // --- Rule (e): mcp_manifest_drift ---

    fn drift_event() -> AseEvent {
        let mut ev = base_event();
        ev.kind = "mcp_manifest_drift".to_string();
        ev.decision = "flag".to_string();
        ev.tool = "mcp:github".to_string();
        ev.action = "discover".to_string();
        ev.resource = Some("github".to_string());
        ev.reason = "MCP tool-manifest drift on server 'github': pinned sha256:aaa != \
                      observed sha256:bbb"
            .to_string();
        ev
    }

    #[test]
    fn mcp_manifest_drift_event_fires_high_alert() {
        let ev = drift_event();
        let alert = mcp_manifest_drift(&ev).expect("rule should fire");
        assert_eq!(alert.rule, "mcp_manifest_drift");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.tenant_id, "tenant_123");
        assert_eq!(alert.source_event_id, "evt_test_1");
        assert!(alert.summary.contains("github"));
    }

    #[test]
    fn authorize_decision_does_not_fire_mcp_manifest_drift() {
        let ev = base_event(); // kind == "authorize_decision"
        assert!(mcp_manifest_drift(&ev).is_none());
    }

    #[test]
    fn evaluate_mcp_manifest_drift_produces_single_high_alert() {
        let det = Detector::default();
        let alerts = det.evaluate(&drift_event());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "mcp_manifest_drift");
        assert_eq!(alerts[0].severity, "high");
    }

    #[test]
    fn evaluate_critical_untrusted_mutation_can_produce_two_alerts() {
        // A deny that is BOTH untrusted-mutating AND critical-tier fires two
        // independent atomic rules — each rule is evaluated in isolation.
        let det = Detector::default();
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        ev.risk_score = 100;
        ev.reason = "Mutating action from untrusted_external content".to_string();
        ev.matched_policies = vec!["forbid-untrusted-critical-mutation".to_string()];
        let alerts = det.evaluate(&ev);
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().any(|a| a.rule == "confused_deputy_block"));
        assert!(alerts.iter().any(|a| a.rule == "critical_deny"));
    }
}
