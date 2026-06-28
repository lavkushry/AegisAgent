//! SOC-003 (#1282) — the YAML detection rule DSL.
//!
//! Operators (and the gateway's own [`default_rules`]) describe detection
//! rules as plain data:
//!
//! ```yaml
//! rule_key: untrusted_mutation_deny
//! name: confused_deputy_block
//! severity: high
//! condition:
//!   decision: deny
//!   mutating: true
//!   context_trust: [untrusted_external, malicious_suspected]
//! summary_template: "Denied {tool}.{action} from untrusted context"
//! ```
//!
//! A [`YamlRule`] is matched against one [`AseEvent`] in isolation — pure,
//! deterministic field comparison only (Agent-SOC design Laws 1-2). No score
//! ever gates a match; `min_risk_score`/`max_risk_score` only *recognize* a
//! risk tier Cedar already pinned inline.
//!
//! Unknown YAML keys, unknown trust levels, and unknown decisions/severities
//! are rejected by [`YamlRule::validate`] — operators get a clear 400, never a
//! silently-ignored typo.

use crate::events::AseEvent;
use serde::{Deserialize, Serialize};

/// The 6 deterministic context-trust levels (see `policies.cedar` /
/// `cedar_policy_authoring.md`). `context_trust` conditions may only name one
/// of these.
const VALID_TRUST_LEVELS: &[&str] = &[
    "trusted_internal_signed",
    "trusted_internal_unsigned",
    "semi_trusted_customer",
    "untrusted_external",
    "malicious_suspected",
    "unknown",
];

const VALID_DECISIONS: &[&str] = &["allow", "deny", "require_approval"];
const VALID_SEVERITIES: &[&str] = &["high", "medium", "low", "info"];

/// A YAML rule's match condition. All specified fields must match (AND);
/// unspecified fields are wildcards. `#[serde(deny_unknown_fields)]` rejects
/// any key that isn't one of these — an operator typo becomes a validation
/// error, not a silently-ignored no-op.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleCondition {
    /// Matches [`AseEvent::kind`] exactly (e.g. `"authorize_decision"`,
    /// `"replay_attempt"`, `"mcp_manifest_drift"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Matches [`AseEvent::decision`] exactly. Must be one of
    /// `allow`/`deny`/`require_approval`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Matches [`AseEvent::tool`] exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Matches [`AseEvent::action`] exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// At least one of the listed trust levels must appear (as a substring,
    /// ASCII case-insensitive) in `reason` or any `matched_policies` entry.
    /// Each entry must be one of the 6 deterministic trust levels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_trust: Option<Vec<String>>,
    /// `reason`/`matched_policies` must contain a mutation signal
    /// (`"mutat"`/`"mutation"`), mirroring the legacy `confused_deputy_block`
    /// rule's mutating check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutating: Option<bool>,
    /// [`AseEvent::risk_score`] must be `>= min_risk_score`. This only
    /// *recognizes* a risk tier Cedar already pinned inline — never gates
    /// (Law 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_risk_score: Option<i32>,
    /// [`AseEvent::risk_score`] must be `<= max_risk_score`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_risk_score: Option<i32>,
    /// `reason`/`matched_policies` must contain at least one of these
    /// substrings (ASCII case-insensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_policy_contains: Option<Vec<String>>,
}

/// One YAML-defined detection rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct YamlRule {
    /// Stable identifier — maps to `detection_rules.rule_key` for
    /// tenant-custom rules.
    pub rule_key: String,
    /// The [`crate::detect::Alert::rule`] value when this rule fires.
    pub name: String,
    pub severity: String,
    pub condition: RuleCondition,
    /// Human-readable summary template. Supports `{tool}`, `{action}`,
    /// `{decision}`, `{reason}`, `{tenant_id}`, `{agent_id}` placeholders.
    pub summary_template: String,
}

/// True if any of `needles` appears (ASCII case-insensitive substring) in
/// `event.reason` or any `event.matched_policies` entry. Shared by
/// `context_trust`, `mutating`, and `matched_policy_contains` matching.
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

impl RuleCondition {
    /// AND of every specified field. An empty condition matches everything.
    fn matches(&self, event: &AseEvent) -> bool {
        if let Some(event_type) = &self.event_type {
            if &event.kind != event_type {
                return false;
            }
        }
        if let Some(decision) = &self.decision {
            if &event.decision != decision {
                return false;
            }
        }
        if let Some(tool) = &self.tool {
            if &event.tool != tool {
                return false;
            }
        }
        if let Some(action) = &self.action {
            if &event.action != action {
                return false;
            }
        }
        if let Some(trust_levels) = &self.context_trust {
            // Cedar policy/rule names carry a short stem (e.g.
            // "untrusted-mutation-forbid", "forbid-malicious-mutation"), not
            // the full trust-level identifier — match on the leading
            // underscore-delimited segment ("untrusted_external" ->
            // "untrusted", "malicious_suspected" -> "malicious"), mirroring
            // the legacy `signals(event, &["untrusted", "malicious"])` check.
            let needles: Vec<&str> = trust_levels
                .iter()
                .map(|level| level.split('_').next().unwrap_or(level.as_str()))
                .collect();
            if !signals(event, &needles) {
                return false;
            }
        }
        if let Some(true) = self.mutating {
            if !signals(event, &["mutat", "mutation"]) {
                return false;
            }
        }
        if let Some(min) = self.min_risk_score {
            if event.risk_score < min {
                return false;
            }
        }
        if let Some(max) = self.max_risk_score {
            if event.risk_score > max {
                return false;
            }
        }
        if let Some(needles) = &self.matched_policy_contains {
            let needles: Vec<&str> = needles.iter().map(String::as_str).collect();
            if !signals(event, &needles) {
                return false;
            }
        }
        true
    }

    /// Reject conditions referencing unknown `decision` values or
    /// `context_trust` levels outside the 6 deterministic trust levels.
    /// Unknown YAML *keys* are already rejected at deserialization time via
    /// `deny_unknown_fields`.
    fn validate(&self) -> Result<(), String> {
        if let Some(decision) = &self.decision {
            if !VALID_DECISIONS.contains(&decision.as_str()) {
                return Err(format!(
                    "condition.decision: invalid value '{decision}' (expected one of {VALID_DECISIONS:?})"
                ));
            }
        }
        if let Some(trust_levels) = &self.context_trust {
            for level in trust_levels {
                if !VALID_TRUST_LEVELS.contains(&level.as_str()) {
                    return Err(format!(
                        "condition.context_trust: invalid value '{level}' (expected one of {VALID_TRUST_LEVELS:?})"
                    ));
                }
            }
        }
        Ok(())
    }
}

impl YamlRule {
    /// True if this rule's condition matches `event`.
    pub fn matches(&self, event: &AseEvent) -> bool {
        self.condition.matches(event)
    }

    /// Render `summary_template`, substituting `{tool}`, `{action}`,
    /// `{decision}`, `{reason}`, `{tenant_id}`, `{agent_id}` with the
    /// matching event's fields.
    pub fn render_summary(&self, event: &AseEvent) -> String {
        self.summary_template
            .replace("{tool}", &event.tool)
            .replace("{action}", &event.action)
            .replace("{decision}", &event.decision)
            .replace("{reason}", &event.reason)
            .replace("{tenant_id}", &event.tenant_id)
            .replace("{agent_id}", &event.agent_id)
    }

    /// Validate `severity` and `condition`. Called on every rule loaded from
    /// YAML — operator-submitted rules return this as a 400, never a panic.
    pub fn validate(&self) -> Result<(), String> {
        if !VALID_SEVERITIES.contains(&self.severity.as_str()) {
            return Err(format!(
                "severity: invalid value '{}' (expected one of {VALID_SEVERITIES:?})",
                self.severity
            ));
        }
        self.condition.validate()
    }
}

/// Parse one or more YAML rule documents (a YAML sequence of [`YamlRule`])
/// and validate each. Returns the first error encountered, prefixed with the
/// offending rule's `rule_key` where possible.
pub fn parse_rules(yaml: &str) -> Result<Vec<YamlRule>, String> {
    let rules: Vec<YamlRule> =
        serde_yml::from_str(yaml).map_err(|e| format!("YAML parse error: {e}"))?;
    for rule in &rules {
        rule.validate()
            .map_err(|e| format!("rule '{}': {e}", rule.rule_key))?;
    }
    Ok(rules)
}

/// Parse and validate a single rule's `condition` + `severity`, as submitted
/// via `POST /v1/soc/rules` (the `condition` and `summary_template` columns of
/// `detection_rules` hold the YAML body for one rule).
pub fn parse_and_validate_rule(rule: &YamlRule) -> Result<(), String> {
    rule.validate()
}

/// Build a [`YamlRule`] from a tenant-managed `detection_rules` row
/// (`aegis_api::models::DetectionRuleRecord`). The row's `condition` column holds
/// the YAML body for [`RuleCondition`] alone; `rule_key`, `name`, `severity`,
/// and `summary_template` are separate columns. Returns an error (never
/// panics) if `condition` isn't valid YAML for `RuleCondition` or the rule
/// fails [`YamlRule::validate`] — callers should skip such rows rather than
/// fail the whole evaluation (SOC alerting is advisory, Law 1).
pub fn yaml_rule_from_condition(
    rule_key: &str,
    name: &str,
    severity: &str,
    condition_yaml: &str,
    summary_template: &str,
) -> Result<YamlRule, String> {
    let condition: RuleCondition = serde_yml::from_str(condition_yaml)
        .map_err(|e| format!("condition: YAML parse error: {e}"))?;
    let rule = YamlRule {
        rule_key: rule_key.to_string(),
        name: name.to_string(),
        severity: severity.to_string(),
        condition,
        summary_template: summary_template.to_string(),
    };
    rule.validate()?;
    Ok(rule)
}

/// The default, built-in detection rules — YAML equivalents of the
/// pre-#1282 hardcoded `detect.rs` functions:
///
/// - `confused_deputy_block` (HIGH): a mutating `deny` driven by
///   untrusted/malicious-suspected provenance.
/// - `approval_required_surface` (INFO): every `require_approval` decision.
/// - `critical_deny` (HIGH): a `deny` Cedar already pinned to the critical
///   tier (`risk_score >= 100`), or matched against a critical /
///   unknown-MCP-tool policy.
/// - `replay_attempt` (HIGH): an approval-integrity replay/tamper event.
/// - `mcp_manifest_drift` (HIGH/MEDIUM/LOW, split by `risk_score` band per
///   #1336's `tool_added`/`tool_modified`/`metadata_changed` classification).
pub fn default_rules() -> Vec<YamlRule> {
    parse_rules(DEFAULT_RULES_YAML).expect("default_rules: embedded YAML must be valid")
}

const DEFAULT_RULES_YAML: &str = r#"
- rule_key: confused_deputy_block
  name: confused_deputy_block
  severity: high
  condition:
    decision: deny
    mutating: true
    context_trust: [untrusted_external, malicious_suspected]
  summary_template: "Mutating action {tool}.{action} denied: triggered by untrusted/malicious provenance (confused-deputy / indirect prompt injection)"

- rule_key: approval_required_surface
  name: approval_required_surface
  severity: info
  condition:
    decision: require_approval
  summary_template: "Human approval required for {tool}.{action}"

- rule_key: critical_deny_risk_score
  name: critical_deny
  severity: high
  condition:
    min_risk_score: 100
  summary_template: "Critical-tier or unknown-MCP-tool action {tool}.{action} (decision={decision})"

- rule_key: critical_deny_policy
  name: critical_deny
  severity: high
  condition:
    matched_policy_contains: [mcp_unknown_tool, critical]
  summary_template: "Critical-tier or unknown-MCP-tool action {tool}.{action} (decision={decision})"

- rule_key: replay_attempt
  name: replay_attempt
  severity: high
  condition:
    event_type: replay_attempt
  summary_template: "Approval-integrity violation ({tool}.{action}) — replay/tamper attempt: {reason}"

- rule_key: mcp_manifest_drift_high
  name: mcp_manifest_drift
  severity: high
  condition:
    event_type: mcp_manifest_drift
    min_risk_score: 75
  summary_template: "MCP tool-manifest drift — advertised manifest differs from the pinned hash: {reason}"

- rule_key: mcp_manifest_drift_medium
  name: mcp_manifest_drift
  severity: medium
  condition:
    event_type: mcp_manifest_drift
    min_risk_score: 40
    max_risk_score: 74
  summary_template: "MCP tool-manifest drift — advertised manifest differs from the pinned hash: {reason}"

- rule_key: mcp_manifest_drift_low
  name: mcp_manifest_drift
  severity: low
  condition:
    event_type: mcp_manifest_drift
    max_risk_score: 39
  summary_template: "MCP tool-manifest drift — advertised manifest differs from the pinned hash: {reason}"
"#;

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

    // --- parsing & validation ---

    #[test]
    fn default_rules_parse_and_validate() {
        let rules = default_rules();
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(
                rule.validate().is_ok(),
                "rule {} should validate",
                rule.rule_key
            );
        }
    }

    #[test]
    fn parse_rules_rejects_unknown_condition_key() {
        let yaml = r#"
- rule_key: bad_rule
  name: bad_rule
  severity: high
  condition:
    not_a_real_field: deny
  summary_template: "x"
"#;
        let err = parse_rules(yaml).expect_err("unknown key should be rejected");
        assert!(err.contains("YAML parse error"), "got: {err}");
    }

    #[test]
    fn parse_rules_rejects_invalid_decision_value() {
        let yaml = r#"
- rule_key: bad_rule
  name: bad_rule
  severity: high
  condition:
    decision: maybe
  summary_template: "x"
"#;
        let err = parse_rules(yaml).expect_err("invalid decision should be rejected");
        assert!(err.contains("condition.decision"), "got: {err}");
    }

    #[test]
    fn parse_rules_rejects_invalid_context_trust_level() {
        let yaml = r#"
- rule_key: bad_rule
  name: bad_rule
  severity: high
  condition:
    context_trust: [definitely_not_a_trust_level]
  summary_template: "x"
"#;
        let err = parse_rules(yaml).expect_err("invalid trust level should be rejected");
        assert!(err.contains("context_trust"), "got: {err}");
    }

    #[test]
    fn parse_rules_rejects_invalid_severity() {
        let yaml = r#"
- rule_key: bad_rule
  name: bad_rule
  severity: extreme
  condition: {}
  summary_template: "x"
"#;
        let err = parse_rules(yaml).expect_err("invalid severity should be rejected");
        assert!(err.contains("severity"), "got: {err}");
    }

    // --- matching ---

    #[test]
    fn empty_condition_matches_everything() {
        let rule = YamlRule {
            rule_key: "always".to_string(),
            name: "always".to_string(),
            severity: "info".to_string(),
            condition: RuleCondition::default(),
            summary_template: "always fires".to_string(),
        };
        assert!(rule.matches(&base_event()));
    }

    #[test]
    fn decision_condition_matches_exact_decision_only() {
        let rule = YamlRule {
            rule_key: "deny_only".to_string(),
            name: "deny_only".to_string(),
            severity: "info".to_string(),
            condition: RuleCondition {
                decision: Some("deny".to_string()),
                ..Default::default()
            },
            summary_template: "x".to_string(),
        };
        let mut ev = base_event();
        assert!(!rule.matches(&ev), "allow should not match deny_only");
        ev.decision = "deny".to_string();
        assert!(rule.matches(&ev));
    }

    #[test]
    fn context_trust_matches_substring_in_reason_or_policies() {
        let rule = YamlRule {
            rule_key: "untrusted".to_string(),
            name: "untrusted".to_string(),
            severity: "info".to_string(),
            condition: RuleCondition {
                context_trust: Some(vec!["untrusted_external".to_string()]),
                ..Default::default()
            },
            summary_template: "x".to_string(),
        };
        let mut ev = base_event();
        assert!(!rule.matches(&ev));
        ev.reason = "Mutating action from untrusted_external content".to_string();
        assert!(rule.matches(&ev));
    }

    #[test]
    fn mutating_condition_requires_mutation_signal() {
        let rule = YamlRule {
            rule_key: "mutating_only".to_string(),
            name: "mutating_only".to_string(),
            severity: "info".to_string(),
            condition: RuleCondition {
                mutating: Some(true),
                ..Default::default()
            },
            summary_template: "x".to_string(),
        };
        let mut ev = base_event();
        assert!(!rule.matches(&ev));
        ev.matched_policies = vec!["forbid-untrusted-mutation".to_string()];
        assert!(rule.matches(&ev));
    }

    #[test]
    fn min_and_max_risk_score_bound_the_match() {
        let rule = YamlRule {
            rule_key: "medium_band".to_string(),
            name: "medium_band".to_string(),
            severity: "medium".to_string(),
            condition: RuleCondition {
                min_risk_score: Some(40),
                max_risk_score: Some(74),
                ..Default::default()
            },
            summary_template: "x".to_string(),
        };
        let mut ev = base_event();
        ev.risk_score = 39;
        assert!(!rule.matches(&ev));
        ev.risk_score = 40;
        assert!(rule.matches(&ev));
        ev.risk_score = 74;
        assert!(rule.matches(&ev));
        ev.risk_score = 75;
        assert!(!rule.matches(&ev));
    }

    #[test]
    fn matched_policy_contains_matches_substring() {
        let rule = YamlRule {
            rule_key: "mcp_unknown".to_string(),
            name: "mcp_unknown".to_string(),
            severity: "high".to_string(),
            condition: RuleCondition {
                matched_policy_contains: Some(vec!["mcp_unknown_tool".to_string()]),
                ..Default::default()
            },
            summary_template: "x".to_string(),
        };
        let mut ev = base_event();
        assert!(!rule.matches(&ev));
        ev.matched_policies = vec!["mcp_unknown_tool".to_string()];
        assert!(rule.matches(&ev));
    }

    // --- yaml_rule_from_condition (detection_rules row -> YamlRule) ---

    #[test]
    fn yaml_rule_from_condition_builds_valid_rule() {
        let rule = yaml_rule_from_condition(
            "custom_github_deny",
            "custom_github_deny",
            "medium",
            "decision: deny\ntool: github\n",
            "Custom rule: {tool}.{action} denied",
        )
        .expect("should build");
        let mut ev = base_event();
        ev.decision = "deny".to_string();
        assert!(rule.matches(&ev));
    }

    #[test]
    fn yaml_rule_from_condition_rejects_invalid_yaml() {
        let err =
            yaml_rule_from_condition("bad", "bad", "medium", "decision: [not, a, string]\n", "x")
                .expect_err("should reject invalid YAML for RuleCondition");
        assert!(err.contains("condition"), "got: {err}");
    }

    #[test]
    fn yaml_rule_from_condition_rejects_invalid_severity() {
        let err = yaml_rule_from_condition("bad", "bad", "extreme", "decision: deny\n", "x")
            .expect_err("should reject invalid severity");
        assert!(err.contains("severity"), "got: {err}");
    }

    // --- summary rendering ---

    #[test]
    fn render_summary_substitutes_placeholders() {
        let rule = YamlRule {
            rule_key: "tpl".to_string(),
            name: "tpl".to_string(),
            severity: "info".to_string(),
            condition: RuleCondition::default(),
            summary_template: "{decision} {tool}.{action} for {agent_id}@{tenant_id}: {reason}"
                .to_string(),
        };
        let ev = base_event();
        let summary = rule.render_summary(&ev);
        assert_eq!(
            summary,
            "allow github.merge_pull_request for coding-agent-prod@tenant_123: Permitted by policy"
        );
    }
}
