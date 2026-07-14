//! Pure risk helpers for the authorization pipeline.
//!
//! Moved from the gateway routes layer so evaluation logic can live below
//! protocol adapters without pulling AppState.

/// Map a risk-level label to a stable integer score used on decision rows.
pub fn risk_score_for_level(risk_level: &str) -> i32 {
    match risk_level {
        "low" => 10,
        "medium" => 40,
        "high" => 75,
        "critical" => 95,
        _ => 10,
    }
}

/// Inverse of [`risk_score_for_level`] — reconstructs `risk_level` for
/// idempotent replay where only `risk_score` was persisted.
pub fn risk_level_for_score(risk_score: i32) -> String {
    match risk_score {
        s if s >= 95 => "critical",
        s if s >= 75 => "high",
        s if s >= 40 => "medium",
        _ => "low",
    }
    .to_string()
}

/// True if a write-decision/audit failure for this action must fail closed
/// rather than degrade to allow-with-warning. Mutating actions and anything
/// risk-level medium/high/critical are high-risk.
pub fn is_high_risk_for_audit(risk_level: &str, mutates_state: bool) -> bool {
    mutates_state || risk_level != "low"
}

/// Protected decisions require a durable, hash-chained receipt before success
/// is reported (mutating, high/critical risk, or any non-`allow` decision).
pub fn decision_requires_durable_receipt(
    decision: &str,
    risk_level: &str,
    mutates_state: bool,
) -> bool {
    if mutates_state {
        return true;
    }
    if matches!(risk_level, "high" | "critical") {
        return true;
    }
    decision != "allow"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_level_round_trip_buckets() {
        for level in ["low", "medium", "high", "critical"] {
            let score = risk_score_for_level(level);
            assert_eq!(risk_level_for_score(score), level);
        }
        assert_eq!(risk_level_for_score(0), "low");
        assert_eq!(risk_level_for_score(50), "medium");
    }

    #[test]
    fn high_risk_audit_gate() {
        assert!(is_high_risk_for_audit("low", true));
        assert!(is_high_risk_for_audit("medium", false));
        assert!(!is_high_risk_for_audit("low", false));
    }

    #[test]
    fn durable_receipt_rules() {
        assert!(decision_requires_durable_receipt("allow", "low", true));
        assert!(decision_requires_durable_receipt(
            "allow", "critical", false
        ));
        assert!(decision_requires_durable_receipt("deny", "low", false));
        assert!(!decision_requires_durable_receipt("allow", "low", false));
        assert!(!decision_requires_durable_receipt("allow", "medium", false));
    }
}
