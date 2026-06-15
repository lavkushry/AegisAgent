//! #1289 — Composite Risk Score Computation.
//!
//! `compute_composite_risk_score` is **advisory display metadata only** (Law 1):
//! it annotates a decision after Cedar has already produced `allow` / `deny` /
//! `require_approval` and must never influence that outcome. Callers persist the
//! result on `decisions.composite_risk_score` and surface it on
//! `AuthorizeResponse.composite_risk_score`.
//!
//! The formula is deterministic and intentionally simple — same inputs always
//! produce the same score, clamped to `0..=100`:
//!
//! ```text
//! composite = base_action_risk
//!            + environment_weight        (if the action mutates state)
//!            + context_trust_penalty     (keyed by source_trust)
//!            + mcp_trust_penalty          (if the tool is an MCP tool)
//!            + anomaly_score * anomaly_weight_pct / 100
//!            - approval_credit           (if a prior approval exists)
//! ```

/// Per-tenant configurable weights. Defaults come from `AEGIS_RISK_*` env vars
/// (see [`RiskWeights::from_env`]) and may be overridden per-tenant via
/// `tenant_risk_weights` (see `db::get_risk_weights`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RiskWeights {
    /// Added when `RiskInputs::mutates_state` is true.
    pub environment_weight_mutating: i32,
    pub context_trust_penalty_trusted_internal_signed: i32,
    pub context_trust_penalty_trusted_internal_unsigned: i32,
    pub context_trust_penalty_semi_trusted_customer: i32,
    pub context_trust_penalty_untrusted_external: i32,
    pub context_trust_penalty_malicious_suspected: i32,
    pub context_trust_penalty_unknown: i32,
    /// Added when `RiskInputs::is_mcp_call` is true.
    pub mcp_trust_penalty: i32,
    /// Percentage (0-100+) applied to `RiskInputs::anomaly_score` before adding it.
    pub anomaly_weight_pct: i32,
    /// Subtracted when `RiskInputs::had_prior_approval` is true.
    pub approval_credit: i32,
}

impl RiskWeights {
    /// Built-in defaults, used when no env var or per-tenant DB row overrides
    /// them. Penalties increase with how untrusted the triggering content is —
    /// mirroring the 6 trust levels in `cedar_policy_authoring.md`.
    pub const DEFAULT: RiskWeights = RiskWeights {
        environment_weight_mutating: 15,
        context_trust_penalty_trusted_internal_signed: 0,
        context_trust_penalty_trusted_internal_unsigned: 5,
        context_trust_penalty_semi_trusted_customer: 15,
        context_trust_penalty_untrusted_external: 30,
        context_trust_penalty_malicious_suspected: 50,
        context_trust_penalty_unknown: 20,
        mcp_trust_penalty: 10,
        anomaly_weight_pct: 100,
        approval_credit: 10,
    };

    /// Reads each weight from `AEGIS_RISK_<FIELD>` (e.g.
    /// `AEGIS_RISK_ENVIRONMENT_WEIGHT_MUTATING`), falling back to
    /// [`RiskWeights::DEFAULT`] for any var that is unset or not a valid `i32`.
    pub fn from_env() -> RiskWeights {
        RiskWeights {
            environment_weight_mutating: env_i32(
                "AEGIS_RISK_ENVIRONMENT_WEIGHT_MUTATING",
                RiskWeights::DEFAULT.environment_weight_mutating,
            ),
            context_trust_penalty_trusted_internal_signed: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_TRUSTED_INTERNAL_SIGNED",
                RiskWeights::DEFAULT.context_trust_penalty_trusted_internal_signed,
            ),
            context_trust_penalty_trusted_internal_unsigned: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_TRUSTED_INTERNAL_UNSIGNED",
                RiskWeights::DEFAULT.context_trust_penalty_trusted_internal_unsigned,
            ),
            context_trust_penalty_semi_trusted_customer: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_SEMI_TRUSTED_CUSTOMER",
                RiskWeights::DEFAULT.context_trust_penalty_semi_trusted_customer,
            ),
            context_trust_penalty_untrusted_external: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_UNTRUSTED_EXTERNAL",
                RiskWeights::DEFAULT.context_trust_penalty_untrusted_external,
            ),
            context_trust_penalty_malicious_suspected: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_MALICIOUS_SUSPECTED",
                RiskWeights::DEFAULT.context_trust_penalty_malicious_suspected,
            ),
            context_trust_penalty_unknown: env_i32(
                "AEGIS_RISK_CONTEXT_TRUST_PENALTY_UNKNOWN",
                RiskWeights::DEFAULT.context_trust_penalty_unknown,
            ),
            mcp_trust_penalty: env_i32(
                "AEGIS_RISK_MCP_TRUST_PENALTY",
                RiskWeights::DEFAULT.mcp_trust_penalty,
            ),
            anomaly_weight_pct: env_i32(
                "AEGIS_RISK_ANOMALY_WEIGHT_PCT",
                RiskWeights::DEFAULT.anomaly_weight_pct,
            ),
            approval_credit: env_i32(
                "AEGIS_RISK_APPROVAL_CREDIT",
                RiskWeights::DEFAULT.approval_credit,
            ),
        }
    }

    /// The configured penalty for a `source_trust` value. Unrecognized values
    /// (forward-compat for new trust levels) fall back to the `unknown` penalty.
    fn context_trust_penalty(&self, source_trust: &str) -> i32 {
        match source_trust {
            "trusted_internal_signed" => self.context_trust_penalty_trusted_internal_signed,
            "trusted_internal_unsigned" => self.context_trust_penalty_trusted_internal_unsigned,
            "semi_trusted_customer" => self.context_trust_penalty_semi_trusted_customer,
            "untrusted_external" => self.context_trust_penalty_untrusted_external,
            "malicious_suspected" => self.context_trust_penalty_malicious_suspected,
            _ => self.context_trust_penalty_unknown,
        }
    }
}

impl Default for RiskWeights {
    fn default() -> Self {
        RiskWeights::DEFAULT
    }
}

fn env_i32(key: &str, default: i32) -> i32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(default)
}

/// Per-decision inputs to [`compute_composite_risk_score`]. All fields are
/// derived from data already available on the `/v1/authorize` hot path —
/// nothing here requires an additional DB round trip beyond what the caller
/// already performs.
#[derive(Debug, Clone, Copy)]
pub struct RiskInputs<'a> {
    /// The existing Cedar-tier risk score (`risk_score_for_level`), 0-100.
    pub base_action_risk: i32,
    pub mutates_state: bool,
    pub source_trust: &'a str,
    pub is_mcp_call: bool,
    /// Behavioral-anomaly score (0-100) for this agent, e.g. from `baseline.rs`.
    /// `0` when no anomaly signal is available.
    pub anomaly_score: i32,
    /// True if this action is executing under a previously granted approval.
    pub had_prior_approval: bool,
}

/// Computes the composite risk score for a decision. Pure and deterministic:
/// identical `inputs`/`weights` always produce the identical result. Clamped
/// to `0..=100` regardless of how the weights are configured.
pub fn compute_composite_risk_score(inputs: &RiskInputs, weights: &RiskWeights) -> i32 {
    let mut score = inputs.base_action_risk;

    if inputs.mutates_state {
        score += weights.environment_weight_mutating;
    }

    score += weights.context_trust_penalty(inputs.source_trust);

    if inputs.is_mcp_call {
        score += weights.mcp_trust_penalty;
    }

    score += inputs.anomaly_score * weights.anomaly_weight_pct / 100;

    if inputs.had_prior_approval {
        score -= weights.approval_credit;
    }

    score.clamp(0, 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_inputs() -> RiskInputs<'static> {
        RiskInputs {
            base_action_risk: 10,
            mutates_state: false,
            source_trust: "trusted_internal_signed",
            is_mcp_call: false,
            anomaly_score: 0,
            had_prior_approval: false,
        }
    }

    #[test]
    fn same_inputs_produce_same_score() {
        let inputs = base_inputs();
        let weights = RiskWeights::DEFAULT;
        let first = compute_composite_risk_score(&inputs, &weights);
        let second = compute_composite_risk_score(&inputs, &weights);
        assert_eq!(first, second);
    }

    #[test]
    fn trusted_internal_signed_adds_no_penalty() {
        let inputs = base_inputs();
        let weights = RiskWeights::DEFAULT;
        assert_eq!(
            compute_composite_risk_score(&inputs, &weights),
            inputs.base_action_risk
        );
    }

    #[test]
    fn mutating_action_adds_environment_weight() {
        let mut inputs = base_inputs();
        inputs.mutates_state = true;
        let weights = RiskWeights::DEFAULT;
        assert_eq!(
            compute_composite_risk_score(&inputs, &weights),
            inputs.base_action_risk + weights.environment_weight_mutating
        );
    }

    #[test]
    fn untrusted_external_adds_higher_penalty_than_semi_trusted() {
        let weights = RiskWeights::DEFAULT;

        let mut semi_trusted = base_inputs();
        semi_trusted.source_trust = "semi_trusted_customer";
        let semi_trusted_score = compute_composite_risk_score(&semi_trusted, &weights);

        let mut untrusted = base_inputs();
        untrusted.source_trust = "untrusted_external";
        let untrusted_score = compute_composite_risk_score(&untrusted, &weights);

        assert!(untrusted_score > semi_trusted_score);
    }

    #[test]
    fn malicious_suspected_adds_highest_trust_penalty() {
        let weights = RiskWeights::DEFAULT;

        let mut malicious = base_inputs();
        malicious.source_trust = "malicious_suspected";

        let mut untrusted = base_inputs();
        untrusted.source_trust = "untrusted_external";

        assert!(
            compute_composite_risk_score(&malicious, &weights)
                > compute_composite_risk_score(&untrusted, &weights)
        );
    }

    #[test]
    fn unrecognized_trust_level_falls_back_to_unknown_penalty() {
        let weights = RiskWeights::DEFAULT;

        let mut unknown = base_inputs();
        unknown.source_trust = "unknown";

        let mut bogus = base_inputs();
        bogus.source_trust = "totally_made_up";

        assert_eq!(
            compute_composite_risk_score(&unknown, &weights),
            compute_composite_risk_score(&bogus, &weights)
        );
    }

    #[test]
    fn mcp_call_adds_mcp_trust_penalty() {
        let mut inputs = base_inputs();
        inputs.is_mcp_call = true;
        let weights = RiskWeights::DEFAULT;
        assert_eq!(
            compute_composite_risk_score(&inputs, &weights),
            inputs.base_action_risk + weights.mcp_trust_penalty
        );
    }

    #[test]
    fn anomaly_score_is_weighted_by_percentage() {
        let mut inputs = base_inputs();
        inputs.anomaly_score = 50;
        let mut weights = RiskWeights::DEFAULT;
        weights.anomaly_weight_pct = 50;
        assert_eq!(
            compute_composite_risk_score(&inputs, &weights),
            inputs.base_action_risk + 25
        );
    }

    #[test]
    fn prior_approval_subtracts_approval_credit() {
        let mut inputs = base_inputs();
        inputs.mutates_state = true;
        inputs.had_prior_approval = true;
        let weights = RiskWeights::DEFAULT;
        assert_eq!(
            compute_composite_risk_score(&inputs, &weights),
            inputs.base_action_risk + weights.environment_weight_mutating - weights.approval_credit
        );
    }

    #[test]
    fn score_is_clamped_to_zero_floor() {
        let mut inputs = base_inputs();
        inputs.base_action_risk = 0;
        inputs.had_prior_approval = true;
        let weights = RiskWeights::DEFAULT;
        assert_eq!(compute_composite_risk_score(&inputs, &weights), 0);
    }

    #[test]
    fn score_is_clamped_to_hundred_ceiling() {
        let mut inputs = base_inputs();
        inputs.base_action_risk = 95;
        inputs.mutates_state = true;
        inputs.is_mcp_call = true;
        inputs.source_trust = "malicious_suspected";
        inputs.anomaly_score = 100;
        let weights = RiskWeights::DEFAULT;
        assert_eq!(compute_composite_risk_score(&inputs, &weights), 100);
    }

    #[test]
    fn env_overrides_apply_when_set() {
        // SAFETY (test-only): sets a single env var read back by env_i32; no
        // other test in this module reads AEGIS_RISK_MCP_TRUST_PENALTY.
        std::env::set_var("AEGIS_RISK_MCP_TRUST_PENALTY", "25");
        let weights = RiskWeights::from_env();
        std::env::remove_var("AEGIS_RISK_MCP_TRUST_PENALTY");
        assert_eq!(weights.mcp_trust_penalty, 25);
    }

    #[test]
    fn from_env_defaults_match_default_when_unset() {
        let weights = RiskWeights::from_env();
        assert_eq!(
            weights.environment_weight_mutating,
            RiskWeights::DEFAULT.environment_weight_mutating
        );
    }
}
