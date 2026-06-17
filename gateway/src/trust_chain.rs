//! Trust propagation across agent chains (#1293).
//!
//! When Agent A triggers Agent B (which may trigger Agent C, etc.), the
//! trust level of the original triggering content must propagate through
//! the chain using a **tighten-only** rule: a downstream hop can never end
//! up with a *more* trusted effective level than the most restrictive level
//! seen anywhere upstream in the chain. This closes a confused-deputy gap
//! where Agent B could claim its own immediate trigger looks internal
//! (`trusted_internal_signed`) even though it was itself invoked by Agent A
//! acting on `untrusted_external` content — B must inherit A's restriction.
//!
//! The 6 trust levels are ranked from most trusted (0) to least trusted (5),
//! matching the ordering documented in `policies.cedar` and
//! `skills/cedar_policy_authoring.md`. An unrecognized level is treated as
//! the least trusted rank (fail closed).

/// Trust levels ordered from most trusted (index 0) to least trusted
/// (highest index). The ordering itself — not the specific strings — is
/// what `tighten` relies on.
const TRUST_LEVELS_MOST_TO_LEAST_TRUSTED: [&str; 6] = [
    "trusted_internal_signed",
    "trusted_internal_unsigned",
    "semi_trusted_customer",
    "untrusted_external",
    "malicious_suspected",
    "unknown",
];

/// Rank a trust level: lower is more trusted. Unrecognized levels rank as
/// the least trusted (one past `unknown`), so a typo or unmapped value never
/// accidentally outranks (i.e. is treated as more trustworthy than) a known
/// restrictive level — fail closed.
fn trust_rank(level: &str) -> usize {
    TRUST_LEVELS_MOST_TO_LEAST_TRUSTED
        .iter()
        .position(|&l| l == level)
        .unwrap_or(TRUST_LEVELS_MOST_TO_LEAST_TRUSTED.len())
}

/// Return whichever of `a` or `b` is the more restrictive (less trusted)
/// level. Ties return `a` unchanged.
pub fn tighten<'a>(a: &'a str, b: &'a str) -> &'a str {
    if trust_rank(b) > trust_rank(a) {
        b
    } else {
        a
    }
}

/// Compute the effective trust level for this hop given an optional
/// inherited `root_trust_level` from an upstream caller and this hop's own
/// declared `source_trust`. With no inherited root (the chain's first hop),
/// the effective level is simply the hop's own declared trust. Otherwise it
/// is the tighten-only combination of the two — the value to both gate this
/// hop's Cedar evaluation on *and* propagate to any downstream hop this
/// agent triggers next.
pub fn propagate(root_trust_level: Option<&str>, own_source_trust: &str) -> String {
    match root_trust_level {
        Some(root) => tighten(root, own_source_trust).to_string(),
        None => own_source_trust.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_rank_orders_most_to_least_trusted() {
        assert!(trust_rank("trusted_internal_signed") < trust_rank("trusted_internal_unsigned"));
        assert!(trust_rank("trusted_internal_unsigned") < trust_rank("semi_trusted_customer"));
        assert!(trust_rank("semi_trusted_customer") < trust_rank("untrusted_external"));
        assert!(trust_rank("untrusted_external") < trust_rank("malicious_suspected"));
        assert!(trust_rank("malicious_suspected") < trust_rank("unknown"));
    }

    #[test]
    fn trust_rank_unrecognized_level_ranks_least_trusted() {
        assert!(trust_rank("totally_made_up") > trust_rank("unknown"));
    }

    #[test]
    fn tighten_returns_more_restrictive_of_two() {
        assert_eq!(
            tighten("trusted_internal_signed", "untrusted_external"),
            "untrusted_external"
        );
        assert_eq!(
            tighten("untrusted_external", "trusted_internal_signed"),
            "untrusted_external"
        );
    }

    #[test]
    fn tighten_equal_levels_returns_either() {
        assert_eq!(
            tighten("semi_trusted_customer", "semi_trusted_customer"),
            "semi_trusted_customer"
        );
    }

    #[test]
    fn tighten_never_loosens_malicious_suspected() {
        assert_eq!(
            tighten("malicious_suspected", "trusted_internal_signed"),
            "malicious_suspected"
        );
    }

    #[test]
    fn propagate_with_no_root_uses_own_trust() {
        assert_eq!(
            propagate(None, "trusted_internal_signed"),
            "trusted_internal_signed"
        );
    }

    #[test]
    fn propagate_root_more_restrictive_than_own_wins() {
        // Agent B declares trusted_internal_signed for its own trigger, but
        // inherited root_trust_level (from Agent A) is untrusted_external —
        // B's effective trust must be the more restrictive untrusted_external.
        assert_eq!(
            propagate(Some("untrusted_external"), "trusted_internal_signed"),
            "untrusted_external"
        );
    }

    #[test]
    fn propagate_own_more_restrictive_than_root_wins() {
        assert_eq!(
            propagate(Some("trusted_internal_signed"), "malicious_suspected"),
            "malicious_suspected"
        );
    }

    #[test]
    fn propagate_three_hop_chain_inherits_most_restrictive_throughout() {
        // A: no root, declares untrusted_external -> effective A = untrusted_external.
        let effective_a = propagate(None, "untrusted_external");
        assert_eq!(effective_a, "untrusted_external");

        // B: inherits A's effective trust as root_trust_level, declares its
        // own trigger as trusted_internal_signed (naively) -> still tightened
        // to untrusted_external.
        let effective_b = propagate(Some(&effective_a), "trusted_internal_signed");
        assert_eq!(effective_b, "untrusted_external");

        // C: inherits B's effective trust, declares semi_trusted_customer ->
        // untrusted_external is still more restrictive, so C inherits it too.
        let effective_c = propagate(Some(&effective_b), "semi_trusted_customer");
        assert_eq!(effective_c, "untrusted_external");
    }
}
