//! Combines a tenant-wide rule set with an optional per-run rule set into
//! one egress decision.

use crate::cidr::CidrSet;
use crate::domain_trie::DomainSuffixTrie;
use crate::rule::{EgressDestination, EgressRule, RuleAction, RuleMatcher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Deny,
}

/// One scope's rules (tenant or run), compiled into matchers once so
/// repeated `check()` calls — one per outbound connection attempt — don't
/// re-walk a raw rule list each time.
#[derive(Debug, Default)]
struct CompiledRuleSet {
    allow_domains: DomainSuffixTrie,
    deny_domains: DomainSuffixTrie,
    allow_cidrs: CidrSet,
    deny_cidrs: CidrSet,
}

impl CompiledRuleSet {
    fn compile(rules: &[EgressRule]) -> Self {
        let mut set = Self::default();
        for rule in rules {
            match (rule.action, &rule.matcher) {
                (RuleAction::Allow, RuleMatcher::DomainSuffix(domain)) => {
                    set.allow_domains.insert(domain)
                }
                (RuleAction::Deny, RuleMatcher::DomainSuffix(domain)) => {
                    set.deny_domains.insert(domain)
                }
                (RuleAction::Allow, RuleMatcher::Cidr(net)) => set.allow_cidrs.insert(*net),
                (RuleAction::Deny, RuleMatcher::Cidr(net)) => set.deny_cidrs.insert(*net),
            }
        }
        set
    }

    fn denies(&self, destination: &EgressDestination) -> bool {
        match destination {
            EgressDestination::Domain(domain) => self.deny_domains.matches(domain),
            EgressDestination::Ip(ip) => self.deny_cidrs.matches(*ip),
        }
    }

    fn allows(&self, destination: &EgressDestination) -> bool {
        match destination {
            EgressDestination::Domain(domain) => self.allow_domains.matches(domain),
            EgressDestination::Ip(ip) => self.allow_cidrs.matches(*ip),
        }
    }
}

/// The egress policy for one tenant/run pair: a tenant-wide baseline rule
/// set plus an optional per-run rule set layered on top. An explicit
/// `Deny` at *either* scope always wins over any `Allow` — a run can add
/// restriction on top of its tenant's baseline but never loosen it, the
/// same tighten-never-loosen rule this codebase already applies to
/// trust-provenance propagation. When neither scope's rules say anything
/// about a destination, `deny_by_default` decides.
pub struct EgressPolicy {
    deny_by_default: bool,
    tenant_rules: CompiledRuleSet,
    run_rules: CompiledRuleSet,
}

impl EgressPolicy {
    pub fn new(
        deny_by_default: bool,
        tenant_rules: &[EgressRule],
        run_rules: &[EgressRule],
    ) -> Self {
        Self {
            deny_by_default,
            tenant_rules: CompiledRuleSet::compile(tenant_rules),
            run_rules: CompiledRuleSet::compile(run_rules),
        }
    }

    pub fn check(&self, destination: &EgressDestination) -> EgressDecision {
        if self.tenant_rules.denies(destination) || self.run_rules.denies(destination) {
            return EgressDecision::Deny;
        }
        if self.tenant_rules.allows(destination) || self.run_rules.allows(destination) {
            return EgressDecision::Allow;
        }
        if self.deny_by_default {
            EgressDecision::Deny
        } else {
            EgressDecision::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(s: &str) -> EgressDestination {
        EgressDestination::Domain(s.to_string())
    }

    fn ip(s: &str) -> EgressDestination {
        EgressDestination::Ip(s.parse().unwrap())
    }

    #[test]
    fn allowlist_domains_pass_and_everything_else_is_denied_by_default() {
        let tenant_rules = vec![EgressRule::allow_domain_suffix("github.com")];
        let policy = EgressPolicy::new(true, &tenant_rules, &[]);

        assert_eq!(
            policy.check(&domain("api.github.com")),
            EgressDecision::Allow
        );
        assert_eq!(policy.check(&domain("evil.com")), EgressDecision::Deny);
    }

    #[test]
    fn blocklist_domains_are_denied_and_everything_else_is_allowed_by_default() {
        let tenant_rules = vec![EgressRule::deny_domain_suffix("evil.com")];
        let policy = EgressPolicy::new(false, &tenant_rules, &[]);

        assert_eq!(policy.check(&domain("evil.com")), EgressDecision::Deny);
        assert_eq!(policy.check(&domain("safe.com")), EgressDecision::Allow);
    }

    #[test]
    fn cidr_matching_is_honored_alongside_domain_rules() {
        let tenant_rules = vec![
            EgressRule::allow_cidr("10.0.0.0/8".parse().unwrap()),
            EgressRule::deny_cidr("10.5.0.0/16".parse().unwrap()),
        ];
        let policy = EgressPolicy::new(true, &tenant_rules, &[]);

        assert_eq!(policy.check(&ip("10.1.2.3")), EgressDecision::Allow);
        // A more specific deny still wins over the broader allow — deny
        // always wins regardless of which rule is "more specific".
        assert_eq!(policy.check(&ip("10.5.1.1")), EgressDecision::Deny);
        assert_eq!(policy.check(&ip("8.8.8.8")), EgressDecision::Deny);
    }

    #[test]
    fn a_domain_that_only_shares_a_string_suffix_is_not_falsely_allowed() {
        let tenant_rules = vec![EgressRule::allow_domain_suffix("github.com")];
        let policy = EgressPolicy::new(true, &tenant_rules, &[]);

        assert_eq!(
            policy.check(&domain("evilgithub.com")),
            EgressDecision::Deny
        );
    }

    #[test]
    fn per_run_rules_add_to_the_tenant_baseline() {
        let tenant_rules = vec![EgressRule::allow_domain_suffix("api.example.com")];
        let run_rules = vec![EgressRule::allow_domain_suffix("extra.example.com")];
        let policy = EgressPolicy::new(true, &tenant_rules, &run_rules);

        assert_eq!(
            policy.check(&domain("api.example.com")),
            EgressDecision::Allow
        );
        assert_eq!(
            policy.check(&domain("extra.example.com")),
            EgressDecision::Allow
        );
        assert_eq!(policy.check(&domain("unrelated.com")), EgressDecision::Deny);
    }

    #[test]
    fn a_run_level_deny_overrides_a_tenant_level_allow() {
        let tenant_rules = vec![EgressRule::allow_domain_suffix("example.com")];
        let run_rules = vec![EgressRule::deny_domain_suffix("blocked.example.com")];
        let policy = EgressPolicy::new(true, &tenant_rules, &run_rules);

        assert_eq!(
            policy.check(&domain("api.example.com")),
            EgressDecision::Allow
        );
        assert_eq!(
            policy.check(&domain("blocked.example.com")),
            EgressDecision::Deny
        );
    }

    #[test]
    fn a_run_level_allow_cannot_loosen_a_tenant_level_deny() {
        let tenant_rules = vec![EgressRule::deny_domain_suffix("evil.com")];
        let run_rules = vec![EgressRule::allow_domain_suffix("evil.com")];
        let policy = EgressPolicy::new(false, &tenant_rules, &run_rules);

        assert_eq!(policy.check(&domain("evil.com")), EgressDecision::Deny);
    }

    #[test]
    fn no_rules_and_deny_by_default_denies_everything() {
        let policy = EgressPolicy::new(true, &[], &[]);
        assert_eq!(policy.check(&domain("anything.com")), EgressDecision::Deny);
        assert_eq!(policy.check(&ip("1.2.3.4")), EgressDecision::Deny);
    }

    #[test]
    fn no_rules_and_allow_by_default_allows_everything() {
        let policy = EgressPolicy::new(false, &[], &[]);
        assert_eq!(policy.check(&domain("anything.com")), EgressDecision::Allow);
        assert_eq!(policy.check(&ip("1.2.3.4")), EgressDecision::Allow);
    }
}
