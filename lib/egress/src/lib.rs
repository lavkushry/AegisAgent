//! `aegis-egress` — Phase 5.1 (`docs/AegisAgent_Phased_PR_Plan.md`, section
//! 7): the egress policy crate. Pure decision logic — domain-suffix and
//! CIDR matching, combined into per-tenant/per-run rule sets with an
//! explicit deny-by-default option. No I/O, no gateway/storage
//! dependency: callers (the gateway's egress-check API in Phase 5.2, and
//! the standalone proxy binary in Phase 5.3) fetch the applicable rules
//! themselves and hand them to [`EgressPolicy::new`].

mod cidr;
mod domain_trie;
mod policy;
mod rule;

pub use cidr::CidrSet;
pub use domain_trie::DomainSuffixTrie;
pub use policy::{EgressDecision, EgressPolicy};
pub use rule::{EgressDestination, EgressRule, RuleAction, RuleMatcher};
