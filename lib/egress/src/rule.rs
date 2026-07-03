//! The egress rule model. Rules are plain data — this crate never fetches
//! them; callers (the gateway's egress-check API, or the proxy binary)
//! look up the applicable tenant/run rules themselves and hand them to
//! [`crate::EgressPolicy::new`].

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
}

/// What an egress check is evaluating — a DNS name (matched against the
/// domain-suffix trie) or a raw IP (matched against the CIDR set). A real
/// connection attempt is checked once by domain (if the destination was
/// given as a hostname) and, once resolved, again by IP — this crate
/// doesn't do the resolution itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDestination {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleMatcher {
    /// Matches the domain itself and every subdomain of it.
    DomainSuffix(String),
    Cidr(IpNet),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRule {
    pub action: RuleAction,
    pub matcher: RuleMatcher,
}

impl EgressRule {
    pub fn allow_domain_suffix(domain: impl Into<String>) -> Self {
        Self {
            action: RuleAction::Allow,
            matcher: RuleMatcher::DomainSuffix(domain.into()),
        }
    }

    pub fn deny_domain_suffix(domain: impl Into<String>) -> Self {
        Self {
            action: RuleAction::Deny,
            matcher: RuleMatcher::DomainSuffix(domain.into()),
        }
    }

    pub fn allow_cidr(net: IpNet) -> Self {
        Self {
            action: RuleAction::Allow,
            matcher: RuleMatcher::Cidr(net),
        }
    }

    pub fn deny_cidr(net: IpNet) -> Self {
        Self {
            action: RuleAction::Deny,
            matcher: RuleMatcher::Cidr(net),
        }
    }
}
